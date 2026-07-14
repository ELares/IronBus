// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tiered storage: offloading cold, SEALED, immutable segments to an object store (#643, V2-M10 —
//! the Kafka KIP-405 / Pulsar / Redpanda tiered-storage class).
//!
//! Phase 1 (#1152) shipped the mechanism + the local-directory [`FsColdStore`] backend; phase 2
//! (#643) adds the S3 backend [`S3ColdStore`] behind the OFF-BY-DEFAULT `s3` feature — a small,
//! purpose-built S3 client (`SigV4` request signing over aws-lc-rs; HTTPS over the same rustls +
//! aws-lc-rs stack the `tls` feature already ships) that pulls NO `ring`, NO XML parser, and NO new
//! crate into the tree (ADR-0004: aws-lc-rs is the sole crypto provider).
//!
//! A sealed segment is immutable (its footer is written, no in-place mutation ever races), which
//! makes it the natural tiering unit: it can be copied to a cheap, high-capacity backing store and
//! its local disk bytes reclaimed, while a durable per-log MANIFEST remembers that the segment now
//! lives REMOTE so a later read can transparently fetch it back. This module is the mechanism —
//! the [`ColdStore`] seam, its local-directory [`FsColdStore`] backend, the offload/reap policy
//! ([`ColdStorageConfig`]), and the durable [`ColdManifest`] — while [`crate::log::Log`] drives the
//! crash-safe upload/fetch/recover/reap lifecycle around it.
//!
//! ## The seam
//!
//! [`ColdStore`] is a tiny key/blob interface (`put`/`get`/`delete`/`exists`) over an opaque object
//! key. Phase 1 ships one backend, [`FsColdStore`], which stores each object as a file in a
//! directory (any [`crate::fs::Filesystem`]: an on-disk [`crate::fs::StdFs`] rooted at a local path
//! or an NFS mount, or an in-memory filesystem for tests). Phase 2 adds [`S3ColdStore`] behind the
//! `s3` feature: it is just another `impl ColdStore`, so it drops into the log's
//! offload/fetch/recover machinery with NO change to any of that crash-safety logic (it is
//! backend-agnostic — proven identically with either backend).
//!
//! ## The durability contract (where a bug is PERMANENT DATA LOSS)
//!
//! The load-bearing invariant is **upload → fsync-manifest-REMOTE → THEN delete the local file**: a
//! local segment is never unlinked before BOTH its remote copy AND its manifest entry are durable.
//! Every crash window in between recovers to either fully-local (the manifest never recorded the
//! REMOTE transition, so the still-present local file is authoritative) or fully-remote-and-recorded
//! (the manifest committed the transition and the object is durable). See [`crate::log::Log`] for
//! the crash-window analysis and the reap ordering (a reaped remote segment deletes its object so no
//! orphan leaks).

use crate::checkpoint::{
    record_checkpoint_damage, CheckpointArtifact, ColdManifestCheckpoint, RecoveredCheckpoint,
    COLD_MANIFEST_PAYLOAD,
};
use crate::fs::Filesystem;
use crate::io::RandomAccessFile;
use crate::segment::StorageError;
use std::collections::BTreeMap;
use std::io;

/// The default number of most-recent sealed segments a log keeps LOCAL before it starts offloading
/// (#643). With the default (4), the four newest sealed segments — the ones a lagging-but-live
/// consumer is most likely to still be reading — stay on local disk, and only the colder tail is
/// tiered out. `0` offloads every sealed segment the moment it seals (the most aggressive tiering);
/// a large value effectively disables offload while leaving the feature wired.
pub const DEFAULT_KEEP_RECENT_SEGMENTS: u64 = 4;

/// The on-disk file name of a log's cold-segment MANIFEST — the durable, dual-slot, CRC-checked
/// record of which sealed segments have been offloaded to the [`ColdStore`] and their verification
/// metadata (#643). It lives at the log's root next to the segments (a [`crate::naming`] sibling of
/// `cursor.ckpt`); its `.ckpt` suffix and non-`seg-` prefix keep it invisible to segment enumeration
/// ([`crate::naming::segment_ids`]). Created LAZILY on the first offload, so a log that never
/// offloads has a byte-for-byte unchanged data directory (the default-OFF conformance guarantee).
pub const COLD_MANIFEST_FILE: &str = "cold-manifest.ckpt";

/// The subdirectory of a log's data directory into which the startup orphan sweep (#1153)
/// QUARANTINE-relocates a local `seg-<id>.log` file it cannot PROVE is a reaped-and-forgotten
/// restore-cache leftover: the bytes are preserved for forensics (never destroyed on ambiguity),
/// while the flat data directory — the only place segment enumeration looks — is cleared so the
/// chain-continuity scan can proceed. A sibling of the `quarantine/` forensic store, with the same
/// structural invisibility guarantee: recovery lists only the flat data directory's files, so a
/// relocated orphan can never be re-read as live data.
pub const COLD_ORPHANS_SUBDIR: &str = "orphans";

/// The magic prefix of the cold-manifest payload (IronBus Cold Manifest), distinguishing a real
/// manifest from an unrelated file: a CRC-valid slot whose magic does not match is treated as a
/// corrupt manifest, never silently as an empty one.
const COLD_MANIFEST_MAGIC: [u8; 4] = *b"IBCM";

/// The cold-manifest payload format version. Bumped only by a breaking manifest-layout change, at
/// which point an older reader refuses a higher version fail-closed (the same discipline as the
/// segment `FORMAT_VERSION` and the `layout.meta` marker).
const COLD_MANIFEST_VERSION: u8 = 1;

/// A category of tiered-storage OFFLOAD error (#643), for the `ironbus_cold_offload_errors_total{reason}`
/// counter. Offload runs BEST-EFFORT on the retention tick — a cold-store outage or a manifest at its
/// slot cap must NEVER fail a produce — so an error there is surfaced as this observable counter (plus
/// a `warn!`) and the offload is retried on the next tick, rather than propagated to the writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColdOffloadErrorReason {
    /// The [`ColdStore`] backend failed (a `put` transport error, a missing object, or no backend
    /// configured): `ColdStoreUnavailable` / `ColdFetch`.
    ColdStore,
    /// Any other offload failure (the manifest is at its slot cap, a local IO error reading the
    /// segment, etc.): the segment stays local and offload retries next tick.
    Other,
}

impl ColdOffloadErrorReason {
    /// Every reason in a fixed order; the index into the counter array. Append-only.
    pub const ALL: [ColdOffloadErrorReason; 2] = [
        ColdOffloadErrorReason::ColdStore,
        ColdOffloadErrorReason::Other,
    ];

    /// This reason's index into [`ColdOffloadErrorReason::ALL`].
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            ColdOffloadErrorReason::ColdStore => 0,
            ColdOffloadErrorReason::Other => 1,
        }
    }

    /// The frozen Prometheus `reason` label value.
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            ColdOffloadErrorReason::ColdStore => "cold_store",
            ColdOffloadErrorReason::Other => "other",
        }
    }

    /// Classifies a [`StorageError`] from an offload pass into a counter reason.
    #[must_use]
    pub fn for_error(err: &StorageError) -> ColdOffloadErrorReason {
        if err.is_cold_read_failure() {
            ColdOffloadErrorReason::ColdStore
        } else {
            ColdOffloadErrorReason::Other
        }
    }
}

/// The process-wide, monotonic `ironbus_cold_offload_errors_total{reason}` counter store (#643), one
/// cell per [`ColdOffloadErrorReason`]. A best-effort retention-tick offload records here on failure
/// instead of failing the produce path; the value is the operator's alert signal that tiering is
/// degraded (a cold-store outage or a full manifest).
static COLD_OFFLOAD_ERRORS: [core::sync::atomic::AtomicU64; ColdOffloadErrorReason::ALL.len()] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// Records one best-effort offload error for `reason`, bumping `ironbus_cold_offload_errors_total{reason}`.
/// Saturating; safe to call from the append actor.
pub fn record_cold_offload_error(reason: ColdOffloadErrorReason) {
    COLD_OFFLOAD_ERRORS[reason.index()].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// The current `ironbus_cold_offload_errors_total{reason}` value, for the `/metrics` render and tests.
#[must_use]
pub fn cold_offload_errors_total(reason: ColdOffloadErrorReason) -> u64 {
    COLD_OFFLOAD_ERRORS[reason.index()].load(core::sync::atomic::Ordering::Relaxed)
}

/// The fixed byte size of one encoded [`ColdEntry`]: six `u64` fields, a `u32` CRC, and a `u8` flags
/// byte. Every entry is fixed width, so the manifest payload is `HEADER_LEN + ENTRY_LEN * count`.
const ENTRY_LEN: usize = 8 * 6 + 4 + 1;

/// The manifest payload header: magic (4) + version (1) + entry count (`u32` LE, 4).
const HEADER_LEN: usize = 4 + 1 + 4;

/// The `flags` bit marking an offloaded segment as a COMPACTED (v2) segment. Reserved in phase 1
/// (which offloads only ordinary sealed segments, so the bit is always clear) so the manifest can
/// carry compacted segments forward-compatibly without a version bump.
const FLAG_COMPACTED: u8 = 0b0000_0001;

/// A typed [`ColdStore`] error. Distinct from a plain [`std::io::Error`] so the log's fetch path can
/// tell "the object is not in the store" ([`ColdStoreError::NotFound`], a data-availability event to
/// surface, never a silent skip) apart from a transient transport failure ([`ColdStoreError::Io`],
/// retryable). Both map to a typed [`StorageError`] the reader sees — never to a phantom record.
#[derive(Debug)]
#[non_exhaustive]
pub enum ColdStoreError {
    /// The object key is absent from the store. For a segment the manifest records as REMOTE this is
    /// a hard data-availability failure (the durable copy is gone), surfaced fail-closed, never a
    /// silent empty read.
    NotFound {
        /// The object key that was absent.
        key: String,
    },
    /// A transport/IO error talking to the backing store (a filesystem error for [`FsColdStore`], a
    /// network/HTTP error for a future object-store backend). Retryable/degraded, never data loss.
    Io(io::Error),
}

impl std::fmt::Display for ColdStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ColdStoreError::NotFound { key } => {
                write!(f, "cold-store object not found: {key}")
            }
            ColdStoreError::Io(e) => write!(f, "cold-store IO error: {e}"),
        }
    }
}

impl std::error::Error for ColdStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ColdStoreError::Io(e) => Some(e),
            ColdStoreError::NotFound { .. } => None,
        }
    }
}

impl From<io::Error> for ColdStoreError {
    fn from(e: io::Error) -> ColdStoreError {
        ColdStoreError::Io(e)
    }
}

/// The tiered-storage backing store seam: a small, object-safe key/blob interface an offloaded
/// sealed segment is `put` to, `get` back on a fetch-on-read, `delete`d on a retention reap, and
/// `exists`-probed on recovery reconciliation (#643).
///
/// It is deliberately minimal (whole-object put/get, no ranged reads or multipart) because a sealed
/// segment is a bounded, immutable blob — the natural granularity of the API. `Send + Sync` so a
/// single shared handle (`Arc<dyn ColdStore>`) serves the append actor's offload/fetch/reap and any
/// future off-actor prefetch. Every method takes `&self` and returns a typed [`ColdStoreError`], so
/// a `get` failure is always surfaced to the reader rather than degrading to a silent gap.
pub trait ColdStore: std::fmt::Debug + Send + Sync {
    /// Durably stores `bytes` under `key`, OVERWRITING any existing object with the same key. Must
    /// not return until the object is durable in the backing store (an [`FsColdStore`] fsyncs the
    /// file and its directory), because the log deletes the local segment only after a `put`
    /// returns. Idempotent by key: a retried offload of the same segment overwrites cleanly, so an
    /// upload interrupted before the manifest recorded it leaves no growing orphan.
    ///
    /// # Errors
    /// Returns [`ColdStoreError::Io`] if the object could not be durably written.
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ColdStoreError>;

    /// Fetches the whole object stored under `key`.
    ///
    /// # Errors
    /// Returns [`ColdStoreError::NotFound`] if no object exists under `key`, or [`ColdStoreError::Io`]
    /// on a transport error. The caller re-verifies the returned bytes (segment header + footer +
    /// CRC) before trusting them, so a corrupt store fails closed rather than delivering garbage.
    fn get(&self, key: &str) -> Result<Vec<u8>, ColdStoreError>;

    /// Deletes the object under `key`, if present. Idempotent: deleting an absent key is `Ok(())`,
    /// so a retried reap after a crash between the manifest update and the object delete is safe.
    ///
    /// # Errors
    /// Returns [`ColdStoreError::Io`] on a transport error.
    fn delete(&self, key: &str) -> Result<(), ColdStoreError>;

    /// Whether an object exists under `key`.
    ///
    /// # Errors
    /// Returns [`ColdStoreError::Io`] on a transport error.
    fn exists(&self, key: &str) -> Result<bool, ColdStoreError>;

    /// Lists every object key currently in the store, or `Ok(None)` for a backend that cannot
    /// enumerate cheaply. Used ONLY by the best-effort startup orphan-object sweep (#1153), which
    /// deletes the bounded object leak a crash mid-reap can leave (the object whose manifest entry
    /// was durably removed but whose delete never ran); a `None` simply skips that sweep — the leak
    /// stays bounded and harmless, exactly as before the sweep existed — so `None` is the safe
    /// default for any backend. The `s3` backend deliberately keeps the default: an S3 LIST needs
    /// the `ListObjectsV2` XML response the purpose-built client is designed NOT to parse (no XML
    /// dependency), and the sweep is an optimization, never correctness.
    ///
    /// # Errors
    /// Returns [`ColdStoreError::Io`] on a transport error.
    fn list(&self) -> Result<Option<Vec<String>>, ColdStoreError> {
        Ok(None)
    }
}

/// The [`ColdStore`] object key for the segment with this id: `seg-<16 hex>.obj`. The `.obj` suffix
/// (not `.log`) keeps a cold object from ever being mistaken for a live local segment even if a
/// backend directory were pointed at a data dir, and the fixed-width lowercase-hex id sorts and
/// round-trips exactly like [`crate::naming::segment_file_name`]. The backing store for a given log
/// is rooted per-log by the caller (the engine), so a bare segment-id key never collides across
/// logs.
#[must_use]
pub fn cold_object_name(segment_id: u64) -> String {
    format!("seg-{segment_id:016x}.obj")
}

/// The exact inverse of [`cold_object_name`]: the segment id parsed from a canonical cold-object
/// key, or `None` for any other shape (a foreign object, a wrong-width or non-lowercase-hex id).
/// Strict on purpose — the startup orphan-object sweep (#1153) classifies ONLY keys it can prove
/// are cold segment objects and leaves everything else untouched, so a foreign object sharing the
/// store's directory can never be swept.
#[must_use]
pub fn parse_cold_object_name(name: &str) -> Option<u64> {
    let hex = name.strip_prefix("seg-")?.strip_suffix(".obj")?;
    if hex.len() != 16 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// A local-directory [`ColdStore`]: each object is one file in a [`crate::fs::Filesystem`]. This is
/// the phase-1 backend — testable against the in-memory / fault-injecting filesystems and
/// deployable against a real directory (an [`crate::fs::StdFs`] rooted at a local path or an NFS
/// mount). A `put` fsyncs the object file and the directory, so an object is durable before the log
/// is told the upload succeeded.
///
/// It is generic over the filesystem so a test can inject faults (a failing `get`, a corrupt
/// object) exactly as the segment engine's tests do, and so the same code path serves both the
/// in-memory and the on-disk deployments.
pub struct FsColdStore<F: Filesystem> {
    fs: F,
}

impl<F: Filesystem> std::fmt::Debug for FsColdStore<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The filesystem handle is not necessarily `Debug`; a placeholder keeps `ColdStore: Debug`
        // (needed so `Log` — which holds an `Arc<dyn ColdStore>` — stays `Debug`) without a bound.
        f.debug_struct("FsColdStore").finish_non_exhaustive()
    }
}

impl<F: Filesystem> FsColdStore<F> {
    /// Wraps a filesystem as a cold store. The filesystem is expected to be rooted at this log's
    /// dedicated cold-storage location (the engine roots each log's store under its own subtree), so
    /// the flat [`cold_object_name`] keys never collide across logs.
    pub fn new(fs: F) -> FsColdStore<F> {
        FsColdStore { fs }
    }
}

impl<F: Filesystem> ColdStore for FsColdStore<F> {
    fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ColdStoreError> {
        // Open-or-create so a retried offload OVERWRITES the prior (possibly orphaned) object rather
        // than failing `AlreadyExists`: the key is idempotent by design.
        let file = match self.fs.create_new(key) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => self.fs.open(key)?,
            Err(e) => return Err(ColdStoreError::Io(e)),
        };
        file.write_all_at(bytes, 0)?;
        // Truncate any tail left by a longer prior object at this key, so the file is EXACTLY the new
        // bytes (a shorter re-offload never leaves stale trailing bytes a later get would read).
        file.set_len(bytes.len() as u64)?;
        // Durable before the log deletes the local segment: the file, then its directory entry.
        file.sync_all()?;
        self.fs.sync_dir()?;
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, ColdStoreError> {
        let file = match self.fs.open(key) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(ColdStoreError::NotFound {
                    key: key.to_string(),
                });
            }
            Err(e) => return Err(ColdStoreError::Io(e)),
        };
        let len = file.len()?;
        let len_usize = usize::try_from(len).map_err(|_| {
            ColdStoreError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "cold object length exceeds usize",
            ))
        })?;
        let mut buf = vec![0u8; len_usize];
        file.read_exact_at(&mut buf, 0)?;
        Ok(buf)
    }

    fn delete(&self, key: &str) -> Result<(), ColdStoreError> {
        match self.fs.remove(key) {
            Ok(()) => {
                self.fs.sync_dir()?;
                Ok(())
            }
            // Idempotent: an already-absent object is a successful delete (a retried reap).
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ColdStoreError::Io(e)),
        }
    }

    fn exists(&self, key: &str) -> Result<bool, ColdStoreError> {
        Ok(self.fs.exists(key)?)
    }

    fn list(&self) -> Result<Option<Vec<String>>, ColdStoreError> {
        // A directory-backed store CAN enumerate (one readdir), so the startup orphan-object sweep
        // (#1153) is exact here. Only regular file names are returned (the `Filesystem::list`
        // contract), each usable as an object key.
        Ok(Some(self.fs.list()?))
    }
}

// =================================================================================================
// S3 backend (#643 phase 2): a `ColdStore` speaking S3 directly, behind the OFF-BY-DEFAULT `s3`
// feature. This is a small, PURPOSE-BUILT S3 client — NOT a general object-storage crate — so it
// pulls no `ring`, no XML parser, and no new crate into the tree (ADR-0004: aws-lc-rs is the sole
// crypto provider). The four `ColdStore` verbs map to four S3 requests: PUT (upload), GET (download),
// DELETE (idempotent), HEAD (exists) — none needs an XML response body, so a non-2xx is a typed error
// read from the STATUS line, never a parsed error document.
//
// `S3ColdStore` is a drop-in `impl ColdStore`; the log's crash-safe offload/fetch/recover/reap
// machinery is UNCHANGED. See `tests/cold_s3.rs` (a mock S3 server) + the `SigV4` vector tests below.
// =================================================================================================
#[cfg(feature = "s3")]
pub use s3_backend::{S3ColdStore, S3ColdStoreConfig};

#[cfg(feature = "s3")]
mod s3_backend {
    use super::{ColdStore, ColdStoreError};
    use std::io;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};
    use zeroize::Zeroize;

    /// The default per-step network timeout for a connect (a hung/blackholed endpoint must NOT wedge
    /// the single-writer append actor). Overridable via [`S3ColdStoreConfig::connect_timeout`].
    const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    /// The default per-step network timeout for the HTTP request + response body. Overridable via
    /// [`S3ColdStoreConfig::request_timeout`].
    const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

    /// The AWS service name for the `SigV4` credential scope.
    const SERVICE: &str = "s3";
    /// The `SigV4` algorithm identifier.
    const ALGORITHM: &str = "AWS4-HMAC-SHA256";
    /// The final scope terminator.
    const AWS4_REQUEST: &str = "aws4_request";
    /// SHA-256 of the empty string — the `x-amz-content-sha256` for a bodyless GET/DELETE/HEAD.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Connection + credential parameters for the [`S3ColdStore`] backend (#643 phase 2). `FsColdStore`
    /// stays the default; this selects the S3 backend.
    #[derive(Clone, Default)]
    pub struct S3ColdStoreConfig {
        /// The S3 bucket the log's cold objects live in.
        pub bucket: String,
        /// An object-key prefix within the bucket (the per-log root — the engine gives each log its own
        /// prefix so the flat [`super::cold_object_name`] keys never collide across logs). May be empty.
        pub prefix: String,
        /// The AWS region (e.g. `us-east-1`) — part of the `SigV4` scope and the default endpoint host.
        pub region: String,
        /// An explicit endpoint URL for an S3-COMPATIBLE store (`MinIO`/Ceph/R2/`LocalStack`), e.g.
        /// `https://s3.example.com` or `http://127.0.0.1:9000`. `None` = real AWS S3
        /// (`s3.<region>.amazonaws.com`).
        pub endpoint: Option<String>,
        /// Path-style addressing (`/<bucket>/<key>`) vs virtual-hosted (`<bucket>.<host>/<key>`).
        /// `true` for most S3-compatible stores + `LocalStack`; real AWS accepts either.
        pub path_style: bool,
        /// The AWS access key id (`SigV4` credential).
        pub access_key_id: String,
        /// The AWS secret access key (`SigV4` signing secret). Redacted in `Debug`.
        pub secret_access_key: String,
        /// An optional session token for temporary/STS credentials (sent as `x-amz-security-token`).
        /// Redacted in `Debug`.
        pub session_token: Option<String>,
        /// The trust-anchor (CA) PEM bundle used to VERIFY the endpoint's certificate over HTTPS
        /// (e.g. the Amazon root CA chain, or the system bundle bytes). REQUIRED for an `https`
        /// endpoint; ignored for a plaintext `http` endpoint. Loading OS/bundled roots automatically
        /// is a documented follow-up.
        pub ca_pem: Option<Vec<u8>>,
        /// The bound on a single TCP connect + TLS handshake. A hung/blackholed endpoint (accepts the
        /// connection, never responds) must NEVER wedge the single-writer append actor, so every
        /// network step is time-bounded; on expiry the op fails with a RETRYABLE typed error (a
        /// timeout is never treated as "object absent"). `None` uses [`DEFAULT_CONNECT_TIMEOUT`] (30s).
        pub connect_timeout: Option<Duration>,
        /// The bound on the HTTP request send and on the response-body read (each separately). `None`
        /// uses [`DEFAULT_REQUEST_TIMEOUT`] (60s). See [`S3ColdStoreConfig::connect_timeout`].
        pub request_timeout: Option<Duration>,
    }

    impl std::fmt::Debug for S3ColdStoreConfig {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Redact the secret credential material (#882 redaction discipline): the secret key and
            // session token are never printed.
            f.debug_struct("S3ColdStoreConfig")
                .field("bucket", &self.bucket)
                .field("prefix", &self.prefix)
                .field("region", &self.region)
                .field("endpoint", &self.endpoint)
                .field("path_style", &self.path_style)
                .field("access_key_id", &self.access_key_id)
                .field("secret_access_key", &"<redacted>")
                .field(
                    "session_token",
                    &self.session_token.as_ref().map(|_| "<redacted>"),
                )
                .field("has_ca_pem", &self.ca_pem.is_some())
                .field("connect_timeout", &self.connect_timeout)
                .field("request_timeout", &self.request_timeout)
                .finish()
        }
    }

    /// Lowercase-hex encode.
    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    /// SHA-256 of `data`, lowercase hex (aws-lc-rs — no `ring`).
    fn sha256_hex(data: &[u8]) -> String {
        hex_lower(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data).as_ref())
    }

    /// HMAC-SHA256(`key`, `msg`) raw bytes (aws-lc-rs — no `ring`).
    fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
        let k = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
        aws_lc_rs::hmac::sign(&k, msg).as_ref().to_vec()
    }

    /// RFC 3986 percent-encode for the `SigV4` canonical URI. Leaves the unreserved set
    /// (`A-Z a-z 0-9 - . _ ~`) as-is; when `encode_slash` is false, `/` is also left (S3 path segments).
    fn uri_encode(input: &str, encode_slash: bool) -> String {
        const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut out = String::with_capacity(input.len());
        for &b in input.as_bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char);
                }
                b'/' if !encode_slash => out.push('/'),
                _ => {
                    out.push('%');
                    out.push(UPPER_HEX[(b >> 4) as usize] as char);
                    out.push(UPPER_HEX[(b & 0x0f) as usize] as char);
                }
            }
        }
        out
    }

    /// The `SigV4` signing key: the four-step HMAC-SHA256 derivation
    /// `kSigning = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`.
    fn signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
        let mut seed = format!("AWS4{secret}");
        let mut k_date = hmac_sha256(seed.as_bytes(), date_stamp.as_bytes());
        let mut k_region = hmac_sha256(&k_date, region.as_bytes());
        let mut k_service = hmac_sha256(&k_region, service.as_bytes());
        let k_signing = hmac_sha256(&k_service, AWS4_REQUEST.as_bytes());
        // Defense-in-depth: wipe every intermediate that is derived directly from the secret.
        seed.zeroize();
        k_date.zeroize();
        k_region.zeroize();
        k_service.zeroize();
        k_signing
    }

    /// Everything needed to compute one `SigV4` signature. Generic over the header set + service so the
    /// AWS published test vectors (service `service`/`iam`) and the S3 client (service `s3`) both drive
    /// the SAME code — the load-bearing correctness path.
    struct SigningRequest<'a> {
        method: &'a str,
        /// The already-percent-encoded canonical URI (also the on-wire request target).
        canonical_uri: &'a str,
        /// The canonical query string (empty for the four `ColdStore` verbs).
        canonical_query: &'a str,
        /// The request headers to sign, `(lowercase-name, value)`; MUST include `host`.
        headers: &'a [(String, String)],
        /// Hex SHA-256 of the payload (the `x-amz-content-sha256` value).
        payload_sha256: &'a str,
        /// `YYYYMMDDTHHMMSSZ`.
        amz_date: &'a str,
        /// `YYYYMMDD`.
        date_stamp: &'a str,
        region: &'a str,
        service: &'a str,
        access_key_id: &'a str,
        secret_access_key: &'a str,
    }

    impl SigningRequest<'_> {
        /// Computes the `Authorization` header value (and the signed-headers list) per AWS `SigV4`.
        fn authorization(&self) -> String {
            // Canonical + signed headers: sort by lowercase name, trim values.
            let mut hs: Vec<(String, String)> = self
                .headers
                .iter()
                .map(|(n, v)| (n.to_ascii_lowercase(), v.trim().to_string()))
                .collect();
            hs.sort_by(|a, b| a.0.cmp(&b.0));
            let mut canonical_headers = String::new();
            for (n, v) in &hs {
                canonical_headers.push_str(n);
                canonical_headers.push(':');
                canonical_headers.push_str(v);
                canonical_headers.push('\n');
            }
            let signed_headers = hs
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(";");

            let canonical_request = format!(
                "{}\n{}\n{}\n{}\n{}\n{}",
                self.method,
                self.canonical_uri,
                self.canonical_query,
                canonical_headers,
                signed_headers,
                self.payload_sha256,
            );
            let scope = format!(
                "{}/{}/{}/{}",
                self.date_stamp, self.region, self.service, AWS4_REQUEST
            );
            let string_to_sign = format!(
                "{}\n{}\n{}\n{}",
                ALGORITHM,
                self.amz_date,
                scope,
                sha256_hex(canonical_request.as_bytes()),
            );
            let mut key = signing_key(
                self.secret_access_key,
                self.date_stamp,
                self.region,
                self.service,
            );
            let signature = hex_lower(&hmac_sha256(&key, string_to_sign.as_bytes()));
            key.zeroize(); // wipe the derived signing key once the signature is computed
            format!(
                "{} Credential={}/{}, SignedHeaders={}, Signature={}",
                ALGORITHM, self.access_key_id, scope, signed_headers, signature
            )
        }
    }

    /// Formats a wall-clock instant as the `SigV4` `(amz_date = YYYYMMDDTHHMMSSZ, date_stamp = YYYYMMDD)`
    /// pair, in UTC, with no external calendar dependency.
    fn format_amz_date(now: SystemTime) -> (String, String) {
        let secs = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let days = i64::try_from(secs / 86_400).unwrap_or(0);
        let rem = secs % 86_400;
        let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
        let (year, month, day) = civil_from_days(days);
        (
            format!("{year:04}{month:02}{day:02}T{hour:02}{min:02}{sec:02}Z"),
            format!("{year:04}{month:02}{day:02}"),
        )
    }

    /// Days-since-Unix-epoch -> `(year, month, day)` (UTC), Howard Hinnant's `civil_from_days`.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn civil_from_days(days: i64) -> (i64, u32, u32) {
        let z = days + 719_468;
        let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
        let doe = z - era * 146_097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
        let year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
        let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
        (if month <= 2 { year + 1 } else { year }, month, day)
    }

    /// A `ColdStore` that stores each offloaded segment as an S3 object (#643 phase 2). Whole-object
    /// PUT/GET/DELETE/HEAD, `SigV4`-signed over aws-lc-rs, HTTPS over rustls + aws-lc-rs. The async S3
    /// requests are driven from the sync `ColdStore` trait by one tokio CURRENT-THREAD runtime +
    /// `block_on` (safe under the log's single-writer append actor — a plain sync thread never inside a
    /// runtime, so `block_on` never re-enters a running one; the actor serializes cold-store calls).
    pub struct S3ColdStore {
        config: S3ColdStoreConfig,
        /// The rustls client config for HTTPS (`None` for a plaintext `http` endpoint).
        tls: Option<Arc<rustls::ClientConfig>>,
        /// Whether the endpoint is HTTPS.
        https: bool,
        /// The connect + `Host`-header + SNI host (already accounts for path-style vs virtual-hosted).
        host: String,
        /// The connect port.
        port: u16,
        /// The resolved bound on a connect + TLS handshake.
        connect_timeout: Duration,
        /// The resolved bound on the request send and the response-body read.
        request_timeout: Duration,
        runtime: tokio::runtime::Runtime,
    }

    impl std::fmt::Debug for S3ColdStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("S3ColdStore")
                .field("config", &self.config)
                .field("https", &self.https)
                .field("host", &self.host)
                .field("port", &self.port)
                .finish_non_exhaustive()
        }
    }

    /// A small typed `io::Error` for an S3-backend failure (mapped to [`ColdStoreError::Io`]).
    fn io_error(msg: impl Into<String>) -> ColdStoreError {
        ColdStoreError::Io(io::Error::other(msg.into()))
    }

    /// A typed, RETRYABLE timeout error for a hung network step. Mapped to [`ColdStoreError::Io`] with
    /// [`io::ErrorKind::TimedOut`] — NEVER [`ColdStoreError::NotFound`] (a timeout is not "object
    /// absent"), so offload retries next tick and a fetch-on-read fails closed-retryable, never
    /// deleting the local segment.
    fn timeout_error(op: &str, dur: Duration) -> ColdStoreError {
        ColdStoreError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("S3 {op} timed out after {dur:?}"),
        ))
    }

    /// Whether `host` is loopback/local (exempt from the plaintext-credentials warning).
    fn host_is_local(host: &str) -> bool {
        host == "localhost" || host == "::1" || host.starts_with("127.")
    }

    impl S3ColdStore {
        /// Builds an S3 cold-store backend from `config` (#643 phase 2). This is the production tiering
        /// backend, selected by config in place of the default [`FsColdStore`].
        ///
        /// # Errors
        /// [`ColdStoreError::Io`] if the endpoint URL is malformed, if an `https` endpoint is configured
        /// without a `ca_pem` trust anchor (or the PEM has none), or if the tokio runtime cannot build.
        pub fn new(config: S3ColdStoreConfig) -> Result<S3ColdStore, ColdStoreError> {
            let (https, endpoint_host, port) = parse_endpoint(&config)?;
            // Path-style => connect to the endpoint host, bucket goes in the path. Virtual-hosted =>
            // the bucket is a host-name label. The chosen host is the Host header + SNI + connect host.
            let host = if config.path_style {
                endpoint_host
            } else {
                format!("{}.{}", config.bucket, endpoint_host)
            };
            let tls = if https {
                let ca = config.ca_pem.as_deref().ok_or_else(|| {
                    io_error("S3 cold store over https requires a ca_pem trust anchor")
                })?;
                Some(build_client_config(ca)?)
            } else {
                None
            };
            // #557-style warning: static credentials sent over a plaintext http:// endpoint to a
            // REMOTE host are exposed on the wire. Real AWS (endpoint None) is always https; this only
            // catches a misconfigured explicit http:// remote (a local dev endpoint is exempt).
            if !https && !config.access_key_id.is_empty() && !host_is_local(&host) {
                tracing::warn!(
                    host = %host,
                    "S3 cold store is sending credentials over a PLAINTEXT http:// endpoint to a \
                     non-local host; the access key + SigV4 signature are exposed on the wire — use \
                     an https endpoint in production"
                );
            }
            let connect_timeout = config.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);
            let request_timeout = config.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(ColdStoreError::Io)?;
            Ok(S3ColdStore {
                config,
                tls,
                https,
                host,
                port,
                connect_timeout,
                request_timeout,
                runtime,
            })
        }

        /// The full S3 object key for a bare `ColdStore` key: `<prefix>/<key>` (or `<key>` if no prefix).
        fn object_key(&self, key: &str) -> String {
            let prefix = self.config.prefix.trim_matches('/');
            if prefix.is_empty() {
                key.to_string()
            } else {
                format!("{prefix}/{key}")
            }
        }

        /// The request path (path-style prepends the bucket), percent-encoded as the canonical URI.
        fn request_path(&self, key: &str) -> String {
            let object_key = self.object_key(key);
            let raw = if self.config.path_style {
                format!("/{}/{}", self.config.bucket, object_key)
            } else {
                format!("/{object_key}")
            };
            uri_encode(&raw, false)
        }

        /// Signs + sends one S3 request, returning `(status, response_body)`. A transport / TLS /
        /// connect failure is a [`ColdStoreError::Io`]; HTTP status handling is the caller's.
        async fn send(
            &self,
            method: &str,
            key: &str,
            body: Vec<u8>,
        ) -> Result<(http::StatusCode, Vec<u8>), ColdStoreError> {
            let canonical_uri = self.request_path(key);
            let payload_sha256 = if body.is_empty() {
                EMPTY_SHA256.to_string()
            } else {
                sha256_hex(&body)
            };
            let (amz_date, date_stamp) = format_amz_date(SystemTime::now());

            let mut headers = vec![
                ("host".to_string(), self.host.clone()),
                ("x-amz-content-sha256".to_string(), payload_sha256.clone()),
                ("x-amz-date".to_string(), amz_date.clone()),
            ];
            if let Some(token) = &self.config.session_token {
                headers.push(("x-amz-security-token".to_string(), token.clone()));
            }
            let authorization = SigningRequest {
                method,
                canonical_uri: &canonical_uri,
                canonical_query: "",
                headers: &headers,
                payload_sha256: &payload_sha256,
                amz_date: &amz_date,
                date_stamp: &date_stamp,
                region: &self.config.region,
                service: SERVICE,
                access_key_id: &self.config.access_key_id,
                secret_access_key: &self.config.secret_access_key,
            }
            .authorization();

            let mut builder = http::Request::builder().method(method).uri(&canonical_uri);
            for (name, value) in &headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            builder = builder.header("authorization", authorization);
            let request = builder
                .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                .map_err(|e| io_error(format!("building the S3 request failed: {e}")))?;

            self.round_trip(request).await
        }

        /// Opens a fresh connection (TCP, + TLS for https), runs the HTTP/1.1 exchange, collects the
        /// response body. EVERY network step is time-bounded so a hung/blackholed endpoint cannot wedge
        /// the single-writer append actor; on expiry the step returns a RETRYABLE typed timeout error.
        async fn round_trip(
            &self,
            request: http::Request<http_body_util::Full<bytes::Bytes>>,
        ) -> Result<(http::StatusCode, Vec<u8>), ColdStoreError> {
            let connect_to = self.connect_timeout;
            let request_to = self.request_timeout;

            // 1. TCP connect (bounded).
            let tcp = tokio::time::timeout(
                connect_to,
                tokio::net::TcpStream::connect((self.host.as_str(), self.port)),
            )
            .await
            .map_err(|_| timeout_error("connect", connect_to))?
            .map_err(ColdStoreError::Io)?;

            // 2. TLS handshake for https (bounded).
            let conn = if self.https {
                let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
                    .map_err(|_| io_error("the S3 endpoint host is not a valid TLS server name"))?;
                let tls = self
                    .tls
                    .clone()
                    .ok_or_else(|| io_error("S3 https endpoint has no TLS config"))?;
                let stream = tokio::time::timeout(
                    connect_to,
                    tokio_rustls::TlsConnector::from(tls).connect(server_name, tcp),
                )
                .await
                .map_err(|_| timeout_error("TLS handshake", connect_to))?
                .map_err(ColdStoreError::Io)?;
                Connection::Tls(Box::new(stream))
            } else {
                Connection::Plain(tcp)
            };

            // 3. HTTP handshake + request + body, driven concurrently with the connection task. The
            // driver is ABORTED on EVERY exit path (success or error) so no parked task lingers for the
            // next `block_on`.
            let (mut sender, driver) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(conn))
                    .await
                    .map_err(|e| io_error(format!("S3 HTTP handshake failed: {e}")))?;
            let driver = tokio::spawn(async move {
                let _ = driver.await;
            });
            let result = self.exchange(&mut sender, request, request_to).await;
            driver.abort();
            result
        }

        /// Sends the request and reads the response body, each bounded by `request_to`.
        async fn exchange(
            &self,
            sender: &mut hyper::client::conn::http1::SendRequest<
                http_body_util::Full<bytes::Bytes>,
            >,
            request: http::Request<http_body_util::Full<bytes::Bytes>>,
            request_to: Duration,
        ) -> Result<(http::StatusCode, Vec<u8>), ColdStoreError> {
            use http_body_util::BodyExt;

            let response = tokio::time::timeout(request_to, sender.send_request(request))
                .await
                .map_err(|_| timeout_error("request", request_to))?
                .map_err(|e| io_error(format!("S3 request failed: {e}")))?;
            let status = response.status();
            let body = tokio::time::timeout(request_to, response.into_body().collect())
                .await
                .map_err(|_| timeout_error("response body", request_to))?
                .map_err(|e| io_error(format!("reading the S3 response body failed: {e}")))?
                .to_bytes()
                .to_vec();
            Ok((status, body))
        }

        /// Blocks the calling (sync append-actor) thread on `fut` via the owned current-thread runtime.
        fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
            self.runtime.block_on(fut)
        }
    }

    /// A non-2xx S3 status turned into a typed transport error (the body may carry an S3 XML error
    /// document; we surface the STATUS, not a parse of it — no XML dependency).
    fn status_error(op: &str, key: &str, status: http::StatusCode) -> ColdStoreError {
        io_error(format!(
            "S3 {op} of {key} returned HTTP {} ({})",
            status.as_u16(),
            status.canonical_reason().unwrap_or("unknown")
        ))
    }

    impl ColdStore for S3ColdStore {
        fn put(&self, key: &str, bytes: &[u8]) -> Result<(), ColdStoreError> {
            // A 2xx PUT = the object is DURABLE in S3 before Ok (S3 acks a PUT only once the object is
            // durably stored + cross-AZ replicated) — the ColdStore durability contract the log relies
            // on before deleting the local segment. Overwrites any existing object (idempotent by key).
            let (status, body) = self.block_on(self.send("PUT", key, bytes.to_vec()))?;
            if status.is_success() {
                Ok(())
            } else {
                Err(status_error("PUT", key, status).with_body(&body))
            }
        }

        fn get(&self, key: &str) -> Result<Vec<u8>, ColdStoreError> {
            let (status, body) = self.block_on(self.send("GET", key, Vec::new()))?;
            if status.is_success() {
                // The caller re-verifies (segment header/footer/CRC) before trusting these bytes.
                Ok(body)
            } else if status == http::StatusCode::NOT_FOUND {
                Err(ColdStoreError::NotFound {
                    key: key.to_string(),
                })
            } else {
                Err(status_error("GET", key, status))
            }
        }

        fn delete(&self, key: &str) -> Result<(), ColdStoreError> {
            let (status, _) = self.block_on(self.send("DELETE", key, Vec::new()))?;
            // Idempotent: 2xx OR a 404 (already gone) is success. A real 403/401/5xx is surfaced, NOT
            // masked as success — a permission/transport failure must not look like a completed reap.
            if status.is_success() || status == http::StatusCode::NOT_FOUND {
                Ok(())
            } else {
                Err(status_error("DELETE", key, status))
            }
        }

        fn exists(&self, key: &str) -> Result<bool, ColdStoreError> {
            let (status, _) = self.block_on(self.send("HEAD", key, Vec::new()))?;
            if status.is_success() {
                Ok(true)
            } else if status == http::StatusCode::NOT_FOUND {
                Ok(false)
            } else {
                Err(status_error("HEAD", key, status))
            }
        }
    }

    impl ColdStoreError {
        /// Appends a short, non-secret snippet of the S3 error body to an IO error, for diagnosis.
        fn with_body(self, body: &[u8]) -> ColdStoreError {
            match self {
                ColdStoreError::Io(e) => {
                    let snippet: String = String::from_utf8_lossy(body).chars().take(200).collect();
                    ColdStoreError::Io(io::Error::new(
                        e.kind(),
                        format!("{e}; body: {}", snippet.trim()),
                    ))
                }
                other => other,
            }
        }
    }

    /// Parses `(https, host, port)` from the config's endpoint (or the AWS default for `None`).
    fn parse_endpoint(config: &S3ColdStoreConfig) -> Result<(bool, String, u16), ColdStoreError> {
        match &config.endpoint {
            None => Ok((true, format!("s3.{}.amazonaws.com", config.region), 443)),
            Some(endpoint) => {
                let (scheme, rest) = endpoint
                    .split_once("://")
                    .ok_or_else(|| io_error("the S3 endpoint must be scheme://host[:port]"))?;
                let https = scheme.eq_ignore_ascii_case("https");
                // Strip any path; keep host[:port].
                let authority = rest.split('/').next().unwrap_or(rest);
                let (host, port) = match authority.split_once(':') {
                    Some((h, p)) => (
                        h.to_string(),
                        p.parse::<u16>()
                            .map_err(|_| io_error("the S3 endpoint port is not a number"))?,
                    ),
                    None => (authority.to_string(), if https { 443 } else { 80 }),
                };
                if host.is_empty() {
                    return Err(io_error("the S3 endpoint host is empty"));
                }
                Ok((https, host, port))
            }
        }
    }

    /// Builds the rustls 1.3-only, aws-lc-rs `ClientConfig` verifying the endpoint against `ca_pem`
    /// (mirrors the client TLS builder; never `ring`, never insecure-skip-verify).
    fn build_client_config(ca_pem: &[u8]) -> Result<Arc<rustls::ClientConfig>, ColdStoreError> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::CertificateDer;

        let anchors = CertificateDer::pem_slice_iter(ca_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| io_error("the S3 ca_pem could not be parsed as PEM certificates"))?;
        let mut roots = rustls::RootCertStore::empty();
        let (added, _ignored) = roots.add_parsable_certificates(anchors);
        if added == 0 {
            return Err(io_error("the S3 ca_pem contained no usable trust anchor"));
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| io_error(format!("building the S3 TLS config failed: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    /// A plaintext TCP or a rustls TLS stream, unified so hyper can drive either. Both variants are
    /// `Unpin`, so the pin projection is a simple `get_mut` + `Pin::new` delegation.
    enum Connection {
        Plain(tokio::net::TcpStream),
        Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    }

    impl tokio::io::AsyncRead for Connection {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            match self.get_mut() {
                Connection::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
                Connection::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_read(cx, buf),
            }
        }
    }

    impl tokio::io::AsyncWrite for Connection {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            match self.get_mut() {
                Connection::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
                Connection::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_write(cx, buf),
            }
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            match self.get_mut() {
                Connection::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
                Connection::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_flush(cx),
            }
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            match self.get_mut() {
                Connection::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
                Connection::Tls(s) => std::pin::Pin::new(s.as_mut()).poll_shutdown(cx),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // AWS-published "deriving the signing key" example (`SigV4` docs): PROVES the four-step HMAC
        // key-derivation chain byte-for-byte.
        #[test]
        fn signing_key_matches_aws_documented_vector() {
            let key = signing_key(
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                "20150830",
                "us-east-1",
                "iam",
            );
            assert_eq!(
                hex_lower(&key),
                "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
            );
        }

        // AWS `SigV4` test suite `get-vanilla`: PROVES the full canonical-request -> string-to-sign ->
        // signature pipeline byte-for-byte against AWS's published expected signature.
        #[test]
        fn get_vanilla_signature_matches_aws_test_suite() {
            let headers = vec![
                ("host".to_string(), "example.amazonaws.com".to_string()),
                ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
            ];
            let auth = SigningRequest {
                method: "GET",
                canonical_uri: "/",
                canonical_query: "",
                headers: &headers,
                payload_sha256: EMPTY_SHA256,
                amz_date: "20150830T123600Z",
                date_stamp: "20150830",
                region: "us-east-1",
                service: "service",
                access_key_id: "AKIDEXAMPLE",
                secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            }
            .authorization();
            assert_eq!(
                auth,
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
                 SignedHeaders=host;x-amz-date, \
                 Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
            );
        }

        // AWS S3 docs' "Transferring Payload in a Single Chunk" PUT example: PROVES the PUT-with-body
        // path the client actually uses — method PUT, a NON-EMPTY payload hash (`x-amz-content-sha256`
        // computed here from the real payload), a key with a percent-encoded special char
        // (`/test%24file.text`), service `s3`, and the S3 example's `/`-in-secret credential — against
        // AWS's published Signature byte-for-byte.
        #[test]
        fn put_object_signature_matches_aws_s3_single_chunk_example() {
            // The exact payload from the AWS example; its SHA-256 is the `x-amz-content-sha256`.
            let content_sha = sha256_hex(b"Welcome to Amazon S3.");
            let headers = vec![
                (
                    "date".to_string(),
                    "Fri, 24 May 2013 00:00:00 GMT".to_string(),
                ),
                (
                    "host".to_string(),
                    "examplebucket.s3.amazonaws.com".to_string(),
                ),
                ("x-amz-content-sha256".to_string(), content_sha.clone()),
                ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
                (
                    "x-amz-storage-class".to_string(),
                    "REDUCED_REDUNDANCY".to_string(),
                ),
            ];
            let auth = SigningRequest {
                method: "PUT",
                canonical_uri: "/test%24file.text",
                canonical_query: "",
                headers: &headers,
                payload_sha256: &content_sha,
                amz_date: "20130524T000000Z",
                date_stamp: "20130524",
                region: "us-east-1",
                service: "s3",
                access_key_id: "AKIAIOSFODNN7EXAMPLE",
                secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            }
            .authorization();
            assert_eq!(
                auth,
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
                 SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, \
                 Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            );
        }

        #[test]
        fn sha256_and_uri_encode_are_correct() {
            assert_eq!(sha256_hex(b""), EMPTY_SHA256);
            // Unreserved chars pass through; a space and a colon are percent-encoded; '/' is kept.
            assert_eq!(uri_encode("/a b/seg-01.obj", false), "/a%20b/seg-01.obj");
            assert_eq!(uri_encode("a/b", true), "a%2Fb");
        }

        #[test]
        fn civil_from_days_matches_known_dates() {
            assert_eq!(civil_from_days(0), (1970, 1, 1)); // Unix epoch
            assert_eq!(civil_from_days(10_957), (2000, 1, 1)); // 30y + 7 leap days
                                                               // The get-vanilla date: 20150830 is 16677 days after the epoch.
            assert_eq!(civil_from_days(16_677), (2015, 8, 30));
        }
    }
}

/// The tiered-storage policy (#643): whether offload is enabled, and how many recent sealed segments
/// stay local. Follows the `0`-means-off / opt-in convention of the other storage knobs, and is
/// `Copy` so it threads through the config plumbing like [`crate::log::LogConfig`]. DISABLED by
/// default: a broker that never enables it writes zero new bytes and touches no new files (the
/// conformance byte-identity guarantee).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColdStorageConfig {
    /// Whether cold-segment offload is active. When `false` (the default), the log never offloads, so
    /// [`crate::log::Log::offload_cold_segments`] is a no-op and no manifest file is created.
    pub enabled: bool,
    /// The number of most-recent sealed segments kept LOCAL (never offloaded). Only sealed segments
    /// OLDER than the newest `keep_recent_segments` are eligible, so a lagging-but-live consumer
    /// reading the recent tail stays on local disk. See [`DEFAULT_KEEP_RECENT_SEGMENTS`].
    pub keep_recent_segments: u64,
}

impl Default for ColdStorageConfig {
    fn default() -> ColdStorageConfig {
        ColdStorageConfig {
            enabled: false,
            keep_recent_segments: DEFAULT_KEEP_RECENT_SEGMENTS,
        }
    }
}

impl ColdStorageConfig {
    /// An ENABLED policy keeping `keep_recent_segments` recent sealed segments local. The
    /// engine-facing constructor (mirroring `CompactionConfig::enabled`): the backend store is
    /// supplied separately at [`crate::log::Log::set_cold_store`].
    #[must_use]
    pub fn enabled(keep_recent_segments: u64) -> ColdStorageConfig {
        ColdStorageConfig {
            enabled: true,
            keep_recent_segments,
        }
    }

    /// Whether offload is active.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// One durable manifest entry: an offloaded sealed segment and the metadata a recovery (which cannot
/// open the absent local file) needs to splice it back into the chain, plus the CRC a fetch
/// re-verifies (#643).
///
/// Everything here is derived from the sealed segment at offload time and is enough to (a) satisfy
/// recovery's base-offset/base-seq contiguity fold without the file, (b) publish the segment into
/// the off-actor read plane as a fetch-through-actor slot, and (c) fail a corrupt fetch closed
/// (`byte_len` + `crc32c` pin the exact bytes uploaded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ColdEntry {
    /// The segment id (its `seg-<id>.log` file-name component and its [`cold_object_name`] key).
    pub(crate) id: u64,
    /// The log offset of the segment's first record (the chain-contiguity anchor).
    pub(crate) base_offset: u64,
    /// The sequence of the segment's first record (the chain-contiguity anchor's sibling).
    pub(crate) base_seq: u64,
    /// How many records the segment holds (advances the running base across the offloaded hole).
    pub(crate) record_count: u64,
    /// The maximum producer timestamp across the segment's records (the age-retention input).
    pub(crate) max_timestamp_ms: u64,
    /// The exact byte length of the segment file that was uploaded (a fetch reads exactly this).
    pub(crate) byte_len: u64,
    /// CRC32C over the whole uploaded segment file (header + records + footer). A fetch recomputes
    /// this and fails closed on a mismatch, so a corrupt object store never delivers garbage.
    pub(crate) crc32c: u32,
    /// Whether the offloaded segment is a COMPACTED (v2) segment. Always `false` in phase 1.
    pub(crate) compacted: bool,
}

impl ColdEntry {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.base_offset.to_le_bytes());
        out.extend_from_slice(&self.base_seq.to_le_bytes());
        out.extend_from_slice(&self.record_count.to_le_bytes());
        out.extend_from_slice(&self.max_timestamp_ms.to_le_bytes());
        out.extend_from_slice(&self.byte_len.to_le_bytes());
        out.extend_from_slice(&self.crc32c.to_le_bytes());
        let flags = if self.compacted { FLAG_COMPACTED } else { 0 };
        out.push(flags);
    }

    fn decode(bytes: &[u8]) -> Option<ColdEntry> {
        if bytes.len() != ENTRY_LEN {
            return None;
        }
        let u64_at = |off: usize| -> u64 {
            u64::from_le_bytes(bytes[off..off + 8].try_into().expect("8 bytes in range"))
        };
        let id = u64_at(0);
        let base_offset = u64_at(8);
        let base_seq = u64_at(16);
        let record_count = u64_at(24);
        let max_timestamp_ms = u64_at(32);
        let byte_len = u64_at(40);
        let crc32c = u32::from_le_bytes(bytes[48..52].try_into().expect("4 bytes in range"));
        let flags = bytes[52];
        Some(ColdEntry {
            id,
            base_offset,
            base_seq,
            record_count,
            max_timestamp_ms,
            byte_len,
            crc32c,
            compacted: flags & FLAG_COMPACTED != 0,
        })
    }
}

/// The durable per-log cold-segment manifest: a dual-slot, CRC-checked [`ColdManifestCheckpoint`]
/// holding the full set of offloaded segments (#643). It is the source of truth for "which absent
/// segment files are REMOTE (offloaded), not lost", read at [`crate::log::Log::open`] so recovery
/// treats an offloaded segment as PRESENT rather than a torn gap, and rewritten+fsynced on every
/// offload and every reap of a remote segment.
///
/// Like the subject-binding table and the shared-WAL reap floor, its payload is LOAD-BEARING: an
/// acked REMOTE transition that a restart could not read back would strand the local-deleted
/// segment, so a torn (never-committed) write reverts to the prior durable manifest (the dual-slot
/// discipline) and a CRC-valid-but-UNDECODABLE payload fails the open closed rather than silently
/// dropping remote pointers.
pub(crate) struct ColdManifest<F: RandomAccessFile> {
    checkpoint: ColdManifestCheckpoint<F>,
    entries: BTreeMap<u64, ColdEntry>,
}

impl<F: RandomAccessFile> std::fmt::Debug for ColdManifest<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Unconditional (no `F: Debug` bound) so `Log`'s derived `Debug` holds for every `F::File`.
        f.debug_struct("ColdManifest")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl<F: RandomAccessFile> ColdManifest<F> {
    /// Opens (and recovers the entries from) an existing manifest file. A fresh/torn (Empty) file
    /// recovers as an empty manifest; a payload that is present but undecodable fails closed
    /// ([`StorageError::ColdManifestCorrupt`]); externally-damaged dual slots are surfaced on the
    /// `ironbus_checkpoint_damaged_total{artifact="cold_manifest"}` counter and then recovered as
    /// empty (the #1142 discipline).
    ///
    /// # Errors
    /// Returns [`StorageError::ColdManifestCorrupt`] on a CRC-valid but structurally invalid payload,
    /// or an IO error.
    pub(crate) fn open(file: F) -> Result<ColdManifest<F>, StorageError> {
        let (checkpoint, recovered) = ColdManifestCheckpoint::open(file)?;
        if recovered.is_damaged() {
            record_checkpoint_damage(CheckpointArtifact::ColdManifest);
        }
        let entries = match recovered {
            RecoveredCheckpoint::Valid(payload) => Self::decode_payload(&payload)?,
            // Empty (fresh/torn-first) or Damaged (surfaced above): recover as no offloaded segments.
            RecoveredCheckpoint::Empty | RecoveredCheckpoint::Damaged => BTreeMap::new(),
        };
        Ok(ColdManifest {
            checkpoint,
            entries,
        })
    }

    /// Decodes a manifest payload into its entry map, fail-closed on any structural inconsistency.
    fn decode_payload(payload: &[u8]) -> Result<BTreeMap<u64, ColdEntry>, StorageError> {
        if payload.len() < HEADER_LEN
            || payload[0..4] != COLD_MANIFEST_MAGIC
            || payload[4] > COLD_MANIFEST_VERSION
        {
            return Err(StorageError::ColdManifestCorrupt);
        }
        let count =
            u32::from_le_bytes(payload[5..9].try_into().expect("4 bytes in range")) as usize;
        let body = &payload[HEADER_LEN..];
        if body.len() != count * ENTRY_LEN {
            return Err(StorageError::ColdManifestCorrupt);
        }
        let mut entries = BTreeMap::new();
        for chunk in body.chunks_exact(ENTRY_LEN) {
            let entry = ColdEntry::decode(chunk).ok_or(StorageError::ColdManifestCorrupt)?;
            entries.insert(entry.id, entry);
        }
        Ok(entries)
    }

    /// Encodes the current entry set into a manifest payload (id-ascending, deterministic).
    fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.entries.len() * ENTRY_LEN);
        out.extend_from_slice(&COLD_MANIFEST_MAGIC);
        out.push(COLD_MANIFEST_VERSION);
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for entry in self.entries.values() {
            entry.encode_into(&mut out);
        }
        out
    }

    /// The offloaded entry for `id`, if the segment is REMOTE.
    pub(crate) fn get(&self, id: u64) -> Option<&ColdEntry> {
        self.entries.get(&id)
    }

    /// Whether `id` is recorded REMOTE.
    pub(crate) fn contains(&self, id: u64) -> bool {
        self.entries.contains_key(&id)
    }

    /// The full offloaded set, id-ascending. Used by recovery to splice remote segments into the
    /// chain and by the read plane to publish them as fetch-through-actor slots.
    pub(crate) fn entries(&self) -> &BTreeMap<u64, ColdEntry> {
        &self.entries
    }

    /// Records `entry` REMOTE and durably rewrites the manifest (fsync). This is the commit point of
    /// an offload: it returns only after the REMOTE transition is durable, so the caller may then
    /// delete the local segment file. A payload that would exceed the slot cap is REFUSED
    /// fail-closed ([`StorageError::ColdManifestFull`]) with the prior manifest left intact, so the
    /// offload simply does not advance rather than writing a truncated manifest.
    ///
    /// # Errors
    /// [`StorageError::ColdManifestFull`] if the manifest is at capacity, or an IO error.
    pub(crate) fn insert(&mut self, entry: ColdEntry) -> Result<(), StorageError> {
        let previous = self.entries.insert(entry.id, entry);
        match self.persist() {
            Ok(()) => Ok(()),
            Err(e) => {
                // Roll the in-memory map back to its durable state so it never runs ahead of disk.
                match previous {
                    Some(prev) => self.entries.insert(entry.id, prev),
                    None => self.entries.remove(&entry.id),
                };
                Err(e)
            }
        }
    }

    /// Removes `id` from the manifest and durably rewrites it (fsync). This is the FIRST step of
    /// reaping a remote segment: once it returns the segment is no longer recorded REMOTE, so a
    /// later object delete that a crash interrupts leaves at worst a bounded orphan object (swept by
    /// a follow-up), never a dangling REMOTE pointer to a deleted object. A no-op (returns `Ok`) if
    /// `id` was not recorded.
    ///
    /// # Errors
    /// An IO error (removal shrinks the payload, so it never trips the cap).
    pub(crate) fn remove(&mut self, id: u64) -> Result<(), StorageError> {
        let Some(prev) = self.entries.remove(&id) else {
            return Ok(());
        };
        match self.persist() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.entries.insert(id, prev);
                Err(e)
            }
        }
    }

    /// Durably (fsync) rewrites the whole manifest from the current entry set.
    fn persist(&mut self) -> Result<(), StorageError> {
        let payload = self.encode_payload();
        if payload.len() > COLD_MANIFEST_PAYLOAD {
            return Err(StorageError::ColdManifestFull);
        }
        self.checkpoint.write(&payload)
    }

    /// The number of offloaded segments recorded (the tiered-storage depth).
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// The number of offloaded segments recorded.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::FaultFs;
    use crate::fs::InMemoryFs;
    use std::sync::Arc;

    fn open_manifest(fs: &InMemoryFs) -> ColdManifest<Arc<crate::io::InMemoryFile>> {
        let file = if fs.exists(COLD_MANIFEST_FILE).unwrap() {
            fs.open(COLD_MANIFEST_FILE).unwrap()
        } else {
            fs.create_new(COLD_MANIFEST_FILE).unwrap()
        };
        ColdManifest::open(file).unwrap()
    }

    fn sample_entry(id: u64) -> ColdEntry {
        ColdEntry {
            id,
            base_offset: id * 100,
            base_seq: id * 100,
            record_count: 100,
            max_timestamp_ms: 1_700_000_000_000 + id,
            byte_len: 4096 + id,
            crc32c: 0xDEAD_BEEF ^ u32::try_from(id).unwrap_or(0),
            compacted: false,
        }
    }

    #[test]
    fn cold_object_name_is_fixed_width_hex_and_not_a_segment() {
        assert_eq!(cold_object_name(1), "seg-0000000000000001.obj");
        assert_eq!(cold_object_name(0xABCD), "seg-000000000000abcd.obj");
        // The `.obj` suffix keeps it out of segment enumeration.
        assert_eq!(
            crate::naming::parse_segment_file_name(&cold_object_name(1)),
            None
        );
    }

    #[test]
    fn parse_cold_object_name_is_the_strict_inverse_and_rejects_foreign() {
        // Round-trips every canonical key (#1153: the orphan-object sweep's classification input).
        for id in [0u64, 1, 0xABCD, u64::MAX] {
            assert_eq!(parse_cold_object_name(&cold_object_name(id)), Some(id));
        }
        // Foreign shapes never parse, so the sweep can never classify (or delete) them: a live
        // segment file name, wrong width, uppercase hex, non-hex, or an unrelated file.
        for bad in [
            "seg-0000000000000001.log",
            "seg-001.obj",
            "seg-000000000000ABCD.obj",
            "seg-000000000000000g.obj",
            "cold-manifest.ckpt",
            "seg-.obj",
        ] {
            assert_eq!(parse_cold_object_name(bad), None, "should reject {bad:?}");
        }
    }

    #[test]
    fn fs_cold_store_lists_its_objects_and_the_trait_default_is_unsupported() {
        // A backend without the override reports None ("cannot enumerate"), so the sweep skips it.
        #[derive(Debug)]
        struct NoList;
        impl ColdStore for NoList {
            fn put(&self, _: &str, _: &[u8]) -> Result<(), ColdStoreError> {
                Ok(())
            }
            fn get(&self, key: &str) -> Result<Vec<u8>, ColdStoreError> {
                Err(ColdStoreError::NotFound {
                    key: key.to_string(),
                })
            }
            fn delete(&self, _: &str) -> Result<(), ColdStoreError> {
                Ok(())
            }
            fn exists(&self, _: &str) -> Result<bool, ColdStoreError> {
                Ok(false)
            }
        }
        assert_eq!(NoList.list().unwrap(), None);

        // FsColdStore enumerates (the #1153 orphan-object sweep is exact on it).
        let store = FsColdStore::new(InMemoryFs::new());
        assert_eq!(store.list().unwrap(), Some(Vec::new()));
        store.put(&cold_object_name(3), b"x").unwrap();
        store.put(&cold_object_name(1), b"y").unwrap();
        assert_eq!(
            store.list().unwrap(),
            Some(vec![cold_object_name(1), cold_object_name(3)])
        );
    }

    #[test]
    fn fs_cold_store_put_get_delete_exists_round_trip() {
        let store = FsColdStore::new(InMemoryFs::new());
        let key = cold_object_name(7);
        assert!(!store.exists(&key).unwrap());
        assert!(matches!(
            store.get(&key).unwrap_err(),
            ColdStoreError::NotFound { .. }
        ));
        let bytes = b"a sealed segment's bytes".to_vec();
        store.put(&key, &bytes).unwrap();
        assert!(store.exists(&key).unwrap());
        assert_eq!(store.get(&key).unwrap(), bytes);
        // Idempotent overwrite with SHORTER bytes leaves no stale tail.
        let shorter = b"short".to_vec();
        store.put(&key, &shorter).unwrap();
        assert_eq!(store.get(&key).unwrap(), shorter);
        // Idempotent delete.
        store.delete(&key).unwrap();
        assert!(!store.exists(&key).unwrap());
        store.delete(&key).unwrap(); // absent delete is Ok
    }

    #[test]
    fn manifest_round_trips_across_reopen() {
        let fs = InMemoryFs::new();
        {
            let mut m = open_manifest(&fs);
            m.insert(sample_entry(1)).unwrap();
            m.insert(sample_entry(2)).unwrap();
            m.insert(sample_entry(3)).unwrap();
            assert_eq!(m.len(), 3);
        }
        // Reopen: entries survive, byte-exact.
        let m = open_manifest(&fs);
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(2), Some(&sample_entry(2)));
        assert!(m.contains(1) && m.contains(3));
        assert!(!m.contains(4));
    }

    #[test]
    fn manifest_remove_persists() {
        let fs = InMemoryFs::new();
        {
            let mut m = open_manifest(&fs);
            m.insert(sample_entry(1)).unwrap();
            m.insert(sample_entry(2)).unwrap();
            m.remove(1).unwrap();
            assert!(!m.contains(1) && m.contains(2));
        }
        let m = open_manifest(&fs);
        assert_eq!(m.len(), 1);
        assert!(m.contains(2));
    }

    #[test]
    fn manifest_insert_failure_rolls_back_in_memory() {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let file = fs.create_new(COLD_MANIFEST_FILE).unwrap();
        let mut m = ColdManifest::open(file).unwrap();
        m.insert(sample_entry(1)).unwrap();
        control.set_fail_sync(true);
        // The fsync in the checkpoint write fails: the entry must NOT linger in the in-memory map
        // (it never became durable), so the map matches disk.
        assert!(m.insert(sample_entry(2)).is_err());
        assert!(
            !m.contains(2),
            "a failed insert must not leave a phantom entry"
        );
        assert!(m.contains(1));
    }

    #[test]
    fn manifest_corrupt_payload_fails_closed() {
        // A valid-CRC slot carrying a wrong-magic payload decodes but fails structural validation.
        let fs = InMemoryFs::new();
        let file = fs.create_new(COLD_MANIFEST_FILE).unwrap();
        let (mut cp, _) = ColdManifestCheckpoint::open(file).unwrap();
        cp.write(b"not-a-cold-manifest-payload").unwrap();
        let file = fs.open(COLD_MANIFEST_FILE).unwrap();
        assert!(matches!(
            ColdManifest::open(file).unwrap_err(),
            StorageError::ColdManifestCorrupt
        ));
    }

    #[test]
    fn entry_encode_decode_is_inverse() {
        let e = sample_entry(42);
        let mut buf = Vec::new();
        e.encode_into(&mut buf);
        assert_eq!(buf.len(), ENTRY_LEN);
        assert_eq!(ColdEntry::decode(&buf), Some(e));
        // Wrong length decodes to None.
        assert_eq!(ColdEntry::decode(&buf[..ENTRY_LEN - 1]), None);
    }

    #[test]
    fn offload_error_reason_classifies_and_counts() {
        // A cold-store outage classifies as ColdStore; a manifest-at-cap as Other.
        assert_eq!(
            ColdOffloadErrorReason::for_error(&StorageError::ColdStoreUnavailable {
                segment_id: 1
            }),
            ColdOffloadErrorReason::ColdStore
        );
        assert_eq!(
            ColdOffloadErrorReason::for_error(&StorageError::ColdManifestFull),
            ColdOffloadErrorReason::Other
        );
        // The frozen Prometheus label values.
        assert_eq!(
            ColdOffloadErrorReason::ColdStore.metric_label(),
            "cold_store"
        );
        assert_eq!(ColdOffloadErrorReason::Other.metric_label(), "other");
        // The counter records a DELTA (process-global; assert the delta, not an absolute).
        let before = cold_offload_errors_total(ColdOffloadErrorReason::Other);
        record_cold_offload_error(ColdOffloadErrorReason::Other);
        assert_eq!(
            cold_offload_errors_total(ColdOffloadErrorReason::Other),
            before + 1
        );
    }
}
