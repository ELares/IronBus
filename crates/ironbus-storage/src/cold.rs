// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tiered storage: offloading cold, SEALED, immutable segments to an object store (#643, V2-M10,
//! phase 1 — the Kafka KIP-405 / Pulsar / Redpanda tiered-storage class).
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
//! or an NFS mount, or an in-memory filesystem for tests). A real S3 / `object_store` backend is a
//! feature-gated follow-up: because it is just another `impl ColdStore`, it drops in with no change
//! to the log's offload/fetch/recover machinery.
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
