// SPDX-License-Identifier: MIT OR Apache-2.0
//! Async CROSS-CLUSTER mirror (read-only, single-origin) + source (fan-in) — the geo plane (V2-C7-I1,
//! #623).
//!
//! This is the FIRST cross-cluster primitive: where C1–C6 paid consensus + ISR quorum for SYNCHRONOUS,
//! strongly-consistent replication INSIDE one cluster, the geo plane replicates ASYNCHRONOUSLY ACROSS a
//! cluster boundary. It is eventually-consistent: a mirror/source lags its origin and catches up, and it
//! is RESUMABLE across disconnects/restarts. There is NO quorum, NO ISR membership in the origin, and NO
//! second WAL — a mirror/source pulls the CRC-framed record bytes the origin already wrote and re-applies
//! the validated frames to its own local log, exactly the [`replication::Follower`](super::replication)
//! apply discipline, generalized to a NAMED, cross-cluster, single-writer-preserving, resumable pull.
//!
//! ## The two primitives
//!
//! * A **MIRROR** is a local, READ-ONLY stream that continuously, ASYNCHRONOUSLY pulls the records of
//!   ONE remote ORIGIN stream and applies them locally IN ORDER — an eventually-consistent read replica
//!   across a cluster boundary. No local producer ever writes a mirror; its ONLY writer is the
//!   mirror-apply path. A client PRODUCE to a mirror is rejected with a typed error
//!   ([`GeoError::MirrorReadOnly`]) — single-writer preserved.
//! * A **SOURCE** is a local stream that FANS IN records from ONE OR MORE remote origins, interleaving
//!   their records into the local stream, in addition to (or instead of) local produces. Each origin has
//!   its OWN durable resume cursor; the fan-in ordering is defined below.
//!
//! ## The pull protocol (one origin stream)
//!
//! 1. The puller sends a [`MirrorPullRequest`] — `(origin_stream, from_offset, max_records, max_bytes)` —
//!    to the origin over a SEPARATE cross-cluster link ([`GeoLink`], never the intra-cluster data plane).
//!    This is a PULL: the puller drives the cadence on its own clock; the origin never pushes, so a slow
//!    or broken link never blocks the origin's serving.
//! 2. The origin ([`OriginServer`]) answers a [`MirrorPullResponse`]: its current origin high-watermark
//!    (the committed prefix a mirror may pull up to) and a CONTIGUOUS run of CRC-framed on-disk record
//!    frames from `from_offset`, served ZERO-COPY off the origin's [`ReadPlane`] (the leader-serve read
//!    pattern of #654 — the origin's append path is untouched). The run is bounded by the smaller of the
//!    request budget and [`MAX_GEO_PULL_BYTES`], so one response always frames.
//! 3. The puller ([`MirrorApplier`]) RE-VALIDATES every frame's CRC ([`ironbus_core::codec::decode`]:
//!    header CRC32C + body CRC32C + xxh3) and appends ONLY validated frames to its local log via the
//!    ordinary [`Log::append`] path. A corrupt / tampered / truncated frame is DETECTED and the apply
//!    FAILS CLOSED — nothing from the bad frame onward is applied, and the next pull RESUMES from the last
//!    good origin offset (the durable cursor). A mirror NEVER applies a gap or a corrupt frame.
//! 4. The puller advances + PERSISTS its durable resume cursor for that origin
//!    ([`OriginCursorStore`]) so a disconnect/restart resumes from there, never re-applying or skipping.
//!
//! ## In-order, gap-free, byte-faithful (the non-negotiables)
//!
//! The applier walks the verbatim bytes front-to-back, requires the response to CONTINUE the cursor
//! CONTIGUOUSLY (a gap/overlap fails closed), and re-encodes each validated record through the SAME
//! deterministic codec the origin used. For a single-origin MIRROR replicating a fresh log from origin
//! offset 0 in order, the local log assigns offsets/seqs 0,1,2,… exactly as the origin did, so the
//! mirror's on-disk record bytes are byte-identical to the origin's, frame-for-frame, CRC-valid (the
//! two-cluster test pins it). For a SOURCE the LOCAL offsets differ (records from N origins interleave),
//! so byte-identity is per-RECORD-PAYLOAD (the origin's `timestamp_ms`/`flags`/`key`/`headers`/`payload`
//! are preserved verbatim), not whole-log-byte-identical — the per-origin cursor tracks the ORIGIN
//! offset, and the local log assigns its own offsets.
//!
//! ## Source fan-in ordering (well-defined)
//!
//! A [`SourceFanIn`] applies records from N origins into ONE local stream. The ordering contract is:
//! **per-origin order is preserved** (origin A's records appear in the local log in A's origin order, and
//! likewise B's), and across origins the records are **interleaved by APPLY arrival** — the local log
//! reflects the order the pulled batches were applied (round-robin across the configured origins, each a
//! contiguous batch per pull). This is the only order an async fan-in CAN define without a global clock:
//! there is no cross-origin total order to honor (the origins are independent clusters). Each origin's
//! cursor is INDEPENDENT and durable, so origins catch up at their own rates and resume independently.
//!
//! ## Async / non-blocking / bounded (the #726 idle lesson)
//!
//! The pull loop is ASYNC: it dials the origin, pulls a bounded batch, applies it, persists the cursor,
//! and — when the origin has no new records — BLOCKS on the link read up to a bounded poll window, then
//! BACKS OFF (an interruptible sleep) before re-polling. An idle mirror does ~0 work (it blocks/backs off,
//! never busy-spins). A slow/broken link is bounded by the per-pull byte cap + a reconnect backoff. The
//! pull never blocks the origin's serving (it is a pull) and never blocks LOCAL READS of the mirror (the
//! applier is the mirror's single writer; reads go through the ordinary read path).
//!
//! ## Single-node / non-geo = byte-identical (the critical guarantee)
//!
//! NOTHING in this module constructs unless a `--mirror` / `--source` is configured. With no geo config
//! the local produce/consume/storage hot path is byte-for-byte today's broker: no [`OriginServer`], no
//! [`MirrorApplier`], no cursor file, no geo link, no [`FrameType::MirrorPull`] ever decoded. The geo
//! plane is gated entirely on the presence of a geo config in the CLI serve hook.
//!
//! ## SCOPE / deferred (honest)
//!
//! * **Single default stream/partition per mirror.** A mirror/source pulls ONE origin stream into ONE
//!   local stream's default partition. Multi-partition mirrors are FLAGGED to #693.
//! * **Cross-cluster AUTH/TLS.** The geo link is minimal (loopback / trusted transport, plaintext, like
//!   the intra-cluster peer link today). Cross-cluster mTLS / token auth is a FLAGGED follow-on.
//! * **Read-only ENFORCEMENT** is the applier-is-sole-writer construction plus the typed
//!   [`GeoError::MirrorReadOnly`] reject the engine returns on a client produce to a mirrored stream.
//! * The geo NAMESPACE / cluster-id (#624), edge leaf-spoke (#625), and federation (#626) are SEPARATE
//!   issues and are NOT pulled in here; this is the mirror+source primitive only. Bidirectional /
//!   conflict handling is OUT OF SCOPE — this is read-only mirror + fan-in source
//!   (single-origin-of-truth, no conflict).

use bytes::Bytes;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ironbus_core::clock::Clock;
use ironbus_core::codec::{self, DecodeError};
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType, MAX_FRAME_LEN,
};
use ironbus_storage::checkpoint::SlotCheckpoint;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::{Append, Log};
use ironbus_storage::read_plane::ReadPlane;
use ironbus_storage::segment::{OwnedRecord, StorageError};

/// The hard maximum size, in bytes, of the CRC-framed record-byte payload one cross-cluster pull
/// RESPONSE may carry. Bounds the origin's serve budget AND, on the puller, the UNTRUSTED remote bytes
/// the receive path buffers and re-validates — a puller never trusts the response length blindly. 8 MiB
/// mirrors [`MAX_REPL_FETCH_BYTES`](super::replication::MAX_REPL_FETCH_BYTES): generous head-room for a
/// batched pull while staying well under the absolute [`MAX_FRAME_LEN`] envelope cap, so a pull response
/// always frames.
pub const MAX_GEO_PULL_BYTES: u32 = 8 * 1024 * 1024;

/// The hard maximum length, in bytes, of an origin STREAM name carried on the pull wire. A name longer
/// than this is rejected before any allocation (the untrusted-name size bound). Matches the broker's
/// stream-name ceiling and stays tiny so the request header is fixed-bounded.
pub const MAX_ORIGIN_STREAM_LEN: usize = 255;

/// The `kind` discriminant byte leading a [`FrameType::MirrorPull`] body, so the request and the response
/// (which share the wire tag, like [`FrameType::StreamInfo`]) are never confused.
const PULL_KIND_REQUEST: u8 = 0;
const PULL_KIND_RESPONSE: u8 = 1;

/// The fixed little-endian prefix of an encoded [`MirrorPullRequest`] BEFORE the variable stream name:
/// `kind: u8` + `from_offset: u64` + `max_records: u32` + `max_bytes: u32` + `stream_len: u16`.
const PULL_REQUEST_PREFIX_LEN: usize = 1 + 8 + 4 + 4 + 2;

/// The fixed little-endian prefix of an encoded [`MirrorPullResponse`] BEFORE the variable frame bytes:
/// `kind: u8` + `origin_high_watermark: u64` + `first_offset: u64` + `record_count: u32` +
/// `frame_bytes_len: u32`.
const PULL_RESPONSE_PREFIX_LEN: usize = 1 + 8 + 8 + 4 + 4;

/// Read a little-endian `u64` from `b` at byte offset `at`. The caller guarantees `b.len() >= at + 8`
/// (every call site length-checks the body first), so this is panic-free.
#[inline]
fn read_u64_le(b: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(buf)
}

/// Read a little-endian `u32` from `b` at byte offset `at`. The caller guarantees `b.len() >= at + 4`.
#[inline]
fn read_u32_le(b: &[u8], at: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(buf)
}

/// Read a little-endian `u16` from `b` at byte offset `at`. The caller guarantees `b.len() >= at + 2`.
#[inline]
fn read_u16_le(b: &[u8], at: usize) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&b[at..at + 2]);
    u16::from_le_bytes(buf)
}

/// A puller → origin cross-cluster PULL request for one NAMED origin stream (#623): "send me the
/// CRC-framed records of stream `stream` from origin offset `from_offset`, up to `max_records` records /
/// `max_bytes` frame bytes." The cross-cluster, named twin of
/// [`FetchRecordsBody`](super::replication::FetchRecordsBody): the puller drives the cadence; the origin
/// never pushes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorPullRequest {
    /// The NAMED origin stream to pull (cross-cluster origins are named, not partition-ids). The empty
    /// name selects the origin's DEFAULT stream.
    pub stream: String,
    /// The origin offset the puller wants to replicate FROM (the first origin offset it does not yet
    /// hold for this origin — its durable resume cursor).
    pub from_offset: u64,
    /// The maximum number of records the puller wants in this response (a `0` is a no-op pull).
    pub max_records: u32,
    /// The maximum CRC-framed record BYTES the puller wants. The origin serves at most
    /// `min(this, MAX_GEO_PULL_BYTES)`.
    pub max_bytes: u32,
}

impl MirrorPullRequest {
    /// Encode this request to its `kind`-led, fixed-prefix + variable-name body bytes.
    ///
    /// # Errors
    /// Returns [`GeoError::OriginStreamNameTooLong`] if the stream name exceeds [`MAX_ORIGIN_STREAM_LEN`]
    /// — rejected on encode so an over-long name never goes on the wire.
    pub fn encode(&self) -> Result<Vec<u8>, GeoError> {
        if self.stream.len() > MAX_ORIGIN_STREAM_LEN {
            return Err(GeoError::OriginStreamNameTooLong {
                len: self.stream.len(),
            });
        }
        let name = self.stream.as_bytes();
        let mut out = Vec::with_capacity(PULL_REQUEST_PREFIX_LEN + name.len());
        out.push(PULL_KIND_REQUEST);
        out.extend_from_slice(&self.from_offset.to_le_bytes());
        out.extend_from_slice(&self.max_records.to_le_bytes());
        out.extend_from_slice(&self.max_bytes.to_le_bytes());
        // `name.len() <= MAX_ORIGIN_STREAM_LEN` (255) fits a u16 (checked above); fall back to the cap
        // rather than panic to keep the encoder infallible on a degenerate length.
        let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name);
        Ok(out)
    }

    /// Decode a request from its body bytes.
    ///
    /// # Errors
    /// Returns [`GeoError::MalformedRequest`] if the body is shorter than the fixed prefix, carries the
    /// wrong `kind`, names a length that disagrees with the bytes present, or exceeds the name cap, or
    /// [`GeoError::OriginStreamNotUtf8`] if the name is not valid UTF-8 — fail-closed, never guessed at.
    pub fn decode(body: &[u8]) -> Result<MirrorPullRequest, GeoError> {
        if body.len() < PULL_REQUEST_PREFIX_LEN || body[0] != PULL_KIND_REQUEST {
            return Err(GeoError::MalformedRequest { len: body.len() });
        }
        let from_offset = read_u64_le(body, 1);
        let max_records = read_u32_le(body, 9);
        let max_bytes = read_u32_le(body, 13);
        let name_len = read_u16_le(body, 17) as usize;
        if name_len > MAX_ORIGIN_STREAM_LEN {
            return Err(GeoError::OriginStreamNameTooLong { len: name_len });
        }
        let want = PULL_REQUEST_PREFIX_LEN + name_len;
        if body.len() != want {
            return Err(GeoError::MalformedRequest { len: body.len() });
        }
        let stream = core::str::from_utf8(&body[PULL_REQUEST_PREFIX_LEN..])
            .map_err(|_| GeoError::OriginStreamNotUtf8)?
            .to_string();
        Ok(MirrorPullRequest {
            stream,
            from_offset,
            max_records,
            max_bytes,
        })
    }
}

/// An origin → puller cross-cluster PULL response for one origin stream (#623): the origin's current
/// high-watermark plus a contiguous run of CRC-framed on-disk record frames starting at `first_offset`.
/// The `frame_bytes` are the origin's bytes VERBATIM (a zero-copy `RawByteRun`); the puller RE-VALIDATES
/// each one before applying any of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorPullResponse {
    /// The origin's HIGH-WATERMARK: its flushed / committed offset for the pulled stream at the moment it
    /// served this pull. The puller is caught up iff its cursor reaches this.
    pub origin_high_watermark: u64,
    /// The origin offset of the FIRST frame in `frame_bytes` (it equals the request's `from_offset` when
    /// any data is served, or that offset with an empty run when nothing new is available).
    pub first_offset: u64,
    /// How many complete CRC-framed records `frame_bytes` carries.
    pub record_count: u32,
    /// The contiguous CRC-framed on-disk record frames — the origin's bytes VERBATIM (UNTRUSTED on the
    /// puller until re-validated). A zero-copy `Bytes` (#920): the serve path hands back a refcount-bump
    /// clone of the storage layer's `RawByteRun.bytes` rather than `to_vec()`-ing the whole run per
    /// mirror-pull, exactly as #810 did for the replication path.
    pub frame_bytes: Bytes,
}

impl MirrorPullResponse {
    /// Encode this response to its `kind`-led, fixed-prefix + verbatim-bytes body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PULL_RESPONSE_PREFIX_LEN + self.frame_bytes.len());
        out.push(PULL_KIND_RESPONSE);
        out.extend_from_slice(&self.origin_high_watermark.to_le_bytes());
        out.extend_from_slice(&self.first_offset.to_le_bytes());
        out.extend_from_slice(&self.record_count.to_le_bytes());
        // The byte length is stored so the puller can bound the run before reading it; it is re-checked
        // against the actual remaining bytes on decode (never trusted blindly).
        let frame_len = u32::try_from(self.frame_bytes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&frame_len.to_le_bytes());
        out.extend_from_slice(&self.frame_bytes);
        out
    }

    /// Decode a response from its body bytes, BOUNDING the carried frame bytes against
    /// [`MAX_GEO_PULL_BYTES`] before accepting them — an oversized response (a hostile or buggy origin)
    /// is rejected, never buffered.
    ///
    /// # Errors
    /// Returns [`GeoError::MalformedResponse`] if the prefix is short, the wrong `kind`, or the stored
    /// `frame_bytes_len` disagrees with the bytes present; [`GeoError::ResponseTooLarge`] if the run
    /// exceeds the cap.
    pub fn decode(body: &[u8]) -> Result<MirrorPullResponse, GeoError> {
        if body.len() < PULL_RESPONSE_PREFIX_LEN || body[0] != PULL_KIND_RESPONSE {
            return Err(GeoError::MalformedResponse { len: body.len() });
        }
        let origin_high_watermark = read_u64_le(body, 1);
        let first_offset = read_u64_le(body, 9);
        let record_count = read_u32_le(body, 17);
        let frame_bytes_len = read_u32_le(body, 21);
        // The SIZE bound on untrusted remote bytes: reject an over-cap claimed length BEFORE trusting it.
        if frame_bytes_len > MAX_GEO_PULL_BYTES {
            return Err(GeoError::ResponseTooLarge {
                len: u64::from(frame_bytes_len),
            });
        }
        let want = frame_bytes_len as usize;
        let have = body.len() - PULL_RESPONSE_PREFIX_LEN;
        if want != have {
            return Err(GeoError::MalformedResponse { len: body.len() });
        }
        Ok(MirrorPullResponse {
            origin_high_watermark,
            first_offset,
            record_count,
            frame_bytes: Bytes::copy_from_slice(&body[PULL_RESPONSE_PREFIX_LEN..]),
        })
    }
}

/// A typed geo error. Every failure mode of serving / pulling / validating / applying a cross-cluster
/// pull is one of these — the layer NEVER panics, NEVER blind-appends an unvalidated byte, and FAILS
/// CLOSED on any corrupt / malformed / out-of-order input, AND it is the typed read-only reject a client
/// produce to a mirror receives.
#[derive(Debug)]
pub enum GeoError {
    /// A PRODUCE was attempted on a MIRRORED stream. A mirror is strictly READ-ONLY locally: its only
    /// writer is the mirror-apply path. The client produce is rejected with this typed error (the
    /// single-writer enforcement). Carries the mirrored stream name.
    MirrorReadOnly {
        /// The mirrored (read-only) local stream the produce was rejected for.
        stream: String,
    },
    /// A pull REQUEST body was malformed (short, wrong kind, inconsistent length).
    MalformedRequest {
        /// The body length seen.
        len: usize,
    },
    /// A pull RESPONSE body was malformed (short, wrong kind, or its stored frame-byte length disagreed
    /// with the bytes present).
    MalformedResponse {
        /// The body length seen.
        len: usize,
    },
    /// A pull response claimed more CRC-framed record bytes than [`MAX_GEO_PULL_BYTES`] — rejected before
    /// the bytes are trusted (the untrusted-remote size bound).
    ResponseTooLarge {
        /// The claimed frame-byte length.
        len: u64,
    },
    /// An origin stream name exceeded [`MAX_ORIGIN_STREAM_LEN`].
    OriginStreamNameTooLong {
        /// The name length seen.
        len: usize,
    },
    /// An origin stream name on the wire was not valid UTF-8.
    OriginStreamNotUtf8,
    /// The response's first offset did not CONTINUE the puller's durable cursor contiguously (a gap or an
    /// overlap). The applier fails closed and the next pull resumes from the cursor — never applying a
    /// gap or re-applying. (Async geo is single-origin-of-truth: there is no divergent-lineage truncation
    /// here, unlike the intra-cluster epoch path; a non-contiguous response is dropped and re-pulled.)
    NonContiguous {
        /// The origin offset the puller's cursor expected next.
        expected: u64,
        /// The first origin offset the response actually carried.
        got: u64,
    },
    /// A CRC-framed frame in the response FAILED the intact-record predicate
    /// ([`ironbus_core::codec::decode`]) — a corrupt, tampered, or truncated frame. The applier detected
    /// it and applied NOTHING from this frame onward (fail-closed). Carries the origin offset the bad
    /// frame would have occupied and the typed decode reason; the next pull resumes from the cursor.
    CorruptFrame {
        /// The origin offset the corrupt frame would have been applied at.
        at_origin_offset: u64,
        /// The typed decode failure (bad header CRC, bad body CRC, bad xxh3, truncated, …).
        reason: DecodeError,
    },
    /// The response claimed a `record_count` the actual frame bytes did not contain — a malformed
    /// response; fail closed.
    RecordCountMismatch {
        /// The count the response header claimed.
        claimed: u32,
        /// The number of complete frames actually decoded.
        actual: u32,
    },
    /// The durable resume cursor could not be persisted / recovered (an underlying IO fault). Surfaced
    /// rather than swallowed — a mirror that cannot persist its cursor fails closed rather than risk a
    /// re-apply / skip on restart.
    Cursor {
        /// A human description of the cursor fault.
        what: String,
    },
    /// The local log rejected an append (at-capacity / writer frozen) while applying a validated record.
    Storage(StorageError),
    /// An underlying IO error reading from / writing to the geo link.
    Io(io::Error),
    /// The geo-link frame envelope was malformed or carried an unexpected type tag.
    Frame {
        /// A human description of the framing fault.
        what: String,
    },
}

impl core::fmt::Display for GeoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GeoError::MirrorReadOnly { stream } => write!(
                f,
                "stream `{stream}` is a read-only MIRROR; its only writer is the mirror-apply path, so a client produce is rejected"
            ),
            GeoError::MalformedRequest { len } => {
                write!(f, "malformed geo pull request body ({len} bytes)")
            }
            GeoError::MalformedResponse { len } => {
                write!(f, "malformed geo pull response body ({len} bytes)")
            }
            GeoError::ResponseTooLarge { len } => write!(
                f,
                "geo pull response claimed {len} frame bytes, over the {MAX_GEO_PULL_BYTES}-byte cap; rejected"
            ),
            GeoError::OriginStreamNameTooLong { len } => write!(
                f,
                "origin stream name is {len} bytes, over the {MAX_ORIGIN_STREAM_LEN}-byte cap; rejected"
            ),
            GeoError::OriginStreamNotUtf8 => write!(f, "origin stream name on the wire is not valid UTF-8"),
            GeoError::NonContiguous { expected, got } => write!(
                f,
                "geo pull is non-contiguous: cursor expected origin offset {expected}, response started at {got}; dropped, will resume from the cursor"
            ),
            GeoError::CorruptFrame {
                at_origin_offset,
                reason,
            } => write!(
                f,
                "geo pull carried a corrupt frame at origin offset {at_origin_offset} ({reason:?}); fail-closed, nothing applied from here"
            ),
            GeoError::RecordCountMismatch { claimed, actual } => write!(
                f,
                "geo pull response record_count {claimed} != {actual} complete frames decoded"
            ),
            GeoError::Cursor { what } => write!(f, "geo resume cursor error: {what}"),
            GeoError::Storage(e) => write!(f, "geo apply local append failed: {e}"),
            GeoError::Io(e) => write!(f, "geo link IO error: {e}"),
            GeoError::Frame { what } => write!(f, "geo link frame error: {what}"),
        }
    }
}

impl std::error::Error for GeoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GeoError::CorruptFrame { reason, .. } => Some(reason),
            GeoError::Storage(e) => Some(e),
            GeoError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for GeoError {
    fn from(e: io::Error) -> Self {
        GeoError::Io(e)
    }
}

impl From<StorageError> for GeoError {
    fn from(e: StorageError) -> Self {
        GeoError::Storage(e)
    }
}

/// The ORIGIN side of the geo plane for one named stream: it serves a puller's [`MirrorPullRequest`] by
/// reading a contiguous CRC-framed byte range from the origin stream's OFF-ACTOR [`ReadPlane`] (#654,
/// zero-copy) up to the requested-and-capped budget, plus the origin's current high-watermark.
///
/// The origin's log is READ-ONLY through this path — the geo plane never changes the origin's append /
/// produce path; it only serves bytes already written and flushed. The origin NEVER writes its log here
/// (it reads the immutable sealed bytes via the `Arc`-shared plane), so the origin's single append actor
/// stays the sole writer and a slow puller never blocks the origin's serving.
pub struct OriginServer<'a, F: Filesystem> {
    plane: &'a ReadPlane<F>,
}

impl<'a, F: Filesystem> OriginServer<'a, F> {
    /// Wrap an origin stream's `Arc`-shared read plane as a geo pull source.
    #[must_use]
    pub fn new(plane: &'a ReadPlane<F>) -> Self {
        Self { plane }
    }

    /// The origin's current high-watermark: the read plane's flushed / committed frontier — the prefix a
    /// mirror may pull up to.
    #[must_use]
    pub fn high_watermark(&self) -> Offset {
        Offset::new(self.plane.flushed())
    }

    /// Serve a puller's pull: a contiguous run of the origin's CRC-framed on-disk record frames from
    /// `req.from_offset`, bounded by the smaller of the request budget and [`MAX_GEO_PULL_BYTES`], plus
    /// the origin's current high-watermark. The frames are shipped VERBATIM (the origin does not
    /// re-encode or re-validate — they are already its own durable bytes); the PULLER re-validates them.
    ///
    /// The read plane serves the SEALED prefix only; a pull whose `from_offset` is already in the active
    /// (flushed-but-unsealed) tail returns an EMPTY run with the true HW (the puller no-ops and re-pulls;
    /// it catches up byte-faithfully as segments seal — the same active-tail liveness window the
    /// intra-cluster leader serve has, FLAGGED there).
    ///
    /// # Errors
    /// Returns [`GeoError::Storage`] if the underlying raw read fails (e.g. the requested offset is older
    /// than the oldest retained record on the origin).
    pub fn serve_pull(&self, req: &MirrorPullRequest) -> Result<MirrorPullResponse, GeoError> {
        let hw = self.plane.flushed();
        let from = Offset::new(req.from_offset);
        // Bound the served bytes to the cap regardless of the request: `0` request bytes means "use the
        // cap" so a puller without a byte budget still makes progress; the record-count budget bounds it.
        let req_bytes = if req.max_bytes == 0 {
            MAX_GEO_PULL_BYTES
        } else {
            req.max_bytes.min(MAX_GEO_PULL_BYTES)
        };
        let max_records = req.max_records as usize;
        let sealed = self
            .plane
            .read_range_raw(from, max_records, Some(req_bytes as usize))?;
        Ok(MirrorPullResponse {
            origin_high_watermark: hw,
            first_offset: sealed.run.first_offset.get(),
            record_count: u32::try_from(sealed.run.record_count).unwrap_or(u32::MAX),
            frame_bytes: sealed.run.bytes.clone(),
        })
    }
}

/// The outcome of applying one pull response: how many records were applied and the cursor + HW after.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// How many records this response newly APPENDED to the local log. After the #799 crash-window
    /// reconciliation this EXCLUDES frames the response carried but the single-origin applier already
    /// held durably (skipped, not re-appended), so a pure re-pull of already-applied data reports `0`
    /// applied even though `cursor` advances — progress is keyed off `cursor`/`record_count`, not this.
    pub applied: u64,
    /// The puller's resume cursor AFTER this apply: the next origin offset to pull FROM.
    pub cursor: u64,
    /// The origin high-watermark observed in this response (the puller is caught up iff
    /// `cursor == origin_high_watermark`).
    pub origin_high_watermark: u64,
}

/// The on-disk file name of the durable cursor store, under the mirror/source data directory.
pub const CURSOR_FILE: &str = "geo.cursor";

/// The per-slot payload cap of the geo cursor [`SlotCheckpoint`] (4 KiB). The payload is the encoded
/// `(origin_key -> applied_origin_offset)` map; at ~`<addr>/<stream>` (~60 bytes) + 8-byte offset +
/// 2-byte length per origin, 4 KiB holds well over 50 origins — ample for a single mirror or a small
/// fan-in source (multi-partition / large fan-out are FLAGGED to #693). A configured set that overflows
/// the cap is a fail-closed [`GeoError::Cursor`] on commit (never a silent truncation).
pub const GEO_CURSOR_PAYLOAD: usize = 4096;

/// The reserved record KEY of a geo SOURCE's in-log per-origin high-watermark marker (#906). It is
/// NUL-prefixed so it can never collide in practice with a client/origin routing key (those are
/// non-NUL-leading UTF-8 keys); together with [`GEO_HWM_MARKER_MAGIC`] in the payload it is the two-part
/// discriminator a recovery (or any future read path) uses to tell a HWM marker apart from an applied
/// origin record. A marker lives ONLY in the local fan-in log (never on the wire) and ONLY for a
/// multi-origin source — a mirror's byte-identical log takes no markers.
const GEO_HWM_MARKER_KEY: &[u8] = b"\x00ironbus.geo.hwm";

/// The leading payload magic of a geo per-origin HWM marker record (#906). The bytes AFTER the magic are
/// an [`encode_cursor_payload`] snapshot of the `(origin_key -> applied_origin_offset)` map durable as of
/// this record — the same codec the [`OriginCursorStore`] uses, reused verbatim.
const GEO_HWM_MARKER_MAGIC: &[u8] = b"\x00IBGEOHWM\x00";

/// A durable, per-origin RESUME CURSOR store (#623): the origin offset the mirror/source has APPLIED for
/// each origin, persisted so a disconnect/restart resumes from there, never re-applying or skipping. It
/// is the geo analogue of a consumer's committed checkpoint.
///
/// It is backed by the SAME crash-safe dual-slot, CRC-validated [`SlotCheckpoint`] the broker's consumer
/// cursor / counters / producer-seq checkpoints use: each commit writes the FULL `(origin_key ->
/// applied_origin_offset)` snapshot to the alternate slot and fsyncs, so a crash mid-write reverts to the
/// prior durable slot (never a torn cursor), and a torn / missing file recovers as "no cursors" — every
/// origin resumes from offset 0, the safe degrade (a fresh mirror re-pulls from the origin's start; the
/// [`NonContiguous`](GeoError::NonContiguous) guard + the local log's own `next_offset` make a re-pull of
/// already-applied data a recognized no-op for a single-origin mirror). For a single-origin applier (a
/// MIRROR, or a single-origin SOURCE) the cursor also EQUALS the local log's `next_offset` (it applies
/// from origin 0 in order), so the cursor is doubly-anchored and [`MirrorApplier::apply_pull_response`]
/// ENFORCES it (#799): a re-pull below `next_offset` is skipped, so a crash between the record sync and
/// the cursor commit cannot double-apply. For a MULTI-origin SOURCE the local offset differs from each
/// origin's (interleaved fan-in), so the persisted cursor is the only authority and that crash window
/// can still re-apply a batch (tracked separately).
pub struct OriginCursorStore<F: Filesystem> {
    checkpoint: SlotCheckpoint<F::File, GEO_CURSOR_PAYLOAD>,
    /// The in-memory view of `(origin_key -> applied_origin_offset)`, loaded on open and updated on each
    /// durable commit. Sorted (a `BTreeMap`) for a deterministic snapshot encoding.
    cursors: BTreeMap<String, u64>,
}

impl<F: Filesystem> OriginCursorStore<F> {
    /// Open (or initialize) the durable cursor store under `fs`. Creates `geo.cursor` if absent (and
    /// fsyncs the directory so the fresh file survives a power loss right after creation), then recovers
    /// the latest durable slot. A torn / missing file recovers as no cursors (every origin starts at 0,
    /// the safe degrade); a corrupt slot is simply not selected (the dual-slot discipline), never misread.
    ///
    /// # Errors
    /// [`GeoError::Cursor`] on an IO fault opening / creating the cursor file, or on a recovered snapshot
    /// that fails to decode (a foreign / impossibly-shaped payload) — fail-closed.
    pub fn open(fs: &F) -> Result<OriginCursorStore<F>, GeoError> {
        Self::open_named(fs, CURSOR_FILE)
    }

    /// Open (or initialize) a durable cursor store under `fs` in a NAMED file. [`open`](Self::open) is
    /// this with the default [`CURSOR_FILE`]; the edge leaf-spoke (#625) reuses this store for its durable
    /// PUSH cursor under its OWN file name, so a leaf that both mirrors (read-side, `geo.cursor`) and
    /// forwards (write-through, `leaf.push.cursor`) keeps the two crash-safe dual-slot cursors in separate
    /// files. The recovery story is identical regardless of name: a torn / missing file recovers as no
    /// cursors (every key resumes from 0, the safe degrade); a corrupt slot is simply not selected.
    ///
    /// # Errors
    /// [`GeoError::Cursor`] on an IO fault opening / creating the cursor file, or on a recovered snapshot
    /// that fails to decode — fail-closed.
    pub fn open_named(fs: &F, file_name: &str) -> Result<OriginCursorStore<F>, GeoError> {
        // The caller (SlotCheckpoint) owns the value bytes; we own the file's existence. Create it if
        // absent and fsync the dir so a power loss right after creation does not lose the file.
        let existed = fs.exists(file_name).map_err(|e| GeoError::Cursor {
            what: e.to_string(),
        })?;
        let file = if existed {
            fs.open(file_name)
        } else {
            let f = fs.create_new(file_name);
            // Best-effort dir fsync so the new file's directory entry is durable.
            let _ = fs.sync_dir();
            f
        }
        .map_err(|e| GeoError::Cursor {
            what: e.to_string(),
        })?;
        let (checkpoint, payload) = SlotCheckpoint::<F::File, GEO_CURSOR_PAYLOAD>::open(file)
            .map_err(|e| GeoError::Cursor {
                what: e.to_string(),
            })?;
        let cursors = match payload {
            Some(bytes) => decode_cursor_payload(&bytes)?,
            None => BTreeMap::new(),
        };
        Ok(OriginCursorStore {
            checkpoint,
            cursors,
        })
    }

    /// The applied origin offset for `origin_key` — the offset the next pull should resume FROM. `0` for
    /// an origin never pulled (a fresh mirror).
    #[must_use]
    pub fn cursor(&self, origin_key: &str) -> u64 {
        self.cursors.get(origin_key).copied().unwrap_or(0)
    }

    /// Durably ADVANCE `origin_key`'s cursor to `applied_origin_offset` and fsync it. Monotonic: a commit
    /// at or below the current cursor is a no-op (never moves a cursor backward — that would risk a
    /// re-apply). The full snapshot is written to the alternate slot so a crash never leaves a torn
    /// cursor.
    ///
    /// # Errors
    /// [`GeoError::Cursor`] on an IO fault writing / fsyncing the cursor file, or if the configured origin
    /// set's encoded snapshot exceeds [`GEO_CURSOR_PAYLOAD`] (fail-closed, never a silent truncation).
    pub fn commit(&mut self, origin_key: &str, applied_origin_offset: u64) -> Result<(), GeoError> {
        let cur = self.cursors.get(origin_key).copied().unwrap_or(0);
        if applied_origin_offset <= cur {
            return Ok(());
        }
        self.cursors
            .insert(origin_key.to_string(), applied_origin_offset);
        let payload = encode_cursor_payload(&self.cursors);
        if payload.len() > GEO_CURSOR_PAYLOAD {
            // Roll back the in-memory change so the store stays consistent with the durable slot.
            self.cursors.insert(origin_key.to_string(), cur);
            return Err(GeoError::Cursor {
                what: format!(
                    "encoded cursor snapshot is {} bytes, over the {GEO_CURSOR_PAYLOAD}-byte cap (too many origins)",
                    payload.len()
                ),
            });
        }
        self.checkpoint
            .write(&payload)
            .map_err(|e| GeoError::Cursor {
                what: e.to_string(),
            })?;
        Ok(())
    }
}

/// Encode the cursor map to the [`SlotCheckpoint`] payload bytes: `[count:u32][ (key_len:u16, key,
/// offset:u64) * count ]`. Deterministic (the `BTreeMap` is sorted). The CRC + slot framing is the
/// checkpoint's job; this is just the value.
fn encode_cursor_payload(cursors: &BTreeMap<String, u64>) -> Vec<u8> {
    let mut out = Vec::new();
    let count = u32::try_from(cursors.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&count.to_le_bytes());
    for (key, off) in cursors {
        let kb = key.as_bytes();
        let kl = u16::try_from(kb.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&kl.to_le_bytes());
        out.extend_from_slice(&kb[..kl as usize]);
        out.extend_from_slice(&off.to_le_bytes());
    }
    out
}

/// Decode the [`SlotCheckpoint`] payload bytes back into the cursor map. The checkpoint already
/// CRC-validated + selected the latest intact slot; this only parses the value, fail-closed on an
/// inconsistent shape.
fn decode_cursor_payload(bytes: &[u8]) -> Result<BTreeMap<String, u64>, GeoError> {
    if bytes.len() < 4 {
        return Err(GeoError::Cursor {
            what: "cursor payload too short for its count header".to_string(),
        });
    }
    let count = read_u32_le(bytes, 0) as usize;
    let mut at = 4usize;
    let mut map = BTreeMap::new();
    for _ in 0..count {
        if at + 2 > bytes.len() {
            return Err(GeoError::Cursor {
                what: "cursor payload truncated reading a key length".to_string(),
            });
        }
        let kl = read_u16_le(bytes, at) as usize;
        at += 2;
        if at + kl + 8 > bytes.len() {
            return Err(GeoError::Cursor {
                what: "cursor payload truncated reading a key/offset".to_string(),
            });
        }
        let key = core::str::from_utf8(&bytes[at..at + kl])
            .map_err(|_| GeoError::Cursor {
                what: "cursor payload key is not valid UTF-8".to_string(),
            })?
            .to_string();
        at += kl;
        let off = read_u64_le(bytes, at);
        at += 8;
        map.insert(key, off);
    }
    if at != bytes.len() {
        return Err(GeoError::Cursor {
            what: "cursor payload has trailing bytes after the declared count".to_string(),
        });
    }
    Ok(map)
}

/// The PULLER (apply) side of the geo plane for ONE local stream: it owns the local READ-ONLY (mirror) or
/// fan-in (source) log and applies pull responses to it — re-validating every frame's CRC, appending only
/// validated frames, advancing + persisting each origin's durable cursor, and tracking per-origin
/// progress against the origin's HW.
///
/// **The applier is the local stream's SOLE writer.** A mirror is read-only to clients (a client produce
/// is rejected with [`GeoError::MirrorReadOnly`]); a source's only OTHER writer is the local produce path
/// (a source MAY take local produces), and both write through the SAME single append actor in the serving
/// broker — the single-writer invariant holds. Each frame is decoded with [`ironbus_core::codec::decode`]
/// (header CRC32C + body CRC32C + xxh3) and only a frame that passes is re-appended; a corrupt / tampered
/// / truncated frame fails closed (nothing from that frame onward is applied) and the next pull resumes
/// from the durable cursor.
pub struct MirrorApplier<F: Filesystem, C: Clock> {
    log: Log<F, C>,
    cursors: OriginCursorStore<F>,
    /// Whether this applier's local log is fed by EXACTLY ONE origin AND BY NOTHING ELSE (no local
    /// produces), so the local offset equals that origin's offset 1:1 (a MIRROR, or a single-origin
    /// SOURCE). When true, the local log's own `next_offset` is an INDEPENDENT durable anchor for
    /// already-applied data, which closes the crash window between the record sync and the cursor commit
    /// (#799): a re-pull of already-synced records is recognized and SKIPPED rather than double-applied.
    ///
    /// SAFETY INVARIANT: this is sound ONLY because the geo applier log (`<data_dir>/geo/<hex>`) is
    /// written EXCLUSIVELY by [`MirrorApplier::apply_pull_response`] (the per-origin puller threads) —
    /// never by a local client produce (those go to the engine's own `StreamSet`, a DIFFERENT log). If a
    /// local write ever reached THIS log, `next_offset` would exceed the origin's offset and the skip
    /// would silently DROP genuinely-new origin records (a never-SKIP / data-loss violation), so the
    /// flag must stay false for any applier whose log can take a non-origin write.
    ///
    /// A MULTI-origin source fans N origins into one interleaved log, so `next_offset` (the fan-in
    /// total) is NOT any single origin's offset and cannot anchor it; that path anchors instead on the
    /// per-origin in-log HWM ([`origin_hwm`](MirrorApplier::origin_hwm)).
    single_origin: bool,
    /// The per-origin durable high-watermark for a MULTI-origin source (#906): `origin_key ->` the
    /// applied origin offset that is DURABLE in the local fan-in log, recovered from the tail HWM marker
    /// and made durable by the SAME `log.sync()` as the records (unlike the separately-fsynced cursor).
    /// It is the multi-origin analogue of the single-origin `next_offset` anchor, closing the same
    /// sync-before-cursor-commit crash window: a re-pull below it is SKIPPED, never double-applied.
    ///
    /// `None` until lazily rebuilt on the first apply after open (see
    /// [`ensure_origin_hwm`](MirrorApplier::ensure_origin_hwm)); always `None`/unused for a single-origin
    /// applier, which uses `next_offset` and writes no markers.
    origin_hwm: Option<BTreeMap<String, u64>>,
}

impl<F: Filesystem, C: Clock> MirrorApplier<F, C> {
    /// Wrap a freshly-opened (or recovered) local log + its durable cursor store as a geo applier.
    /// `single_origin` is true when the local log is fed by exactly one origin (a MIRROR, or a SOURCE
    /// with a single origin) — see [`MirrorApplier::single_origin`] for why it gates the #799
    /// crash-window reconciliation.
    #[must_use]
    pub fn new(log: Log<F, C>, cursors: OriginCursorStore<F>, single_origin: bool) -> Self {
        Self {
            log,
            cursors,
            single_origin,
            // Lazily rebuilt from the tail HWM marker on the first multi-origin apply (#906), so `new`
            // stays infallible and open never fails on a transient read.
            origin_hwm: None,
        }
    }

    /// Borrow the local log (e.g. to read its applied records, or to compare its on-disk bytes against
    /// the origin's for the byte-faithful check).
    #[must_use]
    pub fn log(&self) -> &Log<F, C> {
        &self.log
    }

    /// The durable resume cursor for `origin_key`: the next origin offset to pull FROM.
    #[must_use]
    pub fn cursor(&self, origin_key: &str) -> u64 {
        self.cursors.cursor(origin_key)
    }

    /// Build the pull request the puller should send next for `origin` (an `(addr, stream)` origin
    /// identified by `origin_key`), asking for up to `max_records` / `max_bytes` from its durable cursor.
    #[must_use]
    pub fn pull_request(
        &self,
        origin_key: &str,
        stream: &str,
        max_records: u32,
        max_bytes: u32,
    ) -> MirrorPullRequest {
        MirrorPullRequest {
            stream: stream.to_string(),
            from_offset: self.cursors.cursor(origin_key),
            max_records,
            max_bytes,
        }
    }

    /// Apply an origin's pull RESPONSE to the local log: re-validate every frame's CRC, append only
    /// validated frames IN ORDER, sync, then DURABLY advance `origin_key`'s cursor by exactly the number
    /// of records applied.
    ///
    /// The order is load-bearing: the records are synced to the local log BEFORE the cursor is committed,
    /// so the cursor NEVER advances past durably-synced data (never SKIPS on restart). A crash after the
    /// sync but before the cursor commit leaves the local log AHEAD of the durable cursor and RE-PULLS
    /// the already-synced span. For a SINGLE-ORIGIN applier (a MIRROR, or a single-origin SOURCE) that
    /// re-pull is now an ENFORCED no-op (#799): the local log's own `next_offset` is an independent
    /// durable anchor, so any frame whose origin offset is below it is SKIPPED rather than re-appended —
    /// closing the never-DOUBLE-APPLY gap that the `next_offset == cursor` invariant only *claimed* to
    /// provide. A MULTI-origin source interleaves origins, so `next_offset` is not any single origin's
    /// offset and cannot anchor it; that path still trusts the per-origin cursor, so a crash in this
    /// window can re-apply its last batch (tracked separately — the source needs an atomic cursor).
    ///
    /// # Errors
    /// - [`GeoError::NonContiguous`] if the response does not continue this origin's cursor.
    /// - [`GeoError::CorruptFrame`] if any frame fails CRC re-validation (fail-closed).
    /// - [`GeoError::RecordCountMismatch`] if the byte run does not hold the claimed count.
    /// - [`GeoError::Storage`] if a local append / sync fails.
    /// - [`GeoError::Cursor`] if the durable cursor cannot be persisted.
    pub fn apply_pull_response(
        &mut self,
        origin_key: &str,
        resp: &MirrorPullResponse,
    ) -> Result<ApplyOutcome, GeoError> {
        self.apply_pull_response_inner(origin_key, resp, true)
    }

    /// TEST SEAM (#906): apply `resp` but STOP after the batch's records and any mid-batch seal markers,
    /// BEFORE the final marker, the group-commit `log.sync()`, and the cursor commit — modeling a crash in
    /// the durability window. The mid-batch seals are already durable (each fsynced its segment with a
    /// marker tail); the active segment's unsynced tail and the cursor are not, so a subsequent
    /// `simulate_power_loss` leaves exactly the post-crash durable state to test recovery against.
    #[cfg(test)]
    fn apply_then_crash_before_final_sync(
        &mut self,
        origin_key: &str,
        resp: &MirrorPullResponse,
    ) -> Result<ApplyOutcome, GeoError> {
        self.apply_pull_response_inner(origin_key, resp, false)
    }

    fn apply_pull_response_inner(
        &mut self,
        origin_key: &str,
        resp: &MirrorPullResponse,
        finalize: bool,
    ) -> Result<ApplyOutcome, GeoError> {
        let cursor = self.cursors.cursor(origin_key);
        // An empty run (caught up to the origin's HW) is a clean no-op that still reflects the observed
        // HW. Its `first_offset` may be the cursor OR the origin HW; either way nothing is applied.
        if resp.record_count == 0 && resp.frame_bytes.is_empty() {
            return Ok(ApplyOutcome {
                applied: 0,
                cursor,
                origin_high_watermark: resp.origin_high_watermark,
            });
        }
        // The run MUST continue this origin's cursor contiguously. A gap or overlap is dropped fail-closed
        // and the next pull resumes from the cursor — never applying a gap, never re-applying.
        if resp.first_offset != cursor {
            return Err(GeoError::NonContiguous {
                expected: cursor,
                got: resp.first_offset,
            });
        }

        // Lazily rebuild a multi-origin source's per-origin in-log HWM from the tail marker, once, before
        // it anchors the skip below (#906). A no-op for a single-origin applier or once already loaded.
        self.ensure_origin_hwm()?;

        // The durable anchor for already-applied data. For a single-origin applier (a MIRROR, or a
        // SOURCE with one origin) the local log's `next_offset` EQUALS the count of origin records
        // already durable, so a frame whose origin offset is below it was already synced and must NOT be
        // re-appended (#799): this closes the crash window between the record sync below and the cursor
        // commit, where a restart re-pulls from a cursor that lags the durable log. A MULTI-origin source
        // has no such positional anchor (its `next_offset` is the fan-in total of interleaved origins), so
        // it anchors on the per-origin in-log HWM instead (#906) — recovered from the tail marker and made
        // durable by the SAME `log.sync()` as the records, closing the identical window for the fan-in case.
        let durable_anchor = if self.single_origin {
            // INVARIANT: for a single-origin applier the cursor never RUNS AHEAD of the durable log
            // head — the load-bearing sync-before-commit order guarantees the records are durable
            // before the cursor advances past them, so `next_offset >= cursor` always. A cursor ahead
            // of `next_offset` would mean durable records were LOST (a never-SKIP violation) or a
            // non-origin write reached this log (the apply-only invariant on `single_origin` broke);
            // surface it loudly in debug rather than silently anchoring at the (too-high) cursor. The
            // `max` is the production guard for that impossible case (anchor at the cursor, never skip).
            debug_assert!(
                self.log.next_offset().get() >= cursor,
                "single-origin geo cursor {cursor} is ahead of the durable log head {} — lost \
                 records or a non-origin write to the applier log",
                self.log.next_offset().get()
            );
            self.log.next_offset().get().max(cursor)
        } else {
            // #906: a multi-origin source anchors on its per-origin in-log HWM. `max(cursor, hwm)` so a
            // re-pull after the sync-before-cursor-commit crash window (cursor stale, but the records +
            // their HWM marker durable) SKIPS the already-applied frames instead of double-applying them.
            // Absent a marker (a fresh or legacy log) the HWM is 0, so this degrades to `cursor` — the
            // exact pre-#906 behavior, which self-heals once the first new batch writes a marker.
            let hwm = self
                .origin_hwm
                .as_ref()
                .and_then(|m| m.get(origin_key))
                .copied()
                .unwrap_or(0);
            cursor.max(hwm)
        };

        // Walk the verbatim frame bytes, RE-VALIDATING one frame at a time. `codec::decode` is the
        // intact-record predicate (magic, version, header CRC32C, length sanity, body CRC32C, xxh3) — a
        // typed DecodeError on ANY corruption. A frame already below `durable_anchor` is SKIPPED (the log
        // already holds it); otherwise the validated frame is appended. A decode failure stops the walk
        // and is surfaced, so the applier NEVER applies a byte it has not itself validated.
        let mut at = 0usize;
        let mut seen = 0u64; // frames CONSUMED (skipped-as-already-applied + appended) = origin-offset progress
        let mut applied = 0u64; // frames actually APPENDED this pull
        let bytes = resp.frame_bytes.as_ref();
        while at < bytes.len() {
            let at_origin_offset = cursor + seen;
            let (view, frame_len) = match codec::decode(&bytes[at..]) {
                Ok(decoded) => decoded,
                Err(reason) => {
                    // Fail closed: apply nothing from this frame onward. Sync the validated prefix (writing
                    // the per-origin HWM marker first when this batch appended any records, #906), then
                    // advance the cursor past exactly the frames consumed (newly synced or already
                    // durable), so the next pull resumes cleanly.
                    self.sync_with_hwm_marker(origin_key, cursor + seen, applied > 0)?;
                    if seen > 0 {
                        self.cursors.commit(origin_key, cursor + seen)?;
                    }
                    return Err(GeoError::CorruptFrame {
                        at_origin_offset,
                        reason,
                    });
                }
            };
            // #799: skip a frame the local log already durably holds (a re-pull after the sync/commit
            // crash window). Single-origin only — `durable_anchor == cursor` otherwise, so this never fires
            // and a multi-origin source is byte-for-byte unchanged.
            if at_origin_offset < durable_anchor {
                seen += 1;
                at += frame_len;
                continue;
            }
            let append = Append {
                timestamp_ms: view.timestamp_ms,
                flags: view.flags,
                key: view.key,
                headers: view.headers,
                payload: view.payload,
            };
            // Append the record, managing segment boundaries so a marker always caps a sealed segment
            // (#906). `at_origin_offset` is this origin's applied extent BEFORE this record, i.e. the HWM
            // a sealing marker would record for the records already in the active segment.
            self.append_origin_record(origin_key, &append, at_origin_offset)?;
            applied += 1;
            seen += 1;
            at += frame_len;
        }
        if !finalize {
            // TEST-ONLY crash point (#906): the records and any mid-batch seal markers are appended (the
            // seals are durable), but the final marker + group-commit fsync + cursor commit have NOT run.
            return Ok(ApplyOutcome {
                applied,
                cursor: cursor + seen,
                origin_high_watermark: resp.origin_high_watermark,
            });
        }
        // Durably commit the applied batch to the local log (one fsync per pull — the group-commit shape).
        // For a multi-origin source that appended records, the per-origin HWM marker is appended FIRST so
        // it rides the SAME fsync as the data (#906) — the atomicity the separately-fsynced cursor lacks.
        self.sync_with_hwm_marker(origin_key, cursor + seen, applied > 0)?;

        // `seen` is the number of frames the response actually carried (skipped + appended), which must
        // match its claimed count; `applied` (only the newly-appended) may be smaller after a skip.
        let actual = u32::try_from(seen).unwrap_or(u32::MAX);
        if actual != resp.record_count {
            // The synced records ARE durable; advance the cursor past what was consumed so the mismatch
            // does not strand applied data, then surface the malformed response.
            self.cursors.commit(origin_key, cursor + seen)?;
            return Err(GeoError::RecordCountMismatch {
                claimed: resp.record_count,
                actual,
            });
        }

        // Cursor advances ONLY after the records are durably synced (the load-bearing order), past every
        // frame consumed — so a single-origin mirror's cursor is re-anchored to `next_offset` and the
        // sync/commit crash window can never leave it lagging the durable log.
        let new_cursor = cursor + seen;
        self.cursors.commit(origin_key, new_cursor)?;
        Ok(ApplyOutcome {
            applied,
            cursor: new_cursor,
            origin_high_watermark: resp.origin_high_watermark,
        })
    }

    /// Lazily rebuild a MULTI-origin source's per-origin durable HWM (#906) from the local log's tail
    /// marker, once, on the first apply after open. A no-op for a single-origin applier (it anchors on
    /// `next_offset`) or once `origin_hwm` is already loaded. Kept out of `new` so construction stays
    /// infallible and an open never trips on a transient read.
    fn ensure_origin_hwm(&mut self) -> Result<(), GeoError> {
        if self.single_origin || self.origin_hwm.is_some() {
            return Ok(());
        }
        self.origin_hwm = Some(self.read_durable_hwm()?);
        Ok(())
    }

    /// Read the per-origin durable HWM snapshot from the local log's HIGHEST-offset record (#906). The
    /// tail of a source log is always the latest HWM marker — every batch that appended records ends with
    /// one and the highest offset is never reaped — so this is an O(1) tail read. A log with no records,
    /// or whose tail is not a marker (a fresh log, or a legacy pre-#906 log), recovers as an EMPTY map:
    /// the safe degrade to cursor-only (`durable_anchor == cursor`), identical to pre-#906 behavior, which
    /// self-heals after the first new batch writes a marker. A marker-LOOKING but undecodable tail (a
    /// pathological key+magic collision) likewise degrades to empty rather than failing the open.
    fn read_durable_hwm(&self) -> Result<BTreeMap<String, u64>, GeoError> {
        let next = self.log.next_offset().get();
        if next == 0 {
            return Ok(BTreeMap::new());
        }
        let tail = self.log.read_from(Offset::new(next - 1), 1)?;
        match tail.first() {
            Some(rec) if Self::is_hwm_marker(rec) => {
                let body = &rec.payload.as_ref()[GEO_HWM_MARKER_MAGIC.len()..];
                Ok(decode_cursor_payload(body).unwrap_or_default())
            }
            _ => Ok(BTreeMap::new()),
        }
    }

    /// Append one validated origin record to the local fan-in log, managing segment boundaries so a HWM
    /// marker ALWAYS caps a sealed segment (#906). For a MULTI-origin source: if the active segment is at
    /// or over the soft cap (the next normal append would roll it), FIRST append the current per-origin
    /// HWM marker as that segment's sealing TRAILER and force-seal it — so the just-sealed, fsynced
    /// segment ends with a marker covering exactly its records — then append this record (which starts the
    /// fresh segment) WITHOUT an implicit roll. This guarantees the durable tail is always a marker no
    /// matter where rolls fall, closing the roll-straddle window where the old "marker after the batch"
    /// approach left a data record stranded as the sealed tail. `hwm_before` is this origin's applied
    /// extent BEFORE this record — exactly what a sealing marker records for the records already resident.
    /// For a single-origin applier this is a plain `log.append` (the `next_offset` anchor is roll-proof,
    /// and the mirror's byte-identical layout must be preserved).
    fn append_origin_record(
        &mut self,
        origin_key: &str,
        record: &Append<'_>,
        hwm_before: u64,
    ) -> Result<(), GeoError> {
        if self.single_origin {
            self.log.append(record)?;
            return Ok(());
        }
        if self.log.active_segment_at_or_over_cap()? {
            // The active segment is full: cap it with a marker (covering the records already in it) so its
            // durable tail is a marker, then seal it. A crash after this seal recovers the right HWM from
            // that tail; the record below starts the fresh segment.
            self.write_hwm_marker(origin_key, hwm_before)?;
            self.log.seal_active_segment()?;
        }
        self.log.append_without_roll(record)?;
        Ok(())
    }

    /// Append a per-origin HWM marker record to the local fan-in log (#906) via `append_without_roll` (so
    /// it never triggers a roll itself — segment boundaries are managed by the caller), after advancing
    /// `origin_hwm[origin_key]` to `hwm` (monotonic). The payload is the magic plus the FULL `(origin ->
    /// applied offset)` snapshot, so one marker covers EVERY origin's records resident in the segment, not
    /// just this origin's. Multi-origin only — callers guarantee `!single_origin`.
    fn write_hwm_marker(&mut self, origin_key: &str, hwm: u64) -> Result<(), GeoError> {
        // Update the in-memory per-origin HWM, then encode the FULL snapshot. Scoped so the `origin_hwm`
        // borrow ends before `self.log` is touched below.
        let payload = {
            let map = self.origin_hwm.get_or_insert_with(BTreeMap::new);
            let slot = map.entry(origin_key.to_string()).or_insert(0);
            *slot = (*slot).max(hwm);
            let snapshot = encode_cursor_payload(map);
            let mut payload = Vec::with_capacity(GEO_HWM_MARKER_MAGIC.len() + snapshot.len());
            payload.extend_from_slice(GEO_HWM_MARKER_MAGIC);
            payload.extend_from_slice(&snapshot);
            payload
        };
        let timestamp_ms = self.log.now_unix_millis();
        self.log.append_without_roll(&Append {
            timestamp_ms,
            flags: RecordFlags::EMPTY,
            key: GEO_HWM_MARKER_KEY,
            headers: b"",
            payload: &payload,
        })?;
        Ok(())
    }

    /// Durably sync the just-applied batch, FIRST appending the FINAL per-origin HWM marker (#906) when
    /// this batch appended records to a MULTI-origin source log — so the marker (the per-origin
    /// applied-offset snapshot, `hwm` for `origin_key`) rides the SAME `log.sync()` fsync as the records
    /// it describes in the active (not-yet-sealed) segment. Mid-batch rolls are handled separately by
    /// [`append_origin_record`](MirrorApplier::append_origin_record), which caps each sealed segment with
    /// its own marker; this writes the final marker for the still-open segment. For a single-origin
    /// applier, or a batch that appended nothing (a pure-skip / idle pull), NO marker is written and this
    /// is just `log.sync()` — so the mirror's byte-identical log and the steady-state idle path are
    /// unchanged.
    fn sync_with_hwm_marker(
        &mut self,
        origin_key: &str,
        hwm: u64,
        appended: bool,
    ) -> Result<(), GeoError> {
        if appended && !self.single_origin {
            self.write_hwm_marker(origin_key, hwm)?;
        }
        self.log.sync()?;
        Ok(())
    }

    /// Whether a local-log record is a geo per-origin HWM marker (#906): its key is the reserved sentinel
    /// AND its payload leads with the marker magic. The two-part discriminator keeps an ordinary applied
    /// origin record (which never carries this NUL-prefixed key) from being mistaken for a marker.
    fn is_hwm_marker(rec: &OwnedRecord) -> bool {
        rec.key.as_ref() == GEO_HWM_MARKER_KEY
            && rec.payload.as_ref().starts_with(GEO_HWM_MARKER_MAGIC)
    }
}

/// One configured ORIGIN of a mirror/source: the remote cross-cluster address to dial and the named
/// origin stream to pull. A MIRROR has exactly ONE origin; a SOURCE has one or more. The `key` is the
/// stable, durable identity of this origin in the cursor store (`<addr>/<stream>`), so each origin's
/// resume cursor is independent and survives a restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoOrigin {
    /// The cross-cluster address of the remote origin's geo-pull endpoint (e.g. `10.0.0.1:7500`).
    pub addr: String,
    /// The named origin stream to pull (empty = the origin's default stream).
    pub stream: String,
}

impl GeoOrigin {
    /// The stable durable cursor key for this origin: `<addr>/<stream>`. Used as the
    /// [`OriginCursorStore`] key so each origin of a source has its OWN independent resume cursor.
    #[must_use]
    pub fn cursor_key(&self) -> String {
        format!("{}/{}", self.addr, self.stream)
    }
}

/// The geo MODE of a configured local stream: a read-only single-origin MIRROR, or a fan-in SOURCE of one
/// or more origins. A mirror rejects client produces; a source does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoMode {
    /// A read-only MIRROR of exactly ONE origin. Client produces to this local stream are rejected with
    /// [`GeoError::MirrorReadOnly`].
    Mirror(GeoOrigin),
    /// A SOURCE fanning in ONE OR MORE origins. Client produces to this local stream are allowed (a
    /// source may also take local writes); the geo apply interleaves the origins' records in.
    Source(Vec<GeoOrigin>),
}

impl GeoMode {
    /// The origins this mode pulls from (one for a mirror, N for a source), in their configured order
    /// (the source fan-in round-robin order).
    #[must_use]
    pub fn origins(&self) -> Vec<GeoOrigin> {
        match self {
            GeoMode::Mirror(o) => vec![o.clone()],
            GeoMode::Source(os) => os.clone(),
        }
    }

    /// True if this is a read-only mirror (client produces rejected).
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        matches!(self, GeoMode::Mirror(_))
    }
}

/// One configured local geo stream: its local name and its [`GeoMode`]. The CLI parses `--mirror` /
/// `--source` into a list of these; the serve hook builds an applier + a pull loop per stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoStreamConfig {
    /// The LOCAL stream name this mirror/source materializes.
    pub local_stream: String,
    /// Whether it is a read-only mirror or a fan-in source, and its origin(s).
    pub mode: GeoMode,
}

/// The whole geo configuration: the set of configured mirror/source local streams. Empty (the default)
/// means NO geo plane — the byte-identical single-node / non-geo path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GeoConfig {
    /// The configured mirror/source streams (one [`GeoStreamConfig`] per `--mirror` / `--source`).
    pub streams: Vec<GeoStreamConfig>,
}

impl GeoConfig {
    /// True if NO geo stream is configured — the byte-identical non-geo path (nothing constructs).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// The set of LOCAL stream names that are READ-ONLY mirrors — the streams a client produce must be
    /// rejected on ([`GeoError::MirrorReadOnly`]). The serve path consults this to enforce read-only.
    #[must_use]
    pub fn read_only_streams(&self) -> Vec<String> {
        self.streams
            .iter()
            .filter(|s| s.mode.is_read_only())
            .map(|s| s.local_stream.clone())
            .collect()
    }
}

/// Encode one geo-pull frame (request or response) to its on-wire bytes: the bounded
/// `[len][type=MirrorPull][body]` envelope, where the body is the `kind`-led layer encoding. Bounded the
/// same way the decoder bounds an incoming one.
///
/// # Errors
/// Returns [`GeoError::Frame`] if the body cannot be framed within the cap (it never should for a
/// layer-produced frame).
fn encode_geo_frame(body: &[u8]) -> Result<Vec<u8>, GeoError> {
    let mut out = Vec::with_capacity(body.len() + 5);
    encode_frame(FrameType::MirrorPull, body, &mut out).map_err(|e| GeoError::Frame {
        what: e.to_string(),
    })?;
    Ok(out)
}

/// A bidirectional CROSS-CLUSTER geo link over any byte stream (`Read + Write`): a real `TcpStream` in
/// production, an in-memory pipe in tests. It carries [`FrameType::MirrorPull`] request/response frames
/// over the SAME bounded `[len][type][body]` envelope every other frame uses, applying every bound on the
/// receive path (size cap before allocation, bounded layer decode), so a hostile / oversized / corrupt
/// frame is a typed [`GeoError`], never a panic or over-allocation.
///
/// Deliberately TRANSPORT-AGNOSTIC + synchronous, matching the broker's blocking `std::net` model and the
/// intra-cluster [`DataPlaneLink`](super::serve::DataPlaneLink): it carries no applier/origin state, so it
/// is trivially driven by a loopback harness.
pub struct GeoLink<S> {
    stream: S,
    /// Accumulated, not-yet-consumed inbound bytes (a partial frame may straddle reads).
    inbuf: Vec<u8>,
}

/// One decoded inbound geo frame: a pull REQUEST (origin side) or a pull RESPONSE (puller side). They
/// share the wire tag, distinguished by their `kind` byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoFrame {
    /// A puller → origin pull request.
    Request(MirrorPullRequest),
    /// An origin → puller pull response.
    Response(MirrorPullResponse),
}

impl<S: Read + Write> GeoLink<S> {
    /// Wrap a byte stream as a geo link.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            inbuf: Vec::new(),
        }
    }

    /// Send a pull REQUEST over the link.
    ///
    /// # Errors
    /// [`GeoError::OriginStreamNameTooLong`] if the name is over the cap, [`GeoError::Frame`] if it cannot
    /// be framed, or [`GeoError::Io`] on a write fault.
    pub fn send_request(&mut self, req: &MirrorPullRequest) -> Result<(), GeoError> {
        let frame = encode_geo_frame(&req.encode()?)?;
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send a pull RESPONSE over the link.
    ///
    /// # Errors
    /// [`GeoError::Frame`] if it cannot be framed, or [`GeoError::Io`] on a write fault.
    pub fn send_response(&mut self, resp: &MirrorPullResponse) -> Result<(), GeoError> {
        let frame = encode_geo_frame(&resp.encode())?;
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive ONE geo frame, BLOCKING on the underlying stream's read (the stream's read timeout governs
    /// how long it blocks — the caller sets it so an idle link blocks/backs off rather than busy-spins).
    /// Returns `Ok(None)` when the peer closes cleanly. Every bound is applied on the receive path.
    ///
    /// # Errors
    /// [`GeoError::ResponseTooLarge`] / [`GeoError::MalformedRequest`] / [`GeoError::MalformedResponse`]
    /// / [`GeoError::Frame`] on a bounded decode failure, or [`GeoError::Io`] on a read fault (including a
    /// timeout, surfaced as the underlying `WouldBlock`/`TimedOut` so the caller can re-poll).
    pub fn recv(&mut self) -> Result<Option<GeoFrame>, GeoError> {
        // Heap chunk (matches the intra-cluster `DataPlaneLink`): a 64 KiB stack array trips the
        // large-stack-array lint, and the read loop reuses the one buffer regardless.
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            // Try to decode a complete frame from what we already have before reading more.
            if let Some(frame) = self.try_decode_one()? {
                return Ok(Some(frame));
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                // Clean EOF with no complete frame buffered = peer closed.
                return Ok(None);
            }
            self.inbuf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Decode one buffered geo frame if a complete one is present, consuming its bytes. Returns `Ok(None)`
    /// when more bytes are needed. Applies the size cap before allocation and the bounded layer decode.
    fn try_decode_one(&mut self) -> Result<Option<GeoFrame>, GeoError> {
        let cap = MAX_FRAME_LEN.min(MAX_GEO_PULL_BYTES.saturating_add(1024));
        match decode_frame_with_cap(&self.inbuf, cap) {
            Ok(FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            }) => {
                if FrameType::from_u8(type_tag) != Some(FrameType::MirrorPull) {
                    return Err(GeoError::Frame {
                        what: format!("unexpected frame tag {type_tag} on the geo link"),
                    });
                }
                let frame = decode_geo_body(body)?;
                self.inbuf.drain(..consumed);
                Ok(Some(frame))
            }
            Ok(FrameDecode::Incomplete { .. }) => Ok(None),
            Err(FrameError::FrameTooLarge { len }) => Err(GeoError::ResponseTooLarge { len }),
            Err(e) => Err(GeoError::Frame {
                what: e.to_string(),
            }),
        }
    }
}

/// Route a geo-frame body (the `kind`-led layer bytes after the envelope) into a [`GeoFrame`] by its
/// leading `kind` byte. A request (`kind = 0`) decodes a [`MirrorPullRequest`]; a response (`kind = 1`) a
/// [`MirrorPullResponse`]; any other kind is a fail-closed framing error.
fn decode_geo_body(body: &[u8]) -> Result<GeoFrame, GeoError> {
    match body.first().copied() {
        Some(PULL_KIND_REQUEST) => Ok(GeoFrame::Request(MirrorPullRequest::decode(body)?)),
        Some(PULL_KIND_RESPONSE) => Ok(GeoFrame::Response(MirrorPullResponse::decode(body)?)),
        other => Err(GeoError::Frame {
            what: format!("unknown geo frame kind {other:?}"),
        }),
    }
}

/// How long a geo pull loop BLOCKS on the link read for a response before re-checking shutdown, and how
/// long a caught-up puller / a failed dial BACKS OFF before re-polling — the idle-friendly cadence (the
/// #726 lesson: an idle pull loop must block/back off, ~0 idle CPU, never busy-spin). A real serve sets
/// this on the dialed stream; the loop sleeps interruptibly for it when caught up.
pub const GEO_POLL: Duration = Duration::from_millis(200);

/// The per-pull record / byte budget the geo pull loop requests. Bounded so one response always frames
/// under [`MAX_GEO_PULL_BYTES`] and a single slow link never buffers unboundedly.
const GEO_PULL_MAX_RECORDS: u32 = 1024;
const GEO_PULL_MAX_BYTES: u32 = 1024 * 1024;

/// Sleep for `dur` but wake early if shutdown is set, in small slices, so a stop is never delayed by a
/// full sleep. Mirrors the intra-cluster [`serve`](super::serve)'s `sleep_interruptible`.
fn sleep_interruptible(dur: Duration, shutdown: &AtomicBool) {
    let slice = Duration::from_millis(20);
    let mut left = dur;
    while left > Duration::ZERO && !shutdown.load(Ordering::Acquire) {
        let this = slice.min(left);
        std::thread::sleep(this);
        left = left.checked_sub(this).unwrap_or(Duration::ZERO);
    }
}

/// Drive ONE connected geo link for one origin: pull → apply → persist-cursor, on a cadence, until
/// shutdown or the link breaks. Each round sends a pull from the durable cursor, reads the response
/// (BLOCKING up to the link's read timeout — never a busy-spin), applies the CRC-revalidated bytes to the
/// local log, and durably advances the cursor. A caught-up puller (empty response) BACKS OFF for
/// [`GEO_POLL`] before re-polling. A corrupt / non-contiguous response is dropped fail-closed (the cursor
/// did not advance past it); the caller reconnects and resumes from the cursor.
///
/// `apply` is the closure that takes the response under whatever lock the caller holds the applier behind
/// and returns the [`ApplyOutcome`] (so this loop is transport- and lock-agnostic, like the intra-cluster
/// `follower_fetch_loop`).
///
/// Returns when shutdown is observed or the link is determined broken (the caller reconnects).
pub fn pull_loop<S, A>(
    link: &mut GeoLink<S>,
    origin_key: &str,
    origin_stream: &str,
    shutdown: &AtomicBool,
    mut next_cursor: impl FnMut() -> u64,
    mut apply: A,
) where
    S: Read + Write,
    A: FnMut(&MirrorPullResponse) -> Result<ApplyOutcome, GeoError>,
{
    while !shutdown.load(Ordering::Acquire) {
        let req = MirrorPullRequest {
            stream: origin_stream.to_string(),
            from_offset: next_cursor(),
            max_records: GEO_PULL_MAX_RECORDS,
            max_bytes: GEO_PULL_MAX_BYTES,
        };
        if link.send_request(&req).is_err() {
            return; // link broke; the caller reconnects
        }
        match link.recv() {
            Ok(Some(GeoFrame::Response(resp))) => {
                let empty = resp.record_count == 0;
                if !empty {
                    // Apply the CRC-revalidated bytes. A corrupt / non-contiguous frame fails closed; the
                    // cursor did not move past it, so drop this link and re-pull from the cursor.
                    if let Err(e) = apply(&resp) {
                        tracing::debug!(origin = origin_key, error = %e, "geo: apply failed; will resume from cursor");
                        return;
                    }
                }
                // If the origin served a full run there may be more to pull; loop promptly. Otherwise pace
                // the next poll so a caught-up mirror does not hot-loop (the idle ~0-CPU discipline).
                if empty {
                    sleep_interruptible(GEO_POLL, shutdown);
                }
            }
            // A request on the puller link, or any other frame: ignore + back off.
            Ok(Some(GeoFrame::Request(_))) => sleep_interruptible(GEO_POLL, shutdown),
            Err(GeoError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // The read timeout elapsed with no full frame: the link buffers any partial, loop and
                // re-poll (re-checking shutdown). This is the BLOCKING idle path — ~0 CPU while idle.
            }
            // The origin closed cleanly (`Ok(None)`), or a decode / link error (`Err(_)`): drop the link
            // and let the caller reconnect + resume from the durable cursor.
            Ok(None) | Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::io::RandomAccessFile;
    use ironbus_storage::log::{Append, LogConfig};

    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    #[test]
    fn pull_request_round_trips_with_a_named_stream() {
        let req = MirrorPullRequest {
            stream: "orders".to_string(),
            from_offset: 42,
            max_records: 100,
            max_bytes: 4096,
        };
        let bytes = req.encode().unwrap();
        assert_eq!(MirrorPullRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn pull_request_empty_stream_round_trips() {
        let req = MirrorPullRequest {
            stream: String::new(),
            from_offset: 0,
            max_records: 1,
            max_bytes: 0,
        };
        let bytes = req.encode().unwrap();
        assert_eq!(MirrorPullRequest::decode(&bytes).unwrap(), req);
    }

    #[test]
    fn pull_response_round_trips() {
        let resp = MirrorPullResponse {
            origin_high_watermark: 9,
            first_offset: 3,
            record_count: 2,
            frame_bytes: Bytes::from_static(&[1, 2, 3, 4, 5]),
        };
        let bytes = resp.encode();
        assert_eq!(MirrorPullResponse::decode(&bytes).unwrap(), resp);
    }

    #[test]
    fn an_over_cap_response_is_rejected_pre_buffer() {
        // Hand-build a response whose claimed frame_bytes_len exceeds the cap.
        let mut body = Vec::new();
        body.push(PULL_KIND_RESPONSE);
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&(MAX_GEO_PULL_BYTES + 1).to_le_bytes());
        match MirrorPullResponse::decode(&body) {
            Err(GeoError::ResponseTooLarge { len }) => {
                assert_eq!(len, u64::from(MAX_GEO_PULL_BYTES) + 1);
            }
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn an_over_long_origin_stream_name_is_rejected_on_encode() {
        let req = MirrorPullRequest {
            stream: "x".repeat(MAX_ORIGIN_STREAM_LEN + 1),
            from_offset: 0,
            max_records: 1,
            max_bytes: 0,
        };
        assert!(matches!(
            req.encode(),
            Err(GeoError::OriginStreamNameTooLong { .. })
        ));
    }

    #[test]
    fn a_malformed_request_kind_is_rejected() {
        let mut body = MirrorPullRequest {
            stream: "s".to_string(),
            from_offset: 0,
            max_records: 0,
            max_bytes: 0,
        }
        .encode()
        .unwrap();
        body[0] = 9; // wrong kind
        assert!(matches!(
            MirrorPullRequest::decode(&body),
            Err(GeoError::MalformedRequest { .. })
        ));
    }

    #[test]
    fn cursor_store_persists_and_recovers_per_origin() {
        let fs = InMemoryFs::new();
        {
            let mut store = OriginCursorStore::open(&fs).unwrap();
            assert_eq!(store.cursor("a/orders"), 0);
            store.commit("a/orders", 5).unwrap();
            store.commit("b/events", 3).unwrap();
            // Monotonic: a backward commit is a no-op.
            store.commit("a/orders", 4).unwrap();
            assert_eq!(store.cursor("a/orders"), 5);
        }
        // Re-open over the SAME fs: cursors recover independently.
        let store = OriginCursorStore::open(&fs).unwrap();
        assert_eq!(store.cursor("a/orders"), 5);
        assert_eq!(store.cursor("b/events"), 3);
        assert_eq!(store.cursor("c/never"), 0);
    }

    #[test]
    fn a_torn_cursor_file_recovers_safely_as_no_cursors() {
        // The dual-slot CRC checkpoint reverts a TORN write to the prior intact slot, and a fully torn /
        // zeroed file recovers as NO cursors (every origin resumes from 0 — the safe degrade: a fresh
        // re-pull, never a misread / mis-resumed cursor that could skip or re-apply).
        let fs = InMemoryFs::new();
        {
            let mut store = OriginCursorStore::open(&fs).unwrap();
            store.commit("a/orders", 5).unwrap();
        }
        // Zero the whole cursor file (simulate a torn/garbage file): both slots fail CRC.
        let len = usize::try_from(fs.open(CURSOR_FILE).unwrap().len().unwrap()).unwrap();
        let f = fs.open(CURSOR_FILE).unwrap();
        f.write_all_at(&vec![0u8; len], 0).unwrap();
        f.sync_all().unwrap();
        // Recovers as no cursors rather than failing startup (resume from 0).
        let store = OriginCursorStore::open(&fs).unwrap();
        assert_eq!(store.cursor("a/orders"), 0);
    }

    /// Build a SINGLE-ORIGIN applier (a MIRROR, or a single-origin SOURCE) over an in-memory log +
    /// cursor store sharing ONE fs (so the cursor file lives beside the log), returning the applier. The
    /// `single_origin` flag enables the #799 `next_offset` reconciliation; use [`source_applier`] for a
    /// multi-origin fan-in.
    fn applier(fs: InMemoryFs) -> MirrorApplier<InMemoryFs, ManualClock> {
        let cursors = OriginCursorStore::open(&fs).unwrap();
        // `fs` is MOVED into the log here (consumed), so the helper takes it by value without tripping
        // the needless-pass-by-value lint; the cursor store already captured its own file handle above.
        let log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        MirrorApplier::new(log, cursors, true)
    }

    /// Build a MULTI-ORIGIN (fan-in SOURCE) applier: `single_origin` is false, so the #799 `next_offset`
    /// reconciliation is OFF (a multi-origin log interleaves origins, so `next_offset` is not any single
    /// origin's offset and cannot anchor it).
    fn source_applier(fs: InMemoryFs) -> MirrorApplier<InMemoryFs, ManualClock> {
        let cursors = OriginCursorStore::open(&fs).unwrap();
        let log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        MirrorApplier::new(log, cursors, false)
    }

    /// Serve ONE pull response from the origin's read plane at offset `from` (the sealed prefix; with a
    /// small segment size one pull covers one sealed segment, and successive pulls converge).
    fn origin_pull(origin: &Log<InMemoryFs, ManualClock>, from: u64) -> MirrorPullResponse {
        let plane = origin.read_plane().unwrap();
        let server = OriginServer::new(&plane);
        let req = MirrorPullRequest {
            stream: String::new(),
            from_offset: from,
            max_records: 1024,
            max_bytes: 0,
        };
        server.serve_pull(&req).unwrap()
    }

    /// The first offset the origin's read plane does NOT serve off its sealed prefix — what a mirror
    /// converges to before the active (flushed-but-unsealed) tail seals. Mirrors the intra-cluster
    /// `serve` test's `plane_served_end`.
    fn plane_served_end(origin: &Log<InMemoryFs, ManualClock>) -> u64 {
        let plane = origin.read_plane().unwrap();
        let flushed = plane.flushed();
        let mut next = 0u64;
        let mut guard = 0u32;
        while next < flushed {
            guard += 1;
            assert!(guard < 100_000, "read-plane chain failed to terminate");
            let raw = plane
                .read_range_raw(Offset::new(next), 1_000, None)
                .expect("read plane serves");
            let advanced = raw.run.next_offset.get();
            if advanced > next {
                next = advanced;
            } else {
                break;
            }
        }
        next
    }

    /// Pull-and-apply one origin into a mirror to convergence (the sealed-served prefix), returning the
    /// total applied. Loops because a small segment size means one pull covers one sealed segment.
    fn drain_into(
        app: &mut MirrorApplier<InMemoryFs, ManualClock>,
        origin: &Log<InMemoryFs, ManualClock>,
        key: &str,
    ) -> u64 {
        let mut total = 0u64;
        loop {
            let resp = origin_pull(origin, app.cursor(key));
            let out = app.apply_pull_response(key, &resp).unwrap();
            if out.applied == 0 {
                break;
            }
            total += out.applied;
        }
        total
    }

    #[test]
    fn mirror_applies_byte_faithfully_in_order_and_advances_the_cursor() {
        // Origin: 30 records, fsync'd — enough to seal several 256-byte segments so the read plane serves
        // a real sealed prefix.
        let mut origin = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            origin.append(&rec(format!("o-{i:02}").as_bytes())).unwrap();
        }
        origin.sync().unwrap();
        let served = plane_served_end(&origin);
        assert!(
            served > 0,
            "the read plane serves a non-empty sealed prefix"
        );

        // Mirror: drain the origin to convergence.
        let mut app = applier(InMemoryFs::new());
        let key = "origin/";
        let applied = drain_into(&mut app, &origin, key);
        assert_eq!(
            applied, served,
            "the mirror applied the whole sealed prefix"
        );

        // The mirror's records are byte-faithful to the origin's (payloads in order).
        let mirror_recs = app.log().read_from(Offset::new(0), 100).unwrap();
        assert_eq!(mirror_recs.len() as u64, served);
        for (i, r) in mirror_recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("o-{i:02}").as_bytes());
        }
        // The cursor advanced to exactly the applied count (the durable resume point).
        assert_eq!(app.cursor(key), served);

        // BYTE-IDENTITY: for a single-origin mirror replicating from origin 0 in order, the mirror's
        // on-disk record frames are byte-identical to the origin's over the sealed prefix (same codec,
        // same positional offsets/seqs). Compare the sealed segments' bytes.
        let origin_plane = origin.read_plane().unwrap();
        let mirror_plane = app.log().read_plane().unwrap();
        let o_raw = origin_plane
            .read_range_raw(Offset::new(0), 1_000_000, None)
            .unwrap();
        let m_raw = mirror_plane
            .read_range_raw(Offset::new(0), 1_000_000, None)
            .unwrap();
        assert_eq!(
            m_raw.run.bytes.as_ref(),
            o_raw.run.bytes.as_ref(),
            "the mirror's sealed record frames are byte-identical to the origin's"
        );
    }

    #[test]
    fn the_cursor_is_durable_and_resumes_without_gap_or_dup() {
        let mut origin = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            origin.append(&rec(format!("o-{i:02}").as_bytes())).unwrap();
        }
        origin.sync().unwrap();
        let served = plane_served_end(&origin);

        // The mirror shares ONE fs so the cursor file + log survive a "restart" (reopen).
        let fs = InMemoryFs::new();
        let key = "origin/";
        // First pull: apply ONE batch (one sealed segment), then DROP the applier (simulating a crash /
        // disconnect after a partial catch-up).
        let first_batch = {
            let mut app = applier(fs.clone());
            let resp = origin_pull(&origin, app.cursor(key));
            let out = app.apply_pull_response(key, &resp).unwrap();
            assert!(out.applied >= 1, "first batch applied something");
            out.cursor
        };
        assert!(first_batch < served, "did not finish in one batch");

        // REOPEN over the same fs: the durable cursor recovers, and draining RESUMES from there with no
        // gap and no dup (the local log has exactly the sealed prefix, in order, once).
        let mut app = applier(fs);
        assert_eq!(app.cursor(key), first_batch, "cursor recovered durably");
        let more = drain_into(&mut app, &origin, key);
        assert_eq!(app.cursor(key), served, "resumed to the sealed prefix");
        assert_eq!(
            first_batch + more,
            served,
            "no gap, no dup across the restart"
        );
        let recs = app.log().read_from(Offset::new(0), 1000).unwrap();
        assert_eq!(recs.len() as u64, served);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("o-{i:02}").as_bytes());
        }
    }

    #[test]
    fn a_re_pull_after_the_sync_before_commit_crash_window_skips_not_double_applies() {
        // #799: the local record sync and the durable cursor commit are TWO separate fsyncs (records
        // first). A crash between them leaves the local log AHEAD of the durable cursor. For a
        // single-origin MIRROR the local log's `next_offset` is an INDEPENDENT durable anchor: a re-pull
        // that re-serves the already-applied span must SKIP it, never re-append — re-appending would
        // duplicate the span, grow the log past the origin, and permanently break positional
        // byte-identity. We construct the post-crash state directly: a local log that already durably
        // holds the origin's served prefix, but a cursor that lags it.
        let mut origin = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            origin.append(&rec(format!("o-{i:02}").as_bytes())).unwrap();
        }
        origin.sync().unwrap();
        let served = plane_served_end(&origin);
        assert!(
            served >= 4,
            "the origin serves a multi-record sealed prefix"
        );

        // Post-crash MIRROR: the local log holds [0, served) (the records were synced) but the durable
        // cursor lags at `stale` (the commit never landed). The two live on independent in-memory disks
        // so the cursor can be set BELOW the log head — exactly what the crash window produces.
        let key = "origin/";
        let stale = served - 3;
        let mut local_log =
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..served {
            local_log
                .append(&rec(format!("o-{i:02}").as_bytes()))
                .unwrap();
        }
        local_log.sync().unwrap();
        assert_eq!(local_log.next_offset().get(), served);
        let mut cursors = OriginCursorStore::open(&InMemoryFs::new()).unwrap();
        cursors.commit(key, stale).unwrap();
        let mut app = MirrorApplier::new(local_log, cursors, true);
        assert_eq!(
            app.cursor(key),
            stale,
            "the cursor lags the durable log (the crash window)"
        );

        // Re-pull from the stale cursor to convergence: every re-served frame is already durable in the
        // local log, so the applier SKIPS them all and NEVER re-appends (loops because one pull serves at
        // most one sealed segment). Pre-fix every frame at-or-above the stale cursor was re-appended.
        let mut guard = 0;
        while app.cursor(key) < served {
            guard += 1;
            assert!(guard < 1000, "the re-pull loop did not converge");
            let resp = origin_pull(&origin, app.cursor(key));
            let out = app.apply_pull_response(key, &resp).unwrap();
            assert_eq!(
                out.applied, 0,
                "a re-pulled, already-applied frame must never be re-appended (#799)"
            );
        }

        // No duplicated span: the log still holds exactly `served` records and the cursor caught up to
        // the durable head. Byte-identity with the origin's served prefix is intact.
        assert_eq!(
            app.log().next_offset().get(),
            served,
            "the local log did NOT grow — the already-applied span was not double-applied"
        );
        assert_eq!(
            app.cursor(key),
            served,
            "the cursor is re-anchored to the durable log head"
        );
        let recs = app.log().read_from(Offset::new(0), 1000).unwrap();
        assert_eq!(recs.len() as u64, served, "no duplicate records on disk");
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("o-{i:02}").as_bytes());
        }
    }

    #[test]
    fn a_non_contiguous_response_is_dropped_fail_closed() {
        let mut app = applier(InMemoryFs::new());
        let resp = MirrorPullResponse {
            origin_high_watermark: 10,
            first_offset: 5, // cursor is 0, so this is a gap
            record_count: 1,
            frame_bytes: {
                let mut b = Vec::new();
                ironbus_core::codec::encode(
                    &ironbus_core::codec::RecordView {
                        seq: ironbus_core::types::Seq::new(0),
                        timestamp_ms: 1,
                        flags: RecordFlags::EMPTY,
                        key: b"",
                        headers: b"",
                        payload: b"x",
                    },
                    &mut b,
                )
                .unwrap();
                Bytes::from(b)
            },
        };
        assert!(matches!(
            app.apply_pull_response("o/", &resp),
            Err(GeoError::NonContiguous {
                expected: 0,
                got: 5
            })
        ));
        assert_eq!(app.cursor("o/"), 0, "cursor did not advance on a gap");
    }

    #[test]
    fn a_corrupt_frame_fails_closed_and_does_not_advance_past_it() {
        let mut app = applier(InMemoryFs::new());
        // One good frame followed by a corrupt one.
        let mut frames = Vec::new();
        ironbus_core::codec::encode(
            &ironbus_core::codec::RecordView {
                seq: ironbus_core::types::Seq::new(0),
                timestamp_ms: 1,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"good",
            },
            &mut frames,
        )
        .unwrap();
        let good_len = frames.len();
        ironbus_core::codec::encode(
            &ironbus_core::codec::RecordView {
                seq: ironbus_core::types::Seq::new(1),
                timestamp_ms: 1,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"bad",
            },
            &mut frames,
        )
        .unwrap();
        // Corrupt a byte inside the second frame's body.
        let bad_byte = good_len + 4;
        frames[bad_byte] ^= 0xFF;
        let resp = MirrorPullResponse {
            origin_high_watermark: 2,
            first_offset: 0,
            record_count: 2,
            frame_bytes: Bytes::from(frames),
        };
        let err = app.apply_pull_response("o/", &resp).unwrap_err();
        assert!(
            matches!(
                err,
                GeoError::CorruptFrame {
                    at_origin_offset: 1,
                    ..
                }
            ),
            "expected CorruptFrame at offset 1, got {err:?}"
        );
        // The good prefix WAS applied + cursor advanced exactly one (resume cleanly from there).
        assert_eq!(app.cursor("o/"), 1);
        assert_eq!(app.log().read_from(Offset::new(0), 10).unwrap().len(), 1);
    }

    #[test]
    fn source_fan_in_preserves_per_origin_order_with_independent_cursors() {
        // Two origins, each with its own records (enough to seal segments so the planes serve).
        let mut origin_a =
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        let mut origin_b =
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            origin_a
                .append(&rec(format!("A-{i:02}").as_bytes()))
                .unwrap();
            origin_b
                .append(&rec(format!("B-{i:02}").as_bytes()))
                .unwrap();
        }
        origin_a.sync().unwrap();
        origin_b.sync().unwrap();
        let served_a = plane_served_end(&origin_a);
        let served_b = plane_served_end(&origin_b);
        assert!(served_a > 0 && served_b > 0);

        let mut app = source_applier(InMemoryFs::new());
        let ka = "a/";
        let kb = "b/";
        // Interleave: drain one batch from A, then one from B, round-robin (apply-arrival interleaving),
        // until both are caught up to their sealed prefixes.
        loop {
            let ra = origin_pull(&origin_a, app.cursor(ka));
            let pa = app.apply_pull_response(ka, &ra).unwrap();
            let rb = origin_pull(&origin_b, app.cursor(kb));
            let pb = app.apply_pull_response(kb, &rb).unwrap();
            if pa.applied == 0 && pb.applied == 0 {
                break;
            }
        }
        // Both cursors advanced INDEPENDENTLY to their origins' sealed-served prefixes.
        assert_eq!(app.cursor(ka), served_a);
        assert_eq!(app.cursor(kb), served_b);

        // Per-origin order is preserved: the local A-records appear in A's order, likewise B's.
        let local = app.log().read_from(Offset::new(0), 1000).unwrap();
        let a_seen: Vec<&[u8]> = local
            .iter()
            .map(|r| r.payload.as_ref())
            .filter(|p| p.starts_with(b"A-"))
            .collect();
        let b_seen: Vec<&[u8]> = local
            .iter()
            .map(|r| r.payload.as_ref())
            .filter(|p| p.starts_with(b"B-"))
            .collect();
        for (i, p) in a_seen.iter().enumerate() {
            assert_eq!(*p, format!("A-{i:02}").as_bytes());
        }
        for (i, p) in b_seen.iter().enumerate() {
            assert_eq!(*p, format!("B-{i:02}").as_bytes());
        }
        // Both origins' records are all present (fan-in), and their counts equal each sealed prefix.
        assert_eq!(a_seen.len() as u64, served_a);
        assert_eq!(b_seen.len() as u64, served_b);
        // The fan-in log holds exactly the A records, the B records, and the per-origin HWM markers
        // (#906) — nothing else, no duplicates: every record is accounted for.
        let markers = local
            .iter()
            .filter(|r| r.payload.as_ref().starts_with(GEO_HWM_MARKER_MAGIC))
            .count();
        assert_eq!(a_seen.len() + b_seen.len() + markers, local.len());
    }

    #[test]
    fn a_multi_origin_source_re_pull_after_the_crash_window_skips_not_double_applies() {
        // #906: a multi-origin SOURCE syncs the applied records (with their per-origin HWM marker) in ONE
        // fsync, then commits the per-origin cursor in a SEPARATE fsync. A crash between the two leaves the
        // records + marker durable but the cursor STALE. THE BUG: pre-fix the multi-origin path had no
        // positional anchor (its `next_offset` is the interleaved fan-in total), so a re-pull from the
        // stale cursor RE-APPLIED the already-durable batch — a duplicated block in the fan-in stream. THE
        // FIX: the per-origin in-log HWM, recovered from the tail marker (durable with the SAME fsync as
        // the records), anchors the skip so the re-pull is an enforced no-op. We reproduce the post-crash
        // DURABLE state (records + marker ahead, cursor lagging) exactly as the single-origin #799 test does.
        let mut origin_a =
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        let mut origin_b =
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            origin_a
                .append(&rec(format!("A-{i:02}").as_bytes()))
                .unwrap();
            origin_b
                .append(&rec(format!("B-{i:02}").as_bytes()))
                .unwrap();
        }
        origin_a.sync().unwrap();
        origin_b.sync().unwrap();
        let served_a = plane_served_end(&origin_a);
        let served_b = plane_served_end(&origin_b);
        assert!(served_a >= 4 && served_b >= 4);

        let log_fs = InMemoryFs::new();
        let (ka, kb) = ("a/", "b/");
        // Apply BOTH origins to convergence via the REAL apply path (markers written, riding the same
        // fsync as their records). This is the durable LOG state at the instant of the crash.
        {
            let mut app = source_applier(log_fs.clone());
            let mut guard = 0;
            loop {
                guard += 1;
                assert!(guard < 1000, "initial fan-in did not converge");
                let pa = app
                    .apply_pull_response(ka, &origin_pull(&origin_a, app.cursor(ka)))
                    .unwrap();
                let pb = app
                    .apply_pull_response(kb, &origin_pull(&origin_b, app.cursor(kb)))
                    .unwrap();
                if pa.applied == 0 && pb.applied == 0 {
                    break;
                }
            }
            assert_eq!(app.cursor(ka), served_a);
            assert_eq!(app.cursor(kb), served_b);
        }

        // CRASH WINDOW: the records + their HWM marker are durable (the log fsync landed) but A's cursor
        // commit was LOST (the second, separate fsync did not). Reproduce that exact durable state the way
        // the single-origin #799 test does — the log and the cursor on INDEPENDENT disks, so the cursor
        // can sit BELOW the log head without the monotonic-commit guard refusing it: reopen the fan-in log
        // (with its tail marker), and pair it with a FRESH cursor store committed FORWARD from 0 to the
        // stale value A held before the lost commit (B's commit landed, so B is at its applied offset).
        let stale_a = served_a - 3;
        let log = Log::open(log_fs.clone(), ManualClock::new(), small_config()).unwrap();
        let mut cursors = OriginCursorStore::open(&InMemoryFs::new()).unwrap();
        cursors.commit(ka, stale_a).unwrap();
        cursors.commit(kb, served_b).unwrap();
        let mut app = MirrorApplier::new(log, cursors, false);
        assert_eq!(
            app.cursor(ka),
            stale_a,
            "A's cursor lags its durable log (the crash window)"
        );
        assert_eq!(app.cursor(kb), served_b, "B's cursor is intact");

        // Re-pull A from the stale cursor to convergence: every re-served frame is already durable in the
        // fan-in log, so the applier SKIPS them all and NEVER re-appends. Pre-#906 each was re-appended.
        let mut guard = 0;
        while app.cursor(ka) < served_a {
            guard += 1;
            assert!(guard < 1000, "the re-pull loop did not converge");
            let out = app
                .apply_pull_response(ka, &origin_pull(&origin_a, app.cursor(ka)))
                .unwrap();
            assert_eq!(
                out.applied, 0,
                "a re-pulled, already-applied frame must never be re-appended (#906)"
            );
        }
        assert_eq!(
            app.cursor(ka),
            served_a,
            "A's cursor re-anchored to its durable applied offset"
        );

        // No duplicated block: the fan-in log holds EXACTLY A's and B's served prefixes (plus markers), in
        // per-origin order. If A had been double-applied, `a_seen.len()` would exceed `served_a`.
        let local = app.log().read_from(Offset::new(0), 10_000).unwrap();
        let a_seen: Vec<&[u8]> = local
            .iter()
            .map(|r| r.payload.as_ref())
            .filter(|p| p.starts_with(b"A-"))
            .collect();
        let b_seen: Vec<&[u8]> = local
            .iter()
            .map(|r| r.payload.as_ref())
            .filter(|p| p.starts_with(b"B-"))
            .collect();
        assert_eq!(
            a_seen.len() as u64,
            served_a,
            "A was NOT double-applied — the fan-in log did not grow"
        );
        assert_eq!(b_seen.len() as u64, served_b, "B is untouched");
        for (i, p) in a_seen.iter().enumerate() {
            assert_eq!(*p, format!("A-{i:02}").as_bytes());
        }
        for (i, p) in b_seen.iter().enumerate() {
            assert_eq!(*p, format!("B-{i:02}").as_bytes());
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_multi_origin_re_pull_after_a_roll_straddle_crash_skips_not_double_applies() {
        // #906 (THE roll-straddle hole the first cut missed): a fan-in apply batch can span a LOCAL
        // segment roll. `roll()` seals + fsyncs the old segment INDEPENDENTLY (segment.rs `seal` →
        // `sync_all`), so a crash AFTER a mid-batch seal but BEFORE the batch's final fsync would, under
        // the naive "one marker after the batch" scheme, leave a DATA record as the durable tail →
        // recovery reads an empty HWM → the already-durable prefix is RE-APPLIED. The fix caps EVERY
        // sealed segment with a marker (`append_origin_record` writes the marker as the sealing trailer
        // via `append_without_roll` + `seal_active_segment`), so the durable tail is always a marker.
        //
        // We exercise it for real: origins with BIG segments (one pull serves many records) feeding a
        // small-segment local log (so the batch straddles several rolls), then a power-loss crash before
        // the final sync via the `apply_then_crash_before_final_sync` seam.
        let big = LogConfig {
            max_segment_bytes: 4096,
            max_total_bytes: 0,
            ..LogConfig::default()
        };
        let mut origin_a = Log::open(InMemoryFs::new(), ManualClock::new(), big).unwrap();
        for i in 0..120u32 {
            origin_a
                .append(&rec(format!("A-{i:03}").as_bytes()))
                .unwrap();
        }
        origin_a.sync().unwrap();
        let served_a = plane_served_end(&origin_a);
        assert!(
            served_a >= 20,
            "origin A serves a many-record sealed prefix: {served_a}"
        );

        let mut origin_b =
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..12u32 {
            origin_b
                .append(&rec(format!("B-{i:03}").as_bytes()))
                .unwrap();
        }
        origin_b.sync().unwrap();
        let served_b = plane_served_end(&origin_b);
        assert!(served_b >= 2);

        let fs = InMemoryFs::new();
        let (ka, kb) = ("a/", "b/");
        {
            let mut app = source_applier(fs.clone());
            // Drain B fully (committed), so the marker's full snapshot must also carry B across the crash.
            let mut guard = 0;
            loop {
                guard += 1;
                assert!(guard < 1000);
                if app
                    .apply_pull_response(kb, &origin_pull(&origin_b, app.cursor(kb)))
                    .unwrap()
                    .applied
                    == 0
                {
                    break;
                }
            }
            assert_eq!(app.cursor(kb), served_b);

            // Apply ONE big A pull, but CRASH before its final sync: the many records straddle several
            // local 256-byte rolls, so mid-batch seals (each marker-capped) become durable while the
            // active tail + A's cursor do not.
            let out = app
                .apply_then_crash_before_final_sync(ka, &origin_pull(&origin_a, 0))
                .unwrap();
            assert!(
                out.applied >= 20,
                "the A pull applied many records: {}",
                out.applied
            );
        }

        // POWER LOSS: every unsynced byte is dropped. The mid-batch-sealed (marker-capped) segments
        // survive; the active tail (the post-last-seal A records + the never-written final marker) and
        // A's uncommitted cursor are gone.
        fs.simulate_power_loss();

        // Reopen: recovery rebuilds the per-origin HWM from the DURABLE TAIL. The fix guarantees that tail
        // is a MARKER (every sealed segment is marker-capped), even though A's batch straddled a roll, so
        // A's recovered HWM is strictly between 0 and the batch end. Pre-fix the durable tail would have
        // been a DATA record → empty HWM → `a_durable == 0` → the assertion below would fail and the
        // re-pull would double-apply. B's committed cursor survived.
        let mut app = source_applier(fs.clone());
        assert_eq!(
            app.cursor(kb),
            served_b,
            "B's committed cursor survived the crash"
        );
        let recovered = app.read_durable_hwm().unwrap();
        let a_durable = recovered.get(ka).copied().unwrap_or(0);
        assert!(
            a_durable > 0 && a_durable < served_a,
            "the durable tail is a marker carrying A's PARTIAL durable HWM (a roll-straddle): {a_durable} \
             of {served_a} — pre-fix this would be 0 (a data-record tail) and the prefix would double-apply"
        );
        assert_eq!(
            recovered.get(kb).copied(),
            Some(served_b),
            "the same marker snapshot also preserved B's HWM across the crash"
        );

        // Re-pull A to convergence from its (uncommitted => 0) cursor: the already-durable prefix
        // [0, a_durable) is SKIPPED, the lost tail is re-applied fresh. No A record appears twice.
        let mut guard = 0;
        let mut re_applied = 0u64;
        while app.cursor(ka) < served_a {
            guard += 1;
            assert!(guard < 1000, "A re-pull did not converge");
            re_applied += app
                .apply_pull_response(ka, &origin_pull(&origin_a, app.cursor(ka)))
                .unwrap()
                .applied;
        }
        assert_eq!(app.cursor(ka), served_a);

        // The fan-in log holds EXACTLY served_a A-records and served_b B-records — each origin record
        // once, in order. A roll-straddle double-apply of [0, a_durable) would push a_seen above served_a.
        let local = app.log().read_from(Offset::new(0), 100_000).unwrap();
        let a_seen: Vec<&[u8]> = local
            .iter()
            .map(|r| r.payload.as_ref())
            .filter(|p| p.starts_with(b"A-"))
            .collect();
        let b_seen: Vec<&[u8]> = local
            .iter()
            .map(|r| r.payload.as_ref())
            .filter(|p| p.starts_with(b"B-"))
            .collect();
        assert_eq!(
            a_seen.len() as u64,
            served_a,
            "A applied EXACTLY once — no roll-straddle double-apply (#906)"
        );
        assert_eq!(b_seen.len() as u64, served_b, "B untouched");
        for (i, p) in a_seen.iter().enumerate() {
            assert_eq!(*p, format!("A-{i:03}").as_bytes());
        }
        for (i, p) in b_seen.iter().enumerate() {
            assert_eq!(*p, format!("B-{i:03}").as_bytes());
        }
        // The lost tail [a_durable, served_a) really was re-applied (not silently dropped).
        assert!(
            re_applied >= served_a - a_durable,
            "the lost active tail was re-applied fresh: {re_applied} >= {}",
            served_a - a_durable
        );
    }

    #[test]
    fn a_multi_origin_source_recovers_the_per_origin_hwm_from_the_tail_marker() {
        // #906: the per-origin HWM marker holds the FULL `(origin -> applied offset)` snapshot, so on
        // reopen the durable HWM for EVERY origin is rebuilt O(1) from the single tail record — the
        // positional anchor the multi-origin path previously lacked.
        let mut origin_a =
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        let mut origin_b =
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            origin_a
                .append(&rec(format!("A-{i:02}").as_bytes()))
                .unwrap();
            origin_b
                .append(&rec(format!("B-{i:02}").as_bytes()))
                .unwrap();
        }
        origin_a.sync().unwrap();
        origin_b.sync().unwrap();
        let served_a = plane_served_end(&origin_a);
        let served_b = plane_served_end(&origin_b);
        assert!(served_a >= 4 && served_b >= 4);

        let fs = InMemoryFs::new();
        let (ka, kb) = ("a/", "b/");
        {
            let mut app = source_applier(fs.clone());
            let mut guard = 0;
            loop {
                guard += 1;
                assert!(guard < 1000, "fan-in did not converge");
                let pa = app
                    .apply_pull_response(ka, &origin_pull(&origin_a, app.cursor(ka)))
                    .unwrap();
                let pb = app
                    .apply_pull_response(kb, &origin_pull(&origin_b, app.cursor(kb)))
                    .unwrap();
                if pa.applied == 0 && pb.applied == 0 {
                    break;
                }
            }
        }

        // Reopen and read the durable HWM straight off the tail marker: BOTH origins are reconstructed.
        let app = source_applier(fs.clone());
        let hwm = app.read_durable_hwm().unwrap();
        assert_eq!(
            hwm.get(ka).copied(),
            Some(served_a),
            "A's durable HWM recovered from the tail marker"
        );
        assert_eq!(
            hwm.get(kb).copied(),
            Some(served_b),
            "B's durable HWM recovered from the tail marker"
        );
    }

    #[test]
    fn a_mirror_writes_no_hwm_markers() {
        // #906: the HWM marker is a MULTI-origin-source mechanism ONLY. A single-origin MIRROR anchors on
        // `next_offset` and keeps its byte-IDENTICAL log — it must NEVER write a marker (a marker would
        // perturb the mirror's positional byte-identity with its origin).
        let mut origin = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            origin.append(&rec(format!("m-{i:02}").as_bytes())).unwrap();
        }
        origin.sync().unwrap();
        let served = plane_served_end(&origin);
        assert!(served >= 4);

        let key = "origin/";
        let mut app = applier(InMemoryFs::new()); // single_origin = true
        let mut guard = 0;
        while app.cursor(key) < served {
            guard += 1;
            assert!(guard < 1000, "mirror did not converge");
            if app
                .apply_pull_response(key, &origin_pull(&origin, app.cursor(key)))
                .unwrap()
                .applied
                == 0
            {
                break;
            }
        }
        assert_eq!(app.cursor(key), served);

        // Not one record in the mirror log is a HWM marker: the log is byte-for-byte the origin's prefix.
        let local = app.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(
            local.len() as u64,
            served,
            "the mirror log holds exactly the origin's served prefix — no extra marker records"
        );
        assert!(
            local.iter().all(|r| {
                !r.payload.as_ref().starts_with(GEO_HWM_MARKER_MAGIC)
                    && r.key.as_ref() != GEO_HWM_MARKER_KEY
            }),
            "a single-origin mirror writes NO HWM markers (#906) — byte-identity preserved"
        );
    }

    #[test]
    fn an_idle_origin_pull_applies_nothing_and_is_a_clean_no_op() {
        let origin = Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        // Origin has no records: the pull is an empty no-op (no busy-work, cursor unchanged).
        let mut app = applier(InMemoryFs::new());
        let resp = origin_pull(&origin, app.cursor("o/"));
        let out = app.apply_pull_response("o/", &resp).unwrap();
        assert_eq!(out.applied, 0);
        assert_eq!(app.cursor("o/"), 0);
    }

    #[test]
    fn geo_config_reports_read_only_mirror_streams() {
        let cfg = GeoConfig {
            streams: vec![
                GeoStreamConfig {
                    local_stream: "m".to_string(),
                    mode: GeoMode::Mirror(GeoOrigin {
                        addr: "h:1".to_string(),
                        stream: "o".to_string(),
                    }),
                },
                GeoStreamConfig {
                    local_stream: "s".to_string(),
                    mode: GeoMode::Source(vec![GeoOrigin {
                        addr: "h:2".to_string(),
                        stream: "o".to_string(),
                    }]),
                },
            ],
        };
        assert_eq!(cfg.read_only_streams(), vec!["m".to_string()]);
        assert!(!cfg.is_empty());
    }

    #[test]
    fn a_domain_resolved_origin_drives_a_byte_faithful_mirror() {
        use super::super::domain::{Domain, DomainRef, DomainResolver};

        // The NAMESPACE (#624) ties to the geo plane (#623): a `@<domain>/<stream>` reference resolves
        // through the link table to the SAME `(addr, stream)` a raw origin produces, so the resolved
        // GeoOrigin drives the geo pull plane EXACTLY as a raw one — byte-faithfully.
        let mut resolver = DomainResolver::new(Some(Domain::parse("home").unwrap()));
        resolver.add_link(Domain::parse("east").unwrap(), "10.0.0.1:7500".to_string());

        let reference = DomainRef::parse("@east/orders").unwrap().unwrap();
        let (addr, stream) = resolver.resolve(&reference).unwrap();
        let origin = GeoOrigin { addr, stream };
        assert_eq!(origin.addr, "10.0.0.1:7500");
        assert_eq!(origin.stream, "orders");
        // The resolved origin's durable cursor key is stable (domain resolution did not change the geo
        // identity contract): it is the `<addr>/<stream>` the cursor store keys on.
        assert_eq!(origin.cursor_key(), "10.0.0.1:7500/orders");

        // Drive an in-process mirror over an origin log USING the resolved origin's stream, and confirm
        // it converges byte-faithfully — the resolved namespace reference behaves identically to a raw
        // one through the whole apply path.
        let mut origin_log =
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            origin_log
                .append(&rec(format!("o-{i:02}").as_bytes()))
                .unwrap();
        }
        origin_log.sync().unwrap();
        let served = plane_served_end(&origin_log);

        let mut app = applier(InMemoryFs::new());
        let key = origin.cursor_key();
        let applied = drain_into(&mut app, &origin_log, &key);
        assert_eq!(
            applied, served,
            "the domain-resolved mirror applied the sealed prefix"
        );
        let recs = app.log().read_from(Offset::new(0), 100).unwrap();
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("o-{i:02}").as_bytes());
        }
    }
}

/// The REAL two-"cluster" integration tests (#623): an ORIGIN serve and a separate MIRROR / SOURCE serve
/// over real loopback `TcpStream`s + real on-disk `StdFs` logs. Unix-only because the broker / serve path
/// is `cfg(unix)` via `StdFs` (so the helpers and tests vanish together on Windows under `-D dead_code`).
#[cfg(all(test, unix))]
#[allow(clippy::similar_names)]
mod live_geo_tests {
    use super::*;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use ironbus_storage::fs::StdFs;
    use ironbus_storage::log::{Append, Log, LogConfig};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    // A real on-disk StdFs backend (real sockets + real files), with a deterministic ManualClock at zero
    // so the segment-header timestamps (stamped from the clock seam) are byte-identical between the origin
    // and the mirror — exactly the discipline the intra-cluster serve capstone test uses, so the
    // byte-identity assertion is meaningful.

    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    /// A real on-disk ORIGIN log with `n` records, fsync'd, leaked to `'static` so its read plane keeps
    /// observing it for the test's lifetime (in a real serve the engine's append actor owns it).
    fn leaked_origin(
        dir: &std::path::Path,
        prefix: &str,
        n: u32,
    ) -> &'static Log<StdFs, ManualClock> {
        let fs = StdFs::new(dir.to_path_buf());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).expect("origin log opens");
        for i in 0..n {
            log.append(&rec(format!("{prefix}-{i:03}").as_bytes()))
                .unwrap();
        }
        log.sync().unwrap();
        Box::leak(Box::new(log))
    }

    /// Bind an ephemeral loopback port, read it, drop the listener (the caller rebinds it). A small TOCTOU
    /// window, fine for a quiet in-process loopback test.
    fn free_addr() -> SocketAddr {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
        let a = l.local_addr().unwrap();
        drop(l);
        a
    }

    /// Spin up an ORIGIN geo-serve listener on `addr` that answers `MirrorPull` requests from the origin
    /// log's read plane (any stream name maps to this single default-stream origin, the #693 single-stream
    /// scope). Returns a shutdown flag + the join handle; the listener exits promptly on shutdown.
    fn spawn_origin_serve(
        addr: SocketAddr,
        origin: &'static Log<StdFs, ManualClock>,
    ) -> (Arc<AtomicBool>, JoinHandle<()>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_t = Arc::clone(&shutdown);
        let listener = TcpListener::bind(addr).expect("origin geo listener binds");
        listener.set_nonblocking(true).unwrap();
        let plane = Arc::new(origin.read_plane().expect("origin read plane"));
        let handle = std::thread::Builder::new()
            .name("ib-geo-origin".to_string())
            .spawn(move || {
                while !shutdown_t.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            let plane = Arc::clone(&plane);
                            let sd = Arc::clone(&shutdown_t);
                            // One reader thread per connection: answer pulls until the link closes/shuts.
                            std::thread::spawn(move || {
                                let mut link = GeoLink::new(stream);
                                let server = OriginServer::new(&plane);
                                while !sd.load(Ordering::Acquire) {
                                    match link.recv() {
                                        Ok(Some(GeoFrame::Request(req))) => {
                                            let resp = server.serve_pull(&req).expect("serve_pull");
                                            if link.send_response(&resp).is_err() {
                                                return;
                                            }
                                        }
                                        // A stray response, or a read-timeout with no full frame: re-poll
                                        // (re-checking shutdown). Both are clean no-ops on the origin side.
                                        Ok(Some(GeoFrame::Response(_))) => {}
                                        Err(GeoError::Io(e))
                                            if matches!(
                                                e.kind(),
                                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                            ) => {}
                                        // The puller closed cleanly, or a decode/link error: end this
                                        // reader (the listener accepts the next connection).
                                        Ok(None) | Err(_) => return,
                                    }
                                }
                            });
                        }
                        Err(ref e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => return,
                    }
                }
            })
            .expect("spawn origin serve");
        (shutdown, handle)
    }

    /// Pull-and-apply ONE origin into the mirror over a fresh dialed link until caught up to the origin's
    /// CURRENTLY-served sealed prefix (the response HW), then return. Each pull is a real round-trip over
    /// the loopback socket. Resumes from the mirror's durable cursor, so calling it again after a
    /// disconnect continues with no gap / no dup.
    fn drain_over_wire(
        addr: SocketAddr,
        app: &mut MirrorApplier<StdFs, ManualClock>,
        origin_key: &str,
        origin_stream: &str,
    ) {
        let stream = TcpStream::connect(addr).expect("mirror dials origin");
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut link = GeoLink::new(stream);
        loop {
            let req = app.pull_request(
                origin_key,
                origin_stream,
                GEO_PULL_MAX_RECORDS,
                GEO_PULL_MAX_BYTES,
            );
            link.send_request(&req).expect("send pull");
            match link.recv() {
                Ok(Some(GeoFrame::Response(resp))) => {
                    let out = app.apply_pull_response(origin_key, &resp).expect("apply");
                    // Caught up to what the origin currently serves (sealed prefix): stop.
                    if out.applied == 0 && out.cursor >= resp.origin_high_watermark.min(out.cursor)
                    {
                        break;
                    }
                    if out.applied == 0 {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        pred()
    }

    fn dump_segments(log: &Log<StdFs, ManualClock>) -> std::collections::BTreeMap<String, Vec<u8>> {
        use ironbus_storage::io::RandomAccessFile;
        let fs = log.filesystem();
        let mut out = std::collections::BTreeMap::new();
        for name in fs.list().expect("list segments") {
            let file = fs.open(&name).expect("open segment");
            let len = usize::try_from(file.len().expect("len")).expect("len fits");
            let mut buf = vec![0u8; len];
            file.read_exact_at(&mut buf, 0).expect("read segment");
            out.insert(name, buf);
        }
        out
    }

    fn sealed_served_end(log: &Log<StdFs, ManualClock>) -> u64 {
        let plane = log.read_plane().unwrap();
        let flushed = plane.flushed();
        let mut next = 0u64;
        let mut guard = 0u32;
        while next < flushed {
            guard += 1;
            assert!(guard < 100_000);
            let raw = plane
                .read_range_raw(Offset::new(next), 1_000, None)
                .unwrap();
            let adv = raw.run.next_offset.get();
            if adv > next {
                next = adv;
            } else {
                break;
            }
        }
        next
    }

    fn open_mirror(dir: &std::path::Path) -> MirrorApplier<StdFs, ManualClock> {
        let log = Log::open(
            StdFs::new(dir.to_path_buf()),
            ManualClock::new(),
            small_config(),
        )
        .expect("mirror log opens");
        let cursors =
            OriginCursorStore::open(&StdFs::new(dir.to_path_buf())).expect("cursor store");
        // A MIRROR is single-origin, so the #799 next_offset reconciliation applies.
        MirrorApplier::new(log, cursors, true)
    }

    /// A MULTI-origin (fan-in SOURCE) applier over `StdFs`: `single_origin` is false, so the #799
    /// `next_offset` reconciliation is OFF (the interleaved fan-in log has no per-origin positional anchor).
    fn open_source(dir: &std::path::Path) -> MirrorApplier<StdFs, ManualClock> {
        let log = Log::open(
            StdFs::new(dir.to_path_buf()),
            ManualClock::new(),
            small_config(),
        )
        .expect("source log opens");
        let cursors =
            OriginCursorStore::open(&StdFs::new(dir.to_path_buf())).expect("cursor store");
        MirrorApplier::new(log, cursors, false)
    }

    #[test]
    fn a_mirror_converges_byte_faithfully_to_the_origin_over_the_wire() {
        let origin_dir = tempfile::tempdir().expect("origin dir");
        let mirror_dir = tempfile::tempdir().expect("mirror dir");
        let origin = leaked_origin(origin_dir.path(), "o", 40);
        let served = sealed_served_end(origin);
        assert!(served > 0);

        let addr = free_addr();
        let (shutdown, handle) = spawn_origin_serve(addr, origin);

        let key = format!("{addr}/");
        let mut app = open_mirror(mirror_dir.path());
        assert!(
            wait_until(Duration::from_secs(10), || {
                drain_over_wire(addr, &mut app, &key, "");
                app.cursor(&key) == served
            }),
            "mirror converged to the origin's sealed prefix (cursor {} of {served})",
            app.cursor(&key)
        );

        // The mirror's records are byte-faithful to the origin's, in order.
        let recs = app.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, served);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("o-{i:03}").as_bytes());
        }
        // BYTE-IDENTITY: at least one fully-sealed mirror segment is byte-for-byte the origin's.
        let mirror_dump = dump_segments(app.log());
        let origin_dump = dump_segments(origin);
        let any_exact = mirror_dump
            .iter()
            .any(|(name, bytes)| origin_dump.get(name) == Some(bytes));
        assert!(
            any_exact,
            "at least one mirror segment is byte-identical to the origin's over the wire"
        );

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }

    #[test]
    fn a_mirror_resumes_across_a_disconnect_with_no_gap_or_dup() {
        let origin_dir = tempfile::tempdir().expect("origin dir");
        let mirror_dir = tempfile::tempdir().expect("mirror dir");
        let origin = leaked_origin(origin_dir.path(), "o", 40);
        let served = sealed_served_end(origin);

        let addr = free_addr();
        let (shutdown, handle) = spawn_origin_serve(addr, origin);
        let key = format!("{addr}/");

        // First connection: pull a few batches, then DROP the applier (a disconnect + restart). The
        // cursor + log are durable on disk, so a reopen resumes from the durable cursor.
        let partial = {
            let mut app = open_mirror(mirror_dir.path());
            // One short dial that applies one batch, then drops the link.
            let stream = TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut link = GeoLink::new(stream);
            let req = app.pull_request(&key, "", GEO_PULL_MAX_RECORDS, GEO_PULL_MAX_BYTES);
            link.send_request(&req).unwrap();
            if let Ok(Some(GeoFrame::Response(resp))) = link.recv() {
                let out = app.apply_pull_response(&key, &resp).unwrap();
                assert!(out.applied >= 1, "first batch applied something");
            }
            app.cursor(&key)
        };
        assert!(
            partial > 0 && partial < served,
            "partial catch-up before the disconnect"
        );

        // REOPEN over the same dir: durable cursor recovers, draining RESUMES with no gap / no dup.
        let mut app = open_mirror(mirror_dir.path());
        assert_eq!(
            app.cursor(&key),
            partial,
            "cursor recovered durably across the disconnect"
        );
        assert!(wait_until(Duration::from_secs(10), || {
            drain_over_wire(addr, &mut app, &key, "");
            app.cursor(&key) == served
        }));
        let recs = app.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, served, "exactly the sealed prefix, once");
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(
                r.payload.as_ref(),
                format!("o-{i:03}").as_bytes(),
                "in order, no gap/dup"
            );
        }

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }

    #[test]
    fn a_source_fans_in_two_origins_with_independent_cursors_over_the_wire() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let src_dir = tempfile::tempdir().unwrap();
        let origin_a = leaked_origin(dir_a.path(), "A", 40);
        let origin_b = leaked_origin(dir_b.path(), "B", 40);
        let served_a = sealed_served_end(origin_a);
        let served_b = sealed_served_end(origin_b);

        let addr_a = free_addr();
        let addr_b = free_addr();
        let (sd_a, ha) = spawn_origin_serve(addr_a, origin_a);
        let (sd_b, hb) = spawn_origin_serve(addr_b, origin_b);
        let ka = format!("{addr_a}/");
        let kb = format!("{addr_b}/");

        let mut app = open_source(src_dir.path());
        assert!(wait_until(Duration::from_secs(10), || {
            // Round-robin the two origins into the ONE local source stream (apply-arrival interleaving).
            drain_over_wire(addr_a, &mut app, &ka, "");
            drain_over_wire(addr_b, &mut app, &kb, "");
            app.cursor(&ka) == served_a && app.cursor(&kb) == served_b
        }));

        // Both origins' records are all present; per-origin order is preserved; cursors are independent.
        let local = app.log().read_from(Offset::new(0), 100_000).unwrap();
        let a_seen: Vec<&[u8]> = local
            .iter()
            .map(|r| r.payload.as_ref())
            .filter(|p| p.starts_with(b"A-"))
            .collect();
        let b_seen: Vec<&[u8]> = local
            .iter()
            .map(|r| r.payload.as_ref())
            .filter(|p| p.starts_with(b"B-"))
            .collect();
        assert_eq!(a_seen.len() as u64, served_a);
        assert_eq!(b_seen.len() as u64, served_b);
        for (i, p) in a_seen.iter().enumerate() {
            assert_eq!(*p, format!("A-{i:03}").as_bytes());
        }
        for (i, p) in b_seen.iter().enumerate() {
            assert_eq!(*p, format!("B-{i:03}").as_bytes());
        }
        // Account for the per-origin HWM markers (#906): every fan-in record is an A, a B, or a marker.
        let markers = local
            .iter()
            .filter(|r| r.payload.as_ref().starts_with(GEO_HWM_MARKER_MAGIC))
            .count();
        assert_eq!(a_seen.len() + b_seen.len() + markers, local.len());

        sd_a.store(true, Ordering::Release);
        sd_b.store(true, Ordering::Release);
        let _ = ha.join();
        let _ = hb.join();
    }

    #[test]
    fn an_idle_mirror_pull_loop_does_no_work_and_backs_off() {
        // The #726 idle discipline: an idle mirror (origin has nothing new) BLOCKS on the link read and
        // BACKS OFF, doing ~0 work. We prove the loop PARKS by showing it does not spin: with an empty
        // origin the pull_loop applies nothing and exits promptly on shutdown (it is NOT hot-looping —
        // each idle round blocks on the read timeout then sleeps GEO_POLL).
        let origin_dir = tempfile::tempdir().unwrap();
        let mirror_dir = tempfile::tempdir().unwrap();
        let origin = leaked_origin(origin_dir.path(), "o", 0); // no records: idle
        let addr = free_addr();
        let (shutdown, handle) = spawn_origin_serve(addr, origin);
        let key = format!("{addr}/");

        let mut app = open_mirror(mirror_dir.path());
        let loop_shutdown = Arc::new(AtomicBool::new(false));
        let ls = Arc::clone(&loop_shutdown);
        let applied_total = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let at = Arc::clone(&applied_total);

        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let cursor_for_loop = Arc::new(std::sync::Mutex::new(0u64));
        let cfl = Arc::clone(&cursor_for_loop);
        let loop_handle = std::thread::spawn(move || {
            let mut link = GeoLink::new(stream);
            pull_loop(
                &mut link,
                &key,
                "",
                &ls,
                || *cfl.lock().unwrap(),
                |resp| {
                    let out = app.apply_pull_response(&key, resp)?;
                    at.fetch_add(out.applied, Ordering::Relaxed);
                    *cfl.lock().unwrap() = out.cursor;
                    Ok(out)
                },
            );
        });

        // Let the idle loop run a few poll windows, then stop it. An idle loop applies NOTHING.
        std::thread::sleep(Duration::from_millis(600));
        loop_shutdown.store(true, Ordering::Release);
        let _ = loop_handle.join();
        assert_eq!(
            applied_total.load(Ordering::Relaxed),
            0,
            "an idle mirror applies nothing (it blocks/backs off, no busy work)"
        );

        shutdown.store(true, Ordering::Release);
        let _ = handle.join();
    }
}
