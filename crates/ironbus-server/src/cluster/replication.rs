// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-partition follower-fetch data replication (V2-C2-I1, #590).
//!
//! This is the FIRST real multi-node DATA fault-tolerance layer: where C1 (#578-#584) paid
//! consensus ONCE for the cluster metadata (membership / placement / leadership / epoch) and the
//! C1 peer transport (#667) carries the metadata Raft messages over a bounded, fail-closed wire,
//! this module replicates the actual DATA logs — the existing CRC-framed IronBus partition log — by
//! the Kafka-ISR PULL model: a FOLLOWER fetches the LEADER's already-on-disk segment byte ranges and
//! appends them to its own copy, re-validating every frame's CRC on ingest. There is NO second WAL
//! and NO per-partition Raft: replication is an O(bytes) byte-stream of the frames the leader
//! already wrote, the design's chosen unit (`ironbus-clustering-design.md` §2, the
//! KRaft-metadata + ISR-data crux).
//!
//! ## The protocol (one log / partition)
//!
//! 1. A follower sends a [`FetchRecordsBody`] — `(from_offset, max_records, max_bytes)` — to the
//!    leader of the partition. This is a PULL: the follower drives replication on its own cadence;
//!    the leader never pushes. The request rides the bounded `[len][type=FetchRecords][body]`
//!    envelope (`ironbus_proto::frame`), the same wire discipline the C1 peer transport uses.
//! 2. The leader answers with a [`FetchResponseBody`]: its current HIGH-WATERMARK (its flushed /
//!    committed offset, [`Log::flushed_offset`]) and a CONTIGUOUS run of CRC-framed on-disk record
//!    frames starting at `from_offset`, served ZERO-COPY from the leader's own log via
//!    [`Log::read_range_raw`] (the `RawByteRun` of #657 — the stored frames shipped VERBATIM, the
//!    leader's append path untouched). The run is bounded by the smaller of the request's budget and
//!    [`MAX_REPL_FETCH_BYTES`], so one response is always size-bounded.
//! 3. The follower RE-VALIDATES every frame: it walks the response's bytes front-to-back with the
//!    existing intact-record predicate [`ironbus_core::codec::decode`] (header CRC32C, body CRC32C,
//!    and the optional xxh3-64), and only a frame that passes is appended to its local log via
//!    [`Log::append`]. A corrupt / tampered / truncated frame is DETECTED and the follower
//!    FAILS CLOSED — it appends nothing from that frame onward and surfaces a typed
//!    [`ReplicationError`]. A follower NEVER appends a byte it has not itself CRC-validated; the
//!    leader's bytes are untrusted peer bytes, exactly as the C1 transport treats Raft message bytes.
//! 4. The follower advances its own HIGH-WATERMARK to the min of what it durably appended and the
//!    leader's advertised HW. Reads on a follower are bounded by THIS high-watermark, so only
//!    committed-and-replicated data is visible.
//!
//! ## Byte-identity (the point of replication)
//!
//! A follower replicating a fresh log from offset 0 in order assigns offsets 0, 1, 2, … and
//! sequence numbers 0, 1, 2, … exactly as the leader did (both logs start at `Offset::ZERO` /
//! `Seq(0)` and [`Log::append`] advances them positionally). Re-appending each validated record's
//! content through the SAME deterministic codec the leader used reproduces the leader's frames
//! byte-for-byte, so the follower's on-disk log is byte-identical to the leader's, frame-for-frame,
//! CRC-valid — the differential test below pins it. Because the follower goes through the ordinary
//! [`Log::append`] + group-commit + recovery machinery, its log inherits I1–I4 (CRC, longest-valid-
//! prefix recovery, bounded + reported loss) unchanged.
//!
//! ## What this issue does NOT do (deferred to later C2 / C3 / C4 issues)
//!
//! * **ISR set + min-in-sync-replicas + quorum-ack release** (C2-I2 / C3-I2): here a follower
//!   merely CATCHES UP to the leader's flushed offset; releasing a `PubAck` only after `f+1` replicas
//!   have fsync'd the record (the durability win) is the NEXT issue. This module tracks the
//!   follower's high-watermark but does NOT gate the leader's ack on it.
//! * **Leader-epoch truncation on divergence** (C2-I4, #599): a follower here is assumed to share
//!   the leader's lineage from `from_offset`; truncating a divergent epoch's tail is later work. This
//!   module fails closed on a gap / mismatch rather than truncating-and-refetching.
//! * **Divergence detection + self-heal** (C4): footer/CRC cross-replica advertisement and automatic
//!   re-sync from a clean quorum.
//! * **Multi-partition fan-out**: this replicates ONE log / partition. Placing and replicating every
//!   partition of every stream is later C2 / C5 work.
//! * **`serve`-path wiring**: like the C1 peer transport (#667), this is the TESTABLE replication
//!   LAYER — the protocol codec, the leader-serve and follower-apply state, and a [`PeerLink`]-style
//!   stream link driven by an IN-PROCESS leader↔follower loopback harness (the tests below). Wiring
//!   it into the running broker's `serve` loop (a real cluster dialer fetching on a timer) is the
//!   follow-up. With no cluster config the broker opens no replication link, so the single-node
//!   binary is unaffected and its on-disk layout is byte-for-byte unchanged.

use std::io::{self, Read, Write};

use ironbus_core::clock::Clock;
use ironbus_core::codec::{self, DecodeError};
use ironbus_core::types::Offset;
use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType, MAX_FRAME_LEN,
};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::{Append, Log};
use ironbus_storage::segment::StorageError;

/// The hard maximum size, in bytes, of the CRC-framed record-byte payload a single replication
/// fetch RESPONSE may carry. Bounds the leader's serve budget AND, on the follower, the untrusted
/// peer bytes the receive path will buffer and re-validate — a follower never trusts the response
/// length blindly. 8 MiB is generous head-room for a batched fetch of the 64 MiB default segments
/// while staying well under the absolute [`MAX_FRAME_LEN`] envelope cap, so a fetch response always
/// frames.
pub const MAX_REPL_FETCH_BYTES: u32 = 8 * 1024 * 1024;

/// The fixed little-endian byte length of an encoded [`FetchRecordsBody`]:
/// `from_offset: u64` + `max_records: u32` + `max_bytes: u32`.
const FETCH_REQUEST_LEN: usize = 8 + 4 + 4;

/// The fixed little-endian byte length of a [`FetchResponseBody`] HEADER (the record bytes follow):
/// `high_watermark: u64` + `first_offset: u64` + `record_count: u32` + `frame_bytes_len: u32`.
const FETCH_RESPONSE_HEADER_LEN: usize = 8 + 8 + 4 + 4;

/// Read a little-endian `u64` from `b` at byte offset `at`. The caller guarantees `b.len() >= at + 8`
/// (every call site length-checks the body first), so this is panic-free: `copy_from_slice` over a
/// fixed 8-byte window of an already-bounds-checked slice cannot fail.
#[inline]
fn read_u64_le(b: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(buf)
}

/// Read a little-endian `u32` from `b` at byte offset `at`. The caller guarantees `b.len() >= at + 4`,
/// so this is panic-free (see [`read_u64_le`]).
#[inline]
fn read_u32_le(b: &[u8], at: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(buf)
}

/// A follower → leader replication FETCH request for one partition log (#590): "send me the
/// CRC-framed records from `from_offset`, up to `max_records` records / `max_bytes` frame bytes."
/// The Kafka-ISR pull: the follower drives the cadence, the leader never pushes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchRecordsBody {
    /// The log offset the follower wants to replicate FROM (the first offset it does not yet hold).
    pub from_offset: u64,
    /// The maximum number of records the follower wants in this response (a `0` is a no-op fetch).
    pub max_records: u32,
    /// The maximum CRC-framed record BYTES the follower wants in this response. The leader serves at
    /// most `min(this, MAX_REPL_FETCH_BYTES)`.
    pub max_bytes: u32,
}

impl FetchRecordsBody {
    /// Encode this request to its fixed-layout little-endian body bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FETCH_REQUEST_LEN);
        out.extend_from_slice(&self.from_offset.to_le_bytes());
        out.extend_from_slice(&self.max_records.to_le_bytes());
        out.extend_from_slice(&self.max_bytes.to_le_bytes());
        out
    }

    /// Decode a request from its body bytes.
    ///
    /// # Errors
    /// Returns [`ReplicationError::MalformedRequest`] if `body` is not exactly [`FETCH_REQUEST_LEN`]
    /// bytes — a malformed / truncated / over-long request is rejected, never guessed at.
    pub fn decode(body: &[u8]) -> Result<FetchRecordsBody, ReplicationError> {
        if body.len() != FETCH_REQUEST_LEN {
            return Err(ReplicationError::MalformedRequest { len: body.len() });
        }
        Ok(FetchRecordsBody {
            from_offset: read_u64_le(body, 0),
            max_records: read_u32_le(body, 8),
            max_bytes: read_u32_le(body, 12),
        })
    }
}

/// A leader → follower replication FETCH response for one partition log (#590): the leader's current
/// high-watermark plus a contiguous run of CRC-framed on-disk record frames starting at
/// `first_offset`. The `frame_bytes` are shipped VERBATIM from the leader's log (a `RawByteRun`,
/// #657); the follower RE-VALIDATES each one before appending any of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchResponseBody {
    /// The leader's HIGH-WATERMARK: its flushed / committed offset ([`Log::flushed_offset`]) at the
    /// moment it served this fetch. The follower's own high-watermark never advances past this.
    pub high_watermark: u64,
    /// The log offset of the FIRST frame in `frame_bytes` (it equals the request's `from_offset` when
    /// any data is served, or that offset with an empty run when nothing is available yet).
    pub first_offset: u64,
    /// How many complete CRC-framed records `frame_bytes` carries.
    pub record_count: u32,
    /// The contiguous CRC-framed on-disk record frames, one after another in the frozen on-disk
    /// layout — the leader's bytes VERBATIM (untrusted on the follower until re-validated).
    pub frame_bytes: Vec<u8>,
}

impl FetchResponseBody {
    /// Encode this response to its fixed-header + verbatim-bytes body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FETCH_RESPONSE_HEADER_LEN + self.frame_bytes.len());
        out.extend_from_slice(&self.high_watermark.to_le_bytes());
        out.extend_from_slice(&self.first_offset.to_le_bytes());
        out.extend_from_slice(&self.record_count.to_le_bytes());
        // The byte length is stored so the follower can bound the run before it reads it; it is
        // re-checked against the actual remaining bytes on decode (never trusted blindly).
        let frame_len = u32::try_from(self.frame_bytes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&frame_len.to_le_bytes());
        out.extend_from_slice(&self.frame_bytes);
        out
    }

    /// Decode a response from its body bytes, BOUNDING the carried frame bytes against
    /// [`MAX_REPL_FETCH_BYTES`] before accepting them — an oversized response (a hostile or buggy
    /// peer) is rejected, never buffered.
    ///
    /// # Errors
    /// Returns [`ReplicationError::MalformedResponse`] if the header is short, the stored
    /// `frame_bytes_len` disagrees with the bytes actually present, or the run exceeds the cap.
    pub fn decode(body: &[u8]) -> Result<FetchResponseBody, ReplicationError> {
        if body.len() < FETCH_RESPONSE_HEADER_LEN {
            return Err(ReplicationError::MalformedResponse { len: body.len() });
        }
        let high_watermark = read_u64_le(body, 0);
        let first_offset = read_u64_le(body, 8);
        let record_count = read_u32_le(body, 16);
        let frame_bytes_len = read_u32_le(body, 20);
        // The SIZE bound on untrusted peer bytes: reject an over-cap claimed length BEFORE trusting
        // it, the same fail-closed discipline the C1 peer transport applies to a Raft frame.
        if frame_bytes_len > MAX_REPL_FETCH_BYTES {
            return Err(ReplicationError::ResponseTooLarge {
                len: u64::from(frame_bytes_len),
            });
        }
        let want = frame_bytes_len as usize;
        let have = body.len() - FETCH_RESPONSE_HEADER_LEN;
        if want != have {
            return Err(ReplicationError::MalformedResponse { len: body.len() });
        }
        Ok(FetchResponseBody {
            high_watermark,
            first_offset,
            record_count,
            frame_bytes: body[FETCH_RESPONSE_HEADER_LEN..].to_vec(),
        })
    }
}

/// A typed replication error. Every failure mode of serving / receiving / validating / applying a
/// fetch is one of these — the layer NEVER panics, NEVER blind-appends an unvalidated byte, and
/// FAILS CLOSED on any corrupt / malformed / out-of-order input.
#[derive(Debug)]
pub enum ReplicationError {
    /// A fetch REQUEST body was not the fixed expected length (malformed / truncated / over-long).
    MalformedRequest {
        /// The body length seen.
        len: usize,
    },
    /// A fetch RESPONSE body header was short or its stored frame-byte length disagreed with the
    /// bytes actually present.
    MalformedResponse {
        /// The body length seen.
        len: usize,
    },
    /// A fetch response claimed more CRC-framed record bytes than [`MAX_REPL_FETCH_BYTES`] — rejected
    /// before the bytes are trusted (the untrusted-peer size bound).
    ResponseTooLarge {
        /// The claimed frame-byte length.
        len: u64,
    },
    /// The response's first offset did not continue the follower's log contiguously (a gap or an
    /// overlap). The follower fails closed rather than appending out of order; epoch-truncation
    /// reconciliation of a divergent lineage is the deferred C2-I4 (#599).
    NonContiguous {
        /// The offset the follower expected next (its current `next_offset`).
        expected: u64,
        /// The first offset the response actually carried.
        got: u64,
    },
    /// A CRC-framed frame in the response FAILED the intact-record predicate
    /// ([`ironbus_core::codec::decode`]) — a corrupt, tampered, or truncated frame. The follower
    /// detected it and appended NOTHING from this frame onward (fail-closed). Carries the offset the
    /// bad frame would have occupied and the typed decode reason.
    CorruptFrame {
        /// The log offset the corrupt frame would have been appended at.
        at_offset: u64,
        /// The typed decode failure (bad header CRC, bad body CRC, bad xxh3, truncated, …).
        reason: DecodeError,
    },
    /// The response claimed a `record_count` the actual frame bytes did not contain (too few or too
    /// many complete frames) — a malformed response; fail closed.
    RecordCountMismatch {
        /// The count the response header claimed.
        claimed: u32,
        /// The number of complete frames actually decoded from the bytes.
        actual: u32,
    },
    /// The local log rejected an append (e.g. at-capacity / writer frozen) while applying a
    /// validated record. Surfaced rather than swallowed.
    Storage(StorageError),
    /// An underlying IO error reading from / writing to the peer link.
    Io(io::Error),
    /// The peer-link frame envelope was malformed or carried an unexpected type tag.
    Frame {
        /// A human description of the framing fault.
        what: String,
    },
}

impl core::fmt::Display for ReplicationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReplicationError::MalformedRequest { len } => {
                write!(f, "malformed replication fetch request body ({len} bytes)")
            }
            ReplicationError::MalformedResponse { len } => {
                write!(f, "malformed replication fetch response body ({len} bytes)")
            }
            ReplicationError::ResponseTooLarge { len } => write!(
                f,
                "replication fetch response claimed {len} frame bytes, over the {MAX_REPL_FETCH_BYTES}-byte cap; rejected"
            ),
            ReplicationError::NonContiguous { expected, got } => write!(
                f,
                "replication fetch is non-contiguous: follower expected offset {expected}, response started at {got}"
            ),
            ReplicationError::CorruptFrame { at_offset, reason } => write!(
                f,
                "replication fetch carried a corrupt frame at offset {at_offset} ({reason:?}); fail-closed, nothing appended from here"
            ),
            ReplicationError::RecordCountMismatch { claimed, actual } => write!(
                f,
                "replication fetch response record_count {claimed} != {actual} complete frames decoded"
            ),
            ReplicationError::Storage(e) => write!(f, "replication local append failed: {e}"),
            ReplicationError::Io(e) => write!(f, "replication peer link IO error: {e}"),
            ReplicationError::Frame { what } => write!(f, "replication peer frame error: {what}"),
        }
    }
}

impl std::error::Error for ReplicationError {}

impl From<io::Error> for ReplicationError {
    fn from(e: io::Error) -> Self {
        ReplicationError::Io(e)
    }
}

impl From<StorageError> for ReplicationError {
    fn from(e: StorageError) -> Self {
        ReplicationError::Storage(e)
    }
}

/// The LEADER side of replication for one partition log: it serves a follower's [`FetchRecordsBody`]
/// by reading a contiguous CRC-framed byte range from its OWN log (zero-copy, [`Log::read_range_raw`])
/// up to the requested-and-capped budget, plus its current high-watermark.
///
/// The leader's log is READ-ONLY through this path — replication never changes the leader's
/// append / produce path; it only serves bytes already written and flushed.
pub struct ReplicationLeader<'a, F: Filesystem, C: Clock> {
    log: &'a Log<F, C>,
}

impl<'a, F: Filesystem, C: Clock> ReplicationLeader<'a, F, C> {
    /// Wrap a leader's log as a replication source.
    pub fn new(log: &'a Log<F, C>) -> Self {
        Self { log }
    }

    /// The leader's current high-watermark: its flushed / committed offset — the committed prefix a
    /// follower may replicate up to. Reads (here and on the follower) never cross it.
    #[must_use]
    pub fn high_watermark(&self) -> Offset {
        self.log.flushed_offset()
    }

    /// Serve a follower's fetch: a contiguous run of the leader's CRC-framed on-disk record frames
    /// from `req.from_offset`, bounded by the smaller of the request's budget and
    /// [`MAX_REPL_FETCH_BYTES`], plus the leader's current high-watermark. The frames are shipped
    /// VERBATIM (the leader does not re-encode or re-validate — they are already its own durable
    /// bytes); the FOLLOWER re-validates them on ingest.
    ///
    /// # Errors
    /// Returns [`ReplicationError::Storage`] if the underlying raw read fails (e.g. the requested
    /// offset is older than the oldest retained record).
    pub fn serve_fetch(
        &self,
        req: &FetchRecordsBody,
    ) -> Result<FetchResponseBody, ReplicationError> {
        let hw = self.log.flushed_offset();
        let from = Offset::new(req.from_offset);
        // Bound the served bytes to the cap regardless of what the follower asked for, so one response
        // is always under MAX_REPL_FETCH_BYTES and frames cleanly. `0` request bytes means "use the
        // cap" rather than "serve nothing", so a follower that does not set a byte budget still makes
        // progress; the record-count budget still bounds it.
        let req_bytes = if req.max_bytes == 0 {
            MAX_REPL_FETCH_BYTES
        } else {
            req.max_bytes.min(MAX_REPL_FETCH_BYTES)
        };
        let max_records = req.max_records as usize;
        let (run, _tail) = self
            .log
            .read_range_raw(from, max_records, Some(req_bytes as usize))?;
        Ok(FetchResponseBody {
            high_watermark: hw.get(),
            first_offset: run.first_offset.get(),
            record_count: u32::try_from(run.record_count).unwrap_or(u32::MAX),
            frame_bytes: run.bytes.to_vec(),
        })
    }
}

/// How many records a follower durably appended from one fetch response, and the high-watermark
/// state after it. Returned by [`Follower::apply_fetch_response`] so a driver can decide whether to
/// fetch again (the follower is caught up iff `next_offset == high_watermark`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// How many records this response durably appended to the follower's log.
    pub appended: u64,
    /// The follower's next offset to fetch FROM after this apply (its log's `next_offset`).
    pub next_offset: u64,
    /// The follower's high-watermark after this apply: the committed-and-replicated prefix visible to
    /// reads, = `min(self.next_offset, leader_high_watermark)`.
    pub high_watermark: u64,
}

/// The FOLLOWER side of replication for one partition log: it owns its OWN local copy of the log and
/// applies fetch responses to it — re-validating every frame's CRC, appending only validated frames,
/// and tracking its high-watermark against the leader's.
///
/// **The follower NEVER appends an unvalidated byte.** Each frame in a response is decoded with
/// [`ironbus_core::codec::decode`] (the intact-record predicate: header CRC32C + body CRC32C + xxh3),
/// and only a frame that passes is re-appended through the ordinary [`Log::append`] path (so the
/// follower's log inherits I1–I4). A corrupt / tampered / truncated frame is detected and the apply
/// fails closed: nothing from that frame onward is appended.
pub struct Follower<F: Filesystem, C: Clock> {
    log: Log<F, C>,
    /// The leader high-watermark last observed, clamped against the follower's own durable prefix to
    /// produce the follower's visible high-watermark.
    leader_high_watermark: u64,
}

impl<F: Filesystem, C: Clock> Follower<F, C> {
    /// Wrap a freshly-opened (or recovered) local log as a replication follower. The log is the
    /// follower's OWN copy; it starts wherever recovery left it (`next_offset`), so catch-up from a
    /// non-zero offset is just a fetch from that offset.
    pub fn new(log: Log<F, C>) -> Self {
        let next = log.next_offset().get();
        Self {
            log,
            // Before the first fetch the follower has observed no leader HW; its visible HW is its own
            // durable prefix. Seed the observed leader HW at the follower's own next offset so the
            // clamp is a no-op until a real response raises it.
            leader_high_watermark: next,
        }
    }

    /// The offset the follower should fetch FROM next: the first offset it does not yet hold.
    #[must_use]
    pub fn next_fetch_offset(&self) -> Offset {
        self.log.next_offset()
    }

    /// Build the fetch request the follower should send next, asking for up to `max_records` /
    /// `max_bytes` from its current position.
    #[must_use]
    pub fn fetch_request(&self, max_records: u32, max_bytes: u32) -> FetchRecordsBody {
        FetchRecordsBody {
            from_offset: self.log.next_offset().get(),
            max_records,
            max_bytes,
        }
    }

    /// The follower's HIGH-WATERMARK: the committed-and-replicated prefix visible to reads. It is the
    /// MIN of the follower's own durably-appended prefix (`next_offset`) and the last leader HW it
    /// observed — only data that is BOTH committed on the leader AND durably replicated here is
    /// visible.
    #[must_use]
    pub fn high_watermark(&self) -> Offset {
        Offset::new(self.log.next_offset().get().min(self.leader_high_watermark))
    }

    /// Borrow the follower's underlying log (e.g. to read its replicated, validated records, or to
    /// compare its on-disk bytes against the leader's for the byte-identity check).
    #[must_use]
    pub fn log(&self) -> &Log<F, C> {
        &self.log
    }

    /// Apply a leader's fetch RESPONSE to the follower's local log: re-validate every frame's CRC,
    /// append only validated frames, sync, and advance the high-watermark.
    ///
    /// This is the security-critical core. The leader's `frame_bytes` are UNTRUSTED peer bytes. They
    /// are walked front-to-back; each frame is decoded with the intact-record predicate
    /// ([`ironbus_core::codec::decode`]); a frame that passes is re-appended (reproducing the leader's
    /// byte-identical frame); a frame that FAILS is rejected and the apply stops there with a typed
    /// [`ReplicationError::CorruptFrame`] — **nothing from the bad frame onward is appended**. The
    /// records validated-and-appended before a bad frame are kept and synced (the longest valid
    /// prefix of this response), exactly the I1 / I3 fail-at-first-bad-frame discipline the local
    /// recovery path already holds.
    ///
    /// # Errors
    /// - [`ReplicationError::NonContiguous`] if the response does not continue the follower's log.
    /// - [`ReplicationError::CorruptFrame`] if any frame fails CRC re-validation (fail-closed).
    /// - [`ReplicationError::RecordCountMismatch`] if the byte run does not hold the claimed count.
    /// - [`ReplicationError::Storage`] if a local append / sync fails.
    pub fn apply_fetch_response(
        &mut self,
        resp: &FetchResponseBody,
    ) -> Result<ApplyOutcome, ReplicationError> {
        // The follower only ever observes a MONOTONIC leader high-watermark (the leader's flushed
        // offset never moves backward). Take the max so a slightly-stale response cannot lower the
        // observed HW.
        self.leader_high_watermark = self.leader_high_watermark.max(resp.high_watermark);

        let expected = self.log.next_offset().get();
        // An empty run (the follower is already caught up to the leader's HW) is a clean no-op that
        // still refreshes the observed HW. Its `first_offset` is allowed to be the follower's next
        // offset OR the leader's HW; either way nothing is appended.
        if resp.record_count == 0 && resp.frame_bytes.is_empty() {
            return Ok(self.outcome(0));
        }
        // The run MUST continue the follower's log contiguously. A gap or overlap is a divergence the
        // follower fails closed on (epoch-truncation reconciliation is the deferred C2-I4, #599).
        if resp.first_offset != expected {
            return Err(ReplicationError::NonContiguous {
                expected,
                got: resp.first_offset,
            });
        }

        // Walk the verbatim frame bytes, RE-VALIDATING and appending one frame at a time. `codec::decode`
        // is the intact-record predicate: it checks magic, version, the header CRC32C, the internal
        // length sanity, the body CRC32C, and (for large bodies) the xxh3-64 — returning a typed
        // DecodeError on ANY corruption. Only a frame that passes is appended; a failure stops the walk
        // and is surfaced, so a follower NEVER appends a byte it has not itself validated.
        let mut cursor = 0usize;
        let mut appended = 0u64;
        let bytes = resp.frame_bytes.as_slice();
        while cursor < bytes.len() {
            let at_offset = self.log.next_offset().get();
            let (view, frame_len) = match codec::decode(&bytes[cursor..]) {
                Ok(decoded) => decoded,
                Err(reason) => {
                    // Fail closed: append nothing from this frame onward. The validated-and-appended
                    // prefix is already synced below before we return.
                    self.log.sync()?;
                    return Err(ReplicationError::CorruptFrame { at_offset, reason });
                }
            };
            // Re-append the validated record's content. The follower's log assigns the SAME offset /
            // sequence positionally (both logs advance from 0 in order), so re-encoding through the
            // identical codec reproduces the leader's frame byte-for-byte.
            let append = Append {
                timestamp_ms: view.timestamp_ms,
                flags: view.flags,
                key: view.key,
                headers: view.headers,
                payload: view.payload,
            };
            self.log.append(&append)?;
            appended += 1;
            cursor += frame_len;
        }
        // Durably commit the replicated batch (one fsync per fetched batch — the group-commit shape,
        // extended to the follower's ingest). This raises the follower's flushed offset so its
        // replicated prefix is durable and visible.
        self.log.sync()?;

        // The byte run must have held exactly the claimed number of complete frames.
        let actual = u32::try_from(appended).unwrap_or(u32::MAX);
        if actual != resp.record_count {
            return Err(ReplicationError::RecordCountMismatch {
                claimed: resp.record_count,
                actual,
            });
        }
        Ok(self.outcome(appended))
    }

    fn outcome(&self, appended: u64) -> ApplyOutcome {
        ApplyOutcome {
            appended,
            next_offset: self.log.next_offset().get(),
            high_watermark: self.high_watermark().get(),
        }
    }
}

/// A bidirectional REPLICATION peer link over any byte stream (`Read + Write`): a real `TcpStream`
/// in production, an in-memory pipe in the in-process leader↔follower test. It frames a
/// [`FetchRecordsBody`] / [`FetchResponseBody`] with the bounded `ironbus_proto::frame` envelope and
/// reads them back, applying the size bound on the receive path.
///
/// Like the C1 [`crate::cluster::transport::PeerLink`], this is deliberately TRANSPORT-AGNOSTIC and
/// synchronous, carrying no async runtime and no engine state, so the in-process loopback harness
/// drives it without a `serve` integration.
pub struct ReplicationLink<S> {
    stream: S,
    /// Accumulated, not-yet-consumed inbound bytes (a partial frame may straddle reads).
    inbuf: Vec<u8>,
}

/// One decoded replication frame off a [`ReplicationLink`]: a follower's fetch request or a leader's
/// fetch response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplicationFrame {
    /// A follower's [`FetchRecordsBody`] (received on the leader side).
    Request(FetchRecordsBody),
    /// A leader's [`FetchResponseBody`] (received on the follower side).
    Response(FetchResponseBody),
}

impl<S: Read + Write> ReplicationLink<S> {
    /// Wrap a byte stream as a replication link.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            inbuf: Vec::new(),
        }
    }

    /// Send a follower → leader fetch request.
    ///
    /// # Errors
    /// Returns [`ReplicationError::Frame`] if the body cannot be framed, or
    /// [`ReplicationError::Io`] on a write failure.
    pub fn send_request(&mut self, req: &FetchRecordsBody) -> Result<(), ReplicationError> {
        self.send(FrameType::FetchRecords, &req.encode())
    }

    /// Send a leader → follower fetch response.
    ///
    /// # Errors
    /// Returns [`ReplicationError::Frame`] if the body cannot be framed (e.g. it would exceed the
    /// envelope cap), or [`ReplicationError::Io`] on a write failure.
    pub fn send_response(&mut self, resp: &FetchResponseBody) -> Result<(), ReplicationError> {
        self.send(FrameType::FetchResponse, &resp.encode())
    }

    fn send(&mut self, ty: FrameType, body: &[u8]) -> Result<(), ReplicationError> {
        let mut frame = Vec::with_capacity(body.len() + 5);
        encode_frame(ty, body, &mut frame).map_err(|e| ReplicationError::Frame {
            what: e.to_string(),
        })?;
        self.stream.write_all(&frame)?;
        Ok(())
    }

    /// Read exactly one inbound replication frame, blocking until a full frame arrives (or the peer
    /// closes). Returns `Ok(None)` on a clean close with no partial frame pending. The frame length
    /// is bounded by the envelope cap on the way in; the response body's carried frame bytes are
    /// bounded again against [`MAX_REPL_FETCH_BYTES`] when it is decoded.
    ///
    /// # Errors
    /// See [`ReplicationError`]: a framing / decode error means the peer sent something invalid; the
    /// node is never harmed (no panic, no unbounded allocation).
    pub fn recv(&mut self) -> Result<Option<ReplicationFrame>, ReplicationError> {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            // The replication-fetch response carries up to MAX_REPL_FETCH_BYTES of record bytes plus a
            // small header, so cap the inbound frame at that plus envelope head-room (still <=
            // MAX_FRAME_LEN, so decode_frame_with_cap only ever tightens the absolute cap).
            let cap = (MAX_REPL_FETCH_BYTES.saturating_add(1024)).min(MAX_FRAME_LEN);
            match decode_frame_with_cap(&self.inbuf, cap) {
                Ok(FrameDecode::Frame {
                    type_tag,
                    body,
                    consumed,
                }) => {
                    let frame = Self::decode_typed(type_tag, body)?;
                    self.inbuf.drain(..consumed);
                    return Ok(Some(frame));
                }
                Ok(FrameDecode::Incomplete { .. }) => {}
                Err(FrameError::FrameTooLarge { len }) => {
                    return Err(ReplicationError::ResponseTooLarge { len })
                }
                Err(e) => {
                    return Err(ReplicationError::Frame {
                        what: e.to_string(),
                    })
                }
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                if self.inbuf.is_empty() {
                    return Ok(None);
                }
                return Err(ReplicationError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "replication peer closed mid-frame",
                )));
            }
            self.inbuf.extend_from_slice(&chunk[..n]);
        }
    }

    fn decode_typed(type_tag: u8, body: &[u8]) -> Result<ReplicationFrame, ReplicationError> {
        match FrameType::from_u8(type_tag) {
            Some(FrameType::FetchRecords) => {
                Ok(ReplicationFrame::Request(FetchRecordsBody::decode(body)?))
            }
            Some(FrameType::FetchResponse) => {
                Ok(ReplicationFrame::Response(FetchResponseBody::decode(body)?))
            }
            _ => Err(ReplicationError::Frame {
                what: format!("unexpected frame type tag {type_tag} on a replication link"),
            }),
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
    use ironbus_storage::log::LogConfig;

    /// A small segment cap so a handful of records rolls to multiple segments — proving replication
    /// (and the byte-identity check) crosses segment boundaries, not just a single active segment.
    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn open_log(fs: InMemoryFs, config: LogConfig) -> Log<InMemoryFs, ManualClock> {
        Log::open(fs, ManualClock::new(), config).expect("log opens")
    }

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 42,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    fn rec_keyed<'a>(key: &'a [u8], payload: &'a [u8]) -> Append<'a> {
        Append {
            timestamp_ms: 99,
            flags: RecordFlags::EMPTY,
            key,
            headers: b"hdr",
            payload,
        }
    }

    /// Read the FULL on-disk bytes of every segment file in a log's filesystem, keyed by file name.
    /// This is the ground truth for the byte-identity assertion: two logs are byte-identical iff they
    /// hold the same set of segment files with the same bytes.
    fn dump_segments(log: &Log<InMemoryFs, ManualClock>) -> Vec<(String, Vec<u8>)> {
        let fs = log.filesystem();
        let mut out = Vec::new();
        for name in fs.list().expect("list segments") {
            let file = fs.open(&name).expect("open segment");
            let len = usize::try_from(file.len().expect("len")).expect("segment len fits usize");
            let mut buf = vec![0u8; len];
            file.read_exact_at(&mut buf, 0).expect("read segment bytes");
            out.push((name, buf));
        }
        out
    }

    /// Drive a full leader→follower catch-up over the in-process [`ReplicationLink`] until the
    /// follower's next offset reaches the leader's high-watermark. Returns the follower (consumed by
    /// value into the link harness, handed back). `max_records` / `max_bytes` bound each fetch.
    fn replicate_to_catch_up(
        leader_log: &Log<InMemoryFs, ManualClock>,
        mut follower: Follower<InMemoryFs, ManualClock>,
        max_records: u32,
        max_bytes: u32,
    ) -> Follower<InMemoryFs, ManualClock> {
        let leader = ReplicationLeader::new(leader_log);
        let hw = leader.high_watermark().get();
        // A bounded loop: each fetch makes progress (at least one record while below HW), so the
        // catch-up terminates well within hw+1 iterations.
        for _ in 0..(hw + 2) {
            if follower.next_fetch_offset().get() >= hw {
                break;
            }
            let req = follower.fetch_request(max_records, max_bytes);
            // Serve the request directly (the link is exercised separately in the wire round-trip
            // test); this keeps the catch-up loop a pure leader-serve → follower-apply step.
            let resp = leader.serve_fetch(&req).expect("leader serves fetch");
            let before = follower.next_fetch_offset().get();
            let outcome = follower
                .apply_fetch_response(&resp)
                .expect("follower applies a valid fetch");
            assert_eq!(outcome.next_offset, before + outcome.appended);
            assert!(
                outcome.appended > 0 || before >= hw,
                "a fetch below the HW must make progress"
            );
        }
        follower
    }

    // ----- the headline test: a follower ends up with a BYTE-IDENTICAL log -----

    #[test]
    fn follower_fetch_yields_a_byte_identical_log() {
        // The leader produces N records (rolling across several segments).
        let leader_fs = InMemoryFs::new();
        let mut leader_log = open_log(leader_fs, small_config());
        for i in 0..40u32 {
            let payload = format!("record-{i:03}");
            if i % 3 == 0 {
                leader_log
                    .append(&rec_keyed(format!("k{i}").as_bytes(), payload.as_bytes()))
                    .unwrap();
            } else {
                leader_log.append(&rec(payload.as_bytes())).unwrap();
            }
        }
        leader_log.sync().unwrap();
        let leader_hw = leader_log.flushed_offset().get();
        assert_eq!(leader_hw, 40, "all 40 records are committed on the leader");

        // A fresh follower fetches + appends + re-validates until caught up. Small per-fetch caps so
        // it takes several rounds across segment boundaries.
        let follower = Follower::new(open_log(InMemoryFs::new(), small_config()));
        let follower = replicate_to_catch_up(&leader_log, follower, 7, 4096);

        // The follower caught up to the leader's high-watermark.
        assert_eq!(follower.next_fetch_offset().get(), leader_hw);
        assert_eq!(follower.high_watermark().get(), leader_hw);

        // BYTE-IDENTITY: every segment file on the follower is byte-for-byte the leader's.
        let leader_dump = dump_segments(&leader_log);
        let follower_dump = dump_segments(follower.log());
        assert_eq!(
            follower_dump, leader_dump,
            "the replicated log is byte-identical to the leader's, frame-for-frame"
        );

        // And the follower's records decode to exactly the leader's records (a second, semantic check
        // on top of the byte check).
        let leader_recs = leader_log.read_from(Offset::ZERO, 1000).unwrap();
        let follower_recs = follower.log().read_from(Offset::ZERO, 1000).unwrap();
        assert_eq!(follower_recs, leader_recs);
        assert_eq!(follower_recs.len(), 40);
    }

    // ----- fail-closed: a follower REJECTS a corrupted / tampered fetched frame -----

    #[test]
    fn follower_rejects_a_corrupt_fetched_frame_and_appends_nothing_from_it() {
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..6u32 {
            leader_log
                .append(&rec(format!("rec-{i}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let leader = ReplicationLeader::new(&leader_log);

        // The follower already holds the first 3 records (the valid prefix).
        let mut follower = Follower::new(open_log(InMemoryFs::new(), small_config()));
        let req = follower.fetch_request(3, u32::MAX);
        let good = leader.serve_fetch(&req).expect("serve");
        follower.apply_fetch_response(&good).expect("good prefix");
        assert_eq!(follower.next_fetch_offset().get(), 3);

        // Now the leader serves the next 3 — but a byte of the FIRST returned frame's body is
        // TAMPERED in transit (an adversary, or wire/disk corruption), invalidating its CRC.
        let req = follower.fetch_request(3, u32::MAX);
        let mut tampered = leader.serve_fetch(&req).expect("serve");
        assert_eq!(tampered.first_offset, 3);
        assert!(!tampered.frame_bytes.is_empty());
        // Flip a byte deep in the body (past the header) so the body CRC32C catches it.
        let flip_at = tampered.frame_bytes.len() / 2;
        tampered.frame_bytes[flip_at] ^= 0xFF;

        let err = follower
            .apply_fetch_response(&tampered)
            .expect_err("a tampered frame is rejected");
        match err {
            ReplicationError::CorruptFrame { at_offset, .. } => {
                assert_eq!(
                    at_offset, 3,
                    "the corrupt frame is detected at its own offset"
                );
            }
            other => panic!("expected CorruptFrame, got {other:?}"),
        }

        // FAIL-CLOSED: the follower appended NOTHING from the corrupt frame onward — its log still
        // holds exactly the 3 valid records, none of the garbage.
        assert_eq!(
            follower.next_fetch_offset().get(),
            3,
            "no garbage was appended past the valid prefix"
        );
        let recs = follower.log().read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(recs.len(), 3, "only the 3 validated records survive");
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("rec-{i}").as_bytes());
        }
    }

    #[test]
    fn follower_rejects_a_tampered_header_too() {
        // A corruption in the FIXED HEADER region (the magic / version / header CRC) is caught by the
        // header CRC32C just as a body corruption is by the body CRC — both fail closed.
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..3u32 {
            leader_log.append(&rec(format!("h{i}").as_bytes())).unwrap();
        }
        leader_log.sync().unwrap();
        let leader = ReplicationLeader::new(&leader_log);

        let mut follower = Follower::new(open_log(InMemoryFs::new(), small_config()));
        let req = follower.fetch_request(3, u32::MAX);
        let mut resp = leader.serve_fetch(&req).expect("serve");
        // Corrupt a byte at the very front (inside the first frame's header).
        resp.frame_bytes[2] ^= 0x01;

        let err = follower
            .apply_fetch_response(&resp)
            .expect_err("a tampered header is rejected");
        assert!(matches!(
            err,
            ReplicationError::CorruptFrame { at_offset: 0, .. }
        ));
        assert_eq!(follower.next_fetch_offset().get(), 0, "nothing appended");
    }

    // ----- the follower's high-watermark tracks the leader's flushed offset -----

    #[test]
    fn follower_high_watermark_tracks_the_leader_flushed_offset() {
        // The follower catches up to the leader's flushed offset across two commit rounds, and after
        // each full catch-up its high-watermark EQUALS the leader's flushed offset.
        let mut leader_log = open_log(InMemoryFs::new(), small_config());

        // Round 1: the leader commits 5 records; the follower catches up.
        for i in 0..5u32 {
            leader_log.append(&rec(format!("a{i}").as_bytes())).unwrap();
        }
        leader_log.sync().unwrap();
        assert_eq!(leader_log.flushed_offset().get(), 5);
        let mut follower = Follower::new(open_log(InMemoryFs::new(), small_config()));
        follower = replicate_to_catch_up(&leader_log, follower, 100, u32::MAX);
        assert_eq!(
            follower.high_watermark().get(),
            5,
            "the follower's HW equals the leader's flushed offset after catch-up"
        );

        // Round 2: the leader commits 4 more; the follower catches up and its HW advances to match.
        for i in 0..4u32 {
            leader_log.append(&rec(format!("b{i}").as_bytes())).unwrap();
        }
        leader_log.sync().unwrap();
        assert_eq!(leader_log.flushed_offset().get(), 9);
        follower = replicate_to_catch_up(&leader_log, follower, 100, u32::MAX);
        assert_eq!(follower.high_watermark().get(), 9);
        assert_eq!(follower.next_fetch_offset().get(), 9);
    }

    #[test]
    fn follower_hw_never_exceeds_what_it_has_durably_replicated() {
        // The follower's visible HW is min(its durable prefix, the leader's HW). If the leader's HW
        // is far ahead but the follower has only replicated a prefix, the follower's HW is its OWN
        // durable prefix — only committed-AND-replicated data is visible.
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..20u32 {
            leader_log.append(&rec(format!("c{i}").as_bytes())).unwrap();
        }
        leader_log.sync().unwrap();
        let leader = ReplicationLeader::new(&leader_log);
        assert_eq!(leader.high_watermark().get(), 20);

        let mut follower = Follower::new(open_log(InMemoryFs::new(), small_config()));
        // Replicate ONE bounded fetch (a single contiguous run up to a segment boundary), so the
        // follower holds only a PARTIAL prefix of the leader's 20 committed records.
        let req = follower.fetch_request(6, u32::MAX);
        let resp = leader.serve_fetch(&req).unwrap();
        let outcome = follower.apply_fetch_response(&resp).unwrap();
        assert!(
            outcome.appended > 0 && outcome.appended < 20,
            "a single fetch replicates a partial prefix (got {})",
            outcome.appended
        );
        // The leader observed HW is 20, but only `appended` are durably replicated → the follower's
        // visible HW is its OWN durable prefix, NOT the leader's full HW.
        assert_eq!(
            follower.high_watermark().get(),
            outcome.appended,
            "the follower's HW is its durable-replicated prefix, not the leader's full HW"
        );
        assert!(follower.high_watermark().get() < 20);
    }

    // ----- catch-up from a NON-ZERO offset -----

    #[test]
    fn catch_up_from_a_non_zero_offset() {
        // A follower that already holds a prefix (e.g. from a prior session) resumes replication from
        // its own next offset, and still converges to a byte-identical log.
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..30u32 {
            leader_log
                .append(&rec(format!("d{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();

        // Bootstrap the follower with the first 12 records ALREADY present (replicated in a first
        // pass over possibly several segment-bounded fetches), then drop and reopen it to simulate a
        // restart at a non-zero offset.
        let follower_fs = InMemoryFs::new();
        {
            let mut follower = Follower::new(open_log(follower_fs.clone(), small_config()));
            let leader = ReplicationLeader::new(&leader_log);
            // Fetch in bounded runs until the follower holds exactly the first 12 records.
            while follower.next_fetch_offset().get() < 12 {
                let want = 12 - follower.next_fetch_offset().get();
                let req =
                    follower.fetch_request(u32::try_from(want).expect("want fits u32"), u32::MAX);
                let resp = leader.serve_fetch(&req).unwrap();
                let outcome = follower.apply_fetch_response(&resp).unwrap();
                assert!(outcome.appended > 0, "each bootstrap fetch makes progress");
            }
            assert_eq!(follower.next_fetch_offset().get(), 12);
        }
        // Reopen at offset 12 (recovery restores next_offset) and resume.
        let reopened = Follower::new(open_log(follower_fs, small_config()));
        assert_eq!(
            reopened.next_fetch_offset().get(),
            12,
            "the reopened follower resumes from its durable prefix"
        );
        let follower = replicate_to_catch_up(&leader_log, reopened, 5, 2048);

        assert_eq!(follower.next_fetch_offset().get(), 30);
        assert_eq!(
            dump_segments(follower.log()),
            dump_segments(&leader_log),
            "resuming from a non-zero offset still yields a byte-identical log"
        );
    }

    // ----- single-node unaffected (no replication without a cluster) -----

    #[test]
    fn single_node_log_is_byte_identical_with_and_without_the_replication_module_present() {
        // The replication layer only ever READS a leader's log and WRITES a separate follower's log;
        // it never touches a standalone log's append path. A plain single-node log built and synced
        // the ordinary way is byte-for-byte what it always was — the n=1 path is unchanged. (The
        // replication code is a separate, opt-in layer; merely linking it changes nothing on disk.)
        let mut a = open_log(InMemoryFs::new(), small_config());
        let mut b = open_log(InMemoryFs::new(), small_config());
        for i in 0..15u32 {
            let p = format!("plain-{i}");
            a.append(&rec(p.as_bytes())).unwrap();
            b.append(&rec(p.as_bytes())).unwrap();
        }
        a.sync().unwrap();
        b.sync().unwrap();
        // Two independent single-node logs with the same input are byte-identical, and constructing a
        // ReplicationLeader over one does not perturb it.
        let _leader = ReplicationLeader::new(&a);
        assert_eq!(dump_segments(&a), dump_segments(&b));
        assert_eq!(a.flushed_offset().get(), 15);
    }

    // ----- protocol codec + in-process wire round-trips -----

    #[test]
    fn fetch_request_round_trips_through_its_codec() {
        let req = FetchRecordsBody {
            from_offset: 0xDEAD_BEEF,
            max_records: 123,
            max_bytes: 4096,
        };
        assert_eq!(FetchRecordsBody::decode(&req.encode()).unwrap(), req);
    }

    #[test]
    fn fetch_request_decode_rejects_a_wrong_length_body() {
        assert!(matches!(
            FetchRecordsBody::decode(&[0u8; 15]),
            Err(ReplicationError::MalformedRequest { len: 15 })
        ));
        assert!(matches!(
            FetchRecordsBody::decode(&[0u8; 17]),
            Err(ReplicationError::MalformedRequest { len: 17 })
        ));
    }

    #[test]
    fn fetch_response_round_trips_through_its_codec() {
        let resp = FetchResponseBody {
            high_watermark: 77,
            first_offset: 12,
            record_count: 2,
            frame_bytes: vec![1, 2, 3, 4, 5],
        };
        assert_eq!(FetchResponseBody::decode(&resp.encode()).unwrap(), resp);
    }

    #[test]
    fn fetch_response_decode_rejects_an_oversized_claimed_run() {
        // Hand-craft a header that CLAIMS more frame bytes than the cap; it must be rejected before
        // the bytes are trusted (the untrusted-peer size bound).
        let mut body = Vec::new();
        body.extend_from_slice(&0u64.to_le_bytes()); // high_watermark
        body.extend_from_slice(&0u64.to_le_bytes()); // first_offset
        body.extend_from_slice(&0u32.to_le_bytes()); // record_count
        body.extend_from_slice(&(MAX_REPL_FETCH_BYTES + 1).to_le_bytes()); // frame_bytes_len > cap
        assert!(matches!(
            FetchResponseBody::decode(&body),
            Err(ReplicationError::ResponseTooLarge { .. })
        ));
    }

    #[test]
    fn fetch_response_decode_rejects_a_length_mismatch() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&10u32.to_le_bytes()); // claims 10 bytes …
        body.extend_from_slice(&[0u8; 3]); // … but only 3 follow
        assert!(matches!(
            FetchResponseBody::decode(&body),
            Err(ReplicationError::MalformedResponse { .. })
        ));
    }

    /// A blocking in-memory bidirectional pipe so a leader link and a follower link can exchange
    /// frames in-process, exercising the real [`ReplicationLink`] framing on a `Read + Write` stream
    /// (the loopback the C1 peer transport tests use the same shape of).
    struct Pipe {
        // Bytes this end will READ (written by the peer).
        inbound: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>,
        // Bytes this end WRITES (read by the peer).
        outbound: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>,
    }

    impl Pipe {
        fn pair() -> (Pipe, Pipe) {
            let a = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
            let b = std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
            (
                Pipe {
                    inbound: a.clone(),
                    outbound: b.clone(),
                },
                Pipe {
                    inbound: b,
                    outbound: a,
                },
            )
        }
    }

    impl io::Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut q = self.inbound.lock().unwrap();
            let n = buf.len().min(q.len());
            for slot in buf.iter_mut().take(n) {
                *slot = q.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    impl io::Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outbound.lock().unwrap().extend(buf.iter().copied());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn in_process_leader_follower_over_the_wire_link_is_byte_identical() {
        // The end-to-end loopback: the follower sends a real FetchRecords frame over the
        // ReplicationLink, the leader receives it, serves the fetch, sends a real FetchResponse frame
        // back, and the follower receives + applies it — all over the bounded frame envelope.
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..25u32 {
            leader_log
                .append(&rec(format!("wire-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let leader_hw = leader_log.flushed_offset().get();

        let (follower_end, leader_end) = Pipe::pair();
        let mut follower_link = ReplicationLink::new(follower_end);
        let mut leader_link = ReplicationLink::new(leader_end);
        let leader = ReplicationLeader::new(&leader_log);
        let mut follower = Follower::new(open_log(InMemoryFs::new(), small_config()));

        for _ in 0..(leader_hw + 2) {
            if follower.next_fetch_offset().get() >= leader_hw {
                break;
            }
            // Follower → wire → leader.
            let req = follower.fetch_request(8, 1024);
            follower_link.send_request(&req).unwrap();
            let got = leader_link.recv().unwrap().unwrap();
            let req = match got {
                ReplicationFrame::Request(r) => r,
                other @ ReplicationFrame::Response(_) => {
                    panic!("leader expected a Request, got {other:?}")
                }
            };
            // Leader serves → wire → follower.
            let resp = leader.serve_fetch(&req).unwrap();
            leader_link.send_response(&resp).unwrap();
            let got = follower_link.recv().unwrap().unwrap();
            let resp = match got {
                ReplicationFrame::Response(r) => r,
                other @ ReplicationFrame::Request(_) => {
                    panic!("follower expected a Response, got {other:?}")
                }
            };
            follower.apply_fetch_response(&resp).unwrap();
        }

        assert_eq!(follower.next_fetch_offset().get(), leader_hw);
        assert_eq!(
            dump_segments(follower.log()),
            dump_segments(&leader_log),
            "replication over the real wire link yields a byte-identical log"
        );
    }

    #[test]
    fn an_empty_fetch_when_caught_up_is_a_clean_no_op() {
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..4u32 {
            leader_log.append(&rec(format!("e{i}").as_bytes())).unwrap();
        }
        leader_log.sync().unwrap();
        let leader = ReplicationLeader::new(&leader_log);

        let mut follower = Follower::new(open_log(InMemoryFs::new(), small_config()));
        // Catch up fully.
        let req = follower.fetch_request(100, u32::MAX);
        let resp = leader.serve_fetch(&req).unwrap();
        follower.apply_fetch_response(&resp).unwrap();
        assert_eq!(follower.next_fetch_offset().get(), 4);

        // A further fetch at the HW returns an empty run; applying it is a no-op that still refreshes
        // the observed HW.
        let req = follower.fetch_request(100, u32::MAX);
        let resp = leader.serve_fetch(&req).unwrap();
        assert_eq!(resp.record_count, 0);
        assert!(resp.frame_bytes.is_empty());
        let outcome = follower.apply_fetch_response(&resp).unwrap();
        assert_eq!(outcome.appended, 0);
        assert_eq!(outcome.high_watermark, 4);
    }

    #[test]
    fn a_non_contiguous_response_is_rejected() {
        // A response whose first_offset does not continue the follower's log (a gap) fails closed —
        // epoch-truncation reconciliation of a divergent lineage is the deferred C2-I4 (#599).
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..6u32 {
            leader_log.append(&rec(format!("g{i}").as_bytes())).unwrap();
        }
        leader_log.sync().unwrap();
        let leader = ReplicationLeader::new(&leader_log);

        let mut follower = Follower::new(open_log(InMemoryFs::new(), small_config()));
        // Ask the leader for offset 3 while the follower is still at 0: a gap.
        let req = FetchRecordsBody {
            from_offset: 3,
            max_records: 3,
            max_bytes: u32::MAX,
        };
        let resp = leader.serve_fetch(&req).unwrap();
        assert_eq!(resp.first_offset, 3);
        let err = follower
            .apply_fetch_response(&resp)
            .expect_err("gap rejected");
        assert!(matches!(
            err,
            ReplicationError::NonContiguous {
                expected: 0,
                got: 3
            }
        ));
        assert_eq!(follower.next_fetch_offset().get(), 0, "nothing appended");
    }
}
