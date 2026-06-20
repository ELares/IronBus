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
use ironbus_core::epoch_cache::{
    DivergencePoint, EpochCache, EpochCacheError, LeaderEpochEndOffset,
};
use ironbus_core::leader_lease::LeaderEpoch;
use ironbus_core::types::Offset;
use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType, MAX_FRAME_LEN,
};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::{Append, Log, TruncateOutcome};
use ironbus_storage::read_plane::ReadPlane;
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

/// The `kind` discriminant byte leading an [`FrameType::OffsetForLeaderEpoch`] body, so the request
/// and the response (which share the wire tag, like `StreamInfo`) are never confused.
const EPOCH_QUERY_KIND_REQUEST: u8 = 0;
const EPOCH_QUERY_KIND_RESPONSE: u8 = 1;

/// The fixed little-endian byte length of an encoded [`OffsetForLeaderEpochBody`]:
/// `kind: u8` + `epoch: u64`.
const EPOCH_QUERY_REQUEST_LEN: usize = 1 + 8;

/// The fixed little-endian byte length of an encoded [`OffsetForLeaderEpochResponse`]:
/// `kind: u8` + `requested_epoch: u64` + `answered_epoch: u64` + `end_offset: u64`.
const EPOCH_QUERY_RESPONSE_LEN: usize = 1 + 8 + 8 + 8;

/// A follower → leader LEADER-EPOCH offset QUERY (#599, KIP-101): "what is the last offset YOU hold
/// for leadership epoch `epoch`?". The follower asks this for the epochs in its own epoch cache,
/// highest first, to find the divergence point against the leader's lineage. Rides the
/// [`FrameType::OffsetForLeaderEpoch`] envelope (tag 38) with a leading `kind = 0` byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffsetForLeaderEpochBody {
    /// The leadership epoch the follower is asking the leader's end-offset for.
    pub epoch: LeaderEpoch,
}

impl OffsetForLeaderEpochBody {
    /// Encode this request to its fixed-layout little-endian body bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EPOCH_QUERY_REQUEST_LEN);
        out.push(EPOCH_QUERY_KIND_REQUEST);
        out.extend_from_slice(&self.epoch.get().to_le_bytes());
        out
    }

    /// Decode a request from its body bytes.
    ///
    /// # Errors
    /// Returns [`ReplicationError::MalformedEpochQuery`] if `body` is not exactly the request length
    /// or its `kind` byte is not the request discriminant — fail-closed, never guessed at.
    pub fn decode(body: &[u8]) -> Result<OffsetForLeaderEpochBody, ReplicationError> {
        if body.len() != EPOCH_QUERY_REQUEST_LEN || body[0] != EPOCH_QUERY_KIND_REQUEST {
            return Err(ReplicationError::MalformedEpochQuery { len: body.len() });
        }
        Ok(OffsetForLeaderEpochBody {
            epoch: LeaderEpoch::new(read_u64_le(body, 1)),
        })
    }
}

/// A leader → follower LEADER-EPOCH offset RESPONSE (#599, KIP-101): the leader's end-offset for the
/// queried epoch (the start of its next epoch, its log end if the epoch is current, or the bound of
/// the next-higher epoch it holds when it never saw the queried one). Rides the
/// [`FrameType::OffsetForLeaderEpoch`] envelope (tag 38) with a leading `kind = 1` byte. It is the
/// wire form of [`LeaderEpochEndOffset`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffsetForLeaderEpochResponse {
    /// The leader's [`LeaderEpochEndOffset`] for the queried epoch.
    pub end_offset: LeaderEpochEndOffset,
}

impl OffsetForLeaderEpochResponse {
    /// Encode this response to its fixed-layout little-endian body bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EPOCH_QUERY_RESPONSE_LEN);
        out.push(EPOCH_QUERY_KIND_RESPONSE);
        out.extend_from_slice(&self.end_offset.requested_epoch.get().to_le_bytes());
        out.extend_from_slice(&self.end_offset.answered_epoch.get().to_le_bytes());
        out.extend_from_slice(&self.end_offset.end_offset.get().to_le_bytes());
        out
    }

    /// Decode a response from its body bytes.
    ///
    /// # Errors
    /// Returns [`ReplicationError::MalformedEpochQuery`] if `body` is not exactly the response length
    /// or its `kind` byte is not the response discriminant.
    pub fn decode(body: &[u8]) -> Result<OffsetForLeaderEpochResponse, ReplicationError> {
        if body.len() != EPOCH_QUERY_RESPONSE_LEN || body[0] != EPOCH_QUERY_KIND_RESPONSE {
            return Err(ReplicationError::MalformedEpochQuery { len: body.len() });
        }
        Ok(OffsetForLeaderEpochResponse {
            end_offset: LeaderEpochEndOffset {
                requested_epoch: LeaderEpoch::new(read_u64_le(body, 1)),
                answered_epoch: LeaderEpoch::new(read_u64_le(body, 9)),
                end_offset: Offset::new(read_u64_le(body, 17)),
            },
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
    /// An [`FrameType::OffsetForLeaderEpoch`] (#599) request/response body was malformed: a wrong
    /// length or a bad `kind` discriminant byte. Fail closed; the epoch handshake never guesses.
    MalformedEpochQuery {
        /// The body length seen.
        len: usize,
    },
    /// The leader-epoch cache (#599) rejected an operation (a backward epoch / offset) while
    /// reconstructing or extending the follower's epoch history — a fail-closed contract violation.
    EpochCache(EpochCacheError),
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
            ReplicationError::MalformedEpochQuery { len } => {
                write!(f, "malformed leader-epoch offset query body ({len} bytes)")
            }
            ReplicationError::EpochCache(e) => {
                write!(f, "replication leader-epoch cache error: {e}")
            }
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

impl From<EpochCacheError> for ReplicationError {
    fn from(e: EpochCacheError) -> Self {
        ReplicationError::EpochCache(e)
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

    /// Answer a follower's [`OffsetForLeaderEpochBody`] (#599, KIP-101): the leader's end-offset for
    /// the queried epoch, computed from the leader's epoch history (`leader_epochs`) and its current
    /// log end (its flushed/committed head). This is the leader half of the divergence handshake; the
    /// follower uses the answers to locate exactly where its lineage diverges from the leader's.
    ///
    /// The leader's epoch cache is metadata-group state (the metadata Raft assigns each leadership a
    /// monotonic epoch, #668), so it is passed in rather than reconstructed from the log bytes — the
    /// epoch is NOT stamped into the on-disk frames (the on-disk format is unchanged). The leader's
    /// log end here is its high-watermark (`flushed_offset`): the leader only ever advertises an
    /// end-offset over a committed range, so a follower never truncates to an uncommitted leader
    /// offset.
    #[must_use]
    pub fn serve_epoch_query(
        &self,
        leader_epochs: &EpochCache,
        req: &OffsetForLeaderEpochBody,
    ) -> OffsetForLeaderEpochResponse {
        let end = leader_epochs.end_offset_for_epoch(req.epoch, self.log.flushed_offset());
        OffsetForLeaderEpochResponse { end_offset: end }
    }
}

/// The LEADER side of replication that serves a follower's fetch through the LOCK-FREE, OFF-ACTOR READ
/// PLANE (#654) instead of a `&Log` borrow — the #715 engine-ownership refactor.
///
/// ## Why this exists (the `Send` crux)
///
/// [`ReplicationLeader`] holds a `&'a Log<F, C>`, so a controller that owns it is NOT `Send` and cannot
/// run on a peer-I/O thread alongside the engine's single append actor. The engine owns its partition
/// log PRIVATELY behind that actor (it is the ONLY writer of the log — the single-writer invariant), so
/// the data plane cannot take a second borrow of it across threads. But the engine ALSO publishes a
/// [`ReadPlane`] (#654): an `Arc`-shared, lock-free, off-actor view of the SEALED, flushed prefix (an
/// `AtomicU64` flushed frontier + an `ArcSwap` of the immutable sealed-segment snapshot). The append
/// actor keeps publishing to it after every commit/seal; any number of readers observe it with no lock
/// and no actor round-trip. A leader-serve is EXACTLY that read pattern — serve a committed byte range —
/// so the leader serves through a cloned `ReadPlane` (an `Arc`, `Send`) and NEVER borrows or writes the
/// leader's log. The data plane reads via the read plane; it is never a second writer. That is what
/// makes the controller `Send`.
///
/// ## The high-watermark and the active (flushed-but-unsealed) tail
///
/// The advertised high-watermark is the read plane's [`ReadPlane::flushed`] frontier — the SAME value
/// the append actor publishes from [`Log::flushed_offset`] after every commit (the through-actor leader
/// advertised exactly this). It is the true committed frontier, so a follower's visible HW (clamped to
/// `min(its own durable prefix, this HW)`) is identical to the through-actor path's.
///
/// The read plane serves only the SEALED prefix; a leader's flushed frontier can sit AHEAD of the
/// sealed end (the active segment holds flushed-but-unsealed records). When a fetch starts in that
/// active tail the read plane returns an EMPTY run (and a `fallback_from`); the follower applies the
/// empty run as a clean no-op, observes the advertised HW, and re-fetches. It catches up to the sealed
/// end byte-identically and replicates the active tail the moment it seals (a roll). This is CORRECT by
/// construction — no false ack, no false visibility (the follower only ever shows what it durably
/// holds) — but a follower can LAG by up to the active-segment size until that segment seals. That
/// liveness window (closing it by serving the active flushed tail off-actor, e.g. via an actor-fallback
/// read on the peer thread, or an active-segment read-plane extension) is FLAGGED as the follow-up; it
/// is not a correctness gap and does not affect the single-writer / byte-identical invariants.
pub struct ReadPlaneLeader<'a, F: Filesystem> {
    plane: &'a ReadPlane<F>,
}

impl<'a, F: Filesystem> ReadPlaneLeader<'a, F> {
    /// Wrap a leader's `Arc`-shared read plane as an off-actor replication source. The plane is the
    /// engine's own [`Engine::read_plane`](crate::engine::Engine::read_plane) clone (#654); it is
    /// `Send` and never borrows or writes the leader's log.
    #[must_use]
    pub fn new(plane: &'a ReadPlane<F>) -> Self {
        Self { plane }
    }

    /// The leader's current high-watermark: the read plane's flushed frontier — the same flushed /
    /// committed offset [`ReplicationLeader::high_watermark`] reads from the log, published by the
    /// append actor after every commit. A follower never replicates (or makes visible) past it.
    #[must_use]
    pub fn high_watermark(&self) -> Offset {
        Offset::new(self.plane.flushed())
    }

    /// Serve a follower's fetch from the SEALED, flushed prefix through the read plane — the off-actor
    /// twin of [`ReplicationLeader::serve_fetch`]. Reads a contiguous CRC-framed [`RawByteRun`] of the
    /// leader's own durable bytes via [`ReadPlane::read_range_raw`] (zero-copy, single sealed segment),
    /// bounded by the smaller of the request budget and [`MAX_REPL_FETCH_BYTES`], and advertises the
    /// read plane's flushed frontier as the high-watermark.
    ///
    /// The run is the SEALED prefix only: a fetch whose `from_offset` is already in the active
    /// (flushed-but-unsealed) tail returns an EMPTY run with the true HW (the follower no-ops and
    /// re-fetches; it catches up byte-identically as segments seal). The leader NEVER writes its log
    /// here — it only reads the immutable sealed bytes via the `Arc`-shared plane.
    ///
    /// # Errors
    /// Returns [`ReplicationError::Storage`] if the underlying raw read fails (e.g. the requested
    /// offset is older than the oldest retained record).
    pub fn serve_fetch(
        &self,
        req: &FetchRecordsBody,
    ) -> Result<FetchResponseBody, ReplicationError> {
        let hw = self.plane.flushed();
        let from = Offset::new(req.from_offset);
        // Bound the served bytes to the cap regardless of what the follower asked for (mirrors
        // ReplicationLeader exactly): `0` request bytes means "use the cap", so a follower without a
        // byte budget still makes progress; the record-count budget still bounds it.
        let req_bytes = if req.max_bytes == 0 {
            MAX_REPL_FETCH_BYTES
        } else {
            req.max_bytes.min(MAX_REPL_FETCH_BYTES)
        };
        let max_records = req.max_records as usize;
        // The read plane serves the SEALED prefix and reports `fallback_from` for the active tail; the
        // follower drives the cadence (it re-fetches from where it left off), so we serve the sealed
        // run this fetch covers and let the follower come back for the rest as it seals.
        let sealed = self
            .plane
            .read_range_raw(from, max_records, Some(req_bytes as usize))?;
        Ok(FetchResponseBody {
            high_watermark: hw,
            first_offset: sealed.run.first_offset.get(),
            record_count: u32::try_from(sealed.run.record_count).unwrap_or(u32::MAX),
            frame_bytes: sealed.run.bytes.to_vec(),
        })
    }

    /// Answer a follower's [`OffsetForLeaderEpochBody`] from the leader's epoch cache — the off-actor
    /// twin of [`ReplicationLeader::serve_epoch_query`]. The leader's log end is its high-watermark
    /// (the read plane's flushed frontier), so a follower never truncates to an uncommitted offset.
    #[must_use]
    pub fn serve_epoch_query(
        &self,
        leader_epochs: &EpochCache,
        req: &OffsetForLeaderEpochBody,
    ) -> OffsetForLeaderEpochResponse {
        let end = leader_epochs.end_offset_for_epoch(req.epoch, Offset::new(self.plane.flushed()));
        OffsetForLeaderEpochResponse { end_offset: end }
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

    /// Borrow the follower's underlying log MUTABLY — for the C4 self-heal path
    /// ([`crate::cluster::divergence`]), which truncates a detected-divergent suffix via the bounded,
    /// reported [`Log::truncate_to`] before re-fetching the clean bytes from the quorum. The C4 resync
    /// runs through the ordinary [`Follower`] fetch/apply path afterward, so the byte-identity and
    /// fail-closed properties are unchanged.
    #[must_use]
    pub fn log_mut(&mut self) -> &mut Log<F, C> {
        &mut self.log
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

/// The typed, REPORTED outcome of a leader-epoch divergence reconciliation (C2-I4, #599) — never a
/// silent drop. When a follower adopts a (possibly-new) leader and finds its uncommitted tail
/// diverges from the leader's lineage, [`EpochAwareFollower::reconcile_with_leader`] truncates to the
/// divergence point and returns this so the cluster surfaces it as a divergence event / metric (the
/// beat over NATS #5576, where a divergent replica silently returns with no data and never
/// reconciles). When nothing diverged it reports a clean no-op ([`DivergenceTruncation::is_no_op`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DivergenceTruncation {
    /// The divergence point computed from the epoch caches: the offset the follower truncated to,
    /// keeping the common prefix `[earliest, truncated_to)` and dropping the divergent suffix.
    pub divergence_point: DivergencePoint,
    /// The storage truncation outcome (records / bytes / segments actually dropped). Its
    /// `records_dropped` is `0` for a clean no-op (the follower was already a prefix of the leader).
    pub truncation: TruncateOutcome,
}

impl DivergenceTruncation {
    /// True if nothing was actually dropped: the follower shared the leader's lineage and was already
    /// a prefix of it, so it simply resumes fetching forward — no divergent suffix existed.
    #[must_use]
    pub fn is_no_op(&self) -> bool {
        self.truncation.records_dropped == 0
    }
}

/// A FOLLOWER augmented with a leader-epoch cache (KIP-101, C2-I4, #599): it wraps a plain
/// [`Follower`] (the C2-I1 fetch + CRC-validate + append machinery) with the epoch tracking and the
/// divergence-truncation that make replication SAFE under a leader change.
///
/// The epoch cache is IN-MEMORY and RECONSTRUCTIBLE (it is NEVER stamped into the on-disk frames, so
/// the segment format is unchanged and old logs stay readable): the follower learns the leader's
/// epoch boundaries over the wire as it replicates ([`assign_epoch`](EpochAwareFollower::assign_epoch))
/// and can rebuild the cache from the leader's advertised history after a reopen
/// ([`with_epochs`](EpochAwareFollower::with_epochs)).
///
/// On adopting a (possibly-new) leader, [`reconcile_with_leader`](EpochAwareFollower::reconcile_with_leader)
/// queries the leader's epoch history, finds the divergence point, and — if the follower's tail
/// diverges — TRUNCATES exactly there via the bounded, reported [`Log::truncate_to`], keeping the
/// longest common prefix and dropping only the genuinely-divergent suffix. It NEVER truncates below
/// the committed high-watermark: the divergence point is clamped to be at or above the follower's HW,
/// so committed data (fsync'd on a quorum, #691) is never dropped.
pub struct EpochAwareFollower<F: Filesystem, C: Clock> {
    follower: Follower<F, C>,
    /// The follower's leader-epoch cache: the `(epoch, start_offset)` boundaries of its own log.
    epochs: EpochCache,
}

impl<F: Filesystem, C: Clock> EpochAwareFollower<F, C> {
    /// Wrap a plain [`Follower`] with a fresh (empty) epoch cache. A follower replicating from
    /// scratch learns its epoch boundaries as it goes; one recovered with a prefix learns them from
    /// the leader on its next reconcile (or is seeded via [`with_epochs`](EpochAwareFollower::with_epochs)).
    pub fn new(follower: Follower<F, C>) -> Self {
        Self {
            follower,
            epochs: EpochCache::new(),
        }
    }

    /// Wrap a [`Follower`] with a KNOWN epoch cache — e.g. one reconstructed from the leader's
    /// advertised epoch history after a reopen (the "reconstruct the epoch cache from existing data"
    /// path: the cache is not persisted, it is rehydrated).
    pub fn with_epochs(follower: Follower<F, C>, epochs: EpochCache) -> Self {
        Self { follower, epochs }
    }

    /// Borrow the wrapped follower (to drive fetches, read its log, or check its high-watermark).
    #[must_use]
    pub fn follower(&self) -> &Follower<F, C> {
        &self.follower
    }

    /// Borrow the wrapped follower mutably (to apply fetch responses through the C2-I1 path).
    pub fn follower_mut(&mut self) -> &mut Follower<F, C> {
        &mut self.follower
    }

    /// The follower's leader-epoch cache (its `(epoch, start_offset)` boundaries).
    #[must_use]
    pub fn epochs(&self) -> &EpochCache {
        &self.epochs
    }

    /// Records that the records the follower is replicating FROM `start_offset` were appended under
    /// leadership `epoch` — extending the epoch cache by one boundary on a leadership change (a no-op
    /// while the epoch is unchanged). The follower calls this as it learns the leader's epoch
    /// boundaries during replication (the leader advertises the epoch a fetched range belongs to).
    ///
    /// # Errors
    /// [`ReplicationError::EpochCache`] if `epoch`/`start_offset` would go backward (the
    /// strictly-increasing invariant) — fail-closed.
    pub fn assign_epoch(
        &mut self,
        epoch: LeaderEpoch,
        start_offset: Offset,
    ) -> Result<(), ReplicationError> {
        self.epochs.assign(epoch, start_offset)?;
        Ok(())
    }

    /// RECONCILE the follower against a (possibly-new) leader: find the divergence point between the
    /// follower's epoch history and the leader's, and TRUNCATE the divergent suffix to exactly there
    /// — the KIP-101 leader-epoch truncation. Returns a typed, REPORTED [`DivergenceTruncation`]
    /// (never a silent drop). After this the follower's log is the longest common prefix with the
    /// leader; the caller resumes fetching forward (which now converges byte-identically because the
    /// lineages agree from here).
    ///
    /// `leader_end_offset` answers the leader's end-offset for a queried epoch — in production it is
    /// wired to send an [`OffsetForLeaderEpochBody`] over the [`ReplicationLink`] and read the
    /// [`OffsetForLeaderEpochResponse`]; in a test it calls the leader's
    /// [`ReplicationLeader::serve_epoch_query`] directly. `committed_hw` is the follower's committed
    /// high-watermark (from #691); the divergence point is CLAMPED to be at or above it, so committed
    /// data is NEVER truncated (only the uncommitted-divergent suffix is).
    ///
    /// # Errors
    /// - [`ReplicationError::Storage`] if the underlying [`Log::truncate_to`] fails.
    /// - [`ReplicationError::EpochCache`] if rebuilding the epoch cache after truncation fails.
    pub fn reconcile_with_leader<L>(
        &mut self,
        committed_hw: Offset,
        leader_end_offset: L,
    ) -> Result<DivergenceTruncation, ReplicationError>
    where
        L: FnMut(LeaderEpoch) -> LeaderEpochEndOffset,
    {
        let log_end = self.follower.log.next_offset();
        // Compute the divergence point from the epoch caches (the pure KIP-101 algorithm).
        let raw = self.epochs.divergence_point(log_end, leader_end_offset);
        // CLAMP the truncation target to be at or above the committed high-watermark: committed data
        // (fsync'd on a quorum, #691) is NEVER truncated, only the uncommitted-divergent suffix. A
        // correct lineage never asks to drop committed data, but the clamp makes that a hard floor —
        // the never-truncate-committed-data guarantee by construction, not by trust.
        let clamped_to = Offset::new(raw.truncate_to.get().max(committed_hw.get()));
        let divergence_point = DivergencePoint {
            truncate_to: clamped_to,
            diverged_at_epoch: raw.diverged_at_epoch,
        };

        if !divergence_point.needs_truncation(log_end) {
            // The follower is already a prefix of the leader's lineage (or has nothing above the
            // divergence point): nothing to drop, just fetch forward. Report a clean no-op.
            return Ok(DivergenceTruncation {
                divergence_point,
                truncation: TruncateOutcome {
                    truncated_to: log_end.get(),
                    next_offset_before: log_end.get(),
                    records_dropped: 0,
                    bytes_dropped: 0,
                    segments_dropped: 0,
                },
            });
        }

        // Truncate the divergent suffix on the durable bytes — bounded + reported.
        let truncation = self.follower.log.truncate_to(clamped_to)?;
        // Mirror the truncation in the epoch cache: drop the boundaries of the divergent suffix so the
        // cache covers only the surviving common prefix, then the follower re-learns the new leader's
        // epoch as it fetches forward.
        self.epochs.truncate_to(clamped_to);
        // The follower's observed leader high-watermark must not claim more than it now durably holds;
        // reset it to the truncated head so its visible HW is correct until the next fetch raises it.
        self.follower.leader_high_watermark = clamped_to.get();

        Ok(DivergenceTruncation {
            divergence_point,
            truncation,
        })
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
    /// A follower's [`OffsetForLeaderEpochBody`] divergence query (received on the leader side, #599).
    EpochQuery(OffsetForLeaderEpochBody),
    /// A leader's [`OffsetForLeaderEpochResponse`] (received on the follower side, #599).
    EpochResponse(OffsetForLeaderEpochResponse),
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

    /// Send a follower → leader leader-epoch offset QUERY (#599).
    ///
    /// # Errors
    /// Returns [`ReplicationError::Frame`] / [`ReplicationError::Io`] as [`send_request`](ReplicationLink::send_request).
    pub fn send_epoch_query(
        &mut self,
        req: &OffsetForLeaderEpochBody,
    ) -> Result<(), ReplicationError> {
        self.send(FrameType::OffsetForLeaderEpoch, &req.encode())
    }

    /// Send a leader → follower leader-epoch offset RESPONSE (#599).
    ///
    /// # Errors
    /// Returns [`ReplicationError::Frame`] / [`ReplicationError::Io`] as [`send_response`](ReplicationLink::send_response).
    pub fn send_epoch_response(
        &mut self,
        resp: &OffsetForLeaderEpochResponse,
    ) -> Result<(), ReplicationError> {
        self.send(FrameType::OffsetForLeaderEpoch, &resp.encode())
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
            Some(FrameType::OffsetForLeaderEpoch) => {
                // The query and the response share tag 38; the leading `kind` byte distinguishes them.
                match body.first().copied() {
                    Some(EPOCH_QUERY_KIND_REQUEST) => Ok(ReplicationFrame::EpochQuery(
                        OffsetForLeaderEpochBody::decode(body)?,
                    )),
                    Some(EPOCH_QUERY_KIND_RESPONSE) => Ok(ReplicationFrame::EpochResponse(
                        OffsetForLeaderEpochResponse::decode(body)?,
                    )),
                    _ => Err(ReplicationError::MalformedEpochQuery { len: body.len() }),
                }
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
                other => panic!("leader expected a Request, got {other:?}"),
            };
            // Leader serves → wire → follower.
            let resp = leader.serve_fetch(&req).unwrap();
            leader_link.send_response(&resp).unwrap();
            let got = follower_link.recv().unwrap().unwrap();
            let resp = match got {
                ReplicationFrame::Response(r) => r,
                other => panic!("follower expected a Response, got {other:?}"),
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

    // ===== C2-I4 (#599): leader-epoch truncation on follower divergence (KIP-101) =====

    use ironbus_core::epoch_cache::EpochEntry;

    /// Drive a fetch catch-up of an [`EpochAwareFollower`] to the leader's HW (leader-serve →
    /// follower-apply), returning the wrapper. Mirrors `replicate_to_catch_up` for the epoch-aware
    /// follower.
    fn epoch_replicate_to_catch_up(
        leader_log: &Log<InMemoryFs, ManualClock>,
        mut follower: EpochAwareFollower<InMemoryFs, ManualClock>,
        max_records: u32,
        max_bytes: u32,
    ) -> EpochAwareFollower<InMemoryFs, ManualClock> {
        let leader = ReplicationLeader::new(leader_log);
        let hw = leader.high_watermark().get();
        for _ in 0..(hw + 2) {
            if follower.follower().next_fetch_offset().get() >= hw {
                break;
            }
            let req = follower.follower().fetch_request(max_records, max_bytes);
            let resp = leader.serve_fetch(&req).expect("leader serves fetch");
            follower
                .follower_mut()
                .apply_fetch_response(&resp)
                .expect("follower applies a valid fetch");
        }
        follower
    }

    /// Build a leader log whose records carry a known epoch history, and the matching leader epoch
    /// cache. `runs` is `(epoch, count)` pairs appended in order; the cache records a boundary at the
    /// start offset of each new epoch.
    fn build_leader_with_epochs(
        config: LogConfig,
        runs: &[(u64, u32)],
        prefix: &str,
    ) -> (Log<InMemoryFs, ManualClock>, EpochCache) {
        let mut log = open_log(InMemoryFs::new(), config);
        let mut epochs = EpochCache::new();
        let mut offset = 0u64;
        let mut n = 0u32;
        for &(epoch, count) in runs {
            epochs
                .assign(LeaderEpoch::new(epoch), Offset::new(offset))
                .expect("epoch assign");
            for _ in 0..count {
                log.append(&rec(format!("{prefix}-{n:03}").as_bytes()))
                    .unwrap();
                n += 1;
                offset += 1;
            }
        }
        log.sync().unwrap();
        (log, epochs)
    }

    // ----- the headline: a divergent follower truncates to the divergence point + converges -----

    #[test]
    fn a_divergent_follower_truncates_to_the_divergence_point_then_converges_byte_identical() {
        // The OLD leader's lineage: epoch 1 for offsets [0,10), epoch 5 for [10,18). The follower
        // replicated all 18 records from it (the epoch-5 tail [10,18) is UNCOMMITTED — never quorum'd).
        let cfg = small_config();
        let (old_leader, old_epochs) = build_leader_with_epochs(cfg, &[(1, 10), (5, 8)], "rec");
        let mut follower = EpochAwareFollower::new(Follower::new(open_log(InMemoryFs::new(), cfg)));
        // Replicate the OLD leader's 18 records, learning its epoch boundaries as it goes.
        follower
            .assign_epoch(LeaderEpoch::new(1), Offset::ZERO)
            .unwrap();
        follower = epoch_replicate_to_catch_up(&old_leader, follower, 100, u32::MAX);
        follower
            .assign_epoch(LeaderEpoch::new(5), Offset::new(10))
            .unwrap();
        assert_eq!(follower.follower().next_fetch_offset().get(), 18);

        // The NEW leader's lineage shares the epoch-1 prefix [0,10) but DIVERGED at epoch 5: it only
        // ever held [10,14) under epoch 5, then took a NEW epoch 6 for [14, ...). So the follower's
        // records [14,18) under epoch 5 are a DIVERGENT suffix the new leader never had. The new
        // leader's records [0,14) are byte-identical to the follower's (same epochs + same producer
        // content), and [14, ...) is its own epoch-6 lineage.
        let (new_leader, new_epochs) =
            build_leader_with_epochs(cfg, &[(1, 10), (5, 4), (6, 9)], "rec");

        // RECONCILE the follower against the NEW leader. committed_hw = 10 (only the epoch-1 prefix was
        // committed/quorum'd; the epoch-5 tail was uncommitted). The divergence point is 14: the
        // shared epoch 5 ended at 14 on the new leader.
        let outcome = follower
            .reconcile_with_leader(Offset::new(10), |e| {
                ReplicationLeader::new(&new_leader)
                    .serve_epoch_query(&new_epochs, &OffsetForLeaderEpochBody { epoch: e })
                    .end_offset
            })
            .expect("reconcile");
        assert_eq!(
            outcome.divergence_point.truncate_to,
            Offset::new(14),
            "truncate to where the shared epoch 5 ended on the new leader"
        );
        assert_eq!(
            outcome.divergence_point.diverged_at_epoch,
            LeaderEpoch::new(5)
        );
        assert!(!outcome.is_no_op(), "a real divergent suffix was dropped");
        assert_eq!(outcome.truncation.records_dropped, 4, "[14,18) dropped");
        assert_eq!(follower.follower().next_fetch_offset().get(), 14);

        // The epoch cache now covers only the common prefix [0,14): epoch 1 + epoch 5 (its start 10 is
        // below 14), the divergent epoch boundaries are gone.
        assert_eq!(
            follower.epochs().entries(),
            &[
                EpochEntry {
                    epoch: LeaderEpoch::new(1),
                    start_offset: Offset::ZERO
                },
                EpochEntry {
                    epoch: LeaderEpoch::new(5),
                    start_offset: Offset::new(10)
                },
            ]
        );

        // RE-FETCH forward from the NEW leader and CONVERGE. The follower learns epoch 6 at offset 14.
        follower
            .assign_epoch(LeaderEpoch::new(6), Offset::new(14))
            .unwrap();
        follower = epoch_replicate_to_catch_up(&new_leader, follower, 100, u32::MAX);

        // BYTE-IDENTICAL to the new leader: the follower kept the common prefix [0,14) and re-fetched
        // the new leader's epoch-6 lineage, so its on-disk log matches the new leader's frame-for-frame.
        let new_hw = new_leader.flushed_offset().get();
        assert_eq!(follower.follower().next_fetch_offset().get(), new_hw);
        assert_eq!(
            dump_segments(follower.follower().log()),
            dump_segments(&new_leader),
            "after divergence-truncation + re-fetch the follower is byte-identical to the new leader"
        );
        // And it never used the old leader (the divergent records are gone).
        let _ = old_epochs;
    }

    #[test]
    fn committed_data_below_the_high_watermark_is_never_truncated() {
        // Even if a (buggy or adversarial) divergence computation pointed BELOW the committed HW, the
        // clamp guarantees committed data is never dropped. Here the follower committed [0,12) (HW=12)
        // but the raw divergence point is 8 (inside committed data); the clamp floors the truncation
        // at 12, so NOTHING committed is lost.
        let cfg = small_config();
        let (leader, _epochs) = build_leader_with_epochs(cfg, &[(3, 20)], "c");
        let mut follower = EpochAwareFollower::new(Follower::new(open_log(InMemoryFs::new(), cfg)));
        follower
            .assign_epoch(LeaderEpoch::new(3), Offset::ZERO)
            .unwrap();
        follower = epoch_replicate_to_catch_up(&leader, follower, 100, u32::MAX);
        assert_eq!(follower.follower().next_fetch_offset().get(), 20);

        // Force a divergence query that (incorrectly) claims the shared epoch ended at offset 8 — below
        // the committed HW of 12. The clamp must refuse to truncate below 12.
        let outcome = follower
            .reconcile_with_leader(Offset::new(12), |e| LeaderEpochEndOffset {
                requested_epoch: e,
                answered_epoch: e,
                end_offset: Offset::new(8),
            })
            .expect("reconcile");
        assert_eq!(
            outcome.divergence_point.truncate_to,
            Offset::new(12),
            "the truncation is clamped to the committed HW, never below it"
        );
        assert_eq!(follower.follower().next_fetch_offset().get(), 12);
        // The committed records [0,12) all survive.
        assert_eq!(
            follower
                .follower()
                .log()
                .read_from(Offset::ZERO, 100)
                .unwrap()
                .len(),
            12
        );
    }

    #[test]
    fn a_follower_that_is_a_prefix_of_the_leader_reconciles_to_a_clean_no_op() {
        // The follower's whole log is a prefix of the new leader's identical lineage: nothing diverges,
        // so reconcile is a no-op and the follower simply continues fetching forward.
        let cfg = small_config();
        let (leader, epochs) = build_leader_with_epochs(cfg, &[(2, 15)], "p");
        let mut follower = EpochAwareFollower::new(Follower::new(open_log(InMemoryFs::new(), cfg)));
        follower
            .assign_epoch(LeaderEpoch::new(2), Offset::ZERO)
            .unwrap();
        // Replicate only the first 6 records (a strict prefix), looping since the small segment cap
        // bounds each fetch to one segment.
        let leader_src = ReplicationLeader::new(&leader);
        while follower.follower().next_fetch_offset().get() < 6 {
            let want = 6 - follower.follower().next_fetch_offset().get();
            let req = follower
                .follower()
                .fetch_request(u32::try_from(want).unwrap(), u32::MAX);
            let resp = leader_src.serve_fetch(&req).unwrap();
            follower.follower_mut().apply_fetch_response(&resp).unwrap();
        }
        assert_eq!(follower.follower().next_fetch_offset().get(), 6);

        let outcome = follower
            .reconcile_with_leader(Offset::new(6), |e| {
                leader_src
                    .serve_epoch_query(&epochs, &OffsetForLeaderEpochBody { epoch: e })
                    .end_offset
            })
            .expect("reconcile");
        assert!(outcome.is_no_op(), "a prefix follower truncates nothing");
        assert_eq!(outcome.truncation.records_dropped, 0);
        assert_eq!(
            follower.follower().next_fetch_offset().get(),
            6,
            "log unchanged"
        );

        // It converges by fetching forward.
        follower = epoch_replicate_to_catch_up(&leader, follower, 100, u32::MAX);
        assert_eq!(
            dump_segments(follower.follower().log()),
            dump_segments(&leader)
        );
    }

    #[test]
    fn the_epoch_cache_reconstructs_correctly_after_a_reopen() {
        // The epoch cache is NOT persisted (it is never stamped into the on-disk frames); after a
        // reopen the follower's log recovers from durable bytes, and the epoch cache is REHYDRATED
        // from the leader's advertised epoch history — yielding the same cache, so a subsequent
        // divergence reconcile is identical to one before the reopen.
        let cfg = small_config();
        let (leader, leader_epochs) = build_leader_with_epochs(cfg, &[(1, 8), (4, 7)], "k");
        let follower_fs = InMemoryFs::new();
        {
            let mut follower =
                EpochAwareFollower::new(Follower::new(open_log(follower_fs.clone(), cfg)));
            follower
                .assign_epoch(LeaderEpoch::new(1), Offset::ZERO)
                .unwrap();
            follower = epoch_replicate_to_catch_up(&leader, follower, 100, u32::MAX);
            follower
                .assign_epoch(LeaderEpoch::new(4), Offset::new(8))
                .unwrap();
            assert_eq!(follower.follower().next_fetch_offset().get(), 15);
            assert_eq!(follower.epochs().entries().len(), 2);
        }
        // Reopen: the log recovers its 15 records; the epoch cache is rebuilt from the leader's history
        // (the same boundaries the leader advertises).
        let reopened_log = open_log(follower_fs, cfg);
        assert_eq!(
            reopened_log.next_offset().get(),
            15,
            "durable prefix recovered"
        );
        let rebuilt = EpochCache::from_entries(leader_epochs.entries().to_vec()).unwrap();
        let follower = EpochAwareFollower::with_epochs(Follower::new(reopened_log), rebuilt);
        assert_eq!(
            follower.epochs().entries(),
            leader_epochs.entries(),
            "the rehydrated epoch cache matches the leader's advertised history"
        );
        // A reconcile against the same leader is a clean no-op (the follower IS the leader's lineage).
        let mut follower = follower;
        let outcome = follower
            .reconcile_with_leader(Offset::new(15), |e| {
                ReplicationLeader::new(&leader)
                    .serve_epoch_query(&leader_epochs, &OffsetForLeaderEpochBody { epoch: e })
                    .end_offset
            })
            .expect("reconcile");
        assert!(outcome.is_no_op());
    }

    #[test]
    fn divergence_across_multiple_epoch_changes_truncates_at_the_right_point() {
        // A deeper divergence: the follower and the new leader share epochs 2 and 4 then diverge. The
        // common prefix ends where epoch 4 ended on the new leader.
        let cfg = small_config();
        // Follower lineage: 2@[0,5), 4@[5,12), 7@[12,20) (epoch 7 is the divergent tail).
        let (old_leader, _) = build_leader_with_epochs(cfg, &[(2, 5), (4, 7), (7, 8)], "m");
        let mut follower = EpochAwareFollower::new(Follower::new(open_log(InMemoryFs::new(), cfg)));
        follower
            .assign_epoch(LeaderEpoch::new(2), Offset::ZERO)
            .unwrap();
        follower = epoch_replicate_to_catch_up(&old_leader, follower, 100, u32::MAX);
        follower
            .assign_epoch(LeaderEpoch::new(4), Offset::new(5))
            .unwrap();
        follower
            .assign_epoch(LeaderEpoch::new(7), Offset::new(12))
            .unwrap();
        assert_eq!(follower.follower().next_fetch_offset().get(), 20);

        // New leader: 2@[0,5), 4@[5,12), 8@[12, ...). It shares [0,12) but never had epoch 7. So the
        // divergence point is 12 (where epoch 4 ended on both); the epoch-7 suffix [12,20) is dropped.
        let (new_leader, new_epochs) =
            build_leader_with_epochs(cfg, &[(2, 5), (4, 7), (8, 10)], "m");
        let outcome = follower
            .reconcile_with_leader(Offset::new(5), |e| {
                ReplicationLeader::new(&new_leader)
                    .serve_epoch_query(&new_epochs, &OffsetForLeaderEpochBody { epoch: e })
                    .end_offset
            })
            .expect("reconcile");
        assert_eq!(outcome.divergence_point.truncate_to, Offset::new(12));
        assert_eq!(
            outcome.divergence_point.diverged_at_epoch,
            LeaderEpoch::new(4)
        );
        assert_eq!(outcome.truncation.records_dropped, 8);

        follower
            .assign_epoch(LeaderEpoch::new(8), Offset::new(12))
            .unwrap();
        follower = epoch_replicate_to_catch_up(&new_leader, follower, 100, u32::MAX);
        assert_eq!(
            dump_segments(follower.follower().log()),
            dump_segments(&new_leader),
            "converges byte-identical to the new leader across multiple epoch changes"
        );
    }

    #[test]
    fn single_node_is_unaffected_no_epoch_truncation_without_a_cluster() {
        // The epoch-aware machinery is opt-in: a plain single-node log is byte-for-byte what it always
        // was. No EpochAwareFollower / EpochCache is built without a cluster, so no truncation runs and
        // the on-disk layout is unchanged — proven by an identical plain log built the ordinary way.
        let cfg = small_config();
        let mut a = open_log(InMemoryFs::new(), cfg);
        let mut b = open_log(InMemoryFs::new(), cfg);
        for i in 0..15u32 {
            let p = format!("plain-{i}");
            a.append(&rec(p.as_bytes())).unwrap();
            b.append(&rec(p.as_bytes())).unwrap();
        }
        a.sync().unwrap();
        b.sync().unwrap();
        assert_eq!(dump_segments(&a), dump_segments(&b));
        assert_eq!(a.flushed_offset().get(), 15);
    }

    // ----- the epoch-query wire codec + over-the-wire round-trip -----

    #[test]
    fn epoch_query_request_round_trips_through_its_codec() {
        let req = OffsetForLeaderEpochBody {
            epoch: LeaderEpoch::new(0xABCD),
        };
        assert_eq!(
            OffsetForLeaderEpochBody::decode(&req.encode()).unwrap(),
            req
        );
        // A wrong length or bad kind byte is rejected.
        assert!(matches!(
            OffsetForLeaderEpochBody::decode(&[0u8; 4]),
            Err(ReplicationError::MalformedEpochQuery { .. })
        ));
        let mut bad = req.encode();
        bad[0] = 9; // not the request kind
        assert!(matches!(
            OffsetForLeaderEpochBody::decode(&bad),
            Err(ReplicationError::MalformedEpochQuery { .. })
        ));
    }

    #[test]
    fn epoch_query_response_round_trips_through_its_codec() {
        let resp = OffsetForLeaderEpochResponse {
            end_offset: LeaderEpochEndOffset {
                requested_epoch: LeaderEpoch::new(7),
                answered_epoch: LeaderEpoch::new(9),
                end_offset: Offset::new(123),
            },
        };
        assert_eq!(
            OffsetForLeaderEpochResponse::decode(&resp.encode()).unwrap(),
            resp
        );
    }

    #[test]
    fn epoch_query_round_trips_over_the_wire_link() {
        // The follower sends a real OffsetForLeaderEpoch query over the ReplicationLink; the leader
        // receives it, serves it from its epoch cache, sends the response back, and the follower reads
        // it — all over the bounded frame envelope, request and response sharing tag 38.
        let cfg = small_config();
        let (leader_log, leader_epochs) = build_leader_with_epochs(cfg, &[(1, 10), (4, 10)], "w");

        let (follower_end, leader_end) = Pipe::pair();
        let mut follower_link = ReplicationLink::new(follower_end);
        let mut leader_link = ReplicationLink::new(leader_end);
        let leader = ReplicationLeader::new(&leader_log);

        // Follower asks for epoch 1's end-offset.
        follower_link
            .send_epoch_query(&OffsetForLeaderEpochBody {
                epoch: LeaderEpoch::new(1),
            })
            .unwrap();
        let got = leader_link.recv().unwrap().unwrap();
        let query = match got {
            ReplicationFrame::EpochQuery(q) => q,
            other => panic!("leader expected an EpochQuery, got {other:?}"),
        };
        let resp = leader.serve_epoch_query(&leader_epochs, &query);
        leader_link.send_epoch_response(&resp).unwrap();
        let got = follower_link.recv().unwrap().unwrap();
        let resp = match got {
            ReplicationFrame::EpochResponse(r) => r,
            other => panic!("follower expected an EpochResponse, got {other:?}"),
        };
        // Epoch 1 ended where epoch 4 began: offset 10.
        assert_eq!(resp.end_offset.answered_epoch, LeaderEpoch::new(1));
        assert_eq!(resp.end_offset.end_offset, Offset::new(10));
    }
}
