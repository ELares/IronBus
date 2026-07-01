// SPDX-License-Identifier: MIT OR Apache-2.0
//! The durable transactional half-message store (V2-M8, #640 part 1/2).
//!
//! This is the durable side of the RocketMQ-style transactional-message model (the pure lifecycle
//! is [`ironbus_core::txn`]). A producer's **half (prepared) message** is buffered here durably but
//! kept INVISIBLE to consumers; a later **commit** appends the buffered payload to the REAL target
//! stream and writes a committed op-marker, and a **rollback** writes a rolled-back op-marker (the
//! payload is never delivered). On open, both record kinds are replayed to rebuild the in-memory
//! [`TxnTable`] and the buffered-payload map, so prepared half messages and their resolutions
//! SURVIVE a restart.
//!
//! ## On-disk shape (modeled on the DLQ / geo sub-logs)
//!
//! The store is a SECOND segmented [`Log`](crate::log::Log) rooted at the `txn/` subdirectory of the
//! data directory (via [`crate::fs::Filesystem::subdir`]), exactly like [`crate::dlq::DlqSink`]'s
//! `dlq/` sink — same framed, CRC32C'd, recoverable segment format, readable by the same
//! [`SegmentReader`](crate::segment::SegmentReader) / [`OfflineReader`](crate::offline::OfflineReader)
//! code, with no second segment format to maintain. A single `txn/` log interleaves TWO logical
//! record kinds, distinguished by a magic in the record's `headers` blob:
//!
//! - a **HALF record** ([`TXN_HALF_MAGIC`]) carries the prepared half message: the producer-supplied
//!   `txn_id`, the REAL target stream name, and the original record's headers/flags in the metadata
//!   blob, with the original `key` / `payload` / `timestamp_ms` preserved VERBATIM as the segment
//!   record's own fields — so a commit can faithfully reconstruct the real append.
//! - an **OP record** ([`TXN_OP_MAGIC`]) carries a resolution marker: the `txn_id`, the kind
//!   (committed / rolled-back), and (for a commit) the REAL offset the payload landed at.
//!
//! Both are versioned ([`TXN_FORMAT_VERSION`]) and CRC32C'd, pinned by snapshot tests, so neither
//! format silently changes.
//!
//! ## The unit of crash safety this store owns
//!
//! This module owns the DURABLE PRIMITIVES — append-and-fsync a half record, append-and-fsync an op
//! marker, replay both on open — plus the in-memory [`TxnTable`] + buffered-payload index they
//! rebuild. It does NOT itself append to the real target stream: the engine drives the
//! crash-safe ORDERING (real-stream append first, then the committed op-marker) and makes the
//! real-stream replay-append idempotent with the effectively-once dedup machinery (the txn id as the
//! dedup identity). See the engine's `txn_commit` for the full crash-window argument; this store
//! guarantees only that a half message is never lost while prepared, and that a resolution, once
//! written and fsync'd, survives a restart and replays the lifecycle exactly.

use crate::fs::Filesystem;
use crate::log::{Append, Log, LogConfig};
use crate::naming::segment_file_name;
use crate::segment::{SegmentReader, StorageError};
use ironbus_core::clock::Clock;
use ironbus_core::txn::{
    BackCheckBook, BackCheckConfig, TxnConfig, TxnOutcome, TxnState, TxnTable,
};
use ironbus_core::types::RecordFlags;
use std::collections::HashMap;

/// The subdirectory of the data directory that holds the transactional half-message store's
/// segments. Absent entirely from a deployment that never produces a transactional message, so the
/// non-txn hot path is byte-for-byte unchanged.
pub const TXN_SUBDIR: &str = "txn";

/// The FROZEN on-disk format version for a txn store record's metadata header. Bumped only by a
/// future format change, at which point a reader refuses an unknown value (fail-closed) the same way
/// the segment `FORMAT_VERSION` and layout marker do. Pinned by a snapshot test.
pub const TXN_FORMAT_VERSION: u8 = 1;

/// The 4-byte magic that opens a HALF (prepared) record's metadata header. A `headers` blob that
/// does not begin with a recognized txn magic is foreign to this store and is skipped, never misread.
pub const TXN_HALF_MAGIC: [u8; 4] = *b"TXNH";

/// The 4-byte magic that opens an OP (resolution-marker) record's metadata header.
pub const TXN_OP_MAGIC: [u8; 4] = *b"TXNO";

/// The 4-byte magic that opens a BACK (back-check bookkeeping) record's metadata header (#640 part 2).
/// A back-check record durably persists a still-`Prepared` txn's back-check schedule + attempt count
/// so they SURVIVE a broker restart and the scan resumes; on replay it rebuilds the in-memory
/// [`BackCheckBook`]. A `headers` blob that does not begin with a recognized txn magic is foreign to
/// this store and is skipped, never misread.
pub const TXN_BACK_MAGIC: [u8; 4] = *b"TXNB";

/// The op-marker kind byte: the transaction COMMITTED (its half message is appended to the real
/// stream and becomes visible). The marker also carries the real offset the payload landed at.
const OP_KIND_COMMITTED: u8 = 0;
/// The op-marker kind byte: the transaction ROLLED BACK (its half message is discarded, never
/// delivered).
const OP_KIND_ROLLED_BACK: u8 = 1;

/// One prepared half message read back from the durable store: everything the engine needs to append
/// it to the real target stream on a commit (or a crash-recovery redrive).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HalfMessage {
    /// The producer-supplied transaction id (the lifecycle key).
    pub txn_id: Vec<u8>,
    /// The REAL target stream the committed payload is appended to (empty = the default stream).
    pub stream: String,
    /// The original record's producer timestamp, milliseconds since the Unix epoch (preserved).
    pub timestamp_ms: u64,
    /// The original record's routing/ordering key (preserved verbatim).
    pub key: Vec<u8>,
    /// The original record's headers blob (preserved verbatim; the txn metadata is stripped).
    pub headers: Vec<u8>,
    /// The original record's payload (preserved verbatim).
    pub payload: Vec<u8>,
    /// The original record's content flags (preserved verbatim; `HAS_KEY` is re-derived on append).
    pub flags: RecordFlags,
}

impl HalfMessage {
    /// The RESIDENT heap bytes this buffered half message costs (#958), via [`prepared_resident_bytes`]
    /// over its producer-controlled parts. The per-prepare charge the byte budget meters.
    #[must_use]
    pub fn resident_bytes(&self) -> u64 {
        prepared_resident_bytes(
            &self.txn_id,
            &self.stream,
            &self.key,
            &self.headers,
            &self.payload,
        )
    }
}

/// The RESIDENT heap bytes one buffered prepared half message costs (#958): the sum of its
/// variable-length, producer-controlled parts (`txn_id` + `stream` + `key` + `headers` + `payload`),
/// which is the RAM a `TxnPrepare` pins while the txn stays `Prepared`. This is the exact per-prepare
/// charge the optional byte budget (`--max-prepared-bytes`, #909 follow-up) meters and the refuse-to-
/// boot guard's term 7 bounds when the budget is set — the honest analog of the worst-case
/// `PREPARED_HALF_MESSAGE_BYTES` count-charge. The small fixed per-entry struct/`HashMap` overhead is
/// not counted, exactly as term 1's `consumer_credit_bytes` charges payload bytes, not the slot
/// bookkeeping; each `len` is a bounded (`u16`-framed) wire quantity, but the adds SATURATE so the
/// measure can never wrap.
#[must_use]
pub fn prepared_resident_bytes(
    txn_id: &[u8],
    stream: &str,
    key: &[u8],
    headers: &[u8],
    payload: &[u8],
) -> u64 {
    (txn_id.len() as u64)
        .saturating_add(stream.len() as u64)
        .saturating_add(key.len() as u64)
        .saturating_add(headers.len() as u64)
        .saturating_add(payload.len() as u64)
}

/// The fixed-size prefix of a HALF record's metadata blob: `magic`(4) + `version`(1) +
/// `txn_id_len`(2) + `stream_len`(2) + `orig_headers_len`(2) + `orig_flags`(1).
const HALF_FIXED_LEN: usize = 4 + 1 + 2 + 2 + 2 + 1;

/// The fixed-size prefix of an OP record's metadata blob: `magic`(4) + `version`(1) + `op_kind`(1) +
/// `txn_id_len`(2) + `real_offset`(8).
const OP_FIXED_LEN: usize = 4 + 1 + 1 + 2 + 8;

/// The fixed-size prefix of a BACK record's metadata blob (#640 part 2): `magic`(4) + `version`(1) +
/// `txn_id_len`(2) + `attempts`(4) + `next_eligible`(8).
const BACK_FIXED_LEN: usize = 4 + 1 + 2 + 4 + 8;

/// Encodes the HALF (prepared) record's metadata blob (the segment record's `headers` field): the
/// fixed prefix, then `txn_id`, the `stream` name, and the original headers, then a trailing crc32c
/// over everything before it. Returns `None` if any length field would overflow its `u16` (the wire
/// `PUB` path already bounds them, so a real record never trips this).
#[must_use]
pub fn encode_half_meta(
    txn_id: &[u8],
    stream: &str,
    orig_flags: RecordFlags,
    orig_headers: &[u8],
) -> Option<Vec<u8>> {
    let txn_len = u16::try_from(txn_id.len()).ok()?;
    let stream_len = u16::try_from(stream.len()).ok()?;
    let headers_len = u16::try_from(orig_headers.len()).ok()?;
    let mut out =
        Vec::with_capacity(HALF_FIXED_LEN + txn_id.len() + stream.len() + orig_headers.len() + 4);
    out.extend_from_slice(&TXN_HALF_MAGIC);
    out.push(TXN_FORMAT_VERSION);
    out.extend_from_slice(&txn_len.to_le_bytes());
    out.extend_from_slice(&stream_len.to_le_bytes());
    out.extend_from_slice(&headers_len.to_le_bytes());
    out.push(orig_flags.bits());
    out.extend_from_slice(txn_id);
    out.extend_from_slice(stream.as_bytes());
    out.extend_from_slice(orig_headers);
    let crc = ironbus_core::crc::crc32c(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Some(out)
}

/// Encodes an OP (resolution-marker) record's metadata blob: the fixed prefix (magic, version, op
/// kind, `txn_id_len`, `real_offset`), then `txn_id`, then a trailing crc32c. `real_offset` is the
/// offset the committed payload landed at on the real stream (meaningless / `0` for a rollback).
/// Returns `None` if `txn_id` overflows its `u16` length (unreachable from the bounded wire path).
#[must_use]
pub fn encode_op_meta(txn_id: &[u8], outcome: TxnOutcome, real_offset: u64) -> Option<Vec<u8>> {
    let txn_len = u16::try_from(txn_id.len()).ok()?;
    let op_kind = match outcome {
        TxnOutcome::Committed => OP_KIND_COMMITTED,
        TxnOutcome::RolledBack => OP_KIND_ROLLED_BACK,
    };
    let mut out = Vec::with_capacity(OP_FIXED_LEN + txn_id.len() + 4);
    out.extend_from_slice(&TXN_OP_MAGIC);
    out.push(TXN_FORMAT_VERSION);
    out.push(op_kind);
    out.extend_from_slice(&txn_len.to_le_bytes());
    out.extend_from_slice(&real_offset.to_le_bytes());
    out.extend_from_slice(txn_id);
    let crc = ironbus_core::crc::crc32c(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Some(out)
}

/// Encodes a BACK (back-check bookkeeping) record's metadata blob (#640 part 2): the fixed prefix
/// (magic, version, `txn_id_len`, `attempts`, `next_eligible`), then `txn_id`, then a trailing crc32c.
/// This durably pins a still-`Prepared` txn's back-check schedule + attempt count so they survive a
/// restart. Returns `None` if `txn_id` overflows its `u16` length (unreachable from the bounded wire
/// path).
#[must_use]
pub fn encode_back_meta(txn_id: &[u8], attempts: u32, next_eligible: u64) -> Option<Vec<u8>> {
    let txn_len = u16::try_from(txn_id.len()).ok()?;
    let mut out = Vec::with_capacity(BACK_FIXED_LEN + txn_id.len() + 4);
    out.extend_from_slice(&TXN_BACK_MAGIC);
    out.push(TXN_FORMAT_VERSION);
    out.extend_from_slice(&txn_len.to_le_bytes());
    out.extend_from_slice(&attempts.to_le_bytes());
    out.extend_from_slice(&next_eligible.to_le_bytes());
    out.extend_from_slice(txn_id);
    let crc = ironbus_core::crc::crc32c(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Some(out)
}

/// A decoded HALF record's metadata (the txn id, the real stream, the original flags + the byte range
/// of the original headers within the blob).
struct HalfMeta {
    txn_id: Vec<u8>,
    stream: String,
    orig_flags: RecordFlags,
    orig_headers: Vec<u8>,
}

/// A decoded OP record's metadata.
struct OpMeta {
    txn_id: Vec<u8>,
    outcome: TxnOutcome,
    real_offset: u64,
}

/// A decoded BACK (back-check bookkeeping) record's metadata (#640 part 2).
struct BackMeta {
    txn_id: Vec<u8>,
    attempts: u32,
    next_eligible: u64,
}

/// What a single durable txn record decoded to (or `None` for a foreign / corrupt blob, which is
/// skipped on replay rather than misread).
enum TxnRecordMeta {
    Half(HalfMeta),
    Op(OpMeta),
    Back(BackMeta),
}

/// Reads a little-endian `u16` at `at` as a `usize`, or `None` if `blob` is too short.
fn read_u16(blob: &[u8], at: usize) -> Option<usize> {
    blob.get(at..at + 2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(|b| usize::from(u16::from_le_bytes(b)))
}

/// Reads a little-endian `u64` at `at`, or `None` if `blob` is too short.
fn read_u64(blob: &[u8], at: usize) -> Option<u64> {
    blob.get(at..at + 8)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map(u64::from_le_bytes)
}

/// Validates the trailing crc32c over a txn metadata blob, returning the body (everything before the
/// 4-byte crc) on a match, or `None` on a short blob or a checksum mismatch (a torn or corrupt record
/// is skipped, never misread).
fn verify_crc(blob: &[u8]) -> Option<&[u8]> {
    if blob.len() < 4 {
        return None;
    }
    let crc_at = blob.len() - 4;
    let stored = read_u32_le(blob, crc_at)?;
    if ironbus_core::crc::crc32c(&blob[..crc_at]) != stored {
        return None;
    }
    Some(&blob[..crc_at])
}

/// Reads a little-endian `u32` at `at`, or `None` if `blob` is too short.
fn read_u32_le(blob: &[u8], at: usize) -> Option<u32> {
    blob.get(at..at + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(u32::from_le_bytes)
}

/// Decodes a txn record's metadata `headers` blob to a [`TxnRecordMeta`], or `None` for a foreign or
/// corrupt blob. The version must match [`TXN_FORMAT_VERSION`] (an unknown version fails closed, so a
/// newer record is never silently misread by an older binary), the crc must validate, and every
/// declared length must fit exactly within the blob.
fn decode_meta(blob: &[u8]) -> Option<TxnRecordMeta> {
    let magic = blob.get(0..4)?;
    if magic == TXN_HALF_MAGIC {
        decode_half_meta(blob).map(TxnRecordMeta::Half)
    } else if magic == TXN_OP_MAGIC {
        decode_op_meta(blob).map(TxnRecordMeta::Op)
    } else if magic == TXN_BACK_MAGIC {
        decode_back_meta(blob).map(TxnRecordMeta::Back)
    } else {
        None
    }
}

/// Decodes a HALF record's metadata blob (see [`encode_half_meta`]).
fn decode_half_meta(blob: &[u8]) -> Option<HalfMeta> {
    let body = verify_crc(blob)?;
    if body.len() < HALF_FIXED_LEN {
        return None;
    }
    if *body.get(4)? != TXN_FORMAT_VERSION {
        return None;
    }
    let txn_len = read_u16(body, 5)?;
    let stream_len = read_u16(body, 7)?;
    let headers_len = read_u16(body, 9)?;
    let orig_flags = RecordFlags::from_bits(*body.get(11)?);
    let txn_start = HALF_FIXED_LEN;
    let stream_start = txn_start.checked_add(txn_len)?;
    let headers_start = stream_start.checked_add(stream_len)?;
    let headers_end = headers_start.checked_add(headers_len)?;
    // The body must be EXACTLY the fixed prefix plus the three declared spans: any other length is
    // malformed, so decode fails closed rather than guessing.
    if body.len() != headers_end {
        return None;
    }
    let txn_id = body.get(txn_start..stream_start)?.to_vec();
    let stream = String::from_utf8(body.get(stream_start..headers_start)?.to_vec()).ok()?;
    let orig_headers = body.get(headers_start..headers_end)?.to_vec();
    Some(HalfMeta {
        txn_id,
        stream,
        orig_flags,
        orig_headers,
    })
}

/// Decodes an OP record's metadata blob (see [`encode_op_meta`]).
fn decode_op_meta(blob: &[u8]) -> Option<OpMeta> {
    let body = verify_crc(blob)?;
    if body.len() < OP_FIXED_LEN {
        return None;
    }
    if *body.get(4)? != TXN_FORMAT_VERSION {
        return None;
    }
    let outcome = match *body.get(5)? {
        OP_KIND_COMMITTED => TxnOutcome::Committed,
        OP_KIND_ROLLED_BACK => TxnOutcome::RolledBack,
        // An unknown (future) op kind fails closed rather than being misread.
        _ => return None,
    };
    let txn_len = read_u16(body, 6)?;
    let real_offset = read_u64(body, 8)?;
    let txn_start = OP_FIXED_LEN;
    let txn_end = txn_start.checked_add(txn_len)?;
    if body.len() != txn_end {
        return None;
    }
    let txn_id = body.get(txn_start..txn_end)?.to_vec();
    Some(OpMeta {
        txn_id,
        outcome,
        real_offset,
    })
}

/// Decodes a BACK (back-check bookkeeping) record's metadata blob (#640 part 2, see
/// [`encode_back_meta`]). The version must match [`TXN_FORMAT_VERSION`] (an unknown version fails
/// closed), the crc must validate, and the declared txn-id span must fit exactly within the blob.
fn decode_back_meta(blob: &[u8]) -> Option<BackMeta> {
    let body = verify_crc(blob)?;
    if body.len() < BACK_FIXED_LEN {
        return None;
    }
    if *body.get(4)? != TXN_FORMAT_VERSION {
        return None;
    }
    let txn_len = read_u16(body, 5)?;
    let attempts = read_u32_le(body, 7)?;
    let next_eligible = read_u64(body, 11)?;
    let txn_start = BACK_FIXED_LEN;
    let txn_end = txn_start.checked_add(txn_len)?;
    if body.len() != txn_end {
        return None;
    }
    let txn_id = body.get(txn_start..txn_end)?.to_vec();
    Some(BackMeta {
        txn_id,
        attempts,
        next_eligible,
    })
}

/// The durable transactional half-message store: a segmented [`Log`] under `txn/` holding the half
/// records and op markers, plus the in-memory [`TxnTable`] lifecycle and the buffered prepared
/// payloads, rebuilt at open by replaying the durable records (V2-M8, #640).
pub struct TxnStore<F: Filesystem, C: Clock> {
    log: Log<F, C>,
    /// The pure lifecycle state machine, rebuilt at open from the replayed records.
    table: TxnTable,
    /// The pure back-check schedule + attempt-count book (#640 part 2), rebuilt at open from the
    /// replayed BACK records (clamped against the live clock — see [`TxnStore::replay`]) so the scan
    /// resumes after a restart. EMPTY when no txn is under back-check, so a non-transactional broker
    /// pays nothing.
    back_check: BackCheckBook,
    /// The buffered prepared payloads, keyed by `txn_id`, for every CURRENTLY-`Prepared` txn: the
    /// half message the engine appends to the real stream on a commit. An entry is inserted on a
    /// fresh prepare and removed on resolve (commit OR rollback). Bounded by the table's
    /// `max_prepared` cap (a prepare over the cap is refused), so this never grows without bound.
    prepared_payloads: HashMap<Vec<u8>, HalfMessage>,
    /// The running sum of [`prepared_resident_bytes`] over every CURRENTLY-buffered prepared payload
    /// (#958): kept in lockstep with `prepared_payloads` (added on a fresh half buffer, subtracted on
    /// resolve, recomputed on replay). The engine meters a fresh prepare against the optional
    /// `--max-prepared-bytes` budget using this sum, so the byte budget is an EXACT charge rather than
    /// the worst-case `max_prepared * maximal frame`. Zero whenever no txn is prepared.
    prepared_bytes: u64,
    /// The number of half records durably written across this store's lifetime (for observability).
    half_records: u64,
    /// The number of op markers durably written across this store's lifetime (for observability).
    op_records: u64,
    /// The number of back-check bookkeeping records durably written across this store's lifetime
    /// (#640 part 2, for observability).
    back_records: u64,
}

impl<F: Filesystem, C: Clock> std::fmt::Debug for TxnStore<F, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxnStore")
            .field("prepared", &self.table.prepared_count())
            .field(
                "resolved_tombstones",
                &self.table.resolved_tombstone_count(),
            )
            .field("under_back_check", &self.back_check.len())
            .field("half_records", &self.half_records)
            .field("op_records", &self.op_records)
            .field("back_records", &self.back_records)
            .finish_non_exhaustive()
    }
}

/// A failure committing a transaction at the store layer (the lifecycle errors surface from the pure
/// [`TxnTable`] up through the engine; this is the storage-local typed reject).
#[derive(Debug)]
pub enum TxnStoreError {
    /// A storage error from an append, fsync, or replay.
    Storage(StorageError),
    /// The metadata blob could not be framed (a stream name / headers / txn id longer than
    /// `u16::MAX`, unreachable from the bounded wire path).
    Unframable,
}

impl core::fmt::Display for TxnStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TxnStoreError::Storage(e) => write!(f, "txn store storage error: {e}"),
            TxnStoreError::Unframable => write!(f, "txn record metadata could not be framed"),
        }
    }
}

impl std::error::Error for TxnStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TxnStoreError::Storage(e) => Some(e),
            TxnStoreError::Unframable => None,
        }
    }
}

impl From<StorageError> for TxnStoreError {
    fn from(e: StorageError) -> TxnStoreError {
        TxnStoreError::Storage(e)
    }
}

impl<F: Filesystem, C: Clock> TxnStore<F, C> {
    /// Opens (recovering, or creating fresh) the txn store rooted at the `txn/` subdirectory of
    /// `parent_fs`, rebuilding the in-memory lifecycle table, the buffered prepared payloads, and the
    /// back-check book by replaying the durable half + op + back records in order.
    ///
    /// # Errors
    /// Propagates a storage error from creating the subdirectory, opening the txn log, or scanning
    /// its records.
    pub fn open(
        parent_fs: &F,
        clock: C,
        config: LogConfig,
        txn_config: TxnConfig,
        back_check_config: BackCheckConfig,
    ) -> Result<TxnStore<F, C>, StorageError> {
        let txn_fs = parent_fs.subdir(TXN_SUBDIR).map_err(StorageError::Io)?;
        let log = Log::open(txn_fs, clock, config)?;
        let mut store = TxnStore {
            log,
            table: TxnTable::new(txn_config),
            back_check: BackCheckBook::new(back_check_config),
            prepared_payloads: HashMap::new(),
            prepared_bytes: 0,
            half_records: 0,
            op_records: 0,
            back_records: 0,
        };
        store.replay()?;
        Ok(store)
    }

    /// Whether the `txn/` subdirectory exists under `parent_fs` (a probe that does NOT create it), so
    /// the engine can open the store ONLY when a deployment has ever produced a transactional message
    /// — keeping the non-txn data dir byte-for-byte free of the `txn/` subtree.
    ///
    /// # Errors
    /// Propagates an IO error from the filesystem probe.
    pub fn dir_exists(parent_fs: &F) -> Result<bool, StorageError> {
        parent_fs
            .subdir_exists(TXN_SUBDIR)
            .map_err(StorageError::Io)
    }

    /// Replays every durable txn record in order (the half-log and the op-log are interleaved in the
    /// one `txn/` log), rebuilding the [`TxnTable`] and the buffered-payload map. A HALF record
    /// restores a `Prepared` txn (and buffers its payload); an OP record restores the resolution
    /// (committed / rolled back) and drops the buffered payload. Records are replayed in DURABLE
    /// ORDER (segment id, then offset), so an op marker that follows its half record correctly
    /// supersedes it. A foreign or corrupt record (bad magic, bad crc, unknown version) is SKIPPED,
    /// never misread.
    fn replay(&mut self) -> Result<(), StorageError> {
        self.table = TxnTable::new(self.table.config());
        self.back_check = BackCheckBook::new(self.back_check.config());
        self.prepared_payloads.clear();
        self.prepared_bytes = 0;
        self.half_records = 0;
        self.op_records = 0;
        self.back_records = 0;
        let flushed = self.log.flushed_offset().get();
        if flushed == 0 {
            return Ok(());
        }
        // The durable BACK records carry the LAST persisted attempt count per txn (the op-records are
        // replayed in durable order, so a later BACK record supersedes an earlier one for the same
        // txn). We collect them into `restored_attempts` during the scan and apply them to the book
        // AFTER the half/op replay has settled which txns are still Prepared, so a BACK record for a
        // txn that later resolved (its op-marker followed) is correctly dropped. `next_eligible` is
        // REBASED against the live monotonic clock at open (a persisted absolute monotonic instant is
        // meaningless after a reboot — the monotonic origin resets), so a recovered txn is promptly
        // re-eligible for its next back-check WITHOUT a from-a-previous-boot instant either starving the
        // scan (a far-future value) or storming it: the ATTEMPT COUNT (the terminal-default gate) is
        // what is preserved exactly; the schedule merely resumes.
        let mut restored_attempts: HashMap<Vec<u8>, u32> = HashMap::new();
        let ids = crate::naming::segment_ids(self.log.filesystem()).map_err(StorageError::Io)?;
        for id in ids {
            let scan =
                SegmentReader::open(self.log.filesystem().open(&segment_file_name(id))?)?.scan()?;
            for record in &scan.records {
                if record.offset.get() >= flushed {
                    break;
                }
                let Some(meta) = decode_meta(&record.headers) else {
                    // Foreign / corrupt record: skip it (never misread). The half message it might
                    // have carried is simply absent, which is the safe default (an unrecoverable half
                    // message is treated as never-prepared, not as silently delivered).
                    continue;
                };
                // The durable record's monotonic instant is unavailable on replay (the segment stores
                // only the producer timestamp); the lifecycle's `instant` is used purely for the LRU
                // recency and the back-check age key, so we seed it from the record's offset — a
                // monotonic, replay-stable surrogate that preserves prepare ORDER (the only property
                // the back-check needs). A fresh produce after open uses the real monotonic clock.
                let instant = record.offset.get();
                match meta {
                    TxnRecordMeta::Half(h) => {
                        self.half_records = self.half_records.saturating_add(1);
                        self.table.restore(&h.txn_id, TxnState::Prepared, instant);
                        self.prepared_payloads.insert(
                            h.txn_id.clone(),
                            HalfMessage {
                                txn_id: h.txn_id,
                                stream: h.stream,
                                timestamp_ms: record.timestamp_ms,
                                key: record.key.to_vec(),
                                headers: h.orig_headers,
                                payload: record.payload.to_vec(),
                                flags: h.orig_flags,
                            },
                        );
                    }
                    TxnRecordMeta::Op(o) => {
                        self.op_records = self.op_records.saturating_add(1);
                        self.table
                            .restore(&o.txn_id, TxnState::Resolved(o.outcome), instant);
                        // A resolved txn no longer needs its buffered payload (it was either appended
                        // to the real stream on commit, or discarded on rollback), nor its back-check
                        // bookkeeping (it is settled — never back-check it again).
                        self.prepared_payloads.remove(&o.txn_id);
                        restored_attempts.remove(&o.txn_id);
                        let _ = o.real_offset; // recorded for inspection; the engine dedups the append
                    }
                    TxnRecordMeta::Back(b) => {
                        self.back_records = self.back_records.saturating_add(1);
                        // Record the last persisted attempt count for this txn; a later BACK record (or
                        // an OP record) supersedes it. `next_eligible` from the record is NOT trusted
                        // (rebased below against the live clock), only `attempts`.
                        restored_attempts.insert(b.txn_id, b.attempts);
                        let _ = b.next_eligible;
                    }
                }
            }
        }
        // RE-ENROLL every still-`Prepared` txn into the back-check book, driven off the lifecycle table's
        // `all_prepared()` — NOT the BACK records (#640 part 2, BLOCKER 2 fix). The old loop iterated
        // `restored_attempts` (only txns that had a durable BACK record, written on the FIRST back-check
        // attempt), so a txn that was prepared then survived a restart WITHIN the first timeout window
        // (no attempt yet, so no BACK record) was Prepared but NOT in the book — never scanned, never
        // back-checked, never terminal-defaulted: stuck Prepared (invisible, undelivered) FOREVER, the
        // exact orphan this feature exists to clean up. Driving off `all_prepared()` re-enrolls THAT txn
        // too. The preserved attempt count comes from its BACK record if it had one (the terminal-default
        // gate, kept EXACTLY); a txn with no BACK record enrolls FRESH at 0 attempts. `restore` is
        // idempotent (last write wins on the same id), so there is no double-enroll, and a resolved txn
        // is absent from `all_prepared()` so it is never re-enrolled. The schedule is rebased to "eligible
        // now" via `next_eligible = 0` (the persisted absolute monotonic instant is meaningless after a
        // reboot — the monotonic origin resets), so the engine's first post-open scan (which passes a real
        // monotonic `now` and clamps against it) finds every recovered in-doubt txn promptly due.
        for (txn_id, _prepared_at) in self.table.all_prepared() {
            let attempts = restored_attempts.get(&txn_id).copied().unwrap_or(0);
            self.back_check.restore(&txn_id, attempts, 0);
        }
        // Rebuild the resident-byte sum (#958) from the recovered buffered payloads. Replay never
        // ENFORCES the byte budget — a durable prepared payload is undelivered data that must survive a
        // restart even if the operator later lowered `--max-prepared-bytes` below the recovered total,
        // exactly as replay bypasses the `max_prepared` count cap via `TxnTable::restore` (the budget
        // only refuses FURTHER prepares until the backlog drains).
        self.prepared_bytes = self
            .prepared_payloads
            .values()
            .fold(0u64, |acc, h| acc.saturating_add(h.resident_bytes()));
        Ok(())
    }

    /// Borrows the pure lifecycle table (for the engine's prepare/commit/rollback decisions and the
    /// part-2 back-check's `unresolved_before` scan).
    #[must_use]
    pub fn table(&self) -> &TxnTable {
        &self.table
    }

    /// Mutably borrows the pure lifecycle table (the engine drives prepare/commit/rollback on it).
    pub fn table_mut(&mut self) -> &mut TxnTable {
        &mut self.table
    }

    /// Borrows the pure back-check book (#640 part 2; for the engine's scan `due` query and tests).
    #[must_use]
    pub fn back_check(&self) -> &BackCheckBook {
        &self.back_check
    }

    /// Mutably borrows the pure back-check book (#640 part 2; the engine enrolls/forgets txns and
    /// records attempts on it). A back-check enroll/attempt that must SURVIVE a restart also calls
    /// [`TxnStore::append_back_check`] to durably persist the bookkeeping.
    pub fn back_check_mut(&mut self) -> &mut BackCheckBook {
        &mut self.back_check
    }

    /// The number of currently-enrolled (under-back-check) txns (#640 part 2), for observability and
    /// the scan's hot-path no-op gate.
    #[must_use]
    pub fn under_back_check(&self) -> usize {
        self.back_check.len()
    }

    /// The buffered prepared payload for `txn_id`, or `None` if the txn is not currently prepared
    /// (never prepared, or already resolved). The engine reads this on a commit to append the payload
    /// to the real stream.
    #[must_use]
    pub fn prepared_payload(&self, txn_id: &[u8]) -> Option<&HalfMessage> {
        self.prepared_payloads.get(txn_id)
    }

    /// Durably appends a HALF (prepared) record for `txn_id` — the buffered half message targeting the
    /// real `stream` — and fsyncs it BEFORE returning, then buffers the payload in memory. This is the
    /// durable prepare: after it returns, the half message survives a restart but is INVISIBLE to
    /// consumers (it lives in `txn/`, never the real stream). The caller has already taken a FRESH
    /// prepare decision from [`TxnTable`]; on an idempotent re-prepare the caller does NOT call this
    /// (the half message is already durable).
    ///
    /// # Errors
    /// [`TxnStoreError::Unframable`] if the metadata could not be framed (unreachable from the bounded
    /// wire path), or a storage error from the append or its durability barrier. On any error nothing
    /// is recorded (no in-memory payload buffered), so the caller MUST treat the prepare as not having
    /// happened.
    pub fn append_half(
        &mut self,
        txn_id: &[u8],
        stream: &str,
        message: &Append<'_>,
    ) -> Result<(), TxnStoreError> {
        let meta = encode_half_meta(txn_id, stream, message.flags, message.headers)
            .ok_or(TxnStoreError::Unframable)?;
        // Clear HAS_KEY: the segment codec re-derives it from the key length and overwrites it, so the
        // stored content flags carry only the producer's real content bits (e.g. COMPRESSED), and the
        // original flags for the REAL append are preserved verbatim in the metadata blob instead.
        let stored_flags =
            RecordFlags::from_bits(message.flags.bits() & !RecordFlags::HAS_KEY.bits());
        self.log.append(&Append {
            timestamp_ms: message.timestamp_ms,
            flags: stored_flags,
            key: message.key,
            headers: &meta,
            payload: message.payload,
        })?;
        // fsync the half record BEFORE returning: a prepared half message is never lost.
        self.log.sync()?;
        self.half_records = self.half_records.saturating_add(1);
        let half = HalfMessage {
            txn_id: txn_id.to_vec(),
            stream: stream.to_string(),
            timestamp_ms: message.timestamp_ms,
            key: message.key.to_vec(),
            headers: message.headers.to_vec(),
            payload: message.payload.to_vec(),
            flags: message.flags,
        };
        // Track the resident-byte sum (#958) in lockstep with the buffer insert. The caller (the
        // engine) has ALREADY metered this fresh prepare against the optional `--max-prepared-bytes`
        // budget before reaching here (a re-prepare of a still-prepared id never calls this), so the
        // sum stays under the budget by construction.
        self.prepared_bytes = self.prepared_bytes.saturating_add(half.resident_bytes());
        self.prepared_payloads.insert(txn_id.to_vec(), half);
        Ok(())
    }

    /// The running sum of the buffered prepared payloads' [`prepared_resident_bytes`] (#958), the RAM a
    /// `TxnPrepare` flood currently pins. The engine meters a fresh prepare against the optional
    /// `--max-prepared-bytes` budget with this, and it is a true bound on the term-7 RAM the refuse-to-
    /// boot guard charges (`docs/RAM_BUDGET.md` term 7).
    #[must_use]
    pub fn prepared_bytes(&self) -> u64 {
        self.prepared_bytes
    }

    /// Durably appends a COMMITTED op-marker for `txn_id` (recording the `real_offset` the payload
    /// landed at on the real stream) and fsyncs it BEFORE returning, then drops the buffered payload.
    ///
    /// The CALLER (the engine) MUST have already appended-and-fsync'd the payload to the real stream
    /// BEFORE calling this, and that real append MUST be deduped by the txn id, so a crash AFTER the
    /// real append but BEFORE this op-marker replays the commit exactly once (the re-append is
    /// recognized as a duplicate). See the engine's `txn_commit` for the full crash-window argument.
    ///
    /// # Errors
    /// [`TxnStoreError::Unframable`] (unreachable from the bounded wire path) or a storage error from
    /// the append or its durability barrier.
    pub fn mark_committed(&mut self, txn_id: &[u8], real_offset: u64) -> Result<(), TxnStoreError> {
        self.append_op(txn_id, TxnOutcome::Committed, real_offset)
    }

    /// Durably appends a ROLLED-BACK op-marker for `txn_id` and fsyncs it BEFORE returning, then drops
    /// the buffered payload. The payload is never appended to the real stream — it is discarded.
    ///
    /// # Errors
    /// [`TxnStoreError::Unframable`] (unreachable from the bounded wire path) or a storage error from
    /// the append or its durability barrier.
    pub fn mark_rolled_back(&mut self, txn_id: &[u8]) -> Result<(), TxnStoreError> {
        self.append_op(txn_id, TxnOutcome::RolledBack, 0)
    }

    /// The shared durable op-marker append: frame the marker, append it, fsync it BEFORE returning,
    /// then drop the buffered payload (the txn is resolved). Bumps the op-record count.
    fn append_op(
        &mut self,
        txn_id: &[u8],
        outcome: TxnOutcome,
        real_offset: u64,
    ) -> Result<(), TxnStoreError> {
        let meta = encode_op_meta(txn_id, outcome, real_offset).ok_or(TxnStoreError::Unframable)?;
        self.log.append(&Append {
            timestamp_ms: self.log.now_unix_millis(),
            flags: RecordFlags::EMPTY,
            key: &[],
            headers: &meta,
            payload: &[],
        })?;
        // fsync the op marker BEFORE returning: a resolution, once acked, survives a restart.
        self.log.sync()?;
        self.op_records = self.op_records.saturating_add(1);
        // Drop the buffered payload and release its resident-byte charge (#958), keeping the sum in
        // lockstep with the buffer. A resolve of an id with no buffered payload (an idempotent
        // re-resolve reaching the store, or a payload already dropped) subtracts nothing.
        if let Some(half) = self.prepared_payloads.remove(txn_id) {
            self.prepared_bytes = self.prepared_bytes.saturating_sub(half.resident_bytes());
        }
        Ok(())
    }

    /// Durably appends a BACK (back-check bookkeeping) record for `txn_id` (#640 part 2) recording its
    /// current `attempts` count and `next_eligible` instant, and fsyncs it BEFORE returning, so the
    /// back-check schedule + attempt count SURVIVE a broker restart and the scan resumes. The caller
    /// (the engine) writes this AFTER it bumps the in-memory [`BackCheckBook`] for an issued attempt, so
    /// a crash after the bump but before this append simply re-checks the txn (a safe at-least-once
    /// back-check; the resolution is idempotent), and a crash after this append replays the recorded
    /// attempt count (the terminal-default gate is preserved). It is a NO-OP on the real stream and the
    /// lifecycle — pure bookkeeping — so it never affects delivery.
    ///
    /// `next_eligible` is persisted but treated as advisory on replay: a monotonic instant is rebased
    /// against the live clock at open (see [`TxnStore::replay`]), so only `attempts` is authoritative
    /// across a restart. The append is its own framed, CRC'd, version-tagged record in the same `txn/`
    /// log, interleaved with the half/op records by durable order.
    ///
    /// # Errors
    /// [`TxnStoreError::Unframable`] (unreachable from the bounded wire path) or a storage error from
    /// the append or its durability barrier.
    pub fn append_back_check(
        &mut self,
        txn_id: &[u8],
        attempts: u32,
        next_eligible: u64,
    ) -> Result<(), TxnStoreError> {
        let meta =
            encode_back_meta(txn_id, attempts, next_eligible).ok_or(TxnStoreError::Unframable)?;
        self.log.append(&Append {
            timestamp_ms: self.log.now_unix_millis(),
            flags: RecordFlags::EMPTY,
            key: &[],
            headers: &meta,
            payload: &[],
        })?;
        // fsync the back-check record BEFORE returning: the recorded attempt count survives a restart.
        self.log.sync()?;
        self.back_records = self.back_records.saturating_add(1);
        Ok(())
    }

    /// The number of currently-`Prepared` (unresolved) half messages.
    #[must_use]
    pub fn prepared_count(&self) -> usize {
        self.table.prepared_count()
    }

    /// The number of half records durably written across this store's lifetime (the half records
    /// present at open plus every append since), for observability.
    #[must_use]
    pub fn half_records(&self) -> u64 {
        self.half_records
    }

    /// The number of op markers durably written across this store's lifetime, for observability.
    #[must_use]
    pub fn op_records(&self) -> u64 {
        self.op_records
    }

    /// The number of back-check bookkeeping records durably written across this store's lifetime
    /// (#640 part 2), for observability.
    #[must_use]
    pub fn back_records(&self) -> u64 {
        self.back_records
    }

    /// Borrows the underlying txn log (for inspection and tests).
    #[must_use]
    pub fn log(&self) -> &Log<F, C> {
        &self.log
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use ironbus_core::clock::ManualClock;

    const MAX_ID: usize = ironbus_core::txn::MAX_TXN_ID_LEN;

    fn config() -> LogConfig {
        LogConfig::default()
    }

    fn store(fs: &InMemoryFs) -> TxnStore<InMemoryFs, ManualClock> {
        TxnStore::open(
            fs,
            ManualClock::new(),
            config(),
            TxnConfig::default(),
            BackCheckConfig::default(),
        )
        .unwrap()
    }

    fn half(payload: &[u8]) -> Append<'static> {
        Append {
            timestamp_ms: 1234,
            flags: RecordFlags::EMPTY,
            key: b"k",
            headers: b"orig-hdr",
            payload: Box::leak(payload.to_vec().into_boxed_slice()),
        }
    }

    #[test]
    fn half_meta_round_trips() {
        let blob = encode_half_meta(b"tx1", "orders", RecordFlags::COMPRESSED, b"hh").unwrap();
        assert_eq!(&blob[0..4], &TXN_HALF_MAGIC);
        assert_eq!(blob[4], TXN_FORMAT_VERSION);
        match decode_meta(&blob).unwrap() {
            TxnRecordMeta::Half(h) => {
                assert_eq!(h.txn_id, b"tx1");
                assert_eq!(h.stream, "orders");
                assert_eq!(h.orig_flags, RecordFlags::COMPRESSED);
                assert_eq!(h.orig_headers, b"hh");
            }
            _ => panic!("expected a half record"),
        }
    }

    #[test]
    fn op_meta_round_trips_for_both_outcomes() {
        for (outcome, off) in [(TxnOutcome::Committed, 42u64), (TxnOutcome::RolledBack, 0)] {
            let blob = encode_op_meta(b"tx1", outcome, off).unwrap();
            assert_eq!(&blob[0..4], &TXN_OP_MAGIC);
            match decode_meta(&blob).unwrap() {
                TxnRecordMeta::Op(o) => {
                    assert_eq!(o.txn_id, b"tx1");
                    assert_eq!(o.outcome, outcome);
                    assert_eq!(o.real_offset, off);
                }
                _ => panic!("expected an op record"),
            }
        }
    }

    #[test]
    fn back_meta_round_trips() {
        // #640 part 2: a back-check record carries the txn id, attempt count, and next-eligible instant.
        let blob = encode_back_meta(b"tx1", 3, 0x0102_0304).unwrap();
        assert_eq!(&blob[0..4], &TXN_BACK_MAGIC);
        assert_eq!(blob[4], TXN_FORMAT_VERSION);
        match decode_meta(&blob).unwrap() {
            TxnRecordMeta::Back(b) => {
                assert_eq!(b.txn_id, b"tx1");
                assert_eq!(b.attempts, 3);
                assert_eq!(b.next_eligible, 0x0102_0304);
            }
            _ => panic!("expected a back record"),
        }
    }

    #[test]
    fn the_v1_half_format_is_byte_frozen() {
        // Pin the exact bytes a v1 half-meta produces, so an accidental format drift breaks a test
        // here, not a deployed store. magic + version + lens + flags + spans + crc.
        let blob = encode_half_meta(b"t", "s", RecordFlags::EMPTY, b"h").unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"TXNH");
        expected.push(1); // version
        expected.extend_from_slice(&1u16.to_le_bytes()); // txn_id_len
        expected.extend_from_slice(&1u16.to_le_bytes()); // stream_len
        expected.extend_from_slice(&1u16.to_le_bytes()); // orig_headers_len
        expected.push(0); // orig_flags = EMPTY
        expected.extend_from_slice(b"t");
        expected.extend_from_slice(b"s");
        expected.extend_from_slice(b"h");
        let crc = ironbus_core::crc::crc32c(&expected);
        expected.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(blob, expected);
    }

    #[test]
    fn the_v1_op_format_is_byte_frozen() {
        let blob = encode_op_meta(b"t", TxnOutcome::Committed, 0x0102_0304_0506_0708).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"TXNO");
        expected.push(1); // version
        expected.push(0); // op_kind = committed
        expected.extend_from_slice(&1u16.to_le_bytes()); // txn_id_len
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes()); // real_offset
        expected.extend_from_slice(b"t");
        let crc = ironbus_core::crc::crc32c(&expected);
        expected.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(blob, expected);
    }

    #[test]
    fn decode_rejects_a_corrupt_crc() {
        let mut blob = encode_op_meta(b"tx1", TxnOutcome::Committed, 1).unwrap();
        let n = blob.len();
        blob[n - 5] ^= 0x01; // flip a body byte; the crc no longer matches
        assert!(decode_meta(&blob).is_none());
    }

    #[test]
    fn decode_rejects_an_unknown_version() {
        let mut blob = encode_half_meta(b"t", "s", RecordFlags::EMPTY, b"h").unwrap();
        blob[4] = TXN_FORMAT_VERSION + 1;
        // Re-checksum so only the VERSION (not the crc) is the reason it is rejected.
        let n = blob.len();
        let crc = ironbus_core::crc::crc32c(&blob[..n - 4]);
        blob[n - 4..].copy_from_slice(&crc.to_le_bytes());
        assert!(decode_meta(&blob).is_none());
    }

    #[test]
    fn decode_rejects_a_foreign_or_short_blob() {
        assert!(decode_meta(b"XXXXrest").is_none());
        assert!(decode_meta(b"TXN").is_none());
        assert!(decode_meta(&[]).is_none());
    }

    #[test]
    fn a_prepared_half_is_durable_and_invisible_on_reopen() {
        let fs = InMemoryFs::new();
        {
            let mut s = store(&fs);
            s.table_mut().prepare(b"tx1", 1).unwrap();
            s.append_half(b"tx1", "orders", &half(b"the-payload"))
                .unwrap();
            assert_eq!(s.prepared_count(), 1);
            assert_eq!(s.prepared_payload(b"tx1").unwrap().payload, b"the-payload");
        }
        // Reopen: the prepared half message comes back from the durable record alone.
        let reopened = store(&fs);
        assert_eq!(reopened.prepared_count(), 1);
        let hm = reopened.prepared_payload(b"tx1").unwrap();
        assert_eq!(hm.stream, "orders");
        assert_eq!(hm.payload, b"the-payload");
        assert_eq!(hm.key, b"k");
        assert_eq!(hm.headers, b"orig-hdr");
        assert_eq!(reopened.table().state(b"tx1"), Some(TxnState::Prepared));
    }

    #[test]
    fn prepared_bytes_tracks_the_buffer_and_is_rebuilt_on_replay() {
        // #958: the running resident-byte sum is kept in lockstep with the buffered payloads (added on a
        // fresh half buffer, released on resolve) and RECOMPUTED on replay, so it is a true bound on the
        // term-7 RAM the refuse-to-boot guard charges under the exact byte budget.
        let fs = InMemoryFs::new();
        let tx1_bytes = prepared_resident_bytes(b"tx1", "orders", b"k", b"orig-hdr", b"hello");
        let tx2_bytes = prepared_resident_bytes(b"tx2", "orders", b"k", b"orig-hdr", b"worldwide");
        {
            let mut s = store(&fs);
            assert_eq!(s.prepared_bytes(), 0, "empty store charges nothing");
            s.table_mut().prepare(b"tx1", 1).unwrap();
            s.append_half(b"tx1", "orders", &half(b"hello")).unwrap();
            assert_eq!(
                s.prepared_bytes(),
                tx1_bytes,
                "one buffered half's resident bytes"
            );
            s.table_mut().prepare(b"tx2", 2).unwrap();
            s.append_half(b"tx2", "orders", &half(b"worldwide"))
                .unwrap();
            assert_eq!(
                s.prepared_bytes(),
                tx1_bytes + tx2_bytes,
                "both halves summed"
            );
            // Resolving tx1 releases exactly its bytes; tx2's charge remains.
            s.table_mut().commit(b"tx1", 3).unwrap();
            s.mark_committed(b"tx1", 99).unwrap();
            assert_eq!(
                s.prepared_bytes(),
                tx2_bytes,
                "commit frees exactly tx1's bytes"
            );
        }
        // Replay rebuilds the sum from the recovered buffered payloads (only tx2 is still Prepared).
        let reopened = store(&fs);
        assert_eq!(
            reopened.prepared_bytes(),
            tx2_bytes,
            "replay rebuilds the resident-byte sum from the recovered prepared payloads"
        );
    }

    #[test]
    fn a_committed_txn_survives_restart_as_resolved() {
        let fs = InMemoryFs::new();
        {
            let mut s = store(&fs);
            s.table_mut().prepare(b"tx1", 1).unwrap();
            s.append_half(b"tx1", "orders", &half(b"p")).unwrap();
            // The engine would append to the real stream here; the store records the marker.
            s.table_mut().commit(b"tx1", 2).unwrap();
            s.mark_committed(b"tx1", 99).unwrap();
            assert_eq!(s.prepared_count(), 0);
            assert!(s.prepared_payload(b"tx1").is_none());
        }
        let reopened = store(&fs);
        assert_eq!(reopened.prepared_count(), 0);
        assert_eq!(
            reopened.table().state(b"tx1"),
            Some(TxnState::Resolved(TxnOutcome::Committed))
        );
        // The buffered payload is gone (resolved), so a redrive never re-appends it.
        assert!(reopened.prepared_payload(b"tx1").is_none());
    }

    #[test]
    fn a_rolled_back_txn_survives_restart_and_never_delivers() {
        let fs = InMemoryFs::new();
        {
            let mut s = store(&fs);
            s.table_mut().prepare(b"tx1", 1).unwrap();
            s.append_half(b"tx1", "orders", &half(b"secret")).unwrap();
            s.table_mut().rollback(b"tx1", 2).unwrap();
            s.mark_rolled_back(b"tx1").unwrap();
        }
        let reopened = store(&fs);
        assert_eq!(
            reopened.table().state(b"tx1"),
            Some(TxnState::Resolved(TxnOutcome::RolledBack))
        );
        // The payload was never moved to a real stream and is no longer buffered: never delivered.
        assert!(reopened.prepared_payload(b"tx1").is_none());
    }

    #[test]
    fn crash_after_prepare_before_op_replays_as_prepared() {
        // The crash-window (a) case: only the half record is durable (no op marker). On reopen the
        // txn is Prepared (recoverable, unresolved), so the back-check / redrive can resolve it.
        let fs = InMemoryFs::new();
        {
            let mut s = store(&fs);
            s.table_mut().prepare(b"tx1", 1).unwrap();
            s.append_half(b"tx1", "orders", &half(b"p")).unwrap();
            // CRASH: no commit/rollback op marker written.
        }
        let reopened = store(&fs);
        assert_eq!(reopened.table().state(b"tx1"), Some(TxnState::Prepared));
        assert_eq!(reopened.prepared_count(), 1);
        // The buffered payload is recovered, so the redrive CAN commit it.
        assert_eq!(reopened.prepared_payload(b"tx1").unwrap().payload, b"p");
        // The back-check sees it as unresolved.
        let unresolved = reopened.table().unresolved_before(u64::MAX);
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].0, b"tx1");
    }

    #[test]
    fn replay_applies_op_after_half_in_durable_order() {
        // Multiple txns interleaved: replay order (segment+offset) makes each op marker supersede its
        // half record, so the final state is exactly the resolved/prepared mix.
        let fs = InMemoryFs::new();
        {
            let mut s = store(&fs);
            for id in [b"a".as_slice(), b"b", b"c"] {
                s.table_mut().prepare(id, 1).unwrap();
                s.append_half(id, "s", &half(b"p")).unwrap();
            }
            s.table_mut().commit(b"a", 2).unwrap();
            s.mark_committed(b"a", 10).unwrap();
            s.table_mut().rollback(b"b", 3).unwrap();
            s.mark_rolled_back(b"b").unwrap();
            // c stays prepared.
        }
        let r = store(&fs);
        assert_eq!(
            r.table().state(b"a"),
            Some(TxnState::Resolved(TxnOutcome::Committed))
        );
        assert_eq!(
            r.table().state(b"b"),
            Some(TxnState::Resolved(TxnOutcome::RolledBack))
        );
        assert_eq!(r.table().state(b"c"), Some(TxnState::Prepared));
        assert_eq!(r.prepared_count(), 1);
        assert!(r.prepared_payload(b"c").is_some());
        assert!(r.prepared_payload(b"a").is_none());
    }

    #[test]
    fn an_absent_txn_dir_is_detected_without_creating_it() {
        let fs = InMemoryFs::new();
        // No store opened yet: the txn/ subdir does not exist.
        assert!(!TxnStore::<InMemoryFs, ManualClock>::dir_exists(&fs).unwrap());
        // Probing must not have created it.
        assert!(!TxnStore::<InMemoryFs, ManualClock>::dir_exists(&fs).unwrap());
    }

    #[test]
    fn an_oversized_txn_id_at_the_cap_still_frames() {
        // The store frames a txn id up to MAX_TXN_ID_LEN (the lifecycle table rejects longer ids
        // before the store is ever reached).
        let at_cap = vec![b'z'; MAX_ID];
        let blob = encode_half_meta(&at_cap, "s", RecordFlags::EMPTY, b"").unwrap();
        match decode_meta(&blob).unwrap() {
            TxnRecordMeta::Half(h) => assert_eq!(h.txn_id, at_cap),
            _ => panic!("half expected"),
        }
    }

    #[test]
    fn the_v1_back_format_is_byte_frozen() {
        // #640 part 2: pin the EXACT bytes a v1 back-check record produces, so an accidental format
        // drift breaks a test here, not a deployed store. magic + version + txn_id_len + attempts +
        // next_eligible + txn_id + crc.
        let blob = encode_back_meta(b"t", 0x0203_0405, 0x0607_0809_0a0b_0c0d).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"TXNB");
        expected.push(1); // version
        expected.extend_from_slice(&1u16.to_le_bytes()); // txn_id_len
        expected.extend_from_slice(&0x0203_0405u32.to_le_bytes()); // attempts
        expected.extend_from_slice(&0x0607_0809_0a0b_0c0du64.to_le_bytes()); // next_eligible
        expected.extend_from_slice(b"t");
        let crc = ironbus_core::crc::crc32c(&expected);
        expected.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(blob, expected);
    }

    #[test]
    fn decode_rejects_a_corrupt_back_crc() {
        let mut blob = encode_back_meta(b"tx1", 2, 5).unwrap();
        let n = blob.len();
        blob[n - 5] ^= 0x01; // flip a body byte; the crc no longer matches
        assert!(decode_meta(&blob).is_none());
    }

    /// A store with a deterministic back-check config (retry 50, 3-attempt cap, timeout 0) so a test
    /// can pin the in-memory schedule exactly.
    fn back_store(fs: &InMemoryFs) -> TxnStore<InMemoryFs, ManualClock> {
        TxnStore::open(
            fs,
            ManualClock::new(),
            config(),
            TxnConfig::default(),
            BackCheckConfig {
                timeout: 0,
                retry: 50,
                max_attempts: 3,
                batch: 256,
            },
        )
        .unwrap()
    }

    #[test]
    fn the_back_check_schedule_and_attempt_count_survive_a_restart() {
        // The durability headline (#640 part 2): a back-check record persists the attempt count so it
        // replays after a restart, and the scan resumes (the recovered txn is still Prepared, enrolled,
        // and immediately due on the engine's next scan with its preserved count).
        let fs = InMemoryFs::new();
        {
            let mut s = back_store(&fs);
            s.table_mut().prepare(b"tx1", 1).unwrap();
            s.append_half(b"tx1", "orders", &half(b"p")).unwrap();
            // Enroll + record TWO back-check attempts durably (as the engine's scan would). The
            // in-memory schedule advances by the config retry (50); the durable append persists the
            // matching (attempts, next_eligible) pair.
            s.back_check_mut().enroll(b"tx1", 0);
            s.back_check_mut().record_attempt(b"tx1", 10); // -> (1, 60)
            let (a1, ne1) = s.back_check().bookkeeping(b"tx1").unwrap();
            s.append_back_check(b"tx1", a1, ne1).unwrap();
            assert_eq!((a1, ne1), (1, 60));
            s.back_check_mut().record_attempt(b"tx1", 70); // -> (2, 120)
            let (a2, ne2) = s.back_check().bookkeeping(b"tx1").unwrap();
            s.append_back_check(b"tx1", a2, ne2).unwrap();
            assert_eq!((a2, ne2), (2, 120));
            assert_eq!(s.under_back_check(), 1);
        }
        // Reopen: the txn is still Prepared, the back-check book is rebuilt with the LAST persisted
        // attempt count (2), and it is immediately eligible (next_eligible rebased to 0 against the live
        // clock) so the scan resumes.
        let reopened = back_store(&fs);
        assert_eq!(reopened.table().state(b"tx1"), Some(TxnState::Prepared));
        assert_eq!(reopened.under_back_check(), 1);
        assert_eq!(reopened.back_check().bookkeeping(b"tx1"), Some((2, 0)));
        // It is due on the next scan (eligible at instant 0), and one more attempt (the 3rd, at the cap)
        // fires the terminal default — the count carried across the restart exactly.
        assert_eq!(reopened.back_check().due(0), vec![b"tx1".to_vec()]);
    }

    #[test]
    fn a_resolved_txns_back_check_record_is_dropped_on_replay() {
        // A back-check record for a txn that LATER committed (its op-marker followed in durable order)
        // must NOT re-enroll the resolved txn on replay — it is settled, never back-check it again.
        let fs = InMemoryFs::new();
        {
            let mut s = store(&fs);
            s.table_mut().prepare(b"tx1", 1).unwrap();
            s.append_half(b"tx1", "orders", &half(b"p")).unwrap();
            s.back_check_mut().enroll(b"tx1", 0);
            s.back_check_mut().record_attempt(b"tx1", 10);
            s.append_back_check(b"tx1", 1, 60).unwrap();
            // The producer reconnected and committed: the op-marker supersedes the back-check record.
            s.table_mut().commit(b"tx1", 70).unwrap();
            s.mark_committed(b"tx1", 99).unwrap();
        }
        let reopened = store(&fs);
        assert_eq!(
            reopened.table().state(b"tx1"),
            Some(TxnState::Resolved(TxnOutcome::Committed))
        );
        // No back-check bookkeeping survives for the resolved txn.
        assert_eq!(reopened.under_back_check(), 0);
        assert!(reopened.back_check().bookkeeping(b"tx1").is_none());
    }

    #[test]
    fn a_prepared_txn_with_no_back_record_is_re_enrolled_on_replay() {
        // BLOCKER 2: a txn prepared then left in-doubt across a restart WITHIN the first timeout window
        // (no back-check attempt fired, so NO durable BACK record) must STILL be re-enrolled into the
        // book on replay — driven off `all_prepared()`, not the BACK records. Before the fix the replay
        // rebuilt the book only from BACK records, so this txn would be Prepared but NOT under back-check
        // (orphaned forever). It must re-enroll FRESH at 0 attempts and be immediately due.
        let fs = InMemoryFs::new();
        {
            let mut s = back_store(&fs);
            s.table_mut().prepare(b"tx1", 1).unwrap();
            s.append_half(b"tx1", "orders", &half(b"p")).unwrap();
            // Enroll in memory only (as `txn_prepare` does) — but NEVER record_attempt, so NO BACK
            // record is appended. This is the prepare-then-restart-before-first-attempt orphan.
            s.back_check_mut().enroll(b"tx1", 0);
            assert_eq!(s.under_back_check(), 1);
        }
        // Reopen: the half is still Prepared AND re-enrolled fresh at 0 attempts, immediately due — the
        // scan will back-check it and, unanswered, terminal-default it. Never stuck.
        let reopened = back_store(&fs);
        assert_eq!(reopened.table().state(b"tx1"), Some(TxnState::Prepared));
        assert_eq!(
            reopened.under_back_check(),
            1,
            "the no-BACK-record prepared txn was re-enrolled off all_prepared(), not orphaned"
        );
        assert_eq!(
            reopened.back_check().bookkeeping(b"tx1"),
            Some((0, 0)),
            "re-enrolled fresh at 0 attempts, immediately eligible"
        );
        assert_eq!(reopened.back_check().due(0), vec![b"tx1".to_vec()]);
    }
}
