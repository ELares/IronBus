// SPDX-License-Identifier: MIT OR Apache-2.0
//! The single durable, ordered log: open or recover a data directory, append records,
//! roll to new segments by size, and survive a crash with a consistent prefix.
//!
//! [`Log::open`] recovers the active segment (truncating any torn or unsynced tail) or
//! starts a fresh one, treating a crash that left the highest segment sealed as a roll
//! to continue past. [`Log::append`] assigns each record its monotonic log offset and
//! sequence number, rolling to the next segment once the active one reaches the
//! configured size; [`Log::sync`] makes the appended records durable. The read path is
//! separate later work.

use crate::cold::{
    cold_object_name, ColdEntry, ColdManifest, ColdStorageConfig, ColdStore, COLD_MANIFEST_FILE,
};
use crate::fs::Filesystem;
use crate::io::{InMemoryFile, RandomAccessFile};
use crate::loss::{LossEvent, LossReport, ReasonCode};
use crate::naming::{segment_file_name, segment_ids};
use crate::read_plane::{ReadPlane, SealedSegment};
use crate::segment::{
    OwnedRecord, RawByteRun, RecoveryScan, SegmentReader, SegmentWriter, StorageError,
};
use bytes::Bytes;
use ironbus_core::clock::Clock;
use ironbus_core::codec::{BodyChecksums, RecordView};
use ironbus_core::format::{
    RECORD_HEADER_LEN, RECORD_TRAILER_LEN, SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN,
};
use ironbus_core::segment::SegmentHeader;
use ironbus_core::types::{Offset, RecordFlags, Seq};
use std::sync::Arc;

/// The id of the first segment in a fresh log.
const FIRST_SEGMENT_ID: u64 = 0;

/// Tunables for a [`Log`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogConfig {
    /// Soft cap on a segment's TOTAL byte size, the 64-byte header included (it is compared
    /// against the write position, which starts at the header). The active segment is sealed
    /// and a new one started before the first append that would begin at or beyond this size,
    /// so a segment may exceed it by at most the last record. An empty segment is never
    /// rolled, so a record larger than the cap still gets written (to its own segment).
    ///
    /// Prefer [`LogConfig::new`], which rejects a cap below
    /// [`LogConfig::MIN_MAX_SEGMENT_BYTES`]. Setting this field directly to `0` or any value
    /// below that floor is a footgun: a segment could not hold more than one record, so the
    /// log fragments into one-record segments with no diagnostic.
    pub max_segment_bytes: u64,

    /// Hard cap on the log's TOTAL durable RECORD bytes across every segment: the same
    /// quantity recovery sums as `durable_bytes` (per segment, `valid_end - SEGMENT_HEADER_LEN`,
    /// so the segment headers and footers are excluded). This is the shed backstop of the
    /// overflow policy: when the log is at or over this cap, [`Log::append`] rejects a produce
    /// with [`StorageError::AtCapacity`] and writes nothing, so a produce never silently drops
    /// and never hangs indefinitely. The check is at-or-over BEFORE the append (like
    /// `max_segment_bytes`), so the log may exceed the cap by at most the last record. A record
    /// on an EMPTY log is always written, so an oversized first record is not wedged out.
    ///
    /// HONEST-ACCOUNTING NOTE (#493): this cap counts ONLY the framed record region. It does NOT
    /// count the per-segment headers (64 B) and footers (32 B), the per-segment index cache, the
    /// in-memory image, or a disk backend's per-active-segment preallocation (`max_segment_bytes`,
    /// 64 MiB by default). So the log's true RESIDENT/disk footprint runs ABOVE this cap — up to
    /// ~`1.85x` on small records (where the fixed 44-byte record framing dominates) and higher
    /// still with preallocation. The basis is INTENTIONALLY left at the record region: it is the
    /// only term that retention/reap decrements in O(1), and the parallel resident terms (the
    /// in-memory 2x image is dropping to 1x in #492; disk preallocation is backend-specific) would
    /// poison a single basis. To size a real memory or disk budget, read the HONEST live resident
    /// estimate [`Log::resident_bytes_estimate`] and the per-backend multiplier table in
    /// `docs/CONFIG.md`; do NOT assume `bytes_on_disk == max_total_bytes`.
    ///
    /// `0` means UNLIMITED (the cap is off), which is the default and preserves the historical
    /// spill-by-default behavior: an operator opts in to the cap. The rejection is non-fatal
    /// and does not freeze the writer (see [`StorageError::AtCapacity`]); once retention frees
    /// space (#13), a later produce succeeds.
    pub max_total_bytes: u64,

    /// Total byte budget for the forensic QUARANTINE store (#134): the capped, copy-not-move
    /// capture of the corrupt bytes a recovery corruption skip dropped, kept under `quarantine/`
    /// for offline analysis. When a capture would push the store over this, it evicts OLDEST blobs
    /// first (FIFO) to make room; a single corrupt span larger than the whole budget is skipped, so
    /// the forensic copy can never exhaust a small edge disk.
    ///
    /// `0` means UNLIMITED (the budget is off), matching the `0`-as-off convention of the other
    /// byte caps; [`LogConfig::DEFAULT_MAX_QUARANTINE_BYTES`] (256 MiB) is the finite default. The
    /// store is purely best-effort and forensic: this never affects what recovery recovers, and a
    /// quarantine failure never fails [`Log::open`]. The percentage-aware ceiling the issue
    /// describes (`min(256 MiB, 5% of the data-directory filesystem)`) is computed by the server at
    /// config time, since the IO-free storage core cannot stat the host filesystem (refs #134).
    pub max_quarantine_bytes: u64,

    /// OPT-IN daily PHYSICAL write budget in bytes (#118): a flash-wear governor. When set and the
    /// physical bytes actually written to segments SO FAR TODAY (the encoded record frames plus the
    /// segment headers and footers, the same volume [`Log::physical_bytes_written`] charges, measured
    /// against the clock seam's UTC day) reach this budget, [`Log::append`] sheds the next produce
    /// with the DISTINCT, FINAL [`StorageError::DailyWriteBudgetExceeded`] error. The shed is a clean
    /// PRE-WRITE drop-new reject (the engine counts it as `produce_rejected`, like the byte-cap drop)
    /// AND it is FINAL: it is a SEPARATE variant from the byte-cap [`StorageError::AtCapacity`] so a
    /// `DropOldest` reap can never relieve it (no reap lowers today's physical-write meter), so it
    /// NEVER triggers the force-reap loop under any overflow policy. The over-budget event is surfaced
    /// by [`Log::daily_budget_sheds`]. It NEVER weakens durability: an over-budget produce is DROPPED,
    /// never written unsynced. The today-counter resets at the UTC day boundary
    /// (`now_unix_millis / 86_400_000`), so the budget refreshes each day with no background timer.
    ///
    /// `0` means UNSET (the governor is OFF), the default, so existing behavior is byte-for-byte
    /// unchanged: an operator opts in. A budget smaller than a single record still admits the FIRST
    /// write of the day (the append-on-empty rule that keeps an oversized first record from wedging
    /// the log applies here too), so the broker always makes some daily progress.
    pub daily_physical_write_budget_bytes: u64,
}

impl LogConfig {
    /// The frozen v1 default segment size, 64 MiB.
    pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

    /// The default total byte budget for the forensic quarantine store (#134), 256 MiB: the upper
    /// half of the issue's `min(256 MiB, 5% of FS)` ceiling. A finite default so a forensic copy
    /// is bounded out of the box; an operator can lower it (for a tiny edge disk) or set `0` to
    /// disable the cap entirely.
    pub const DEFAULT_MAX_QUARANTINE_BYTES: u64 = 256 * 1024 * 1024;

    /// The smallest sane `max_segment_bytes`: the segment header and footer plus room for at
    /// least two minimum-size records, so a segment can always hold more than one record. A
    /// cap below this fragments the log into one-record segments and is rejected by
    /// [`LogConfig::new`].
    pub const MIN_MAX_SEGMENT_BYTES: u64 =
        (SEGMENT_HEADER_LEN + SEGMENT_FOOTER_LEN + 2 * (RECORD_HEADER_LEN + RECORD_TRAILER_LEN))
            as u64;

    /// Builds a [`LogConfig`], rejecting a `max_segment_bytes` below
    /// [`LogConfig::MIN_MAX_SEGMENT_BYTES`]. This is the validating path that keeps a
    /// degenerate cap (`0`, or a sub-header value) from silently fragmenting the log. The
    /// durable-log byte cap (`max_total_bytes`) is left UNLIMITED (`0`); set it with
    /// [`LogConfig::with_max_total_bytes`].
    ///
    /// # Errors
    /// Returns [`LogConfigError::MaxSegmentBytesTooSmall`] if `max_segment_bytes` is below the
    /// floor.
    pub fn new(max_segment_bytes: u64) -> Result<LogConfig, LogConfigError> {
        if max_segment_bytes < LogConfig::MIN_MAX_SEGMENT_BYTES {
            return Err(LogConfigError::MaxSegmentBytesTooSmall {
                value: max_segment_bytes,
                floor: LogConfig::MIN_MAX_SEGMENT_BYTES,
            });
        }
        Ok(LogConfig {
            max_segment_bytes,
            max_total_bytes: 0,
            max_quarantine_bytes: LogConfig::DEFAULT_MAX_QUARANTINE_BYTES,
            // The daily physical write budget is OFF by default; an operator opts in (#118).
            daily_physical_write_budget_bytes: 0,
        })
    }

    /// Sets the forensic quarantine byte budget ([`LogConfig::max_quarantine_bytes`]) and returns
    /// the updated config. `0` disables the cap (unlimited). Most callers keep the default; this is
    /// for an operator who wants a smaller forensic budget on a tiny edge disk, or none at all.
    #[must_use]
    pub fn with_max_quarantine_bytes(mut self, max_quarantine_bytes: u64) -> LogConfig {
        self.max_quarantine_bytes = max_quarantine_bytes;
        self
    }

    /// Sets the hard durable-log byte cap (`max_total_bytes`) and returns the updated config.
    /// `0` is accepted and means UNLIMITED (the cap is off). Any non-zero value opts in to the
    /// drop-new shed: an at-or-over-cap produce is rejected with [`StorageError::AtCapacity`].
    /// See [`LogConfig::max_total_bytes`] for the exact accounting and at-or-over semantics, and
    /// note (#493) that the cap counts only the framed record region — to size a real disk/RAM
    /// budget use [`Log::resident_bytes_estimate`] and the `docs/CONFIG.md` multiplier.
    #[must_use]
    pub fn with_max_total_bytes(mut self, max_total_bytes: u64) -> LogConfig {
        self.max_total_bytes = max_total_bytes;
        self
    }

    /// Sets the OPT-IN daily physical write budget ([`LogConfig::daily_physical_write_budget_bytes`])
    /// and returns the updated config. `0` (the default) disables the governor; any non-zero value
    /// opts in: once today's physical write volume reaches the budget, an append is shed with the
    /// distinct, FINAL [`StorageError::DailyWriteBudgetExceeded`] (a clean pre-write drop-new reject
    /// that no reap can relieve) rather than weakening durability, and the over-budget shed is counted
    /// by [`Log::daily_budget_sheds`].
    #[must_use]
    pub fn with_daily_physical_write_budget_bytes(mut self, budget: u64) -> LogConfig {
        self.daily_physical_write_budget_bytes = budget;
        self
    }
}

/// An invalid [`LogConfig`] rejected by [`LogConfig::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogConfigError {
    /// `max_segment_bytes` is below [`LogConfig::MIN_MAX_SEGMENT_BYTES`]: a cap so small a
    /// segment could not hold more than one record.
    MaxSegmentBytesTooSmall {
        /// The rejected value.
        value: u64,
        /// The smallest accepted value.
        floor: u64,
    },
}

impl std::fmt::Display for LogConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogConfigError::MaxSegmentBytesTooSmall { value, floor } => write!(
                f,
                "max_segment_bytes {value} is below the minimum {floor} (smaller caps make \
                 one-record segments)"
            ),
        }
    }
}

impl std::error::Error for LogConfigError {}

impl Default for LogConfig {
    fn default() -> LogConfig {
        LogConfig {
            max_segment_bytes: LogConfig::DEFAULT_MAX_SEGMENT_BYTES,
            // Unlimited durable-log byte cap by default: spill-by-default behavior is
            // unchanged, an operator opts in to the shed.
            max_total_bytes: 0,
            // A finite forensic quarantine budget by default, so a corrupt-byte copy is bounded
            // out of the box (#134).
            max_quarantine_bytes: LogConfig::DEFAULT_MAX_QUARANTINE_BYTES,
            // The daily physical write budget is OFF by default (#118): existing behavior is
            // unchanged unless an operator opts in to the flash-wear governor.
            daily_physical_write_budget_bytes: 0,
        }
    }
}

/// A record to append: the producer-supplied content. The log assigns the sequence
/// number and the log offset, and the codec derives the `HAS_KEY` flag from `key`.
#[derive(Clone, Copy, Debug)]
pub struct Append<'a> {
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Record flags, excluding `HAS_KEY` (the codec derives that from `key`).
    pub flags: RecordFlags,
    /// The routing or ordering key (empty if none).
    pub key: &'a [u8],
    /// The record headers blob (empty if none).
    pub headers: &'a [u8],
    /// The record payload.
    pub payload: &'a [u8],
}

/// How [`Log::append_inner`] lays one record into the active segment: RE-ENCODE a producer-supplied
/// [`Append`] into a fresh canonical frame (the produce path), or copy a PRE-VALIDATED verbatim frame
/// the follower already CRC-checked on ingest (#820). Both share the identical cap / daily-budget /
/// roll prologue, id reservation, seek-index maintenance, and write-amplification accounting — only
/// the per-record write into the segment writer differs, so the on-disk bytes are identical either way.
#[derive(Clone, Copy)]
enum AppendSource<'a> {
    /// Re-frame the record through the codec (via [`SegmentWriter::append`] /
    /// [`SegmentWriter::append_precomputed`]). `precomputed` carries the body checksums computed OFF
    /// the single-writer actor on the producing connection thread (issue #830) when present, so the
    /// actor skips the serialized body CRC32C/xxh3 pass; `None` computes them on the append path
    /// exactly as before. Either way the on-disk frame is byte-identical.
    Encode {
        record: &'a Append<'a>,
        precomputed: Option<BodyChecksums>,
        /// The stored SUBJECT for this record (#594), or EMPTY for a plain publish. Carried
        /// alongside the record (rather than on [`Append`]) so every existing produce path is
        /// byte-for-byte unchanged and only the by-subject produce threads a non-empty value; it
        /// routes to the subject-storing codec path in `write_source`.
        subject: &'a [u8],
        /// The stored STREAM TAG for this record (#597, the shared-WAL demux key), or EMPTY for a
        /// per-stream-log / default produce. Carried like `subject` so every existing produce path is
        /// byte-for-byte unchanged and only the shared-WAL append threads a non-empty value; it routes
        /// to the tag-storing codec path in `write_source`. Mutually exclusive with `subject`.
        stream_tag: &'a [u8],
    },
    /// Copy an already-sealed, already-validated frame verbatim (via
    /// [`SegmentWriter::append_verbatim`]), skipping the redundant re-encode + re-checksum. `frame`
    /// is one complete on-disk record frame the caller decoded in place; `view` is that decode's
    /// result. The caller GUARANTEES `view.seq` equals the log's positional `next_seq`, so the copied
    /// bytes are byte-identical to what the `Encode` path would have produced (a debug assert checks it).
    Verbatim {
        frame: &'a [u8],
        view: &'a RecordView<'a>,
    },
}

/// The three composable retention bounds the segment reaper enforces (refs #13, #80). A sealed
/// segment is eligible to delete when ANY ENABLED bound says it should be (the log is over the
/// byte bound, OR over the count bound, OR the segment is older than the age bound); each bound is
/// independently disabled by setting it to `0`, and all three at `0` is the default (retention
/// OFF, nothing reaped). Eligibility never overrides consumer-safety: the reaper still deletes
/// only whole sealed segments entirely below the protect floor, oldest first, never the active
/// segment (see [`Log::reap`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionBounds {
    /// Delete oldest sealed segments while the log's total durable RECORD bytes exceed this. `0`
    /// means UNLIMITED (the byte bound is off). This is the bound [`Log::reap_to_size`] enforces.
    pub max_bytes: u64,
    /// Delete a sealed segment whose MAXIMUM record timestamp is older than `now - max_age_ms`,
    /// i.e. EVERY record in it is older than this many milliseconds. The max (not the min) is used
    /// so a segment is deleted only once ALL its records have aged out. `0` means DISABLED. `now`
    /// comes from the log's clock seam, so the deterministic simulation drives it.
    pub max_age_ms: u64,
    /// Delete oldest sealed segments while the log's total durable RECORD COUNT exceeds this. `0`
    /// means DISABLED.
    pub max_messages: u64,
}

/// What a reap pass ([`Log::reap`] or [`Log::reap_to_size`]) reclaimed: how many whole sealed
/// segments it unlinked and the total durable RECORD bytes those segments held (the same quantity
/// [`Log::durable_record_bytes`] dropped by). Both are zero when nothing was reaped (every bound
/// is off, the log is already under them, or the oldest sealed segment is still needed by a
/// consumer).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReapOutcome {
    /// The number of whole sealed segments unlinked this pass.
    pub segments_reaped: u64,
    /// The total durable RECORD bytes those reaped segments held (each segment's
    /// `valid_end - SEGMENT_HEADER_LEN`, the same per-segment term the sealed-bytes total
    /// accumulates), so the caller can confirm `durable_record_bytes()` dropped by exactly this.
    pub bytes_reaped: u64,
}

/// What a [`Log::truncate_to`] dropped: the typed, REPORTED result of a leader-epoch divergence
/// truncation (C2-I4, #599). A divergence truncation is NEVER silent — the caller surfaces this as a
/// divergence event / metric (the beat over NATS #5576, where a divergent replica returns with no
/// data and never reconciles). Distinct from a [`crate::loss::LossReport`] event (which records
/// CORRUPTION / torn-tail loss): this is an INTENTIONAL, correct reconciliation of a divergent
/// suffix against the new leader's lineage, not data corruption — so it is reported separately and
/// does not count against the I3 corruption-loss caps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TruncateOutcome {
    /// The offset the log was truncated TO: records `[truncated_to, next_offset_before)` were
    /// dropped, records `[earliest, truncated_to)` (the common prefix) were kept untouched.
    pub truncated_to: u64,
    /// The log's `next_offset` BEFORE the truncation (so the dropped offset range is
    /// `[truncated_to, next_offset_before)`).
    pub next_offset_before: u64,
    /// How many records were dropped (`next_offset_before - truncated_to`). Zero when the target was
    /// already at the durable head (a clean no-op — the follower simply fetches forward).
    pub records_dropped: u64,
    /// The durable RECORD bytes the truncation reclaimed (the on-disk record bytes of the dropped
    /// suffix, the same per-segment term [`Log::durable_record_bytes`] is defined over).
    pub bytes_dropped: u64,
    /// How many whole segment FILES were unlinked (the dropped suffix may span several sealed
    /// segments above the truncation point).
    pub segments_dropped: u64,
}

/// An in-memory directory entry: a segment id, the log offset of its first record, and the
/// per-segment retention metadata the reaper consults without rescanning the file. Held sorted
/// by `base_offset` (which is monotonic with the id) so a read can binary search for the segment
/// that holds a given offset.
///
/// `record_count` and `max_timestamp_ms` are populated when a segment is SEALED on a roll (from
/// the active writer's running totals) and recomputed at recovery from the streaming scan, so the
/// count- and time-retention bounds are O(1) to evaluate per sealed segment.
#[derive(Clone, Copy, Debug)]
struct SegmentSlot {
    id: u64,
    base_offset: u64,
    /// How many records this segment holds. Meaningful for a SEALED segment (set on its roll or
    /// at recovery); the active segment's live count is read from the writer, so the slot's value
    /// for the active segment is `0` until it is sealed. For a COMPACTED segment this is the
    /// SURVIVOR count (sparse), NOT the covered count.
    record_count: u64,
    /// The maximum producer timestamp (milliseconds since the Unix epoch) across this segment's
    /// records, or `0` if it is empty. Tracked as the MAX (producer timestamps are not monotonic)
    /// so the age-retention reaper deletes a segment only when ALL its records are older than the
    /// bound. Meaningful for a SEALED segment, like `record_count`.
    max_timestamp_ms: u64,
    /// For a COMPACTED (v2) segment (#337): the covered range `[covered_base_offset,
    /// covered_end_offset)` of the ORIGINAL source set this segment supersedes (the SPARSE survivor
    /// offsets within are a subset of `[base_offset, covered_end_offset)`). `None` for an ordinary
    /// segment, whose actual range is the dense `[base_offset, base_offset + record_count)`. A read
    /// against a compacted slot routes through the v2 scan and skips absent offsets.
    compacted_covered: Option<CompactedCover>,
}

/// The covered offset/sequence span a COMPACTED segment declares in its v2 metadata block (#337):
/// the source set's true range, used by recovery to abut the chain and to identify a superseded
/// original. A compacted segment's records are sparse WITHIN this range.
// The `covered_` prefix mirrors the on-disk v2 block field names (CONTRACTS.md) on purpose, so the
// struct reads 1:1 against the byte layout; the shared prefix is intentional, not noise.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug)]
struct CompactedCover {
    covered_base_offset: u64,
    covered_end_offset: u64,
    covered_base_seq: u64,
    covered_end_seq: u64,
}

impl SegmentSlot {
    /// The lowest covered offset of this segment: for a COMPACTED segment its true
    /// `covered_base_offset` (which may be BELOW the lowest survivor's `base_offset`), for an
    /// ordinary segment `base_offset`. Used by the read path and the reaper so a compacted hole's
    /// offsets resolve to the segment that supersedes them.
    fn covered_base_offset(&self) -> u64 {
        match self.compacted_covered {
            Some(c) => c.covered_base_offset,
            None => self.base_offset,
        }
    }
}

/// One ORDINARY (v1) segment discovered during compaction-aware recovery (#337): its recovered
/// scan facts, used to reconcile against the compacted segments and then build the chain.
struct OrdinaryCandidate {
    id: u64,
    base_offset: u64,
    base_seq: u64,
    record_count: u64,
    max_timestamp_ms: u64,
    valid_end: u64,
    sealed: bool,
    file_len: u64,
    tail_reason: Option<ReasonCode>,
    last_seq: Seq,
    header: SegmentHeader,
}

/// One COMPACTED (v2) segment discovered during compaction-aware recovery (#337): its survivor
/// facts plus the covered source range from its v2 metadata block, used to supersede the originals
/// it replaced and to abut the chain by covered range.
struct CompactedCandidate {
    id: u64,
    record_count: u64,
    max_timestamp_ms: u64,
    cover: CompactedCover,
    valid_end: u64,
}

/// The validated segment chain `Log::recover` rebuilds from a streaming scan of every segment:
/// the in-memory slots (with their per-segment retention metadata), the running totals the live
/// log tracks (durable record bytes and count), the next base offset and sequence past the prefix,
/// and the highest segment's scan (the active segment, unless a seal-only crash rolls it forward).
struct RecoveredChain {
    slots: Vec<SegmentSlot>,
    next_base_offset: u64,
    next_base_seq: u64,
    /// Total durable record-region bytes across the recovered prefix, for the I3 global loss cap.
    durable_bytes: u64,
    /// Total durable record COUNT across the recovered prefix: the running count-retention total.
    total_record_count: u64,
    /// The highest segment's recovery scan (always present: `recover` is only called non-empty).
    highest: RecoveryScan,
}

/// The byte stride between [`SegmentIndex`] anchors (#537): one sparse anchor per this many bytes of
/// frame data, Kafka's `.index` default interval. It bounds a resident dense-segment index's RAM to
/// `O(region_bytes / stride)` (independent of the record count) and the per-read forward scan from
/// an anchor to `stride` bytes. 4 KiB on an 8 MiB edge segment is ~2048 anchors ≈ 32 KiB resident
/// (vs ~1.86 MiB for a dense one-entry-per-36-byte-record index), well inside the tiny-profile RAM
/// budget while keeping the bounded scan tiny (~114 minimum-size frames). NOT an on-disk constant:
/// the index is in-memory only, rebuilt from the durable frames on reopen, so changing it is a pure
/// memory/latency trade with no format or recovery impact.
const SEGMENT_INDEX_STRIDE_BYTES: u64 = 4096;

/// The RESIDENT, in-memory `offset -> byte position` seek index for ONE open DENSE (v1) segment
/// (#483, sparsified by #537). It lets [`Log::read_from`] SEEK to a record's frame in near-O(1)
/// (an anchor lookup plus a bounded forward scan) instead of rescanning the segment from its base on
/// every delivery (the consume hot path reads `read_from(off, 1)` per record, so the old scan made
/// each delivery O(records-per-segment)).
///
/// `anchors[i] = (offset_i, byte_pos_i)` is a SPARSE anchor: the frame START byte position of the
/// record at log offset `offset_i`, ascending by offset. The index is SPARSE — Kafka's `.index`
/// design (#537) — holding ONE anchor per [`SEGMENT_INDEX_STRIDE_BYTES`] bytes of frame data rather
/// than one per record, so its RAM is `O(region_bytes / stride)` REGARDLESS of how many small
/// records the segment packs. The pre-#537 DENSE index held one `u64` per record: a fully-packed
/// 8 MiB edge segment of 36-byte frames is ~233k records = ~1.86 MiB of index, UNACCOUNTED in the
/// RAM budget and scaling with the record count and the read working set (replay/follower reads pin
/// many sealed segments resident). The sparse index is a small bounded constant (~32 KiB for that
/// same 8 MiB segment at a 4 KiB stride), so a slow/replaying consumer's resident footprint stays
/// inside the tiny-profile budget (see `docs/RAM_BUDGET.md`).
///
/// A read SEEKS to [`SegmentIndex::seek_anchor`]'s anchor at or before the target offset and scans
/// FORWARD at most `stride` bytes (a bounded frame count) to reach the exact record, so the consume
/// locate is O(stride) — a small constant — instead of the pre-#483 O(records-per-segment) full
/// rescan. `base_offset` is the segment's lowest offset (always anchored, so any in-range offset has
/// an anchor at or before it). `valid_end` is the byte offset at which the durable record region
/// ends (a sealed segment's footer start, or the active segment's torn-free prefix end), so a
/// seek-and-read-forward never reads past the valid prefix into a torn tail.
///
/// RESIDENT-ONLY by design: built once when a segment is first consulted on the read path (or seeded
/// from the active segment as it appends), kept while the segment is open, and DROPPED the instant
/// the segment is retired (reaped, force-reaped, or superseded by compaction) so a recycled slot can
/// never seek with a stale index, and so RAM is bounded to the working set of segments actually
/// being read. It is NEVER persisted: a reopen rebuilds it from the durable frames.
///
/// COMPACTED (v2, sparse) segments are NOT indexed here: their survivors are sparse and the read
/// path already routes them through the v2 scan, which this change leaves untouched.
#[derive(Clone, Debug)]
struct SegmentIndex {
    /// The lowest log offset this segment holds (the segment's `base_offset`): always the first
    /// anchor's offset, so any in-range offset resolves to an anchor at or before it.
    base_offset: u64,
    /// The SPARSE `(offset, frame START byte position)` anchors, ascending by offset: one per
    /// `stride` bytes of frame data, NOT one per record (#537).
    anchors: Vec<(u64, u64)>,
    /// How many records this index covers: the covered offset range is `[base_offset, base_offset +
    /// record_count)`. Tracked separately from `anchors.len()` because the index is SPARSE (far
    /// fewer anchors than records). A read targeting an offset at or past `base_offset +
    /// record_count` is in the not-yet-indexed tail, so the seek returns `None`.
    record_count: u64,
    /// The frame byte stride between anchors: at most this many bytes separate consecutive anchors,
    /// so a read forward-scans at most this far from an anchor to the target. Echoed from
    /// [`SEGMENT_INDEX_STRIDE_BYTES`] (or set per-test); kept on the index so the append-extend path
    /// uses the SAME stride the build used.
    stride: u64,
    /// The next byte position at or past which the next appended frame is anchored (the active
    /// segment's running anchor boundary): advances by `stride` each time an anchor is taken, so the
    /// append-seeded index stays byte-identical to a rebuild.
    next_anchor_at: u64,
    /// The byte offset at which the valid record region ends: the read-forward upper bound, so a
    /// seek never materializes a frame from beyond the durable prefix (a torn tail or a footer). For
    /// the active segment this tracks the appended prefix (`write_pos`), which may include the
    /// writer's not-yet-flushed PENDING bytes; reads are bounded by `flushed_end` (below), never this.
    valid_end: u64,
    /// The byte offset at which the FLUSHED (in-file) prefix ends: the safe read-forward upper bound
    /// for the ACTIVE segment, since appended-but-pending bytes are not yet in the file (#452, #537).
    /// Set to `valid_end` whenever the log raises the visible head (`sync`/`flush_no_sync`, which
    /// flush pending to the file first), so every record below `flushed_offset` is guaranteed in the
    /// file up to here. For a SEALED segment this equals `valid_end` (the whole region is durable).
    flushed_end: u64,
}

impl SegmentIndex {
    /// The SEEK target for log offset `offset`: the `(anchor offset, anchor byte position)` of the
    /// nearest anchor AT OR BEFORE `offset`, so the caller seeks to the anchor byte position, reads
    /// forward, and skips the (at most `stride`-bytes' worth of) records before `offset`. `None`
    /// when `offset` is below the base or at/past the last covered offset (the caller then has no
    /// in-range anchor to seek to and falls back to a full scan).
    ///
    /// `covered_end` is the first offset this index does NOT cover (the active segment's not-yet-
    /// indexed tail begins here), so a target at or beyond it returns `None` rather than seeking to
    /// the last anchor and reading a partially-indexed region.
    fn seek_anchor(&self, offset: u64, covered_end: u64) -> Option<(u64, u64)> {
        if offset < self.base_offset || offset >= covered_end {
            return None;
        }
        // The anchors ascend by offset; find the last one whose offset is <= `offset`.
        let idx = self
            .anchors
            .partition_point(|&(anchor_off, _)| anchor_off <= offset);
        idx.checked_sub(1)
            .and_then(|i| self.anchors.get(i))
            .copied()
    }

    /// The first log offset this index does NOT yet cover (`base_offset + record_count`): the offset
    /// the next appended record to the active segment will carry, used to EXTEND the active
    /// segment's index and to bound [`SegmentIndex::seek_anchor`]'s covered range.
    fn covered_end(&self) -> u64 {
        self.base_offset.saturating_add(self.record_count)
    }

    /// The WINDOW-BOUNDED read-end (#664): the byte position past which a read that wants the
    /// records in `[from_offset, from_offset + want_records)` need not look. A seek-and-scan-forward
    /// reads `[anchor_byte, read_end)` into one buffer up front; before #664 `read_end` was the
    /// SEGMENT-WIDE `flushed_end`, so a forward streaming drain read `O(distance-to-segment-end)`
    /// bytes per fetch and was `O(N^2)` overall. This bounds the read to the FIRST sparse anchor
    /// STRICTLY ABOVE the last wanted offset (`from_offset + want_records`): every wanted record lies
    /// below that anchor's byte position, so the read covers the window plus at most one extra stride
    /// of slack — `O(want + stride)` bytes, INDEPENDENT of how far `from_offset` sits from the
    /// segment end. When no anchor lies above the window (the window reaches the indexed tail) the
    /// bound is the full `flushed_end`, exactly the pre-#664 behavior for that (final) window.
    ///
    /// `want_records == 0` (or a `want` that overflows) falls back to `flushed_end`: the caller
    /// returns nothing anyway, and a conservative (larger) read-end is always correct — it only ever
    /// reads MORE bytes, never wrong ones (the per-record `max`/`flushed` filters still bound the
    /// returned run). The result is clamped to `flushed_end`, so a window-bounded read never reaches
    /// past the durable, in-file prefix.
    fn window_read_end(&self, from_offset: u64, want_records: usize, flushed_end: u64) -> u64 {
        let want = want_records as u64;
        if want == 0 {
            return flushed_end;
        }
        // The first offset PAST the window. Saturating: an enormous `want` (e.g. `usize::MAX`)
        // resolves to `u64::MAX`, for which no anchor is strictly above => the bound is `flushed_end`
        // (the whole prefix), correctly degrading to "read to the end" for an unbounded fetch.
        let window_end = from_offset.saturating_add(want);
        // The first anchor whose OFFSET is strictly greater than `window_end`. Its byte position is a
        // safe upper bound: every record with offset `< window_end` has its frame entirely below it
        // (anchors mark frame STARTS, ascending). `partition_point` is O(log anchors).
        let idx = self
            .anchors
            .partition_point(|&(anchor_off, _)| anchor_off <= window_end);
        let bound = self
            .anchors
            .get(idx)
            .map_or(flushed_end, |&(_, byte_pos)| byte_pos);
        bound.min(flushed_end)
    }
}

/// The RESIDENT, in-memory SPARSE seek index for ONE open COMPACTED (v2) segment (#481). It is the
/// compacted analogue of [`SegmentIndex`]: where the dense index keys a contiguous offset run by
/// array position, a compacted segment's survivors are SPARSE (compaction leaves holes: an offset
/// may be absent, #337), so this index holds an explicit `(offset, byte position)` entry per
/// survivor, sorted ascending by offset. It lets [`Log::read_from`] SEEK to the first survivor at or
/// above a requested `start` via a binary search and read forward up to `max` records, instead of
/// re-reading the WHOLE survivor region into a `Vec` and decoding EVERY survivor on every poll (the
/// pre-#481 behavior, which made a slow/replaying consumer — the one that reads compacted segments
/// most — pay O(survivors) + a whole-region alloc per delivery).
///
/// `entries[i] = (offset_i, byte_pos_i)` where `byte_pos_i` is the file byte offset of survivor
/// `offset_i`'s frame; `valid_end` is the byte offset at which the survivor region ends (the footer
/// start), the read-forward upper bound so a seek never decodes the trailing footer/compaction
/// block as a record. A requested offset that falls in a compaction HOLE resolves (by the binary
/// search) to the NEXT present survivor, so the read advances over the gap exactly as the full scan
/// did — absent offsets simply have no entry.
///
/// RESIDENT-ONLY, identical lifecycle to the dense index: built once when the compacted segment is
/// first consulted on the read path, kept while it is open, and DROPPED the instant the segment is
/// retired (reaped, force-reaped, or — never, for a compacted segment, since it is itself the
/// compaction product — superseded) by the SAME [`Log::evict_segment_index`] that drops a dense
/// index, so a recycled slot can never seek with a stale index and RAM stays bounded to the working
/// set. NEVER persisted: a reopen rebuilds it from the durable frames.
#[derive(Clone, Debug)]
struct CompactedIndex {
    /// Each survivor's `(original sparse log offset, frame START byte position)`, ascending by
    /// offset. Sparse: there is NO entry for a compacted-away (hole) offset.
    entries: Vec<(u64, u64)>,
    /// The byte offset at which the survivor record region ends (the footer start): the
    /// read-forward upper bound, so a seek never materializes the trailing footer/compaction block.
    valid_end: u64,
}

impl CompactedIndex {
    /// The frame byte position of the FIRST survivor whose offset is at or above `start`, if any.
    /// A `start` that lands on a present survivor returns that survivor; a `start` in a compaction
    /// HOLE (or below the lowest survivor) returns the next present survivor, so the read advances
    /// over the gap; a `start` past the last survivor returns `None` (nothing left to seek to).
    fn seek_at_or_after(&self, start: u64) -> Option<u64> {
        let idx = self.entries.partition_point(|&(offset, _)| offset < start);
        self.entries.get(idx).map(|&(_, byte_pos)| byte_pos)
    }
}

/// The default number of opened SEALED-segment readers the through-actor `Log` keeps resident (#808).
/// Each entry is one fd + a validated header; the cache is FIFO-bounded so a retention-off cold full
/// scan opens-and-reuses a working set instead of leaking one fd per sealed segment. 256 sits well under
/// a typical 1024 `RLIMIT_NOFILE`, leaving room for the active writer fd plus sockets.
const DEFAULT_SEALED_READER_CACHE_CAP: usize = 256;

/// A small FIFO-bounded cache of opened [`SegmentReader`]s keyed by SEALED segment id (#808), used by the
/// through-actor `Log` read path so a repeated `read_from` over a hot sealed segment does ONE
/// open+fstat+header-CRC, not one per read. The active (growing) segment is NEVER cached. Interior
/// mutability (the read path is `&self`), single-writer / never aliased across threads — the same
/// rationale as `segment_indexes`. Holds only derived data: dropping or rebuilding an entry changes
/// nothing a reader observes (same bytes, same per-record CRC), it only re-pays the open. Entries are
/// evicted at segment retirement via [`Log::evict_segment_index`]; segment ids are never recycled
/// (ADR 0002), so a cached fd can never alias a different physical segment.
struct SealedReaderCache<F: Filesystem> {
    readers:
        std::cell::RefCell<std::collections::HashMap<u64, std::sync::Arc<SegmentReader<F::File>>>>,
    /// Insertion order of the resident ids, so the cache sheds the OLDEST opened reader when it hits its
    /// cap — a bound on resident fds, not a correctness device (any victim is safe to re-open).
    fifo: std::cell::RefCell<std::collections::VecDeque<u64>>,
    cap: usize,
}

impl<F: Filesystem> SealedReaderCache<F> {
    fn new(cap: usize) -> SealedReaderCache<F> {
        SealedReaderCache {
            readers: std::cell::RefCell::new(std::collections::HashMap::new()),
            fifo: std::cell::RefCell::new(std::collections::VecDeque::new()),
            cap,
        }
    }

    fn get(&self, id: u64) -> Option<std::sync::Arc<SegmentReader<F::File>>> {
        self.readers.borrow().get(&id).cloned()
    }

    fn insert(&self, id: u64, reader: std::sync::Arc<SegmentReader<F::File>>) {
        let mut readers = self.readers.borrow_mut();
        if !readers.contains_key(&id) {
            let mut fifo = self.fifo.borrow_mut();
            while fifo.len() >= self.cap {
                match fifo.pop_front() {
                    Some(evicted) => {
                        readers.remove(&evicted);
                    }
                    None => break,
                }
            }
            fifo.push_back(id);
        }
        readers.insert(id, reader);
    }

    fn evict(&self, id: u64) {
        if self.readers.borrow_mut().remove(&id).is_some() {
            self.fifo.borrow_mut().retain(|&x| x != id);
        }
    }
}

impl<F: Filesystem> std::fmt::Debug for SealedReaderCache<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedReaderCache")
            .field("resident", &self.readers.borrow().len())
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

/// A single durable, ordered log backed by one data directory of segment files.
///
/// One active segment receives appends; sealed predecessors hold the older records.
/// Offsets and sequence numbers are monotonic and never reused. The log is
/// single-writer: one owner appends. The concurrent append actor and lock-free readers
/// are layered on later.
#[derive(Debug)]
pub struct Log<F: Filesystem, C: Clock> {
    fs: F,
    clock: C,
    config: LogConfig,
    /// The active segment writer. `None` only after a fatal error froze the writer.
    active: Option<SegmentWriter<F::File>>,
    active_id: u64,
    next_offset: Offset,
    next_seq: Seq,
    /// The read-visibility (flushed) high-water mark: reads are bounded by this, so a reader
    /// never observes a record at or beyond it. Under the default `sync` level it equals
    /// `synced_offset` (every visible record is also durable, I2); under a relaxed level it may
    /// run AHEAD of `synced_offset` by the unsynced window (a `flush_no_sync` raises this without
    /// the covering fsync).
    flushed_offset: Offset,
    /// The DURABLE high-water mark: the first offset NOT yet covered by a returned `fdatasync`
    /// (#341, #379). Advanced only by a real durability barrier: [`Log::sync`], a roll's seal (which
    /// fsyncs every record in the sealed segment), and recovery (everything recovered is durable).
    /// A `flush_no_sync` does NOT advance it, so under a relaxed level the records in
    /// `[synced_offset, flushed_offset)` are exactly the acked-but-not-durable tail a power loss
    /// would revert. Equal to `flushed_offset` whenever the writer is fully synced. Exposed by
    /// [`Log::synced_offset`] for the engine's worst-case-loss accounting.
    synced_offset: Offset,
    /// Every segment in the log, sorted by base offset, for offset-to-segment lookup.
    segments: Vec<SegmentSlot>,
    /// Total durable RECORD bytes (per segment, `write_pos - SEGMENT_HEADER_LEN`) across every
    /// SEALED predecessor, the same quantity recovery sums as `durable_bytes`. The live total
    /// is this plus the active segment's record bytes; tracking it here keeps the durable-log
    /// byte cap check O(1) per append instead of an O(segments) scan. Updated on each roll.
    sealed_record_bytes: u64,
    /// Total durable RECORD COUNT across EVERY segment (sealed predecessors plus the active one),
    /// maintained the way `sealed_record_bytes` is but covering the active segment too:
    /// initialized at recovery, incremented on each append, and decremented by a reaped segment's
    /// count on a reap. Keeps the count-retention bound O(1) to check instead of an O(segments)
    /// scan. Exposed by [`Log::durable_record_count`].
    total_record_count: u64,
    /// Bytes dropped from a torn or unsynced active-segment tail at recovery: the silent
    /// loss that recovery truncates to reach the last intact record. Bounded at one past the
    /// tail's last NON-ZERO byte (`crate::io::last_nonzero_end`): the never-written zeros of a
    /// preallocated logical extension past that bound are truncated too but were never data, so
    /// they are not counted. Zero for a fresh log, a clean recovery, or an all-zero tail.
    recovered_truncated_bytes: u64,
    /// The structured, versioned report of what recovery dropped (#120): the same loss as
    /// `recovered_truncated_bytes`, but as per-segment events carrying the byte span and the
    /// reason. Empty for a fresh log or a clean recovery.
    loss_report: LossReport,
    /// The PERSISTED on-disk footprint of the forensic quarantine store (#134, #315): the total
    /// bytes of the corruption-skip blobs `quarantine/` currently holds, seeded at open from a
    /// one-time read-only scan of the durable blobs (so it SURVIVES a restart and reflects real disk
    /// pressure even when this recovery had no new corruption skip) and advanced by any new capture
    /// this recovery makes. Zero only when the quarantine dir is absent, empty, or unreadable.
    /// Best-effort: the scan and any capture are read-only/forensic and never fail the open, so a
    /// quarantine error leaves this at most stale, never blocking recovery. Exposed for the
    /// `ironbus_quarantine_bytes` gauge.
    quarantined_bytes: u64,
    /// The total LOGICAL bytes this log instance has appended since it was opened (#118): the sum of
    /// each appended record's user payload (key + headers + payload), EXCLUDING all framing. The
    /// numerator-free denominator of the flash write-amplification ratio: "the bytes the application
    /// asked us to store". Process-lifetime monotonic (it counts every append this run, never
    /// decremented by a reap), so it pairs with [`Log::physical_bytes_written`] to give a stable
    /// write-amp ratio. Seeded to `0` on open (a fresh run starts the amplification window fresh);
    /// it is an observability rate signal, not a durable total. Saturating. Exposed for the
    /// `ironbus_logical_bytes_written` counter.
    logical_bytes_written: u64,
    /// The total PHYSICAL bytes this log instance has actually appended to segment files since it
    /// was opened (#118): every record FRAME (header + body + trailer, the encoded length the
    /// segment writer advanced its write position by), PLUS every segment HEADER stamped on a
    /// `start_segment` and every segment FOOTER written on a `seal`. This is the real on-disk write
    /// volume an SSD/eMMC wear model cares about, so `physical / logical` is the flash
    /// write-amplification ratio. Process-lifetime monotonic (a reap frees disk but does not un-write
    /// the bytes a wear counter already charged), so it never decreases even as retention reclaims
    /// segments. Seeded to `0` on open. Saturating. Exposed for the `ironbus_physical_bytes_written`
    /// counter and the derived `ironbus_write_amp_ratio` gauge.
    physical_bytes_written: u64,
    /// The physical bytes written SO FAR on the current UTC day (#118): the daily-write-budget
    /// accumulator. Charged the same encoded-frame / segment-header / segment-footer volume as
    /// `physical_bytes_written`, but RESET to zero at each UTC day boundary so the budget refreshes
    /// daily. Exposed for the `ironbus_physical_bytes_written_today` gauge. Always tracked (cheap),
    /// even when no budget is configured, so the accounting is visible without enabling the shed.
    physical_bytes_written_today: u64,
    /// The UTC day index (`now_unix_millis / 86_400_000`) the `physical_bytes_written_today` total
    /// belongs to (#118). When an append observes a different day on the clock seam, the today-total
    /// is rolled over to zero before the new write is charged, so the daily budget is measured per
    /// UTC day against the deterministic clock seam (no background timer).
    physical_write_today_day: u64,
    /// The count of appends SHED because the daily physical write budget was reached (#118): the
    /// over-budget signal an operator alerts on, distinct from the byte-cap `produce_rejected` (this
    /// is the flash-wear governor firing, not a disk-full shed). Process-lifetime monotonic, never
    /// reset on a day rollover. Exposed for the `ironbus_daily_write_budget_sheds_total` counter.
    daily_budget_sheds: u64,
    /// The UNSYNCED record-byte exposure (#341, #379): the logical record bytes (key + headers +
    /// payload, no framing) appended since the last real durability barrier (`sync` or a roll's seal).
    /// Accumulated on each [`Log::append`] and RESET to zero by [`Log::sync`] and [`Log::roll`] (the
    /// barriers that make the unsynced records durable). It is `0` whenever the writer is fully synced
    /// (so always `0` under the default `sync` level). Under a relaxed level it is the live
    /// bytes-at-risk a power cut would lose, the `interval` byte-trigger input and the engine's
    /// loss-exposure gauge. Saturating; a `flush_no_sync` does NOT reset it (those records are visible
    /// but not yet durable). Exposed by [`Log::unsynced_bytes`].
    unsynced_record_bytes: u64,
    /// The RESIDENT, per-OPEN-segment `offset -> byte position` seek index keyed by segment id
    /// (#483): the cache that turns [`Log::read_from`] from an O(records-per-segment) base rescan
    /// into an O(1) seek-and-read-forward on the consume hot path. A DENSE (v1) segment's entry is
    /// built lazily the first time the read path consults it (or seeded for the active segment),
    /// EXTENDED in lockstep as the active segment appends, and EVICTED the instant the segment is
    /// retired (reap, force-reap, compaction install) so a recycled segment id never seeks with a
    /// stale index. Resident-only: never persisted (a reopen rebuilds it) and bounded to the
    /// working set of open segments, not a permanent dense vector for every cold sealed segment.
    /// COMPACTED (v2, sparse) segments are absent here (they keep the v2 scan read path).
    ///
    /// Interior mutability: a `read_from(&self)` lazily builds and caches an entry, so the cache
    /// sits behind a `RefCell`. The log is single-writer with no shared reader yet (the doc on
    /// [`Log`] notes the lock-free readers are layered later), so the cell is never aliased across
    /// threads; when the concurrent read path lands it replaces this with the appropriate shared
    /// structure. The cell holds only derived data: dropping or rebuilding it changes nothing a
    /// reader observes (same records, same CRC validation), it only re-pays the build cost.
    segment_indexes: std::cell::RefCell<std::collections::HashMap<u64, SegmentIndex>>,
    /// The RESIDENT, per-OPEN-COMPACTED-segment SPARSE seek index keyed by segment id (#481): the
    /// compacted analogue of `segment_indexes`. It turns [`Log::read_from`]'s compacted branch from
    /// an O(survivors) whole-region re-read-and-decode on every poll into a binary-search SEEK to the
    /// first survivor at or above `start` plus an O(`max`) read-forward. Built lazily the first time
    /// the read path reads a compacted slot, and EVICTED by the SAME [`Log::evict_segment_index`]
    /// retirement path (reap, force-reap, compaction install) that drops a dense index, so a stale
    /// sparse index can never outlive its segment. Resident-only: never persisted (a reopen rebuilds
    /// it) and bounded to the working set of open compacted segments. DENSE (v1) segments are absent
    /// here (they use `segment_indexes`); the two maps never hold the same id.
    ///
    /// Same interior-mutability rationale as `segment_indexes`: a `read_from(&self)` lazily builds
    /// and caches an entry behind a `RefCell`, holding only derived data (dropping or rebuilding it
    /// changes nothing a reader observes — same survivors, same CRC validation).
    compacted_indexes: std::cell::RefCell<std::collections::HashMap<u64, CompactedIndex>>,
    /// The resident, FIFO-bounded cache of OPENED sealed-segment readers (#808): the through-actor read
    /// path (e.g. the Tier-W per-record poll, which reads `read_from(off, 1)` per delivered message)
    /// reuses one opened `SegmentReader` per sealed segment instead of re-opening (open+fstat+header-CRC)
    /// on every read. The active segment is never cached (it grows); evicted in lockstep with the seek
    /// index by [`Log::evict_segment_index`] at retirement.
    sealed_readers: SealedReaderCache<F>,
    /// The lock-free, off-actor consume READ plane (#539): the shared atomic flushed frontier plus
    /// the arc-swapped immutable snapshot of the SEALED segments + their seek anchors, which any
    /// number of reader threads observe with NO lock and NO append-actor round-trip. The single
    /// writer (this `Log`, owned by the append actor) PUBLISHES to it: the new flushed frontier
    /// after every `sync`/`flush_no_sync`/`roll`, and a fresh sealed snapshot when a roll seals a
    /// segment or a reap retires one.
    ///
    /// Built LAZILY on the first [`Log::read_plane`] (which needs `F: Clone` to put the filesystem
    /// handle behind an `Arc` for cross-thread readers), and cached behind a `RefCell` so the
    /// `&self` build and the `&mut self` publish hooks can both reach it. `None` until a consumer
    /// first asks for the plane — a single-writer log that is never read off-actor (e.g. the
    /// `FaultFs`-backed durability tests, whose `F` is not `Clone`) never builds it and pays
    /// nothing. The cell holds only derived state: the snapshot is rebuilt from `self.segments`, so
    /// dropping or rebuilding it changes nothing a reader observes.
    read_plane: std::cell::RefCell<Option<ReadPlane<F>>>,
    /// A roll that SEALED the predecessor but could not yet CREATE the next active segment, because
    /// `start_segment` hit a transient resource fault (EMFILE from fd exhaustion, a short ENOSPC a
    /// reap will clear, EINTR) at the roll boundary (#867). The seal is durable, so no data is lost;
    /// the next write retries the deferred creation via [`ensure_writable`](Log::ensure_writable), so
    /// a recoverable fault no longer permanently freezes the writer. `None` in steady state: the only
    /// thing that sets it is a failed `start_segment` during a roll, and the next successful create
    /// clears it. While it is `Some`, `active` is `None` but the writer is RESUMABLE, not frozen.
    pending_roll: Option<PendingRoll>,
    /// The durable per-log COLD-SEGMENT MANIFEST (#643, tiered storage): the record of which sealed
    /// segments have been offloaded to the [`ColdStore`] and are now REMOTE (their local file may be
    /// absent), plus the metadata a recovery/read needs. `None` until the first offload creates
    /// `cold-manifest.ckpt`, OR — after a restart of a log that DID offload — opened at [`Log::open`]
    /// from the existing file so recovery treats an offloaded segment as PRESENT, not a torn gap. A
    /// log that never offloads has this `None` and a byte-for-byte unchanged data directory.
    cold_manifest: Option<ColdManifest<F::File>>,
    /// The [`ColdStore`] backend used to upload (offload), fetch (restore-on-read), and delete
    /// (reap) remote segments (#643). Injected post-open via [`Log::set_cold_store`] (the engine
    /// constructs a per-log-rooted backend), mirroring how compaction config is applied post-open.
    /// `None` disables offload and makes a read of an already-offloaded segment fail closed with
    /// [`StorageError::ColdStoreUnavailable`] until the operator re-attaches the backend.
    cold_store: Option<Arc<dyn ColdStore>>,
    /// The tiered-storage policy (#643): disabled by default (the log never offloads and writes no
    /// new bytes). Set alongside the backend by [`Log::set_cold_store`].
    cold_config: ColdStorageConfig,
}

/// A deferred active-segment creation: a [`Log::roll`] sealed the old segment but a transient fault
/// stopped it from creating the next one, so the create is retried on the next write (#867). The
/// fields are exactly the arguments [`Log::start_segment`] needs to finish the roll.
#[derive(Clone, Copy, Debug)]
struct PendingRoll {
    /// The id of the not-yet-created next active segment.
    id: u64,
    /// Its base sequence (continues the sealed predecessor's run).
    base_seq: Seq,
    /// Its base offset (continues the sealed predecessor's run).
    base_offset: Offset,
}

/// A STAGED, not-yet-covered durability barrier for the pipelined sync tier (#1040): the snapshot
/// [`Log::prepare_async_sync`] takes at the dirty-at-sync-start boundary, applied by
/// [`Log::complete_async_sync`] once the EXTERNAL `fdatasync` on the shared file handle has
/// RETURNED successfully. Everything appended AFTER the stage is deliberately outside this
/// ticket: it stays in the unsynced window and is covered by the NEXT barrier, which is what lets
/// the caller overlap one in-flight fdatasync with further appends on the same fd without ever
/// advertising an uncovered byte as durable. Opaque outside this module: the engine and the
/// append actor carry it between `prepare` and `complete` without reading it.
#[derive(Clone, Copy, Debug)]
pub struct SyncTicket {
    /// The offset the durable head advances TO when this barrier completes: `next_offset` at
    /// stage time. Bytes appended during the flight are never credited to this ticket.
    target: Offset,
    /// The active segment id at stage time: guards the resident seek-index raise across a roll
    /// (a completion must never touch a DIFFERENT segment's index; after a roll the seal already
    /// raised the sealed index to its full prefix).
    segment_id: u64,
    /// The resident active index `valid_end` at stage time, AFTER the stage's flush put every
    /// staged byte in the file (#537): the exact in-file prefix this barrier covers, so the
    /// completion raises the index's `flushed_end` to THIS snapshot — never the then-current
    /// `valid_end`, whose tail may still sit in the writer's pending buffer.
    staged_valid_end: u64,
    /// The unsynced record-byte exposure at stage time: exactly the bytes this barrier covers,
    /// subtracted (saturating) from the live meter on completion so records appended during the
    /// flight keep their at-risk accounting until their own barrier returns.
    covered_bytes: u64,
}

/// What [`Log::prepare_async_sync`] stages for a DIRTIED log (#1040): the SHARED active-segment
/// fd the external `fdatasync` runs on, paired with the [`SyncTicket`] to apply on completion.
/// `None` = the log is CLEAN (no barrier owed) — distinct by construction from a FROZEN writer,
/// which is an `Err`, never a clean `None`.
pub type StagedSync<F> = Option<(Arc<F>, SyncTicket)>;

/// The bounds of a single [`Log::read_range`] pass, threaded to the per-segment read helpers so
/// they share one definition of the start, the durable end, and the record/byte caps (#538).
struct ReadBounds {
    /// The requested start log offset.
    start_v: u64,
    /// The flushed (durable) end: no record at or past this is ever returned.
    flushed: u64,
    /// The maximum record COUNT to return across the whole read.
    max: usize,
    /// The optional cap on total ENCODED frame bytes across the whole read (`None` = uncapped).
    max_bytes: Option<usize>,
}

/// The peak number of concurrent [`Log::open`] recoveries a multi-stream / multi-partition boot
/// runs across (#822): the OUTER, cross-subtree recovery width. Each inner `Log::open` SEPARATELY
/// bounds its own per-segment scan to [`Log::RECOVERY_SCAN_MAX_WORKERS`] (#817), so the peak live
/// thread count is at most `RECOVERY_OPEN_MAX_WORKERS * RECOVERY_SCAN_MAX_WORKERS` — a CONSTANT,
/// INDEPENDENT of the stream/partition/segment counts on disk. So `streams * partitions * segments`
/// recovery work never explodes into that many threads: both levels are bounded worker sets, never
/// one-thread-per-item.
pub(crate) const RECOVERY_OPEN_MAX_WORKERS: usize = 8;

/// Runs `open` for every item across a bounded [`std::thread::scope`] worker set, returning one
/// result per item in the SAME order as `items` (index-aligned to it), regardless of the order the
/// workers finished. This is the OUTER, cross-subtree half of recovery (#822): each item is an
/// independent, byte-isolated stream/partition subtree, so opening them is embarrassingly parallel;
/// the caller then folds the index-aligned results into its `BTreeMap` / `Vec` in deterministic
/// key/index order, byte-for-byte identical to the strictly serial open (including WHICH item's
/// error surfaces first — the caller `?`-propagates in item order).
///
/// Mirrors [`Log::par_scan_segments`] (the INNER per-segment pattern): a fixed set of scoped workers
/// steals items off one shared atomic cursor, so a fast subtree's worker immediately picks up the
/// next item rather than blocking on a slow one. Helpers are spawned FALLIBLY via
/// `Builder::spawn_scoped` and the MAIN thread is itself the final participant, so a cold-boot OS
/// thread exhaustion degrades to fewer helpers (or fully serial) instead of panicking. No external
/// threadpool (no rayon). The effective width is `min(max_workers, cores, items)`; a single item
/// (or a single-worker cap) runs inline with no threads spawned — so the common single-log
/// deployment (one default stream, `count == 1`) opens on the calling thread exactly as before.
pub(crate) fn par_recover_open<W, T, S>(
    items: &[W],
    max_workers: usize,
    open: S,
) -> Vec<Result<T, StorageError>>
where
    W: Sync,
    T: Send,
    S: Fn(&W) -> Result<T, StorageError> + Send + Sync,
{
    let total = items.len();
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(max_workers)
        .min(total);
    if workers <= 1 {
        // One subtree, one core, or a single-worker cap: run inline, no threads, no cursor.
        return items.iter().map(&open).collect();
    }
    let cursor = std::sync::atomic::AtomicUsize::new(0);
    // Each participant returns the (index, result) pairs it computed; we reassemble by index so the
    // returned order is item order no matter who won which item. Helpers are spawned FALLIBLY via
    // `Builder::spawn_scoped`: if a worker thread cannot be created (OS thread exhaustion on a cold
    // boot) we simply run with fewer helpers, and the main thread is itself the final participant —
    // so even if EVERY helper fails to spawn, every index is still opened inline. Recovery therefore
    // degrades to serial rather than panicking, matching the resilience this boot path demands.
    let collected: Vec<(usize, Result<T, StorageError>)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers.saturating_sub(1))
            .filter_map(|k| {
                let cursor = &cursor;
                let open = &open;
                std::thread::Builder::new()
                    .name(format!("ib-recover-open-{k}"))
                    .spawn_scoped(s, move || {
                        let mut local: Vec<(usize, Result<T, StorageError>)> = Vec::new();
                        loop {
                            let i = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if i >= total {
                                break;
                            }
                            local.push((i, open(&items[i])));
                        }
                        local
                    })
                    .ok()
            })
            .collect();
        // The main thread is the final participant: drain whatever indices remain (this alone covers
        // 0..total if no helper spawned).
        let mut all: Vec<(usize, Result<T, StorageError>)> = Vec::with_capacity(total);
        loop {
            let i = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if i >= total {
                break;
            }
            all.push((i, open(&items[i])));
        }
        for h in handles {
            all.extend(h.join().expect("recovery open worker panicked"));
        }
        all
    });
    let mut slots: Vec<Option<Result<T, StorageError>>> = (0..total).map(|_| None).collect();
    for (i, r) in collected {
        slots[i] = Some(r);
    }
    // Every index in 0..total is assigned exactly once (the cursor hands each out once), so no slot
    // is None here.
    slots
        .into_iter()
        .map(|r| r.expect("every recovery open index was assigned"))
        .collect()
}

/// The upper bound on the number of covering `fdatasync` barriers ONE group-commit tick fans out
/// concurrently (#823). Same shape as [`RECOVERY_OPEN_MAX_WORKERS`]: a small fixed cap keeps the
/// barrier fan-out from ever spawning one-thread-per-dirtied-fd on a wide (K = hundreds) tick, while
/// still overlapping the blocking syscalls; the effective width is `min(this, cores, K)`.
pub(crate) const COMMIT_BARRIER_MAX_WORKERS: usize = 8;

/// Fans out the K per-fd covering `fdatasync` barriers of ONE group-commit tick
/// ([`crate::streamset::StreamSet::commit_tick`] / [`crate::partitioned::PartitionedStream::commit_tick`])
/// across a bounded [`std::thread::scope`] worker set, so the tick's barrier phase costs
/// `max(barrier)` instead of `sum(barrier)` (#823). Each dirtied partition/stream is its OWN [`Log`]
/// over its own segment set, so its covering `fdatasync` is on an INDEPENDENT fd and the K barriers
/// are embarrassingly parallel; the kernel cannot batch `fdatasync` across fds, but the barriers can
/// OVERLAP in wall time. Returns one `(tag, barrier result)` per input; the returned order is NOT
/// input order (results come back in completion order), so the caller reassembles by `tag`.
///
/// Mirrors [`par_recover_open`] / [`Log::par_scan_segments`]: a fixed set of scoped workers steals the
/// `(tag, &mut Log)` barriers off one shared queue, so a fast fd's worker immediately picks up the
/// next barrier rather than blocking behind a slow one; helpers are spawned FALLIBLY via
/// `Builder::spawn_scoped` and the MAIN thread is itself the final participant, so OS thread
/// exhaustion degrades to fewer helpers (or fully serial) instead of panicking. No external threadpool
/// (no rayon). The effective width is `min(COMMIT_BARRIER_MAX_WORKERS, cores, K)`; a single dirtied fd
/// (the common `P = 1` / default-stream tick) runs inline on the calling thread with NO threads
/// spawned — byte- and behaviour-identical to the old serial barrier loop.
///
/// ## Durability invariant (paramount)
/// This ONLY parallelizes the blocking `fdatasync` SYSCALLS. It does NOT touch any durable-head or
/// ack bookkeeping: each barrier is a disjoint `&mut Log` (no two barriers touch shared state, so the
/// ack/commit accounting cannot race), and this returns ONLY after EVERY barrier has completed (a full
/// JOIN). The caller MUST therefore run its durable-head advance / ack-release pass ONLY after this
/// returns, and advance a fd's durable head ONLY on that fd's `Ok(())` result — a fd whose barrier
/// returned `Err` (froze) must have its commits FAIL (durable head not advanced, acks stay parked),
/// never acked. No ack in the group is released until after this join, so I2 (ack-implies-durable) and
/// the per-fd freeze isolation are byte-identical to the serial loop.
pub(crate) fn par_sync_data_only<F: Filesystem, C: Clock>(
    barriers: Vec<(usize, &mut Log<F, C>)>,
) -> Vec<(usize, Result<(), StorageError>)> {
    let total = barriers.len();
    let workers = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(COMMIT_BARRIER_MAX_WORKERS)
        .min(total);
    if workers <= 1 {
        // One barrier, one core, or a single-worker cap: run the fdatasyncs inline (no threads, no
        // queue), byte-identical to the old serial barrier loop.
        return barriers
            .into_iter()
            .map(|(tag, log)| (tag, log.sync_data_only()))
            .collect();
    }
    // Shared work queue of the remaining `(tag, &mut Log)` barriers. Each participant locks the queue
    // just long enough to POP one barrier (O(1), not the blocking fsync) and then runs that fd's
    // `fdatasync` OUTSIDE the lock, so the barriers themselves overlap. The `&mut Log` handles are
    // disjoint (each names a different fd/writer), so no barrier can observe or mutate another's
    // writer state — the pop order does not matter because the caller reassembles by `tag`.
    // `&mut Log` is `Send` (`Log: Send`), so `Mutex<Vec<(usize, &mut Log)>>` is `Sync`.
    let queue: std::sync::Mutex<Vec<(usize, &mut Log<F, C>)>> = std::sync::Mutex::new(barriers);
    std::thread::scope(|s| {
        // Helpers are spawned FALLIBLY: a worker that cannot be created (OS thread exhaustion) is
        // simply skipped, and the main thread below is the final participant that drains whatever is
        // left — so even if EVERY helper fails to spawn, every barrier still runs (serially, inline).
        let handles: Vec<_> = (0..workers.saturating_sub(1))
            .filter_map(|k| {
                let queue = &queue;
                std::thread::Builder::new()
                    .name(format!("ib-commit-fsync-{k}"))
                    .spawn_scoped(s, move || {
                        let mut local: Vec<(usize, Result<(), StorageError>)> = Vec::new();
                        loop {
                            // Drop the queue `MutexGuard` right after the O(1) `pop` — BEFORE the
                            // blocking `fdatasync` below — so the K barriers actually overlap. Under
                            // edition-2021 temporary scoping, a guard created in a `while let`
                            // SCRUTINEE lives until the END of the loop body, which would hold the
                            // shared queue lock across `sync_data_only` and force every barrier
                            // strictly SERIAL (the #823 regression: tick latency becomes sum, not
                            // max). The explicit block scopes the guard to the pop alone, so the
                            // fdatasync runs with the lock released and the participants run
                            // concurrently.
                            let Some((tag, log)) =
                                ({ queue.lock().expect("commit barrier queue poisoned").pop() })
                            else {
                                break;
                            };
                            local.push((tag, log.sync_data_only()));
                        }
                        local
                    })
                    .ok()
            })
            .collect();
        // The main thread is the final participant: drain whatever barriers remain (this alone covers
        // the whole set if no helper spawned).
        let mut all: Vec<(usize, Result<(), StorageError>)> = Vec::with_capacity(total);
        loop {
            // Same guard-scoping as the helpers above: drop the queue lock right after the `pop` so
            // this final participant's `fdatasync` overlaps the helpers' rather than running under a
            // held lock (which would serialize the whole fan-out — the #823 regression).
            let Some((tag, log)) = ({ queue.lock().expect("commit barrier queue poisoned").pop() })
            else {
                break;
            };
            all.push((tag, log.sync_data_only()));
        }
        // JOIN every helper before returning: no barrier result — and so no ack — is released until
        // every fd's fdatasync has completed.
        for h in handles {
            all.extend(h.join().expect("commit-tick fsync worker panicked"));
        }
        all
    })
}

impl<F: Filesystem, C: Clock> Log<F, C> {
    /// Opens the log in `fs`, recovering the active segment or creating a fresh one.
    ///
    /// Recovery scans the highest-numbered segment: an unsealed one is recovered as the
    /// active segment, truncating any torn or unsynced tail to the last intact record; a
    /// sealed one means a crash after sealing but before the next segment was created, so
    /// recovery rolls forward and creates that next segment. A fresh log creates segment
    /// 0. New segment headers are stamped from the clock seam and dir-synced.
    ///
    /// # Errors
    /// Returns [`StorageError`] on an IO error or a structurally invalid segment.
    pub fn open(fs: F, clock: C, config: LogConfig) -> Result<Log<F, C>, StorageError> {
        // Check (and, on a pre-marker dir, durably write) the data-directory LAYOUT version marker
        // BEFORE any recovery, so a FUTURE layout is refused fail-closed before its unknown-shaped
        // contents are interpreted (#562). An absent or torn/corrupt marker recovers as layout v1
        // and is (re)written idempotently; an existing single-log deployment is byte-for-byte layout
        // v1, so this records a fact and reinterprets no segment, cursor, or DLQ byte. Recovery below
        // is unchanged. Reserves the `streams/` subtree for per-stream logs (M2-I2); does not create it.
        crate::layout::open_or_upgrade(&fs)?;
        // #643 tiered storage: read the cold manifest BEFORE the chain scan so recovery is
        // manifest-AWARE. A local `seg-<id>.log` for a REMOTE (offloaded) id is a restore-on-access
        // CACHE — "absent until verified against the manifest", NOT a chain anchor. Excluding every
        // REMOTE id from the enumeration is the load-bearing fix: without it, a lagging consumer that
        // restored only a NON-adjacent subset of the offloaded prefix (e.g. seg-0 via a low-offset
        // read) leaves the still-remote segments between that restored file and the local tail as a
        // phantom gap, and the strict contiguity scan hard-fails `SegmentChainBroken` before the
        // manifest is ever consulted. The manifest's spliced prefix (below) provides the
        // authoritative, contiguous chain for those ids; the on-disk cache copy is reconciled on
        // read (`ensure_segment_local` verifies it against the manifest before trusting it).
        let cold_manifest = Self::open_cold_manifest(&fs)?;
        let remote_ids: std::collections::BTreeSet<u64> = cold_manifest
            .as_ref()
            .map_or_else(std::collections::BTreeSet::new, |m| {
                m.entries().keys().copied().collect()
            });
        // PURGE any restore-on-access CACHE file for a REMOTE id BEFORE recovery. A cache file is a
        // process-lifetime, re-fetchable copy of an offloaded segment — deleting it here means NO
        // recovery scan (the compaction-segment probe, `reap_bad_trailing_segment`, the chain scan)
        // can trip over a partial restore (a phantom gap) or a torn cache (a crash mid-restore, since
        // the fs seam has no atomic rename). The authoritative copy is the object store + the manifest
        // splice below; a later read re-fetches the segment cleanly. This is what makes a restart
        // after a routine tiered read robust.
        for &id in &remote_ids {
            let name = segment_file_name(id);
            match fs.remove(&name) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(StorageError::Io(e)),
            }
        }
        if !remote_ids.is_empty() {
            fs.sync_dir().map_err(StorageError::Io)?;
        }
        // The remaining segment files are all genuine LOCAL segments (every REMOTE id's cache was
        // purged above); the filter is defense-in-depth on the id list.
        let ids: Vec<u64> = segment_ids(&fs)?
            .into_iter()
            .filter(|id| !remote_ids.contains(id))
            .collect();
        // #868: a crash during `start_segment` (or bit-rot of the trailing header) can leave the
        // HIGHEST-id segment as a zero-length or undecodable-header file: an empty unsealed tail
        // that holds nothing durable, because the prior segment was sealed before this one was
        // created. The strict chain scan would abort the whole boot on it, so a supervisor restart
        // loops forever and the node stays down until an operator deletes the file by hand. Reap it
        // here so recovery rolls forward and recreates it; the abandonment is recorded in the loss
        // report below. Strictly the trailing id, strictly an undecodable/too-short HEADER — see
        // `reap_bad_trailing_segment` for the cases this deliberately leaves to hard-fail.
        let (ids, recreated_bad_tail) = Self::reap_bad_trailing_segment(&fs, ids)?;
        let mut log = match ids.last().copied() {
            None => {
                // Even with no live segments, a prior recovery's quarantine blobs may still occupy
                // disk (the reaper can delete every segment while the forensic copies are retained),
                // so seed the gauge from the persisted footprint here too (#315). Read-only and
                // best-effort, scanned before `fs` moves into the log.
                let persisted_quarantine_bytes = crate::quarantine::persisted_bytes(&fs);
                let mut log = Log {
                    fs,
                    clock,
                    config,
                    active: None,
                    active_id: FIRST_SEGMENT_ID,
                    next_offset: Offset::ZERO,
                    next_seq: Seq::new(0),
                    flushed_offset: Offset::ZERO,
                    // A fresh log has no records, so the durable head is also the origin (#341).
                    synced_offset: Offset::ZERO,
                    segments: Vec::new(),
                    sealed_record_bytes: 0,
                    total_record_count: 0,
                    recovered_truncated_bytes: 0,
                    loss_report: LossReport::new(),
                    quarantined_bytes: persisted_quarantine_bytes,
                    // The write-amplification counters (#118) measure THIS run's append volume, so
                    // both start at zero; `start_segment` below charges the first segment header.
                    logical_bytes_written: 0,
                    physical_bytes_written: 0,
                    // A fresh log has no unsynced records (#341).
                    unsynced_record_bytes: 0,
                    physical_bytes_written_today: 0,
                    physical_write_today_day: 0,
                    daily_budget_sheds: 0,
                    // A fresh log has no segment to index yet; `start_segment` below seeds the
                    // active segment's (empty) entry.
                    segment_indexes: std::cell::RefCell::new(std::collections::HashMap::new()),
                    // A fresh log has no compacted segment, so the sparse index map (#481) starts
                    // empty; it is filled lazily the first time a compacted slot is read.
                    compacted_indexes: std::cell::RefCell::new(std::collections::HashMap::new()),
                    sealed_readers: SealedReaderCache::new(DEFAULT_SEALED_READER_CACHE_CAP),
                    // The off-actor read plane (#539) is built lazily on the first consumer
                    // `read_plane()` call; a never-read log pays nothing.
                    read_plane: std::cell::RefCell::new(None),
                    pending_roll: None,
                    // Tiered storage (#643): a fresh (empty) log has no manifest and never
                    // offloads until a backend + policy are attached post-open.
                    cold_manifest: None,
                    cold_store: None,
                    cold_config: ColdStorageConfig::default(),
                };
                log.start_segment(FIRST_SEGMENT_ID, Seq::new(0), Offset::ZERO)?;
                log
            }
            Some(last_id) => {
                // Compaction reconciliation (#337): if ANY segment is COMPACTED (v2), recovery must
                // resolve a possibly-overlapping offset range from the self-describing v2 metadata,
                // because a compacted segment has a high id but covers a LOW range, and a crash may
                // have left both it and the originals it replaced. The reconciliation runs FIRST,
                // physically retiring superseded originals and redundant orphan compacted segments,
                // then the surviving set is recovered as a v2-aware chain. When NO compacted segment
                // is present (the overwhelmingly common case) the directory is all-ordinary and the
                // existing v1 recovery runs UNCHANGED, so a non-compacted log's recovery is
                // byte-for-byte the same code path it always was.
                if crate::compaction::directory_has_compacted_segment(&fs)? {
                    Self::recover_with_compaction(fs, clock, config, &ids)?
                } else {
                    Self::recover(fs, clock, config, &ids, last_id)?
                }
            }
        };
        // #868: record the abandoned + recreated empty trailing tail (if any) in the loss report.
        // It held nothing durable, so it is a ZERO-byte `CorruptSegmentHeader` event: visible to an
        // operator and the offline inspector as "segment N had an unreadable header and was rebuilt",
        // but it contributes no skipped or data-loss bytes. That zero is deliberate: recording the
        // full (possibly `max_segment_bytes` of preallocated zeros) span would itself trip the I3
        // global loss cap and re-block the very boot this fix unblocks, and those zero bytes were
        // never acked durable records to begin with.
        if let Some(seg_id) = recreated_bad_tail {
            log.loss_report.push(LossEvent::span(
                seg_id,
                0,
                0,
                0,
                ReasonCode::CorruptSegmentHeader,
            ));
        }
        // #643 tiered storage: attach the (already-read) cold manifest and SPLICE the offloaded
        // (oldest) prefix back into the recovered chain so an offloaded segment recovers as PRESENT,
        // never as a torn gap. The recovered local chain already EXCLUDES every REMOTE id (a restored
        // cache file never anchored the scan), so the splice provides the sole, contiguous chain for
        // those ids. Absent manifest => nothing happens (the default-OFF, byte-identical path).
        log.cold_manifest = cold_manifest;
        log.splice_cold_prefix()?;
        Ok(log)
    }

    /// #868: if the HIGHEST-id segment is an EMPTY unsealed tail left by a crash during
    /// `start_segment` (a 0-length or header-only file, or a header followed by an all-zero
    /// preallocated body), remove it and return the reduced id list plus its id, so [`Log::open`]
    /// rolls forward and recreates it instead of aborting the whole boot. The reaped tail holds
    /// nothing durable: the prior segment was sealed before this one was created.
    ///
    /// Deliberately narrow, because for a durable log a WRONG reap is silent data loss. ALL hold:
    /// - There is at least one PREDECESSOR (`ids.len() >= 2`). A sole bad-header segment is left to
    ///   the strict scan, which fails closed: an unreadable header gives no way to reconstruct the
    ///   offset/seq space, and an empty-looking sole segment is byte-indistinguishable from a wholly
    ///   corrupt one (the corruption-corpus `*_fails_closed` contract, e.g. `all_zeros_whole_*`).
    /// - The trailing HEADER is undecodable or too short. A header that DECODES (even to a
    ///   conflicting id, the [`StorageError::SegmentIdMismatch`] case) is a normal tail for the scan.
    /// - The trailing BODY is provably EMPTY (see
    ///   [`segment_body_is_all_zero`](Log::segment_body_is_all_zero)): if ANY non-zero record byte
    ///   follows the bad header, the segment may hold acked records (for example a bit-rotted
    ///   ACTIVE-segment header over real frames), so it must NOT be deleted — it is left for the
    ///   strict scan to fail closed and PRESERVE the file for forensics. This body proof is the line
    ///   between an availability recovery and data loss.
    /// - A bad header on any NON-final segment is untouched here and still hard-fails in the scan.
    /// - A real IO error (not a structural header error) is propagated, never masked into a reap.
    fn reap_bad_trailing_segment(
        fs: &F,
        mut ids: Vec<u64>,
    ) -> Result<(Vec<u64>, Option<u64>), StorageError> {
        let Some(&last) = ids.last() else {
            return Ok((ids, None));
        };
        // A sole bad-header segment has no predecessor to roll forward from: fail closed.
        if ids.len() < 2 {
            return Ok((ids, None));
        }
        let name = segment_file_name(last);
        // A decodable header is a normal tail (recovered / rolled / id-rejected by the strict scan);
        // only an undecodable/too-short header is a reap candidate. A real IO error is surfaced.
        match SegmentReader::open(fs.open(&name)?) {
            Ok(_) => return Ok((ids, None)),
            Err(StorageError::Segment(_)) => {}
            Err(e) => return Err(e),
        }
        // The header is undecodable. Reap ONLY if the body carries no record bytes — a genuinely
        // empty preallocated tail, not a populated segment whose header rotted. The re-open is
        // because `SegmentReader::open` consumed the first handle.
        if !Self::segment_body_is_all_zero(&fs.open(&name)?)? {
            return Ok((ids, None));
        }
        fs.remove(&name)?;
        ids.pop();
        Ok((ids, Some(last)))
    }

    /// `true` if `file` has no record bytes past the 64-byte segment header: it is at most a header
    /// long, or every byte in `[SEGMENT_HEADER_LEN, len)` is zero. Used by #868's reap to prove a
    /// bad-header trailing segment is a genuinely-empty preallocated tail (safe to recreate) rather
    /// than a populated segment whose header rotted (whose acked records must never be silently
    /// deleted). Reads in bounded chunks so a `max_segment_bytes`-preallocated file costs no large
    /// allocation.
    fn segment_body_is_all_zero(file: &F::File) -> Result<bool, StorageError> {
        let file_len = file.len()?;
        let header = SEGMENT_HEADER_LEN as u64;
        if file_len <= header {
            return Ok(true);
        }
        Self::region_is_all_zero(file, header, file_len)
    }

    /// `true` if every byte of `file` in `[start, end)` is zero. Reads in bounded 4 KiB chunks so
    /// a `max_segment_bytes`-long region costs no large allocation (and, on a filesystem with
    /// unwritten-extent tracking, no device IO at all: a preallocated hole reads back as zeros
    /// straight from the kernel). The #868 reap uses it via
    /// [`segment_body_is_all_zero`](Log::segment_body_is_all_zero) to prove a bad-header trailing
    /// segment is a genuinely-empty preallocated tail. (Recovery's zero-tail REPORTING rule uses
    /// the sibling [`crate::io::last_nonzero_end`], which additionally bounds a non-zero tail at
    /// one past its last written byte.)
    fn region_is_all_zero(file: &F::File, start: u64, end: u64) -> Result<bool, StorageError> {
        let mut pos = start;
        let mut buf = [0u8; 4096];
        while pos < end {
            let want = buf
                .len()
                .min(usize::try_from(end - pos).unwrap_or(usize::MAX));
            let chunk = &mut buf[..want];
            file.read_exact_at(chunk, pos)?;
            if chunk.iter().any(|&b| b != 0) {
                return Ok(false);
            }
            pos += want as u64;
        }
        Ok(true)
    }

    /// The upper bound on how many segment scans run concurrently during recovery (#817, #821).
    /// Recovery is a cold path, so the pool is capped to a small fixed width regardless of core
    /// count: it recovers most of the linear-in-cores speedup on a big box while keeping Edge RAM
    /// (one streamed record per in-flight worker) and IO-device pressure (concurrent positioned
    /// reads on one spinning disk) bounded. The effective width is `min(this, cores, segments)`.
    const RECOVERY_SCAN_MAX_WORKERS: usize = 8;

    /// Runs `scan` for every id across a bounded [`std::thread::scope`] worker set, returning one
    /// result per id in the SAME order as `ids` (index-aligned to it), regardless of the order the
    /// workers finished (#817, #821). Each id's scan is fully independent — it opens and CRC-walks
    /// only its own file — so this is the embarrassingly-parallel MAP half of recovery; the
    /// deterministic serial FOLD over the returned vector (chain-continuity, sealed-predecessor,
    /// running totals) is the caller's job and is byte-for-byte the serial-path computation.
    ///
    /// No external threadpool (no rayon): a fixed set of scoped workers steals ids off one shared
    /// atomic cursor, so a fast segment's worker immediately picks up the next id rather than
    /// blocking on a slow one, and every worker borrows `fs` (`Filesystem: Send + Sync`) and reads
    /// its own file with no shared mutable state. The width is bounded by
    /// [`Self::RECOVERY_SCAN_MAX_WORKERS`]; a single-segment log (or a single worker) runs the
    /// scans inline with no threads spawned.
    fn par_scan_segments<T, S>(fs: &F, ids: &[u64], scan: S) -> Vec<Result<T, StorageError>>
    where
        T: Send,
        S: Fn(&F, u64) -> Result<T, StorageError> + Send + Sync,
    {
        let total = ids.len();
        let workers = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(Self::RECOVERY_SCAN_MAX_WORKERS)
            .min(total);
        if workers <= 1 {
            // One segment, one core, or a single-worker cap: run inline, no threads, no cursor.
            return ids.iter().map(|&id| scan(fs, id)).collect();
        }
        let cursor = std::sync::atomic::AtomicUsize::new(0);
        // Each participant returns the (index, result) pairs it computed; we reassemble by index so
        // the returned order is id order no matter who won which id. Helpers are spawned FALLIBLY via
        // `Builder::spawn_scoped`: if a worker thread cannot be created (OS thread exhaustion on a
        // cold boot) we simply run with fewer helpers, and the main thread is itself the final
        // participant — so even if EVERY helper fails to spawn, every index is still scanned inline.
        // Recovery therefore degrades to serial rather than panicking, matching the resilience this
        // boot path demands (and consistent with #870).
        let collected: Vec<(usize, Result<T, StorageError>)> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..workers.saturating_sub(1))
                .filter_map(|k| {
                    let cursor = &cursor;
                    let scan = &scan;
                    std::thread::Builder::new()
                        .name(format!("ib-recover-scan-{k}"))
                        .spawn_scoped(s, move || {
                            let mut local: Vec<(usize, Result<T, StorageError>)> = Vec::new();
                            loop {
                                let i = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if i >= total {
                                    break;
                                }
                                local.push((i, scan(fs, ids[i])));
                            }
                            local
                        })
                        .ok()
                })
                .collect();
            // The main thread is the final participant: drain whatever indices remain (this alone
            // covers 0..total if no helper spawned).
            let mut all: Vec<(usize, Result<T, StorageError>)> = Vec::with_capacity(total);
            loop {
                let i = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i >= total {
                    break;
                }
                all.push((i, scan(fs, ids[i])));
            }
            for h in handles {
                all.extend(h.join().expect("recovery scan worker panicked"));
            }
            all
        });
        let mut slots: Vec<Option<Result<T, StorageError>>> = (0..total).map(|_| None).collect();
        for (i, r) in collected {
            slots[i] = Some(r);
        }
        // Every index in 0..total is assigned exactly once (the cursor hands each out once), so no
        // slot is None here.
        slots
            .into_iter()
            .map(|r| r.expect("every recovery scan index was assigned"))
            .collect()
    }

    /// Walks every segment in ascending order from a streaming recovery scan, validating the
    /// chain (each segment's stored id matches its file name, its base continues from its
    /// predecessor, its records are a contiguous sequence run, and every NON-final segment is
    /// sealed) and accumulating the in-memory slots plus the running byte and record-count totals.
    /// A corrupt or unreadable segment fails its scan here, not silently at read time. The
    /// per-segment retention metadata (record count, max timestamp) is recomputed from the scan so
    /// the reaper behaves identically after a reopen.
    ///
    /// The per-segment scan+CRC MAP runs across a bounded worker set ([`Self::par_scan_segments`],
    /// #817/#821), then this deterministic serial FOLD assembles the chain in id order: the
    /// recovered result (slots, offsets, sequence run, running totals, and every error decision) is
    /// byte-for-byte identical to a strictly serial scan, since the fold consumes the scans in the
    /// same id order and returns the first failing id's error exactly as the serial loop did.
    fn scan_recover_chain(fs: &F, ids: &[u64]) -> Result<RecoveredChain, StorageError> {
        let mut next_base_offset = 0u64;
        let mut next_base_seq = 0u64;
        let mut durable_bytes = 0u64;
        let mut total_record_count = 0u64;
        let mut highest: Option<RecoveryScan> = None;
        let mut slots: Vec<SegmentSlot> = Vec::with_capacity(ids.len());
        let total = ids.len();
        let scans = Self::par_scan_segments(fs, ids, |fs, id| {
            SegmentReader::open(fs.open(&segment_file_name(id))?)?.scan_recovery()
        });
        for (i, (&id, scan)) in ids.iter().zip(scans).enumerate() {
            let scan = scan?;
            let header = scan.header;
            if header.segment_id != id {
                return Err(StorageError::SegmentIdMismatch {
                    file_id: id,
                    header_id: header.segment_id,
                });
            }
            let base_offset = header.base_offset.get();
            let base_seq = header.base_seq.get();
            // The highest (active unless rolled forward) segment's slot is corrected when it is
            // installed as the writer or sealed; the rest are sealed predecessors.
            slots.push(SegmentSlot {
                id,
                base_offset,
                record_count: scan.record_count,
                max_timestamp_ms: scan.max_timestamp_ms,
                // This v1 path is only reached for an all-ordinary directory (the compaction
                // reconciliation in `open` routes a directory containing a compacted segment
                // elsewhere), so every slot here is ordinary.
                compacted_covered: None,
            });
            if i > 0 && (base_offset != next_base_offset || base_seq != next_base_seq) {
                return Err(StorageError::SegmentChainBroken {
                    segment_id: id,
                    expected_base_offset: next_base_offset,
                    found_base_offset: base_offset,
                    expected_base_seq: next_base_seq,
                    found_base_seq: base_seq,
                });
            }
            let is_last = i + 1 == total;
            if !is_last && scan.footer.is_none() {
                return Err(StorageError::UnsealedPredecessor { segment_id: id });
            }
            let count = scan.record_count;
            next_base_offset = base_offset
                .checked_add(count)
                .ok_or(StorageError::SegmentFull)?;
            next_base_seq = base_seq
                .checked_add(count)
                .ok_or(StorageError::SegmentFull)?;
            durable_bytes = durable_bytes
                .saturating_add(scan.valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64));
            total_record_count = total_record_count.saturating_add(count);
            if is_last {
                highest = Some(scan);
            }
        }
        // `highest` is Some because `open` only calls `recover` (hence this) with a non-empty list.
        let highest = highest.ok_or(StorageError::WriterFrozen)?;
        Ok(RecoveredChain {
            slots,
            next_base_offset,
            next_base_seq,
            durable_bytes,
            total_record_count,
            highest,
        })
    }

    fn recover(
        fs: F,
        clock: C,
        config: LogConfig,
        ids: &[u64],
        last_id: u64,
    ) -> Result<Log<F, C>, StorageError> {
        let chain = Self::scan_recover_chain(&fs, ids)?;
        let RecoveredChain {
            slots,
            next_base_offset,
            next_base_seq,
            durable_bytes,
            total_record_count,
            highest: scan,
        } = chain;
        let header = scan.header;
        let next_offset = Offset::new(next_base_offset);
        let next_seq = Seq::new(next_base_seq);
        // The highest segment's durable record bytes (the same term the loop added for it). It
        // is the active segment unless we roll forward below, so the sealed total starts as the
        // sum over every predecessor and the highest's bytes are added back if it gets sealed.
        let highest_record_bytes = scan.valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64);
        let sealed_record_bytes = durable_bytes.saturating_sub(highest_record_bytes);

        // Seed the gauge from the PERSISTED on-disk footprint of prior recoveries (#315) BEFORE `fs`
        // moves into the log, so a clean reopen with no new corruption skip still surfaces the real
        // disk pressure the forensic copies create.
        let persisted_quarantine_bytes = crate::quarantine::persisted_bytes(&fs);

        let mut log = Log {
            fs,
            clock,
            config,
            active: None,
            active_id: last_id,
            next_offset,
            next_seq,
            // Everything recovered is durable, so both the visible and the durable head are the
            // recovered head (#341): a relaxed level's unsynced tail never survives a power loss, so
            // recovery only ever yields a fully-durable prefix.
            flushed_offset: next_offset,
            synced_offset: next_offset,
            segments: slots,
            sealed_record_bytes,
            total_record_count,
            recovered_truncated_bytes: 0,
            loss_report: LossReport::new(),
            // The persisted footprint (#315). This scan is best-effort and strictly read-only (a
            // missing or unreadable quarantine dir degrades to 0), so it preserves the #134 never-
            // blocks-recovery and copy-not-move properties. A new corruption skip below ADDS its
            // capture on top, so the total stays the true persisted on-disk footprint.
            quarantined_bytes: persisted_quarantine_bytes,
            // The write-amplification counters (#118) measure THIS run's append volume: a recovered
            // log starts the amplification window fresh (recovery itself writes nothing here; a
            // roll-forward below charges the new segment's header).
            logical_bytes_written: 0,
            physical_bytes_written: 0,
            // Everything recovered is durable (a relaxed level's unsynced tail never survives), so
            // there is no unsynced exposure right after recovery (#341).
            unsynced_record_bytes: 0,
            physical_bytes_written_today: 0,
            physical_write_today_day: 0,
            daily_budget_sheds: 0,
            // Resident seek indexes (#483) are built lazily on the read path and EXTENDED as the
            // active segment appends, so recovery starts them empty: nothing is read yet, and a
            // reopen always rebuilds from the durable frames (the index is never persisted).
            segment_indexes: std::cell::RefCell::new(std::collections::HashMap::new()),
            // The compacted (sparse) seek index map (#481) is likewise resident-only: a reopen
            // rebuilds it lazily from the durable frames the first time a compacted slot is read.
            compacted_indexes: std::cell::RefCell::new(std::collections::HashMap::new()),
            sealed_readers: SealedReaderCache::new(DEFAULT_SEALED_READER_CACHE_CAP),
            // The off-actor read plane (#539) is built lazily on the first consumer `read_plane()`.
            read_plane: std::cell::RefCell::new(None),
            pending_roll: None,
            // Tiered storage (#643): the cold manifest is ATTACHED after construction by
            // `open` (which reads `cold-manifest.ckpt` if present); the backend + policy are
            // injected post-open. A never-offloaded log leaves all three at their off defaults.
            cold_manifest: None,
            cold_store: None,
            cold_config: ColdStorageConfig::default(),
        };

        if scan.footer.is_some() {
            // Crash after sealing the highest segment but before the next was created:
            // roll forward and create it, continuing the offset and sequence space. The
            // highest segment is sealed, so its record bytes join the sealed total; the new
            // active segment is empty.
            let next_id = last_id.checked_add(1).ok_or(StorageError::SegmentFull)?;
            log.sealed_record_bytes = log.sealed_record_bytes.saturating_add(highest_record_bytes);
            log.start_segment(next_id, next_seq, next_offset)?;
        } else {
            // The active segment is unsealed: drop any torn or unsynced tail and resume.
            // set_len changes the length, so it needs sync_all, not sync_data.
            let name = segment_file_name(last_id);
            let file = log.fs.open(&name)?;
            let len = file.len()?;
            if scan.valid_end < len {
                // Distinguish DISCARDED DATA from the unwritten remainder of a preallocated,
                // logically-extended active segment: the production `StdFile::preallocate` advances
                // the logical length to the roll size up front, so even a clean kill leaves the
                // active segment with a (possibly roll-size) all-zero tail past the last record.
                // Zeros are provably not acked data — a zero word is never a valid frame magic, so
                // no frame was ever written there — so everything REPORTED (the loss event, the
                // quarantine capture, `recovered_truncated_bytes`) is bounded at one past the
                // tail's LAST NON-ZERO byte, the end of the bytes that were ever plausibly
                // written. An ALL-ZERO tail is truncated silently (the same I3-tripping non-loss
                // #868 declined to record); reporting to the FILE length instead would claim (and
                // quarantine) up to a whole roll size of never-written zeros for ONE torn byte,
                // and would fail the boot on the I3 per-event cap whenever `max_segment_bytes`
                // exceeds it. The FILE truncation below still cuts at `valid_end` as before.
                let reported_end = crate::io::last_nonzero_end(&file, scan.valid_end, len)?;
                if reported_end > scan.valid_end {
                    // Record the silent loss before dropping it, so an operator can see that a
                    // torn or unsynced tail was discarded at recovery, both as a raw byte count
                    // and as a structured loss event carrying the span and the reason (#120). The
                    // records-lost estimate is a lower bound: the torn or corrupt span is, by
                    // definition, not fully parseable, but at least the frame at `valid_end` is gone.
                    log.recovered_truncated_bytes = reported_end - scan.valid_end;
                    let reason = scan.tail_reason.unwrap_or(ReasonCode::TornTail);
                    let event = LossEvent::span(last_id, scan.valid_end, reported_end, 1, reason);
                    log.loss_report.push(event);
                    // Quarantine the corrupt bytes BEFORE truncating them away, while `file` still holds
                    // the full image (#134). This is a COPY: it only ever reads `file`, and the
                    // truncation below is unchanged. It is best-effort and forensic, so any quarantine
                    // failure is swallowed and never affects the truncation or the open; a clean torn
                    // tail is not quarantined (see `quarantine::is_corruption_skip`).
                    if crate::quarantine::is_corruption_skip(reason) {
                        let captured = crate::quarantine::quarantine_corrupt_span(
                            &log.fs,
                            &file,
                            &event,
                            log.config.max_quarantine_bytes,
                        );
                        // Reflect the new blob in the PERSISTED total (#315). A capture under a cap can
                        // evict older blobs to make room, so re-derive the gauge from the true on-disk
                        // footprint (the seeded scan plus this capture, net of any eviction) rather than
                        // a naive add. The re-scan is read-only and best-effort, so it never affects the
                        // truncation below or the open. The cheap `captured > 0` guard skips the re-scan
                        // when nothing was captured (a cap skip or a best-effort give-up).
                        if captured > 0 {
                            log.quarantined_bytes = crate::quarantine::persisted_bytes(&log.fs);
                        }
                    }
                    // I3, enforced BEFORE the destructive truncate below: a cap-exceeding loss must
                    // fail closed with the evidence still ON DISK (plus the forensic quarantine copy
                    // just taken). Truncating first would destroy the over-cap bytes, so the NEXT
                    // boot would open clean with an empty loss report — a fail-closed refusal that
                    // scrubbed the very state the operator is being told to inspect. The end-of-open
                    // check below stays as the backstop for the paths that push no event here.
                    log.enforce_loss_caps(durable_bytes)?;
                }
                file.set_len(scan.valid_end)?;
                file.sync_all()?;
            }
            let record_count =
                u32::try_from(scan.record_count).map_err(|_| StorageError::SegmentFull)?;
            let last_seq = scan.last_seq;
            // Resume the writer with the recovered running record max timestamp, so a record
            // appended after recovery keeps the segment's max correct (and the slot stays exact
            // when this segment is later sealed on a roll).
            log.active = Some(SegmentWriter::resume(
                file,
                header,
                scan.valid_end,
                record_count,
                last_seq,
                scan.max_timestamp_ms,
            ));
        }

        // I3 backstop: the torn-tail path above already enforced the caps BEFORE its truncate;
        // this covers the no-event paths (a roll-forward pushes nothing) so every recovery exit
        // is cap-checked exactly once against its final report.
        log.enforce_loss_caps(durable_bytes)?;
        Ok(log)
    }

    /// I3: fail closed if recovery would drop more than the bounded-loss caps allow (#120),
    /// rather than accept unbounded silent loss. The per-event cap is one segment or 64 MiB,
    /// whichever is smaller. The global cap is 1% of the durable bytes, FLOORED at the
    /// per-event cap so a single in-cap event (the normal torn tail, even on a tiny log whose
    /// 1% is under one byte) is always within bounds; without that floor the literal 1% would
    /// freeze a normal small-log recovery.
    ///
    /// Both recovery paths call this at two points: right AFTER pushing the active-segment tail
    /// loss event but BEFORE the truncate that would destroy the over-cap bytes (fail-closed must
    /// leave the evidence on disk for the next boot and the offline inspector), and once more at
    /// the end of the open as the backstop for the paths that push no tail event.
    fn enforce_loss_caps(&self, durable_bytes: u64) -> Result<(), StorageError> {
        let per_event_cap = self
            .config
            .max_segment_bytes
            .min(LossReport::PER_EVENT_BYTE_CAP);
        let global_cap = LossReport::global_loss_cap_bytes(durable_bytes).max(per_event_cap);
        self.loss_report
            .check_caps(per_event_cap, global_cap)
            .map_err(StorageError::ExcessiveRecoveryLoss)
    }

    /// Recovers a data directory that contains at least one COMPACTED (v2) segment (#337),
    /// resolving a possibly-overlapping offset range deterministically from the self-describing v2
    /// metadata, with NO compaction-specific repair beyond two generic file-set reconciliations and
    /// NO manifest. It is reached only when [`compaction::directory_has_compacted_segment`] is true;
    /// an all-ordinary directory takes the unchanged v1 [`Log::recover`] path.
    ///
    /// The reconciliation, in order:
    /// 1. Classify each segment as ordinary or compacted. A compacted-flagged segment whose
    ///    trailing footer/block is torn or CRC-mismatched did NOT reach its commit point: it is an
    ///    orphan from a crash before the directory fsync, discarded (unlinked).
    /// 2. A committed compacted segment is AUTHORITATIVE over every original whose offset range is
    ///    fully inside its covered range (the crash-after-commit-during-retire case): those
    ///    superseded originals are unlinked.
    /// 3. Two compacted segments never partially overlap by construction; if a crash somehow left
    ///    two with overlapping covered ranges, the HIGHER segment id (the later clean, by ADR 0002
    ///    monotonicity) wins and the lower is unlinked.
    /// 4. The surviving set (compacted segments plus uncompacted originals) is sorted by
    ///    covered/actual offset range (NOT by id, since a compacted id no longer tracks its range)
    ///    and must stitch into one offset-contiguous-at-the-segment-boundary chain; the sequence
    ///    half advances by the covered SPAN across a compacted segment, not the survivor count.
    ///
    /// The orphan-discard and superseded-original reconciliations emit NO `LossReport` event: a
    /// discarded orphan's data is fully present in the originals, and an unlinked superseded
    /// original's surviving records are present in the compacted segment, so no durable record is
    /// actually lost (the I1 to I4 invariants hold). The ONE exception (#836) is a COMMITTED
    /// compacted segment (footer + meta CRC-valid) whose BODY is corrupt: it is the sole durable
    /// copy of the survivors it covers, so it is NOT silently unlinked like a crash-before-commit
    /// orphan — it is quarantined (a forensic copy) and its covered survivor loss IS accounted in
    /// the `LossReport` (fail-closed + reported, never a silent drop).
    ///
    /// Long for the same reason [`Log::build_compacted_chain`] is: the classify MAP, the serial
    /// side-effecting FOLD (orphan unlink, #836 committed-but-corrupt quarantine + loss accounting),
    /// and the three overlap/supersede reconciliations are one cohesive procedure that does not
    /// factor below the line limit without obscuring the ordering the on-disk image depends on.
    #[allow(clippy::too_many_lines)]
    fn recover_with_compaction(
        fs: F,
        clock: C,
        config: LogConfig,
        ids: &[u64],
    ) -> Result<Log<F, C>, StorageError> {
        // Step 1: classify every segment. The per-segment scan+CRC MAP runs across the same bounded
        // worker set as the v1 path (#817/#821): each id opens and CRC-walks only its own file, so
        // the classification is independent. The deterministic serial FOLD below then performs the
        // order-sensitive side effects (unlinking a crash-before-commit orphan) and pushes each
        // candidate in id order, so the surviving set and the resulting on-disk image are identical
        // to a strictly serial classification.
        enum Classified {
            /// An ordinary (v1) segment recovered to a chain candidate.
            Ordinary(OrdinaryCandidate),
            /// A committed compacted (v2) segment recovered to a chain candidate.
            Compacted(CompactedCandidate),
            /// A compacted-flagged segment with a torn/CRC-bad trailing footer or block: it did NOT
            /// reach its commit point, so the serial fold unlinks it as a crash-before-commit orphan.
            CompactedOrphan { id: u64 },
            /// #836: a COMMITTED compacted segment (its footer AND meta block both decoded
            /// CRC-VALID, proving it reached its commit point) whose BODY is corrupt (a survivor
            /// frame failed its CRC, or the footer count / body length disagrees). It is the SOLE
            /// durable copy of the survivors it covers, so it must NEVER be silently unlinked like a
            /// crash-before-commit orphan: the serial fold QUARANTINES it (a forensic copy) and
            /// accounts the covered survivor loss in the `LossReport`, then removes the poisoned live
            /// copy. Carries the survivor byte region + count estimate needed to quarantine + account
            /// the loss (the covered offset range travels on the typed error for its diagnostics).
            CompactedCorrupt {
                id: u64,
                record_region_start: u64,
                record_region_end: u64,
                record_count_estimate: u64,
            },
        }
        let classified = Self::par_scan_segments(&fs, ids, |fs, id| {
            let reader = SegmentReader::open(fs.open(&segment_file_name(id))?)?;
            if reader.header().is_compacted() {
                // Three distinct outcomes (#836): a valid committed compacted segment (`Ok(Some)`),
                // a crash-before-commit orphan with no valid trailer (`Ok(None)`, silently unlinked
                // below because nothing was committed), and a COMMITTED-but-body-corrupt segment
                // (`Err(CorruptCompacted)`: footer+meta CRC-valid but the body is bit-rotted / count
                // -inconsistent). The last is the sole durable copy of acked survivors, so it must be
                // QUARANTINED + reported, never conflated with the orphan unlink.
                match reader.scan_compacted() {
                    Ok(Some(scan)) => Ok(Classified::Compacted(CompactedCandidate {
                        id,
                        record_count: scan.records.len() as u64,
                        max_timestamp_ms: scan.max_timestamp_ms,
                        cover: CompactedCover {
                            covered_base_offset: scan.meta.covered_base_offset,
                            covered_end_offset: scan.meta.covered_end_offset,
                            covered_base_seq: scan.meta.covered_base_seq,
                            covered_end_seq: scan.meta.covered_end_seq,
                        },
                        valid_end: scan.valid_end,
                    })),
                    Ok(None) => Ok(Classified::CompactedOrphan { id }),
                    Err(StorageError::CorruptCompacted {
                        segment_id: _,
                        covered_base_offset: _,
                        covered_end_offset: _,
                        record_region_start,
                        record_region_end,
                        record_count_estimate,
                    }) => Ok(Classified::CompactedCorrupt {
                        id,
                        record_region_start,
                        record_region_end,
                        record_count_estimate,
                    }),
                    Err(e) => Err(e),
                }
            } else {
                let scan = reader.scan_recovery()?;
                Ok(Classified::Ordinary(OrdinaryCandidate {
                    id,
                    base_offset: scan.header.base_offset.get(),
                    base_seq: scan.header.base_seq.get(),
                    record_count: scan.record_count,
                    max_timestamp_ms: scan.max_timestamp_ms,
                    valid_end: scan.valid_end,
                    sealed: scan.footer.is_some(),
                    file_len: fs.open(&segment_file_name(id))?.len()?,
                    tail_reason: scan.tail_reason,
                    last_seq: scan.last_seq,
                    header: scan.header,
                }))
            }
        });
        let mut ordinaries: Vec<OrdinaryCandidate> = Vec::new();
        let mut compacteds: Vec<CompactedCandidate> = Vec::new();
        // #836: loss events for any COMMITTED-but-body-corrupt compacted segment quarantined below,
        // carried into `build_compacted_chain` so they land in the recovered log's `LossReport` and
        // are subject to the I3 bounded-loss caps alongside any active-segment torn tail.
        let mut corrupt_losses: Vec<LossEvent> = Vec::new();
        for c in classified {
            match c? {
                Classified::Ordinary(o) => ordinaries.push(o),
                Classified::Compacted(cc) => compacteds.push(cc),
                Classified::CompactedOrphan { id } => {
                    // A compacted-flagged segment with a torn/CRC-bad trailing footer or block did
                    // NOT reach its commit point: discard it as a crash-before-commit orphan. Nothing
                    // was committed, so the originals remain authoritative and this is not a loss.
                    fs.remove(&segment_file_name(id))?;
                    fs.sync_dir()?;
                }
                Classified::CompactedCorrupt {
                    id,
                    record_region_start,
                    record_region_end,
                    record_count_estimate,
                } => {
                    // #836: a COMMITTED compacted segment (footer+meta CRC-valid) whose body is
                    // corrupt is the SOLE durable copy of the survivors it covers, so it must NEVER
                    // be silently unlinked like a crash-before-commit orphan. Fail closed exactly as
                    // the active-segment corruption path does: COPY the poisoned survivor region into
                    // the forensic quarantine store, account the covered survivor loss in the
                    // `LossReport`, THEN remove the poisoned live copy so it is neither re-triggered
                    // every boot nor served as truth. The reason is `CorruptRecordBody` (a survivor
                    // record can no longer be trusted): it counts as data loss and is quarantined,
                    // the same boundary the active-segment skip uses.
                    let event = LossEvent::span(
                        id,
                        record_region_start,
                        record_region_end,
                        record_count_estimate.max(1),
                        ReasonCode::CorruptRecordBody,
                    );
                    // Forensic COPY (never a silent drop), best-effort: a quarantine IO failure never
                    // blocks recovery, exactly like the active-segment corruption skip.
                    if let Ok(source) = fs.open(&segment_file_name(id)) {
                        let _ = crate::quarantine::quarantine_corrupt_span(
                            &fs,
                            &source,
                            &event,
                            config.max_quarantine_bytes,
                        );
                    }
                    corrupt_losses.push(event);
                    // Remove the poisoned live copy AFTER the forensic capture: this mirrors the
                    // orphan unlink, but only once the loss is preserved (quarantine) and reported
                    // (LossReport), so it is never a SILENT drop.
                    fs.remove(&segment_file_name(id))?;
                    fs.sync_dir()?;
                }
            }
        }

        // Step 3: two compacted segments with overlapping covered ranges => higher id wins.
        compacteds.sort_by(|a, b| {
            a.cover
                .covered_base_offset
                .cmp(&b.cover.covered_base_offset)
        });
        let mut keep_compacted: Vec<CompactedCandidate> = Vec::new();
        for cand in compacteds {
            if let Some(prev) = keep_compacted.last() {
                let overlaps = cand.cover.covered_base_offset < prev.cover.covered_end_offset;
                if overlaps {
                    // The higher id is the later clean (ADR 0002 monotonicity): keep it, drop the
                    // lower. Because we iterate in covered-base order, `prev` is the lower base; the
                    // overlap tie-break is by id.
                    if cand.id > prev.id {
                        let dropped = keep_compacted.pop();
                        if let Some(d) = dropped {
                            fs.remove(&segment_file_name(d.id))?;
                            fs.sync_dir()?;
                        }
                        keep_compacted.push(cand);
                    } else {
                        fs.remove(&segment_file_name(cand.id))?;
                        fs.sync_dir()?;
                    }
                    continue;
                }
            }
            keep_compacted.push(cand);
        }

        // Step 2: drop any ordinary segment fully inside some surviving compacted segment's covered
        // range (a superseded original from a crash mid-retire). Unlink it; its surviving records
        // are present in the compacted segment, so this is not a loss.
        let mut keep_ordinary: Vec<OrdinaryCandidate> = Vec::new();
        for ord in ordinaries {
            let ord_end = ord.base_offset.saturating_add(ord.record_count);
            let superseded = keep_compacted.iter().any(|c| {
                ord.base_offset >= c.cover.covered_base_offset
                    && ord_end <= c.cover.covered_end_offset
            });
            if superseded {
                fs.remove(&segment_file_name(ord.id))?;
                fs.sync_dir()?;
            } else {
                keep_ordinary.push(ord);
            }
        }

        // Step 4: build the reconciled, offset-ordered slot list and verify the chain stitches at
        // segment boundaries. Each entry carries its covered/actual base and end so the continuity
        // check uses the covered span across a compacted segment. Any #836 committed-but-corrupt
        // loss events are threaded in so they land in the recovered log's `LossReport`.
        Self::build_compacted_chain(
            fs,
            clock,
            config,
            keep_ordinary,
            keep_compacted,
            corrupt_losses,
        )
    }

    /// Stitches the reconciled ordinary + compacted candidate set into the recovered [`Log`],
    /// validating offset-and-sequence continuity at every segment boundary (the covered span across
    /// a compacted segment, the dense span across an ordinary one), recovering the active segment's
    /// torn tail or rolling it forward, and seeding the running totals. Split out of
    /// [`Log::recover_with_compaction`] to keep each function focused. It mirrors the structure of
    /// the v1 [`Log::recover`], which is itself long: the chain walk, the active-segment torn-tail or
    /// roll-forward, and the I3 cap check are one cohesive recovery procedure that does not factor
    /// cleanly below the line limit without obscuring it.
    #[allow(clippy::too_many_lines)]
    fn build_compacted_chain(
        fs: F,
        clock: C,
        config: LogConfig,
        ordinaries: Vec<OrdinaryCandidate>,
        compacteds: Vec<CompactedCandidate>,
        corrupt_losses: Vec<LossEvent>,
    ) -> Result<Log<F, C>, StorageError> {
        // A reconciled chain entry, sorted by covered/actual base offset.
        enum Entry {
            Ordinary(OrdinaryCandidate),
            Compacted(CompactedCandidate),
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(ordinaries.len() + compacteds.len());
        entries.extend(ordinaries.into_iter().map(Entry::Ordinary));
        entries.extend(compacteds.into_iter().map(Entry::Compacted));
        // Sort by covered/actual base offset; the id no longer proxies offset order.
        entries.sort_by_key(|e| match e {
            Entry::Ordinary(o) => o.base_offset,
            Entry::Compacted(c) => c.cover.covered_base_offset,
        });

        let mut slots: Vec<SegmentSlot> = Vec::with_capacity(entries.len());
        let mut next_base_offset = 0u64;
        let mut next_base_seq = 0u64;
        let mut durable_bytes = 0u64;
        let mut total_record_count = 0u64;
        // The highest-offset-range ORDINARY entry is the active segment candidate; track its index.
        let mut active_ordinary: Option<OrdinaryCandidate> = None;
        let total = entries.len();
        for (i, entry) in entries.into_iter().enumerate() {
            let is_last = i + 1 == total;
            // The covered/actual base and end, plus the sequence span, for the continuity check.
            let (base_offset, base_seq, end_offset, end_seq, rec_count, max_ts, valid_end, id) =
                match &entry {
                    Entry::Ordinary(o) => (
                        o.base_offset,
                        o.base_seq,
                        o.base_offset.saturating_add(o.record_count),
                        o.base_seq.saturating_add(o.record_count),
                        o.record_count,
                        o.max_timestamp_ms,
                        o.valid_end,
                        o.id,
                    ),
                    Entry::Compacted(c) => (
                        c.cover.covered_base_offset,
                        c.cover.covered_base_seq,
                        c.cover.covered_end_offset,
                        c.cover.covered_end_seq,
                        c.record_count,
                        c.max_timestamp_ms,
                        c.valid_end,
                        c.id,
                    ),
                };
            if i > 0 && (base_offset != next_base_offset || base_seq != next_base_seq) {
                return Err(StorageError::SegmentChainBroken {
                    segment_id: id,
                    expected_base_offset: next_base_offset,
                    found_base_offset: base_offset,
                    expected_base_seq: next_base_seq,
                    found_base_seq: base_seq,
                });
            }
            // Every NON-final ordinary segment must be sealed (the same rule v1 recovery applies).
            // A compacted segment is always born sealed, so it is always allowed mid-chain.
            if let Entry::Ordinary(o) = &entry {
                if !is_last && !o.sealed {
                    return Err(StorageError::UnsealedPredecessor { segment_id: o.id });
                }
            }
            // Advance the offset/seq expectation by the COVERED span (which, for an ordinary
            // segment, reduces to the dense span). The durable-bytes and count totals charge the
            // actual on-disk record region and survivor/record count, not the covered span.
            next_base_offset = end_offset;
            next_base_seq = end_seq;
            durable_bytes =
                durable_bytes.saturating_add(valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64));
            total_record_count = total_record_count.saturating_add(rec_count);

            let slot = SegmentSlot {
                id,
                base_offset,
                record_count: rec_count,
                max_timestamp_ms: max_ts,
                compacted_covered: match &entry {
                    Entry::Ordinary(_) => None,
                    Entry::Compacted(c) => Some(c.cover),
                },
            };
            slots.push(slot);

            // The active segment is the highest-offset-range ORDINARY entry. A compacted segment is
            // never active. We track the last ordinary entry seen; because entries are offset-sorted
            // and the active ordinary segment has the highest range, the LAST ordinary entry is it.
            if let Entry::Ordinary(o) = entry {
                active_ordinary = Some(o);
            }
        }

        let next_offset = Offset::new(next_base_offset);
        let next_seq = Seq::new(next_base_seq);
        let persisted_quarantine_bytes = crate::quarantine::persisted_bytes(&fs);
        // The active segment's on-disk record bytes are subtracted back out of the sealed total only
        // when the active segment is an unsealed ordinary one (it is the WAL, not a sealed
        // predecessor). If the highest entry is a SEALED segment we roll forward (no active record
        // bytes to subtract).
        let active = active_ordinary;
        let active_is_unsealed = active.as_ref().is_some_and(|a| !a.sealed);
        let active_record_bytes = if active_is_unsealed {
            active
                .as_ref()
                .map_or(0, |a| a.valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64))
        } else {
            0
        };
        let sealed_record_bytes = durable_bytes.saturating_sub(active_record_bytes);

        let mut log = Log {
            fs,
            clock,
            config,
            active: None,
            active_id: active.as_ref().map_or(0, |a| a.id),
            next_offset,
            next_seq,
            flushed_offset: next_offset,
            synced_offset: next_offset,
            segments: slots,
            sealed_record_bytes,
            total_record_count,
            recovered_truncated_bytes: 0,
            loss_report: LossReport::new(),
            quarantined_bytes: persisted_quarantine_bytes,
            logical_bytes_written: 0,
            physical_bytes_written: 0,
            unsynced_record_bytes: 0,
            physical_bytes_written_today: 0,
            physical_write_today_day: 0,
            daily_budget_sheds: 0,
            // Resident seek indexes (#483) are built lazily on the read path; recovery (including
            // the compaction-aware path) starts them empty. Compacted (v2, sparse) segments are
            // never indexed here — they keep the v2 scan read path.
            segment_indexes: std::cell::RefCell::new(std::collections::HashMap::new()),
            // The compacted (sparse) seek index map (#481) starts empty and is filled lazily on the
            // read path; the recovered chain may include compacted segments, indexed on first read.
            compacted_indexes: std::cell::RefCell::new(std::collections::HashMap::new()),
            sealed_readers: SealedReaderCache::new(DEFAULT_SEALED_READER_CACHE_CAP),
            // The off-actor read plane (#539) is built lazily on the first consumer `read_plane()`.
            read_plane: std::cell::RefCell::new(None),
            pending_roll: None,
            // Tiered storage (#643): the cold manifest is ATTACHED after construction by
            // `open` (which reads `cold-manifest.ckpt` if present); the backend + policy are
            // injected post-open. A never-offloaded log leaves all three at their off defaults.
            cold_manifest: None,
            cold_store: None,
            cold_config: ColdStorageConfig::default(),
        };

        // #836: record the covered survivor loss of any COMMITTED-but-corrupt compacted segment the
        // reconciliation quarantined + removed above. These are real DATA-loss events (unlike the
        // orphan/superseded unlinks, which lose nothing), so they must show up in the recovered
        // log's `LossReport` and be subject to the I3 bounded-loss caps below, exactly like an
        // active-segment corruption skip. The forensic bytes were already copied to `quarantine/`
        // during the fold; `quarantined_bytes` was seeded from `persisted_bytes` above, which
        // already reflects them.
        for event in corrupt_losses {
            log.loss_report.push(event);
        }

        match active {
            // The highest-range entry is an UNSEALED ordinary segment: it is the active WAL. Drop
            // any torn or unsynced tail and resume appending at the valid prefix end, exactly as the
            // v1 recovery does.
            Some(a) if !a.sealed => {
                let name = segment_file_name(a.id);
                let file = log.fs.open(&name)?;
                if a.valid_end < a.file_len {
                    // As in the v1 recovery: the REPORTED span (loss event, quarantine capture,
                    // `recovered_truncated_bytes`) is bounded at one past the tail's LAST NON-ZERO
                    // byte — an all-zero tail is the unwritten remainder of the preallocated
                    // logical extension (never acked data), truncated silently; a non-zero tail is
                    // reported and quarantined over only the bytes that were ever plausibly
                    // written, never the roll-size extension. The FILE truncation stays at
                    // `valid_end`.
                    let reported_end = crate::io::last_nonzero_end(&file, a.valid_end, a.file_len)?;
                    if reported_end > a.valid_end {
                        log.recovered_truncated_bytes = reported_end - a.valid_end;
                        let reason = a.tail_reason.unwrap_or(ReasonCode::TornTail);
                        let event = LossEvent::span(a.id, a.valid_end, reported_end, 1, reason);
                        log.loss_report.push(event);
                        if crate::quarantine::is_corruption_skip(reason) {
                            let captured = crate::quarantine::quarantine_corrupt_span(
                                &log.fs,
                                &file,
                                &event,
                                log.config.max_quarantine_bytes,
                            );
                            if captured > 0 {
                                log.quarantined_bytes = crate::quarantine::persisted_bytes(&log.fs);
                            }
                        }
                        // I3 BEFORE the destructive truncate, as in the v1 path: a cap-exceeding
                        // report (this tail event, or the #836 corrupt-compacted events already
                        // pushed above) must fail closed with the tail evidence still on disk.
                        log.enforce_loss_caps(durable_bytes)?;
                    }
                    file.set_len(a.valid_end)?;
                    file.sync_all()?;
                }
                let record_count =
                    u32::try_from(a.record_count).map_err(|_| StorageError::SegmentFull)?;
                log.active = Some(SegmentWriter::resume(
                    file,
                    a.header,
                    a.valid_end,
                    record_count,
                    a.last_seq,
                    a.max_timestamp_ms,
                ));
            }
            // The highest-range entry is a SEALED ordinary segment (a crash after sealing but before
            // the next was created): roll forward into a fresh active segment, continuing the offset
            // and sequence space.
            Some(a) => {
                let next_id = a.id.checked_add(1).ok_or(StorageError::SegmentFull)?;
                log.start_segment(next_id, next_seq, next_offset)?;
            }
            // No ordinary segment at all (every surviving segment is compacted): roll forward into a
            // fresh active segment past the highest covered range, so appends resume into a clean
            // segment. The fresh id is one past the highest segment id seen.
            None => {
                let next_id = log
                    .segments
                    .iter()
                    .map(|s| s.id)
                    .max()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(StorageError::SegmentFull)?;
                log.start_segment(next_id, next_seq, next_offset)?;
            }
        }

        // I3 bounded-loss caps, identical to the v1 path: fail closed rather than accept unbounded
        // silent loss. The orphan/superseded reconciliation unlinks lose nothing (their data is
        // present elsewhere), so the only loss events here are an active-segment torn tail (already
        // cap-checked BEFORE its truncate above) and any #836 committed-but-corrupt compacted
        // segment the reconciliation quarantined — the latter is exactly why this backstop matters
        // on the no-tail-event paths, so a cascade of corrupt compacted segments fails closed
        // rather than silently dropping every survivor they covered.
        log.enforce_loss_caps(durable_bytes)?;
        Ok(log)
    }

    /// Creates a fresh segment `id` with the given base, makes it durable (header sync
    /// plus dir sync), and installs it as the active segment.
    fn start_segment(
        &mut self,
        id: u64,
        base_seq: Seq,
        base_offset: Offset,
    ) -> Result<(), StorageError> {
        let header = SegmentHeader {
            segment_id: id,
            base_seq,
            base_offset,
            created_unix_ms: self.clock.now_unix_millis(),
            flags: 0,
        };
        let file = self.fs.create_new(&segment_file_name(id))?;
        // Preallocate the new active segment to the full roll size BEFORE the first append: the
        // production backend reserves the blocks AND advances the LOGICAL length to the roll size
        // (`docs/PREALLOCATION.md`), so every steady-state append lands inside both the reserved
        // space and the logical size and the per-commit fdatasync carries no i_size update (the
        // one-time unwritten→written extent-state conversions are still journaled on first touch;
        // `io.rs` has the honest accounting). This is a BEST-EFFORT optimization: a filesystem
        // with no reservation primitive (or any preallocate error) degrades to today's
        // grow-on-append, so the failure is SWALLOWED and never fails the create. The unwritten
        // tail is zeros that recovery's torn-tail scan stops at (the frozen #45 zero-window
        // fixture) and truncates SILENTLY (never-written space, not loss), and `seal` truncates
        // the file down to the footer end, so preallocation cannot break recovery or footer
        // discovery: a freshly preallocated empty segment (header then zeros) recovers as no
        // records, and a partially-written one recovers to its longest valid prefix. A genuine
        // create-time out-of-space is therefore not surfaced here as a distinct fail-fast event;
        // it falls back to grow-on-append and surfaces at the append/sync as it does today (the
        // doc's ENOSPC-to-`AtCapacity` routing is a forward refinement, not required for
        // correctness).
        let _ = file.preallocate(self.config.max_segment_bytes);
        let mut writer = SegmentWriter::create(file, header)?;
        writer.sync()?; // the header is durable...
        self.fs.sync_dir()?; // ...and so is its directory entry.
        self.install_started_segment(writer, id, base_offset);
        Ok(())
    }

    /// Installs a freshly created + durably-headered active segment into the in-memory log state: the
    /// active writer, its id, its (empty) retention slot, and its empty resident seek index, and
    /// charges the header's physical write volume. The IO half (create + preallocate + header/dir
    /// fsync) is done by the caller ([`start_segment`](Log::start_segment) or
    /// [`create_or_defer_segment`](Log::create_or_defer_segment)); this is the infallible commit that
    /// makes the new segment the active one once it is durable.
    fn install_started_segment(
        &mut self,
        writer: SegmentWriter<F::File>,
        id: u64,
        base_offset: Offset,
    ) {
        // The segment header is physical write volume an SSD/eMMC wear model charges (#118): the
        // 64-byte header is on disk now (the `sync` above made it durable). Counted here, after the
        // create succeeded, so a failed create never inflates the physical-bytes total.
        self.charge_physical(SEGMENT_HEADER_LEN as u64);
        self.active = Some(writer);
        self.active_id = id;
        // A fresh active segment starts empty; its per-segment retention metadata is filled in
        // when it is later sealed on a roll (from the writer's running totals).
        self.segments.push(SegmentSlot {
            id,
            base_offset: base_offset.get(),
            record_count: 0,
            max_timestamp_ms: 0,
            // A freshly started active segment is always an ordinary (v1) segment; only the
            // off-hot-path cleaner ever writes a compacted segment, and it never becomes active.
            compacted_covered: None,
        });
        // Seed an EMPTY resident seek index (#483, sparse #537) for the new active segment: appends
        // EXTEND it in lockstep (so the consume hot path hits the cache without ever rebuilding), and
        // its `valid_end` tracks the writer's flushed prefix. A fresh segment holds no records yet, so
        // `valid_end` is the header end and the first appended frame (which starts AT the header end)
        // is the first anchor (`next_anchor_at` = header end). The id is fresh (ADR 0002), so no stale
        // entry can exist.
        self.segment_indexes.borrow_mut().insert(
            id,
            SegmentIndex {
                base_offset: base_offset.get(),
                anchors: Vec::new(),
                record_count: 0,
                stride: SEGMENT_INDEX_STRIDE_BYTES,
                next_anchor_at: SEGMENT_HEADER_LEN as u64,
                valid_end: SEGMENT_HEADER_LEN as u64,
                flushed_end: SEGMENT_HEADER_LEN as u64,
            },
        );
    }

    /// The next FRESH segment id, strictly greater than any id ever used: `max(active_id, the
    /// highest slot id) + 1`. With compaction (#337) a compacted segment carries a HIGH id but a LOW
    /// covered range, so the highest slot id can exceed `active_id`; a fresh id must clear it to
    /// honor ADR 0002 (ids never recycled). For a plain log the max id is `active_id`, so this is
    /// `active_id + 1`.
    fn next_fresh_segment_id(&self) -> Result<u64, StorageError> {
        let highest = self
            .segments
            .iter()
            .map(|s| s.id)
            .max()
            .unwrap_or(self.active_id)
            .max(self.active_id);
        highest.checked_add(1).ok_or(StorageError::SegmentFull)
    }

    /// Seals the active segment and starts the next one, continuing the offset and
    /// sequence space. The old segment is sealed (durable footer) BEFORE the new segment
    /// becomes discoverable, so a crash in between is recovered by rolling forward.
    fn roll(&mut self) -> Result<(), StorageError> {
        // The next active segment id is strictly greater than ANY id ever used (ADR 0002), which now
        // includes COMPACTED segments (#337): a compacted segment took a FRESH high id, so the
        // active roll must skip past it rather than collide with `active_id + 1`. A plain log (no
        // compacted segment) has `active_id` as the max id, so this reduces to `active_id + 1`.
        let next_id = self.next_fresh_segment_id()?;
        // Take the active writer out and seal it. From here, any error leaves `active` as
        // `None` and the writer frozen; surface `WriterFrozen` (the fatal, never-retried
        // state) rather than the raw IO error, so the in-flight produce ends its session
        // instead of retrying against a dead writer.
        let old = self.active.take().ok_or(StorageError::WriterFrozen)?;
        // The segment about to be sealed contributes its record bytes to the sealed total, so
        // the live durable-record-bytes total stays O(1) without rescanning every segment.
        let old_record_bytes = old.write_pos().saturating_sub(SEGMENT_HEADER_LEN as u64);
        // Freeze the sealed segment's retention metadata into its slot from the writer's running
        // totals, so the count- and time-retention reaper can consult it O(1) (no file rescan).
        // The active segment is always the LAST slot (the most recent `start_segment` pushed it).
        let old_record_count = u64::from(old.record_count());
        let old_max_timestamp_ms = old.max_timestamp_ms();
        if let Some(slot) = self.segments.last_mut() {
            slot.record_count = old_record_count;
            slot.max_timestamp_ms = old_max_timestamp_ms;
        }
        old.seal().map_err(|_| StorageError::WriterFrozen)?;
        // The seal flushed and fsynced every pending byte, so the just-sealed segment's whole record
        // region is now in the file: raise ITS resident seek index `flushed_end` to its full
        // `valid_end` so a read of this now-sealed predecessor seeks over its entire prefix (#537).
        // Done by the OLD active id, BEFORE `start_segment` repoints `active_id` to the new segment.
        if let Some(idx) = self.segment_indexes.borrow_mut().get_mut(&self.active_id) {
            idx.flushed_end = idx.valid_end;
        }
        // The segment footer is durable physical write volume (#118): `seal` wrote and fsynced the
        // 32-byte footer, so charge it to the wear total here (the per-record frames and this
        // segment's header were charged on append and `start_segment`).
        self.charge_physical(SEGMENT_FOOTER_LEN as u64);
        self.sealed_record_bytes = self.sealed_record_bytes.saturating_add(old_record_bytes);
        // Sealing fsynced every record in the old segment, so both the visible and the DURABLE
        // head advance to the start of the new segment even without an explicit sync. Advancing
        // `synced_offset` here is what bounds a relaxed level's loss to the open segment's unsynced
        // tail: a roll is a real durability barrier, so every record up to it is durable (#341). These
        // reflect the SEAL (already durable), so they hold even if the create below is deferred by a
        // transient fault (#867): the durable head is `next_offset` the moment the predecessor sealed.
        self.flushed_offset = self.next_offset;
        self.synced_offset = self.next_offset;
        // The seal made every previously-unsynced record durable and the new active segment is empty,
        // so the at-risk exposure resets to zero: this is what bounds the relaxed levels' loss to at
        // most one open segment's worth of records (#341, #379).
        self.unsynced_record_bytes = 0;
        // Create the next active segment. The predecessor is already durably sealed, so a failure
        // here loses NO data and must not permanently freeze the writer on a TRANSIENT resource fault
        // (EMFILE / a short ENOSPC at the roll boundary, #867): `create_or_defer_segment` records a
        // pending roll and surfaces the raw, NON-FATAL error, and the next write retries the create.
        let result = self.create_or_defer_segment(next_id, self.next_seq, self.next_offset);
        // A roll SEALED a segment: the sealed set changed, so REPUBLISH the whole off-actor read
        // plane (#539) — the new immutable sealed snapshot FIRST (Release), then the new frontier
        // (Release). After this the just-sealed segment is served lock-free off-actor; before it the
        // active-tail fallback served those same records, so consume behavior is identical across the
        // seal. A no-op if no consumer has built the plane. Done AFTER the create so the new active
        // slot is installed first (so `build_sealed_descriptor` includes the just-sealed predecessor
        // in the sealed prefix); on a DEFERRED roll there is no active slot and the predecessor is
        // served as a fully-sealed prefix (#867).
        self.republish_read_plane();
        result
    }

    /// Creates the next active segment for a roll, distinguishing a TRANSIENT create fault (defer and
    /// retry) from a genuine DURABILITY-BARRIER fault (freeze), so a recoverable resource fault no
    /// longer permanently freezes the writer (#867).
    ///
    /// The predecessor was already sealed and fsynced before this is reached, so NOTHING here can lose
    /// durable data, and reads keep serving off the sealed plane regardless of the outcome:
    /// - **Create phase** (`create_new` + `SegmentWriter::create`): a failure is a transient resource
    ///   fault (EMFILE from fd exhaustion, a short ENOSPC a reap will clear, EINTR). Record a
    ///   [`PendingRoll`] and return the RAW error, which is NOT [`StorageError::WriterFrozen`], so
    ///   [`EngineError::is_fatal`] is false and the writer stays RESUMABLE: the next write retries via
    ///   [`ensure_writable`](Log::ensure_writable), so the writer resumes once the fault clears.
    /// - **Durability-barrier phase** (the header / dir fsync): a failure means the disk cannot make
    ///   even the 64-byte header durable — a genuine durability fault — so FREEZE
    ///   ([`StorageError::WriterFrozen`]), exactly as a failed sync on the append path does, so a dead
    ///   disk is surfaced fail-stop to health rather than retried forever.
    ///
    /// Any partial orphan from a prior failed attempt is removed first so the retry's `create_new`
    /// cannot collide on the id; the orphan holds nothing durable (the predecessor is already sealed),
    /// so the remove is safe and best-effort.
    fn create_or_defer_segment(
        &mut self,
        id: u64,
        base_seq: Seq,
        base_offset: Offset,
    ) -> Result<(), StorageError> {
        let _ = self.fs.remove(&segment_file_name(id));
        let header = SegmentHeader {
            segment_id: id,
            base_seq,
            base_offset,
            created_unix_ms: self.clock.now_unix_millis(),
            flags: 0,
        };
        // Create phase — a failure is transient: DEFER (the predecessor is durably sealed, no loss).
        let defer = |this: &mut Self, e: StorageError| -> StorageError {
            let _ = this.fs.remove(&segment_file_name(id));
            this.pending_roll = Some(PendingRoll {
                id,
                base_seq,
                base_offset,
            });
            e
        };
        let file = match self.fs.create_new(&segment_file_name(id)) {
            Ok(f) => f,
            Err(e) => return Err(defer(self, StorageError::Io(e))),
        };
        let _ = file.preallocate(self.config.max_segment_bytes);
        let mut writer = match SegmentWriter::create(file, header) {
            Ok(w) => w,
            Err(e) => return Err(defer(self, e)),
        };
        // Durability-barrier phase — a failure is a genuine durability fault: FREEZE. Clear any
        // pending roll so the freeze is TERMINAL even when this is a retry of a previously-deferred
        // roll, matching `WriterFrozen`'s "fatal, never-retried" contract (a later write must not
        // resume it via `ensure_writable`). The orphan new segment is recovered at boot (#868).
        if writer.sync().is_err() || self.fs.sync_dir().is_err() {
            self.pending_roll = None;
            return Err(StorageError::WriterFrozen);
        }
        // Durable: install the new active segment and clear the pending roll.
        self.install_started_segment(writer, id, base_offset);
        self.pending_roll = None;
        Ok(())
    }

    /// Completes a roll whose active-segment creation was deferred by a transient fault (#867), so
    /// the writer resumes once the fault clears. A no-op when no roll is pending (the steady state).
    /// Called at the top of every write entry point: if the deferred create still fails it returns
    /// the raw (non-fatal) error and stays pending, so the write is refused without freezing.
    fn ensure_writable(&mut self) -> Result<(), StorageError> {
        if let Some(p) = self.pending_roll {
            self.create_or_defer_segment(p.id, p.base_seq, p.base_offset)?;
        }
        Ok(())
    }

    fn active(&self) -> Result<&SegmentWriter<F::File>, StorageError> {
        self.active.as_ref().ok_or(StorageError::WriterFrozen)
    }

    /// Charges `bytes` of real physical write volume to BOTH the process-lifetime
    /// `physical_bytes_written` total and the per-UTC-day `physical_bytes_written_today` accumulator
    /// (the daily-write-budget meter), rolling the today-meter over to zero first if the clock seam
    /// has crossed into a new UTC day (#118). The day index is `now_unix_millis / 86_400_000`,
    /// measured on the injected clock seam so the deterministic simulation stays reproducible (no
    /// wall-clock read). Saturating; never panics.
    fn charge_physical(&mut self, bytes: u64) {
        self.roll_physical_day_if_needed();
        self.physical_bytes_written = self.physical_bytes_written.saturating_add(bytes);
        self.physical_bytes_written_today = self.physical_bytes_written_today.saturating_add(bytes);
    }

    /// The current UTC day index on the clock seam: `now_unix_millis / 86_400_000`.
    fn current_utc_day(&self) -> u64 {
        const MILLIS_PER_DAY: u64 = 24 * 60 * 60 * 1000;
        self.clock.now_unix_millis() / MILLIS_PER_DAY
    }

    /// Resets the per-day physical-write meter to zero when the clock seam has advanced to a new UTC
    /// day, so the daily write budget (#118) refreshes each day with no background timer. A no-op
    /// within the same day. Idempotent.
    fn roll_physical_day_if_needed(&mut self) {
        let day = self.current_utc_day();
        if day != self.physical_write_today_day {
            self.physical_write_today_day = day;
            self.physical_bytes_written_today = 0;
        }
    }

    /// The log's current total durable RECORD bytes: the sealed predecessors' record bytes
    /// plus the active segment's (`write_pos - SEGMENT_HEADER_LEN`). This is the same quantity
    /// recovery sums as `durable_bytes` and the one [`LogConfig::max_total_bytes`] caps. Cheap
    /// (O(1)): it reads the running sealed total, never rescanning every segment. A frozen
    /// writer has no active segment, so its active term is zero.
    #[must_use]
    pub fn durable_record_bytes(&self) -> u64 {
        let active_record_bytes = self.active.as_ref().map_or(0, |w| {
            w.write_pos().saturating_sub(SEGMENT_HEADER_LEN as u64)
        });
        self.sealed_record_bytes.saturating_add(active_record_bytes)
    }

    /// The log's total durable RECORD COUNT across every segment (sealed predecessors and the
    /// active one). This is the quantity the count-retention bound ([`RetentionBounds::max_messages`])
    /// is measured against. Cheap (O(1)): it reads the running total maintained on append and
    /// reap, never rescanning every segment. It matches a fresh reopen's recomputed count.
    #[must_use]
    pub fn durable_record_count(&self) -> u64 {
        self.total_record_count
    }

    /// The total LOGICAL bytes appended since this log was opened (#118): the sum of each record's
    /// user payload (key + headers + payload), EXCLUDING all framing. The denominator of the flash
    /// write-amplification ratio. Process-lifetime monotonic (a reap never lowers it). Exposed as
    /// the `ironbus_logical_bytes_written` counter on `/metrics`.
    #[must_use]
    pub fn logical_bytes_written(&self) -> u64 {
        self.logical_bytes_written
    }

    /// The total PHYSICAL bytes appended to segment files since this log was opened (#118): every
    /// record FRAME (header + body + trailer) plus every segment HEADER and FOOTER. The real on-disk
    /// write volume a flash-wear model charges, and the numerator of the write-amplification ratio.
    /// Process-lifetime monotonic (a reap frees disk but does not un-write the charged bytes).
    /// Exposed as the `ironbus_physical_bytes_written` counter on `/metrics`.
    #[must_use]
    pub fn physical_bytes_written(&self) -> u64 {
        self.physical_bytes_written
    }

    /// An HONEST estimate of the log's LIVE on-disk RESIDENT framed bytes (#493): the durable
    /// RECORD bytes the byte cap is measured against PLUS the per-segment framing the cap basis
    /// omits — every live segment's 64-byte header and every SEALED segment's 32-byte footer (the
    /// active segment has no footer until it is sealed). This is the quantity an operator should
    /// compare against a disk budget, since [`LogConfig::max_total_bytes`] caps only the record
    /// region and so reads ~`1.85x` low on small records where framing dominates.
    ///
    /// It is LIVE (reap-tracking): it is built from [`Log::durable_record_bytes`] and the current
    /// [`Log::segment_count`], both of which fall as retention reclaims segments — UNLIKE
    /// [`Log::physical_bytes_written`], which is a write-AMPLIFICATION counter that never decreases.
    /// That is exactly why the cap cannot simply switch its basis to `physical_bytes_written`: a
    /// monotonic meter would tighten the cap after every reap and eventually wedge the writer.
    ///
    /// What this estimate DELIBERATELY excludes, because both are backend- and config-dependent
    /// (an honest single number cannot fold them in):
    /// - DISK PREALLOCATION: a disk-backed broker preallocates the active segment to
    ///   `max_segment_bytes` (default 64 MiB), so its true disk footprint is up to one
    ///   `max_segment_bytes` higher than this estimate; the in-memory backend reserves nothing.
    /// - the in-memory backend's IMAGE multiplier (the historical 2x copy, being reduced to 1x in
    ///   #492), and the per-segment index cache.
    ///
    /// `docs/CONFIG.md` documents the full per-backend multiplier (record region → resident → disk)
    /// so an operator can size a memory or disk budget without overshooting. Cheap (O(1)).
    #[must_use]
    pub fn resident_bytes_estimate(&self) -> u64 {
        let segments = self.segments.len() as u64;
        // Every live segment carries a 64-byte header; every SEALED segment also carries a 32-byte
        // footer. The active segment (the last slot) has no durable footer yet, so the footer count
        // is `segments - 1` (saturating to 0 when the log somehow holds no segments).
        let header_overhead = segments.saturating_mul(SEGMENT_HEADER_LEN as u64);
        let footer_overhead = segments
            .saturating_sub(1)
            .saturating_mul(SEGMENT_FOOTER_LEN as u64);
        self.durable_record_bytes()
            .saturating_add(header_overhead)
            .saturating_add(footer_overhead)
    }

    /// The physical bytes written so far on the current UTC day (#118): the daily-write-budget meter,
    /// reset to zero at each UTC day boundary on the clock seam. Always tracked (even with no budget
    /// configured), so the accounting is visible without enabling the shed. Exposed as the
    /// `ironbus_physical_bytes_written_today` gauge on `/metrics`.
    ///
    /// This is the value as of the last write; a scrape between writes does not roll the day forward
    /// (the meter rolls lazily on the next charged write), so a long-idle broker may briefly report
    /// yesterday's total until its next append. The budget shed itself always rolls the day first, so
    /// the governor decision is never stale.
    #[must_use]
    pub fn physical_bytes_written_today(&self) -> u64 {
        self.physical_bytes_written_today
    }

    /// The OPT-IN daily physical write budget in bytes (`0` = the governor is off), echoed from the
    /// effective [`LogConfig`] for the `ironbus_daily_physical_write_budget_bytes` gauge (#118).
    #[must_use]
    pub fn daily_physical_write_budget_bytes(&self) -> u64 {
        self.config.daily_physical_write_budget_bytes
    }

    /// The count of appends SHED because the daily physical write budget was reached (#118): the
    /// flash-wear governor's over-budget signal, distinct from the disk-full byte-cap shed.
    /// Process-lifetime monotonic. Exposed as the `ironbus_daily_write_budget_sheds_total` counter.
    #[must_use]
    pub fn daily_budget_sheds(&self) -> u64 {
        self.daily_budget_sheds
    }

    /// The number of segments the log currently holds: every sealed predecessor plus the one
    /// active segment (a frozen writer's slots still count). It falls as retention or a forced
    /// reap reclaims old sealed segments. Cheap (O(1)): the slot vector length. Read-only, for
    /// the introspection endpoint (#99).
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// The log's effective configuration (the segment-size soft cap and the durable-log byte
    /// hard cap). Read-only echo for the introspection endpoint (#99).
    #[must_use]
    pub fn config(&self) -> LogConfig {
        self.config
    }

    /// The log offset the next appended record will receive.
    #[must_use]
    pub fn next_offset(&self) -> Offset {
        self.next_offset
    }

    /// The sequence number the next appended record will receive.
    #[must_use]
    pub fn next_seq(&self) -> Seq {
        self.next_seq
    }

    /// The id of the active segment.
    #[must_use]
    pub fn active_segment_id(&self) -> u64 {
        self.active_id
    }

    /// Borrows the underlying filesystem (for inspection and tests).
    #[must_use]
    pub fn filesystem(&self) -> &F {
        &self.fs
    }

    /// Consumes the log and returns the underlying filesystem, so it can be reopened.
    #[must_use]
    pub fn into_filesystem(self) -> F {
        self.fs
    }

    /// Appends one record, rolling to a new segment first if the active one has reached
    /// the configured size, and returns the assigned log offset. The record is durable
    /// only after [`Log::sync`].
    ///
    /// # Errors
    /// Returns [`StorageError::AtCapacity`] (non-fatal) if the durable-log byte cap
    /// ([`LogConfig::max_total_bytes`]) is set and the log is at or over it, in which case
    /// nothing is written and no offset or sequence advances. Returns the distinct, FINAL
    /// [`StorageError::DailyWriteBudgetExceeded`] (non-fatal) if the opt-in daily physical write
    /// budget ([`LogConfig::daily_physical_write_budget_bytes`]) is set and today's physical write
    /// volume is at or over it, again writing nothing and advancing nothing (a reap can never
    /// relieve it, so it is final). Returns [`StorageError::SegmentFull`] if the offset or sequence
    /// space is exhausted or the record is too large to frame, [`StorageError::WriterFrozen`] if a
    /// prior fatal error froze the writer, or an IO error from the write.
    pub fn append(&mut self, record: &Append<'_>) -> Result<Offset, StorageError> {
        self.append_inner(
            AppendSource::Encode {
                record,
                precomputed: None,
                subject: b"",
                stream_tag: b"",
            },
            true,
        )
    }

    /// Appends one record ALSO storing `subject` as the optional subject field (#594), otherwise
    /// identical to [`Log::append`] (same cap/budget/roll prologue, id reservation, seek-index and
    /// write-amplification accounting). An EMPTY `subject` is byte-for-byte [`Log::append`]; a
    /// non-empty subject is stored with its own CRC inside the CRC'd record frame, immediately after
    /// the header. The caller validates the subject grammar at the wire boundary.
    ///
    /// # Errors
    /// Same as [`Log::append`].
    pub fn append_with_subject(
        &mut self,
        record: &Append<'_>,
        subject: &[u8],
    ) -> Result<Offset, StorageError> {
        self.append_inner(
            AppendSource::Encode {
                record,
                precomputed: None,
                subject,
                stream_tag: b"",
            },
            true,
        )
    }

    /// Appends one record ALSO storing `stream_tag` as the optional stream-tag field (#597), the
    /// shared-WAL demux key that names the stream this record belongs to in a SHARED, interleaved
    /// commit log. Otherwise identical to [`Log::append`] (same cap/budget/roll prologue, id
    /// reservation, seek-index and write-amplification accounting). An EMPTY `stream_tag` is
    /// byte-for-byte [`Log::append`]; a non-empty tag is stored with its own CRC inside the CRC'd
    /// record frame, immediately after the header. Mutually exclusive with a stored subject. The
    /// caller supplies a validated stream name as the tag ([`crate::shared_wal::SharedWal`]).
    ///
    /// # Errors
    /// Same as [`Log::append`].
    pub fn append_with_stream_tag(
        &mut self,
        record: &Append<'_>,
        stream_tag: &[u8],
    ) -> Result<Offset, StorageError> {
        self.append_inner(
            AppendSource::Encode {
                record,
                precomputed: None,
                subject: b"",
                stream_tag,
            },
            true,
        )
    }

    /// The precomputed-body-checksum twin of [`Log::append_with_subject`] (#594/#830).
    ///
    /// # Errors
    /// Same as [`Log::append`].
    pub fn append_precomputed_with_subject(
        &mut self,
        record: &Append<'_>,
        checksums: BodyChecksums,
        subject: &[u8],
    ) -> Result<Offset, StorageError> {
        self.append_inner(
            AppendSource::Encode {
                record,
                precomputed: Some(checksums),
                subject,
                stream_tag: b"",
            },
            true,
        )
    }

    /// Appends one record whose body checksums were PRE-COMPUTED off the single-writer append actor,
    /// on the producing connection thread that already held the body bytes (issue #830). Identical to
    /// [`Log::append`] in every observable effect — the same cap/budget/roll prologue, id reservation,
    /// seek-index and write-amplification accounting, and the SAME on-disk frame bytes — except the
    /// body CRC32C (and, for a large body, the xxh3-64) come from `checksums` rather than being
    /// computed on the serialized append path. The caller GUARANTEES `checksums` describes `record`'s
    /// exact stored body; a mismatch is not a safety hazard (the checksum is re-validated on read) but
    /// would durably store a self-corrupt record.
    ///
    /// # Errors
    /// Same as [`Log::append`].
    pub fn append_precomputed(
        &mut self,
        record: &Append<'_>,
        checksums: BodyChecksums,
    ) -> Result<Offset, StorageError> {
        self.append_inner(
            AppendSource::Encode {
                record,
                precomputed: Some(checksums),
                subject: b"",
                stream_tag: b"",
            },
            true,
        )
    }

    /// Appends an already-sealed, already-VALIDATED frame VERBATIM — the follower replication ingest
    /// fast path (#820). `frame` is one complete on-disk record frame the caller has just decoded in
    /// place with the intact-record predicate ([`codec::decode`]); `view` is that decode's result.
    /// The leader already produced the canonical frame and the follower assigns the SAME
    /// `seq`/offset positionally, so the frame is byte-identical to what [`Log::append`] would
    /// re-encode from `view` — copying it verbatim skips the redundant re-frame + re-checksum (the
    /// crc32c-over-header, crc32c-over-body, and, for large bodies, xxh3-64 that the decode just
    /// verified). Everything else — the byte-cap and daily-write-budget sheds, the soft-size-cap
    /// roll, id reservation, the resident seek index, and the write-amplification meters — is
    /// IDENTICAL to [`Log::append`].
    ///
    /// The caller MUST guarantee `view.seq == self.next_seq()` (the frame's embedded, already-CRC'd
    /// sequence matches the follower's positional assignment); a debug assert checks it. This method
    /// does NOT re-validate `frame` — validation is the caller's decode step.
    ///
    /// # Errors
    /// Identical to [`Log::append`] (byte-cap / daily-budget sheds, `SegmentFull`, `WriterFrozen`, IO).
    pub fn append_frame_verbatim(
        &mut self,
        frame: &[u8],
        view: &RecordView<'_>,
    ) -> Result<Offset, StorageError> {
        self.append_inner(AppendSource::Verbatim { frame, view }, true)
    }

    /// Like [`append`](Log::append) but NEVER triggers the implicit soft-size-cap roll: the record
    /// always lands in the CURRENT active segment, even if that pushes it past `max_segment_bytes`. The
    /// caller manages segment boundaries explicitly via [`seal_active_segment`](Log::seal_active_segment).
    /// The byte-cap and daily-write-budget sheds still apply (durability and the wear governor are
    /// unchanged). Used by the geo source applier (#906) to keep a per-origin HWM marker and the records
    /// it covers in ONE segment, so a segment never seals BETWEEN them — which would strand the marker in
    /// a different fsync than its data and reopen the multi-origin double-apply window across a roll.
    ///
    /// # Errors
    /// Same as [`append`](Log::append) (byte-cap / daily-budget sheds, `SegmentFull`, `WriterFrozen`, IO),
    /// minus anything roll-specific.
    pub fn append_without_roll(&mut self, record: &Append<'_>) -> Result<Offset, StorageError> {
        self.append_inner(
            AppendSource::Encode {
                record,
                precomputed: None,
                subject: b"",
                stream_tag: b"",
            },
            false,
        )
    }

    /// Force-seal the active segment and start a fresh one — exactly the seal the implicit soft-cap roll
    /// performs (the seal fsyncs the segment via its footer). A no-op if the active segment is empty
    /// (nothing to seal). Lets a caller that appends via [`append_without_roll`](Log::append_without_roll)
    /// place a segment boundary DETERMINISTICALLY — e.g. right after a sealing trailer record — so a
    /// segment never seals between a marker and the records it covers (#906).
    ///
    /// # Errors
    /// [`StorageError::WriterFrozen`] if the writer is frozen, or an IO error from the seal's fsync.
    pub fn seal_active_segment(&mut self) -> Result<(), StorageError> {
        // Finish any roll a transient fault deferred first (#867): a pending roll already sealed the
        // predecessor, so once its empty successor is created there is nothing more to seal.
        self.ensure_writable()?;
        if self.active()?.record_count() == 0 {
            return Ok(());
        }
        self.roll()
    }

    /// Whether the active segment is at or over the soft size cap (`max_segment_bytes`) AND non-empty —
    /// i.e. the next normal [`append`](Log::append) would roll it first. A caller using
    /// [`append_without_roll`](Log::append_without_roll) consults this to decide when to place a sealing
    /// trailer record + [`seal_active_segment`](Log::seal_active_segment) (#906).
    ///
    /// # Errors
    /// [`StorageError::WriterFrozen`] if the writer is frozen.
    pub fn active_segment_at_or_over_cap(&self) -> Result<bool, StorageError> {
        // A roll deferred by a transient fault (#867) has already sealed the predecessor; its
        // not-yet-created successor will be EMPTY, so it is not at cap. Answer without a frozen error
        // (this is a `&self` query, so it cannot itself complete the deferred create).
        if self.pending_roll.is_some() {
            return Ok(false);
        }
        let active = self.active()?;
        Ok(active.write_pos() >= self.config.max_segment_bytes && active.record_count() > 0)
    }

    /// Write ONE record into the active segment, either RE-ENCODING it through the codec or copying
    /// an already-validated verbatim frame (#820). `seq` is the id the log reserved for it. Returns
    /// `(offset, pos_before, frame_len)`: the assigned log offset, the byte position the frame starts
    /// at in the segment, and its encoded byte length. Either path advances the writer's `write_pos`
    /// by exactly the frame length, so `frame_len` (the write-position delta) is measured identically
    /// and equals `frame.len()` on the verbatim path.
    fn write_source(
        &mut self,
        source: AppendSource<'_>,
        seq: Seq,
    ) -> Result<(Offset, u64, u64), StorageError> {
        let (offset, pos_before) = match source {
            AppendSource::Encode {
                record,
                precomputed,
                subject,
                stream_tag,
            } => {
                let view = RecordView {
                    seq,
                    timestamp_ms: record.timestamp_ms,
                    flags: record.flags,
                    key: record.key,
                    headers: record.headers,
                    payload: record.payload,
                };
                let writer = self.active.as_mut().ok_or(StorageError::WriterFrozen)?;
                let pos_before = writer.write_pos();
                // Offload the body checksum onto the producing connection thread when it precomputed
                // it (#830); otherwise the codec computes it here as before. A non-empty subject
                // (#594) routes to the subject-storing writer path and a non-empty stream tag (#597)
                // to the tag-storing path (the two are mutually exclusive); an empty pair is
                // byte-for-byte the historical frame.
                let offset = if stream_tag.is_empty() {
                    match (precomputed, subject.is_empty()) {
                        (Some(checksums), true) => writer.append_precomputed(&view, checksums)?,
                        (None, true) => writer.append(&view)?,
                        (Some(checksums), false) => {
                            writer.append_precomputed_with_subject(&view, subject, checksums)?
                        }
                        (None, false) => writer.append_with_subject(&view, subject)?,
                    }
                } else {
                    match precomputed {
                        Some(checksums) => writer
                            .append_precomputed_with_stream_tag(&view, stream_tag, checksums)?,
                        None => writer.append_with_stream_tag(&view, stream_tag)?,
                    }
                };
                (offset, pos_before)
            }
            AppendSource::Verbatim { frame, view } => {
                // Byte-identity invariant: the follower assigns `seq` positionally, and the copied
                // frame carries the leader's embedded (already-CRC'd) `seq`. They MUST match, or the
                // verbatim bytes would diverge from what the encode path produces. The caller
                // (replication ingest) enforces this with a typed error; assert it here too.
                debug_assert_eq!(
                    view.seq, seq,
                    "verbatim frame seq must equal the follower's positional next_seq (#820)"
                );
                let writer = self.active.as_mut().ok_or(StorageError::WriterFrozen)?;
                let pos_before = writer.write_pos();
                let offset = writer.append_verbatim(frame, seq, view.timestamp_ms)?;
                (offset, pos_before)
            }
        };
        // The FRAME length is the writer's write-position delta across the append (the segment writer
        // advances `write_pos` by exactly the encoded record's byte length: header + body + trailer).
        // Measuring the delta avoids re-encoding the record just to size it.
        let frame_len = self
            .active
            .as_ref()
            .map_or(0, |w| w.write_pos().saturating_sub(pos_before));
        Ok((offset, pos_before, frame_len))
    }

    fn append_inner(
        &mut self,
        source: AppendSource<'_>,
        allow_roll: bool,
    ) -> Result<Offset, StorageError> {
        // The producer-supplied logical content lengths (key + headers + payload, no framing) drive
        // the write-amplification meters below and are the ONLY per-source difference before the
        // write. Reading them once up front keeps the cap / budget / roll prologue source-agnostic.
        let (key_len, headers_len, payload_len) = match &source {
            AppendSource::Encode { record, .. } => {
                (record.key.len(), record.headers.len(), record.payload.len())
            }
            AppendSource::Verbatim { view, .. } => {
                (view.key.len(), view.headers.len(), view.payload.len())
            }
        };
        // Hard durable-log byte cap (the drop-new shed): when the log is at or over the cap,
        // reject the produce and write nothing, advancing no offset or sequence. The check is
        // at-or-over BEFORE the append (like the segment cap), so the log overshoots by at most
        // the last record. A record on an EMPTY log (no durable record bytes yet) is always
        // written, so an oversized first record is not wedged out. This is non-fatal: the
        // writer stays live, so a later produce succeeds once retention (#13) frees space.
        let cap = self.config.max_total_bytes;
        if cap != 0 {
            let total = self.durable_record_bytes();
            if total >= cap && total > 0 {
                return Err(StorageError::AtCapacity {
                    durable_bytes: total,
                    cap,
                });
            }
        }

        // OPT-IN daily PHYSICAL write budget (#118), the flash-wear governor: when today's physical
        // write volume is at or over the budget, shed this produce with the DISTINCT, FINAL
        // `DailyWriteBudgetExceeded` error (NOT `AtCapacity`). This is a clean PRE-WRITE drop-new
        // reject (it runs at the top of append, before any write, roll, or id reservation, so
        // nothing is written and no offset or sequence advances) AND it is FINAL: no reap ever
        // lowers today's physical-write meter, so the engine must never enter the `DropOldest`
        // reap-retry loop on it (which is why it is a separate variant from the byte-cap shed).
        // Durability is never weakened (the record is dropped, never written unsynced). The day
        // meter is rolled first so the decision is never stale across a UTC day boundary. Like the
        // byte cap, the at-or-over check requires the meter to be NON-ZERO, so the FIRST write of
        // each day always goes through even if the budget is smaller than one record (the broker
        // always makes daily progress).
        let budget = self.config.daily_physical_write_budget_bytes;
        if budget != 0 {
            self.roll_physical_day_if_needed();
            let today = self.physical_bytes_written_today;
            if today >= budget && today > 0 {
                self.daily_budget_sheds = self.daily_budget_sheds.saturating_add(1);
                return Err(StorageError::DailyWriteBudgetExceeded {
                    bytes_today: today,
                    budget,
                });
            }
        }

        // Complete any roll a transient fault deferred (#867) before touching the writer, so a
        // momentary EMFILE/ENOSPC at a previous roll boundary resolves on this write instead of having
        // permanently frozen the stream. If the deferred create still fails, this returns the raw
        // (non-fatal) error and the produce is refused without freezing.
        self.ensure_writable()?;
        // Soft size cap: roll before appending if the active segment has reached the cap,
        // but never roll an empty one (so an oversized record still gets written). `allow_roll` is
        // false ONLY on the `append_without_roll` path (#906), where the caller manages segment
        // boundaries explicitly so a marker and the records it covers cannot seal apart.
        let active = self.active()?;
        if allow_roll
            && active.write_pos() >= self.config.max_segment_bytes
            && active.record_count() > 0
        {
            self.roll()?;
        }

        let seq = self.next_seq;
        // Reserve the next ids BEFORE writing, so a record is never durably written under
        // an id we cannot advance past (which would force the next append to reuse it).
        let next_seq = seq.checked_next().ok_or(StorageError::SegmentFull)?;
        let next_offset = self
            .next_offset
            .checked_next()
            .ok_or(StorageError::SegmentFull)?;
        // Lay the record into the active segment (encode-and-checksum, or copy the already-validated
        // verbatim frame). Returns the assigned offset, the frame's start byte position, and its
        // encoded length — the seek-index maintenance below needs all three.
        let (offset, pos_before, frame_len) = self.write_source(source, seq)?;
        // The ids advance only after the write returns Ok.
        self.next_seq = next_seq;
        self.next_offset = next_offset;
        // EXTEND the active segment's resident seek index (#483, sparse #537) in lockstep with the
        // append: the record's frame starts at `pos_before` (the writer's `write_pos` before this
        // append, the exact file byte offset it will occupy once flushed) and ends at `pos_before +
        // frame_len`, which becomes the new readable `valid_end`. The frame is ANCHORED only when it
        // is the first frame at or past the running `next_anchor_at` boundary (so anchors stay
        // `stride` bytes apart, byte-identical to a rebuild's sparse walk); `record_count` still
        // advances for EVERY record so the covered offset range is exact. Reads are clamped to
        // `flushed_offset`, which never runs ahead of the file, so an index entry is only ever USED
        // once its bytes are in the file. Keeping the index current here lets the consume hot path
        // seek without rebuilding. If the active entry was evicted (it never is on this path, but be
        // defensive), skip silently: a later read rebuilds.
        {
            let mut indexes = self.segment_indexes.borrow_mut();
            if let Some(idx) = indexes.get_mut(&self.active_id) {
                // The append must be contiguous with the index (dense, in-order). If it somehow is
                // not (an inconsistency that cannot occur on the single-writer path), drop the entry
                // rather than record a wrong position, so a later read rebuilds from disk.
                if idx.covered_end() == offset.get() {
                    if pos_before >= idx.next_anchor_at {
                        idx.anchors.push((offset.get(), pos_before));
                        idx.next_anchor_at = pos_before.saturating_add(idx.stride);
                    }
                    idx.record_count = idx.record_count.saturating_add(1);
                    idx.valid_end = pos_before.saturating_add(frame_len);
                } else {
                    indexes.remove(&self.active_id);
                }
            }
        }
        // Write-amplification accounting (#118), charged only after the append returned Ok (a failed
        // append wrote nothing). Logical = the STORED payload this append carries (key + headers +
        // payload, no framing); under the #430 write path the engine compresses BEFORE this append,
        // so these are post-compression stored bytes, not the producer-facing logical bytes (the
        // engine's `produced_bytes` keeps that meaning). Physical = the encoded frame actually
        // written to the segment. `physical / logical` over the run is the flash write-amplification
        // ratio, defined over stored bytes: under the default codec it can inflate for small
        // compressible payloads even as the real flash wear per user byte falls.
        let logical = key_len
            .saturating_add(headers_len)
            .saturating_add(payload_len);
        self.logical_bytes_written = self
            .logical_bytes_written
            .saturating_add(u64::try_from(logical).unwrap_or(u64::MAX));
        // The UNSYNCED exposure (#341, #379): this record's logical bytes are now appended but not yet
        // covered by a returned fdatasync, so add them to the at-risk total. A real barrier (`sync` or
        // a roll's seal) resets this to zero; a relaxed level reads it as the live bytes-at-risk.
        self.unsynced_record_bytes = self
            .unsynced_record_bytes
            .saturating_add(u64::try_from(logical).unwrap_or(u64::MAX));
        self.charge_physical(frame_len);
        // Maintain the running total record count the same way the byte total is maintained, so
        // the count-retention bound stays O(1). The active segment's records live in the writer's
        // running count; the slot's count is filled in only when the segment is sealed.
        self.total_record_count = self.total_record_count.saturating_add(1);
        Ok(offset)
    }

    /// Flushes appended records to durable storage (fdatasync). A record may be
    /// acknowledged once this returns.
    ///
    /// # Errors
    /// Returns [`StorageError::WriterFrozen`] if the writer is already frozen, or if this
    /// sync fails its durability barrier: a failed fsync freezes the writer read-only, and
    /// the freezing sync itself surfaces `WriterFrozen` (the fatal, never-retried state)
    /// rather than the raw IO error, so the in-flight produce ends its session instead of
    /// retrying against a dead writer.
    pub fn sync(&mut self) -> Result<(), StorageError> {
        // A fatal sync (a failed durability barrier) freezes the writer read-only and is never
        // retried: drop the active segment so every later append and sync returns WriterFrozen,
        // and a health check sees the degraded state. Reads keep serving the durable prefix.
        // The sync needs the writer mutably (#452: it flushes the pending buffered records to
        // the file before its fdatasync, so durable keeps its meaning).
        // Finish any transient-fault-deferred roll first (#867); the predecessor it sealed is already
        // durable, so once the empty successor exists there is nothing pending to sync.
        self.ensure_writable()?;
        self.active()?;
        let frozen = match self.active.as_mut() {
            Some(w) => w.sync().is_err(),
            None => true,
        };
        if frozen {
            self.active = None;
            return Err(StorageError::WriterFrozen);
        }
        // All appended records are now durable and become visible to readers: advance BOTH the
        // visible head and the DURABLE head, so after a `sync` the unsynced window is empty (the
        // relaxed levels' `synced_offset` catches up to the visible head, #341).
        self.flushed_offset = self.next_offset;
        self.synced_offset = self.next_offset;
        // The pending bytes were just written to the file (the `sync` flushed them before its
        // fdatasync), so the active seek index's flushed (in-file) prefix now reaches its full
        // appended prefix: reads may safely seek up to here (#537).
        self.raise_active_index_flushed_end();
        // The covering fsync just made every unsynced record durable, so the at-risk exposure is now
        // zero (#341): the next relaxed-level window measures from here.
        self.unsynced_record_bytes = 0;
        // Publish the new flushed frontier to the off-actor read plane (#539): the sealed set is
        // unchanged by a plain sync (no roll), so only the atomic frontier (a Release store) is
        // republished. A no-op if no consumer has built the plane yet.
        self.publish_flushed_frontier();
        Ok(())
    }

    /// Advances the read-visibility (flushed) head over the appended records WITHOUT issuing the
    /// covering `fdatasync` (#341, #379): the relaxed-durability primitive. The record bytes are
    /// ALREADY in the OS page cache (every [`Log::append`] called `write_all_at`, a synchronous
    /// page-cache write), so the data is readable; this only makes those page-cache writes visible
    /// to readers by raising `flushed_offset`. It does NOT make them DURABLE: a power loss before a
    /// later [`Log::sync`] (or a clean shutdown / segment roll) reverts the unsynced tail, so this
    /// path WAIVES I2 (ack-implies-durable). Use it only under an opted-in relaxed durability level
    /// (`interval`/`async`/`none`); the default `sync` level never calls it. Returns the highest
    /// offset now visible-but-not-yet-durable in `[flushed_before, next_offset)`.
    ///
    /// This never calls `sync_data`, so unlike [`Log::sync`] it cannot fail its durability barrier
    /// and cannot freeze the writer; it only errors if the writer is ALREADY frozen by a prior fatal
    /// fault (then nothing is made visible and the relaxed level surfaces the same fatal error the
    /// `sync` level would).
    ///
    /// # Errors
    /// Returns [`StorageError::WriterFrozen`] if a prior fatal fsync already froze the writer.
    pub fn flush_no_sync(&mut self) -> Result<(), StorageError> {
        // Finish any transient-fault-deferred roll first (#867) so a momentary roll-boundary fault
        // does not leave the visible head stuck.
        self.ensure_writable()?;
        // A frozen writer has no active segment: surface the fatal state rather than silently
        // advancing the visible head over records the writer can no longer own.
        self.active()?;
        // Flush the writer's pending buffered records to the page cache first (#452): raising
        // the visible head promises readers the bytes are in the file. A flush failure is the
        // fatal frozen-writer class, exactly like a failed sync barrier.
        let flush_failed = match self.active.as_mut() {
            Some(w) => w.flush_pending().is_err(),
            None => true,
        };
        if flush_failed {
            self.active = None;
            return Err(StorageError::WriterFrozen);
        }
        // Make the flushed records readable by raising the visible head, WITHOUT the fdatasync
        // that `sync` issues. The records are NOT durable until a later `sync`, a roll's seal,
        // or a clean shutdown flush.
        self.flushed_offset = self.next_offset;
        // The `flush_pending` above put every appended byte in the file, so the active seek index's
        // flushed (in-file) prefix now reaches its full appended prefix (#537), exactly as after a
        // `sync` — the records are visible (and in-file) even though not yet durable.
        self.raise_active_index_flushed_end();
        // Publish the new (relaxed-level) flushed frontier to the off-actor read plane (#539): like
        // `sync`, no roll, so only the atomic frontier is republished. The plane's hard read bound is
        // exactly this flushed frontier, so a reader under a relaxed level still only ever observes
        // the visible prefix, never the not-yet-flushed tail.
        self.publish_flushed_frontier();
        Ok(())
    }

    /// Issues the covering `fdatasync` for this log's active segment ALONE — the bare durability
    /// barrier, WITHOUT re-flushing pending bytes and WITHOUT advancing the durable head (#564).
    /// This is the middle phase of [`Log::sync`] exposed on its own so the cross-stream
    /// `CommitCoordinator` (M2-I3) can drive a single commit tick as: (a) one
    /// [`Log::flush_no_sync`] pass over every DIRTIED stream (drains each `pending` to the page
    /// cache, raises each visible head), then (b) one `sync_data_only` per dirtied stream's fd (the
    /// K fdatasyncs the kernel cannot batch across different fds), then (c) one
    /// [`Log::advance_synced_offset_after_external_sync`] per dirtied stream to advance its durable
    /// head and release its parked acks. Splitting the phases this way amortizes the per-stream
    /// barrier across the whole batch exactly as today's single-log group-commit amortizes one
    /// `fdatasync` across a batch of appends — the per-RECORD fsync cost stays O(1/batch); only the
    /// fsync COUNT per tick is O(dirtied streams).
    ///
    /// The caller MUST have flushed this log first (via [`Log::flush_no_sync`]); this method does
    /// NOT flush, so it makes durable exactly the prefix already in the file. It does NOT touch
    /// `synced_offset`: durability is only ACKNOWLEDGED once the caller follows a SUCCESSFUL
    /// `sync_data_only` with [`Log::advance_synced_offset_after_external_sync`], preserving I2
    /// (ack-implies-durable) — never advance the durable head before its covering fdatasync returns.
    ///
    /// A failed barrier FREEZES this writer read-only (drops the active segment, surfaces
    /// [`StorageError::WriterFrozen`]), exactly as [`Log::sync`] does — and because each stream is
    /// its OWN `Log`, freezing this one cannot touch a sibling stream (the per-stream
    /// resilience-isolation property). The coordinator skips the durable-head advance for a frozen
    /// stream (its acks are NOT released) and continues the batch for its siblings.
    ///
    /// # Errors
    /// Returns [`StorageError::WriterFrozen`] if the writer is already frozen, or if this fdatasync
    /// fails its durability barrier (which freezes the writer read-only).
    pub(crate) fn sync_data_only(&mut self) -> Result<(), StorageError> {
        // Complete any transient-fault-deferred roll first (#867), so this barrier runs against a
        // fully installed active segment rather than a momentarily-deferred one.
        self.ensure_writable()?;
        self.active()?;
        let frozen = match self.active.as_mut() {
            Some(w) => w.sync_data_only().is_err(),
            None => true,
        };
        if frozen {
            self.active = None;
            return Err(StorageError::WriterFrozen);
        }
        Ok(())
    }

    /// Advances the DURABLE head to the visible head after an EXTERNALLY-issued covering
    /// `fdatasync` ([`Log::sync_data_only`]) has returned successfully (#564): the final phase of
    /// [`Log::sync`] exposed on its own for the cross-stream `CommitCoordinator`. It advances
    /// `synced_offset` to `next_offset`, zeroes the unsynced at-risk byte exposure, and republishes
    /// the flushed frontier — exactly the post-barrier bookkeeping [`Log::sync`] does inline, minus
    /// the fsync (already done by the coordinator's batched barrier).
    ///
    /// SAFETY OF THE CONTRACT (I2): the caller MUST call this ONLY after a successful
    /// [`Log::sync_data_only`] (or [`Log::sync`]) that covered the records in
    /// `[synced_offset, next_offset)`. Calling it without that covering fdatasync would advertise
    /// records as durable that a power loss could revert — violating I2 (ack-implies-durable). The
    /// coordinator enforces this by advancing a stream's durable head ONLY on the success path of
    /// its `sync_data_only`, and skipping it (leaving the acks parked) for any stream whose barrier
    /// froze. A debug assert guards the obvious misuse: the writer must still be live (a frozen
    /// writer's barrier failed, so its durable head must not advance).
    ///
    /// Idempotent for a fully-synced log (`synced_offset` already equals `next_offset`): advancing
    /// to the same head and re-zeroing an already-zero exposure is a no-op, so a coordinator that
    /// over-calls it on a clean stream does no harm.
    pub(crate) fn advance_synced_offset_after_external_sync(&mut self) {
        debug_assert!(
            self.is_writable(),
            "advance_synced_offset_after_external_sync must follow a SUCCESSFUL covering fdatasync; \
             a frozen writer's durable head must never advance (#564)"
        );
        self.flushed_offset = self.next_offset;
        self.synced_offset = self.next_offset;
        self.raise_active_index_flushed_end();
        self.unsynced_record_bytes = 0;
        self.publish_flushed_frontier();
    }

    /// STAGES the covering durability barrier for the PIPELINED sync tier (#1040) without issuing
    /// it: the third sibling of the #564 split-barrier family. It drains the writer's pending
    /// buffer to the file (page cache) so the appended bytes are all IN the file, then returns a
    /// SHARED handle to the active segment's fd plus a [`SyncTicket`] snapshotting the
    /// dirty-at-sync-start boundary. The caller issues `sync_data` on the handle OFF this thread
    /// (the flusher) and, once that external fdatasync has RETURNED successfully, applies the
    /// ticket with [`Log::complete_async_sync`] — never before, preserving I2 exactly as
    /// [`Log::advance_synced_offset_after_external_sync`]'s contract demands.
    ///
    /// Deliberately touches NEITHER head: contrast [`Log::flush_no_sync`], which raises the
    /// VISIBLE head — reusing it here would leak not-yet-durable records to readers (and to the
    /// cluster leader frontier) before the covering barrier returned, breaking
    /// visible-equals-durable on this tier. Bytes appended AFTER this call are NOT covered by the
    /// returned ticket (they stay in the unsynced window for the NEXT barrier), which is what
    /// makes an in-flight barrier safe to overlap with further appends on the same fd.
    ///
    /// The three outcomes are DISTINCT by design (the false-ack conflation this API kills):
    /// - **frozen** writer => `Err(WriterFrozen)`, NEVER a clean `None` — a frozen writer also
    ///   reports `has_unsynced_records() == false`, so the frozen check precedes the clean check;
    /// - **clean** log (nothing unsynced) => `Ok(None)`, no barrier owed;
    /// - **dirtied** log => `Ok(Some((file, ticket)))`, one barrier owed.
    ///
    /// # Errors
    /// Returns [`StorageError::WriterFrozen`] if the writer is frozen (or if staging the pending
    /// bytes fails, which freezes it — the same fatal class as in [`Log::flush_no_sync`]), or the
    /// raw transient error from a deferred-roll retry (#867), exactly as [`Log::sync`] surfaces it.
    pub fn prepare_async_sync(&mut self) -> Result<StagedSync<F::File>, StorageError> {
        // Finish a transient-fault-deferred roll first (#867), exactly as `sync` does, so the
        // barrier is staged against a fully installed active segment.
        self.ensure_writable()?;
        // FROZEN IS AN ERROR, NEVER A CLEAN None: `has_unsynced_records` reports `false` for a
        // frozen writer, so this check MUST come first or a dead writer would be
        // indistinguishable from a clean log and its parked producers would never be fataled.
        if self.active.is_none() {
            return Err(StorageError::WriterFrozen);
        }
        // CLEAN: nothing appended since the last covering barrier, no barrier owed. Distinct
        // from frozen by construction (the writer is live here).
        if !self.has_unsynced_records() {
            return Ok(None);
        }
        // Stage the writer's pending bytes into the file so the external fdatasync covers every
        // appended byte (the same flush-before-barrier ordering `sync` uses). A flush failure is
        // the fatal frozen-writer class, exactly as in `flush_no_sync`; clear the pending roll
        // too so `ensure_writable` can never resurrect a frozen writer.
        let Some(w) = self.active.as_mut() else {
            return Err(StorageError::WriterFrozen);
        };
        if w.flush_pending().is_err() {
            self.active = None;
            self.pending_roll = None;
            return Err(StorageError::WriterFrozen);
        }
        let file = w.shared_file();
        let write_pos = w.write_pos();
        // The staged in-file prefix (#537): the resident active index's `valid_end`, which now —
        // post-flush — equals the writer's write position. Snapshotted so the completion raises
        // the index's flushed bound to exactly what THIS barrier covered, never to a later
        // (possibly still-pending) prefix. Defensive fallback to the writer's position if the
        // active index were ever absent (it never is on this path).
        let staged_valid_end = self
            .segment_indexes
            .borrow()
            .get(&self.active_id)
            .map_or(write_pos, |idx| idx.valid_end);
        Ok(Some((
            file,
            SyncTicket {
                target: self.next_offset,
                segment_id: self.active_id,
                staged_valid_end,
                covered_bytes: self.unsynced_record_bytes,
            },
        )))
    }

    /// Applies a RETURNED, SUCCESSFUL external barrier staged by [`Log::prepare_async_sync`]:
    /// generalizes [`Log::advance_synced_offset_after_external_sync`] from "advance to
    /// `next_offset`" to "advance to the SNAPSHOTTED ticket target", so bytes appended while the
    /// barrier was in flight are never advertised durable by it (they belong to the next ticket).
    ///
    /// ALL-OR-NOTHING staleness guard: a completion that arrives after the writer FROZE, or after
    /// an intervening covering barrier (a roll's seal, an inline [`Log::sync`]) already advanced
    /// the durable head at or past this ticket's target, is a FULL no-op — heads, unsynced byte
    /// meter, seek index, read-plane frontier, ALL untouched. Half-applying a stale ticket is
    /// exactly the byte-meter-undercount / index-corruption class this guard exists to kill (a
    /// roll's seal already advanced the heads and ZEROED the meter; subtracting the stale ticket's
    /// covered bytes on top would undercount the new segment's live exposure).
    ///
    /// Staleness is BINARY under the caller's depth-1 dispatch discipline: any intervening barrier
    /// advanced `synced_offset` to a then-current `next_offset >= ticket.target`, so a PARTIAL
    /// overlap (guard passed but the ticket straddles a barrier) is unreachable; reaching the body
    /// means no barrier ran since the stage.
    pub fn complete_async_sync(&mut self, ticket: &SyncTicket) {
        if !self.is_writable() || self.synced_offset >= ticket.target {
            return;
        }
        // Monotone by construction (offsets are never rewound): a ticket's target can never
        // exceed the appended head. An op that REWINDS offsets must quiesce the pipeline first.
        debug_assert!(
            ticket.target <= self.next_offset,
            "a staged ticket's target must never exceed the appended head (#1040)"
        );
        // The external fdatasync covered exactly the staged prefix: advance BOTH heads to the
        // ticket's target. Bytes appended during the flight stay unsynced and unadvertised
        // (visible == durable on this tier). `max` keeps the visible head monotone even if a
        // relaxed-level `flush_no_sync` ran it ahead (not a pipelined-tier flow; defensive).
        self.flushed_offset = self.flushed_offset.max(ticket.target);
        self.synced_offset = ticket.target;
        // Retire the covered bytes from the at-risk meter — SUBTRACT the snapshot, never zero
        // it: the meter kept accumulating for records appended during the flight, and those are
        // still at risk until their own barrier returns. Saturating, like every meter update.
        self.unsynced_record_bytes = self
            .unsynced_record_bytes
            .saturating_sub(ticket.covered_bytes);
        // Raise the ACTIVE index's flushed read bound to the SNAPSHOTTED staged prefix (#537) —
        // never the current `valid_end`, whose tail may still be in the writer's pending buffer
        // (not yet in the file). Only if the staged segment is still the active one: after a
        // roll the seal already raised the sealed index to its full prefix.
        if ticket.segment_id == self.active_id {
            if let Some(idx) = self.segment_indexes.borrow_mut().get_mut(&self.active_id) {
                idx.flushed_end = idx.flushed_end.max(ticket.staged_valid_end);
            }
        }
        // Publish the new flushed frontier to the off-actor read plane (#539): the LAST step, so
        // a reader that observes the frontier also observes every prior store, and the caller
        // releases producer acks only after readers can already serve the acked records.
        self.publish_flushed_frontier();
    }

    /// FREEZES the writer after an EXTERNALLY-issued covering barrier (a flusher's `sync_data` on
    /// the [`Log::prepare_async_sync`] handle) FAILED: the exact terminal state a failed
    /// [`Log::sync`] leaves — `active` dropped so every later append/sync surfaces the fatal,
    /// never-retried [`StorageError::WriterFrozen`], and `pending_roll` cleared so
    /// [`ensure_writable`](Log::ensure_writable) can never resurrect the writer after the freeze
    /// (matching the roll-boundary freeze discipline in `create_or_defer_segment`). Reads keep
    /// serving the durable prefix, and a health check sees the degraded state, exactly as after
    /// any other fatal barrier. Idempotent.
    pub fn freeze_after_external_sync_failure(&mut self) {
        self.active = None;
        self.pending_roll = None;
    }

    /// Whether this log has appended records not yet covered by a returned `fdatasync` — i.e. it is
    /// DIRTIED and owes the next commit tick a durability barrier (#564). The exact gate the
    /// cross-stream `CommitCoordinator` uses to pick which streams a tick must sync: a stream whose
    /// durable head ([`Log::synced_offset`]) trails the offset its next append will receive
    /// ([`Log::next_offset`]) has un-synced records. A fully-synced (or never-appended) stream is
    /// CLEAN and the coordinator skips it entirely (a cold stream costs zero fdatasyncs), so the
    /// tick's fsync count scales with the dirtied (hot) streams, not with the total stream count.
    ///
    /// A frozen writer (`active` is `None`) reports `false`: it can no longer be made durable, so
    /// the coordinator must not pick it for a barrier (it would only re-surface `WriterFrozen`); its
    /// acked-but-now-lost tail is a recovery/loss concern, not a commit-tick concern.
    ///
    /// `pub` (widened from `pub(crate)`, #1040): the engine's pipelined-tier dispatch gate reads
    /// the same predicate to decide whether a barrier is owed. NOTE the frozen-reports-`false`
    /// caveat above — a dispatch seam must distinguish frozen from clean via
    /// [`Log::prepare_async_sync`]'s `Err`, never via this predicate alone.
    #[must_use]
    pub fn has_unsynced_records(&self) -> bool {
        self.is_writable() && self.synced_offset != self.next_offset
    }

    /// Advances the ACTIVE segment's resident seek index `flushed_end` to its current `valid_end`
    /// (#537): called after a `sync`/`flush_no_sync` flushes the writer's pending bytes to the file
    /// and raises the visible head, so the index's flushed (in-file) read bound now reaches the whole
    /// appended prefix. Every record below `flushed_offset` is thereby guaranteed in the file up to
    /// `flushed_end`, so a seek-and-read never touches a not-yet-flushed (not-in-file) frame. A no-op
    /// if the active index was evicted (it never is on this path, but be defensive).
    fn raise_active_index_flushed_end(&self) {
        if let Some(idx) = self.segment_indexes.borrow_mut().get_mut(&self.active_id) {
            idx.flushed_end = idx.valid_end;
        }
    }

    /// The first offset NOT yet covered by a returned `fdatasync` (the DURABLE head): under the
    /// default `sync` level this equals [`Log::flushed_offset`] (every visible record is also
    /// durable, I2). Under a relaxed level the visible head ([`Log::flushed_offset`]) may run AHEAD
    /// of this durable head by the unsynced window, and the records in `[synced_offset, flushed)`
    /// are exactly the acked-but-not-yet-durable tail a power loss would lose. A `sync` advances
    /// this to match the visible head; a `flush_no_sync` does not. Exposed so the engine can compute
    /// the worst-case unsynced exposure for the relaxed levels.
    #[must_use]
    pub fn synced_offset(&self) -> Offset {
        self.synced_offset
    }

    /// The UNSYNCED record-byte exposure (#341, #379): the logical record bytes (key + headers +
    /// payload, no framing) appended since the last real durability barrier (`sync` or a roll's seal)
    /// and not yet covered by a returned `fdatasync`. Always `0` when the writer is fully synced (so
    /// always `0` under the default `sync` level, where every `commit` syncs). Under a relaxed level
    /// it is the live bytes-at-risk a power cut would lose, the `interval` byte-trigger input and the
    /// engine's loss-exposure gauge.
    #[must_use]
    pub fn unsynced_bytes(&self) -> u64 {
        self.unsynced_record_bytes
    }

    /// The durable high-water mark: the first offset NOT yet flushed to stable storage.
    /// Reads never return a record at or beyond this offset.
    #[must_use]
    pub fn flushed_offset(&self) -> Offset {
        self.flushed_offset
    }

    /// Bytes dropped from a torn or unsynced active-segment tail at recovery: the silent
    /// loss that recovery truncated to reach the last intact record. Zero for a fresh log
    /// or a clean recovery. This is the raw recovery-loss signal an operator can surface;
    /// the structured loss report is later work (#120).
    #[must_use]
    pub fn recovered_truncated_bytes(&self) -> u64 {
        self.recovered_truncated_bytes
    }

    /// The structured, versioned [`LossReport`] from recovery: every byte span recovery
    /// dropped to reach the last intact record, with its reason. Empty for a fresh log or a
    /// clean recovery. The metrics endpoint (#16) and the offline inspector (#15) read this.
    #[must_use]
    pub fn loss_report(&self) -> &LossReport {
        &self.loss_report
    }

    /// The PERSISTED on-disk footprint of the forensic quarantine store (#134, #315): the total
    /// bytes of the corruption-skip blobs `quarantine/` currently holds (copy-not-move, capped),
    /// seeded at open from a one-time read-only scan of the durable blobs and advanced by any new
    /// capture this recovery made. Unlike the original this-recovery-only count, it SURVIVES a
    /// restart, so a clean reopen with no new corruption skip still surfaces the real disk pressure
    /// prior recoveries' forensic copies create. Zero only when the quarantine dir is absent, empty,
    /// or unreadable. Best-effort: the scan and any capture are forensic and never fail the open, so
    /// this is a disk-pressure signal, not a correctness invariant. The metrics endpoint exposes it
    /// as the `ironbus_quarantine_bytes` gauge.
    #[must_use]
    pub fn quarantined_bytes(&self) -> u64 {
        self.quarantined_bytes
    }

    /// The current monotonic time from the log's clock, for the consumer's lease deadlines.
    #[must_use]
    pub fn now_monotonic(&self) -> u64 {
        self.clock.now_monotonic_nanos()
    }

    /// The current wall-clock time from the log's clock, in Unix milliseconds. The engine reads it
    /// once at open to stamp the metric registry's start-time series (#97); routing it through the
    /// clock seam (not a raw `SystemTime::now`) keeps the deterministic sim reproducible.
    #[must_use]
    pub fn now_unix_millis(&self) -> u64 {
        self.clock.now_unix_millis()
    }

    /// Clones the log's clock, so a SECONDARY durable store (the DLQ sink, #63) opened from the
    /// same data directory shares the same kind of time source without the caller threading a
    /// clock separately. For a `ManualClock` the clone is an independent snapshot; for an
    /// `Arc<ManualClock>` it aliases the same clock; either is correct for the sink, which uses the
    /// clock only to stamp segment-creation timestamps.
    #[must_use]
    pub fn clock_clone(&self) -> C
    where
        C: Clone,
    {
        self.clock.clone()
    }

    /// Whether the writer is still live (NOT permanently frozen). The writer freezes when a fatal
    /// `fdatasync` fails (see [`Log::sync`]) or a roll hits a genuine durability-barrier fault; this
    /// reports that degraded state without a failing write, so a health check can surface it. Reads
    /// keep serving the durable prefix from a frozen writer.
    ///
    /// A roll a TRANSIENT fault merely DEFERRED (#867) has `active == None` but is RESUMABLE — the
    /// next write completes the deferred create — so it reports `true`, NOT a freeze: a momentary
    /// EMFILE/ENOSPC at a roll boundary must not flap a node out of `/readyz`.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.active.is_some() || self.pending_roll.is_some()
    }

    /// Reads up to `max` records starting at log offset `start`, crossing segment
    /// boundaries, and stops at the flushed (durable) offset. Returns fewer records than
    /// `max` if the flushed end is reached first, and an empty vector if `start` is at or
    /// past the flushed offset.
    ///
    /// # Errors
    /// Returns [`StorageError::OffsetOutOfRange`] if `start` is older than the oldest
    /// retained record, or an IO error reading a segment.
    pub fn read_from(&self, start: Offset, max: usize) -> Result<Vec<OwnedRecord>, StorageError> {
        // `read_from` is `read_range` with no byte cap: one seek + one forward pass per segment.
        self.read_range(start, max, None)
    }

    /// Reads a CONTIGUOUS RUN of records starting at log offset `start` in a SINGLE forward pass
    /// per segment — the single-pass batch-read primitive of the consume read plane (#538, on the
    /// I1 #537 sparse seek index). Where the engine's per-record `read_from(off, 1)` re-pays a
    /// segment open + anchor seek + forward scan PER record (N separate locates for a batch of N),
    /// `read_range` does ONE seek to the nearest anchor at or before `start`, forward-scans the
    /// bounded gap to `start`, then materializes a contiguous run in ONE linear pass over the
    /// segment bytes — `O(N)` over the run, not `O(N * records-per-segment)`. It crosses segment
    /// boundaries transparently (continuing the single-pass read into each next segment) and stops
    /// at the flushed (durable) offset, exactly like `read_from`.
    ///
    /// Bounds (a record is returned only while ALL hold):
    /// - `max_records`: at most this many records. `max_records == 0` returns empty (as `read_from`).
    /// - `max_bytes`: at most this many ENCODED frame bytes in total. `None` means no byte cap.
    ///   To avoid stalling on a record larger than the cap, the FIRST record is ALWAYS returned
    ///   even if it alone exceeds `max_bytes` (the standard "at least one" fetch rule); the cap then
    ///   bounds every record AFTER the first. The byte budget accumulates ACROSS segment boundaries.
    /// - the flushed offset: never returns a record at or past the durable end.
    ///
    /// Each returned record is FULLY CRC-validated (header AND body) by the codec decode, exactly as
    /// `read_from` — the seek index is a LOCATOR, never a CRC bypass (verify-once CRC-skip is the
    /// separate #540, zero-copy / `sendfile` the separate #542; this returns materialized
    /// [`OwnedRecord`]s). Wiring the engine to USE batched delivery via `read_range` is the separate
    /// #550, and the lock-free off-actor read plane the separate #539; this issue is the single-pass
    /// primitive only.
    ///
    /// # Errors
    /// Returns [`StorageError::OffsetOutOfRange`] if `start` is older than the oldest retained
    /// record, or an IO error reading a segment.
    pub fn read_range(
        &self,
        start: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<Vec<OwnedRecord>, StorageError> {
        let max = max_records;
        let start_v = start.get();
        let flushed = self.flushed_offset.get();
        if max == 0 || start_v >= flushed {
            return Ok(Vec::new());
        }
        // The empty/at-end check above precedes the out-of-range check below, which is
        // safe while `flushed >= oldest` always holds (it does: `flushed` is `next_offset`,
        // never below the last segment's base, never below the oldest base). Once front
        // reaping can advance `oldest` past a small `flushed`, reorder these two so a
        // reaped offset reports OffsetOutOfRange instead of an empty read.
        // The oldest retained offset is the FIRST segment's covered base (for a compacted segment
        // this is its `covered_base_offset`, which can be BELOW its lowest surviving offset; a read
        // that targets a compacted-away offset in that range is valid and simply skips forward over
        // the gap to the next present survivor).
        let oldest = self
            .segments
            .first()
            .map_or(0, SegmentSlot::covered_base_offset);
        if start_v < oldest {
            return Err(StorageError::OffsetOutOfRange {
                requested: start_v,
                oldest,
            });
        }
        let mut out: Vec<OwnedRecord> = Vec::new();
        // Running total of the ENCODED frame bytes of the records ALREADY in `out`, the whole-read
        // (not per-segment) byte budget the optional `max_bytes` cap is enforced against (#538).
        let mut byte_total = 0usize;
        let bounds = ReadBounds {
            start_v,
            flushed,
            max,
            max_bytes,
        };
        for slot in &self.segments[self.segment_index_for(start_v)..] {
            if slot.covered_base_offset() >= flushed {
                // This segment, and every later one, begins beyond the durable end.
                break;
            }
            if out.len() >= max {
                break;
            }
            let stop = self.read_slot_into(slot, &bounds, &mut out, &mut byte_total)?;
            if stop {
                break;
            }
        }
        Ok(out)
    }

    /// The opened [`SegmentReader`] for segment `id`, served from the resident reader cache (#808) for a
    /// SEALED segment (opened on first touch, reused thereafter) and opened FRESH for the active segment
    /// (which grows, so its length/tail must never be cached). The returned `Arc` is cheap to clone and
    /// reads it with positioned `pread`s.
    fn sealed_reader_for(
        &self,
        id: u64,
    ) -> Result<std::sync::Arc<SegmentReader<F::File>>, StorageError> {
        // #643 tiered storage: restore an offloaded segment to local disk before opening it (a no-op
        // for a local segment). Defense-in-depth: the read entry points already restore, but this is
        // the canonical open-by-id, so it never hands back a NotFound for a REMOTE segment.
        if self.is_segment_remote(id) {
            self.ensure_segment_local(id)?;
        }
        if id == self.active_id {
            return Ok(std::sync::Arc::new(SegmentReader::open(
                self.fs.open(&segment_file_name(id))?,
            )?));
        }
        if let Some(reader) = self.sealed_readers.get(id) {
            return Ok(reader);
        }
        let reader =
            std::sync::Arc::new(SegmentReader::open(self.fs.open(&segment_file_name(id))?)?);
        self.sealed_readers
            .insert(id, std::sync::Arc::clone(&reader));
        Ok(reader)
    }

    /// Reads ONE segment's contribution to a [`Log::read_range`] in a single forward pass, pushing
    /// the in-range records into `out` and advancing `byte_total` (#538). Returns `true` when the
    /// read should STOP (a record/byte/flushed bound was hit), `false` to advance to the next
    /// segment. Routes a compacted (sparse, v2) slot to the survivor seek path and a dense (v1) slot
    /// to the anchor seek path, each materializing only a BOUNDED forward run — never a full rescan.
    fn read_slot_into(
        &self,
        slot: &SegmentSlot,
        bounds: &ReadBounds,
        out: &mut Vec<OwnedRecord>,
        byte_total: &mut usize,
    ) -> Result<bool, StorageError> {
        // #643 tiered storage: if this slot is offloaded and its local file is absent, restore it
        // from the cold store (fetch + re-verify + re-materialize) BEFORE any open — the seek-index
        // build, the sealed-reader open, and the fallback full-scan below all read the local file.
        // A no-op for a local (never-offloaded or already-restored) segment.
        if self.is_segment_remote(slot.id) {
            self.ensure_segment_local(slot.id)?;
        }
        let remaining = bounds.max - out.len();
        // A COMPACTED segment is SPARSE: SEEK via the resident #481 sparse index to the FIRST
        // survivor at or above the per-segment start, then read FORWARD up to `remaining`, instead of
        // re-decoding the WHOLE survivor region per poll. A start that lands on a compacted-away hole
        // resolves to the next present survivor (the read skips the gap). Survivors come back already
        // at-or-above the start, so no below-start skip is needed; the per-segment start is
        // `max(start_v, covered_base)`.
        if slot.compacted_covered.is_some() {
            let seg_start = bounds.start_v.max(slot.covered_base_offset());
            let reader = SegmentReader::open(self.fs.open(&segment_file_name(slot.id))?)?;
            let Some((byte_pos, base_off, base_seq, read_end)) =
                self.seek_in_compacted(slot, seg_start, &reader)?
            else {
                // No survivor at or above `seg_start`: the segment is exhausted for this read; advance.
                return Ok(false);
            };
            // Survivors come back at-or-above `seg_start` (no gap-skip), so the remaining byte budget
            // can bound the segment-level scan directly; `push_record` enforces the exact cap.
            let seg_byte_budget = bounds.max_bytes.map(|cap| cap.saturating_sub(*byte_total));
            let records = reader.scan_compacted_range(
                byte_pos,
                base_off,
                base_seq,
                read_end,
                remaining,
                seg_byte_budget,
            )?;
            // A sparse survivor may still land at/beyond `flushed`; the per-record flushed clamp in
            // `push_record` handles it (a no-op for a sealed compacted predecessor).
            for record in records {
                if Self::push_record(record, bounds, out, byte_total) {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        // ORDINARY (dense, v1) segment: SEEK via the resident #483/#537 SPARSE index to the nearest
        // ANCHOR at or before the start frame and read FORWARD, instead of rescanning from the base.
        // The anchor may sit a BOUNDED run (<= `stride` bytes) BEFORE `seg_start`; those records come
        // back and are skipped below. The per-segment start is `max(start_v, base)`.
        let seg_start = bounds.start_v.max(slot.base_offset);
        // #664: bound the seek's read span to the WINDOW (`remaining` records from `seg_start`), not
        // the whole segment, so a forward streaming drain reads O(window) bytes per fetch (not
        // O(distance-to-segment-end)). The `want`/gap clamp below still governs the records returned.
        let Some((anchor_offset, byte_pos, read_end)) =
            self.seek_in_segment(slot, seg_start, remaining)?
        else {
            // The index does not cover `seg_start` (the as-yet-unflushed active tail): fall back to a
            // full scan for this segment — correct, only (rarely) slower, the same records. The
            // ACTIVE segment's scan is bounded at the writer's `write_pos`: its preallocated logical
            // extension makes the FILE roll-size long, and an unbounded fallback would eagerly
            // allocate and read the whole zero tail (up to 64 MiB of zeros for the same records).
            let mut reader = SegmentReader::open(self.fs.open(&segment_file_name(slot.id))?)?;
            if slot.id == self.active_id {
                if let Some(writer) = self.active.as_ref() {
                    reader = reader.with_data_end(writer.write_pos());
                }
            }
            let records = reader.scan()?.records;
            for record in records {
                if record.offset.get() < bounds.start_v {
                    continue;
                }
                if Self::push_record(record, bounds, out, byte_total) {
                    return Ok(true);
                }
            }
            return Ok(false);
        };
        // `want` covers the bounded gap (`seg_start - anchor_offset`, <= `stride` bytes) the anchor
        // precedes `seg_start` by, plus the records wanted, clamped to the records below `flushed`.
        // No segment-level byte cap on the DENSE scan: the dropped gap records would mis-charge it;
        // the `want` count bounds the read and `push_record` enforces the whole-read byte cap.
        let gap = usize::try_from(seg_start.saturating_sub(anchor_offset)).unwrap_or(0);
        let below_flushed =
            usize::try_from(bounds.flushed.saturating_sub(anchor_offset)).unwrap_or(usize::MAX);
        let want = remaining.saturating_add(gap).min(below_flushed);
        // #808: reuse an opened reader for a SEALED segment (the consume hot path — Tier-W polls
        // `read_from(off, 1)` per delivered message), re-opening only the growing active segment.
        let reader = self.sealed_reader_for(slot.id)?;
        let records = reader.scan_from(byte_pos, Offset::new(anchor_offset), read_end, want)?;
        for record in records {
            // Skip the bounded run of records the anchor preceded `seg_start` by.
            if record.offset.get() < seg_start {
                continue;
            }
            if Self::push_record(record, bounds, out, byte_total) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Admits `record` to a [`Log::read_range`] result `out` (advancing `byte_total`) unless a bound
    /// is hit (#538). Returns `true` when the read must STOP: the record is at/past the flushed
    /// (durable) end, the record-count `max` is already reached, or admitting it would breach
    /// `max_bytes` — EXCEPT the FIRST record (`out` empty) is always admitted even if it alone
    /// exceeds the byte cap (the "at least one" fetch rule), so an oversized record never stalls the
    /// read. The byte cap is checked here, AFTER the gap/start/flushed filtering, so gap-skipped and
    /// below-start records never charge it.
    fn push_record(
        record: OwnedRecord,
        bounds: &ReadBounds,
        out: &mut Vec<OwnedRecord>,
        byte_total: &mut usize,
    ) -> bool {
        if record.offset.get() >= bounds.flushed || out.len() >= bounds.max {
            return true;
        }
        let over_bytes = bounds.max_bytes.is_some_and(|cap| {
            !out.is_empty() && byte_total.saturating_add(record.encoded_len()) > cap
        });
        if over_bytes {
            return true;
        }
        *byte_total = byte_total.saturating_add(record.encoded_len());
        out.push(record);
        false
    }

    /// Reads a CONTIGUOUS RAW byte run starting at `start`, returning the records' ON-DISK frame bytes
    /// VERBATIM as one [`RawByteRun`] (the zero-copy read primitive, #542) — the raw, through-actor twin
    /// of [`Log::read_range`] used by the Tier-S `DeliverBatch` delivery path (#541, M1-I5). Where
    /// `read_range` decodes every frame into an [`OwnedRecord`], this seeks to the same anchor and hands
    /// back the contiguous on-disk frame bytes with NO body decode and NO per-record allocation, so a
    /// later disk `sendfile(2)` path (#658) can splice the segment's bytes straight from page cache.
    ///
    /// Bounded to a SINGLE DENSE (v1) segment: a contiguous BYTE range is one slice of one segment file,
    /// so a run that reaches a segment boundary (or a compacted/active-but-unindexed start) stops there
    /// and the returned `tail_from` is `Some(off)` — the next offset the caller serves through the
    /// ordinary materialize path ([`Log::read_range`]). `None` when the read is complete (it hit
    /// `max_records`, the byte cap, or the flushed frontier within this segment). The seek/clamp logic
    /// MIRRORS `read_range` exactly, so the run decodes to byte-identical records.
    ///
    /// Bounds are identical to `read_range`: `max_records`, the optional `max_bytes` (whole-read cap,
    /// first-frame always admitted), and the flushed frontier (no record at/past it is served).
    ///
    /// # Errors
    /// Returns [`StorageError::OffsetOutOfRange`] if `start` is older than the oldest retained record,
    /// or an IO error reading a segment.
    pub fn read_range_raw(
        &self,
        start: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<(RawByteRun, Option<Offset>), StorageError> {
        let start_v = start.get();
        let flushed = self.flushed_offset.get();
        let empty = RawByteRun {
            bytes: Bytes::new(),
            first_offset: start,
            record_count: 0,
            next_offset: start,
        };
        if max_records == 0 || start_v >= flushed {
            // Nothing to serve raw, and nothing remains below the flushed head from `start`.
            return Ok((empty, None));
        }
        let oldest = self
            .segments
            .first()
            .map_or(0, SegmentSlot::covered_base_offset);
        if start_v < oldest {
            return Err(StorageError::OffsetOutOfRange {
                requested: start_v,
                oldest,
            });
        }
        // #643 tiered storage: restore an offloaded slot to local disk before the raw read opens it.
        let slot_id = self.segments[self.segment_index_for(start_v)].id;
        if self.is_segment_remote(slot_id) {
            self.ensure_segment_local(slot_id)?;
        }
        let slot = &self.segments[self.segment_index_for(start_v)];
        // A COMPACTED (sparse, v2) slot is NOT served raw (its byte run is non-contiguous): hand the
        // whole remainder to the materialize path from this segment's covered base (clamped to start).
        if slot.compacted_covered.is_some() {
            let tail = start_v.max(slot.covered_base_offset());
            return Ok((empty, Some(Offset::new(tail))));
        }
        let seg_start = start_v.max(slot.base_offset);
        // #664: bound the seek's read span to the WINDOW (`max_records` records from `seg_start`), not
        // the whole segment, so a forward Tier-S streaming drain reads O(window) bytes per fetch (not
        // O(distance-to-segment-end) => O(N^2) overall). The `want`/`max_records` clamp below still
        // governs the frames returned; `read_end` only bounds how many bytes are read into the buffer.
        let Some((anchor_offset, byte_pos, read_end)) =
            self.seek_in_segment(slot, seg_start, max_records)?
        else {
            // The dense index does not cover `seg_start` (a not-yet-indexed active tail): serve it
            // through the materialize path, exactly as `read_slot_into`'s full-scan fallback would.
            return Ok((empty, Some(start)));
        };
        // The anchor may sit a BOUNDED run before `seg_start`; `raw_byte_range` returns frames from the
        // anchor forward, so trim the leading `gap` records below `seg_start` after the read. We read
        // `gap + max_records` frames so the wanted count survives the trim, clamped to records below
        // `flushed` (the per-frame visibility bound the raw read cannot apply itself).
        let gap = usize::try_from(seg_start.saturating_sub(anchor_offset)).unwrap_or(0);
        let below_flushed =
            usize::try_from(flushed.saturating_sub(anchor_offset)).unwrap_or(usize::MAX);
        let want = max_records.saturating_add(gap).min(below_flushed);
        let reader = SegmentReader::open(self.fs.open(&segment_file_name(slot.id))?)?;
        // No byte cap on the raw read when there is a leading gap: the trimmed frames would mis-charge
        // it. When there is NO gap (`gap == 0`, the common case where the anchor lands exactly on
        // `seg_start`) the byte cap binds the read directly, identical to `read_range`.
        let raw_max_bytes = if gap == 0 { max_bytes } else { None };
        let run = reader.raw_byte_range(
            byte_pos,
            Offset::new(anchor_offset),
            read_end,
            want,
            raw_max_bytes,
        )?;
        // Trim the leading `gap` frames (the bounded run the anchor preceded `seg_start` by) and apply
        // the record-count and byte caps to the surviving frames, so the result is byte-identical to the
        // prefix `read_range` would return over the same single segment.
        let trimmed = trim_and_bound_raw_run(&run, seg_start, max_records, max_bytes);
        // Where does the caller resume? If the trimmed run stopped strictly below the flushed head with
        // records still available in this segment or beyond, the caller continues from `next_offset`
        // through the materialize path (the next segment, or the active tail). If it reached the flushed
        // head, the read is complete (`None`).
        let next = trimmed.next_offset.get();
        let tail_from = if next < flushed && trimmed.record_count >= max_records as u64 {
            // Stopped because the record/byte cap bound within this segment: complete (the cap, not the
            // data, ended it), exactly as `read_range` stops without a fallback.
            None
        } else if next < flushed {
            // More flushed offsets remain past this single-segment raw run (a segment boundary, or a
            // byte-cap stop with offsets still below flushed): serve the remainder via materialize.
            Some(Offset::new(next))
        } else {
            None
        };
        Ok((trimmed, tail_from))
    }

    // -----------------------------------------------------------------------------------------
    // Tiered storage: offload cold sealed segments to an object store (#643, V2-M10, phase 1).
    // All of these run on the single append actor (the `&mut Log` owner), so they are serialized
    // with seal/reap/compaction — there is no offload-vs-reap-vs-compaction race by construction.
    // See `crate::cold` for the crash-window analysis.
    // -----------------------------------------------------------------------------------------

    /// Attaches the [`ColdStore`] backend and the offload policy to this log (#643), the tiered-storage
    /// analogue of `Engine::set_compaction_config`: the engine constructs a per-log-rooted backend and
    /// installs it here after [`Log::open`]. Enabling offload writes no bytes by itself — the first
    /// [`Log::offload_cold_segments`] call is what lazily creates the manifest and tiers segments out.
    pub fn set_cold_store(&mut self, store: Arc<dyn ColdStore>, config: ColdStorageConfig) {
        self.cold_store = Some(store);
        self.cold_config = config;
    }

    /// The tiered-storage policy currently in effect.
    #[must_use]
    pub fn cold_config(&self) -> ColdStorageConfig {
        self.cold_config
    }

    /// Whether segment `id` is recorded REMOTE (offloaded) in the durable manifest. The single source
    /// of truth for "is this segment's authoritative copy in the cold store" — every open-by-id and
    /// the read plane derive their remote handling from it.
    #[must_use]
    pub fn is_segment_remote(&self, id: u64) -> bool {
        self.cold_manifest.as_ref().is_some_and(|m| m.contains(id))
    }

    /// How many segments are currently offloaded (REMOTE) — the tiered-storage depth, for tests and
    /// the engine's observability.
    #[must_use]
    pub fn cold_offloaded_count(&self) -> usize {
        self.cold_manifest
            .as_ref()
            .map_or(0, ColdManifest::entry_count)
    }

    /// Reads the durable cold-segment manifest at `Log::open` (if `cold-manifest.ckpt` exists),
    /// returning the recovered offloaded set. Kept separate from the splice so the caller can read it
    /// FIRST — before the chain scan — and exclude REMOTE ids from the enumeration (#643). A no-op
    /// (and a byte-for-byte unchanged data dir) for a log that never offloaded.
    fn open_cold_manifest(fs: &F) -> Result<Option<ColdManifest<F::File>>, StorageError> {
        if !fs.exists(COLD_MANIFEST_FILE).map_err(StorageError::Io)? {
            return Ok(None);
        }
        let file = fs.open(COLD_MANIFEST_FILE).map_err(StorageError::Io)?;
        Ok(Some(ColdManifest::open(file)?))
    }

    /// Splices ALL the manifest's offloaded segments into `self.segments` as a contiguous PREFIX below
    /// the recovered oldest LOCAL segment, validating that the offloaded set abuts the local chain
    /// exactly (offset/seq contiguity). A manifest inconsistent with the on-disk chain fails closed —
    /// never a silent reinterpretation. The offloaded records still count toward retention totals
    /// (they are retained data, just tiered off local disk).
    ///
    /// Every REMOTE id was already EXCLUDED from the local chain scan at open (a restored cache file
    /// is "absent until verified"), so no offloaded segment is in `self.segments` yet and the whole
    /// offloaded set is the prefix — including the crash-after-manifest-before-delete window (a
    /// segment whose local file lingers is spliced from the manifest here and its cache file is
    /// reconciled on read, never double-counted).
    fn splice_cold_prefix(&mut self) -> Result<(), StorageError> {
        let Some(manifest) = self.cold_manifest.as_ref() else {
            return Ok(());
        };
        if manifest.entries().is_empty() {
            return Ok(());
        }
        // Copy the entries out (id-ascending == base-offset-ascending), so we can mutate `segments`.
        let entries: Vec<ColdEntry> = manifest.entries().values().copied().collect();
        // The offloaded prefix must abut the recovered oldest LOCAL segment (or, if there is none,
        // there is nothing valid to abut and the manifest is inconsistent with the local chain).
        let local_oldest_base = self
            .segments
            .first()
            .map(SegmentSlot::covered_base_offset)
            .ok_or(StorageError::ColdManifestCorrupt)?;
        // Validate internal contiguity (offset AND seq), strictly ascending, and the abutment to the
        // local chain. Any disagreement is a fail-closed refuse, never a fabricated chain.
        let mut splice_bytes = 0u64;
        let mut splice_count = 0u64;
        let mut new_slots: Vec<SegmentSlot> = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            if let Some(next) = entries.get(i + 1) {
                let abuts_offset =
                    entry.base_offset.checked_add(entry.record_count) == Some(next.base_offset);
                let abuts_seq =
                    entry.base_seq.checked_add(entry.record_count) == Some(next.base_seq);
                if !abuts_offset || !abuts_seq {
                    return Err(StorageError::ColdManifestCorrupt);
                }
            } else {
                // The highest offloaded segment must end exactly where the local chain begins.
                if entry.base_offset.checked_add(entry.record_count) != Some(local_oldest_base) {
                    return Err(StorageError::ColdManifestCorrupt);
                }
            }
            let record_bytes = entry
                .byte_len
                .saturating_sub(SEGMENT_HEADER_LEN as u64)
                .saturating_sub(SEGMENT_FOOTER_LEN as u64);
            splice_bytes = splice_bytes.saturating_add(record_bytes);
            splice_count = splice_count.saturating_add(entry.record_count);
            new_slots.push(SegmentSlot {
                id: entry.id,
                base_offset: entry.base_offset,
                record_count: entry.record_count,
                max_timestamp_ms: entry.max_timestamp_ms,
                compacted_covered: None,
            });
        }
        // Prepend the offloaded prefix, oldest first. The local chain (including the active segment,
        // never offloaded) follows unchanged, so `next_offset`/`next_seq`/`active_id` are untouched.
        new_slots.append(&mut self.segments);
        self.segments = new_slots;
        self.sealed_record_bytes = self.sealed_record_bytes.saturating_add(splice_bytes);
        self.total_record_count = self.total_record_count.saturating_add(splice_count);
        Ok(())
    }

    /// Ensures the durable cold-segment manifest exists and is open, creating `cold-manifest.ckpt`
    /// (and dir-syncing its new entry) on first use. Called before the first offload records an entry,
    /// so a log that never offloads never creates the file (default-OFF, byte-identical).
    fn ensure_cold_manifest(&mut self) -> Result<(), StorageError> {
        if self.cold_manifest.is_some() {
            return Ok(());
        }
        let file = if self
            .fs
            .exists(COLD_MANIFEST_FILE)
            .map_err(StorageError::Io)?
        {
            self.fs.open(COLD_MANIFEST_FILE).map_err(StorageError::Io)?
        } else {
            let f = self
                .fs
                .create_new(COLD_MANIFEST_FILE)
                .map_err(StorageError::Io)?;
            // The new manifest file's directory entry must be durable before its first slot write.
            self.fs.sync_dir().map_err(StorageError::Io)?;
            f
        };
        self.cold_manifest = Some(ColdManifest::open(file)?);
        Ok(())
    }

    /// Offloads eligible COLD sealed segments to the [`ColdStore`], oldest first, and returns how many
    /// were tiered out (#643). A no-op when offload is disabled or no backend is attached.
    ///
    /// ## Policy (deterministic, documented)
    /// A sealed segment is offload-eligible iff it is a non-active, non-compacted sealed predecessor
    /// AND there are more than `keep_recent_segments` sealed segments (so it is among the oldest
    /// `sealed_count - keep_recent_segments`). Offload proceeds strictly oldest-first and STOPS at the
    /// first compacted segment, so the offloaded set stays a CONTIGUOUS PREFIX of the chain — which is
    /// what lets recovery splice it back as a prefix. (Offloading compacted v2 segments and non-prefix
    /// holes are deferred follow-ups.)
    ///
    /// ## Crash safety (the load-bearing ordering)
    /// Per segment: upload the bytes to the cold store (durable) → record the segment REMOTE in the
    /// manifest and fsync it (the COMMIT POINT) → only THEN delete the local file. A crash before the
    /// manifest commit recovers fully-local (the still-present file is authoritative; the orphaned
    /// object is overwritten by an idempotent re-offload); a crash after the commit recovers
    /// fully-remote-and-recorded. A local segment is NEVER unlinked before both its remote copy and
    /// its manifest entry are durable.
    ///
    /// # Errors
    /// Propagates an IO/upload error or [`StorageError::ColdManifestFull`]; on any error the offloaded
    /// prefix so far is durable and consistent (a contiguous remote prefix), so a retry resumes.
    pub fn offload_cold_segments(&mut self) -> Result<u64, StorageError> {
        if !self.cold_config.enabled || self.cold_store.is_none() {
            return Ok(0);
        }
        let active_present = self.active.is_some();
        let sealed_count = if active_present {
            self.segments.len().saturating_sub(1)
        } else {
            self.segments.len()
        };
        let keep = usize::try_from(self.cold_config.keep_recent_segments).unwrap_or(usize::MAX);
        if sealed_count <= keep {
            return Ok(0);
        }
        let offload_upto = sealed_count - keep;
        let mut offloaded = 0u64;
        for i in 0..offload_upto {
            let slot = self.segments[i];
            if self.is_segment_remote(slot.id) {
                // Already offloaded (part of the contiguous remote prefix): skip.
                continue;
            }
            if slot.compacted_covered.is_some() {
                // Phase 1 does not offload compacted (v2) segments; stop here so the remote set stays
                // a contiguous prefix (never a compacted hole below a later offloaded segment).
                break;
            }
            self.offload_one_segment(slot)?;
            offloaded = offloaded.saturating_add(1);
        }
        Ok(offloaded)
    }

    /// Offloads ONE ordinary sealed segment with the crash-safe upload → manifest → delete ordering.
    fn offload_one_segment(&mut self, slot: SegmentSlot) -> Result<(), StorageError> {
        let name = segment_file_name(slot.id);
        // 1) Read the whole local segment file (header + records + footer) and checksum it.
        let file = self.fs.open(&name)?;
        let byte_len = file.len()?;
        if byte_len < (SEGMENT_HEADER_LEN + SEGMENT_FOOTER_LEN) as u64 {
            // A sealed segment is always at least a header + footer; anything shorter is not a
            // tierable sealed segment (never a live sealed predecessor). Refuse fail-closed.
            return Err(StorageError::ColdCorrupt {
                segment_id: slot.id,
            });
        }
        let byte_len_usize = usize::try_from(byte_len).map_err(|_| StorageError::ColdCorrupt {
            segment_id: slot.id,
        })?;
        let mut bytes = vec![0u8; byte_len_usize];
        file.read_exact_at(&mut bytes, 0)?;
        let crc = crc32c::crc32c(&bytes);
        // The base sequence lives only in the segment header (not the in-memory slot), so decode it.
        let header = SegmentHeader::decode(&bytes[..SEGMENT_HEADER_LEN])?;
        if header.segment_id != slot.id {
            return Err(StorageError::ColdCorrupt {
                segment_id: slot.id,
            });
        }
        let entry = ColdEntry {
            id: slot.id,
            base_offset: slot.base_offset,
            base_seq: header.base_seq.get(),
            record_count: slot.record_count,
            max_timestamp_ms: slot.max_timestamp_ms,
            byte_len,
            crc32c: crc,
            compacted: false,
        };
        // 2) Upload to the cold store (durable) BEFORE the manifest records it.
        let store = self
            .cold_store
            .as_ref()
            .ok_or(StorageError::ColdStoreUnavailable {
                segment_id: slot.id,
            })?;
        store
            .put(&cold_object_name(slot.id), &bytes)
            .map_err(|e| StorageError::ColdFetch {
                segment_id: slot.id,
                source: e,
            })?;
        // 3) THE COMMIT POINT: record the segment REMOTE in the durable manifest (fsync). After this
        //    returns, the offload is committed and the local file may be safely deleted.
        self.ensure_cold_manifest()?;
        self.cold_manifest
            .as_mut()
            .expect("ensure_cold_manifest installed it")
            .insert(entry)?;
        // 4) Only now, with BOTH the object and the manifest entry durable, delete the local file.
        self.fs.remove(&name)?;
        self.fs.sync_dir()?;
        // 5) Drop the retired local segment's resident seek index + cached reader (its file is gone).
        self.evict_segment_index(slot.id);
        // 6) Republish the off-actor read plane so its snapshot marks the segment REMOTE (a read of it
        //    now falls back through the actor, which restores-on-access).
        self.republish_read_plane();
        Ok(())
    }

    /// Restore-on-access (#643): make REMOTE segment `id` readable locally. Its `seg-<id>.log` is a
    /// process-lifetime restore CACHE (a re-fetchable copy of the offloaded object). A cache file
    /// present WITHIN a run was written by THIS process's restore below — AFTER the fetched bytes were
    /// verified against the manifest — so it is trusted by existence; only an absent one is fetched.
    /// A torn/stale cache from a PRIOR run's crash never reaches here: [`Log::open`] PURGES every
    /// REMOTE id's cache file before recovery, so a read always starts from either a valid cache this
    /// run wrote or a clean fetch. Idempotent; runs on the actor.
    ///
    /// A fetch or verification failure is a TYPED, fail-closed error surfaced to the reader (never a
    /// silent gap or a phantom record): the poisoned bytes are never materialized as a local segment.
    fn ensure_segment_local(&self, id: u64) -> Result<(), StorageError> {
        let name = segment_file_name(id);
        if self.fs.exists(&name).map_err(StorageError::Io)? {
            // Present: a genuine local segment, or a cache this run already restored (verified before
            // it was written). Trusted by existence — `Log::open` purged any stale/torn prior cache.
            return Ok(());
        }
        let Some(entry) = self.cold_manifest.as_ref().and_then(|m| m.get(id)).copied() else {
            // Absent and NOT recorded REMOTE: let the caller's normal open surface a genuine NotFound.
            return Ok(());
        };
        let store = self
            .cold_store
            .as_ref()
            .ok_or(StorageError::ColdStoreUnavailable { segment_id: id })?;
        let bytes = store
            .get(&cold_object_name(id))
            .map_err(|e| StorageError::ColdFetch {
                segment_id: id,
                source: e,
            })?;
        // Verify the fetched bytes (length + CRC32C + a structural header/footer scan) BEFORE
        // materializing them, so a corrupt object store fails closed rather than caching garbage.
        Self::verify_fetched_segment(id, &entry, &bytes)?;
        match self.fs.create_new(&name) {
            Ok(file) => {
                file.write_all_at(&bytes, 0)?;
                file.sync_all()?;
                self.fs.sync_dir()?;
            }
            // A benign race on a shared fs: the bytes are byte-identical (both manifest-verified).
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(StorageError::Io(e)),
        }
        Ok(())
    }

    /// Re-verifies fetched offloaded-segment bytes against the manifest entry, fail-closed on any
    /// mismatch (#643): the byte length, the CRC32C over the whole file, and a structural scan (a
    /// decodable header whose id/base match, plus a body-consistent sealed footer whose record count
    /// matches). A corrupt object store therefore fails closed rather than delivering garbage.
    fn verify_fetched_segment(
        id: u64,
        entry: &ColdEntry,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        if bytes.len() as u64 != entry.byte_len || crc32c::crc32c(bytes) != entry.crc32c {
            return Err(StorageError::ColdCorrupt { segment_id: id });
        }
        // Structural re-verify over the fetched bytes: open a reader and scan for a body-consistent
        // sealed footer. Any decode/scan error, a header id/base mismatch, an unsealed result, or a
        // record-count disagreement is a fail-closed corruption.
        let reader = SegmentReader::open(Arc::new(InMemoryFile::from_bytes(bytes.to_vec())))
            .map_err(|_| StorageError::ColdCorrupt { segment_id: id })?;
        if reader.header().segment_id != id
            || reader.header().base_offset.get() != entry.base_offset
            || reader.header().base_seq.get() != entry.base_seq
        {
            return Err(StorageError::ColdCorrupt { segment_id: id });
        }
        let scan = reader
            .scan()
            .map_err(|_| StorageError::ColdCorrupt { segment_id: id })?;
        if scan.footer.is_none() || !scan.clean || scan.records.len() as u64 != entry.record_count {
            return Err(StorageError::ColdCorrupt { segment_id: id });
        }
        Ok(())
    }

    /// Retires the OLDEST segment's on-disk STORAGE for a reap and returns its (record bytes, record
    /// count) for the running-total decrement (#643). Handles a REMOTE (offloaded) oldest segment: it
    /// removes the manifest entry (fsync) FIRST — so no dangling REMOTE pointer can survive a crash —
    /// then best-effort deletes the cold object (a failed delete leaks a bounded orphan, swept by a
    /// follow-up, never blocks retention) and any lingering local cache file. A LOCAL oldest segment
    /// keeps the exact prior discipline: read its bytes/count, unlink, dir-sync. In both cases the
    /// durable removal precedes the caller's in-memory slot removal, so disk and memory never disagree.
    fn reap_retire_oldest_files(
        &mut self,
        oldest: &SegmentSlot,
    ) -> Result<(u64, u64), StorageError> {
        if self.is_segment_remote(oldest.id) {
            let entry = *self
                .cold_manifest
                .as_ref()
                .and_then(|m| m.get(oldest.id))
                .expect("is_segment_remote implies a manifest entry");
            let record_bytes = entry
                .byte_len
                .saturating_sub(SEGMENT_HEADER_LEN as u64)
                .saturating_sub(SEGMENT_FOOTER_LEN as u64);
            // Manifest entry removal (fsync) FIRST: after this the segment is no longer REMOTE-recorded,
            // so a crash before the object delete leaves at worst a bounded orphan object (no dangling
            // pointer, no data-availability error). This is the only fatal step; if it fails the slot
            // and manifest are unchanged, so a retry is consistent.
            self.cold_manifest
                .as_mut()
                .expect("remote implies a manifest")
                .remove(oldest.id)?;
            // Best-effort object + local-cache cleanup: a failure here must not block retention or
            // leave the manifest (already clean) inconsistent with the removed slot.
            if let Some(store) = self.cold_store.as_ref() {
                let _ = store.delete(&cold_object_name(oldest.id));
            }
            let _ = self.fs.remove(&segment_file_name(oldest.id));
            let _ = self.fs.sync_dir();
            Ok((record_bytes, entry.record_count))
        } else {
            let (bytes, count) = self.segment_record_bytes_and_count(oldest)?;
            self.fs.remove(&segment_file_name(oldest.id))?;
            self.fs.sync_dir()?;
            Ok((bytes, count))
        }
    }

    /// Reclaims disk by deleting whole OLD SEALED segments under any of three composable retention
    /// [`RetentionBounds`] (size, age, count), but NEVER a segment any consumer still needs (the
    /// consumer-safe segment reaper, refs #13, #80). This is the drain side of the overflow policy
    /// that complements the byte-cap shed ([`LogConfig::max_total_bytes`], #259): the cap sheds new
    /// produces when the log is full, this frees space as consumers drain.
    ///
    /// `protect_below_offset` is the floor below which records are safe to drop: every consumer has
    /// committed at least this far, so no consumer still needs any record with an offset strictly
    /// below it. The caller passes the MINIMUM committed offset across every consumer group, so the
    /// slowest group's unconsumed records are never reaped.
    ///
    /// Looping from the OLDEST sealed segment, a segment `segments[0]` is unlinked only while ALL
    /// of these hold:
    /// - SOME enabled bound says it should go: the log is over the byte bound
    ///   (`durable_record_bytes() > bounds.max_bytes`, with `max_bytes != 0`), OR over the count
    ///   bound (`durable_record_count() > bounds.max_messages`, with `max_messages != 0`), OR the
    ///   oldest sealed segment is older than the age bound (its MAXIMUM record timestamp is below
    ///   `now - bounds.max_age_ms`, with `max_age_ms != 0`, so EVERY record in it has aged out).
    ///   When every bound is `0` (the default), nothing is ever eligible and the reaper is OFF.
    /// - more than one segment exists, so the ACTIVE segment (the last slot) is never reaped;
    /// - the oldest sealed segment is ENTIRELY consumed: since segments are contiguous,
    ///   `segments[0]` ends exactly where `segments[1]` begins, so every record in `segments[0]`
    ///   has offset `< segments[1].base_offset`. The segment is fully consumed iff
    ///   `segments[1].base_offset <= protect_below_offset`, which guarantees every record in it is
    ///   below the protect floor and so needed by no consumer.
    ///
    /// The loop stops as soon as no enabled bound is satisfied for the oldest segment, the next
    /// oldest segment is not fully consumed (`segments[1].base_offset > protect_below_offset`), or
    /// only the active segment remains. A whole segment is unlinked or left untouched; a record
    /// inside a segment is never rewritten or partially removed.
    ///
    /// `now` is read from the log's clock seam (so the deterministic simulation drives it, never
    /// the host wall clock), once per pass, and compared against each oldest segment's running
    /// max timestamp (set when the segment was sealed and recomputed at recovery). The max (not
    /// the min) timestamp is used so age never deletes a segment that still holds a record newer
    /// than the bound.
    ///
    /// Each unlink is crash-safe and ordered so disk and memory never disagree: the segment file
    /// is removed and the directory fsynced (so the removal is durable) BEFORE the slot leaves
    /// `segments` and the running `sealed_record_bytes`/`total_record_count` totals are
    /// decremented. A crash after some unlinks leaves a shorter contiguous chain with a non-zero
    /// start, which recovery already accepts; a crash mid-unlink is fine because the unlink is
    /// atomic and the in-memory state was not yet changed, so the next open simply recomputes the
    /// running totals from what survived.
    ///
    /// The byte accounting decrements `sealed_record_bytes` by each reaped segment's record region,
    /// read as `valid_end - SEGMENT_HEADER_LEN` from a streaming recovery scan: this is EXACTLY the
    /// per-segment term the sealed-bytes total accumulated on each roll (a sealed segment's
    /// `valid_end` is the start of its footer, so it excludes both the 64-byte header and the
    /// 32-byte footer). The count accounting decrements `total_record_count` by the same scan's
    /// `record_count`. Both cross-check the slot's stored metadata, so after a reap the running
    /// totals still equal a fresh reopen's recomputed values.
    ///
    /// Returns a [`ReapOutcome`] reporting the segments and bytes reclaimed (zero for a no-op).
    ///
    /// # Errors
    /// Returns [`StorageError`] from reading a segment's length, unlinking it, or the directory
    /// sync. On such an error the in-memory state is left consistent with disk: any segment
    /// removed-and-synced before the failure has already been dropped from `segments` and the
    /// running totals; the failing segment is NOT removed from memory, so it is never orphaned.
    /// This is best-effort space reclamation, so a caller may log and continue, but a real IO error
    /// is surfaced (never swallowed into silent state corruption).
    pub fn reap(
        &mut self,
        bounds: RetentionBounds,
        protect_below_offset: u64,
    ) -> Result<ReapOutcome, StorageError> {
        let mut outcome = ReapOutcome::default();
        // Every bound off (the default) is unlimited: retention is off, so reap nothing.
        if bounds.max_bytes == 0 && bounds.max_age_ms == 0 && bounds.max_messages == 0 {
            return Ok(outcome);
        }
        // `now` is read once per pass from the clock seam (never the host wall clock), so the
        // deterministic simulation drives the age check.
        let now_ms = self.clock.now_unix_millis();
        // Loop while a SECOND slot exists: that keeps the ACTIVE segment (the last slot) off the
        // table, so with only one slot (the single segment IS the active one) the loop ends.
        // The "fully consumed" test is the NEXT segment's COVERED base (== the oldest segment's
        // covered end): every offset in the oldest segment, including any compacted-away holes, is
        // strictly below it, so a consumer at or past it needs none of them.
        while let Some(next_base) = self.segments.get(1).map(SegmentSlot::covered_base_offset) {
            let oldest = self.segments[0];
            // Is the OLDEST sealed segment eligible under any enabled bound? Size and count are
            // log-wide totals; age is per-segment (the oldest segment's max timestamp).
            let over_bytes =
                bounds.max_bytes != 0 && self.durable_record_bytes() > bounds.max_bytes;
            let over_count =
                bounds.max_messages != 0 && self.durable_record_count() > bounds.max_messages;
            // Aged out iff the bound is set AND the segment's NEWEST record is older than the
            // bound: `max_timestamp_ms < now - max_age_ms`. Rearranged to avoid underflow when
            // `now < max_age_ms` (then nothing is old enough): `max_timestamp_ms + max_age_ms < now`.
            let aged_out = bounds.max_age_ms != 0
                && oldest.max_timestamp_ms.saturating_add(bounds.max_age_ms) < now_ms;
            if !(over_bytes || over_count || aged_out) {
                break;
            }
            // The oldest segment is fully consumed only if it ends at or below the protect floor.
            // Its end is exactly the next segment's covered base (contiguous), so every record in it
            // is strictly below `next_base <= protect_below_offset`, hence needed by no consumer.
            if next_base > protect_below_offset {
                break;
            }
            // The reaped segment's durable RECORD bytes and COUNT, and its storage retirement. A
            // LOCAL oldest is read + unlinked as before; a REMOTE (offloaded) oldest removes its
            // manifest entry (fsync) first, then best-effort deletes the cold object so no orphan
            // leaks (#643). Either way the durable removal precedes the in-memory slot removal below,
            // so memory never claims a segment is gone while it survives on disk.
            let (segment_record_bytes, segment_record_count) =
                self.reap_retire_oldest_files(&oldest)?;
            self.segments.remove(0);
            // EVICT this retired segment's resident seek index (#483) the moment its slot leaves
            // memory: the id is now free to be... never reused (ADR 0002), but evicting here keeps
            // the resident set bounded to live segments and guarantees no stale entry can survive a
            // segment's retirement. Done after the slot is removed so memory and the index agree.
            self.evict_segment_index(oldest.id);
            self.sealed_record_bytes = self
                .sealed_record_bytes
                .saturating_sub(segment_record_bytes);
            self.total_record_count = self.total_record_count.saturating_sub(segment_record_count);
            outcome.segments_reaped = outcome.segments_reaped.saturating_add(1);
            outcome.bytes_reaped = outcome.bytes_reaped.saturating_add(segment_record_bytes);
        }
        // A reap RETIRED sealed segments (raising `oldest` and deleting their files), so REPUBLISH
        // the off-actor read plane (#539) — the new sealed snapshot no longer references the
        // now-deleted files, so a concurrent reader can never seek into a reaped segment. The flushed
        // frontier is unchanged by a reap (the head only ever loses a PREFIX), but republishing it is
        // harmless and keeps the publish path uniform. A no-op if nothing was reaped or no plane is
        // built. A consumer below the new `oldest` already gets the through-actor truncation signal.
        if outcome.segments_reaped > 0 {
            self.republish_read_plane();
        }
        Ok(outcome)
    }

    /// The size-only segment reaper: deletes whole old sealed segments while the durable log
    /// exceeds `max_retained_bytes` (refs #13, #80). A thin wrapper over [`Log::reap`] with only
    /// the byte bound set, preserved for callers and tests that want the byte bound alone; `0`
    /// means UNLIMITED (the byte bound is off, the default). See [`Log::reap`] for the full
    /// consumer-safety, ordering, and accounting contract.
    ///
    /// # Errors
    /// Returns [`StorageError`] from reading a segment's length, unlinking it, or the directory
    /// sync, leaving the in-memory state consistent with disk (see [`Log::reap`]).
    pub fn reap_to_size(
        &mut self,
        max_retained_bytes: u64,
        protect_below_offset: u64,
    ) -> Result<ReapOutcome, StorageError> {
        self.reap(
            RetentionBounds {
                max_bytes: max_retained_bytes,
                ..RetentionBounds::default()
            },
            protect_below_offset,
        )
    }

    /// FORCE-reaps the OLDEST sealed segment, IGNORING consumer-safety: the disk-full drop-oldest
    /// reclamation primitive (#82). Unlike [`Log::reap`], this does NOT protect a slow consumer's
    /// unconsumed records, so it may delete records below a group's cursor; the caller (the engine
    /// under the drop-oldest policy) is responsible for surfacing the resulting below-earliest
    /// truncation to that consumer (#84). It still NEVER reaps the active segment: with only the
    /// active segment present (one slot), it returns `Ok(None)` and reclaims nothing, so a single
    /// oversized in-flight set cannot wedge the log empty.
    ///
    /// The earliest retained offset after a successful force-reap is the new oldest segment's
    /// `base_offset` (see [`Log::earliest_offset`]); a consumer whose cursor is below it has lost
    /// the span `[old_cursor, new_earliest)`.
    ///
    /// Crash-safety and accounting are IDENTICAL to [`Log::reap`]: the segment file is unlinked and
    /// the directory fsynced (so the removal is durable) BEFORE the slot leaves `segments` and the
    /// running `sealed_record_bytes` / `total_record_count` totals are decremented by exactly that
    /// segment's record region (`valid_end - SEGMENT_HEADER_LEN`) and record count, read the same
    /// way the totals were accumulated. A crash before the in-memory update leaves the slot and the
    /// totals untouched (memory never claims a segment is gone while it survives on disk); a crash
    /// after leaves a shorter contiguous chain with a non-zero start, which recovery already
    /// accepts and from which it recomputes the running totals. So after a force-reap the running
    /// totals still equal a fresh reopen's recomputed values.
    ///
    /// Returns `Ok(Some(outcome))` reporting the one segment and its bytes reclaimed, or `Ok(None)`
    /// when only the active segment remains (nothing was reaped).
    ///
    /// # Errors
    /// Returns [`StorageError`] from reading the reaped segment's scan, unlinking it, or the
    /// directory sync, leaving the in-memory state consistent with disk (as [`Log::reap`]).
    pub fn reap_oldest_forced(&mut self) -> Result<Option<ReapOutcome>, StorageError> {
        // A second slot must exist so the ACTIVE segment (the last slot) is never reaped. With
        // only one slot (the single segment IS the active one) there is nothing to force-reap.
        if self.segments.len() < 2 {
            return Ok(None);
        }
        let oldest = self.segments[0];
        // The reaped segment's durable RECORD bytes and COUNT, and its storage retirement (a REMOTE
        // oldest deletes its manifest entry + cold object, #643). The durable removal precedes the
        // in-memory slot removal below, so memory never claims a segment is gone while it survives.
        let (segment_record_bytes, segment_record_count) =
            self.reap_retire_oldest_files(&oldest)?;
        self.segments.remove(0);
        // EVICT the force-reaped segment's resident seek index (#483) as its slot leaves memory, so
        // no stale index can outlive the segment it described (the same retirement guarantee `reap`
        // makes).
        self.evict_segment_index(oldest.id);
        self.sealed_record_bytes = self
            .sealed_record_bytes
            .saturating_sub(segment_record_bytes);
        self.total_record_count = self.total_record_count.saturating_sub(segment_record_count);
        // The force-reap RETIRED a sealed segment (raising `oldest`, deleting its file): REPUBLISH
        // the off-actor read plane (#539) so its snapshot drops the now-deleted segment and no
        // concurrent reader can seek into it. A no-op if no plane is built.
        self.republish_read_plane();
        Ok(Some(ReapOutcome {
            segments_reaped: 1,
            bytes_reaped: segment_record_bytes,
        }))
    }

    /// TRUNCATES the log so its durable bytes end exactly at `target` — dropping the suffix
    /// `[target, next_offset)` and keeping the prefix `[earliest, target)` byte-for-byte. This is the
    /// storage primitive behind C2-I4 leader-epoch divergence truncation (KIP-101, #599): when a
    /// follower discovers (via the epoch cache + the leader's epoch history) that its uncommitted tail
    /// diverges from a new leader's lineage, it truncates EXACTLY to the divergence point, drops only
    /// the genuinely-divergent suffix, and re-fetches forward — never silently diverging, never
    /// over-truncating committed data.
    ///
    /// It REUSES the existing recovery machinery: it performs the physical file surgery (unlink whole
    /// segments above the kept one, `set_len` + fsync the kept segment down to `target`'s record-frame
    /// boundary), then RE-DERIVES every in-memory field by re-running the same [`Log::scan_recover_chain`]
    /// scan over the surviving durable bytes — so the post-truncation log is BYTE-IDENTICAL to a fresh
    /// log of the same prefix, and recovery stays a pure function of the durable bytes (I4). The
    /// truncation is BOUNDED (it drops a measured, reported suffix) and REPORTED (it returns a typed
    /// [`TruncateOutcome`] the caller surfaces as a divergence event — never a silent drop, the beat
    /// over NATS #5576).
    ///
    /// The kept segment is the one holding the LAST surviving record (offset `target - 1`); truncating
    /// to a segment's exact base offset drops that segment wholesale and UNSEALS its predecessor as the
    /// new active writer — so the result is the same shape a fresh log of `target` records has, never a
    /// sealed-tail-plus-empty-active artifact.
    ///
    /// `target` must lie in `[earliest_offset(), next_offset()]`:
    /// - `target == next_offset()` drops nothing (a clean no-op `TruncateOutcome`).
    /// - `target == earliest_offset()` drops the whole retained range (the log stays writable, empty).
    ///
    /// The CALLER guarantees `target` is at or above the committed high-watermark, so committed data
    /// (fsync'd on a quorum, #691) is NEVER truncated — only the uncommitted-divergent suffix is. This
    /// method enforces the durable-range bound; the never-below-HW property is the cluster layer's.
    ///
    /// # Errors
    /// - [`StorageError::TruncateOutOfRange`] if `target` is below the earliest retained offset or
    ///   above the durable head, or lands inside a COMPACTED segment (committed data, out of the
    ///   C2-I4 uncommitted-suffix contract) — fail-closed: the log is left untouched.
    /// - [`StorageError::WriterFrozen`] if the writer is frozen, or an IO/segment error from the file
    ///   surgery or the re-derivation. The unlink-then-truncate order keeps the chain
    ///   valid-prefix-recoverable at every step, so a crash mid-surgery is reconciled by [`Log::open`].
    pub fn truncate_to(&mut self, target: Offset) -> Result<TruncateOutcome, StorageError> {
        // Finish any transient-fault-deferred roll first (#867) so the truncation acts on a fully
        // installed active segment, not a momentarily-deferred one.
        self.ensure_writable()?;
        // Fail closed if the writer is already dead: we never truncate against a frozen log.
        self.active()?;
        let next = self.next_offset.get();
        let earliest = self.earliest_offset().get();
        let target_v = target.get();
        if target_v > next || target_v < earliest {
            return Err(StorageError::TruncateOutOfRange {
                requested: target_v,
                earliest,
                next_offset: next,
            });
        }
        // A truncate to the durable head drops nothing.
        if target_v == next {
            return Ok(TruncateOutcome {
                truncated_to: target_v,
                next_offset_before: next,
                records_dropped: 0,
                bytes_dropped: 0,
                segments_dropped: 0,
            });
        }

        // The durable record bytes BEFORE the surgery, so the reclaimed bytes are the exact drop.
        let bytes_before = self.durable_record_bytes();

        // The kept segment is the one holding the LAST surviving record. When the whole retained range
        // is dropped (`target == earliest`), there is no surviving record, so keep the FIRST segment
        // and empty it to header-only — the log stays writable from `earliest`.
        let keep_idx = if target_v > earliest {
            self.segment_index_for(target_v - 1)
        } else {
            0
        };
        let keep_slot = self.segments[keep_idx];
        // A compacted segment never holds an uncommitted divergent suffix (its records are committed +
        // compacted, always below the caller's HW floor): a target landing in one is out of the C2-I4
        // contract, refused fail-closed.
        if keep_slot.compacted_covered.is_some() {
            return Err(StorageError::TruncateOutOfRange {
                requested: target_v,
                earliest,
                next_offset: next,
            });
        }

        // Capture the active writer's data end BEFORE dropping it: when the KEPT segment is the
        // active one, its preallocated logical extension makes the file roll-size long, and the
        // `record_byte_positions` walk below would otherwise eagerly allocate and read the whole
        // zero tail. Bounding the reader at `write_pos` is byte-identical for the walk (zeros
        // decode no frame) and leaves the truncate-down below untouched.
        let keep_data_end = (keep_slot.id == self.active_id)
            .then(|| self.active.as_ref().map(SegmentWriter::write_pos))
            .flatten();

        // Drop the active writer before any file surgery: it is rebuilt from the recovered chain.
        self.active = None;

        // Unlink every WHOLE segment strictly ABOVE the kept one (its base_offset >= target, so its
        // entire range is in the divergent suffix). `split_off` keeps `[0, keep_idx]` and yields the
        // tail to unlink. Iterate the tail HIGHEST-id-first (reverse order): the single trailing
        // dir-sync below still batches every removal durable together, so under the InMemoryFs
        // canonical crash model (durable reverts to the last sync barrier atomically) the final state
        // is unchanged. On a REAL FS a crash MID-loop can leave only a PREFIX of the ISSUED unlink
        // sequence durable — same-directory metadata ops complete in issue order under ordered
        // journaling (the prefix-durability this storage layer already relies on), and the single
        // trailing dir-sync batches the rest. Removing highest-first makes that surviving prefix
        // `{highest, highest-1, ...}` drop the TOP of the chain, so the survivors are always a
        // CONTIGUOUS prefix `[0, kept..k]` (never [kept, <gap>, higher]) — always openable, in the
        // same spirit as `Log::reap`. A later reconcile then re-runs this truncation idempotently over
        // the valid, over-long prefix. (Lowest-first could leave a durable low-unlink with a surviving
        // higher segment -> a gap -> `scan_recover_chain` fails `SegmentChainBroken` -> an UNOPENABLE
        // log. NOTE: under truly ARBITRARY unlink reorder highest-first alone would not suffice — that
        // needs a per-unlink dir-sync as `Log::reap` does; here we rely on same-dir prefix-durability
        // plus the trailing sync_dir.)
        let mut segments_dropped = 0u64;
        let mut tail = self.segments.split_off(keep_idx + 1);
        while let Some(slot) = tail.pop() {
            self.fs.remove(&segment_file_name(slot.id))?;
            self.evict_segment_index(slot.id);
            segments_dropped += 1;
        }

        // Truncate the kept segment's file down to the frame boundary of `target`. The record at log
        // offset `target` (and every record after it within this segment) is dropped; the region
        // `[header, byte_pos_of(target))` survives. When `target` is the kept segment's own next
        // offset (it held only surviving records), nothing inside it is cut beyond removing a sealed
        // footer — which unseals it into the active writer, matching a fresh log's shape.
        let keep_name = segment_file_name(keep_slot.id);
        let mut reader = SegmentReader::open(self.fs.open(&keep_name)?)?;
        if let Some(end) = keep_data_end {
            reader = reader.with_data_end(end);
        }
        let (positions, body_end) = reader.record_byte_positions()?;
        let within = usize::try_from(target_v - keep_slot.base_offset)
            .map_err(|_| StorageError::SegmentFull)?;
        // `positions[i]` is the frame start of the (base_offset + i)-th record; `body_end` is the end
        // of the record region (excluding any sealed footer). The cut is that frame start for an
        // in-segment record, or `body_end` when `target` is this segment's next offset (drop only the
        // footer, if any).
        let truncate_at = positions.get(within).copied().unwrap_or(body_end);
        let file = self.fs.open(&keep_name)?;
        if truncate_at < file.len()? {
            file.set_len(truncate_at)?;
            file.sync_all()?;
        }
        // Persist the unlinks + the truncation durably before we trust the new on-disk shape.
        self.fs.sync_dir()?;

        // Re-derive EVERY in-memory field from the surviving durable bytes, exactly as a reopen would
        // (recovery is a pure function of the durable bytes, I4), and commit the new state.
        let new_next_offset = self.rederive_state_after_truncation(keep_slot.id)?;

        let records_dropped = next.saturating_sub(new_next_offset.get());
        let bytes_dropped = bytes_before.saturating_sub(self.durable_record_bytes());
        Ok(TruncateOutcome {
            truncated_to: new_next_offset.get(),
            next_offset_before: next,
            records_dropped,
            bytes_dropped,
            segments_dropped,
        })
    }

    /// Re-derives every in-memory field of the log from the surviving durable bytes after the
    /// truncation file surgery has run, exactly as [`Log::recover`] would on a reopen (recovery is a
    /// pure function of the durable bytes, I4), and commits the new state. `last_id` is the kept
    /// (now-truncated, unsealed) highest segment, which becomes the active writer. Returns the new
    /// `next_offset`. Factored out of [`Log::truncate_to`] to keep both functions small.
    fn rederive_state_after_truncation(&mut self, last_id: u64) -> Result<Offset, StorageError> {
        // The surviving ids are the kept slot and its predecessors (the divergent suffix's whole
        // segments were already unlinked from `self.segments`).
        let surviving_ids: Vec<u64> = self.segments.iter().map(|s| s.id).collect();
        let RecoveredChain {
            slots,
            next_base_offset,
            next_base_seq,
            durable_bytes,
            total_record_count,
            highest: scan,
        } = Self::scan_recover_chain(&self.fs, &surviving_ids)?;

        let new_next_offset = Offset::new(next_base_offset);
        let highest_record_bytes = scan.valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64);
        let sealed_record_bytes = durable_bytes.saturating_sub(highest_record_bytes);

        // Rebuild the active writer over the (now-truncated, unsealed) highest segment. After a
        // truncation the highest segment is NEVER sealed (we cut its footer off), so we always resume
        // it as the writer — there is no roll-forward case here.
        let file = self.fs.open(&segment_file_name(last_id))?;
        let record_count =
            u32::try_from(scan.record_count).map_err(|_| StorageError::SegmentFull)?;
        let writer = SegmentWriter::resume(
            file,
            scan.header,
            scan.valid_end,
            record_count,
            scan.last_seq,
            scan.max_timestamp_ms,
        );

        // Commit the re-derived state. Everything recovered is durable, so both the visible and the
        // durable head are the recovered head (#341). The truncation only ever LOWERS these.
        self.segments = slots;
        self.active = Some(writer);
        self.active_id = last_id;
        self.next_offset = new_next_offset;
        self.next_seq = Seq::new(next_base_seq);
        self.flushed_offset = new_next_offset;
        self.synced_offset = new_next_offset;
        self.sealed_record_bytes = sealed_record_bytes;
        self.total_record_count = total_record_count;
        self.unsynced_record_bytes = 0;
        // The kept active segment's resident seek index must be rebuilt from the truncated bytes, so
        // evict any stale one (a later read rebuilds it). The dropped segments' indexes were evicted.
        self.evict_segment_index(last_id);
        // The truncation RETIRED the divergent suffix: republish the off-actor read plane so any
        // concurrent reader's snapshot drops the now-removed offsets and cannot seek into them.
        self.republish_read_plane();
        Ok(new_next_offset)
    }

    /// Runs ONE rate-limited, OFF-HOT-PATH key-compaction pass if compaction is enabled and a run of
    /// adjacent dirty SEALED segments meets the trigger (#337). It NEVER touches the active segment,
    /// so it does not race or block an append; the single writer (the append actor) calls this
    /// between commits, not inside the critical section. A pass reads N adjacent dirty sealed source
    /// segments, writes the survivors (keeping their ORIGINAL sparse offsets) into a fresh
    /// `version` = 2 compacted segment, fsyncs it, dir-fsyncs (the atomic commit point), then
    /// retires the originals, and finally replaces the covered ordinary slots in memory with the new
    /// compacted slot. A crash at any step is recovered deterministically by [`Log::open`].
    ///
    /// Returns the [`crate::compaction::CompactionOutcome`] (an empty outcome when compaction is off
    /// or no run met the trigger).
    ///
    /// # Errors
    /// Returns [`StorageError::WriterFrozen`] if the writer is frozen (no compaction on a dead
    /// writer), or propagates an IO/segment error from the pass. On an error mid-retire the
    /// directory may be partially swapped; the next [`Log::open`] reconciles it deterministically.
    pub fn maybe_compact(
        &mut self,
        config: &crate::compaction::CompactionConfig,
    ) -> Result<crate::compaction::CompactionOutcome, StorageError> {
        if !config.enabled {
            return Ok(crate::compaction::CompactionOutcome::default());
        }
        // Finish any transient-fault-deferred roll first (#867) so compaction sees a fully installed
        // active segment.
        self.ensure_writable()?;
        // Never compact on a frozen writer (it has no active segment to protect against, but the
        // log is degraded; do no extra IO).
        self.active()?;
        // Feed the trigger the resident sealed-segment metadata (#824) so discovery reads the record
        // counts already in RAM instead of re-scanning + CRC-validating every sealed segment on each
        // produce commit. The active slot is included but skipped by `select_dirty_run`'s
        // `id >= active_id` guard (its count is only meaningful once sealed anyway).
        // #643: an OFFLOADED (REMOTE) segment's bytes are not on local disk, so it can never be a
        // compaction source. Excluding it here keeps `select_dirty_run`'s candidate run to the local
        // segments (the offloaded set is always the oldest contiguous prefix, so the remaining local
        // segments still abut), and it upholds the "a segment is either offloaded or compacted, never
        // concurrently" invariant.
        let sealed: Vec<crate::compaction::SealedSegmentMeta> = self
            .segments
            .iter()
            .filter(|slot| !self.is_segment_remote(slot.id))
            .map(|slot| crate::compaction::SealedSegmentMeta {
                id: slot.id,
                base_offset: slot.base_offset,
                record_count: slot.record_count,
                is_compacted: slot.compacted_covered.is_some(),
            })
            .collect();
        let Some(source_ids) = crate::compaction::select_dirty_run(
            &self.fs,
            &self.clock,
            config,
            self.active_id,
            &sealed,
        )?
        else {
            return Ok(crate::compaction::CompactionOutcome::default());
        };
        // The fresh compacted id is strictly greater than ANY id ever used (ADR 0002): a compacted
        // segment carries a HIGH id but a LOW covered range. The active roll uses the SAME allocator,
        // so the active segment never collides with a compacted id.
        let fresh_id = self.next_fresh_segment_id()?;
        // Capture the source segments' on-disk record bytes and counts BEFORE the pass retires them
        // (after retire the files are gone), so the running-total adjustment below is exact. Each is
        // read the same way the running totals were accumulated.
        let source_set: std::collections::HashSet<u64> = source_ids.iter().copied().collect();
        let mut source_bytes = 0u64;
        let mut source_count = 0u64;
        // Clone the covered slots out so we do not hold a borrow of `self.segments` across the
        // mutating call below.
        let covered_slots: Vec<SegmentSlot> = self
            .segments
            .iter()
            .filter(|s| source_set.contains(&s.id))
            .copied()
            .collect();
        for slot in &covered_slots {
            let (bytes, count) = self.segment_record_bytes_and_count(slot)?;
            source_bytes = source_bytes.saturating_add(bytes);
            source_count = source_count.saturating_add(count);
        }
        let outcome =
            crate::compaction::compact_run(&self.fs, &self.clock, config, &source_ids, fresh_id)?;
        // Update the in-memory slot set to match the swapped directory: drop the covered ordinary
        // slots and insert the new compacted slot in their place, recomputed from the just-written
        // segment so the running totals stay exact. The sealed-record-byte total changes by the
        // (smaller) survivor bytes replacing the (larger) source bytes.
        if let Some(compacted_id) = outcome.compacted_segment_id {
            self.install_compacted_slot(compacted_id, &source_set, source_bytes, source_count)?;
        }
        Ok(outcome)
    }

    /// Replaces the in-memory ordinary slots covered by a freshly written compacted segment with the
    /// compacted slot, adjusting the running byte and count totals so they stay exact (#337). The
    /// source segments' bytes and counts are captured by the caller BEFORE the pass retired them.
    /// Called only by [`Log::maybe_compact`] after a successful pass.
    fn install_compacted_slot(
        &mut self,
        compacted_id: u64,
        source_set: &std::collections::HashSet<u64>,
        source_bytes: u64,
        source_count: u64,
    ) -> Result<(), StorageError> {
        let reader = SegmentReader::open(self.fs.open(&segment_file_name(compacted_id))?)?;
        let Some(scan) = reader.scan_compacted()? else {
            // The just-written segment must scan as a valid compacted segment; if not, surface a
            // fatal error rather than corrupt the in-memory totals.
            return Err(StorageError::WriterFrozen);
        };
        let survivor_bytes = scan.valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64);
        let survivor_count = scan.records.len() as u64;
        // Drop the covered ordinary slots, then insert the compacted slot, then re-sort by covered
        // base offset so the slot vector stays offset-ordered for the binary search.
        self.segments.retain(|s| !source_set.contains(&s.id));
        // EVICT each superseded source segment's resident seek index (#483): those ordinary slots
        // are gone, so their dense indexes must go too. The freshly installed compacted segment is
        // SPARSE and is never indexed here — the read path routes it through the v2 scan — so there
        // is nothing to add, only the source entries to drop. This is the compaction-retirement leg
        // of the evict-on-every-retirement guarantee.
        for id in source_set {
            self.evict_segment_index(*id);
        }
        self.segments.push(SegmentSlot {
            id: compacted_id,
            base_offset: scan.header.base_offset.get(),
            record_count: survivor_count,
            max_timestamp_ms: scan.max_timestamp_ms,
            compacted_covered: Some(CompactedCover {
                covered_base_offset: scan.meta.covered_base_offset,
                covered_end_offset: scan.meta.covered_end_offset,
                covered_base_seq: scan.meta.covered_base_seq,
                covered_end_seq: scan.meta.covered_end_seq,
            }),
        });
        self.segments.sort_by_key(SegmentSlot::covered_base_offset);
        // Adjust the running totals: the survivors replace the (larger) source set on disk.
        self.sealed_record_bytes = self
            .sealed_record_bytes
            .saturating_sub(source_bytes)
            .saturating_add(survivor_bytes);
        self.total_record_count = self
            .total_record_count
            .saturating_sub(source_count)
            .saturating_add(survivor_count);
        // Compaction RETIRED the source ordinary segments (their files are gone) and installed a
        // SPARSE compacted slot in their place: REPUBLISH the off-actor read plane (#539) so its
        // snapshot drops the now-deleted source files. The compacted slot is recorded as a fallback
        // marker in the snapshot (the off-actor plane does not serve the sparse v2 scan), so a read
        // of its covered range routes through the actor — identical to today's compacted read path.
        self.republish_read_plane();
        Ok(())
    }

    /// The OLDEST retained log offset: the oldest segment's `base_offset`, the first offset still
    /// present in the durable log. `0` for a fresh log or one that has never been reaped. After a
    /// reap (consumer-safe [`Log::reap`] or forced [`Log::reap_oldest_forced`]) this rises to the
    /// surviving oldest segment's base, so a consumer below it has had its records reclaimed. A
    /// read at an offset below this is [`StorageError::OffsetOutOfRange`].
    #[must_use]
    pub fn earliest_offset(&self) -> Offset {
        // The COVERED base of the first segment: for a compacted oldest segment this is the lowest
        // covered (source) offset, the true low end of the durable range, even though its lowest
        // surviving record sits above it.
        Offset::new(
            self.segments
                .first()
                .map_or(0, SegmentSlot::covered_base_offset),
        )
    }

    /// Whether the consumer-safe retention reaper ([`Log::reap`]) would consider the OLDEST sealed
    /// segment ELIGIBLE under `bounds` right now — the SAME size / count / age trip test `reap`'s
    /// loop head applies, WITHOUT unlinking anything. `false` when every bound is off, or when only
    /// the active segment exists (there is never anything to reap then). This is the read-only
    /// pre-check the shared-WAL global reap (#597) uses to decide whether paying its demux-floor
    /// checkpoint fsync could actually unlock a physical reap; keeping it here (beside `reap`) keeps
    /// the two trip tests one derivation, so they can never drift.
    #[must_use]
    pub fn retention_tripped(&self, bounds: RetentionBounds) -> bool {
        if self.segments.len() < 2 {
            return false;
        }
        let oldest = self.segments[0];
        let over_bytes = bounds.max_bytes != 0 && self.durable_record_bytes() > bounds.max_bytes;
        let over_count =
            bounds.max_messages != 0 && self.durable_record_count() > bounds.max_messages;
        let now_ms = self.clock.now_unix_millis();
        let aged_out = bounds.max_age_ms != 0
            && oldest.max_timestamp_ms.saturating_add(bounds.max_age_ms) < now_ms;
        over_bytes || over_count || aged_out
    }

    /// The HIGHEST sealed-segment boundary (a covered base offset, i.e. an offset a [`Log::reap`]
    /// could raise [`Log::earliest_offset`] to) that sits at or below `protect_below_offset`, or
    /// `None` when no sealed prefix ends at or below it (including when only the active segment
    /// exists). Walks the same "next segment's covered base" boundaries `reap` frees whole segments
    /// against, so the returned offset is by construction ACHIEVABLE by a physical reap protected at
    /// it. Read-only; used by the shared-WAL global reap (#597) to pick the exact demux-floor
    /// checkpoint value, so the logical (indexed) earliest and the physical earliest coincide after
    /// a completed reap.
    #[must_use]
    pub fn sealed_prefix_end_at_or_below(&self, protect_below_offset: u64) -> Option<u64> {
        let mut end = None;
        for slot in self.segments.iter().skip(1) {
            let base = slot.covered_base_offset();
            if base <= protect_below_offset {
                end = Some(base);
            } else {
                break;
            }
        }
        end
    }

    /// The index in `segments` of the segment whose range holds `offset` (the slot with
    /// the largest `base_offset` not exceeding `offset`). Callers guarantee `offset` is
    /// at least the oldest base offset.
    /// The durable RECORD bytes (`valid_end - SEGMENT_HEADER_LEN`) and record COUNT of one segment,
    /// read the SAME way the running totals were accumulated, so a reap's decrement is exact. A
    /// COMPACTED segment is read via the v2 scan (its survivors are sparse and would fail the dense
    /// v1 recovery scan); an ordinary segment uses the streaming recovery scan. Used by the reapers
    /// so they can reclaim a compacted oldest segment too.
    fn segment_record_bytes_and_count(
        &self,
        slot: &SegmentSlot,
    ) -> Result<(u64, u64), StorageError> {
        let name = segment_file_name(slot.id);
        let reader = SegmentReader::open(self.fs.open(&name)?)?;
        if slot.compacted_covered.is_some() {
            match reader.scan_compacted()? {
                Some(scan) => Ok((
                    scan.valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64),
                    scan.records.len() as u64,
                )),
                None => Err(StorageError::WriterFrozen),
            }
        } else {
            let scan = reader.scan_recovery()?;
            Ok((
                scan.valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64),
                scan.record_count,
            ))
        }
    }

    /// Ensures a RESIDENT seek index (#483) exists for the DENSE (v1) segment `slot`, building it
    /// from a one-time frame walk of the durable record region if it is not already cached, and
    /// returns the byte position of `start_offset`'s frame together with the byte READ-END for a
    /// seek-and-read-forward bounded by `flushed`. The frame walk validates each frame's header CRC
    /// and delimits the SAME valid prefix a full scan would (it stops at the first torn or corrupt
    /// frame); the FULL body-CRC validation of the records actually returned happens in
    /// [`SegmentReader::scan_from`].
    ///
    /// The read-end is the byte position of the FIRST non-visible offset (`flushed`) within this
    /// segment when the index covers it, otherwise the segment's `valid_end`. This is CRITICAL: a
    /// record's index entry is written on append (`valid_end` extends immediately), but the bytes
    /// may still sit in the writer's pending buffer until a flush; reads are clamped to `flushed`,
    /// and every record BELOW `flushed` is guaranteed to be IN the file (a flush precedes raising
    /// the visible head), so bounding the read at `flushed`'s byte position never reads a pending
    /// (not-yet-in-file) frame.
    ///
    /// Returns `Ok(None)` only when `start_offset` is NOT covered by the built index (it is at or
    /// past the segment's last indexed record — e.g. the read targets the as-yet-unflushed tail);
    /// the caller falls back to its existing scan for that segment, so a miss is never wrong, only
    /// (rarely) slower. The active segment's index is seeded/extended by the append path, so the
    /// common consume case hits the cache without a rebuild.
    fn seek_in_segment(
        &self,
        slot: &SegmentSlot,
        start_offset: u64,
        want_records: usize,
    ) -> Result<Option<(u64, u64, u64)>, StorageError> {
        // A compacted (v2, sparse) segment is never indexed here; the caller routes it to the v2
        // scan. This guard keeps the resident index strictly to the dense case.
        debug_assert!(slot.compacted_covered.is_none());
        if let Some(idx) = self.segment_indexes.borrow().get(&slot.id) {
            return Ok(Self::seek_with(idx, start_offset, want_records));
        }
        // Build once from the durable frames: the SPARSE anchors delimit exactly the valid prefix a
        // scan would (the streaming walk stops at the same torn tail), so seeking into the index can
        // never point past a torn tail. The build is `O(records)` ONCE (header-only stepping, no body
        // materialization) and the resident result is `O(region_bytes / stride)`. This build path is
        // for SEALED predecessors (the active segment's index is always append-seeded), whose whole
        // record region is durable and in the file, so `flushed_end == valid_end`.
        let reader = SegmentReader::open(self.fs.open(&segment_file_name(slot.id))?)?;
        let (anchors, valid_end) =
            reader.sparse_record_byte_positions(SEGMENT_INDEX_STRIDE_BYTES)?;
        // The covered record count is the dense record count of the valid prefix. Recover it from the
        // segment's own recovery scan (the authoritative count of the valid prefix), falling back to
        // the slot's running count if that scan somehow fails.
        let record_count = reader
            .scan_recovery()
            .map_or(slot.record_count, |r| r.record_count);
        let index = SegmentIndex {
            base_offset: slot.base_offset,
            anchors,
            record_count,
            stride: SEGMENT_INDEX_STRIDE_BYTES,
            next_anchor_at: valid_end,
            valid_end,
            flushed_end: valid_end,
        };
        let result = Self::seek_with(&index, start_offset, want_records);
        self.segment_indexes.borrow_mut().insert(slot.id, index);
        Ok(result)
    }

    /// Resolves `start_offset` to its SEEK anchor (the nearest indexed `(anchor offset, anchor byte
    /// position)` at or before it) and the WINDOW-BOUNDED read-end against a built `index` (#537,
    /// window bound #664). The caller seeks to the anchor byte position, reads forward, and skips the
    /// bounded run of records below `start_offset`. `None` when `start_offset` is not covered (the
    /// caller falls back to a full scan).
    ///
    /// The read-end is bounded BOTH by the index's `flushed_end` (the in-file prefix end — for the
    /// active segment the byte position up to which pending bytes were last flushed, so a seek never
    /// reads an appended-but-not-yet-flushed frame; for a sealed predecessor the whole durable record
    /// region, `flushed_end == valid_end`) AND by the WINDOW (#664): `want_records` records starting
    /// at `start_offset` span at most up to the first sparse anchor above `start_offset +
    /// want_records`, so a seek-and-read-forward reads `O(want + stride)` bytes, NOT
    /// `O(distance-to-segment-end)`. Before #664 the read-end was the segment-wide `flushed_end`,
    /// making a forward streaming drain `O(N^2)`. The per-record `>= flushed` / `max` filters in the
    /// scan then enforce the exact visibility and count boundary among the frames the read returns.
    fn seek_with(
        index: &SegmentIndex,
        start_offset: u64,
        want_records: usize,
    ) -> Option<(u64, u64, u64)> {
        let covered_end = index.covered_end();
        let (anchor_offset, byte_pos) = index.seek_anchor(start_offset, covered_end)?;
        let flushed_end = index.flushed_end.min(index.valid_end);
        // #664: bound the read to the WINDOW (anchor -> first anchor above `start + want`), clamped to
        // the flushed prefix end. The anchor may sit BELOW `start_offset` (sparse, one-per-stride), so
        // the window is measured from `start_offset` (where the caller's wanted records begin); the
        // gap below it is at most one stride and is contained by the same first-anchor-above bound.
        let read_end = index.window_read_end(start_offset, want_records, flushed_end);
        Some((anchor_offset, byte_pos, read_end))
    }

    /// Ensures a RESIDENT sparse seek index (#481) exists for the COMPACTED (v2) segment `slot`,
    /// building it from a one-time validating walk of the survivor region ([`SegmentReader::
    /// compacted_byte_positions`]) if it is not already cached, and returns the SEEK target for a
    /// read starting at `start_offset`: the byte position of the first survivor at or above
    /// `start_offset`, the segment's offset/sequence base (for the original-offset reconstruction),
    /// and the survivor-region byte READ-END.
    ///
    /// The build applies the SAME structural validation `scan_compacted` does, so a slot that no
    /// longer indexes as a valid compacted segment surfaces [`StorageError::WriterFrozen`] (the
    /// recovery reconciliation should have prevented it) rather than silently serving nothing —
    /// preserving the pre-#481 behavior where the read path errored on an invalid compacted slot.
    ///
    /// Returns `Ok(None)` when no survivor is at or above `start_offset` (the segment is exhausted
    /// for this read): the caller advances to the next slot. A `start_offset` that lands in a
    /// compaction HOLE resolves to the next present survivor, so the read advances over the gap. The
    /// survivor region lies entirely below `flushed` for a sealed compacted segment (compaction only
    /// ever produces sealed segments, never the active one), so unlike the dense path there is no
    /// flushed-byte clamp here; the per-record `>= flushed` filter in `read_from` is the (no-op for a
    /// compacted slot, belt-and-suspenders) visibility bound.
    fn seek_in_compacted<R: RandomAccessFile>(
        &self,
        slot: &SegmentSlot,
        start_offset: u64,
        reader: &SegmentReader<R>,
    ) -> Result<Option<(u64, u64, u64, u64)>, StorageError> {
        debug_assert!(slot.compacted_covered.is_some());
        let base_off = reader.header().base_offset.get();
        let base_seq = reader.header().base_seq.get();
        if let Some(idx) = self.compacted_indexes.borrow().get(&slot.id) {
            return Ok(idx
                .seek_at_or_after(start_offset)
                .map(|byte_pos| (byte_pos, base_off, base_seq, idx.valid_end)));
        }
        // Build once from the durable survivor frames: the walk validates the footer/block and the
        // whole-set sequence run exactly as `scan_compacted` does, so a seek into the index can never
        // point past the survivor region or serve an unvalidated set.
        let Some((entries, valid_end)) = reader.compacted_byte_positions()? else {
            // A compacted slot that no longer scans as a valid compacted segment is a structural
            // inconsistency the recovery reconciliation should have prevented; surface it rather than
            // silently serving nothing (the same verdict the pre-#481 read path reached).
            return Err(StorageError::WriterFrozen);
        };
        let index = CompactedIndex { entries, valid_end };
        let result = index
            .seek_at_or_after(start_offset)
            .map(|byte_pos| (byte_pos, base_off, base_seq, index.valid_end));
        self.compacted_indexes.borrow_mut().insert(slot.id, index);
        Ok(result)
    }

    /// EVICTS the resident seek index for segment `id`, called on EVERY segment retirement (reap,
    /// force-reap, compaction install) so a recycled or compacted-away segment id can never be
    /// seeked with a stale index. Drops the entry from BOTH the dense (#483) and the compacted
    /// sparse (#481) index maps — a given id is in at most one, and a retiring segment may be of
    /// either kind — so the evict-on-retirement guarantee covers compacted segments too. A no-op if
    /// no index was cached for `id`. Resident-only: the dropped index is rebuilt on demand if a
    /// (different) higher-id segment is later read — ids are never reused (ADR 0002), so this only
    /// ever drops a now-gone segment's data.
    fn evict_segment_index(&mut self, id: u64) {
        self.segment_indexes.borrow_mut().remove(&id);
        self.compacted_indexes.borrow_mut().remove(&id);
        // Drop the cached open reader (and its fd) for the retired segment in lockstep (#808), so a
        // reaped/compacted-away segment's fd is released, not leaked.
        self.sealed_readers.evict(id);
    }

    fn segment_index_for(&self, offset: u64) -> usize {
        // Search by the segment's COVERED base offset, not the survivor base: for a compacted
        // segment the covered base can be BELOW the lowest survivor, and a target offset in that
        // (compacted-away) sub-range still belongs to the compacted segment, where the read advances
        // forward to the next present survivor. For an ordinary segment the covered base IS the
        // base, so this reduces to the original search.
        match self
            .segments
            .binary_search_by(|slot| slot.covered_base_offset().cmp(&offset))
        {
            Ok(index) => index,
            Err(0) => 0,
            Err(index) => index - 1,
        }
    }

    // ---- The off-actor lock-free READ plane publish hooks (#539) ----

    /// Builds the immutable SEALED-prefix descriptor the read plane snapshot is published from
    /// (#539): one [`SealedSegment`] per sealed predecessor (every slot EXCEPT the active one, which
    /// is the last) carrying its covered range, its sparse seek anchors, and its durable `valid_end`,
    /// plus the `(oldest, sealed_end)` covered bounds. The active (un-sealed) segment is deliberately
    /// EXCLUDED: it is still being appended to (its index is mutated on every append), so it is never
    /// in the snapshot and a reader can never observe its in-flight bytes off-actor.
    ///
    /// Anchors are taken from the resident seek index when cached (a sealed segment's `flushed_end`
    /// equals its `valid_end`, so the cached anchors are complete), and built once from the durable
    /// frames otherwise — exactly the same `sparse_record_byte_positions` walk `seek_in_segment`
    /// uses, so the snapshot's anchors are byte-identical to the through-actor read's. A COMPACTED
    /// (v2, sparse) sealed segment is recorded as a fallback marker (no anchors): the off-actor plane
    /// hands its reads back to the through-actor v2 scan.
    fn build_sealed_descriptor(&self) -> Result<(Vec<SealedSegment>, u64, u64), StorageError> {
        let oldest = self
            .segments
            .first()
            .map_or(0, SegmentSlot::covered_base_offset);
        // The active segment is the LAST slot; the sealed prefix is everything before it. The active
        // base is the first offset NOT in the sealed prefix (the sealed end). With no sealed
        // predecessor (only the active segment, or none) the sealed prefix is empty and ends at the
        // oldest offset.
        //
        // When there is NO active segment — a frozen writer, or a roll a transient fault deferred
        // (#867), where the last slot is the just-sealed predecessor, not an active tail — EVERY slot
        // is sealed and the sealed prefix runs to the durable head. Treating the predecessor as active
        // here would drop the hottest just-sealed segment from the off-actor plane (it would fall back
        // through the actor) until the next republish.
        let active_present = self.active.is_some();
        let sealed_count = if active_present {
            self.segments.len().saturating_sub(1)
        } else {
            self.segments.len()
        };
        let sealed_slots = &self.segments[..sealed_count];
        let sealed_end = if active_present {
            self.segments
                .last()
                .map_or(oldest, SegmentSlot::covered_base_offset)
        } else {
            // No active tail: the durable head is the end of the (fully sealed) prefix.
            self.next_offset.get()
        };
        let mut sealed = Vec::with_capacity(sealed_count);
        for slot in sealed_slots {
            if self.is_segment_remote(slot.id) {
                // #643: an OFFLOADED (REMOTE) sealed segment. Its local bytes may be absent, so DON'T
                // open it to build anchors — publish it as a fetch-through-actor marker (like a
                // compacted slot) so the snapshot's offset-to-segment search stays exact across the
                // offloaded range and a read of it falls back to the actor (which restores-on-access).
                sealed.push(SealedSegment {
                    id: slot.id,
                    base_offset: slot.base_offset,
                    record_count: slot.record_count,
                    compacted: false,
                    remote: true,
                    anchors: Vec::new(),
                    valid_end: 0,
                });
                continue;
            }
            if slot.compacted_covered.is_some() {
                // A compacted sealed segment: the off-actor plane does not serve it (the through-
                // actor v2 scan does). Record it as a fallback marker so the snapshot's offset-to-
                // segment search stays exact across its covered range.
                sealed.push(SealedSegment {
                    id: slot.id,
                    base_offset: slot.covered_base_offset(),
                    record_count: slot.compacted_covered.map_or(slot.record_count, |c| {
                        c.covered_end_offset.saturating_sub(c.covered_base_offset)
                    }),
                    compacted: true,
                    remote: false,
                    anchors: Vec::new(),
                    valid_end: 0,
                });
                continue;
            }
            // Prefer the resident index (a sealed segment's anchors are complete: flushed_end ==
            // valid_end), else build once from the durable frames — the SAME sparse walk the read
            // path uses, so the snapshot's anchors match the through-actor read byte-for-byte.
            let (anchors, valid_end) =
                if let Some(idx) = self.segment_indexes.borrow().get(&slot.id) {
                    (idx.anchors.clone(), idx.valid_end)
                } else {
                    let reader = SegmentReader::open(self.fs.open(&segment_file_name(slot.id))?)?;
                    reader.sparse_record_byte_positions(SEGMENT_INDEX_STRIDE_BYTES)?
                };
            sealed.push(SealedSegment {
                id: slot.id,
                base_offset: slot.base_offset,
                record_count: slot.record_count,
                compacted: false,
                remote: false,
                anchors,
                valid_end,
            });
        }
        Ok((sealed, oldest, sealed_end))
    }

    /// PUBLISHES the new flushed frontier to the read plane after every commit/flush (#539), IF the
    /// plane has been built (a consumer asked for it). The sealed set is UNCHANGED by a plain
    /// `sync`/`flush_no_sync` (no roll), so only the atomic frontier is republished — the cheap, hot
    /// path. A RELEASE store: it is the LAST thing the writer publishes and the FIRST thing a reader
    /// observes, so a reader that sees this frontier also sees every prior `publish_sealed` (the
    /// module-level ordering argument). A no-op when no plane is built.
    fn publish_flushed_frontier(&self) {
        if let Some(plane) = self.read_plane.borrow().as_ref() {
            plane.publish_flushed(self.flushed_offset.get());
        }
    }

    /// REPUBLISHES the whole read plane after the SEALED SET changed (a roll sealed a segment, or a
    /// reap retired one) (#539), IF the plane is built. Rebuilds the immutable sealed snapshot from
    /// the current `self.segments` and stores it FIRST (a Release `ArcSwap::store`), THEN stores the
    /// frontier (a Release store). This publish ORDER is load-bearing: a reader observes the frontier
    /// FIRST (Acquire) and the snapshot SECOND, so a frontier it sees never admits an offset the
    /// snapshot lacks. A no-op when no plane is built. Best-effort on the snapshot build: a transient
    /// read error leaves the previous snapshot in place (still valid, covering fewer offsets), and
    /// the frontier is still published, so the through-actor fallback serves any gap correctly.
    fn republish_read_plane(&self) {
        let needs_publish = self.read_plane.borrow().is_some();
        if !needs_publish {
            return;
        }
        // Build the new sealed descriptor OUTSIDE the plane borrow (the build borrows
        // `segment_indexes`). On a build error keep the old snapshot and still bump the frontier.
        match self.build_sealed_descriptor() {
            Ok((sealed, oldest, sealed_end)) => {
                if let Some(plane) = self.read_plane.borrow().as_ref() {
                    // The Arc<F> the plane already holds is reused for the new snapshot (the
                    // filesystem handle is the same directory); rebuild only the segment view.
                    plane.republish_sealed(sealed, oldest, sealed_end);
                    plane.publish_flushed(self.flushed_offset.get());
                }
            }
            Err(_) => self.publish_flushed_frontier(),
        }
    }
}

impl<F: Filesystem + Clone, C: Clock> Log<F, C> {
    /// Returns a clone of the lock-free, off-actor consume READ plane (#539), BUILDING it on the
    /// first call. A consumer thread holds this handle to read the SEALED, flushed prefix with NO
    /// lock and NO append-actor round-trip; the single append actor (this `Log`) keeps PUBLISHING to
    /// it after every commit/seal. Cloning the returned handle is two `Arc` bumps, so every consumer
    /// shares the SAME published frontier and snapshot.
    ///
    /// Built lazily so a single-writer log that is never read off-actor pays nothing, and so the
    /// `F: Clone` bound (needed to put the filesystem handle behind an `Arc` for cross-thread
    /// readers) is required only HERE, not on `Log::open` (which stays generic over any
    /// `F: Filesystem`, including the non-`Clone` fault filesystems the durability tests use). The
    /// build is idempotent: the first caller seeds the plane from the current durable state (the
    /// recovered/​live flushed frontier + the current sealed snapshot), every later caller clones it.
    ///
    /// # Errors
    /// Propagates an IO error from building the initial sealed snapshot (reading the sealed segments'
    /// sparse seek anchors). After it returns Ok the plane is cached and never rebuilt.
    pub fn read_plane(&self) -> Result<ReadPlane<F>, StorageError> {
        if let Some(plane) = self.read_plane.borrow().as_ref() {
            return Ok(plane.clone());
        }
        // Seed from the current durable state. The filesystem handle is CLONED behind an `Arc` so
        // any number of reader threads can open the immutable sealed files concurrently with the
        // writer (a clone aliases the SAME directory; `Filesystem` is `Send + Sync`).
        let (sealed, oldest, sealed_end) = self.build_sealed_descriptor()?;
        let plane = ReadPlane::new(
            std::sync::Arc::new(self.fs.clone()),
            self.flushed_offset.get(),
            sealed,
            oldest,
            sealed_end,
        );
        *self.read_plane.borrow_mut() = Some(plane.clone());
        Ok(plane)
    }
}

/// Trims a [`RawByteRun`] to begin at `seg_start` (dropping the leading frames a sparse anchor preceded
/// it by) and re-bounds it to `max_records` / `max_bytes` over the trimmed run — a HEADER-ONLY walk (no
/// body decode), so it preserves the zero-copy property (the result is a refcount RE-SLICE of the input's
/// `bytes`, never a copy). The through-actor twin of the read-plane's `trim_raw_run`, used by
/// [`Log::read_range_raw`] (#541) to make a raw run byte-identical to the prefix [`Log::read_range`] would
/// return over the same single segment.
fn trim_and_bound_raw_run(
    run: &RawByteRun,
    seg_start: u64,
    max_records: usize,
    max_bytes: Option<usize>,
) -> RawByteRun {
    let mut cursor = 0usize;
    let mut offset = run.first_offset.get();
    let bytes = &run.bytes;
    // Drop the leading frames below `seg_start` by walking their header lengths.
    while offset < seg_start && cursor < bytes.len() {
        let Ok(consumed) = ironbus_core::codec::decoded_len(&bytes[cursor..]) else {
            break;
        };
        if cursor.saturating_add(consumed) > bytes.len() {
            break;
        }
        cursor += consumed;
        offset = offset.saturating_add(1);
    }
    let run_start_byte = cursor;
    let first_offset = offset;
    // Admit up to `max_records` / `max_bytes` frames from `seg_start`, "at least one" honored.
    let mut count = 0usize;
    let mut byte_total = 0usize;
    while cursor < bytes.len() && count < max_records {
        let Ok(consumed) = ironbus_core::codec::decoded_len(&bytes[cursor..]) else {
            break;
        };
        if cursor.saturating_add(consumed) > bytes.len() {
            break;
        }
        if let Some(cap) = max_bytes {
            if count != 0 && byte_total.saturating_add(consumed) > cap {
                break;
            }
        }
        byte_total = byte_total.saturating_add(consumed);
        count += 1;
        offset = offset.saturating_add(1);
        cursor += consumed;
    }
    RawByteRun {
        bytes: bytes.slice(run_start_byte..run_start_byte + byte_total),
        first_offset: Offset::new(first_offset),
        record_count: count as u64,
        next_offset: Offset::new(offset),
    }
}

#[cfg(test)]
impl<F: Filesystem, C: Clock> Log<F, C> {
    /// Whether a resident seek index (#483) is currently cached for segment `id`. Lets a test assert
    /// the evict-on-retirement contract directly.
    fn has_segment_index(&self, id: u64) -> bool {
        self.segment_indexes.borrow().contains_key(&id)
    }

    /// Whether an opened sealed-segment reader (#808) is currently cached for segment `id`. Lets a test
    /// assert the same evict-on-retirement contract for the reader cache.
    fn has_sealed_reader(&self, id: u64) -> bool {
        self.sealed_readers.get(id).is_some()
    }

    /// The number of resident seek indexes currently cached, so a test can assert the resident set
    /// stays bounded to the working set (no permanent dense vector per cold sealed segment).
    fn segment_index_count(&self) -> usize {
        self.segment_indexes.borrow().len()
    }

    /// Drops EVERY cached seek index, forcing the next read to rebuild from the durable frames. A
    /// test uses this to prove the freshly-BUILT index path (not just the append-seeded one) is
    /// byte-identical to a full scan.
    fn clear_segment_indexes(&self) {
        self.segment_indexes.borrow_mut().clear();
    }

    /// Installs a deliberately CORRUPT seek index for segment `id` with ONE anchor pointing at a
    /// byte position WELL PAST the segment's records (`valid_end`), so a seek that consulted it would
    /// read nothing (the wrong, empty result) for every covered offset. A test installs this,
    /// confirms the retirement path EVICTS it, and then confirms the rebuilt index serves the right
    /// data — proving a stale index can never outlive its segment.
    fn poison_segment_index(&self, id: u64, base_offset: u64, len: usize, valid_end: u64) {
        self.segment_indexes.borrow_mut().insert(
            id,
            SegmentIndex {
                base_offset,
                // A single anchor at the END of the region: `seek_anchor` resolves every covered
                // offset to it, so a read would seek past the records and return the wrong (empty)
                // slice — clear evidence the poisoned index was consulted instead of being evicted.
                anchors: vec![(base_offset, valid_end)],
                record_count: len as u64,
                stride: SEGMENT_INDEX_STRIDE_BYTES,
                next_anchor_at: valid_end,
                valid_end,
                flushed_end: valid_end,
            },
        );
    }

    /// Whether a resident COMPACTED (sparse, #481) seek index is currently cached for segment `id`.
    /// Lets a test assert the compacted-segment evict-on-retirement contract directly.
    fn has_compacted_index(&self, id: u64) -> bool {
        self.compacted_indexes.borrow().contains_key(&id)
    }

    /// Drops EVERY cached compacted (sparse) seek index, forcing the next compacted read to rebuild
    /// from the durable survivor frames. A test uses this to prove the freshly-BUILT seek path (not
    /// just the lazily-cached one) is byte-identical to the full v2 scan.
    fn clear_compacted_indexes(&self) {
        self.compacted_indexes.borrow_mut().clear();
    }

    /// Installs a deliberately CORRUPT compacted seek index for segment `id` whose every survivor
    /// entry points at the survivor region's FIRST frame byte position, so a seek that consulted it
    /// would return the WRONG (lowest) survivor for every requested offset. A test installs this,
    /// confirms the retirement path EVICTS it, and then confirms the rebuilt index serves the right
    /// sparse survivors — proving a stale compacted index can never outlive its segment.
    fn poison_compacted_index(&self, id: u64, offsets: &[u64], valid_end: u64) {
        let first = SEGMENT_HEADER_LEN as u64;
        self.compacted_indexes.borrow_mut().insert(
            id,
            CompactedIndex {
                entries: offsets.iter().map(|&o| (o, first)).collect(),
                valid_end,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use crate::segment::OwnedRecord;
    use ironbus_core::clock::ManualClock;

    // A small segment cap so rolling happens after a handful of records. This deliberately
    // sets the field below `MIN_MAX_SEGMENT_BYTES` via the struct literal (the documented
    // test path), since `LogConfig::new` would reject it; recovery and rolling do not depend
    // on the floor, only on the cap value.
    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 128,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn open_mem(config: LogConfig) -> Log<InMemoryFs, ManualClock> {
        Log::open(InMemoryFs::new(), ManualClock::new(), config).unwrap()
    }

    #[test]
    fn log_config_new_rejects_a_cap_below_the_floor() {
        // A cap that cannot hold more than one record is rejected with a typed error, not
        // silently accepted (#162). The floor leaves room for the header, the footer, and at
        // least two minimum records.
        let floor = LogConfig::MIN_MAX_SEGMENT_BYTES;
        assert!(floor >= (SEGMENT_HEADER_LEN + SEGMENT_FOOTER_LEN + 2 * RECORD_HEADER_LEN) as u64);
        for bad in [0, 1, 64, floor - 1] {
            assert_eq!(
                LogConfig::new(bad),
                Err(LogConfigError::MaxSegmentBytesTooSmall { value: bad, floor }),
                "cap {bad} should be rejected"
            );
        }
    }

    #[test]
    fn log_config_new_accepts_the_floor_and_above() {
        assert_eq!(
            LogConfig::new(LogConfig::MIN_MAX_SEGMENT_BYTES)
                .unwrap()
                .max_segment_bytes,
            LogConfig::MIN_MAX_SEGMENT_BYTES
        );
        assert_eq!(
            LogConfig::new(LogConfig::DEFAULT_MAX_SEGMENT_BYTES)
                .unwrap()
                .max_segment_bytes,
            LogConfig::DEFAULT_MAX_SEGMENT_BYTES
        );
        // A config built through `new` opens and rolls like any other.
        let cfg = LogConfig::new(LogConfig::MIN_MAX_SEGMENT_BYTES).unwrap();
        let mut log = open_mem(cfg);
        log.append(&rec(b"x")).unwrap();
        log.sync().unwrap();
        assert_eq!(log.flushed_offset(), Offset::new(1));
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

    /// Builds `k` independent logs, each rooted in its OWN in-memory disk but SHARING one
    /// [`FaultControl`](crate::fault::FaultControl), each with a record appended and
    /// flushed-but-not-synced — so every log owes exactly one covering `fdatasync`
    /// ([`has_unsynced_records`](Log::has_unsynced_records)). The shared control lets the sync
    /// rendezvous count barriers across all K fds (a barrier per fd). No sync fires here (open runs
    /// while the rendezvous is disarmed; `flush_no_sync` never syncs).
    fn build_dirtied_logs(
        control: &crate::fault::FaultControl,
        k: usize,
    ) -> Vec<Log<crate::fault::FaultFs<InMemoryFs>, ManualClock>> {
        (0..k)
            .map(|_| {
                let fs = crate::fault::FaultFs::with_control(InMemoryFs::new(), control.clone());
                let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
                log.append(&rec(b"payload")).unwrap();
                log.flush_no_sync().unwrap();
                assert!(
                    log.has_unsynced_records(),
                    "a dirtied log must owe exactly one barrier"
                );
                log
            })
            .collect()
    }

    #[test]
    fn group_commit_barriers_overlap_and_do_not_serialize() {
        use crate::fault::FaultControl;
        // #823 regression: `par_sync_data_only` must run its K per-fd `fdatasync` barriers
        // CONCURRENTLY (tick latency = max(barrier), not sum). If the shared work-queue's MutexGuard
        // is held across the blocking `fdatasync` (the edition-2021 `while let`-scrutinee drop trap),
        // the barriers SERIALIZE and this test fails — the froze/synced-SET tests can never catch that
        // because the results are identical whether the fdatasyncs overlapped or not.
        //
        // How it proves overlap: every barrier's `fdatasync` joins a rendezvous in the fault fs. The
        // group is released only once `width` barriers are inside their `fdatasync` AT THE SAME TIME.
        // A serial fan-out can never get more than one barrier in at once (the in-flight one holds the
        // queue lock, so no sibling can even reach its `fdatasync`), so the rendezvous is never
        // reached; after a bounded deadline this thread force-drains and the assertion FAILS. A
        // concurrent fan-out reaches it in microseconds and PASSES.
        const K: usize = 4;
        // The fan-out's effective width = min(cores, cap, K): at most this many barriers are ever
        // inside a `fdatasync` at once, so the rendezvous must expect exactly this many, not K.
        let width = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(COMMIT_BARRIER_MAX_WORKERS)
            .min(K);

        if width < 2 {
            // Single-core (or single-worker) CI: `par_sync_data_only` runs the fdatasyncs INLINE with
            // no threads, so there is NO overlap to observe. Prove the fan-out still completes every
            // barrier, but SKIP the strict overlap assertion (it would be meaningless with one worker,
            // and a width-1 rendezvous would trivially "reach" on the first entrant).
            let control = FaultControl::default();
            let mut logs = build_dirtied_logs(&control, K);
            let barriers = logs.iter_mut().enumerate().collect();
            let results = par_sync_data_only(barriers);
            assert_eq!(results.len(), K);
            assert!(results.iter().all(|(_, r)| r.is_ok()));
            return;
        }

        let control = FaultControl::default();
        let mut logs = build_dirtied_logs(&control, K);
        // Arm the rendezvous to the effective worker width, then run the REAL fan-out on a driver
        // thread while THIS thread enforces a bounded deadline — so a serial fan-out fails fast
        // instead of hanging the suite forever.
        control.arm_sync_rendezvous(width);
        let reached = std::thread::scope(|s| {
            let barriers = logs.iter_mut().enumerate().collect();
            let driver = s.spawn(move || par_sync_data_only(barriers));
            // The deadline is enormous versus the microseconds a concurrent rendezvous needs (a
            // correct fan-out returns on the rendezvous notify, never waiting the full timeout), so
            // this is NOT timing-flaky; the deadline only bites — failing fast — when the fan-out has
            // serialized.
            let reached =
                control.wait_for_rendezvous_or_release(std::time::Duration::from_secs(10));
            let results = driver.join().expect("fan-out driver panicked");
            assert_eq!(results.len(), K, "every barrier ran");
            assert!(
                results.iter().all(|(_, r)| r.is_ok()),
                "no barrier should freeze under a clean fs"
            );
            reached
        });
        assert!(
            reached,
            "the {width} group-commit fdatasync barriers must OVERLAP (>= {width} inside a fdatasync \
             at once); a failure here means they serialized — the queue MutexGuard is held across the \
             blocking fdatasync (#823)"
        );
    }

    // A record carrying an explicit producer timestamp, for the age-retention tests.
    fn rec_at(ts: u64, payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: ts,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    fn read_back<G: Filesystem>(fs: &G, id: u64) -> Vec<OwnedRecord> {
        let file = fs.open(&segment_file_name(id)).unwrap();
        SegmentReader::open(file).unwrap().scan().unwrap().records
    }

    fn view(seq: u64, payload: &[u8]) -> RecordView<'_> {
        RecordView {
            seq: Seq::new(seq),
            timestamp_ms: seq,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    fn header_at(segment_id: u64, base: u64) -> SegmentHeader {
        SegmentHeader {
            segment_id,
            base_seq: Seq::new(base),
            base_offset: Offset::new(base),
            created_unix_ms: 0,
            flags: 0,
        }
    }

    #[test]
    fn open_empty_creates_the_first_segment() {
        let log = open_mem(LogConfig::default());
        assert_eq!(log.active_segment_id(), FIRST_SEGMENT_ID);
        assert_eq!(log.next_offset(), Offset::ZERO);
        assert_eq!(log.next_seq(), Seq::new(0));
        assert!(log.filesystem().exists(&segment_file_name(0)).unwrap());
    }

    #[test]
    fn append_within_one_segment_does_not_roll() {
        let mut log = open_mem(LogConfig::default());
        assert_eq!(log.append(&rec(b"a")).unwrap(), Offset::new(0));
        assert_eq!(log.append(&rec(b"b")).unwrap(), Offset::new(1));
        assert_eq!(log.active_segment_id(), 0);
        assert_eq!(log.next_offset(), Offset::new(2));
        log.sync().unwrap();
        assert_eq!(read_back(log.filesystem(), 0).len(), 2);
    }

    #[test]
    fn appending_past_the_cap_rolls_to_the_next_segment() {
        let mut log = open_mem(small_config());
        // Each record is well under 128 bytes but a few cross the cap.
        let mut offsets = Vec::new();
        for i in 0..6u8 {
            offsets.push(log.append(&rec(&[i; 16])).unwrap().get());
            log.sync().unwrap();
        }
        // Offsets stay globally monotonic across the roll.
        assert_eq!(offsets, vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(log.next_offset(), Offset::new(6));
        assert_eq!(log.next_seq(), Seq::new(6));
        // More than one segment now exists, and all records are accounted for across them.
        let mut total = 0usize;
        for id in 0..=log.active_segment_id() {
            total += read_back(log.filesystem(), id).len();
        }
        assert!(log.active_segment_id() >= 1, "should have rolled");
        assert_eq!(total, 6);
        // Sealed predecessors carry a footer; the active segment does not.
        let first = SegmentReader::open(log.filesystem().open(&segment_file_name(0)).unwrap())
            .unwrap()
            .scan()
            .unwrap();
        assert!(first.footer.is_some(), "segment 0 should be sealed");
    }

    #[test]
    fn segment_ids_increase_monotonically_and_are_never_recycled() {
        // #139 decision: v1 never recycles segments. A new segment always gets a fresh id higher
        // than any existing one, never reusing a lower id, across rolls AND a restart. This keeps
        // the at-rest nonce (#18) safe: a segment_id is never reused under a fixed key.
        let mut log = open_mem(small_config());
        for i in 0..16u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        log.sync().unwrap();
        let max_before = log.active_segment_id();
        assert!(max_before >= 2, "rolled multiple segments");
        // The on-disk ids are exactly 0..=max_before, a contiguous run, each used once.
        let ids = segment_ids(log.filesystem()).unwrap();
        assert_eq!(
            ids,
            (0..=max_before).collect::<Vec<_>>(),
            "segment ids are a contiguous run with no recycling"
        );

        // Restart on the same data dir and append more: the new segments get ids STRICTLY
        // GREATER than max_before; id 0 and every prior id is retained, never reused.
        let fs = log.into_filesystem();
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        for i in 0..16u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(
            log.active_segment_id() > max_before,
            "after a restart, new segments use fresh ids, never recycling a lower one"
        );
        let ids_after = segment_ids(log.filesystem()).unwrap();
        for id in 0..=max_before {
            assert!(
                ids_after.contains(&id),
                "original segment {id} is retained, not recycled or overwritten"
            );
        }
        assert_eq!(
            ids_after,
            (0..=log.active_segment_id()).collect::<Vec<_>>(),
            "the whole id space stays a contiguous, monotonic, never-recycled run"
        );
    }

    #[test]
    fn segment_base_offset_and_seq_continue_across_a_roll() {
        let mut log = open_mem(small_config());
        for i in 0..8u8 {
            log.append(&rec(&[i; 20])).unwrap();
            log.sync().unwrap();
        }
        // The active segment's header base equals the count of records in all
        // predecessors, so global offsets are contiguous.
        let active_id = log.active_segment_id();
        let active = log
            .filesystem()
            .open(&segment_file_name(active_id))
            .unwrap();
        let header = *SegmentReader::open(active).unwrap().header();
        let predecessors: usize = (0..active_id)
            .map(|id| read_back(log.filesystem(), id).len())
            .sum();
        assert_eq!(header.base_offset.get(), predecessors as u64);
        assert_eq!(header.base_seq.get(), predecessors as u64);
    }

    #[test]
    fn reopen_recovers_across_multiple_segments() {
        let mut log = open_mem(small_config());
        for i in 0..7u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        log.sync().unwrap();
        let rolled_id = log.active_segment_id();
        assert!(rolled_id >= 1);
        let fs = log.into_filesystem();

        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(log.active_segment_id(), rolled_id);
        assert_eq!(log.next_offset(), Offset::new(7));
        assert_eq!(log.next_seq(), Seq::new(7));
        assert_eq!(log.append(&rec(b"next")).unwrap(), Offset::new(7));
    }

    #[test]
    fn reopen_after_a_seal_only_crash_rolls_forward() {
        // Simulate a crash that sealed segment 0 but never created segment 1: hand-build
        // a single sealed segment, then open. Recovery must create the next segment and
        // continue, not error or overwrite the footer.
        let fs = InMemoryFs::new();
        let file = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w = SegmentWriter::create(file, header_at(0, 0)).unwrap();
        w.append(&view(0, b"a")).unwrap();
        w.append(&view(1, b"b")).unwrap();
        w.seal().unwrap();

        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(log.active_segment_id(), 1, "should roll to segment 1");
        assert_eq!(log.next_offset(), Offset::new(2));
        assert_eq!(log.next_seq(), Seq::new(2));
        // Segment 0's footer is intact (not overwritten).
        let seg0 = SegmentReader::open(log.filesystem().open(&segment_file_name(0)).unwrap())
            .unwrap()
            .scan()
            .unwrap();
        assert!(seg0.footer.is_some());
        assert_eq!(seg0.records.len(), 2);
        // The new active segment takes records starting at offset 2.
        assert_eq!(log.append(&rec(b"c")).unwrap(), Offset::new(2));
    }

    #[test]
    fn recovery_rolls_forward_over_a_bad_header_trailing_segment() {
        // #868: a crash during `start_segment` can leave the highest segment as an EMPTY unsealed
        // tail (the prior segment was sealed before this one was created, so it holds nothing
        // durable). Recovery must roll forward and recreate it, recording the abandonment in the loss
        // report, NOT abort the whole boot on `Segment(Truncated)` and wedge a restart loop. Four
        // empty shapes are covered: 0 bytes, a zeroed 64-byte header, a header + small all-zero
        // preallocated body, and a header + all-zero body LARGER than one `segment_body_is_all_zero`
        // chunk (4096), which exercises the multi-iteration cross-chunk scan path.
        for trailing_len in [
            0usize,
            SEGMENT_HEADER_LEN,
            SEGMENT_HEADER_LEN + 256,
            SEGMENT_HEADER_LEN + 4096 + 64,
        ] {
            let fs = InMemoryFs::new();
            // A valid sealed chain seg-0 (offsets 0,1) then seg-1 (offset 2).
            let f0 = fs.create_new(&segment_file_name(0)).unwrap();
            let mut w0 = SegmentWriter::create(f0, header_at(0, 0)).unwrap();
            w0.append(&view(0, b"a")).unwrap();
            w0.append(&view(1, b"b")).unwrap();
            w0.seal().unwrap();
            let f1 = fs.create_new(&segment_file_name(1)).unwrap();
            let mut w1 = SegmentWriter::create(f1, header_at(1, 2)).unwrap();
            w1.append(&view(2, b"c")).unwrap();
            w1.seal().unwrap();
            // The trailing seg-2 a crash left mid-`start_segment`: 0 bytes, a zeroed (undecodable)
            // 64-byte header, or a header + preallocated all-zero body. All are an empty bad-HEADER
            // tail, the pre-fix unskippable abort.
            let f2 = fs.create_new(&segment_file_name(2)).unwrap();
            f2.write_all_at(&vec![0u8; trailing_len], 0).unwrap();
            f2.sync_data().unwrap();
            assert!(
                matches!(
                    SegmentReader::open(fs.open(&segment_file_name(2)).unwrap()),
                    Err(StorageError::Segment(_))
                ),
                "len={trailing_len}: a direct reader rejects the trailing tail (the pre-fix abort)"
            );

            let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
            // Rolled forward: the recreated seg-2 is active, continuing past the 3 sealed records.
            assert_eq!(
                log.active_segment_id(),
                2,
                "len={trailing_len}: rolls forward to seg 2"
            );
            assert_eq!(log.next_offset(), Offset::new(3), "len={trailing_len}");
            assert_eq!(log.next_seq(), Seq::new(3), "len={trailing_len}");
            // The abandonment is a single ZERO-byte CorruptSegmentHeader event: visible to an
            // operator but adding no skipped/data-loss bytes, so it can never trip the I3 caps.
            let report = log.loss_report();
            assert_eq!(report.events.len(), 1, "len={trailing_len}");
            let e = report.events[0];
            assert_eq!(e.reason_code, crate::loss::ReasonCode::CorruptSegmentHeader);
            assert_eq!(e.segment_id, 2);
            assert_eq!(e.bytes_skipped, 0, "len={trailing_len}");
            assert_eq!(report.total_bytes_skipped(), 0, "len={trailing_len}");
            assert_eq!(report.data_loss_bytes(), 0, "len={trailing_len}");
            // The recovered log is appendable and the sealed predecessors are intact.
            assert_eq!(log.append(&rec(b"d")).unwrap(), Offset::new(3));
            log.sync().unwrap();
            assert_eq!(
                read_back(log.filesystem(), 0).len(),
                2,
                "len={trailing_len}"
            );
            assert_eq!(
                read_back(log.filesystem(), 1).len(),
                1,
                "len={trailing_len}"
            );
        }
    }

    #[test]
    fn recovery_still_hard_fails_a_bad_header_that_is_not_an_empty_trailing_tail() {
        // The #868 roll-forward is deliberately narrow: a bad header still fails closed unless it is a
        // genuinely-EMPTY trailing tail with a valid predecessor. Each case must fail closed, and a
        // populated segment must NOT be deleted.

        // (1) A bad header on a NON-final segment is real mid-chain corruption, not an empty tail:
        // seg-0 zeroed, seg-1 a valid sealed trailing segment. The trailing reap leaves seg-1 alone
        // (it decodes), and the strict chain scan then rejects seg-0.
        let fs = InMemoryFs::new();
        let f0 = fs.create_new(&segment_file_name(0)).unwrap();
        f0.write_all_at(&[0u8; SEGMENT_HEADER_LEN], 0).unwrap();
        f0.sync_data().unwrap();
        let f1 = fs.create_new(&segment_file_name(1)).unwrap();
        let mut w1 = SegmentWriter::create(f1, header_at(1, 0)).unwrap();
        w1.append(&view(0, b"a")).unwrap();
        w1.seal().unwrap();
        assert!(
            Log::open(fs, ManualClock::new(), small_config()).is_err(),
            "a bad header on a non-final segment must hard-fail"
        );

        // (2) A SOLE bad-header segment has no predecessor to roll forward from, so it fails closed
        // whether its id is 0 (a wholly-corrupt log is byte-indistinguishable from an empty one — the
        // corruption-corpus `*_fails_closed` contract) or > 0 (predecessors retention-reaped, so the
        // offset/seq space cannot be reconstructed from an unreadable header).
        for sole_id in [0u64, 5] {
            let fs = InMemoryFs::new();
            let f = fs.create_new(&segment_file_name(sole_id)).unwrap();
            f.write_all_at(&[0u8; SEGMENT_HEADER_LEN], 0).unwrap();
            f.sync_data().unwrap();
            assert!(
                Log::open(fs, ManualClock::new(), small_config()).is_err(),
                "a sole bad-header segment (id {sole_id}) must hard-fail"
            );
        }

        // (3) The cardinal case (data-loss safety): a POPULATED trailing segment whose header rotted
        // holds sole-copy acked records. It must NOT be reaped — recovery fails closed AND the file
        // is preserved for forensics. seg-0 sealed, seg-1 active with a real record, then seg-1's
        // magic is clobbered while the record frame after the header stays intact.
        let fs = InMemoryFs::new();
        let f0 = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w0 = SegmentWriter::create(f0, header_at(0, 0)).unwrap();
        w0.append(&view(0, b"a")).unwrap();
        w0.seal().unwrap();
        let f1 = fs.create_new(&segment_file_name(1)).unwrap();
        let mut w1 = SegmentWriter::create(f1, header_at(1, 1)).unwrap();
        w1.append(&view(1, b"sole-copy-acked-record")).unwrap();
        w1.sync().unwrap();
        drop(w1);
        // Clobber only seg-1's magic at offset 0; the record frame past the 64-byte header is intact,
        // so the body is NOT all-zero and the reap must decline.
        let f1 = fs.open(&segment_file_name(1)).unwrap();
        f1.write_all_at(&[0u8; 8], 0).unwrap();
        f1.sync_data().unwrap();
        let probe = fs.clone();
        assert!(
            Log::open(fs, ManualClock::new(), small_config()).is_err(),
            "a populated trailing segment with a rotted header must hard-fail, never silently reap"
        );
        assert!(
            probe.exists(&segment_file_name(1)).unwrap(),
            "the populated segment must be preserved (not deleted) for forensics"
        );
    }

    #[test]
    fn power_loss_drops_the_unsynced_tail_and_resumes() {
        let mut log = open_mem(LogConfig::default());
        log.append(&rec(b"durable")).unwrap();
        log.sync().unwrap();
        log.append(&rec(b"lost")).unwrap(); // never synced
        log.filesystem().simulate_power_loss();
        let fs = log.into_filesystem();

        let mut log = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
        assert_eq!(log.next_offset(), Offset::new(1));
        assert_eq!(log.next_seq(), Seq::new(1));
        assert_eq!(log.append(&rec(b"after")).unwrap(), Offset::new(1));
        log.sync().unwrap();
        let records = read_back(log.filesystem(), 0);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].payload.as_ref(), b"durable");
        assert_eq!(records[1].payload.as_ref(), b"after");
    }

    #[test]
    fn start_segment_preallocates_the_active_segment_to_the_roll_size() {
        // `start_segment` preallocates each new active segment to the full roll size up front
        // (#330, `docs/PREALLOCATION.md`). The in-memory backend records the reservation request,
        // so we can assert the first segment AND a rolled-to segment were each preallocated to
        // `max_segment_bytes`, without changing the deterministic on-disk image.
        let cfg = LogConfig {
            max_segment_bytes: 256,
            ..LogConfig::default()
        };
        let mut log = open_mem(cfg);
        // The first active segment (created on open) was preallocated to the roll size.
        let seg0 = log.filesystem().open(&segment_file_name(0)).unwrap();
        assert_eq!(
            seg0.preallocated_to(),
            256,
            "segment 0 is preallocated to the roll size on open"
        );
        // Append past the cap so a roll creates segment 1, then assert it too was preallocated.
        for _ in 0..16 {
            log.append(&rec(b"payload-payload")).unwrap();
            log.sync().unwrap();
        }
        assert!(
            log.active_segment_id() >= 1,
            "the workload rolled at least once"
        );
        let seg1 = log.filesystem().open(&segment_file_name(1)).unwrap();
        assert_eq!(
            seg1.preallocated_to(),
            256,
            "a rolled-to active segment is also preallocated to the roll size"
        );
    }

    #[test]
    fn a_preallocated_then_crashed_empty_segment_recovers_as_no_records() {
        // A freshly preallocated active segment is header + zeros. The active segment is created
        // and dir-synced on open, but no record was ever appended. A power loss (the zero tail is
        // not durable in the in-memory model, but even a durable header + zeros must recover empty)
        // then a reopen must recover ZERO records with no spurious record minted from the zero
        // region (the preallocated tail is the torn/zero tail recovery truncates). This is the
        // recovery-correctness-over-a-zero-region tooth.
        let cfg = LogConfig {
            max_segment_bytes: 4096,
            ..LogConfig::default()
        };
        let log = open_mem(cfg);
        // Confirm the segment was preallocated, then crash before any append.
        assert_eq!(
            log.filesystem()
                .open(&segment_file_name(0))
                .unwrap()
                .preallocated_to(),
            4096
        );
        log.filesystem().simulate_power_loss();
        let fs = log.into_filesystem();
        let mut log = Log::open(fs, ManualClock::new(), cfg).unwrap();
        assert_eq!(log.next_offset(), Offset::ZERO, "no record recovered");
        assert_eq!(log.next_seq(), Seq::new(0));
        assert_eq!(
            log.durable_record_count(),
            0,
            "zero region minted no record"
        );
        // The recovered log is fully appendable: the first record lands at offset 0.
        assert_eq!(log.append(&rec(b"first")).unwrap(), Offset::ZERO);
        log.sync().unwrap();
        assert_eq!(read_back(log.filesystem(), 0)[0].payload.as_ref(), b"first");
    }

    #[test]
    fn a_partially_written_preallocated_segment_recovers_its_longest_valid_prefix() {
        // With preallocation ON, a crash after some records but before the segment filled leaves a
        // header + records + a preallocated zero tail. Recovery must recover the longest valid
        // prefix (exactly the synced records) and truncate the zero tail, never inventing a record
        // from the zeros. This is the longest-valid-prefix tooth over a preallocated region.
        let cfg = LogConfig {
            max_segment_bytes: 64 * 1024, // big enough that several records never roll
            ..LogConfig::default()
        };
        let mut log = open_mem(cfg);
        for i in 0..5u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap(); // the five records are acked-durable
        log.append(&rec(b"unsynced-tail")).unwrap(); // never synced
        log.filesystem().simulate_power_loss();
        let fs = log.into_filesystem();

        let mut log = Log::open(fs, ManualClock::new(), cfg).unwrap();
        // Exactly the five synced records survive; the unsynced record and the zero tail are gone.
        assert_eq!(
            log.next_offset(),
            Offset::new(5),
            "longest valid prefix = 5"
        );
        assert_eq!(log.durable_record_count(), 5);
        let records = read_back(log.filesystem(), 0);
        assert_eq!(records.len(), 5, "no spurious record from the zero region");
        for (i, r) in (0u8..5).zip(&records) {
            assert_eq!(r.payload, vec![i; 8]);
        }
        // The recovered writer resumes cleanly at offset 5.
        assert_eq!(log.append(&rec(b"after")).unwrap(), Offset::new(5));
    }

    #[test]
    fn a_preallocated_logical_extension_zero_tail_recovers_silently_with_no_loss_event() {
        // The PRODUCTION preallocation (`StdFile`) advances the active segment's logical length to
        // the roll size, so a crash — or even a clean kill — leaves header + records + a large
        // all-zero tail (here a multi-MiB one, the hazard case: the scan must stop at the first
        // zero word, never walk the span frame-by-frame, and never classify it as loss). Recovery
        // must recover exactly the records and truncate the never-written zero tail SILENTLY: no
        // loss event, no quarantine, no recovered_truncated_bytes — those zeros were never acked
        // data, and reporting a roll-size span on every boot would trip the I3 caps for nothing.
        // The in-memory backend models the reservation only, so the test writes the logical
        // extension out for real with the same set_len-up the production preallocate performs.
        let cfg = LogConfig {
            max_segment_bytes: 8 * 1024 * 1024,
            ..LogConfig::default()
        };
        let mut log = open_mem(cfg);
        for i in 0..3u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap();
        let file = log.filesystem().open(&segment_file_name(0)).unwrap();
        let valid_end = file.len().unwrap();
        file.set_len(cfg.max_segment_bytes).unwrap();
        file.sync_all().unwrap();
        let fs = log.into_filesystem();

        let mut log = Log::open(fs, ManualClock::new(), cfg).unwrap();
        assert_eq!(log.next_offset(), Offset::new(3), "the records survive");
        assert!(
            log.loss_report().events.is_empty(),
            "an all-zero preallocated tail is never-written space, not reported loss"
        );
        assert_eq!(
            log.recovered_truncated_bytes(),
            0,
            "no data byte was discarded"
        );
        assert_eq!(
            log.quarantined_bytes(),
            0,
            "never-written zeros are not forensic material"
        );
        assert_eq!(
            log.filesystem()
                .open(&segment_file_name(0))
                .unwrap()
                .len()
                .unwrap(),
            valid_end,
            "recovery truncated the unwritten extension back to the durable prefix"
        );
        // The resumed writer appends cleanly at the next offset.
        assert_eq!(log.append(&rec(b"after")).unwrap(), Offset::new(3));
    }

    #[test]
    fn a_torn_tail_inside_a_preallocated_extension_is_reported_bounded_to_its_written_span() {
        // Only a PROVABLY all-zero tail is silent. Any non-zero byte after the valid prefix means
        // real written bytes are being discarded (a torn/corrupt frame that reached the disk), so
        // the skip-and-report path runs — BOUNDED at one past the tail's last non-zero byte,
        // never at the extended file length: the loss event, `recovered_truncated_bytes`, and the
        // quarantined forensic blob all cover exactly the 3 written garbage bytes, not the
        // ~64 KiB extension of never-written zeros behind them. (Unbounded, one torn byte would
        // quarantine a near-all-zero roll-size blob — four such boots would evict every genuine
        // forensic blob under the default 256 MiB store cap — and would fail the boot outright on
        // the I3 per-event cap for any `max_segment_bytes` above 64 MiB.)
        let cfg = LogConfig {
            max_segment_bytes: 64 * 1024,
            ..LogConfig::default()
        };
        let mut log = open_mem(cfg);
        log.append(&rec(b"durable")).unwrap();
        log.sync().unwrap();
        let file = log.filesystem().open(&segment_file_name(0)).unwrap();
        let valid_end = file.len().unwrap();
        // Garbage (not a valid frame magic) directly after the prefix, then the zero extension.
        file.write_all_at(&[0xAB, 0xCD, 0xEF], valid_end).unwrap();
        file.set_len(cfg.max_segment_bytes).unwrap();
        file.sync_all().unwrap();
        let fs = log.into_filesystem();

        let log = Log::open(fs, ManualClock::new(), cfg).unwrap();
        assert_eq!(
            log.next_offset(),
            Offset::new(1),
            "the durable record survives"
        );
        let events = &log.loss_report().events;
        assert_eq!(events.len(), 1, "the discarded non-zero tail is reported");
        let e = events[0];
        assert_eq!(e.reason_code, ReasonCode::CorruptRecordHeader);
        assert_eq!(e.byte_offset_start, valid_end);
        assert_eq!(
            e.byte_offset_end,
            valid_end + 3,
            "the span is the 3 written bytes, not the extension"
        );
        assert_eq!(e.bytes_skipped, 3);
        assert_eq!(log.recovered_truncated_bytes(), 3);
        assert_eq!(
            log.quarantined_bytes(),
            3,
            "the forensic blob is the real span: bytes, not the roll size"
        );
        assert_eq!(
            log.filesystem()
                .open(&segment_file_name(0))
                .unwrap()
                .len()
                .unwrap(),
            valid_end,
            "truncated back to the valid prefix"
        );
    }

    #[test]
    fn one_torn_byte_under_a_roll_size_beyond_the_per_event_cap_still_boots() {
        // THE AVAILABILITY REGRESSION (perf/r5 review): with `max_segment_bytes` ABOVE the I3
        // per-event cap (64 MiB), an UNBOUNDED torn-tail span [valid_end, file_len) on an
        // extended active segment would be ~the roll size, exceed the cap, and fail Log::open
        // with ExcessiveRecoveryLoss after a routine crash — one torn byte would take the broker
        // down unrecoverably. Bounded at the last non-zero byte, the same boot succeeds and
        // reports a ONE-BYTE loss event; the next boot is clean and consistent with it.
        let cfg = LogConfig {
            max_segment_bytes: 128 * 1024 * 1024, // 2x the 64 MiB per-event cap
            ..LogConfig::default()
        };
        let mut log = open_mem(cfg);
        log.append(&rec(b"durable")).unwrap();
        log.sync().unwrap();
        let file = log.filesystem().open(&segment_file_name(0)).unwrap();
        let valid_end = file.len().unwrap();
        // One non-zero torn byte at valid_end, then the roll-size logical extension (written out
        // for real, as the production preallocate leaves it).
        file.write_all_at(&[0xAB], valid_end).unwrap();
        file.set_len(cfg.max_segment_bytes).unwrap();
        file.sync_all().unwrap();
        let fs = log.into_filesystem();

        // Boot 1 SUCCEEDS: the reported span is one byte, far under the 64 MiB per-event cap.
        let log = Log::open(fs, ManualClock::new(), cfg).unwrap();
        let events = &log.loss_report().events;
        assert_eq!(events.len(), 1);
        let e = events[0];
        assert_eq!(e.byte_offset_start, valid_end);
        assert_eq!(e.byte_offset_end, valid_end + 1, "one byte, not ~128 MiB");
        assert_eq!(e.bytes_skipped, 1);
        assert_eq!(log.recovered_truncated_bytes(), 1);
        assert_eq!(log.quarantined_bytes(), 1, "a one-byte forensic blob");
        assert_eq!(log.next_offset(), Offset::new(1));

        // Boot 2 is CLEAN and consistent with boot 1's report: the file was truncated to the
        // valid prefix, so nothing is left to report (and the recovered records are unchanged).
        let fs = log.into_filesystem();
        let log = Log::open(fs, ManualClock::new(), cfg).unwrap();
        assert!(
            log.loss_report().events.is_empty(),
            "boot 2 reports nothing new"
        );
        assert_eq!(log.recovered_truncated_bytes(), 0);
        assert_eq!(log.next_offset(), Offset::new(1));
        assert_eq!(read_back(log.filesystem(), 0).len(), 1);
    }

    #[test]
    fn a_cap_exceeding_corrupt_tail_fails_closed_without_destroying_the_evidence() {
        // THE EVIDENCE-DESTRUCTION REGRESSION (perf/r5 review; the ordering predates the branch):
        // recovery used to run its set_len(valid_end) + sync_all BEFORE the I3 cap check, so a
        // cap-failing boot TRUNCATED the over-cap corrupt bytes and the NEXT boot opened clean
        // with an empty loss report — the fail-closed refusal scrubbed the very state the
        // operator is told to inspect. The cap check now runs BEFORE the destructive truncate:
        // every cap-failing boot leaves the file byte-identical, so boot 2 (and an offline
        // inspector) still see the full evidence and fail the same way.
        let config = LogConfig {
            max_segment_bytes: 4096, // the per-event cap: min(4096, 64 MiB) = 4096
            max_total_bytes: 0,
            ..LogConfig::default()
        };
        let mut log = open_mem(config);
        for i in 0..3u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap();
        let active = log.active_segment_id();
        let fs = log.into_filesystem();

        // 5000 bytes of 0xff garbage past the durable tail: GENUINE over-cap corruption (every
        // byte non-zero, so the last-non-zero bound does not shrink it below the 4096 cap).
        let file = fs.open(&segment_file_name(active)).unwrap();
        let len_before = file.len().unwrap();
        file.write_all_at(&[0xffu8; 5000], len_before).unwrap();
        file.sync_data().unwrap();
        let expected_len = len_before + 5000;

        // Boot 1 fails closed...
        let err = Log::open(fs.clone(), ManualClock::new(), config).unwrap_err();
        assert!(
            matches!(
                err,
                StorageError::ExcessiveRecoveryLoss(crate::loss::CapViolation::PerEvent {
                    cap: 4096,
                    ..
                })
            ),
            "expected a per-event cap violation, got {err:?}"
        );
        // ...WITHOUT truncating: the evidence is byte-for-byte on disk.
        assert_eq!(
            fs.open(&segment_file_name(active)).unwrap().len().unwrap(),
            expected_len,
            "a cap-failing boot must not destroy its own evidence"
        );

        // Boot 2 sees the SAME evidence and fails the SAME way (no silent clean open).
        let err2 = Log::open(fs.clone(), ManualClock::new(), config).unwrap_err();
        assert!(
            matches!(
                err2,
                StorageError::ExcessiveRecoveryLoss(crate::loss::CapViolation::PerEvent { .. })
            ),
            "boot 2 must fail closed on the surviving evidence, got {err2:?}"
        );
        assert_eq!(
            fs.open(&segment_file_name(active)).unwrap().len().unwrap(),
            expected_len,
            "the evidence survives every refused boot"
        );
    }

    #[test]
    fn a_roll_seals_an_extended_active_segment_down_to_its_footer_end() {
        // Footer discovery reads the END of the file. If the active segment carries a preallocated
        // logical extension when it rolls, `seal` must truncate the zero tail so the sealed image
        // ends exactly at the footer — otherwise the seal would be invisible (zeros where the
        // footer is expected) and a reopen would refuse the chain with UnsealedPredecessor.
        let cfg = LogConfig {
            max_segment_bytes: 256,
            ..LogConfig::default()
        };
        let mut log = open_mem(cfg);
        log.append(&rec(b"first")).unwrap();
        log.sync().unwrap();
        // Extend segment 0 as the production preallocate would have at create time.
        log.filesystem()
            .open(&segment_file_name(0))
            .unwrap()
            .set_len(cfg.max_segment_bytes * 4)
            .unwrap();
        // Append past the cap so the extended segment 0 is sealed by a roll.
        for _ in 0..16 {
            log.append(&rec(b"payload-payload")).unwrap();
            log.sync().unwrap();
        }
        assert!(log.active_segment_id() >= 1, "the workload rolled");
        let total = log.durable_record_count();
        let seg0 = log.filesystem().open(&segment_file_name(0)).unwrap();
        let len = seg0.len().unwrap();
        assert!(
            len < cfg.max_segment_bytes * 4,
            "the extension was truncated at seal"
        );
        let scan = SegmentReader::open(seg0).unwrap().scan().unwrap();
        assert!(
            scan.footer.is_some(),
            "the footer is discoverable at the file end"
        );
        assert_eq!(
            scan.valid_end + SEGMENT_FOOTER_LEN as u64,
            len,
            "the sealed image ends exactly at the footer"
        );
        // A reopen recovers the sealed predecessor + the rest of the chain with no loss.
        let fs = log.into_filesystem();
        let log = Log::open(fs, ManualClock::new(), cfg).unwrap();
        assert_eq!(log.durable_record_count(), total);
        assert!(log.loss_report().events.is_empty());
    }

    /// A file whose `preallocate` always errors (an unsupported FS or an out-of-space reservation),
    /// counting each failure so a test can prove the failing path was genuinely taken; every other
    /// op delegates to the inner file. Used to exercise `start_segment`'s best-effort swallow.
    struct FailPreallocFile<G> {
        inner: G,
        fails: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl<G: RandomAccessFile> RandomAccessFile for FailPreallocFile<G> {
        fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
            self.inner.read_at(buf, offset)
        }
        fn write_all_at(&self, buf: &[u8], offset: u64) -> std::io::Result<()> {
            self.inner.write_all_at(buf, offset)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            self.inner.sync_data()
        }
        fn sync_all(&self) -> std::io::Result<()> {
            self.inner.sync_all()
        }
        fn len(&self) -> std::io::Result<u64> {
            self.inner.len()
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.inner.set_len(len)
        }
        fn preallocate(&self, _len: u64) -> std::io::Result<()> {
            self.fails.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(std::io::Error::other("preallocate unsupported on this fs"))
        }
    }

    /// A filesystem that hands out [`FailPreallocFile`]s, so every segment's preallocate fails.
    struct FailPreallocFs {
        inner: InMemoryFs,
        fails: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl Filesystem for FailPreallocFs {
        type File = FailPreallocFile<<InMemoryFs as Filesystem>::File>;
        fn open(&self, name: &str) -> std::io::Result<Self::File> {
            Ok(FailPreallocFile {
                inner: self.inner.open(name)?,
                fails: std::sync::Arc::clone(&self.fails),
            })
        }
        fn create_new(&self, name: &str) -> std::io::Result<Self::File> {
            Ok(FailPreallocFile {
                inner: self.inner.create_new(name)?,
                fails: std::sync::Arc::clone(&self.fails),
            })
        }
        fn remove(&self, name: &str) -> std::io::Result<()> {
            self.inner.remove(name)
        }
        fn list(&self) -> std::io::Result<Vec<String>> {
            self.inner.list()
        }
        fn exists(&self, name: &str) -> std::io::Result<bool> {
            self.inner.exists(name)
        }
        fn sync_dir(&self) -> std::io::Result<()> {
            self.inner.sync_dir()
        }
        fn subdir(&self, name: &str) -> std::io::Result<Self> {
            Ok(FailPreallocFs {
                inner: self.inner.subdir(name)?,
                fails: std::sync::Arc::clone(&self.fails),
            })
        }
        fn subdir_exists(&self, name: &str) -> std::io::Result<bool> {
            self.inner.subdir_exists(name)
        }
        fn list_subdirs(&self) -> std::io::Result<Vec<String>> {
            self.inner.list_subdirs()
        }
    }

    #[test]
    fn a_preallocate_failure_is_non_fatal_and_the_broker_still_starts_and_appends() {
        // Preallocation is a best-effort optimization: a filesystem whose `preallocate` ALWAYS
        // errors must NOT prevent the broker from opening or appending. `start_segment` swallows the
        // error and falls back to grow-on-append. `FailPreallocFs` fails (and counts) every
        // segment's preallocate, so the test proves the failing path was genuinely taken (no false
        // pass) AND the broker still opens, rolls, and appends.
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let fails = Arc::new(AtomicU64::new(0));
        let fs = FailPreallocFs {
            inner: InMemoryFs::new(),
            fails: Arc::clone(&fails),
        };
        // A small cap so the workload rolls (each roll re-attempts the failing preallocate).
        let cfg = LogConfig {
            max_segment_bytes: 256,
            ..LogConfig::default()
        };
        // The broker OPENS despite the first segment's preallocate failing (best-effort, swallowed).
        let mut log = Log::open(fs, ManualClock::new(), cfg)
            .expect("the broker opens even though every preallocate fails");
        assert!(
            fails.load(Ordering::SeqCst) >= 1,
            "the failing preallocate was taken on open"
        );
        // It appends, rolls, and the records are durable: grow-on-append fallback works end to end.
        for _ in 0..16 {
            log.append(&rec(b"payload-payload")).unwrap();
            log.sync().unwrap();
        }
        assert!(
            log.active_segment_id() >= 1,
            "the workload rolled despite failing preallocate"
        );
        assert!(
            fails.load(Ordering::SeqCst) >= 2,
            "a rolled-to segment re-attempted (and swallowed) the failing preallocate"
        );
        assert_eq!(
            read_back(log.filesystem(), 0)[0].payload.as_ref(),
            b"payload-payload"
        );
    }

    #[test]
    fn an_oversized_record_is_written_rather_than_rolling_forever() {
        // A record larger than the cap is written to its own (empty) segment instead of
        // triggering an endless roll.
        let mut log = open_mem(LogConfig {
            max_segment_bytes: 80,
            max_total_bytes: 0,
            ..LogConfig::default()
        });
        let big = vec![0xab; 4096];
        assert_eq!(log.append(&rec(&big)).unwrap(), Offset::new(0));
        log.sync().unwrap();
        // The next append rolls (the segment is now well past the cap).
        assert_eq!(log.append(&rec(b"small")).unwrap(), Offset::new(1));
        assert_eq!(log.active_segment_id(), 1);
    }

    // The durable RECORD bytes one `rec(payload)` append adds to the log: the framed record
    // size, measured against the running total so the cap tests never hardcode the codec's
    // frame overhead.
    fn record_bytes(payload: &[u8]) -> u64 {
        let mut log = open_mem(LogConfig::default());
        let before = log.durable_record_bytes();
        log.append(&rec(payload)).unwrap();
        log.durable_record_bytes() - before
    }

    #[test]
    fn unlimited_total_cap_preserves_unlimited_behavior() {
        // max_total_bytes == 0 is the default: the cap is OFF and many records append freely,
        // exactly as before this feature. This pins the no-regression requirement.
        let mut log = open_mem(LogConfig::default());
        assert_eq!(log.config.max_total_bytes, 0, "default is unlimited");
        for i in 0..200u32 {
            let payload = i.to_le_bytes();
            assert_eq!(
                log.append(&rec(&payload)).unwrap(),
                Offset::new(u64::from(i))
            );
        }
        log.sync().unwrap();
        assert_eq!(log.flushed_offset(), Offset::new(200));
    }

    #[test]
    fn durable_record_bytes_counts_records_across_a_roll() {
        // The running total equals exactly the sum of the framed record bytes, both within one
        // segment and across a roll (sealed predecessors plus the active segment), never the
        // segment headers or footers. This is the quantity the cap is measured against.
        let one = record_bytes(b"payload-xyz");
        let mut log = open_mem(small_config());
        let mut appended = 0u64;
        for i in 0..12u8 {
            log.append(&rec(&[i; 11])).unwrap();
            appended += 1;
            assert_eq!(
                log.durable_record_bytes(),
                appended * one,
                "total tracks each appended record (i={i})"
            );
        }
        assert!(log.active_segment_id() >= 1, "should have rolled");
        // After a reopen the running total is reconstructed to the same value (recovery sums
        // durable_bytes), so the cap is enforced consistently across a restart.
        log.sync().unwrap();
        let fs = log.into_filesystem();
        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(reopened.durable_record_bytes(), 12 * one);
    }

    #[test]
    fn write_amp_counters_track_logical_physical_and_imply_the_ratio() {
        // The write-amplification counters (#118): a known produce yields a known logical (the user
        // payload) and a known physical (the framed record plus the segment header). The frame is
        // larger than the payload (header + trailer + length fields), so physical > logical, i.e. the
        // amplification ratio is greater than 1. A test that pins the EXACT relationship fails if the
        // accounting regresses.
        let payload = b"payload-xyz"; // 11 bytes
        let frame = record_bytes(payload); // the exact framed length (header + body + trailer)
        let mut log = open_mem(LogConfig::default());
        // A fresh log has already charged its FIRST segment header to physical, nothing to logical.
        assert_eq!(
            log.logical_bytes_written(),
            0,
            "no logical bytes before any append"
        );
        assert_eq!(
            log.physical_bytes_written(),
            SEGMENT_HEADER_LEN as u64,
            "the first segment header is the only physical write before any append"
        );
        // Append three known records (no roll: the default segment cap is far larger).
        for _ in 0..3 {
            log.append(&rec(payload)).unwrap();
        }
        assert_eq!(
            log.logical_bytes_written(),
            3 * payload.len() as u64,
            "logical is exactly the sum of the user payloads"
        );
        assert_eq!(
            log.physical_bytes_written(),
            SEGMENT_HEADER_LEN as u64 + 3 * frame,
            "physical is the segment header plus the three framed records"
        );
        // The physical-minus-the-header equals the durable record bytes (the framed records), the
        // independent quantity the byte cap is measured against: a cross-check on the accounting.
        assert_eq!(
            log.physical_bytes_written() - SEGMENT_HEADER_LEN as u64,
            log.durable_record_bytes(),
            "physical minus the header equals the framed record bytes"
        );
        // Each frame is strictly larger than its payload, so the amplification ratio exceeds 1.
        assert!(
            log.physical_bytes_written() > log.logical_bytes_written(),
            "physical {} should exceed logical {} (amplification > 1)",
            log.physical_bytes_written(),
            log.logical_bytes_written()
        );
    }

    #[test]
    fn resident_estimate_adds_segment_framing_to_the_record_region_and_tracks_reaps() {
        // The honest resident estimate (#493): record region + every live segment's 64-byte header
        // + every SEALED segment's 32-byte footer (the active segment has no footer yet). Unlike
        // the byte cap (record region only) it counts the framing an operator's disk budget pays
        // for, and unlike `physical_bytes_written` (monotonic write-amp) it FALLS as retention
        // reaps segments — which is exactly why the cap basis stays the reap-tracked record region.

        // One segment, three records, no roll: estimate = record region + ONE header, no footer
        // (the lone segment is the active one).
        let payload = b"payload-xyz";
        let frame = record_bytes(payload);
        let mut log = open_mem(LogConfig::default());
        for _ in 0..3 {
            log.append(&rec(payload)).unwrap();
        }
        assert_eq!(
            log.segment_count(),
            1,
            "no roll under the default segment cap"
        );
        assert_eq!(
            log.resident_bytes_estimate(),
            log.durable_record_bytes() + SEGMENT_HEADER_LEN as u64,
            "single active segment: record region + one header, no footer"
        );
        assert_eq!(
            log.resident_bytes_estimate(),
            3 * frame + SEGMENT_HEADER_LEN as u64,
            "exact framed value"
        );
        // The estimate is strictly above the cap basis: that gap is the honesty fix.
        assert!(log.resident_bytes_estimate() > log.durable_record_bytes());

        // Roll several segments, then confirm the per-segment overhead is exactly
        // segments*header + (segments-1)*footer on top of the live record region.
        let mut log = open_mem(small_config());
        for i in 0..12u8 {
            log.append(&rec(&[i; 11])).unwrap();
        }
        let segs = log.segment_count() as u64;
        assert!(segs >= 2, "should have rolled to multiple segments");
        let expected = log.durable_record_bytes()
            + segs * SEGMENT_HEADER_LEN as u64
            + (segs - 1) * SEGMENT_FOOTER_LEN as u64;
        assert_eq!(
            log.resident_bytes_estimate(),
            expected,
            "estimate = record region + per-segment header/footer framing"
        );

        // After a size reap deletes old sealed segments, the estimate DROPS (record region AND
        // segment-framing terms both fall), proving it is live/reap-tracking, not monotonic.
        let before = log.resident_bytes_estimate();
        let before_segs = log.segment_count();
        // Protect nothing (all consumers past the head): the reaper is free to drop sealed segments
        // down to the byte bound. A tiny bound forces several reaps.
        let outcome = log.reap_to_size(frame, u64::MAX).unwrap();
        assert!(outcome.segments_reaped > 0, "the reap dropped segments");
        assert!(
            log.segment_count() < before_segs,
            "segment count fell after the reap"
        );
        assert!(
            log.resident_bytes_estimate() < before,
            "the resident estimate FELL after the reap (it is live, not a monotonic write-amp meter)"
        );
        // The estimate stays exactly the record region plus the surviving segments' framing.
        let segs_after = log.segment_count() as u64;
        assert_eq!(
            log.resident_bytes_estimate(),
            log.durable_record_bytes()
                + segs_after * SEGMENT_HEADER_LEN as u64
                + segs_after.saturating_sub(1) * SEGMENT_FOOTER_LEN as u64,
        );
    }

    #[test]
    fn the_daily_write_budget_sheds_when_today_exceeds_it() {
        // The opt-in daily physical write budget (#118): once today's physical writes reach the
        // budget, the next produce is shed with the distinct, FINAL DailyWriteBudgetExceeded (a clean
        // pre-write drop-new reject, NOT the byte-cap AtCapacity) and the shed counter ticks;
        // durability is never weakened (nothing is written). The first write of the day always goes
        // through (the at-or-over check requires a non-zero meter), so the broker always makes daily
        // progress. A budget just above one record's physical cost lets one record through, then sheds.
        let frame = record_bytes(b"abc");
        // Budget = the first segment header + one frame: after the first record the meter equals the
        // budget exactly, so the at-or-over check sheds the SECOND record. The first record is still
        // admitted (when it is checked the meter is only the header, below the budget).
        let budget = SEGMENT_HEADER_LEN as u64 + frame;
        let config = LogConfig {
            daily_physical_write_budget_bytes: budget,
            ..LogConfig::default()
        };
        let mut log = open_mem(config);
        // The first produce is admitted (the meter was below the budget when checked).
        log.append(&rec(b"abc")).unwrap();
        assert_eq!(log.daily_budget_sheds(), 0, "the first record is admitted");
        assert!(
            log.physical_bytes_written_today() >= budget,
            "after the first record today's physical writes reach the budget"
        );
        // The second produce is shed: at-or-over the budget, non-fatal, nothing written.
        let before_bytes = log.physical_bytes_written();
        let err = log.append(&rec(b"def")).unwrap_err();
        assert!(
            err.is_daily_write_budget_exceeded(),
            "an over-budget produce sheds with the distinct, final DailyWriteBudgetExceeded, got {err:?}"
        );
        assert!(
            !err.is_at_capacity(),
            "the budget shed is NOT the byte-cap AtCapacity (a reap can never relieve it), got {err:?}"
        );
        assert_eq!(
            log.daily_budget_sheds(),
            1,
            "the over-budget shed is counted"
        );
        assert_eq!(
            log.physical_bytes_written(),
            before_bytes,
            "the shed produce wrote nothing (durability is never weakened)"
        );
        // The writer is NOT frozen: a budget shed is non-fatal, so the log stays usable.
        assert!(
            log.flushed_offset().get() <= 1,
            "only the first record is durable after sync"
        );
    }

    #[test]
    fn the_daily_write_budget_resets_at_the_utc_day_boundary() {
        // The daily meter resets at the UTC day boundary on the clock seam (#118), so the budget
        // refreshes each day with no background timer. Drive the clock past midnight and the next
        // produce is admitted again even though yesterday hit the budget.
        let frame = record_bytes(b"abc");
        let budget = SEGMENT_HEADER_LEN as u64 + frame;
        let config = LogConfig {
            daily_physical_write_budget_bytes: budget,
            ..LogConfig::default()
        };
        // A shared ManualClock so the test can advance wall time across a UTC day boundary.
        let clock = std::sync::Arc::new(ManualClock::at_unix_millis(0));
        let mut log = Log::open(InMemoryFs::new(), std::sync::Arc::clone(&clock), config).unwrap();
        // Day 0: first record admitted, second shed.
        log.append(&rec(b"abc")).unwrap();
        assert!(
            log.append(&rec(b"def")).is_err(),
            "day 0 is over budget after one record"
        );
        assert_eq!(log.daily_budget_sheds(), 1);
        // Advance the wall clock to the next UTC day (86_400_000 ms): the meter rolls over, so the
        // first produce of the new day is admitted again.
        clock.set_unix_millis(24 * 60 * 60 * 1000);
        log.append(&rec(b"ghi")).unwrap();
        assert_eq!(
            log.physical_bytes_written_today(),
            frame,
            "the new day's meter starts fresh at one frame (the header was charged on day 0)"
        );
        assert_eq!(
            log.daily_budget_sheds(),
            1,
            "no new shed on the fresh day's first record"
        );
    }

    #[test]
    fn at_capacity_rejects_the_produce_writes_nothing_and_is_not_fatal() {
        // A cap that holds exactly two records: the third produce is at-or-over the cap and is
        // rejected with the non-fatal AtCapacity, nothing is written, and no offset/seq moves.
        let one = record_bytes(b"abc");
        let cap = 2 * one;
        let mut log = open_mem(LogConfig::default().with_max_total_bytes(cap));
        assert_eq!(log.append(&rec(b"abc")).unwrap(), Offset::new(0));
        assert_eq!(log.append(&rec(b"abc")).unwrap(), Offset::new(1));
        log.sync().unwrap();
        // The log is now AT the cap (2 records == cap), so the next produce is rejected.
        assert_eq!(log.durable_record_bytes(), cap);
        let next_offset = log.next_offset();
        let next_seq = log.next_seq();
        let err = log.append(&rec(b"abc")).unwrap_err();
        assert!(
            matches!(err, StorageError::AtCapacity { durable_bytes, cap: c } if durable_bytes == cap && c == cap),
            "got {err:?}"
        );
        // The rejection is NOT a fatal freeze: the writer stays live and reads keep serving.
        assert!(err.is_at_capacity(), "AtCapacity reports itself");
        assert!(log.is_writable(), "the shed does not freeze the writer");
        // Nothing advanced: no offset, no sequence, the durable head unchanged.
        assert_eq!(log.next_offset(), next_offset);
        assert_eq!(log.next_seq(), next_seq);
        assert_eq!(log.flushed_offset(), Offset::new(2));

        // Reopen and confirm the rejected record is absent (only the two durable records), so
        // nothing leaked to disk under a reserved id.
        log.sync().unwrap();
        let fs = log.into_filesystem();
        let reopened = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
        assert_eq!(
            reopened.flushed_offset(),
            Offset::new(2),
            "rejected record absent"
        );
        assert_eq!(reopened.next_offset(), Offset::new(2));
        let records = reopened.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn appends_under_the_cap_succeed_then_the_writer_stays_live_for_more() {
        // Under the cap every produce succeeds; once over, the writer is not frozen, so a later
        // produce (modeling space freed by retention, simulated here by raising the cap on a
        // fresh handle) succeeds again.
        let one = record_bytes(b"z");
        let cap = 3 * one;
        let mut log = open_mem(LogConfig::default().with_max_total_bytes(cap));
        for i in 0..3u8 {
            assert!(
                log.append(&rec(&[i])).is_ok(),
                "under-cap append {i} succeeds"
            );
        }
        log.sync().unwrap();
        // At the cap: rejected, writer still live.
        assert!(matches!(
            log.append(&rec(b"x")),
            Err(StorageError::AtCapacity { .. })
        ));
        assert!(log.is_writable());
        // The writer never froze: sync still works and a subsequent at-cap produce is still a
        // shed (not a WriterFrozen), proving the shed is repeatable and non-terminal.
        log.sync().unwrap();
        assert!(matches!(
            log.append(&rec(b"y")),
            Err(StorageError::AtCapacity { .. })
        ));
    }

    #[test]
    fn an_oversized_first_record_on_an_empty_log_is_always_written() {
        // The cap is far smaller than a single record, yet the FIRST record on an empty log is
        // still written (the empty-log exception), so an oversized first record is not wedged
        // out. The second produce, now over the cap, is rejected.
        let mut log = open_mem(LogConfig::default().with_max_total_bytes(8));
        let big = vec![0xcd; 4096];
        assert_eq!(
            log.append(&rec(&big)).unwrap(),
            Offset::new(0),
            "the first record is written despite exceeding the tiny cap"
        );
        log.sync().unwrap();
        assert!(
            log.durable_record_bytes() > 8,
            "the log is now over the cap"
        );
        // The log is no longer empty, so the next produce is rejected.
        assert!(matches!(
            log.append(&rec(b"more")),
            Err(StorageError::AtCapacity { .. })
        ));
    }

    #[test]
    fn rejects_a_segment_with_a_sequence_gap() {
        let fs = InMemoryFs::new();
        let file = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w = SegmentWriter::create(file, header_at(0, 0)).unwrap();
        w.append(&view(0, b"a")).unwrap();
        w.append(&view(5, b"b")).unwrap();
        w.sync().unwrap();
        drop(w);
        let err = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap_err();
        assert!(matches!(
            err,
            StorageError::RecoveredSequenceMismatch {
                index: 1,
                expected: 1,
                found: 5
            }
        ));
    }

    #[test]
    fn rejects_a_corrupt_predecessor_segment() {
        // A predecessor that no longer decodes its header must fail recovery, not be
        // discovered as garbage only when a reader later reaches it.
        let mut log = open_mem(small_config());
        for i in 0..7u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 1);
        let f = log.filesystem().open(&segment_file_name(0)).unwrap();
        let mut bytes = f.snapshot();
        bytes[0] ^= 0xff; // corrupt segment 0's header magic
        f.set_len(0).unwrap();
        f.write_all_at(&bytes, 0).unwrap();
        f.sync_data().unwrap();
        let fs = log.into_filesystem();

        let err = Log::open(fs, ManualClock::new(), small_config()).unwrap_err();
        assert!(matches!(err, StorageError::Segment(_)));
    }

    #[test]
    fn parallel_recovery_scan_is_deterministic_and_byte_identical_across_many_segments() {
        // #817/#821: recovery fans the per-segment scan+CRC across a bounded worker set, then folds
        // the chain deterministically in id order. Build a log with FAR more sealed segments than
        // the worker cap, so the parallel map actually fans out and its work-stealing completion
        // order is exercised, then assert every reopen recovers the identical chain (offsets,
        // sequence, record count, active id) AND leaves a byte-for-byte identical on-disk image.
        let cfg = LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        };
        // The whole durable directory image, as a sorted (name, bytes) list, so two recoveries can
        // be compared byte-for-byte.
        let dir_image = |fs: &InMemoryFs| -> Vec<(String, Vec<u8>)> {
            let mut names = fs.list().unwrap();
            names.sort();
            names
                .into_iter()
                .map(|n| {
                    let bytes = fs.open(&n).unwrap().snapshot();
                    (n, bytes)
                })
                .collect()
        };

        let fs = InMemoryFs::new();
        let mut log = Log::open(fs.clone(), ManualClock::new(), cfg).unwrap();
        // Roll well past the worker cap (RECOVERY_SCAN_MAX_WORKERS = 8): keep appending until the
        // active segment id is at least 30, i.e. ~30 sealed predecessors plus the active one.
        let mut appended = 0u64;
        while log.active_segment_id() < 30 {
            log.append(&rec(&[0xab; 40])).unwrap();
            appended += 1;
        }
        log.sync().unwrap();
        let expected_next_offset = log.next_offset();
        let expected_next_seq = log.next_seq();
        let expected_count = log.durable_record_count();
        let expected_active = log.active_segment_id();
        assert_eq!(expected_next_offset, Offset::new(appended));
        assert!(expected_active >= 30, "the log rolled into many segments");
        drop(log);

        let image0 = dir_image(&fs);
        // Every reopen re-runs the parallel scan; the recovered chain and the resulting on-disk
        // image must be identical across repeated recoveries, proving the reassembly is order-
        // independent and deterministic.
        for _ in 0..5 {
            let log = Log::open(fs.clone(), ManualClock::new(), cfg).unwrap();
            assert_eq!(log.next_offset(), expected_next_offset);
            assert_eq!(log.next_seq(), expected_next_seq);
            assert_eq!(log.durable_record_count(), expected_count);
            assert_eq!(log.active_segment_id(), expected_active);
            assert_eq!(log.segment_count() as u64, expected_active + 1);
            drop(log);
            assert_eq!(
                dir_image(&fs),
                image0,
                "a reopen must leave the on-disk image byte-for-byte identical"
            );
        }
    }

    #[test]
    fn rejects_a_segment_chain_with_a_base_gap() {
        // seg0: two records, sealed, base 0.
        let fs = InMemoryFs::new();
        let f0 = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w0 = SegmentWriter::create(f0, header_at(0, 0)).unwrap();
        w0.append(&view(0, b"a")).unwrap();
        w0.append(&view(1, b"b")).unwrap();
        w0.seal().unwrap();
        // seg1: base 999 instead of the expected 2.
        let f1 = fs.create_new(&segment_file_name(1)).unwrap();
        let mut w1 = SegmentWriter::create(f1, header_at(1, 999)).unwrap();
        w1.append(&view(999, b"c")).unwrap();
        w1.sync().unwrap();
        drop(w1);

        let err = Log::open(fs, ManualClock::new(), small_config()).unwrap_err();
        assert!(matches!(
            err,
            StorageError::SegmentChainBroken {
                segment_id: 1,
                expected_base_offset: 2,
                found_base_offset: 999,
                ..
            }
        ));
    }

    #[test]
    fn rejects_an_unsealed_predecessor() {
        // Two segments where the lower one was never sealed: two appendable segments.
        let fs = InMemoryFs::new();
        let f0 = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w0 = SegmentWriter::create(f0, header_at(0, 0)).unwrap();
        w0.append(&view(0, b"a")).unwrap();
        w0.sync().unwrap(); // synced but NOT sealed
        drop(w0);
        let f1 = fs.create_new(&segment_file_name(1)).unwrap();
        let mut w1 = SegmentWriter::create(f1, header_at(1, 1)).unwrap();
        w1.append(&view(1, b"b")).unwrap();
        w1.sync().unwrap();
        drop(w1);

        let err = Log::open(fs, ManualClock::new(), small_config()).unwrap_err();
        assert!(matches!(
            err,
            StorageError::UnsealedPredecessor { segment_id: 0 }
        ));
    }

    #[test]
    fn recovery_resumes_an_empty_active_segment_after_a_completed_roll() {
        // Crash point (e): seg0 sealed, seg1 created (empty, base 2) and durable.
        let fs = InMemoryFs::new();
        let f0 = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w0 = SegmentWriter::create(f0, header_at(0, 0)).unwrap();
        w0.append(&view(0, b"a")).unwrap();
        w0.append(&view(1, b"b")).unwrap();
        w0.seal().unwrap();
        let f1 = fs.create_new(&segment_file_name(1)).unwrap();
        let mut w1 = SegmentWriter::create(f1, header_at(1, 2)).unwrap();
        w1.sync().unwrap();
        drop(w1);

        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(log.active_segment_id(), 1);
        assert_eq!(log.next_offset(), Offset::new(2));
        assert_eq!(log.next_seq(), Seq::new(2));
        assert_eq!(log.append(&rec(b"c")).unwrap(), Offset::new(2));
    }

    #[test]
    fn power_loss_after_a_roll_recovers_the_synced_prefix() {
        let mut log = open_mem(small_config());
        for i in 0..7u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 1, "should have rolled");
        log.append(&rec(b"lost")).unwrap(); // never synced
        log.filesystem().simulate_power_loss();
        let fs = log.into_filesystem();

        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(log.next_offset(), Offset::new(7));
        let total: usize = segment_ids(log.filesystem())
            .unwrap()
            .iter()
            .map(|id| read_back(log.filesystem(), *id).len())
            .sum();
        assert_eq!(total, 7);
        assert_eq!(log.append(&rec(b"after")).unwrap(), Offset::new(7));
    }

    #[test]
    fn a_transient_create_fault_at_a_roll_defers_and_resumes_the_writer() {
        use crate::fault::FaultFs;
        // #867: a momentary EMFILE / short ENOSPC failing `create_new` at a roll boundary must NOT
        // permanently freeze the writer. The roll's predecessor is already durably sealed, so the
        // create is DEFERRED (a non-fatal error) and retried on the next write, which succeeds once
        // the fault clears — instead of the old behaviour that killed write availability until restart.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();

        // Fill the first segment (syncing each record) until the next append would roll it.
        let mut durable = 0u64;
        while !log.active_segment_at_or_over_cap().unwrap() {
            assert_eq!(log.append(&rec(&[7u8; 20])).unwrap(), Offset::new(durable));
            log.sync().unwrap();
            durable += 1;
        }

        // Arm a one-shot transient create fault; the next append triggers a roll whose `create_new`
        // fails. The roll seals the predecessor (durable) and then DEFERS the create.
        control.fail_create_new(1);
        let err = log.append(&rec(&[8u8; 20])).unwrap_err();
        assert!(
            !matches!(err, StorageError::WriterFrozen),
            "a transient create fault must NOT freeze the writer: {err:?}"
        );
        assert!(matches!(err, StorageError::Io(_)), "got {err:?}");
        // The predecessor was durably sealed by the roll, so its records survive; the failed produce
        // consumed no offset (the reservation happens after the roll).
        assert_eq!(log.flushed_offset(), Offset::new(durable));

        // The fault has cleared: the NEXT append completes the deferred roll and succeeds, proving the
        // writer resumed rather than freezing until restart. The resumed produce takes the offset the
        // deferred one did not consume.
        assert_eq!(log.append(&rec(&[9u8; 20])).unwrap(), Offset::new(durable));
        log.sync().unwrap();
        assert_eq!(
            log.active_segment_id(),
            1,
            "the deferred roll completed to segment 1"
        );

        // Everything is durable across a reopen: the predecessor's records plus the resumed one.
        let fs = log.into_filesystem();
        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(reopened.next_offset(), Offset::new(durable + 1));
    }

    #[test]
    fn a_durability_barrier_fault_at_a_roll_freezes_the_writer() {
        use crate::fault::FaultFs;
        // #867: a TRANSIENT create fault defers, but a genuine DURABILITY-BARRIER fault — the new
        // segment's directory-publish fsync — is a real durability failure and must still FREEZE the
        // writer fail-stop, so a dead disk surfaces to health instead of being retried forever.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        while !log.active_segment_at_or_over_cap().unwrap() {
            log.append(&rec(&[7u8; 20])).unwrap();
            log.sync().unwrap();
        }
        // Fail the new segment's directory-publish fsync during the roll (the seal of the predecessor
        // fsyncs the FILE, not the directory, so it still succeeds — only the create's barrier fails).
        control.set_fail_sync_dir(true);
        let err = log.append(&rec(&[8u8; 20])).unwrap_err();
        assert!(
            matches!(err, StorageError::WriterFrozen),
            "a durability-barrier fault at a roll must freeze: {err:?}"
        );
        // The freeze is permanent even after the fault clears: further writes refuse, getters stay
        // sane (no panic).
        control.set_fail_sync_dir(false);
        assert!(matches!(
            log.append(&rec(b"x")),
            Err(StorageError::WriterFrozen)
        ));
        assert!(matches!(log.sync(), Err(StorageError::WriterFrozen)));
        let _ = log.next_offset();
        let _ = log.next_seq();
        let _ = log.active_segment_id();
    }

    #[test]
    fn a_roll_republishes_the_just_sealed_segment_to_the_off_actor_read_plane() {
        // #867 review finding 1: the roll must republish the #539 read plane AFTER installing the new
        // active segment, so the just-sealed predecessor is served lock-free off-actor rather than
        // forced through the actor. Build the plane FIRST (so the roll republishes it), roll, then
        // read a predecessor offset and assert it completes off-plane (no fallback).
        let mut log = open_mem(small_config());
        let _ = log.read_plane().unwrap(); // cache the plane so the next roll REPUBLISHES it
        let mut durable = 0u64;
        while log.active_segment_id() == 0 {
            log.append(&rec(&[7u8; 20])).unwrap();
            log.sync().unwrap();
            durable += 1;
        }
        assert!(log.active_segment_id() >= 1, "a roll happened");
        let plane = log.read_plane().unwrap();
        let read = plane.read_one(Offset::ZERO).unwrap();
        assert_eq!(
            read.records.len(),
            1,
            "the just-sealed predecessor's record is served"
        );
        assert!(
            read.fallback_from.is_none(),
            "the just-sealed segment is served off-actor, not via the through-actor fallback"
        );
        let _ = durable;
    }

    #[test]
    fn a_persistent_transient_create_fault_keeps_deferring_then_resumes() {
        use crate::fault::FaultFs;
        // #867 review finding 5: a transient create fault that persists across several writes must
        // keep DEFERRING (each write non-fatal, the writer never frozen and reported writable) and
        // then resume cleanly once the fault clears — no data lost, no offset skipped.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        let mut durable = 0u64;
        while !log.active_segment_at_or_over_cap().unwrap() {
            assert_eq!(log.append(&rec(&[7u8; 20])).unwrap(), Offset::new(durable));
            log.sync().unwrap();
            durable += 1;
        }
        // The next 3 create_new calls fail: the roll defers, and the next two writes RE-defer.
        control.fail_create_new(3);
        for attempt in 0..3 {
            let err = log.append(&rec(&[8u8; 20])).unwrap_err();
            assert!(
                !matches!(err, StorageError::WriterFrozen),
                "attempt {attempt} must not freeze: {err:?}"
            );
            assert!(
                log.is_writable(),
                "attempt {attempt}: a deferred roll is resumable, reported writable (#867 finding 2)"
            );
            assert_eq!(
                log.flushed_offset(),
                Offset::new(durable),
                "attempt {attempt}: no durable data lost while deferring"
            );
        }
        // The fault has cleared: the next write completes the roll at the un-consumed offset.
        assert_eq!(log.append(&rec(&[9u8; 20])).unwrap(), Offset::new(durable));
        log.sync().unwrap();
        let fs = log.into_filesystem();
        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(reopened.next_offset(), Offset::new(durable + 1));
    }

    #[test]
    fn a_deferred_roll_is_completed_by_a_later_sync() {
        use crate::fault::FaultFs;
        // #867 review finding 5: a deferred roll is completed by ANY write entry point, not just
        // append — here a `sync` finishes it via `ensure_writable`.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        let mut durable = 0u64;
        while !log.active_segment_at_or_over_cap().unwrap() {
            log.append(&rec(&[7u8; 20])).unwrap();
            log.sync().unwrap();
            durable += 1;
        }
        control.fail_create_new(1);
        let err = log.append(&rec(&[8u8; 20])).unwrap_err();
        assert!(!matches!(err, StorageError::WriterFrozen), "got {err:?}");
        // A `sync` (not an append) completes the deferred roll; the fault has already cleared.
        log.sync().unwrap();
        assert!(log.is_writable(), "the roll completed, the writer is live");
        assert_eq!(log.append(&rec(&[9u8; 20])).unwrap(), Offset::new(durable));
    }

    #[test]
    fn many_segments_hold_every_record_in_global_offset_order() {
        let mut log = open_mem(small_config());
        let n: usize = 20;
        for i in 0..n {
            let b = u8::try_from(i).unwrap();
            log.append(&rec(&[b; 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(
            log.active_segment_id() >= 2,
            "should span three or more segments"
        );
        // Concatenating records across all segments in id order yields a contiguous
        // global offset and sequence run 0..n, the end-to-end continuity invariant.
        let mut all = Vec::new();
        for id in segment_ids(log.filesystem()).unwrap() {
            all.extend(read_back(log.filesystem(), id));
        }
        assert_eq!(all.len(), n);
        for (i, r) in all.iter().enumerate() {
            assert_eq!(r.offset, Offset::new(i as u64));
            assert_eq!(r.seq, Seq::new(i as u64));
        }
    }

    #[test]
    fn read_within_a_single_segment() {
        let mut log = open_mem(LogConfig::default());
        log.append(&rec(b"a")).unwrap();
        log.append(&rec(b"b")).unwrap();
        log.append(&rec(b"c")).unwrap();
        log.sync().unwrap();
        let records = log.read_from(Offset::ZERO, 10).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].offset, Offset::new(0));
        assert_eq!(records[0].payload.as_ref(), b"a");
        assert_eq!(records[2].payload.as_ref(), b"c");
    }

    #[test]
    fn read_only_returns_flushed_records() {
        let mut log = open_mem(LogConfig::default());
        log.append(&rec(b"durable")).unwrap();
        log.sync().unwrap();
        log.append(&rec(b"pending")).unwrap(); // appended but not synced
        assert_eq!(log.flushed_offset(), Offset::new(1));
        let records = log.read_from(Offset::ZERO, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload.as_ref(), b"durable");
        // After sync the pending record becomes visible.
        log.sync().unwrap();
        assert_eq!(log.read_from(Offset::ZERO, 10).unwrap().len(), 2);
    }

    #[test]
    fn read_from_a_middle_offset() {
        let mut log = open_mem(LogConfig::default());
        for i in 0..5u8 {
            log.append(&rec(&[i; 4])).unwrap();
        }
        log.sync().unwrap();
        let records = log.read_from(Offset::new(2), 10).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].offset, Offset::new(2));
        assert_eq!(records[2].offset, Offset::new(4));
    }

    #[test]
    fn read_honors_the_max_batch_size() {
        let mut log = open_mem(LogConfig::default());
        for i in 0..5u8 {
            log.append(&rec(&[i; 4])).unwrap();
        }
        log.sync().unwrap();
        let records = log.read_from(Offset::ZERO, 2).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].offset, Offset::new(1));
    }

    #[test]
    fn read_at_or_past_the_flushed_offset_is_empty() {
        let mut log = open_mem(LogConfig::default());
        log.append(&rec(b"a")).unwrap();
        log.sync().unwrap();
        assert!(log.read_from(Offset::new(1), 10).unwrap().is_empty()); // == flushed
        assert!(log.read_from(Offset::new(5), 10).unwrap().is_empty()); // past flushed
        assert!(log.read_from(Offset::ZERO, 0).unwrap().is_empty()); // max 0
    }

    #[test]
    fn read_spans_multiple_segments_in_order() {
        let mut log = open_mem(small_config());
        let n: usize = 12;
        for i in 0..n {
            log.append(&rec(&[u8::try_from(i).unwrap(); 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 1, "should have rolled");
        let records = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(records.len(), n);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.offset, Offset::new(i as u64));
            assert_eq!(r.seq, Seq::new(i as u64));
        }
        // A mid-stream read that begins inside a later segment, with a batch limit.
        let from5 = log.read_from(Offset::new(5), 4).unwrap();
        assert_eq!(from5.len(), 4);
        assert_eq!(from5[0].offset, Offset::new(5));
        assert_eq!(from5[3].offset, Offset::new(8));
    }

    // ---- #483 resident seek index: equivalence + eviction correctness ----

    /// A REFERENCE read that bypasses the resident #483 seek index entirely: it reads each
    /// ORDINARY segment with a full `SegmentReader::scan()` (the pre-#483 behavior) and applies the
    /// exact same bounds/start/flushed/max filter `read_from` does, so any divergence between this
    /// and `read_from` is a seek-index bug. A compacted (sparse) segment routes through the v2 scan
    /// exactly as the production path does (the index never touches it).
    fn read_from_by_full_scan<G: Filesystem, K: Clock>(
        log: &Log<G, K>,
        start: u64,
        max: usize,
    ) -> Vec<OwnedRecord> {
        let flushed = log.flushed_offset().get();
        if max == 0 || start >= flushed {
            return Vec::new();
        }
        let oldest = log
            .segments
            .first()
            .map_or(0, SegmentSlot::covered_base_offset);
        assert!(start >= oldest, "test only covers in-range starts");
        let mut out = Vec::new();
        for slot in &log.segments[log.segment_index_for(start)..] {
            if slot.covered_base_offset() >= flushed {
                break;
            }
            let reader =
                SegmentReader::open(log.fs.open(&segment_file_name(slot.id)).unwrap()).unwrap();
            let records = if slot.compacted_covered.is_some() {
                reader.scan_compacted().unwrap().unwrap().records
            } else {
                reader.scan().unwrap().records
            };
            for record in records {
                let offset = record.offset.get();
                if offset < start {
                    continue;
                }
                if offset >= flushed || out.len() >= max {
                    return out;
                }
                out.push(record);
            }
        }
        out
    }

    #[test]
    fn read_from_via_the_index_is_byte_identical_to_a_full_scan_over_every_window() {
        // A multi-segment dense log (the tiny cap forces several rolls), then a final UNSYNCED tail
        // so `flushed` sits mid-active-segment (exercising the flushed-clamped read end). Sweep every
        // (start, max) window and require the index-driven `read_from` to equal the full-scan
        // reference EXACTLY (offset, seq, payload — full `OwnedRecord` equality).
        let mut log = open_mem(small_config());
        let n: u64 = 25;
        for i in 0..n {
            log.append(&rec(&[u8::try_from(i % 256).unwrap(); 16]))
                .unwrap();
        }
        log.sync().unwrap();
        // Append a few MORE without syncing so the active segment has visible (rolled) + invisible
        // (unsynced) records, putting `flushed` strictly inside the active segment's range.
        for i in n..n + 3 {
            log.append(&rec(&[u8::try_from(i % 256).unwrap(); 16]))
                .unwrap();
        }
        assert!(
            log.active_segment_id() >= 2,
            "should have rolled several times"
        );
        let flushed = log.flushed_offset().get();

        let sweep = |log: &Log<InMemoryFs, ManualClock>| {
            for start in 0..=flushed + 2 {
                for max in [0usize, 1, 2, 3, 7, 1000] {
                    let via_index = log.read_from(Offset::new(start), max).unwrap();
                    let via_scan = read_from_by_full_scan(log, start, max);
                    assert_eq!(
                        via_index, via_scan,
                        "index vs scan mismatch at start={start} max={max}"
                    );
                }
            }
        };

        // First with the append-SEEDED active index and lazily-built sealed indexes in place...
        sweep(&log);
        // ...then after DROPPING every index, so the next reads rebuild from the durable frames and
        // the freshly-BUILT index path is proven byte-identical too.
        log.clear_segment_indexes();
        sweep(&log);
    }

    // ---- #538 single-pass contiguous read_range: differential + byte cap + boundaries ----

    /// A multi-segment dense log with `n` synced records (the tiny `small_config` cap forces several
    /// rolls), plus a few UNSYNCED tail records so `flushed` sits mid-active-segment. The shared
    /// fixture for the `read_range` tests below.
    fn rolled_log_unsynced_tail(n: u64) -> Log<InMemoryFs, ManualClock> {
        let mut log = open_mem(small_config());
        for i in 0..n {
            log.append(&rec(&[u8::try_from(i % 256).unwrap(); 16]))
                .unwrap();
        }
        log.sync().unwrap();
        for i in n..n + 3 {
            log.append(&rec(&[u8::try_from(i % 256).unwrap(); 16]))
                .unwrap();
        }
        assert!(
            log.active_segment_id() >= 2,
            "should have rolled several times"
        );
        log
    }

    #[test]
    fn read_range_equals_n_single_record_reads_over_every_window() {
        // The core differential: a single-pass `read_range(start, max, None)` must return the EXACT
        // same records (full `OwnedRecord` equality) as gluing together N successive single-record
        // `read_from(off, 1)` reads from `start` — across segment boundaries, the anchor stride, the
        // flushed clamp, and the empty/partial-tail edges. Anything else is a single-pass bug.
        let n: u64 = 25;
        let log = rolled_log_unsynced_tail(n);
        let flushed = log.flushed_offset().get();

        let differential = |log: &Log<InMemoryFs, ManualClock>| {
            for start in 0..=flushed + 2 {
                for max in [0usize, 1, 2, 3, 7, 1000] {
                    let batch = log.read_range(Offset::new(start), max, None).unwrap();
                    // The reference: read records one at a time, advancing the offset, up to `max`.
                    let mut piecewise = Vec::new();
                    let mut off = start;
                    while piecewise.len() < max {
                        let one = log.read_from(Offset::new(off), 1).unwrap();
                        let Some(record) = one.into_iter().next() else {
                            break; // hit the flushed end
                        };
                        off = record.offset.get() + 1;
                        piecewise.push(record);
                    }
                    assert_eq!(
                        batch, piecewise,
                        "read_range != N x read_from(off,1) at start={start} max={max}"
                    );
                }
            }
        };

        // With the seeded/lazy indexes, then after dropping them so the rebuilt path is proven too.
        differential(&log);
        log.clear_segment_indexes();
        differential(&log);
    }

    /// Decodes a [`RawByteRun`]'s bytes front-to-back into `(RecordView, offset)` pairs the way a
    /// `DeliverBatch` client does: positional offset reconstruction (`first_offset + i`), each frame
    /// fully CRC-validated by `codec::decode`. Asserts the run is EXACTLY `record_count` whole frames.
    fn decode_raw_run(run: &RawByteRun) -> Vec<(RecordView<'_>, u64)> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        let mut offset = run.first_offset.get();
        while cursor < run.bytes.len() {
            let (view, consumed) =
                ironbus_core::codec::decode(&run.bytes[cursor..]).expect("raw run frame decodes");
            out.push((view, offset));
            offset = offset.saturating_add(1);
            cursor += consumed;
        }
        assert_eq!(cursor, run.bytes.len(), "raw run is exactly whole frames");
        assert_eq!(
            out.len() as u64,
            run.record_count,
            "count matches the frames"
        );
        out
    }

    #[test]
    fn read_range_raw_is_byte_identical_to_read_range_and_chains_the_whole_prefix() {
        // #541: the through-actor raw read (the DeliverBatch source) decodes to the SAME records as the
        // materialize path, with offsets reconstructed POSITIONALLY, and chaining each raw run's
        // `tail_from` through `read_range` reconstructs the WHOLE flushed prefix with no gaps/overlaps —
        // across the anchor stride, segment boundaries, and the sealed/active boundary.
        let n: u64 = 25;
        let log = rolled_log_unsynced_tail(n);
        let flushed = log.flushed_offset().get();
        assert!(log.active_segment_id() >= 2, "must span several segments");

        let differential = |log: &Log<InMemoryFs, ManualClock>| {
            // Per-window: a single raw run is byte-identical to the prefix `read_range` returns over the
            // same single segment, and its records start exactly at `start`.
            for start in 0..flushed {
                for max in [1usize, 2, 3, 7, 1000] {
                    let (run, _tail) = log.read_range_raw(Offset::new(start), max, None).unwrap();
                    let materialized = log.read_range(Offset::new(start), max, None).unwrap();
                    let decoded = decode_raw_run(&run);
                    for ((view, off), owned) in decoded.iter().zip(materialized.iter()) {
                        assert_eq!(*off, owned.offset.get(), "offset at start={start}");
                        assert_eq!(view.seq, owned.seq, "seq at start={start}");
                        assert_eq!(view.timestamp_ms, owned.timestamp_ms);
                        assert_eq!(view.flags, owned.flags);
                        assert_eq!(view.key, &owned.key[..]);
                        assert_eq!(view.headers, &owned.headers[..]);
                        assert_eq!(view.payload, &owned.payload[..]);
                    }
                    if let Some((_, off)) = decoded.first() {
                        assert_eq!(*off, start, "raw run starts at the requested offset");
                    }
                }
            }
            // Chaining: follow each run's `tail_from` (serving it raw when possible, else materialized)
            // to walk the whole flushed prefix exactly once, in order.
            let mut next = 0u64;
            let mut seen: Vec<u64> = Vec::new();
            let mut guard = 0u32;
            while next < flushed {
                guard += 1;
                assert!(guard < 10_000, "raw-read chain did not terminate");
                let (run, tail_from) = log.read_range_raw(Offset::new(next), 1_000, None).unwrap();
                for (_, off) in decode_raw_run(&run) {
                    seen.push(off);
                }
                match tail_from {
                    // A raw-served-then-resume boundary (segment edge): continue from the run's end. When
                    // the raw run was EMPTY (the start landed on the active tail the raw path doesn't
                    // serve), drain that remainder via the materialize path so the chain advances.
                    Some(off) => {
                        if run.record_count == 0 {
                            for record in log.read_range(off, 1_000, None).unwrap() {
                                seen.push(record.offset.get());
                            }
                            // The active tail is the last region below flushed; the chain ends here.
                            break;
                        }
                        next = off.get();
                    }
                    None => break,
                }
            }
            let expected: Vec<u64> = (0..flushed).collect();
            assert_eq!(
                seen, expected,
                "raw chain covers the whole prefix once, in order"
            );
        };

        differential(&log);
        log.clear_segment_indexes();
        differential(&log);
    }

    #[test]
    fn read_range_raw_honors_max_records_and_max_bytes_like_read_range() {
        // The raw read applies the SAME record-count and byte caps (first-frame-always rule) as
        // read_range, so a capped raw run decodes to the same records the capped materialize path does.
        let mut log = open_mem(LogConfig::default());
        for i in 0..50u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
        }
        log.sync().unwrap();
        let one_frame = log.read_range(Offset::ZERO, 1, None).unwrap()[0].encoded_len();
        for k in 1..=8usize {
            let cap = k * one_frame;
            let (run, _) = log
                .read_range_raw(Offset::ZERO, usize::MAX, Some(cap))
                .unwrap();
            let materialized = log.read_range(Offset::ZERO, usize::MAX, Some(cap)).unwrap();
            let decoded = decode_raw_run(&run);
            assert_eq!(
                decoded.len(),
                materialized.len(),
                "raw byte-capped count matches materialize at cap={cap}"
            );
            for ((_, off), owned) in decoded.iter().zip(materialized.iter()) {
                assert_eq!(*off, owned.offset.get());
            }
        }
        // max_records == 0 serves nothing; a start at/past the flushed head serves nothing and resumes
        // nowhere.
        let (empty, tail) = log.read_range_raw(Offset::ZERO, 0, None).unwrap();
        assert_eq!(empty.record_count, 0);
        assert_eq!(tail, None);
        let head = log.flushed_offset();
        let (caught_up, tail) = log.read_range_raw(head, 100, None).unwrap();
        assert_eq!(caught_up.record_count, 0);
        assert_eq!(tail, None);
    }

    #[test]
    fn read_range_crosses_the_anchor_stride_and_segment_boundaries_in_one_call() {
        // A batch spanning many segments (small_config rolls every ~2 records) returns the whole
        // contiguous run in ONE call, identical to the per-record reference, proving the single pass
        // crosses both the index anchor stride and the physical segment boundaries.
        let n: u64 = 25;
        let log = rolled_log_unsynced_tail(n);
        let flushed = log.flushed_offset().get();
        assert!(log.active_segment_id() >= 2, "must span several segments");

        let batch = log.read_range(Offset::ZERO, usize::MAX, None).unwrap();
        // Every visible record, in order, exactly once.
        assert_eq!(batch.len() as u64, flushed);
        for (i, record) in batch.iter().enumerate() {
            assert_eq!(record.offset, Offset::new(i as u64));
        }
        // Equals the read_from full read (same single-pass machinery, no byte cap).
        assert_eq!(batch, log.read_from(Offset::ZERO, usize::MAX).unwrap());
    }

    #[test]
    fn read_range_honors_max_bytes_and_always_returns_at_least_one() {
        // Uniform 16-byte-payload records, so every frame has the same encoded length. A `max_bytes`
        // budget then admits a predictable record count, and a budget BELOW one frame still returns
        // exactly one record (the "at least one" fetch rule), never an empty stall.
        let n: u64 = 12;
        let mut log = open_mem(LogConfig {
            max_segment_bytes: 8 * 1024,
            max_total_bytes: 0,
            ..LogConfig::default()
        });
        for i in 0..n {
            log.append(&rec(&[u8::try_from(i % 256).unwrap(); 16]))
                .unwrap();
        }
        log.sync().unwrap();
        let one_frame = log.read_range(Offset::ZERO, 1, None).unwrap()[0].encoded_len();

        // A budget of exactly K frames yields exactly K records (the K+1th would exceed it).
        for k in 1..=6usize {
            let got = log
                .read_range(Offset::ZERO, usize::MAX, Some(k * one_frame))
                .unwrap();
            assert_eq!(
                got.len(),
                k,
                "max_bytes for {k} frames should yield {k} records"
            );
            let total: usize = got.iter().map(OwnedRecord::encoded_len).sum();
            assert!(total <= k * one_frame, "byte total {total} over the cap");
        }
        // A budget smaller than one frame (even zero) still returns exactly one record.
        for cap in [0usize, 1, one_frame - 1] {
            let got = log.read_range(Offset::ZERO, usize::MAX, Some(cap)).unwrap();
            assert_eq!(
                got.len(),
                1,
                "a sub-frame cap of {cap} must still return one record"
            );
            assert_eq!(got[0].offset, Offset::ZERO);
        }
        // max_records still bounds the read independently of max_bytes.
        let got = log
            .read_range(Offset::ZERO, 2, Some(100 * one_frame))
            .unwrap();
        assert_eq!(
            got.len(),
            2,
            "max_records caps below the generous byte budget"
        );
    }

    #[test]
    fn read_range_max_bytes_budget_accumulates_across_segment_boundaries() {
        // The byte budget is a WHOLE-READ bound, not per-segment: with a tiny cap that rolls every
        // ~2 records, a byte budget spanning several segments must stop at the same record count it
        // would on a single segment, and never reset its accounting at a segment boundary.
        let n: u64 = 20;
        let log = rolled_log_unsynced_tail(n);
        let one_frame = log.read_range(Offset::ZERO, 1, None).unwrap()[0].encoded_len();
        // Budget for 5 frames; small_config rolls within that span, so this crosses boundaries.
        let got = log
            .read_range(Offset::ZERO, usize::MAX, Some(5 * one_frame))
            .unwrap();
        assert_eq!(got.len(), 5, "byte budget must not reset per segment");
        // Contiguous from 0.
        for (i, record) in got.iter().enumerate() {
            assert_eq!(record.offset, Offset::new(i as u64));
        }
    }

    #[test]
    fn read_range_respects_the_torn_tail_and_flushed_boundary() {
        // Records appended but NOT synced sit in the active segment's pending buffer, past `flushed`,
        // and must never be returned, even with an unbounded record/byte budget — the same durable-
        // prefix safety `read_from` enforces. A roomy cap keeps the unsynced tail in ONE active
        // segment (no roll, which would flush), so it stays genuinely beyond the flushed boundary.
        let mut log = open_mem(LogConfig {
            max_segment_bytes: 8 * 1024,
            max_total_bytes: 0,
            ..LogConfig::default()
        });
        for i in 0..6u8 {
            log.append(&rec(&[i; 16])).unwrap();
        }
        log.sync().unwrap();
        // Append more WITHOUT syncing: these are not durable and do not roll at this cap.
        for i in 6..10u8 {
            log.append(&rec(&[i; 16])).unwrap();
        }
        let flushed = log.flushed_offset().get();
        assert_eq!(
            flushed, 6,
            "only the synced prefix is flushed; the tail is pending"
        );
        let got = log.read_range(Offset::ZERO, usize::MAX, None).unwrap();
        assert_eq!(
            got.len() as u64,
            flushed,
            "only the flushed prefix is visible"
        );
        assert!(got.iter().all(|r| r.offset.get() < flushed));
        // It matches read_from exactly (same durable-prefix bound).
        assert_eq!(got, log.read_from(Offset::ZERO, usize::MAX).unwrap());
        // A read AT the flushed offset is empty (nothing durable beyond it).
        assert!(log
            .read_range(Offset::new(flushed), usize::MAX, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn read_range_empty_and_partial_edges() {
        let n: u64 = 8;
        let log = rolled_log_unsynced_tail(n);
        let flushed = log.flushed_offset().get();
        // max_records == 0 is empty regardless of byte budget.
        assert!(log
            .read_range(Offset::ZERO, 0, Some(usize::MAX))
            .unwrap()
            .is_empty());
        // start at/past flushed is empty.
        assert!(log
            .read_range(Offset::new(flushed), 100, None)
            .unwrap()
            .is_empty());
        assert!(log
            .read_range(Offset::new(flushed + 5), 100, None)
            .unwrap()
            .is_empty());
        // A partial read near the tail returns just the remaining records.
        let tail = log.read_range(Offset::new(flushed - 2), 100, None).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].offset, Offset::new(flushed - 2));
        assert_eq!(tail[1].offset, Offset::new(flushed - 1));
        // An out-of-range (below oldest) start errors, like read_from. (oldest is 0 here, so use a
        // reaped scenario is overkill; instead assert read_from and read_range agree on the error
        // surface by reading from 0 on a non-empty log — both succeed.)
        assert_eq!(
            log.read_range(Offset::ZERO, 100, None).unwrap(),
            log.read_from(Offset::ZERO, 100).unwrap()
        );
    }

    #[test]
    fn the_seeded_active_index_matches_a_rebuild_after_a_reopen() {
        // The append-seeded active index (extended record-by-record) must agree with the index a
        // fresh reopen rebuilds from the durable frames: same records for every window.
        let mut log = open_mem(small_config());
        for i in 0..14u8 {
            log.append(&rec(&[i; 16])).unwrap();
        }
        log.sync().unwrap();
        let seeded: Vec<_> = (0..14)
            .map(|s| log.read_from(Offset::new(s), 100).unwrap())
            .collect();
        let fs = log.into_filesystem();
        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        for (s, expected) in seeded.iter().enumerate() {
            let got = reopened.read_from(Offset::new(s as u64), 100).unwrap();
            assert_eq!(&got, expected, "rebuilt index diverged at start={s}");
        }
    }

    #[test]
    fn a_reap_evicts_the_seek_index_so_no_stale_entry_survives_retirement() {
        // Build several sealed segments, POISON the oldest sealed segment's resident index (every
        // entry points at the first record — a wrong-data index), then reap it. The eviction on
        // retirement must drop the poisoned entry; a subsequent read of the surviving log is correct.
        let mut log = open_mem(small_config());
        for i in 0..18u8 {
            log.append(&rec(&[i; 16])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.segments.len() >= 3, "need several sealed segments");

        let oldest = log.segments[0];
        // Build the real index first (a read), then overwrite it with a poisoned one bound to the
        // SAME id, proving that without eviction a seek would serve wrong data.
        let _ = log.read_from(Offset::new(oldest.base_offset), 1).unwrap();
        log.poison_segment_index(
            oldest.id,
            oldest.base_offset,
            usize::try_from(oldest.record_count.max(1)).unwrap(),
            // A large valid_end is fine; the poisoned positions are what would mislead a seek.
            u64::MAX,
        );
        assert!(log.has_segment_index(oldest.id));

        // Reap the oldest segment: the protect floor is above its whole range (fully consumed), and a
        // tiny byte bound makes it eligible.
        let next_base = log.segments[1].base_offset;
        let outcome = log
            .reap(
                RetentionBounds {
                    max_bytes: 1,
                    ..RetentionBounds::default()
                },
                next_base,
            )
            .unwrap();
        assert!(
            outcome.segments_reaped >= 1,
            "the oldest should have reaped"
        );
        // The retirement EVICTED the poisoned index: it is gone, not serving stale data.
        assert!(
            !log.has_segment_index(oldest.id),
            "the reaped segment's index must be evicted"
        );

        // The surviving log still reads correctly across every window (a fresh, correct index is
        // rebuilt for the new oldest segment on demand).
        let flushed = log.flushed_offset().get();
        for start in next_base..flushed {
            let via_index = log.read_from(Offset::new(start), 100).unwrap();
            let via_scan = read_from_by_full_scan(&log, start, 100);
            assert_eq!(
                via_index, via_scan,
                "post-reap read diverged at start={start}"
            );
        }
    }

    #[test]
    fn forced_reap_evicts_the_seek_index() {
        let mut log = open_mem(small_config());
        for i in 0..16u8 {
            log.append(&rec(&[i; 16])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.segments.len() >= 2);
        let oldest = log.segments[0];
        let _ = log.read_from(Offset::new(oldest.base_offset), 1).unwrap();
        log.poison_segment_index(
            oldest.id,
            oldest.base_offset,
            usize::try_from(oldest.record_count.max(1)).unwrap(),
            u64::MAX,
        );
        assert!(log.has_segment_index(oldest.id));
        let out = log.reap_oldest_forced().unwrap();
        assert!(out.is_some(), "a force-reap should remove the oldest");
        assert!(
            !log.has_segment_index(oldest.id),
            "the force-reaped segment's index must be evicted"
        );
    }

    #[test]
    fn repeated_read_from_opens_a_sealed_segment_once() {
        // #808: the through-actor consume hot path (Tier-W polls `read_from(off, 1)` per delivered
        // message) reuses one opened reader per SEALED segment, so N reads of one sealed segment do ONE
        // open, not N. Without the cache the open-count delta would equal the number of reads.
        use crate::fault::FaultFs;
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        for i in 0..16u8 {
            log.append(&rec(&[i; 16])).unwrap();
        }
        log.sync().unwrap();
        assert!(
            log.segments.len() >= 2,
            "the tiny cap sealed several segments"
        );
        let oldest = log.segments[0];
        let base = oldest.base_offset;
        // Read the first sealed segment's base offset many times; it is opened on the first read and the
        // opened reader is reused for the rest.
        let baseline = control.open_count();
        for _ in 0..20 {
            let recs = log.read_from(Offset::new(base), 1).unwrap();
            assert_eq!(recs.len(), 1, "each read served the sealed record");
        }
        assert_eq!(
            control.open_count() - baseline,
            1,
            "20 reads of one sealed segment opened it ONCE (#808), not 20 times"
        );
        assert!(
            log.has_sealed_reader(oldest.id),
            "the sealed reader is cached"
        );
    }

    #[test]
    fn a_force_reap_evicts_the_cached_sealed_reader() {
        // #808: a retired segment's cached reader (and its fd) is dropped in lockstep with its seek index
        // via `evict_segment_index`, so a reaped segment never leaves a leaked fd behind.
        let mut log = open_mem(small_config());
        for i in 0..16u8 {
            log.append(&rec(&[i; 16])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.segments.len() >= 2);
        let oldest = log.segments[0];
        // Warm the cache for the oldest sealed segment.
        let _ = log.read_from(Offset::new(oldest.base_offset), 1).unwrap();
        assert!(
            log.has_sealed_reader(oldest.id),
            "the oldest sealed segment's reader is cached after a read"
        );
        let out = log.reap_oldest_forced().unwrap();
        assert!(out.is_some(), "a force-reap removes the oldest");
        assert!(
            !log.has_sealed_reader(oldest.id),
            "the force-reaped segment's cached reader (and its fd) must be evicted (#808)"
        );
    }

    #[test]
    fn compaction_install_evicts_the_source_segment_seek_indexes() {
        use crate::compaction::CompactionConfig;
        // A keyed, multi-version log across several sealed segments, so a compaction pass retires a
        // run of ORDINARY source segments and replaces them with one compacted segment. The source
        // indexes (poisoned to prove the point) must be evicted on install; the post-compaction read
        // serves the correct sparse survivors at their original offsets.
        let mut log = open_mem(small_config());
        for v in 0..6u8 {
            for (k, base) in [(&b"alpha"[..], 0u8), (&b"beta"[..], 100u8)] {
                log.append(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: k,
                    headers: b"",
                    payload: &[v + base; 12],
                })
                .unwrap();
                log.sync().unwrap();
            }
        }
        // A keyless carry-through and a one-shot key so survivors include verbatim records.
        log.append(&rec(b"keyless")).unwrap();
        log.sync().unwrap();
        let active = log.active_segment_id();
        let source_ids: Vec<u64> = (0..active).collect();
        assert!(
            source_ids.len() >= 2,
            "need adjacent sealed sources to compact"
        );

        // Build + poison each source segment's resident index, so a surviving entry would mislead.
        let before = read_from_by_full_scan(&log, 0, 10_000);
        for &id in &source_ids {
            let slot = *log.segments.iter().find(|s| s.id == id).unwrap();
            let _ = log.read_from(Offset::new(slot.base_offset), 1).unwrap();
            log.poison_segment_index(
                id,
                slot.base_offset,
                usize::try_from(slot.record_count.max(1)).unwrap(),
                u64::MAX,
            );
        }

        let out = log.maybe_compact(&CompactionConfig::enabled()).unwrap();
        assert!(
            out.compacted_segment_id.is_some(),
            "a dirty keyed log should compact"
        );
        // EVERY retired source index is evicted; the new compacted (sparse) segment is never indexed.
        for &id in &source_ids {
            assert!(
                !log.has_segment_index(id),
                "compaction must evict source segment {id}'s seek index"
            );
        }
        assert!(
            !log.has_segment_index(out.compacted_segment_id.unwrap()),
            "a compacted (sparse) segment is not seek-indexed"
        );

        // The post-compaction read (sparse survivors at original offsets) is correct and matches a
        // full scan; the surviving latest-per-key set is a subset of the pre-compaction records.
        let after_index = {
            let head = log.flushed_offset().get();
            log.read_from(Offset::ZERO, usize::try_from(head).unwrap())
                .unwrap()
        };
        let after_scan = read_from_by_full_scan(&log, 0, 10_000);
        assert_eq!(
            after_index, after_scan,
            "post-compaction index vs scan mismatch"
        );
        assert!(
            after_index.len() < before.len(),
            "compaction dropped superseded versions"
        );
    }

    // ---- #481 compacted (sparse) seek index: equivalence over windows + holes + eviction ----

    /// Builds a keyed, multi-version log, runs a compaction pass so a real COMPACTED (v2, sparse)
    /// segment with COMPACTION HOLES exists, and returns the log. The survivors are the
    /// latest-per-key set, so their offsets are sparse: the superseded earlier versions leave
    /// absent (hole) offsets between the survivors. Used by the seek-equivalence tests below.
    fn log_with_a_sparse_compacted_segment() -> Log<InMemoryFs, ManualClock> {
        use crate::compaction::CompactionConfig;
        let mut log = open_mem(small_config());
        // Several versions of each of a few keys, each synced so they land in sealed segments a
        // compaction pass can pick up. Interleaving keys + versions makes the survivor offsets
        // genuinely sparse (the latest of each key sits at a scattered original offset).
        for v in 0..6u8 {
            for (k, base) in [
                (&b"alpha"[..], 0u8),
                (&b"beta"[..], 50u8),
                (&b"gamma"[..], 100u8),
            ] {
                log.append(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: k,
                    headers: b"",
                    payload: &[v + base; 12],
                })
                .unwrap();
                log.sync().unwrap();
            }
        }
        let out = log.maybe_compact(&CompactionConfig::enabled()).unwrap();
        assert!(
            out.compacted_segment_id.is_some(),
            "the keyed log must compact into a v2 segment"
        );
        assert!(
            log.segments.iter().any(|s| s.compacted_covered.is_some()),
            "a compacted (sparse) slot must be present"
        );
        log
    }

    #[test]
    fn compacted_read_via_the_seek_is_byte_identical_to_the_full_scan_over_every_window() {
        // The #481 contract: reading a COMPACTED segment by SEEKING to `start` and materializing
        // <= `max` survivors must equal the pre-#481 whole-region full scan for EVERY (start, max)
        // window — including starts that land on a compaction HOLE (an absent offset, which must
        // advance to the next present survivor) and starts below/above the survivor range.
        let log = log_with_a_sparse_compacted_segment();
        let flushed = log.flushed_offset().get();

        // Confirm the segment really is sparse (has holes): the survivor count is below the covered
        // span, so some offsets in `[0, flushed)` are absent — the case this test must cover.
        let all = read_from_by_full_scan(&log, 0, 10_000);
        assert!(
            (all.len() as u64) < flushed,
            "the compacted segment must have holes for this test to mean anything"
        );
        // And there is at least one genuine hole offset to start a read ON.
        let present: std::collections::HashSet<u64> = all.iter().map(|r| r.offset.get()).collect();
        assert!(
            (0..flushed).any(|o| !present.contains(&o)),
            "expected at least one compaction-hole offset"
        );

        let sweep = |log: &Log<InMemoryFs, ManualClock>| {
            // `..=flushed + 2` so starts AT and PAST the durable end are exercised too.
            for start in 0..=flushed + 2 {
                for max in [0usize, 1, 2, 3, 5, 1000] {
                    let via_seek = log.read_from(Offset::new(start), max).unwrap();
                    let via_scan = read_from_by_full_scan(log, start, max);
                    assert_eq!(
                        via_seek, via_scan,
                        "compacted seek vs full-scan mismatch at start={start} max={max}"
                    );
                }
            }
        };

        // First with the lazily-built compacted index in place...
        sweep(&log);
        // ...then after DROPPING it, so the next reads rebuild the sparse index from the durable
        // survivor frames and the freshly-BUILT seek path is proven byte-identical too.
        log.clear_compacted_indexes();
        sweep(&log);
    }

    #[test]
    fn read_range_over_a_compacted_segment_matches_per_record_and_honors_max_bytes() {
        // The single-pass batch read crosses the SPARSE compacted survivor region too (#538): a
        // `read_range` over a compacted segment must equal the per-record reference (so the sparse
        // seek + forward scan is the same set), and a `max_bytes` budget bounds the survivors it
        // returns while still always returning at least one.
        let log = log_with_a_sparse_compacted_segment();
        let flushed = log.flushed_offset().get();
        let all = read_from_by_full_scan(&log, 0, 10_000);
        assert!(
            (all.len() as u64) < flushed,
            "the segment must be sparse for this test"
        );

        // Differential vs N single-record reads, over every window (including hole starts).
        for start in 0..=flushed + 1 {
            for max in [0usize, 1, 2, 3, 1000] {
                let batch = log.read_range(Offset::new(start), max, None).unwrap();
                let mut piecewise = Vec::new();
                let mut off = start;
                while piecewise.len() < max && off < flushed {
                    let one = log.read_from(Offset::new(off), 1).unwrap();
                    let Some(record) = one.into_iter().next() else {
                        break;
                    };
                    off = record.offset.get() + 1;
                    piecewise.push(record);
                }
                assert_eq!(
                    batch, piecewise,
                    "compacted read_range != per-record at start={start} max={max}"
                );
            }
        }

        // A max_bytes budget bounds the survivors returned (and always returns at least one).
        let one_frame = log.read_range(Offset::ZERO, 1, None).unwrap()[0].encoded_len();
        let two = log
            .read_range(Offset::ZERO, usize::MAX, Some(2 * one_frame))
            .unwrap();
        assert!(
            two.len() <= 2 && !two.is_empty(),
            "a 2-frame byte budget returns 1 or 2 survivors, never zero (got {})",
            two.len()
        );
        let sub = log.read_range(Offset::ZERO, usize::MAX, Some(0)).unwrap();
        assert_eq!(
            sub.len(),
            1,
            "a zero byte budget still returns one survivor"
        );
    }

    #[test]
    fn a_reap_evicts_the_compacted_seek_index_so_no_stale_entry_survives_retirement() {
        // The compacted-segment leg of the evict-on-retirement guarantee (#481, mirroring #483's
        // dense leg). Build a sparse compacted segment, POISON its resident sparse index (every
        // survivor entry points at the FIRST survivor — a wrong-data index that would serve the
        // lowest survivor for every offset), then reap it. The eviction on retirement must drop the
        // poisoned entry, and a read of the surviving log is correct (a fresh index is rebuilt).
        let mut log = log_with_a_sparse_compacted_segment();
        // The compacted slot is the oldest (it covers the lowest range). Append + roll a couple more
        // ORDINARY records so a later segment exists and the compacted one is reapable (never the
        // active segment).
        for i in 0..6u8 {
            log.append(&rec(&[200 + i; 16])).unwrap();
            log.sync().unwrap();
        }
        let compacted = *log
            .segments
            .iter()
            .find(|s| s.compacted_covered.is_some())
            .expect("a compacted slot");
        assert_eq!(
            compacted.id, log.segments[0].id,
            "the compacted slot is the oldest, hence reapable"
        );

        // Build the real sparse index (a read touches it), then overwrite it with a poisoned one
        // bound to the SAME id, proving that without eviction a seek would serve wrong data.
        let _ = log
            .read_from(Offset::new(compacted.covered_base_offset()), 1)
            .unwrap();
        assert!(log.has_compacted_index(compacted.id));
        let survivor_offsets: Vec<u64> = read_from_by_full_scan(&log, 0, 10_000)
            .iter()
            .map(|r| r.offset.get())
            .filter(|&o| o < log.segments[1].covered_base_offset())
            .collect();
        log.poison_compacted_index(compacted.id, &survivor_offsets, u64::MAX);
        assert!(log.has_compacted_index(compacted.id));

        // Reap the oldest (compacted) segment: the protect floor is above its whole covered range
        // (fully consumed) and a tiny byte bound makes it eligible.
        let next_base = log.segments[1].covered_base_offset();
        let outcome = log
            .reap(
                RetentionBounds {
                    max_bytes: 1,
                    ..RetentionBounds::default()
                },
                next_base,
            )
            .unwrap();
        assert!(outcome.segments_reaped >= 1, "the compacted oldest reaped");
        // The retirement EVICTED the poisoned compacted index: it is gone, not serving stale data.
        assert!(
            !log.has_compacted_index(compacted.id),
            "the reaped compacted segment's sparse index must be evicted"
        );

        // The surviving log still reads correctly across every window.
        let flushed = log.flushed_offset().get();
        for start in next_base..flushed {
            let via_seek = log.read_from(Offset::new(start), 100).unwrap();
            let via_scan = read_from_by_full_scan(&log, start, 100);
            assert_eq!(
                via_seek, via_scan,
                "post-reap read diverged at start={start}"
            );
        }
    }

    #[test]
    fn the_resident_index_set_stays_bounded_to_open_segments() {
        // After reaping old segments, the resident index map holds no entry for a gone segment, so
        // RAM is bounded to the working set, not a permanent dense vector per cold sealed segment.
        let mut log = open_mem(small_config());
        for i in 0..20u8 {
            log.append(&rec(&[i; 16])).unwrap();
        }
        log.sync().unwrap();
        // Touch every segment so each gets a resident index built.
        let flushed = log.flushed_offset().get();
        for s in 0..flushed {
            let _ = log.read_from(Offset::new(s), 1).unwrap();
        }
        let segs_before = log.segments.len();
        assert_eq!(
            log.segment_index_count(),
            segs_before,
            "one resident index per open segment after reads"
        );
        // Reap as much as retention allows (everything consumed), then assert the index count fell to
        // exactly the surviving segment count — no orphaned entries for reaped ids.
        let protect = log.flushed_offset().get();
        log.reap(
            RetentionBounds {
                max_bytes: 1,
                ..RetentionBounds::default()
            },
            protect,
        )
        .unwrap();
        assert!(log.segments.len() < segs_before, "some segments reaped");
        assert_eq!(
            log.segment_index_count(),
            log.segments.len(),
            "no stale index entry survives a reap"
        );
    }

    /// #537 BOUNDED MEMORY: a single segment packed with MANY small records has a resident SPARSE
    /// index whose anchor count is `O(region_bytes / stride)` — far below one-per-record — so the
    /// per-segment index RAM does not scale with the record count. This is the property that keeps a
    /// slow/replaying consumer's resident footprint inside the tiny-profile RAM budget; a dense index
    /// would hold one entry per record here.
    #[test]
    fn the_sparse_index_holds_far_fewer_anchors_than_records() {
        // One big segment (no rolling) packed with many tiny records, so the dense count is large.
        let mut log = open_mem(LogConfig::new(8 * 1024 * 1024).unwrap());
        let n: u64 = 4000;
        for i in 0..n {
            log.append(&rec(&[u8::try_from(i % 256).unwrap(); 4]))
                .unwrap();
        }
        log.sync().unwrap();
        assert_eq!(log.segment_count(), 1, "all records in one segment");
        // A read builds/extends the resident index; read everything so it is fully populated.
        let all = log.read_from(Offset::ZERO, usize::MAX).unwrap();
        assert_eq!(all.len() as u64, n, "all records read back");
        // The 4 KiB-stride anchor count is bounded by region_bytes / stride. A 4-byte-payload frame
        // is 48 bytes, so n records ≈ 192 KiB of frames ≈ ~48 anchors at a 4 KiB stride — far below
        // the n records a dense index would hold.
        let anchors = log
            .segment_indexes
            .borrow()
            .get(&log.active_segment_id())
            .map(|idx| idx.anchors.len())
            .unwrap();
        let frame_bytes = log.durable_record_bytes();
        let bound = (frame_bytes / SEGMENT_INDEX_STRIDE_BYTES) as usize + 2;
        assert!(
            anchors <= bound,
            "anchors {anchors} exceed the stride bound {bound}"
        );
        assert!(
            (anchors as u64) * 8 < n,
            "the sparse index ({anchors} anchors) is far smaller than a dense one ({n} records)"
        );
    }

    /// #537 LOCATE CORRECTNESS through a BUILT (not append-seeded) sparse index: a reopen rebuilds
    /// the index from the durable frames, and a read of EVERY offset in a many-record segment returns
    /// exactly the record at that offset — proving the anchor-then-bounded-forward-scan locates the
    /// right byte range across the sparse gaps.
    #[test]
    fn the_built_sparse_index_locates_every_offset_in_a_packed_segment() {
        let mut log = open_mem(LogConfig::new(8 * 1024 * 1024).unwrap());
        let n: u64 = 500;
        for i in 0..n {
            log.append(&rec(&[u8::try_from(i % 256).unwrap(); 7]))
                .unwrap();
        }
        log.sync().unwrap();
        // Reopen so the index is BUILT from disk (the sparse walk), not the append-seeded one.
        let fs = log.into_filesystem();
        let log = Log::open(
            fs,
            ManualClock::new(),
            LogConfig::new(8 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        for start in 0..n {
            let got = log.read_from(Offset::new(start), 3).unwrap();
            let want_len = 3.min(usize::try_from(n - start).unwrap());
            assert_eq!(got.len(), want_len, "count at start={start}");
            for (k, r) in got.iter().enumerate() {
                assert_eq!(
                    r.offset,
                    Offset::new(start + k as u64),
                    "offset at start={start} k={k}"
                );
                assert_eq!(
                    r.payload.as_ref(),
                    &[u8::try_from((start + k as u64) % 256).unwrap(); 7],
                    "payload at start={start} k={k}"
                );
            }
        }
    }

    #[test]
    fn read_after_reopen_returns_all_durable_records() {
        let mut log = open_mem(small_config());
        for i in 0..9u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        log.sync().unwrap();
        let fs = log.into_filesystem();

        let log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(log.flushed_offset(), Offset::new(9));
        let records = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(records.len(), 9);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.offset, Offset::new(i as u64));
        }
    }

    #[test]
    fn read_before_the_oldest_offset_is_out_of_range() {
        // A single segment whose first record is at offset 5 (as if earlier segments had
        // been reaped); reading from 0 must report the offset as out of range.
        let fs = InMemoryFs::new();
        let f0 = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w0 = SegmentWriter::create(f0, header_at(0, 5)).unwrap();
        w0.append(&view(5, b"a")).unwrap();
        w0.sync().unwrap();
        drop(w0);

        let log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        let err = log.read_from(Offset::ZERO, 10).unwrap_err();
        assert!(matches!(
            err,
            StorageError::OffsetOutOfRange {
                requested: 0,
                oldest: 5
            }
        ));
    }

    #[test]
    fn a_roll_makes_records_readable_without_an_explicit_sync() {
        // A roll seals (fsyncs) the old segment, so its records become durable and
        // readable even though the caller never called sync.
        let mut log = open_mem(small_config());
        for i in 0..8u8 {
            log.append(&rec(&[i; 20])).unwrap(); // no sync anywhere
        }
        assert!(log.active_segment_id() >= 1, "should have rolled");
        let flushed = log.flushed_offset().get();
        assert!(flushed > 0, "the roll advanced the flush mark");
        assert!(
            flushed < 8,
            "records appended after the roll are not yet synced"
        );
        let records = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(records.len() as u64, flushed);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.offset, Offset::new(i as u64));
        }
    }

    #[test]
    fn read_skips_an_unsynced_tail_in_the_active_segment() {
        let mut log = open_mem(LogConfig::default());
        log.append(&rec(b"a")).unwrap();
        log.append(&rec(b"b")).unwrap();
        log.sync().unwrap();
        log.append(&rec(b"c")).unwrap(); // synced...
                                         // ...not yet: only a and b are durable.
        let records = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].payload.as_ref(), b"b");
    }

    #[test]
    fn reads_serve_the_durable_prefix_from_a_frozen_writer() {
        use crate::fault::FaultFs;
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        let mut durable = 0u64;
        while !log.active_segment_at_or_over_cap().unwrap() {
            log.append(&rec(&[7u8; 20])).unwrap();
            log.sync().unwrap();
            durable += 1;
        }
        // Freeze the writer with a durability-barrier fault at the roll (the new segment's dir fsync).
        control.set_fail_sync_dir(true);
        assert!(matches!(
            log.append(&rec(b"x")),
            Err(StorageError::WriterFrozen)
        ));
        // Reads ignore the writer and still serve the flushed prefix.
        let records = log.read_from(Offset::ZERO, 100).unwrap();
        assert!(!records.is_empty());
        assert_eq!(records.len() as u64, durable);
        assert_eq!(records.len() as u64, log.flushed_offset().get());
    }

    #[test]
    fn a_spill_flush_io_error_mid_append_does_not_corrupt_offsets_or_lose_acked_data() {
        use crate::fault::FaultFs;
        // #859 regression: a write error on the 256 KiB spill flush mid-append must NOT leave the writer
        // TORN (write_pos advanced, record_count not bumped) - which would reuse this offset/seq on the
        // next append and, when a later flush succeeds, write both frames under one count, corrupting the
        // log and silently losing the acked record. A single > 256 KiB record makes its own pending
        // buffer cross the spill cap, so its in-append flush fires; armed with a write fault it fails.
        // After clearing the fault the next record must take the SAME offset (the failed one consumed
        // none and left no torn frame), and the dense log must survive a reopen.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let probe = fs.inner().clone();
        {
            let mut log = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
            // Three durable records (offsets 0..=2, fsync clean).
            for i in 0..3u64 {
                assert_eq!(log.append(&rec(b"durable")).unwrap(), Offset::new(i));
            }
            log.sync().unwrap();
            assert_eq!(log.flushed_offset(), Offset::new(3));

            // A single record larger than the 256 KiB spill cap: its in-append flush fails under the
            // armed write fault, so the append errors. Pre-fix this left the writer torn at offset 3.
            let big = vec![b'x'; 300 * 1024];
            control.set_fail_write(true);
            assert!(
                log.append(&rec(&big)).is_err(),
                "the > 256 KiB record's spill flush fails under the armed write fault"
            );

            // Clear the fault and append the next record: with the roll-back fix it takes offset 3 (the
            // failed append consumed NO offset and left no torn frame), not a skipped or reused one.
            control.set_fail_write(false);
            let after = log.append(&rec(b"survivor")).unwrap();
            assert_eq!(
                after,
                Offset::new(3),
                "after a rolled-back spill failure the next append reuses no offset and skips none"
            );
            log.sync().unwrap();

            // Dense and no-duplicate in the live log.
            let recs = log.read_from(Offset::ZERO, 1000).unwrap();
            assert_eq!(
                recs.len(),
                4,
                "record_count matches the frames on disk: no duplicate or skipped offset"
            );
            assert_eq!(&recs.last().unwrap().payload[..], &b"survivor"[..]);
        }

        // Reopen over the surviving disk: the post-fault record is durable and recovery finds a
        // consistent, dense log (the torn-writer bug would have made dense-seq recovery truncate it).
        let reopened = Log::open(probe, ManualClock::new(), LogConfig::default()).unwrap();
        let recs = reopened.read_from(Offset::ZERO, 1000).unwrap();
        assert_eq!(
            recs.len(),
            4,
            "the dense log (incl. the post-fault record) survives reopen"
        );
        assert_eq!(
            &recs.last().unwrap().payload[..],
            &b"survivor"[..],
            "the post-fault record survives a reopen"
        );
    }

    #[test]
    fn a_partial_spill_flush_write_mid_append_still_recovers_a_dense_consistent_log() {
        use crate::fault::FaultFs;
        // #859, the partial-write case: the clean-fail variant above proves the IN-MEMORY roll back; a
        // real `write_all_at` can persist a PREFIX of the spill buffer and THEN error, leaving garbage
        // on disk past the durable head. This asserts the fix is sound there too: after the roll back the
        // next successful flush rewrites from the unchanged `pending_base`, overwriting the partial bytes,
        // so the reopened log is dense and consistent with no torn-frame corruption and no lost ack.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let probe = fs.inner().clone();
        // A large survivor (4 KiB) whose frame dwarfs the 64-byte torn prefix, so its flush fully
        // overwrites the persisted partial bytes - the recovered log carries no leftover garbage.
        let survivor = vec![0xABu8; 4096];
        {
            let mut log = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
            for i in 0..3u64 {
                assert_eq!(log.append(&rec(b"durable")).unwrap(), Offset::new(i));
            }
            log.sync().unwrap();

            // The > 256 KiB record's spill flush persists 64 bytes then errors (a torn write).
            let big = vec![b'x'; 300 * 1024];
            control.arm_torn_write(64);
            assert!(
                log.append(&rec(&big)).is_err(),
                "the > 256 KiB record's spill flush tears (persists a prefix, then errors)"
            );

            // The roll back restored the writer; the survivor takes offset 3 and its flush overwrites the
            // 64 torn bytes at the unchanged pending_base.
            let after = log.append(&rec(&survivor)).unwrap();
            assert_eq!(
                after,
                Offset::new(3),
                "no offset reuse or skip after a torn spill flush"
            );
            log.sync().unwrap();

            let recs = log.read_from(Offset::ZERO, 1000).unwrap();
            assert_eq!(
                recs.len(),
                4,
                "dense, no duplicate frame from the torn write"
            );
            assert_eq!(&recs.last().unwrap().payload[..], &survivor[..]);
        }

        // Reopen over the disk that carried the partial bytes: recovery yields exactly the dense log, the
        // big record's torn prefix never resurfaces as a record, and the acked survivor is durable.
        let reopened = Log::open(probe, ManualClock::new(), LogConfig::default()).unwrap();
        let recs = reopened.read_from(Offset::ZERO, 1000).unwrap();
        assert_eq!(
            recs.len(),
            4,
            "the dense log survives reopen after a partial spill-flush write"
        );
        assert_eq!(
            &recs.last().unwrap().payload[..],
            &survivor[..],
            "the post-fault record survives a reopen even when the failed flush left partial bytes"
        );
        assert!(
            recs.iter().all(|r| r.payload.len() != 300 * 1024),
            "the torn big record (the only 300 KiB payload) never becomes a readable record"
        );
    }

    #[test]
    fn a_fatal_fsync_freezes_the_writer_and_reads_keep_serving_the_flushed_prefix() {
        use crate::fault::FaultFs;
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
        // One durable record (its sync succeeds).
        log.append(&rec(b"durable")).unwrap();
        log.sync().unwrap();
        assert!(log.is_writable());
        let flushed = log.flushed_offset();
        assert_eq!(flushed, Offset::new(1));

        // Append another, then arm a fatal fsync: the freezing sync surfaces the fatal
        // WriterFrozen (not a soft IO error), so the in-flight produce ends its session.
        log.append(&rec(b"unsynced")).unwrap();
        control.set_fail_sync(true);
        assert!(
            matches!(log.sync(), Err(StorageError::WriterFrozen)),
            "the freezing fsync surfaces the fatal WriterFrozen, not a soft IO error"
        );

        // The writer is now frozen: it refuses every further write and is not writable, so a
        // health check (is_writable) sees the degraded state.
        assert!(!log.is_writable(), "a fatal fsync freezes the writer");
        assert!(matches!(
            log.append(&rec(b"x")),
            Err(StorageError::WriterFrozen)
        ));
        assert!(matches!(log.sync(), Err(StorageError::WriterFrozen)));

        // The in-process flush mark is unchanged (the unsynced record was never flushed), so
        // an in-process reader keeps serving exactly the acked prefix. This is the live-handle
        // property; durability across a restart is covered by the recovery tests.
        assert_eq!(log.flushed_offset(), flushed);
        let records = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(records.len() as u64, flushed.get());
    }

    #[test]
    fn a_fatal_fsync_during_a_roll_freezes_the_writer() {
        use crate::fault::FaultFs;
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        // Arm the sync failure, then append (never calling sync) until the active segment
        // fills and the next append must roll. The roll seals the old segment, whose fsync
        // now faults, freezing the writer from inside the roll path (not an explicit sync).
        control.set_fail_sync(true);
        let mut froze = false;
        for i in 0..30u8 {
            match log.append(&rec(&[i; 20])) {
                Ok(_) => {}
                Err(StorageError::WriterFrozen) => {
                    froze = true;
                    break;
                }
                Err(other) => panic!("a freezing roll must be fatal, got {other:?}"),
            }
        }
        assert!(froze, "a roll's seal fsync should have frozen the writer");
        // Frozen: not writable, and every further write and sync is the fatal WriterFrozen.
        assert!(!log.is_writable());
        assert!(matches!(
            log.append(&rec(b"x")),
            Err(StorageError::WriterFrozen)
        ));
        assert!(matches!(log.sync(), Err(StorageError::WriterFrozen)));
        // The only fsync attempt was the roll's, and it faulted, so nothing became durable:
        // the flush mark is unchanged at the start.
        assert_eq!(log.flushed_offset(), Offset::ZERO);
    }

    // --- The pipelined-sync-tier staging API (#1040): prepare/complete/freeze ---

    #[test]
    fn prepare_async_sync_on_a_frozen_writer_is_an_error_never_a_clean_none() {
        use crate::fault::FaultFs;
        // Freeze the writer through a REAL failed barrier (the exact state a dead disk leaves).
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
        log.append(&rec(b"unsynced")).unwrap();
        control.set_fail_sync(true);
        assert!(matches!(log.sync(), Err(StorageError::WriterFrozen)));
        assert!(!log.is_writable());
        // The L1 conflation this API kills: a frozen writer also reports
        // `has_unsynced_records() == false`, so a clean-check-first implementation would return
        // `Ok(None)` here and the caller would treat a dead writer as a clean log — its parked
        // producers would never be fataled. Frozen MUST be a DISTINCT error outcome.
        assert!(!log.has_unsynced_records());
        assert!(
            matches!(log.prepare_async_sync(), Err(StorageError::WriterFrozen)),
            "a frozen writer must be Err, never a clean Ok(None)"
        );
        // The external-failure freeze reaches the same terminal state and stays an error too.
        log.freeze_after_external_sync_failure();
        assert!(matches!(
            log.prepare_async_sync(),
            Err(StorageError::WriterFrozen)
        ));
    }

    #[test]
    fn prepare_async_sync_on_a_clean_log_is_none() {
        let mut log = open_mem(LogConfig::default());
        // A fresh, never-appended log owes no barrier.
        assert!(log.prepare_async_sync().unwrap().is_none());
        // A fully-synced log owes no barrier either (clean, NOT frozen: the writer is live).
        log.append(&rec(b"payload")).unwrap();
        log.sync().unwrap();
        assert!(log.is_writable());
        assert!(log.prepare_async_sync().unwrap().is_none());
        // And a dirtied log owes exactly one: the three outcomes are distinct.
        log.append(&rec(b"more")).unwrap();
        assert!(log.prepare_async_sync().unwrap().is_some());
    }

    #[test]
    fn stage_then_complete_advances_both_heads_to_the_target_and_publishes_the_frontier() {
        let mut log = open_mem(LogConfig::default());
        // Build the off-actor read plane FIRST so the completion's frontier publish is observable.
        let plane = log.read_plane().unwrap();
        log.append(&rec(b"aaaa")).unwrap();
        log.append(&rec(b"bbbb")).unwrap();
        let meter_before = log.unsynced_bytes();
        assert_eq!(meter_before, 8, "two 4-byte payloads are at risk");

        let (file, ticket) = log.prepare_async_sync().unwrap().unwrap();
        // Staging touches NEITHER head (contrast `flush_no_sync`): nothing is visible or durable
        // until the external barrier RETURNS, and the byte meter still carries the exposure.
        assert_eq!(log.flushed_offset(), Offset::ZERO);
        assert_eq!(log.synced_offset(), Offset::ZERO);
        assert_eq!(log.unsynced_bytes(), meter_before);
        assert!(log.has_unsynced_records());
        assert_eq!(plane.flushed(), 0, "no frontier before the barrier returns");
        assert!(log.read_from(Offset::ZERO, 10).unwrap().is_empty());

        // The external covering barrier (what the flusher thread does), then the completion.
        file.sync_data().unwrap();
        log.complete_async_sync(&ticket);

        // Both heads advance EXACTLY to the snapshotted target, the meter retires the covered
        // bytes, the frontier is published, and the records are readable.
        assert_eq!(log.flushed_offset(), Offset::new(2));
        assert_eq!(log.synced_offset(), Offset::new(2));
        assert_eq!(log.unsynced_bytes(), 0);
        assert!(!log.has_unsynced_records());
        assert_eq!(
            plane.flushed(),
            2,
            "completion publishes the flushed frontier"
        );
        assert_eq!(log.read_from(Offset::ZERO, 10).unwrap().len(), 2);
        // Nothing further owed: the next prepare is a clean None.
        assert!(log.prepare_async_sync().unwrap().is_none());
    }

    #[test]
    fn the_byte_meter_stays_exact_across_overlapping_stage_complete_cycles() {
        let mut log = open_mem(LogConfig::default());
        // Cycle 1 stages record A (7 logical bytes)...
        log.append(&rec(b"aaaaaaa")).unwrap();
        assert_eq!(log.unsynced_bytes(), 7);
        let (_file1, t1) = log.prepare_async_sync().unwrap().unwrap();
        // ...record B (11 bytes) lands DURING the flight: the meter keeps accumulating and B is
        // outside t1's snapshot (dirty-at-sync-start).
        log.append(&rec(b"bbbbbbbbbbb")).unwrap();
        assert_eq!(log.unsynced_bytes(), 18);
        log.complete_async_sync(&t1);
        // t1 retires EXACTLY its own 7 covered bytes: B's 11 stay at risk until ITS barrier.
        assert_eq!(log.unsynced_bytes(), 11);
        assert_eq!(log.synced_offset(), Offset::new(1));
        assert_eq!(log.flushed_offset(), Offset::new(1));
        assert!(log.has_unsynced_records(), "B is still unsynced");
        // Cycle 2 covers B; after its completion the meter is exactly zero — no drift in either
        // direction across the overlapped cycles.
        let (_file2, t2) = log.prepare_async_sync().unwrap().unwrap();
        log.complete_async_sync(&t2);
        assert_eq!(log.unsynced_bytes(), 0);
        assert_eq!(log.synced_offset(), Offset::new(2));
        assert!(!log.has_unsynced_records());
    }

    #[test]
    fn a_stale_completion_after_an_intervening_inline_sync_is_a_full_no_op() {
        let mut log = open_mem(LogConfig::default());
        log.append(&rec(b"aaaa")).unwrap();
        let (_file, stale) = log.prepare_async_sync().unwrap().unwrap();
        // An INLINE barrier (a Run job's `commit_batch`, a quiesce) overtakes the flight: it
        // covers everything, including a record appended after the stage.
        log.append(&rec(b"bbbb")).unwrap();
        log.sync().unwrap();
        assert_eq!(log.synced_offset(), Offset::new(2));
        assert_eq!(log.unsynced_bytes(), 0);
        // The late completion is a FULL no-op — applying it would REWIND the durable head to the
        // stale target and rewind is exactly what the all-or-nothing guard forbids.
        log.complete_async_sync(&stale);
        assert_eq!(log.synced_offset(), Offset::new(2), "no rewind");
        assert_eq!(log.flushed_offset(), Offset::new(2));
        assert_eq!(log.unsynced_bytes(), 0);
    }

    #[test]
    fn a_stale_completion_after_an_intervening_roll_is_a_full_no_op_including_the_byte_meter() {
        // The L2 regression: a mid-flight roll's seal is itself a covering barrier that advances
        // the heads and ZEROES the meter; the stale completion must then touch NOTHING — a
        // half-applied ticket subtracting its covered bytes on top would UNDERCOUNT the new
        // segment's live exposure forever.
        let mut log = open_mem(small_config());
        log.append(&rec(b"first")).unwrap();
        let (file, stale) = log.prepare_async_sync().unwrap().unwrap();
        // Force rolls while the barrier is "in flight": the 128-byte cap rolls within a few
        // 20-byte records, and each roll's seal advances both heads past the stale target.
        for i in 0..10u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        assert!(
            log.synced_offset() > Offset::new(1),
            "a roll's seal advanced the durable head past the stale target"
        );
        let synced_after_rolls = log.synced_offset();
        let flushed_after_rolls = log.flushed_offset();
        let meter_after_rolls = log.unsynced_bytes();
        assert!(
            meter_after_rolls > 0,
            "the new active segment carries live unsynced exposure the stale ticket must not touch"
        );
        let index_flushed_end = log
            .segment_indexes
            .borrow()
            .get(&log.active_id)
            .unwrap()
            .flushed_end;
        // The stray fdatasync on the SEALED old fd is harmless (the Arc kept it alive)...
        file.sync_data().unwrap();
        // ...and its completion is a FULL no-op: heads, byte meter, and index all untouched.
        log.complete_async_sync(&stale);
        assert_eq!(log.synced_offset(), synced_after_rolls);
        assert_eq!(log.flushed_offset(), flushed_after_rolls);
        assert_eq!(
            log.unsynced_bytes(),
            meter_after_rolls,
            "the meter must keep the NEW segment's exposure intact (no stale subtract)"
        );
        assert_eq!(
            log.segment_indexes
                .borrow()
                .get(&log.active_id)
                .unwrap()
                .flushed_end,
            index_flushed_end,
            "the new active index's flushed bound is untouched by the stale completion"
        );
        // The log is fully live afterwards: appends and real barriers keep working.
        log.append(&rec(b"after")).unwrap();
        log.sync().unwrap();
        assert_eq!(log.unsynced_bytes(), 0);
    }

    #[test]
    fn a_spill_during_the_flight_never_raises_flushed_end_past_the_staged_snapshot() {
        // The #1040 prep-review mutation gap: a record appended DURING a flight that crosses the
        // writer's 256 KiB spill bound flushes its bytes into the FILE (raising the resident
        // index's `valid_end`) while still un-fsynced. The late completion must raise the index's
        // flushed read bound to the ticket's SNAPSHOTTED `staged_valid_end` — never the current
        // `valid_end`, whose spilled tail the returned barrier did NOT cover. A mutant that reads
        // the live `valid_end` at completion instead of the snapshot fails here.
        let mut log = open_mem(LogConfig::default());
        log.append(&rec(b"covered")).unwrap();
        let (file, ticket) = log.prepare_async_sync().unwrap().unwrap();
        let staged_end = log
            .segment_indexes
            .borrow()
            .get(&log.active_id)
            .unwrap()
            .valid_end;
        // The in-flight append: bigger than the spill bound, so its frame lands IN THE FILE now.
        let spill_payload = vec![0x7a_u8; 300 * 1024];
        log.append(&rec(&spill_payload)).unwrap();
        let valid_end_after_spill = log
            .segment_indexes
            .borrow()
            .get(&log.active_id)
            .unwrap()
            .valid_end;
        assert!(
            valid_end_after_spill > staged_end,
            "the spilled frame extended the appended prefix during the flight"
        );
        // The external barrier returns; the completion applies the SNAPSHOT, not the live end.
        file.sync_data().unwrap();
        log.complete_async_sync(&ticket);
        let idx_flushed_end = log
            .segment_indexes
            .borrow()
            .get(&log.active_id)
            .unwrap()
            .flushed_end;
        assert_eq!(
            idx_flushed_end, staged_end,
            "flushed_end raises to the ticket's dirty-at-sync-start snapshot ONLY (#537, INV-5)"
        );
        assert!(
            idx_flushed_end < valid_end_after_spill,
            "the spilled-but-unsynced tail stays outside the flushed read bound"
        );
        // Heads track the ticket target exactly: the spilled record is still unsynced.
        assert_eq!(log.synced_offset(), Offset::new(1));
        assert!(log.has_unsynced_records());
        // Its own barrier then covers the spilled tail and raises the bound to the full prefix.
        let (file2, t2) = log.prepare_async_sync().unwrap().unwrap();
        file2.sync_data().unwrap();
        log.complete_async_sync(&t2);
        assert_eq!(log.synced_offset(), Offset::new(2));
        assert_eq!(
            log.segment_indexes
                .borrow()
                .get(&log.active_id)
                .unwrap()
                .flushed_end,
            valid_end_after_spill,
            "the second completion raises the bound to the spilled frame's end"
        );
        assert_eq!(log.unsynced_bytes(), 0);
    }

    #[test]
    fn a_completion_on_a_frozen_writer_is_a_full_no_op() {
        let mut log = open_mem(LogConfig::default());
        log.append(&rec(b"payload")).unwrap();
        let (_file, ticket) = log.prepare_async_sync().unwrap().unwrap();
        let meter_before = log.unsynced_bytes();
        // The barrier FAILED on the flusher: the caller freezes the writer, then (in a race) the
        // completion for an earlier Ok could still arrive — it must be a full no-op, because no
        // ack may ever be released past a failed barrier and a frozen writer's heads are final.
        log.freeze_after_external_sync_failure();
        assert!(!log.is_writable());
        log.complete_async_sync(&ticket);
        assert_eq!(log.synced_offset(), Offset::ZERO);
        assert_eq!(log.flushed_offset(), Offset::ZERO);
        assert_eq!(log.unsynced_bytes(), meter_before);
        // And the pipeline can never re-arm against the frozen writer.
        assert!(matches!(
            log.prepare_async_sync(),
            Err(StorageError::WriterFrozen)
        ));
    }

    #[test]
    fn a_ticket_with_a_mismatched_segment_id_skips_the_index_raise() {
        // The release-mode defensive arm of the completion's index raise: a ticket staged against
        // a DIFFERENT segment id must never touch the current active segment's resident index
        // (the heads/meter half still applies under the guard — this pins ONLY the index skip).
        let mut log = open_mem(LogConfig::default());
        log.append(&rec(b"aaaa")).unwrap();
        log.append(&rec(b"bbbb")).unwrap();
        let (_file, ticket) = log.prepare_async_sync().unwrap().unwrap();
        let mut mismatched = ticket;
        mismatched.segment_id = ticket.segment_id + 1;
        let index_flushed_end_before = log
            .segment_indexes
            .borrow()
            .get(&log.active_id)
            .unwrap()
            .flushed_end;
        log.complete_async_sync(&mismatched);
        // Heads and meter applied (the ticket is not stale)...
        assert_eq!(log.synced_offset(), Offset::new(2));
        assert_eq!(log.unsynced_bytes(), 0);
        // ...but the active index's flushed bound was NOT raised by a foreign-segment ticket.
        assert_eq!(
            log.segment_indexes
                .borrow()
                .get(&log.active_id)
                .unwrap()
                .flushed_end,
            index_flushed_end_before
        );
    }

    #[test]
    fn a_shared_file_handle_held_across_rolls_and_a_freeze_stays_harmless() {
        // The Arc'd-writer property the flusher relies on (#1040): a staged handle that outlives
        // the segment it was staged against (rolled away mid-flight) still accepts a barrier
        // call, never resurrects the writer, and never disturbs the successor segment.
        let mut log = open_mem(small_config());
        log.append(&rec(b"first")).unwrap();
        let (file, _ticket) = log.prepare_async_sync().unwrap().unwrap();
        for i in 0..10u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        // The clone still points at the (long-sealed) old fd: a stray barrier is a no-op Ok.
        file.sync_data().unwrap();
        // The log keeps operating normally on the successor segments.
        log.append(&rec(b"tail")).unwrap();
        log.sync().unwrap();
        assert!(log.is_writable());
        assert_eq!(log.unsynced_bytes(), 0);
        let total = log.read_from(Offset::ZERO, 100).unwrap().len();
        assert_eq!(total, 12);
    }

    #[test]
    fn read_three_segments_crossing_two_boundaries() {
        let mut log = open_mem(small_config());
        let n: usize = 20;
        for i in 0..n {
            log.append(&rec(&[u8::try_from(i).unwrap(); 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 2, "three or more segments");
        let all = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(all.len(), n);
        // A read starting in an early segment and spanning into a later one.
        let mid = log.read_from(Offset::new(3), 12).unwrap();
        assert_eq!(mid.len(), 12);
        assert_eq!(mid[0].offset, Offset::new(3));
        assert_eq!(mid[11].offset, Offset::new(14));
    }

    #[test]
    fn recovery_reports_the_truncated_tail_bytes() {
        let mut log = open_mem(LogConfig::default());
        for i in 0..4u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap();
        let fs = log.into_filesystem();

        // A clean reopen reports zero loss.
        let clean = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
        assert_eq!(clean.recovered_truncated_bytes(), 0);
        assert!(
            clean.loss_report().is_empty(),
            "a clean recovery reports no loss"
        );
        assert_eq!(clean.flushed_offset(), Offset::new(4));
        let fs = clean.into_filesystem();

        // Tear three bytes off the last record: recovery drops the partial tail and reports
        // exactly the number of bytes it discarded (the pre-recovery length minus the
        // post-recovery length).
        let file = fs.open(&segment_file_name(0)).unwrap();
        let torn_len = file.len().unwrap() - 3;
        file.set_len(torn_len).unwrap();
        file.sync_data().unwrap();
        let torn = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
        assert_eq!(
            torn.flushed_offset(),
            Offset::new(3),
            "the torn record is dropped"
        );
        let post_len = torn
            .filesystem()
            .open(&segment_file_name(0))
            .unwrap()
            .len()
            .unwrap();
        assert!(torn.recovered_truncated_bytes() > 0);
        assert_eq!(torn.recovered_truncated_bytes(), torn_len - post_len);

        // The same loss is also reported structurally (#120): one torn-tail event in segment
        // 0 whose byte span is exactly the dropped region and whose bytes agree with the raw
        // counter.
        let report = torn.loss_report();
        assert!(!report.is_empty());
        assert_eq!(report.events.len(), 1);
        let e = report.events[0];
        assert_eq!(e.reason_code, crate::loss::ReasonCode::TornTail);
        assert_eq!(e.segment_id, 0);
        assert_eq!(e.byte_offset_start, post_len);
        assert_eq!(e.byte_offset_end, torn_len);
        assert_eq!(e.bytes_skipped, torn.recovered_truncated_bytes());
        assert_eq!(
            report.total_bytes_skipped(),
            torn.recovered_truncated_bytes()
        );
        assert!(e.records_lost_estimate >= 1);
    }

    #[test]
    fn recovery_reports_a_corrupt_body_in_the_loss_report() {
        let mut log = open_mem(LogConfig::default());
        for i in 0..4u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap();
        let fs = log.into_filesystem();

        // Flip the last byte of the segment (inside the last record's frame) so its body CRC
        // fails. The length is unchanged, so this is a corrupt body, not a torn tail.
        let file = fs.open(&segment_file_name(0)).unwrap();
        let mut bytes = file.snapshot();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();

        let recovered = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
        // The corrupt last record is dropped; the three intact records survive.
        assert_eq!(recovered.flushed_offset(), Offset::new(3));
        let report = recovered.loss_report();
        assert_eq!(report.events.len(), 1, "one corrupt-tail event");
        assert_eq!(
            report.events[0].reason_code,
            crate::loss::ReasonCode::CorruptRecordBody
        );
        assert_eq!(report.events[0].segment_id, 0);
        assert_eq!(
            report.events[0].bytes_skipped,
            recovered.recovered_truncated_bytes()
        );
    }

    #[test]
    fn recovery_fails_closed_when_loss_exceeds_the_per_event_cap() {
        // A single torn span larger than the per-event cap (here one segment, 4096) must fail
        // recovery closed, not be accepted as silent loss (#120, I3).
        let config = LogConfig {
            max_segment_bytes: 4096,
            max_total_bytes: 0,
            ..LogConfig::default()
        };
        let mut log = open_mem(config);
        for i in 0..3u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap();
        let active = log.active_segment_id();
        let fs = log.into_filesystem();

        // Append a 5000-byte run of 0xff past the durable tail: a corrupt tail bigger than the
        // 4096 per-event cap. (0xffff is not the record magic, so it is a corrupt header.)
        let file = fs.open(&segment_file_name(active)).unwrap();
        let len = file.len().unwrap();
        file.write_all_at(&[0xffu8; 5000], len).unwrap();
        file.sync_data().unwrap();

        let err = Log::open(fs, ManualClock::new(), config).unwrap_err();
        assert!(
            matches!(
                err,
                StorageError::ExcessiveRecoveryLoss(crate::loss::CapViolation::PerEvent {
                    cap: 4096,
                    ..
                })
            ),
            "expected a per-event cap violation, got {err:?}"
        );
    }

    #[test]
    fn a_normal_small_log_torn_tail_recovers_despite_exceeding_one_percent() {
        // The small-log-safe floor: a tiny log (4 records, a few dozen durable bytes) whose
        // torn tail is far more than 1% of its durable bytes still recovers, because the global
        // cap is floored at the per-event cap. Without the floor, the literal 1% would freeze
        // this normal recovery.
        let mut log = open_mem(LogConfig::default());
        for i in 0..4u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap();
        let fs = log.into_filesystem();
        let file = fs.open(&segment_file_name(0)).unwrap();
        let len = file.len().unwrap();
        file.set_len(len - 3).unwrap();
        file.sync_data().unwrap();

        // Recovery SUCCEEDS (does not freeze) and reports the loss. The durable record region
        // here is only a few dozen bytes, so its 1% is under a single byte and the three torn
        // bytes exceed it; without the per-event-cap floor on the global cap this recovery
        // would have failed closed.
        let recovered = Log::open(fs, ManualClock::new(), LogConfig::default()).unwrap();
        assert_eq!(recovered.flushed_offset(), Offset::new(3));
        assert!(recovered.recovered_truncated_bytes() > 0);
        assert_eq!(recovered.loss_report().events.len(), 1);
    }

    #[test]
    fn read_exactly_at_the_flushed_minus_one_offset() {
        let mut log = open_mem(LogConfig::default());
        for i in 0..3u8 {
            log.append(&rec(&[i; 4])).unwrap();
        }
        log.sync().unwrap();
        assert_eq!(log.flushed_offset(), Offset::new(3));
        let records = log.read_from(Offset::new(2), 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].offset, Offset::new(2));
    }

    #[cfg(unix)]
    #[test]
    fn stdfs_read_across_segments() {
        use crate::fs::StdFs;
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(
            StdFs::new(dir.path().to_path_buf()),
            ManualClock::new(),
            small_config(),
        )
        .unwrap();
        let n: usize = 10;
        for i in 0..n {
            log.append(&rec(&[u8::try_from(i).unwrap(); 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 1);
        let records = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(records.len(), n);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.offset, Offset::new(i as u64));
        }
    }

    #[cfg(unix)]
    #[test]
    fn rolling_and_recovery_on_a_real_directory() {
        use crate::fs::StdFs;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let mut log =
            Log::open(StdFs::new(root.clone()), ManualClock::new(), small_config()).unwrap();
        for i in 0..8u8 {
            log.append(&rec(&[i; 20])).unwrap();
            log.sync().unwrap();
        }
        let rolled_id = log.active_segment_id();
        assert!(rolled_id >= 1);
        drop(log);

        let mut log =
            Log::open(StdFs::new(root.clone()), ManualClock::new(), small_config()).unwrap();
        assert_eq!(log.active_segment_id(), rolled_id);
        assert_eq!(log.next_offset(), Offset::new(8));
        assert_eq!(log.append(&rec(b"more")).unwrap(), Offset::new(8));
        log.sync().unwrap();

        // Count across every segment that exists (the final append may have rolled
        // again, since the recovered active segment was already past the cap).
        let fs = StdFs::new(root.clone());
        let total: usize = segment_ids(&fs)
            .unwrap()
            .iter()
            .map(|id| read_back(&fs, *id).len())
            .sum();
        assert_eq!(total, 9);
    }

    #[cfg(unix)]
    #[test]
    fn stdfs_preallocation_extends_the_active_segment_and_recovery_is_silent() {
        // The PRODUCTION path end to end: `StdFile::preallocate` reserves blocks and advances the
        // active segment's LOGICAL length to the roll size (so the per-commit fdatasync is a pure
        // data flush), a kill + reopen recovers the records and truncates the unwritten zero tail
        // SILENTLY (no loss event, nothing quarantined), and the log keeps working.
        use crate::fs::StdFs;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let cfg = LogConfig {
            max_segment_bytes: 64 * 1024,
            ..LogConfig::default()
        };
        let mut log = Log::open(StdFs::new(root.clone()), ManualClock::new(), cfg).unwrap();
        log.append(&rec(b"one")).unwrap();
        log.append(&rec(b"two")).unwrap();
        log.sync().unwrap();
        let seg0_len = StdFs::new(root.clone())
            .open(&segment_file_name(0))
            .unwrap()
            .len()
            .unwrap();
        assert_eq!(
            seg0_len, cfg.max_segment_bytes,
            "the active segment is logically extended to the roll size"
        );
        // A kill + reopen: the crash shape every preallocated broker leaves behind.
        drop(log);
        let mut log = Log::open(StdFs::new(root.clone()), ManualClock::new(), cfg).unwrap();
        assert_eq!(log.next_offset(), Offset::new(2), "both records recovered");
        assert!(
            log.loss_report().events.is_empty(),
            "the unwritten zero tail is not loss"
        );
        assert_eq!(log.recovered_truncated_bytes(), 0);
        assert!(
            StdFs::new(root.clone())
                .open(&segment_file_name(0))
                .unwrap()
                .len()
                .unwrap()
                < cfg.max_segment_bytes,
            "the zero tail was truncated at recovery"
        );
        // The resumed writer appends and syncs cleanly.
        assert_eq!(log.append(&rec(b"three")).unwrap(), Offset::new(2));
        log.sync().unwrap();
        assert_eq!(read_back(log.filesystem(), 0).len(), 3);
    }

    // ---- direct io-mode (the SAFE T1 O_DIRECT tier), end to end over a real StdFs ----
    // These run on every unix target (macOS included): `DirectFile`'s bytes are platform-independent
    // (only the O_DIRECT cache-bypass is Linux-specific, and it does not change the recovered image),
    // so the whole segment/roll/seal/recovery machinery is exercised over the direct backend here;
    // the physical-device durability + the actual O_DIRECT flag are validated by the t4g step.

    #[cfg(unix)]
    #[test]
    fn direct_io_mode_recovers_every_acked_record_across_rolls() {
        // The crash-consistency tooth: append+sync a record stream that ROLLS across several
        // segments in direct mode (so the written pre-format + O_DIRECT appends + seal all run), then
        // kill + reopen (still direct) and assert every acked record recovered, in order, with NO
        // loss event and no torn block.
        use crate::fs::StdFs;
        use crate::substrate::ResolvedIoMode;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let open = |root: std::path::PathBuf| {
            Log::open(
                StdFs::with_io_mode(root, ResolvedIoMode::Direct),
                ManualClock::new(),
                small_config(),
            )
            .unwrap()
        };
        let mut log = open(root.clone());
        let n = 24u8;
        for i in 0..n {
            log.append(&rec(&[i; 20])).unwrap();
            log.sync().unwrap();
        }
        assert!(
            log.active_segment_id() >= 2,
            "the stream rolled across several segments"
        );
        drop(log); // an unclean kill (the segment files stay as the O_DIRECT writes left them)

        let log = open(root.clone());
        assert_eq!(
            log.next_offset(),
            Offset::new(u64::from(n)),
            "every acked record recovered"
        );
        assert!(
            log.loss_report().events.is_empty(),
            "no loss on a clean direct-mode restart"
        );
        assert_eq!(log.recovered_truncated_bytes(), 0);
        let records = log.read_from(Offset::ZERO, 1000).unwrap();
        assert_eq!(records.len(), usize::from(n));
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.offset, Offset::new(i as u64));
            assert_eq!(&r.payload[..], &[u8::try_from(i).unwrap(); 20][..]);
        }
    }

    #[cfg(unix)]
    #[test]
    fn direct_and_buffered_produce_identical_sealed_bytes_and_recovered_state() {
        // The metamorphic byte-identity proof (spec §7): the SAME record stream through a BUFFERED
        // log and a DIRECT log yields byte-identical SEALED segment images and identical recovered
        // records. If the bytes are identical, recovery (and the conformance gate) are mode-agnostic
        // by construction.
        use crate::fs::StdFs;
        use crate::substrate::ResolvedIoMode;
        let base = tempfile::tempdir().unwrap();
        let buf_root = base.path().join("buffered");
        let dir_root = base.path().join("direct");
        std::fs::create_dir(&buf_root).unwrap();
        std::fs::create_dir(&dir_root).unwrap();

        let run = |fs: StdFs| {
            let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
            for i in 0..24u8 {
                log.append(&rec(&[i; 20])).unwrap();
                log.sync().unwrap();
            }
            log.active_segment_id()
        };
        let buf_active = run(StdFs::new(buf_root.clone()));
        let dir_active = run(StdFs::with_io_mode(
            dir_root.clone(),
            ResolvedIoMode::Direct,
        ));
        assert_eq!(buf_active, dir_active, "both modes roll at the same points");

        // Every SEALED segment (all but the active one) is byte-identical between the two modes.
        let buf_fs = StdFs::new(buf_root.clone());
        let dir_fs = StdFs::new(dir_root.clone()); // read back in BUFFERED mode: a sealed segment is exact
        for id in 0..buf_active {
            let name = segment_file_name(id);
            let bf = buf_fs.open(&name).unwrap();
            let df = dir_fs.open(&name).unwrap();
            let bl = bf.len().unwrap();
            let dl = df.len().unwrap();
            assert_eq!(
                bl, dl,
                "sealed segment {id} lengths differ (buffered {bl}, direct {dl})"
            );
            let mut b = vec![0u8; usize::try_from(bl).unwrap()];
            let mut d = vec![0u8; usize::try_from(dl).unwrap()];
            bf.read_exact_at(&mut b, 0).unwrap();
            df.read_exact_at(&mut d, 0).unwrap();
            assert_eq!(
                b, d,
                "sealed segment {id} bytes differ between buffered and direct"
            );
        }

        // And the recovered record streams are identical.
        let recovered = |root: std::path::PathBuf| {
            let log = Log::open(StdFs::new(root), ManualClock::new(), small_config()).unwrap();
            log.read_from(Offset::ZERO, 1000)
                .unwrap()
                .iter()
                .map(|r| (r.offset, r.payload.to_vec()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            recovered(buf_root),
            recovered(dir_root),
            "recovered state differs across modes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn direct_io_mode_torn_tail_is_dropped_and_acked_records_survive() {
        // A torn/garbage tail block past the acked frontier (a crash mid-append that left partial,
        // non-frame bytes) must be caught by the frame CRC on recovery and dropped — never accepted
        // as data — while every acked record survives. We simulate the torn write by stamping
        // non-frame garbage just past the durable frontier of the active segment.
        use crate::fs::StdFs;
        use crate::io::StdFile;
        use crate::substrate::ResolvedIoMode;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut log = Log::open(
            StdFs::with_io_mode(root.clone(), ResolvedIoMode::Direct),
            ManualClock::new(),
            small_config(),
        )
        .unwrap();
        for i in 0..3u8 {
            log.append(&rec(&[i; 20])).unwrap();
            log.sync().unwrap(); // acked
        }
        let acked = log.next_offset();
        let active = log.active_segment_id();
        drop(log);

        // Stamp garbage at the TRUE frame boundary (the scan's `valid_end`, one past record 2's
        // complete frame — NOT `last_nonzero_end`, which can point INSIDE a frame that ends in zero
        // bytes), exactly as a crash mid-4th-append would leave a torn, non-frame tail.
        let name = segment_file_name(active);
        let frontier = SegmentReader::open(StdFile::open(&root.join(&name)).unwrap())
            .unwrap()
            .scan()
            .unwrap()
            .valid_end;
        let raw = StdFile::open(&root.join(&name)).unwrap();
        raw.write_all_at(&[0xAB; 48], frontier).unwrap();
        raw.sync_all().unwrap();
        drop(raw);

        // Recover: the acked records survive, the torn tail is dropped (not accepted as a record).
        let log = Log::open(
            StdFs::with_io_mode(root.clone(), ResolvedIoMode::Direct),
            ManualClock::new(),
            small_config(),
        )
        .unwrap();
        assert_eq!(
            log.next_offset(),
            acked,
            "no acked record lost, no torn block accepted"
        );
        assert_eq!(log.read_from(Offset::ZERO, 100).unwrap().len(), 3);
    }

    // Fills a small-segment log with `n` single-byte records (each `payload` byte `i`), synced,
    // and returns it rolled across several segments so the reaper has sealed predecessors.
    fn rolled_log(n: u8) -> Log<InMemoryFs, ManualClock> {
        let mut log = open_mem(small_config());
        for i in 0..n {
            log.append(&rec(&[i; 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 2, "should span 3+ segments");
        log
    }

    #[test]
    fn reap_with_a_zero_bound_is_unlimited_and_reaps_nothing() {
        // max_retained_bytes == 0 means UNLIMITED: the reaper is off (the default), so even a
        // fully-consumed multi-segment log keeps every segment.
        let mut log = rolled_log(16);
        let before = log.durable_record_bytes();
        let segs_before = segment_ids(log.filesystem()).unwrap();
        let outcome = log.reap_to_size(0, u64::MAX).unwrap();
        assert_eq!(
            outcome,
            ReapOutcome::default(),
            "a zero bound reaps nothing"
        );
        assert_eq!(log.durable_record_bytes(), before);
        assert_eq!(segment_ids(log.filesystem()).unwrap(), segs_before);
    }

    #[test]
    fn reap_with_a_bound_larger_than_the_log_reaps_nothing() {
        // A bound above the whole log's durable bytes never trips, even with everything consumed.
        let mut log = rolled_log(16);
        let total = log.durable_record_bytes();
        let segs_before = segment_ids(log.filesystem()).unwrap();
        let outcome = log.reap_to_size(total + 1_000_000, u64::MAX).unwrap();
        assert_eq!(outcome, ReapOutcome::default());
        assert_eq!(log.durable_record_bytes(), total);
        assert_eq!(segment_ids(log.filesystem()).unwrap(), segs_before);
    }

    #[test]
    fn reap_deletes_oldest_consumed_segments_until_under_the_bound() {
        // Everything consumed (protect at the head), a bound far below the log: the reaper deletes
        // the oldest sealed segments one at a time until the durable total is at or below the
        // bound, never touching the active segment.
        let mut log = rolled_log(20);
        let head = log.next_offset().get();
        let active_id = log.active_segment_id();
        let bytes_before = log.durable_record_bytes();
        let one_record = bytes_before / 20; // 20 equal records
                                            // Aim for roughly two records' worth of headroom; the reaper overshoots downward by
                                            // whole sealed segments, so the result is at or under the bound.
        let bound = 2 * one_record;

        let outcome = log.reap_to_size(bound, head).unwrap();
        assert!(outcome.segments_reaped >= 1, "should have reaped a segment");
        assert!(
            log.durable_record_bytes() <= bound,
            "the log is brought to or under the bound ({} <= {bound})",
            log.durable_record_bytes()
        );
        // The active segment is never reaped: it still exists and is still the active id.
        assert_eq!(log.active_segment_id(), active_id);
        assert!(log
            .filesystem()
            .exists(&segment_file_name(active_id))
            .unwrap());
        // bytes_reaped equals exactly how much durable_record_bytes dropped.
        assert_eq!(
            outcome.bytes_reaped,
            bytes_before - log.durable_record_bytes()
        );
        // The reaped oldest segments are gone from disk; the surviving prefix starts above 0.
        let surviving = segment_ids(log.filesystem()).unwrap();
        assert!(
            !surviving.contains(&0),
            "segment 0 was reaped, so the surviving prefix starts above 0: {surviving:?}"
        );
        // The number of segments dropped from the directory matches the reported count.
        assert_eq!(
            (active_id + 1) - surviving.len() as u64,
            outcome.segments_reaped
        );
    }

    #[test]
    fn reap_never_deletes_a_segment_above_the_protect_floor() {
        // A protect floor of 0 means no consumer has committed anything, so NOTHING may be
        // reaped even though the log is far over a tiny bound. This is the consumer-safety rule.
        let mut log = rolled_log(20);
        let before = log.durable_record_bytes();
        let segs_before = segment_ids(log.filesystem()).unwrap();
        let outcome = log.reap_to_size(1, 0).unwrap();
        assert_eq!(
            outcome,
            ReapOutcome::default(),
            "a zero protect floor protects every record"
        );
        assert_eq!(log.durable_record_bytes(), before);
        assert_eq!(segment_ids(log.filesystem()).unwrap(), segs_before);
    }

    #[test]
    fn reap_stops_at_the_first_segment_not_fully_consumed() {
        // The protect floor sits inside the SECOND segment: only the first segment is fully
        // consumed (ends at segments[1].base <= protect), so exactly one segment is reaped even
        // though the bound is tiny, because the next segment is not fully consumed.
        let mut log = rolled_log(20);
        let ids = segment_ids(log.filesystem()).unwrap();
        // segments[1].base_offset is the count of records in segment 0.
        let seg0_records = read_back(log.filesystem(), ids[0]).len() as u64;
        // Protect exactly at segments[1].base: segment 0 (records < that) is reapable, segment 1
        // (it begins at the floor, so it holds a record AT the floor) is not.
        let protect = seg0_records;
        let bytes_before = log.durable_record_bytes();
        let outcome = log.reap_to_size(1, protect).unwrap();
        assert_eq!(
            outcome.segments_reaped, 1,
            "only segment 0 is fully consumed"
        );
        // Segment 0 is gone; segment 1 and the rest survive.
        assert!(!log.filesystem().exists(&segment_file_name(ids[0])).unwrap());
        assert!(log.filesystem().exists(&segment_file_name(ids[1])).unwrap());
        assert_eq!(
            log.durable_record_bytes(),
            bytes_before - outcome.bytes_reaped
        );
    }

    #[test]
    fn reap_never_deletes_the_active_segment_even_fully_consumed_and_over_bound() {
        // A single-segment log (only the active segment) over a tiny bound, everything consumed:
        // the active segment is never reaped, so nothing happens.
        let mut log = open_mem(LogConfig::default());
        for i in 0..4u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap();
        assert_eq!(log.active_segment_id(), 0, "still a single segment");
        let before = log.durable_record_bytes();
        let outcome = log.reap_to_size(1, log.next_offset().get()).unwrap();
        assert_eq!(outcome, ReapOutcome::default());
        assert_eq!(log.durable_record_bytes(), before);
        assert!(log.filesystem().exists(&segment_file_name(0)).unwrap());
    }

    #[test]
    fn after_a_reap_a_reopen_recovers_the_remaining_contiguous_chain() {
        // The durability-critical assertion: after a reap deletes a prefix of sealed segments,
        // reopening the data dir recovers the remaining contiguous chain from a NON-ZERO start,
        // the head/offsets are correct, the reaped records are gone, and the survivors read back.
        let mut log = rolled_log(20);
        let head = log.next_offset().get();
        let one_record = log.durable_record_bytes() / 20;
        let outcome = log.reap_to_size(3 * one_record, head).unwrap();
        assert!(outcome.segments_reaped >= 1);
        let oldest_surviving_base = {
            // The first surviving segment's base is the lowest offset still present.
            let ids = segment_ids(log.filesystem()).unwrap();
            SegmentReader::open(log.filesystem().open(&segment_file_name(ids[0])).unwrap())
                .unwrap()
                .header()
                .base_offset
        };
        let live_bytes = log.durable_record_bytes();
        let fs = log.into_filesystem();

        // Reopen: recovery accepts the non-zero start and rebuilds the chain.
        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(reopened.next_offset().get(), head, "head is unchanged");
        assert_eq!(reopened.flushed_offset().get(), head);
        // The recomputed durable total equals the live total after the reap (byte accounting
        // survives a round trip).
        assert_eq!(reopened.durable_record_bytes(), live_bytes);
        // The reaped records are gone: a read below the oldest surviving base is out of range.
        let err = reopened.read_from(Offset::ZERO, 10).unwrap_err();
        assert!(
            matches!(err, StorageError::OffsetOutOfRange { requested: 0, oldest } if oldest == oldest_surviving_base.get())
        );
        // The un-reaped records still read correctly, contiguous from the surviving base to head.
        let survivors = reopened.read_from(oldest_surviving_base, 1000).unwrap();
        assert_eq!(survivors.len() as u64, head - oldest_surviving_base.get());
        for (i, r) in survivors.iter().enumerate() {
            assert_eq!(
                r.offset,
                Offset::new(oldest_surviving_base.get() + i as u64)
            );
        }
    }

    #[test]
    fn sealed_record_bytes_after_a_reap_matches_a_fresh_reopen() {
        // Cross-check the in-place running total against a fresh reopen's recomputed value, so the
        // decrement is provably exact (not merely self-consistent).
        let mut log = rolled_log(24);
        let one_record = log.durable_record_bytes() / 24;
        log.reap_to_size(4 * one_record, log.next_offset().get())
            .unwrap();
        let live = log.durable_record_bytes();
        let fs = log.into_filesystem();
        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(
            reopened.durable_record_bytes(),
            live,
            "the running total equals the recomputed total after a reap"
        );
    }

    #[test]
    fn a_reap_followed_by_a_power_loss_yields_a_valid_log() {
        // Crash-safety: the reap dir-synced each removal, so a power loss after it does NOT
        // resurrect a reaped segment and does NOT break the chain. A simulated power loss then a
        // reopen must yield a valid log with the same surviving chain.
        let mut log = rolled_log(20);
        let head = log.next_offset().get();
        let one_record = log.durable_record_bytes() / 20;
        let outcome = log.reap_to_size(3 * one_record, head).unwrap();
        assert!(outcome.segments_reaped >= 1);
        let surviving = segment_ids(log.filesystem()).unwrap();
        let live_bytes = log.durable_record_bytes();

        // A power loss now: the durably-removed segments stay removed (the reap dir-synced).
        log.filesystem().simulate_power_loss();
        assert_eq!(
            segment_ids(log.filesystem()).unwrap(),
            surviving,
            "no reaped segment is resurrected by a power loss"
        );
        let fs = log.into_filesystem();
        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(reopened.next_offset().get(), head);
        assert_eq!(reopened.durable_record_bytes(), live_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn reap_and_recovery_on_a_real_directory() {
        use crate::fs::StdFs;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut log =
            Log::open(StdFs::new(root.clone()), ManualClock::new(), small_config()).unwrap();
        for i in 0..20u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 2);
        let head = log.next_offset().get();
        let one_record = log.durable_record_bytes() / 20;
        let outcome = log.reap_to_size(3 * one_record, head).unwrap();
        assert!(outcome.segments_reaped >= 1, "should reap on a real dir");
        let live_bytes = log.durable_record_bytes();
        drop(log);

        // Reopen the real directory: recovery rebuilds the survivors from a non-zero start.
        let reopened =
            Log::open(StdFs::new(root.clone()), ManualClock::new(), small_config()).unwrap();
        assert_eq!(reopened.next_offset().get(), head);
        assert_eq!(reopened.durable_record_bytes(), live_bytes);
    }

    // ---- Forced (disk-full drop-oldest) reap tests (refs #82, #84) ----

    #[test]
    fn earliest_offset_starts_at_zero_and_rises_after_a_reap() {
        // A fresh log's earliest retained offset is 0; after the oldest segment is forced out it
        // rises to the new oldest segment's base.
        let mut log = rolled_log(20);
        assert_eq!(log.earliest_offset(), Offset::ZERO, "nothing reaped yet");
        let ids = segment_ids(log.filesystem()).unwrap();
        let seg1_base = read_back(log.filesystem(), ids[0]).len() as u64;
        log.reap_oldest_forced().unwrap().expect("a segment exists");
        assert_eq!(
            log.earliest_offset(),
            Offset::new(seg1_base),
            "earliest rises to the second segment's base"
        );
    }

    #[test]
    fn reap_oldest_forced_deletes_the_oldest_below_any_protect_offset() {
        // The force-reaper IGNORES consumer-safety: with NOTHING consumed (a protect floor of 0
        // would block the consumer-safe reaper entirely), it still deletes the oldest sealed
        // segment, updates both running totals by exactly that segment's amounts, and reports them.
        let mut log = rolled_log(20);
        let ids = segment_ids(log.filesystem()).unwrap();
        let active_id = log.active_segment_id();
        let bytes_before = log.durable_record_bytes();
        let count_before = log.durable_record_count();
        let seg0_records = read_back(log.filesystem(), ids[0]).len() as u64;

        let outcome = log
            .reap_oldest_forced()
            .unwrap()
            .expect("the oldest sealed segment is force-reaped");
        assert_eq!(outcome.segments_reaped, 1, "exactly one segment forced out");
        // Segment 0 is gone even though no consumer has consumed it; the active segment is intact.
        assert!(!log.filesystem().exists(&segment_file_name(ids[0])).unwrap());
        assert_eq!(log.active_segment_id(), active_id);
        assert!(log
            .filesystem()
            .exists(&segment_file_name(active_id))
            .unwrap());
        // Both running totals dropped by exactly the reaped segment's amounts.
        assert_eq!(
            log.durable_record_bytes(),
            bytes_before - outcome.bytes_reaped
        );
        assert_eq!(log.durable_record_count(), count_before - seg0_records);
        // The earliest retained offset is now the second segment's base.
        assert_eq!(log.earliest_offset(), Offset::new(seg0_records));
    }

    #[test]
    fn reap_oldest_forced_never_reaps_the_active_segment() {
        // A single-segment log (only the active segment): the force-reaper returns None and
        // reclaims nothing, so a single in-flight set cannot wedge the log empty.
        let mut log = open_mem(LogConfig::default());
        for i in 0..4u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap();
        assert_eq!(log.active_segment_id(), 0, "still a single segment");
        let before = log.durable_record_bytes();
        let count_before = log.durable_record_count();
        assert_eq!(
            log.reap_oldest_forced().unwrap(),
            None,
            "nothing to force out"
        );
        assert_eq!(log.durable_record_bytes(), before, "nothing reaped");
        assert_eq!(log.durable_record_count(), count_before);
        assert!(log.filesystem().exists(&segment_file_name(0)).unwrap());
    }

    #[test]
    fn repeated_forced_reaps_stop_at_the_last_remaining_active_segment() {
        // Forcing out the oldest segment repeatedly drains the whole sealed prefix but always
        // stops once only the active segment remains (a bounded loop never wedges the log empty).
        let mut log = rolled_log(20);
        let active_id = log.active_segment_id();
        let mut reaped = 0u64;
        while let Some(outcome) = log.reap_oldest_forced().unwrap() {
            reaped += outcome.segments_reaped;
            assert!(
                reaped <= active_id,
                "cannot reap more than the sealed prefix"
            );
        }
        // Only the active segment is left; it is never reaped.
        assert_eq!(segment_ids(log.filesystem()).unwrap(), vec![active_id]);
        assert_eq!(reaped, active_id, "every sealed predecessor was forced out");
        // The earliest retained offset is now the active segment's base.
        let active_base = SegmentReader::open(
            log.filesystem()
                .open(&segment_file_name(active_id))
                .unwrap(),
        )
        .unwrap()
        .header()
        .base_offset;
        assert_eq!(log.earliest_offset(), active_base);
    }

    #[test]
    fn forced_totals_match_a_fresh_reopen_and_recover_the_remaining_chain() {
        // The durability-critical cross-check: after force-reaping a prefix, the in-place running
        // byte and count totals equal a fresh reopen's recomputed values, the reopen recovers the
        // remaining contiguous chain from a non-zero start, and the reaped records are gone.
        let mut log = rolled_log(20);
        let head = log.next_offset().get();
        log.reap_oldest_forced().unwrap().unwrap();
        log.reap_oldest_forced().unwrap().unwrap();
        let live_bytes = log.durable_record_bytes();
        let live_count = log.durable_record_count();
        let oldest_surviving_base = log.earliest_offset();
        assert!(oldest_surviving_base.get() > 0, "reaped a non-empty prefix");
        let fs = log.into_filesystem();

        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(reopened.next_offset().get(), head, "head is unchanged");
        assert_eq!(
            reopened.durable_record_bytes(),
            live_bytes,
            "byte total survives a reopen"
        );
        assert_eq!(
            reopened.durable_record_count(),
            live_count,
            "count total survives a reopen"
        );
        assert_eq!(reopened.earliest_offset(), oldest_surviving_base);
        // The reaped records are gone: a read below the oldest surviving base is out of range.
        let err = reopened.read_from(Offset::ZERO, 10).unwrap_err();
        assert!(matches!(
            err,
            StorageError::OffsetOutOfRange { requested: 0, oldest } if oldest == oldest_surviving_base.get()
        ));
        // The survivors read back contiguous from the surviving base to the head.
        let survivors = reopened.read_from(oldest_surviving_base, 1000).unwrap();
        assert_eq!(survivors.len() as u64, head - oldest_surviving_base.get());
    }

    #[cfg(unix)]
    #[test]
    fn forced_reap_then_power_loss_keeps_the_segment_gone() {
        // Crash-safety on a real directory: the forced reap unlink + dir-sync makes the removal
        // durable, so a power loss after it does NOT resurrect the reaped segment, and a reopen
        // rebuilds the same surviving chain with the same totals.
        use crate::fs::StdFs;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mut log =
            Log::open(StdFs::new(root.clone()), ManualClock::new(), small_config()).unwrap();
        for i in 0..20u8 {
            log.append(&rec(&[i; 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 2);
        let head = log.next_offset().get();
        log.reap_oldest_forced().unwrap().unwrap();
        let surviving = segment_ids(log.filesystem()).unwrap();
        let live_bytes = log.durable_record_bytes();
        let live_count = log.durable_record_count();
        drop(log);

        // Reopen the real directory: the durably-removed segment stays removed and the chain rebuilds.
        let reopened =
            Log::open(StdFs::new(root.clone()), ManualClock::new(), small_config()).unwrap();
        assert_eq!(segment_ids(reopened.filesystem()).unwrap(), surviving);
        assert_eq!(reopened.next_offset().get(), head);
        assert_eq!(reopened.durable_record_bytes(), live_bytes);
        assert_eq!(reopened.durable_record_count(), live_count);
    }

    // ---- Count-, time-, and composed-retention tests (refs #13, #80) ----

    use std::sync::Arc;

    // Opens a small-segment log over a shared `ManualClock` the caller can drive (for age tests).
    fn open_mem_clock(clock: Arc<ManualClock>) -> Log<InMemoryFs, Arc<ManualClock>> {
        Log::open(InMemoryFs::new(), clock, small_config()).unwrap()
    }

    #[test]
    fn count_retention_reaps_oldest_until_under_the_bound() {
        // With max_messages set and everything consumed, producing past it reaps the OLDEST sealed
        // segments until the total record count is at or under the bound; never the active segment,
        // never below the protect floor.
        let mut log = rolled_log(20);
        let head = log.next_offset().get();
        let active_id = log.active_segment_id();
        assert_eq!(log.durable_record_count(), 20, "all 20 records counted");
        let bounds = RetentionBounds {
            max_messages: 6,
            ..RetentionBounds::default()
        };
        let outcome = log.reap(bounds, head).unwrap();
        assert!(outcome.segments_reaped >= 1, "reaped at least one segment");
        assert!(
            log.durable_record_count() <= 6,
            "count brought to or under the bound: {} <= 6",
            log.durable_record_count()
        );
        // The active segment is never reaped.
        assert_eq!(log.active_segment_id(), active_id);
        assert!(log
            .filesystem()
            .exists(&segment_file_name(active_id))
            .unwrap());
        // The oldest segments are gone; the surviving prefix starts above offset 0.
        let surviving = segment_ids(log.filesystem()).unwrap();
        assert!(!surviving.contains(&0), "segment 0 reaped: {surviving:?}");
    }

    #[test]
    fn count_retention_never_reaps_below_the_protect_floor() {
        // A zero protect floor pins every record; even far over the count bound, nothing is reaped.
        let mut log = rolled_log(20);
        let before = log.durable_record_count();
        let segs_before = segment_ids(log.filesystem()).unwrap();
        let bounds = RetentionBounds {
            max_messages: 1,
            ..RetentionBounds::default()
        };
        let outcome = log.reap(bounds, 0).unwrap();
        assert_eq!(
            outcome,
            ReapOutcome::default(),
            "protect floor 0 reaps nothing"
        );
        assert_eq!(log.durable_record_count(), before);
        assert_eq!(segment_ids(log.filesystem()).unwrap(), segs_before);
    }

    #[test]
    fn count_retention_after_a_reap_matches_a_fresh_reopen() {
        // The running total count decrements by exactly the reaped segments' counts, cross-checked
        // against a fresh reopen's recomputed count.
        let mut log = rolled_log(24);
        let bounds = RetentionBounds {
            max_messages: 8,
            ..RetentionBounds::default()
        };
        log.reap(bounds, log.next_offset().get()).unwrap();
        let live_count = log.durable_record_count();
        let live_bytes = log.durable_record_bytes();
        let fs = log.into_filesystem();
        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(
            reopened.durable_record_count(),
            live_count,
            "the running count equals the recomputed count after a reap"
        );
        assert_eq!(
            reopened.durable_record_bytes(),
            live_bytes,
            "bytes also exact"
        );
    }

    #[test]
    fn age_retention_reaps_a_fully_aged_segment_and_advances_with_the_clock() {
        // A segment is age-eligible only when its MAXIMUM record timestamp is older than
        // now - max_age. Old segments are reaped first; a recent record in a later segment must NOT
        // make it eligible; advancing the clock makes more segments eligible.
        let clock = Arc::new(ManualClock::new());
        let mut log = open_mem_clock(Arc::clone(&clock));
        // Fill several segments with OLD records (timestamp 100), then a batch of NEW records
        // (timestamp 10_000) so the newest segments are not yet aged.
        for i in 0..10u8 {
            log.append(&rec_at(100, &[i; 20])).unwrap();
        }
        for i in 0..10u8 {
            log.append(&rec_at(10_000, &[i; 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 2, "spans several segments");
        let head = log.next_offset().get();
        let segs_before = segment_ids(log.filesystem()).unwrap().len();
        let count_before = log.durable_record_count();

        // now = 5_000, max_age = 1_000: a segment is eligible iff max_ts < 4_000. The old segments
        // (max_ts 100) qualify; any segment holding a 10_000-ts record does not.
        let bounds = RetentionBounds {
            max_age_ms: 1_000,
            ..RetentionBounds::default()
        };
        clock.set_unix_millis(5_000);
        let outcome = log.reap(bounds, head).unwrap();
        assert!(
            outcome.segments_reaped >= 1,
            "the aged-out old segments are reaped"
        );
        let segs_after_first = segment_ids(log.filesystem()).unwrap().len();
        assert!(segs_after_first < segs_before, "some old segments reaped");
        // The 10 NEW records all survive: no segment holding a 10_000-ts record was reaped.
        let surviving_records: u64 = segment_ids(log.filesystem())
            .unwrap()
            .iter()
            .map(|id| read_back(log.filesystem(), *id).len() as u64)
            .sum();
        assert!(
            surviving_records >= 10,
            "the 10 new records survive at clock 5_000: {surviving_records}"
        );
        // A second pass at the SAME clock reaps nothing more (the new segments are not yet aged).
        assert_eq!(
            log.reap(bounds, head).unwrap(),
            ReapOutcome::default(),
            "no further reap until the clock advances"
        );

        // Advance past the new records' age: now everything below the head is older than
        // now - max_age, so the reaper trims down toward the active segment.
        clock.set_unix_millis(20_000);
        let outcome2 = log.reap(bounds, head).unwrap();
        assert!(
            outcome2.segments_reaped >= 1,
            "advancing the clock makes the previously-too-new segments eligible"
        );
        assert!(
            log.durable_record_count() < count_before,
            "the total count dropped as segments were reaped over time"
        );
        // The active segment always survives.
        assert!(log
            .filesystem()
            .exists(&segment_file_name(log.active_segment_id()))
            .unwrap());
    }

    #[test]
    fn age_retention_uses_the_max_timestamp_not_the_min() {
        // A segment with one OLD record and one RECENT record must NOT be reaped: the max
        // timestamp (the recent one) is not past the bound, even though an old record precedes it.
        let clock = Arc::new(ManualClock::new());
        // A segment cap that holds exactly two of these records, so the first segment carries one
        // old and one recent record.
        let cfg = LogConfig {
            max_segment_bytes: 200,
            max_total_bytes: 0,
            ..LogConfig::default()
        };
        let mut log = Log::open(InMemoryFs::new(), Arc::clone(&clock), cfg).unwrap();
        // Segment 0: an old record (ts 100) then a recent record (ts 9_000).
        log.append(&rec_at(100, &[0u8; 20])).unwrap();
        log.append(&rec_at(9_000, &[1u8; 20])).unwrap();
        // Force a roll by producing more so segment 0 is sealed with max_ts 9_000.
        for i in 0..6u8 {
            log.append(&rec_at(9_000, &[i; 20])).unwrap();
        }
        log.sync().unwrap();
        assert!(log.active_segment_id() >= 1, "segment 0 is sealed");
        let head = log.next_offset().get();
        let segs_before = segment_ids(log.filesystem()).unwrap();

        // now = 5_000, max_age = 1_000: eligible iff max_ts < 4_000. Segment 0's max_ts is 9_000,
        // so it is NOT eligible despite holding an old record. Nothing is reaped.
        clock.set_unix_millis(5_000);
        let bounds = RetentionBounds {
            max_age_ms: 1_000,
            ..RetentionBounds::default()
        };
        let outcome = log.reap(bounds, head).unwrap();
        assert_eq!(
            outcome,
            ReapOutcome::default(),
            "a segment whose MAX timestamp is recent is not reaped (max, not min)"
        );
        assert_eq!(segment_ids(log.filesystem()).unwrap(), segs_before);

        // Advance past the recent record's age: now max_ts 9_000 < now - max_age, so it is reaped.
        clock.set_unix_millis(11_000);
        let outcome2 = log.reap(bounds, head).unwrap();
        assert!(
            outcome2.segments_reaped >= 1,
            "once even the newest record has aged out, the segment is reaped"
        );
    }

    #[test]
    fn age_retention_recomputes_after_a_reopen() {
        // The per-segment max timestamp is recomputed at recovery, so the age reaper behaves
        // identically after a reopen.
        let clock = Arc::new(ManualClock::new());
        let mut log = open_mem_clock(Arc::clone(&clock));
        for i in 0..10u8 {
            log.append(&rec_at(100, &[i; 20])).unwrap();
        }
        for i in 0..10u8 {
            log.append(&rec_at(10_000, &[i; 20])).unwrap();
        }
        log.sync().unwrap();
        let head = log.next_offset().get();
        let fs = log.into_filesystem();

        // Reopen over a fresh clock set to 5_000: the recomputed max timestamps drive the same
        // decision as before the reopen (old segments eligible, new ones not).
        let clock2 = Arc::new(ManualClock::at_unix_millis(5_000));
        let mut reopened = Log::open(fs, Arc::clone(&clock2), small_config()).unwrap();
        assert_eq!(
            reopened.next_offset().get(),
            head,
            "head unchanged after reopen"
        );
        let bounds = RetentionBounds {
            max_age_ms: 1_000,
            ..RetentionBounds::default()
        };
        let outcome = reopened.reap(bounds, head).unwrap();
        assert!(
            outcome.segments_reaped >= 1,
            "recomputed max timestamps still make the old segments age-eligible"
        );
        // The new (10_000-ts) records survive.
        let surviving: u64 = segment_ids(reopened.filesystem())
            .unwrap()
            .iter()
            .map(|id| read_back(reopened.filesystem(), *id).len() as u64)
            .sum();
        assert!(surviving >= 10, "the new records survive: {surviving}");
    }

    #[test]
    fn each_bound_independently_triggers_a_reap() {
        // Composition: size OR count OR age each ALONE triggers a reap (the others disabled).
        let head_of = |log: &Log<InMemoryFs, ManualClock>| log.next_offset().get();

        // Size only.
        let mut log = rolled_log(20);
        let one = log.durable_record_bytes() / 20;
        let out = log
            .reap(
                RetentionBounds {
                    max_bytes: 3 * one,
                    ..RetentionBounds::default()
                },
                head_of(&log),
            )
            .unwrap();
        assert!(out.segments_reaped >= 1, "size bound alone reaps");

        // Count only.
        let mut log = rolled_log(20);
        let out = log
            .reap(
                RetentionBounds {
                    max_messages: 5,
                    ..RetentionBounds::default()
                },
                head_of(&log),
            )
            .unwrap();
        assert!(out.segments_reaped >= 1, "count bound alone reaps");

        // Age only.
        let clock = Arc::new(ManualClock::new());
        let mut log = open_mem_clock(Arc::clone(&clock));
        for i in 0..20u8 {
            log.append(&rec_at(100, &[i; 20])).unwrap();
        }
        log.sync().unwrap();
        let head = log.next_offset().get();
        clock.set_unix_millis(10_000);
        let out = log
            .reap(
                RetentionBounds {
                    max_age_ms: 1_000,
                    ..RetentionBounds::default()
                },
                head,
            )
            .unwrap();
        assert!(out.segments_reaped >= 1, "age bound alone reaps");
    }

    #[test]
    fn every_bound_disabled_reaps_nothing() {
        // The #261 default-off behavior is preserved: all three bounds 0 reaps nothing, even with
        // everything consumed and many segments.
        let mut log = rolled_log(20);
        let before = log.durable_record_bytes();
        let count_before = log.durable_record_count();
        let segs_before = segment_ids(log.filesystem()).unwrap();
        let outcome = log
            .reap(RetentionBounds::default(), log.next_offset().get())
            .unwrap();
        assert_eq!(
            outcome,
            ReapOutcome::default(),
            "all bounds off reaps nothing"
        );
        assert_eq!(log.durable_record_bytes(), before);
        assert_eq!(log.durable_record_count(), count_before);
        assert_eq!(segment_ids(log.filesystem()).unwrap(), segs_before);
    }

    #[test]
    fn composed_bounds_still_gate_on_consumer_safety() {
        // Even with size, age, and count ALL tripped, a protect floor of 0 (no consumer has
        // committed) blocks every delete: consumer-safety gates every bound.
        let clock = Arc::new(ManualClock::new());
        let mut log = open_mem_clock(Arc::clone(&clock));
        for i in 0..20u8 {
            log.append(&rec_at(100, &[i; 20])).unwrap();
        }
        log.sync().unwrap();
        clock.set_unix_millis(10_000);
        let before = log.durable_record_bytes();
        let segs_before = segment_ids(log.filesystem()).unwrap();
        let bounds = RetentionBounds {
            max_bytes: 1,
            max_age_ms: 1,
            max_messages: 1,
        };
        let outcome = log.reap(bounds, 0).unwrap();
        assert_eq!(
            outcome,
            ReapOutcome::default(),
            "consumer-safety blocks every delete even with all bounds tripped"
        );
        assert_eq!(log.durable_record_bytes(), before);
        assert_eq!(segment_ids(log.filesystem()).unwrap(), segs_before);
    }

    #[test]
    fn count_retention_never_reaps_the_active_segment() {
        // A single-segment log over a tiny count bound, everything consumed: the active segment is
        // never reaped, so nothing happens.
        let mut log = open_mem(LogConfig::default());
        for i in 0..4u8 {
            log.append(&rec(&[i; 8])).unwrap();
        }
        log.sync().unwrap();
        assert_eq!(log.active_segment_id(), 0, "still a single segment");
        let before = log.durable_record_count();
        let bounds = RetentionBounds {
            max_messages: 1,
            ..RetentionBounds::default()
        };
        let outcome = log.reap(bounds, log.next_offset().get()).unwrap();
        assert_eq!(outcome, ReapOutcome::default());
        assert_eq!(log.durable_record_count(), before);
        assert!(log.filesystem().exists(&segment_file_name(0)).unwrap());
    }

    /// #664: the WINDOW-BOUNDED read-end (the fix) returns BYTE-IDENTICAL records to a read whose
    /// read-end was the whole segment, for EVERY (start, window) over a multi-segment log — the
    /// differential that proves bounding the read span never drops, duplicates, or corrupts a record.
    /// Covers BOTH `read_range` (materialized) and `read_range_raw` (zero-copy), and a non-sequential
    /// SEEK (a start that jumps backward/forward) re-locates exactly.
    #[test]
    fn window_bounded_read_is_byte_identical_to_an_unbounded_read_everywhere() {
        // Several segments (small cap) so the seek crosses segment boundaries, plus enough records
        // per segment that windows land mid-segment (where the old whole-segment read-end and the new
        // window read-end differ the most).
        let mut log = open_mem(LogConfig {
            max_segment_bytes: 4096,
            max_total_bytes: 0,
            ..LogConfig::default()
        });
        let total = 2_000u32;
        for i in 0..total {
            log.append(&rec(&i.to_le_bytes())).unwrap();
            if i % 13 == 0 {
                log.sync().unwrap();
            }
        }
        log.sync().unwrap();
        let flushed = log.flushed_offset().get();
        // The single shared read primitive `read_from` (max-records, no window subtlety) is the oracle:
        // window-bounding only changes HOW MANY BYTES are buffered, never WHICH records decode.
        for start in 0..flushed {
            for window in [1usize, 3, 17, 64, 257] {
                let oracle = log.read_from(Offset::new(start), window).unwrap();
                let ranged = log.read_range(Offset::new(start), window, None).unwrap();
                assert_eq!(
                    ranged, oracle,
                    "read_range differs from oracle at start={start} window={window}"
                );
                // The raw twin: reconstruct its records (raw frames + the materialized active tail)
                // and compare field-by-field against the oracle.
                let (raw, tail_from) = log
                    .read_range_raw(Offset::new(start), window, None)
                    .unwrap();
                let decoded = decode_raw_run(&raw);
                for ((view, off), owned) in decoded.iter().zip(oracle.iter()) {
                    assert_eq!(*off, owned.offset.get(), "raw offset at start={start}");
                    assert_eq!(
                        view.payload,
                        &owned.payload[..],
                        "raw payload at start={start}"
                    );
                }
                let mut chained = decoded.len();
                if let Some(from) = tail_from {
                    let remaining = window - chained;
                    if remaining > 0 {
                        let tail = log.read_range(from, remaining, None).unwrap();
                        for (i, owned) in tail.iter().enumerate() {
                            assert_eq!(
                                owned,
                                &oracle[chained + i],
                                "raw tail record at start={start} window={window}"
                            );
                        }
                        chained += tail.len();
                    }
                }
                assert_eq!(
                    chained,
                    oracle.len(),
                    "raw run + tail count != oracle at start={start} window={window}"
                );
            }
        }
    }

    /// #664: a non-sequential SEEK (jumping the start offset around, not draining forward) re-locates
    /// via the binary-search anchor seek and returns the exact records, with the window read-end
    /// bounded fresh each time — there is no stale forward cursor to mislead a seek.
    #[test]
    fn window_bounded_read_handles_a_non_sequential_seek() {
        let mut log = open_mem(LogConfig {
            max_segment_bytes: 4096,
            max_total_bytes: 0,
            ..LogConfig::default()
        });
        for i in 0..1_500u32 {
            log.append(&rec(&i.to_le_bytes())).unwrap();
        }
        log.sync().unwrap();
        let flushed = log.flushed_offset().get();
        // A scattered, deliberately non-monotonic sequence of starts (forward, backward, repeated).
        for &start in &[900u64, 12, 1_400, 1, 700, 0, 1_499, 256, 257, 13] {
            if start >= flushed {
                continue;
            }
            let oracle = log.read_from(Offset::new(start), 50).unwrap();
            let ranged = log.read_range(Offset::new(start), 50, None).unwrap();
            assert_eq!(ranged, oracle, "seek to {start} mis-located");
            assert_eq!(
                ranged.first().unwrap().offset.get(),
                start,
                "first offset != start"
            );
        }
    }

    /// #664: the window read-end bound makes `read_range_raw`'s buffered span INDEPENDENT of how far
    /// the start sits from the segment end. Asserted structurally: the returned run's byte length for
    /// a fixed window is ~the same near the segment start as near its end (it would GROW with
    /// distance-to-end before the fix). One large active segment holds the whole log.
    #[test]
    fn window_bounded_raw_read_span_does_not_grow_with_start() {
        let mut log = open_mem(LogConfig::default());
        let payload = [7u8; 64];
        for _ in 0..50_000u32 {
            log.append(&rec(&payload)).unwrap();
        }
        log.sync().unwrap();
        let flushed = log.flushed_offset().get();
        assert_eq!(log.active_segment_id(), 0, "single segment");
        let window = 128usize;
        let (near_start, _) = log.read_range_raw(Offset::new(10), window, None).unwrap();
        let (near_end, _) = log
            .read_range_raw(Offset::new(flushed - 200), window, None)
            .unwrap();
        // Both serve `window` whole frames; their byte runs must be the same size (same frame size),
        // NOT proportional to the distance from the segment end. Allow exact equality here: the
        // payload is fixed-size, so two equal-count runs are byte-equal in length.
        assert_eq!(near_start.record_count, window as u64);
        assert_eq!(
            near_start.bytes.len(),
            near_end.bytes.len(),
            "raw run byte length grew with start offset (window bound not applied)"
        );
    }

    /// #664 MICRO-BENCH (ignored; run with `--ignored --nocapture`). Times a FIXED-window
    /// `read_range_raw` at increasing `start_offset` over ONE large active segment (the bench's
    /// shape: all records in one un-sealed 64 MiB segment). BEFORE the fix the per-fetch cost GROWS
    /// with `start` (each fetch reads anchor->segment-end bytes => O(distance-to-end)); AFTER the
    /// window-bounded read it is FLAT (each fetch reads ~one window). Prints the curve so the PR can
    /// show O(start)->O(1).
    #[test]
    #[ignore = "perf micro-bench, run explicitly with --ignored --nocapture"]
    fn micro_bench_664_read_range_raw_fixed_window_vs_start() {
        let total: u64 = 200_000;
        let window = 256usize;
        let payload = [0u8; 100];
        let mut log = open_mem(LogConfig::default());
        for _ in 0..total {
            log.append(&rec(&payload)).unwrap();
        }
        log.sync().unwrap();
        let flushed = log.flushed_offset().get();
        assert!(flushed >= total, "all records flushed in one segment");
        assert_eq!(log.active_segment_id(), 0, "single un-sealed segment");

        eprintln!("#664 read_range_raw fixed-window={window} cost vs start_offset:");
        for frac in [1u64, 4, 8, 16, 32, 64, 128, 256, 512] {
            let start = (flushed / 1024) * frac;
            if start >= flushed {
                continue;
            }
            // Warm the seek index, then time a batch of identical fixed-window fetches.
            let _ = log
                .read_range_raw(Offset::new(start), window, None)
                .unwrap();
            let iters = 200u32;
            let t0 = std::time::Instant::now();
            for _ in 0..iters {
                let (run, _) = log
                    .read_range_raw(Offset::new(start), window, None)
                    .unwrap();
                std::hint::black_box(&run);
            }
            let per = t0.elapsed().as_nanos() / u128::from(iters);
            eprintln!("  start={start:>8}  per_fetch={per:>9} ns");
        }
    }

    /// #664 STREAMING-DRAIN micro-bench (ignored). Drains the WHOLE log forward in fixed windows
    /// via the same sequential `read_range_raw(next_offset)` a Tier-S consumer issues, and reports
    /// records/sec at several record counts. BEFORE the fix throughput HALVES per record-count
    /// doubling (the O(N^2) drain); AFTER it is FLAT.
    #[test]
    #[ignore = "perf micro-bench, run explicitly with --ignored --nocapture"]
    // The record counts here are <= 200k, far below f64's 2^52 exact-integer range, so the
    // records/sec ratio loses no precision; the cast is purely for the printed throughput.
    #[allow(clippy::cast_precision_loss)]
    fn micro_bench_664_sequential_drain_throughput() {
        let window = 256usize;
        let payload = [0u8; 100];
        eprintln!("#664 sequential drain throughput (window={window}):");
        for total in [20_000u64, 50_000, 100_000, 200_000] {
            let mut log = open_mem(LogConfig::default());
            for _ in 0..total {
                log.append(&rec(&payload)).unwrap();
            }
            log.sync().unwrap();
            let flushed = log.flushed_offset().get();
            let t0 = std::time::Instant::now();
            let mut next = 0u64;
            let mut drained = 0u64;
            while next < flushed {
                let (run, tail_from) = log.read_range_raw(Offset::new(next), window, None).unwrap();
                if run.record_count == 0 {
                    // Active-tail remainder: materialize forward (mirrors the engine's tail read).
                    let recs = log.read_range(Offset::new(next), window, None).unwrap();
                    if recs.is_empty() {
                        break;
                    }
                    drained += recs.len() as u64;
                    next = recs.last().unwrap().offset.get() + 1;
                    continue;
                }
                drained += run.record_count;
                next = run.next_offset.get();
                let _ = tail_from;
            }
            let secs = t0.elapsed().as_secs_f64();
            let rps = drained as f64 / secs;
            eprintln!("  total={total:>7}  drained={drained:>7}  {rps:>12.0} rec/s");
            assert_eq!(drained, flushed, "drained the whole log");
        }
    }

    // ----- C2-I4 (#599): Log::truncate_to leader-epoch divergence truncation primitive -----

    /// Read every segment file's full bytes keyed by name — the ground truth for byte-identity.
    fn dump_all_segments(log: &Log<InMemoryFs, ManualClock>) -> Vec<(String, Vec<u8>)> {
        let fs = log.filesystem();
        let mut out = Vec::new();
        for name in fs.list().unwrap() {
            let file = fs.open(&name).unwrap();
            let len = usize::try_from(file.len().unwrap()).unwrap();
            let mut buf = vec![0u8; len];
            file.read_exact_at(&mut buf, 0).unwrap();
            out.push((name, buf));
        }
        out.sort();
        out
    }

    #[test]
    fn truncate_to_drops_the_suffix_and_keeps_a_byte_identical_prefix() {
        // Build a log of 30 records that rolls across several small segments, then truncate to 13 (an
        // offset that lands mid-segment, so the kept segment is cut in its body).
        let mut log = open_mem(small_config());
        for i in 0..30u32 {
            log.append(&rec(format!("t{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        assert_eq!(log.next_offset(), Offset::new(30));

        // An independent reference log built with ONLY the first 13 records: the truncated log must
        // end byte-identical to it (recovery is a pure function of the surviving durable bytes).
        let mut reference = open_mem(small_config());
        for i in 0..13u32 {
            reference
                .append(&rec(format!("t{i:02}").as_bytes()))
                .unwrap();
        }
        reference.sync().unwrap();

        let outcome = log.truncate_to(Offset::new(13)).unwrap();
        assert_eq!(outcome.truncated_to, 13);
        assert_eq!(outcome.next_offset_before, 30);
        assert_eq!(outcome.records_dropped, 17);
        assert!(outcome.bytes_dropped > 0);
        assert!(outcome.segments_dropped >= 1, "the suffix spanned segments");

        // The log now ends exactly at offset 13, and is BYTE-IDENTICAL to the reference.
        assert_eq!(log.next_offset(), Offset::new(13));
        assert_eq!(log.flushed_offset(), Offset::new(13));
        assert_eq!(
            dump_all_segments(&log),
            dump_all_segments(&reference),
            "the truncated log is byte-identical to a fresh 13-record log"
        );

        // The surviving records decode correctly and the log keeps appending from 13.
        let recs = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(recs.len(), 13);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("t{i:02}").as_bytes());
        }
        log.append(&rec(b"new13")).unwrap();
        log.sync().unwrap();
        assert_eq!(log.next_offset(), Offset::new(14));
    }

    #[test]
    fn truncate_to_inside_a_preallocated_extension_cuts_at_the_frame_boundary() {
        // The admin truncate on an EXTENDED active segment (the production preallocate shape):
        // the record-position walk is bounded at the writer's data end (never reading the
        // roll-size zero tail eagerly), and the surgery still cuts exactly at the target's frame
        // boundary — dropping both the divergent records AND the logical extension, exactly as a
        // reopen-recovery would leave the file.
        let cfg = LogConfig {
            max_segment_bytes: 512 * 1024,
            ..LogConfig::default()
        };
        let mut log = open_mem(cfg);
        for i in 0..8u8 {
            log.append(&rec(&[i; 16])).unwrap();
        }
        log.sync().unwrap();
        // Write the logical extension out for real (the in-memory backend models the
        // reservation only).
        log.filesystem()
            .open(&segment_file_name(0))
            .unwrap()
            .set_len(cfg.max_segment_bytes)
            .unwrap();

        let outcome = log.truncate_to(Offset::new(5)).unwrap();
        assert_eq!(outcome.truncated_to, 5);
        assert_eq!(outcome.records_dropped, 3);
        assert_eq!(log.next_offset(), Offset::new(5));

        // The surviving records are intact and the extension is gone (a truncate-down).
        let recs = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(recs.len(), 5);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), &[u8::try_from(i).unwrap(); 16]);
        }
        assert!(
            log.filesystem()
                .open(&segment_file_name(0))
                .unwrap()
                .len()
                .unwrap()
                < cfg.max_segment_bytes,
            "the truncate cut the extension off with the suffix"
        );
        // Appending resumes cleanly at the truncation point.
        log.append(&rec(b"resumed")).unwrap();
        log.sync().unwrap();
        assert_eq!(log.next_offset(), Offset::new(6));
    }

    #[test]
    fn truncate_to_a_segment_boundary_unseals_the_predecessor_byte_identical() {
        // When `target` lands EXACTLY on a segment base offset, the empty segment is dropped wholesale
        // and its predecessor is UNSEALED into the active writer — the same shape a fresh log has, not
        // a sealed-tail-plus-empty-active artifact. We sweep every offset so a boundary hit is covered.
        for target in 1..30u64 {
            let mut log = open_mem(small_config());
            for i in 0..30u32 {
                log.append(&rec(format!("b{i:02}").as_bytes())).unwrap();
            }
            log.sync().unwrap();

            let mut reference = open_mem(small_config());
            for i in 0..u32::try_from(target).unwrap() {
                reference
                    .append(&rec(format!("b{i:02}").as_bytes()))
                    .unwrap();
            }
            reference.sync().unwrap();

            log.truncate_to(Offset::new(target)).unwrap();
            assert_eq!(log.next_offset(), Offset::new(target), "target {target}");
            assert_eq!(
                dump_all_segments(&log),
                dump_all_segments(&reference),
                "truncate to {target} is byte-identical to a fresh {target}-record log"
            );
        }
    }

    #[test]
    fn truncate_to_reopens_byte_identical_recovery_is_a_pure_function_of_durable_bytes() {
        // After a truncate, a REOPEN of the same filesystem yields an identical log — the truncation
        // left the durable bytes in a clean state recovery reconstructs deterministically.
        let fs = InMemoryFs::new();
        let mut log = Log::open(fs.clone(), ManualClock::new(), small_config()).unwrap();
        for i in 0..25u32 {
            log.append(&rec(format!("r{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        log.truncate_to(Offset::new(9)).unwrap();
        let after_truncate = dump_all_segments(&log);
        let next_after = log.next_offset();
        drop(log);

        let reopened = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        assert_eq!(reopened.next_offset(), next_after);
        assert_eq!(
            dump_all_segments(&reopened),
            after_truncate,
            "a reopen after truncation recovers the same bytes (I4 pure function)"
        );
        assert_eq!(reopened.read_from(Offset::ZERO, 100).unwrap().len(), 9);
    }

    #[test]
    fn truncate_to_within_a_single_active_segment_cuts_at_the_frame_boundary() {
        // A log that fits in ONE segment: truncating mid-segment cuts the active file at the record
        // frame boundary and resumes the writer there.
        let mut log = open_mem(LogConfig::default());
        for i in 0..8u32 {
            log.append(&rec(format!("s{i}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        assert_eq!(log.segment_count(), 1, "all 8 fit in one segment");

        let outcome = log.truncate_to(Offset::new(5)).unwrap();
        assert_eq!(outcome.records_dropped, 3);
        assert_eq!(outcome.segments_dropped, 0, "no whole segment was dropped");
        assert_eq!(log.next_offset(), Offset::new(5));
        let recs = log.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(recs.len(), 5);
        // The writer resumes: appending continues the offset/seq space from 5.
        let off = log.append(&rec(b"five")).unwrap();
        assert_eq!(off, Offset::new(5));
        assert_eq!(log.next_seq(), Seq::new(6));
    }

    #[test]
    fn truncate_to_the_head_is_a_clean_no_op() {
        let mut log = open_mem(small_config());
        for i in 0..10u32 {
            log.append(&rec(format!("h{i}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        let before = dump_all_segments(&log);
        let outcome = log.truncate_to(Offset::new(10)).unwrap();
        assert_eq!(outcome.records_dropped, 0);
        assert_eq!(outcome.bytes_dropped, 0);
        assert_eq!(outcome.segments_dropped, 0);
        assert_eq!(log.next_offset(), Offset::new(10));
        assert_eq!(
            dump_all_segments(&log),
            before,
            "head truncation changes nothing"
        );
    }

    #[test]
    fn truncate_to_zero_empties_the_log_but_keeps_it_writable() {
        let mut log = open_mem(small_config());
        for i in 0..12u32 {
            log.append(&rec(format!("z{i}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        let outcome = log.truncate_to(Offset::ZERO).unwrap();
        assert_eq!(outcome.records_dropped, 12);
        assert_eq!(log.next_offset(), Offset::ZERO);
        assert_eq!(log.read_from(Offset::ZERO, 100).unwrap().len(), 0);
        // The emptied log still appends from 0.
        let off = log.append(&rec(b"fresh")).unwrap();
        assert_eq!(off, Offset::ZERO);
    }

    #[test]
    fn truncate_to_out_of_range_fails_closed_and_leaves_the_log_untouched() {
        let mut log = open_mem(small_config());
        for i in 0..6u32 {
            log.append(&rec(format!("o{i}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        let before = dump_all_segments(&log);
        // Above the durable head: rejected.
        assert!(matches!(
            log.truncate_to(Offset::new(7)),
            Err(StorageError::TruncateOutOfRange {
                requested: 7,
                next_offset: 6,
                ..
            })
        ));
        // The log is untouched after the rejected truncation.
        assert_eq!(log.next_offset(), Offset::new(6));
        assert_eq!(dump_all_segments(&log), before);
        // It still works normally.
        log.append(&rec(b"still")).unwrap();
        assert_eq!(log.next_offset(), Offset::new(7));
    }

    #[test]
    fn truncate_to_crash_mid_surgery_reopens_to_a_valid_prefix_never_torn() {
        // #873 Phase 5 gap (i): a crash MID-`truncate_to` must reopen to a VALID, contiguous prefix —
        // never a torn/gapped chain, never losing a record below the truncation target. The
        // unlink-then-truncate order (whole tail segments unlinked FIRST, then the kept segment cut)
        // keeps every intermediate durable state valid-prefix-recoverable; this proves it across the two
        // interior crash windows, both reopened from the surviving durable bytes (a pure function, I4).
        use crate::fault::FaultFs;

        // WINDOW A: crash AFTER the whole tail segments are unlinked but BEFORE the kept segment's
        // `set_len` — the exact "segments unlinked, set_len not completed" window. The kept segment's
        // `record_byte_positions` read (which computes the cut boundary, run after the unlinks and before
        // `set_len`) faults, aborting the surgery with the kept segment still holding records above the
        // target.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let durable = fs.inner().clone();
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            log.append(&rec(format!("t{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        assert!(
            log.segment_count() >= 3,
            "the log must span several segments so the truncate unlinks whole ones"
        );
        let files_before = durable.list().unwrap().len();

        control.set_fail_read(true);
        assert!(
            log.truncate_to(Offset::new(13)).is_err(),
            "the mid-surgery read fault aborts the truncate"
        );
        // Prove we are genuinely in the "unlinked but not yet set_len" window: the whole tail segments
        // were already removed from the durable store before the read fault fired.
        assert!(
            durable.list().unwrap().len() < files_before,
            "the divergent tail segments were unlinked before the mid-surgery fault"
        );
        drop(log); // crash: the in-memory handles are gone; only the durable bytes survive.

        // Reopen from the surviving bytes (no fault): recovery reconstructs a valid prefix, never torn.
        let reopened = Log::open(durable, ManualClock::new(), small_config()).unwrap();
        let next = reopened.next_offset().get();
        assert!(
            (13..=30).contains(&next),
            "reopen recovered a valid prefix in [target, original] (got {next}), never short of the \
             target (no committed loss) and never a torn/over-long chain"
        );
        // The recovered prefix is DENSE and contiguous — no gap, no committed loss below the target, no
        // fabricated bytes leaking from the dropped suffix.
        let recs = reopened.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(
            recs.len() as u64,
            next,
            "the recovered prefix is dense and contiguous"
        );
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(
                r.payload.as_ref(),
                format!("t{i:02}").as_bytes(),
                "record {i} survived the aborted surgery intact"
            );
        }
        // The recovered log is fully writable: the aborted surgery left a clean state, not a frozen one.
        let mut reopened = reopened;
        reopened.append(&rec(b"afterA")).unwrap();
        reopened.sync().unwrap();
        assert_eq!(reopened.next_offset().get(), next + 1);

        // WINDOW B: crash AFTER the kept segment's `set_len` but BEFORE the final directory `sync_dir`
        // (the kept segment is already cut to the target on disk). Recovery lands on EXACTLY the target —
        // the fully-formed truncated prefix, no torn tail.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let durable = fs.inner().clone();
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            log.append(&rec(format!("t{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        // The kept segment's `sync_all` (issued immediately after its `set_len`) faults, aborting the
        // surgery after the byte-cut is durable but before the directory publish.
        control.set_fail_sync(true);
        assert!(
            log.truncate_to(Offset::new(13)).is_err(),
            "the post-set_len sync fault aborts the truncate"
        );
        drop(log);
        let reopened = Log::open(durable, ManualClock::new(), small_config()).unwrap();
        let next = reopened.next_offset().get();
        // The kept segment's byte-cut is already durable here (the fault fired on the sync AFTER the
        // `set_len`), so recovery lands on EXACTLY the truncation target — not merely somewhere in the
        // valid `[target, original]` band. (Tightened from a range check per review: this window's
        // outcome is deterministic.)
        assert_eq!(
            next, 13,
            "window B recovers to exactly the truncation target"
        );
        let recs = reopened.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(recs.len() as u64, next, "window B is dense and contiguous");
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("t{i:02}").as_bytes());
        }
    }

    #[test]
    fn truncate_to_crash_mid_multi_segment_unlink_reopens_to_a_contiguous_prefix() {
        // #873 Phase 5 gap: the divergent-tail unlink loop removes MANY whole segments under a single
        // trailing `sync_dir`. On a real FS, directory writeback can reorder unlinks across that fsync
        // barrier, so a crash mid-loop can leave only SOME removals durable. `truncate_to` unlinks
        // HIGHEST-id-first so whatever partial subset survives is always a CONTIGUOUS prefix
        // `[0, kept..k]` — always openable — never `[kept, <gap>, higher]` (which `scan_recover_chain`
        // rejects `SegmentChainBroken` -> an UNOPENABLE log). This models that exact reordered crash:
        // FaultFs fails the SECOND unlink, then we reopen the LIVE (most-flushed) store — the stronger
        // model than `simulate_power_loss` (which would revert the whole batch atomically and hide the
        // ordering entirely) — and assert recovery SUCCEEDS to a dense, contiguous prefix.
        //
        // Mutation check: reverting the unlink to lowest-id-first makes the surviving set
        // `[kept, <gap>, higher...]`, so `Log::open` below fails `SegmentChainBroken` and this test
        // fails — the fix is load-bearing.
        use crate::fault::FaultFs;

        let (fs, control) = FaultFs::new(InMemoryFs::new());
        // `durable` aliases the SAME in-memory disk (Arc-backed), so it observes every unlink the
        // aborted truncate made durable — the live, most-flushed image, NOT a power-loss revert.
        let durable = fs.inner().clone();
        let mut log = Log::open(fs, ManualClock::new(), small_config()).unwrap();
        for i in 0..30u32 {
            log.append(&rec(format!("t{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        // A low target keeps only the first segment(s), so the divergent tail is MANY (>=3) whole
        // segments — enough that a SECOND unlink genuinely runs (the mid-loop crash point).
        let seg_count = log.segment_count();
        assert!(
            seg_count >= 4,
            "need a >=3-segment divergent tail so a second unlink runs (got {seg_count} segments)"
        );
        let files_before = durable.list().unwrap().len();

        // Arm the crash on the SECOND unlink AFTER this point. `fail_remove_on` is RELATIVE to the
        // current `remove_count` (segment rolls already issued their own unlinks during the appends),
        // so this pins the second unlink of the truncate's own tail loop. Highest-first, that loop's
        // 1st unlink drops the TOP segment durably; its 2nd faults, so the loop aborts with the
        // surviving set still a contiguous prefix.
        let removes_before = control.remove_count();
        control.fail_remove_on(2);
        assert!(
            log.truncate_to(Offset::new(3)).is_err(),
            "the mid-loop unlink fault aborts the truncate"
        );
        // Prove we genuinely reached the second removal (no false pass) and that exactly ONE segment
        // was unlinked before the fault — the highest, leaving a contiguous prefix.
        assert_eq!(
            control.remove_count() - removes_before,
            2,
            "the truncate reached (and faulted on) the second unlink"
        );
        assert_eq!(
            durable.list().unwrap().len(),
            files_before - 1,
            "exactly the top divergent segment was unlinked before the crash"
        );
        drop(log); // crash: only the durable/live bytes survive.

        // Reopen the LIVE store: highest-first leaves `[0, kept..k-1]`, a valid contiguous prefix, so
        // recovery SUCCEEDS. (Lowest-first would leave a gap here and this `unwrap` would panic.)
        let reopened = Log::open(durable, ManualClock::new(), small_config()).unwrap();
        let next = reopened.next_offset().get();
        // No committed loss below the truncation target, and never an over-short chain: recovery lands
        // in the valid `[target, original]` band (the kept segments were never cut, so the surviving
        // prefix is over-long — a later reconcile re-truncates it idempotently).
        assert!(
            (3..=30).contains(&next),
            "recovered a valid over-long prefix in [target, original] (got {next})"
        );
        let recs = reopened.read_from(Offset::ZERO, 100).unwrap();
        assert_eq!(
            recs.len() as u64,
            next,
            "the recovered prefix is dense and contiguous — no gap, no torn tail"
        );
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(
                r.payload.as_ref(),
                format!("t{i:02}").as_bytes(),
                "record {i} survived the aborted multi-segment unlink intact"
            );
        }
        // The recovered log is fully writable: the aborted surgery left a clean prefix, not a frozen
        // or torn state.
        let mut reopened = reopened;
        reopened.append(&rec(b"after")).unwrap();
        reopened.sync().unwrap();
        assert_eq!(reopened.next_offset().get(), next + 1);
    }

    /// #822 discriminator for the OUTER cross-subtree recovery pool: [`par_recover_open`] MUST return
    /// results index-aligned to `items`, regardless of the order the workers finish — the whole
    /// determinism guarantee of parallel recovery rests on this reassembly. The closure deliberately
    /// finishes EARLIER indices LATER (a descending artificial delay), so a naive impl that collected
    /// in completion order would scramble the vector; the correct by-index reassembly stays ordered.
    /// (On a single-core box the pool runs inline in item order — still index-aligned — so this test
    /// is not flaky either way.)
    #[test]
    fn par_recover_open_returns_results_in_item_order_regardless_of_completion() {
        let items: Vec<usize> = (0..64).collect();
        let out = par_recover_open(&items, RECOVERY_OPEN_MAX_WORKERS, |&i| {
            // Earlier indices sleep LONGER, so completion order tends to be the REVERSE of item
            // order under real concurrency. Micros keep the test fast.
            std::thread::sleep(std::time::Duration::from_micros((64 - i as u64) * 4));
            Ok::<_, StorageError>(i * 10)
        });
        let values: Result<Vec<usize>, _> = out.into_iter().collect();
        let values = values.expect("no item errored");
        assert_eq!(
            values,
            items.iter().map(|&i| i * 10).collect::<Vec<_>>(),
            "results are index-aligned to the input, not to completion order"
        );
    }

    /// #822: [`par_recover_open`] surfaces the FIRST failing item's error in ITEM order (the caller
    /// `?`-propagates the index-aligned vector in order), so which error wins is deterministic and
    /// matches the serial loop — never whichever worker happened to fail first.
    #[test]
    fn par_recover_open_first_error_is_the_lowest_failing_index() {
        let items: Vec<usize> = (0..32).collect();
        let out = par_recover_open(&items, RECOVERY_OPEN_MAX_WORKERS, |&i| {
            if i == 7 || i == 20 {
                return Err(StorageError::SegmentIdMismatch {
                    file_id: i as u64,
                    header_id: 999,
                });
            }
            Ok::<_, StorageError>(i)
        });
        // Fold in item order exactly as the recovery callers do.
        let first_err = out.into_iter().collect::<Result<Vec<_>, _>>().unwrap_err();
        match first_err {
            StorageError::SegmentIdMismatch { file_id, .. } => assert_eq!(
                file_id, 7,
                "the lowest failing index wins, deterministically"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
