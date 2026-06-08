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

use crate::fs::Filesystem;
use crate::io::RandomAccessFile;
use crate::loss::{LossEvent, LossReport, ReasonCode};
use crate::naming::{segment_file_name, segment_ids};
use crate::segment::{OwnedRecord, RecoveryScan, SegmentReader, SegmentWriter, StorageError};
use ironbus_core::clock::Clock;
use ironbus_core::codec::RecordView;
use ironbus_core::format::{
    RECORD_HEADER_LEN, RECORD_TRAILER_LEN, SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN,
};
use ironbus_core::segment::SegmentHeader;
use ironbus_core::types::{Offset, RecordFlags, Seq};

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
    /// with the same non-fatal [`StorageError::AtCapacity`] the byte cap uses, so the shed flows
    /// through the existing #10 drop-new path (the engine counts it as `produce_rejected`) and the
    /// over-budget event is surfaced by [`Log::daily_budget_sheds`]. It NEVER weakens durability: an
    /// over-budget produce is DROPPED, never written unsynced. The today-counter resets at the UTC
    /// day boundary (`now_unix_millis / 86_400_000`), so the budget refreshes each day with no
    /// background timer.
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
    /// See [`LogConfig::max_total_bytes`] for the exact accounting and at-or-over semantics.
    #[must_use]
    pub fn with_max_total_bytes(mut self, max_total_bytes: u64) -> LogConfig {
        self.max_total_bytes = max_total_bytes;
        self
    }

    /// Sets the OPT-IN daily physical write budget ([`LogConfig::daily_physical_write_budget_bytes`])
    /// and returns the updated config. `0` (the default) disables the governor; any non-zero value
    /// opts in: once today's physical write volume reaches the budget, an append is shed with the
    /// non-fatal [`StorageError::AtCapacity`] (the #10 drop-new path) rather than weakening
    /// durability, and the over-budget shed is counted by [`Log::daily_budget_sheds`].
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
    /// for the active segment is `0` until it is sealed.
    record_count: u64,
    /// The maximum producer timestamp (milliseconds since the Unix epoch) across this segment's
    /// records, or `0` if it is empty. Tracked as the MAX (producer timestamps are not monotonic)
    /// so the age-retention reaper deletes a segment only when ALL its records are older than the
    /// bound. Meaningful for a SEALED segment, like `record_count`.
    max_timestamp_ms: u64,
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
    /// The durable (flushed) high-water mark: reads are bounded by this, so a reader
    /// never observes a record that is not yet on stable storage.
    flushed_offset: Offset,
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
    /// loss that recovery truncates to reach the last intact record. Zero for a fresh log
    /// or a clean recovery.
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
        let ids = segment_ids(&fs)?;
        match ids.last().copied() {
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
                    physical_bytes_written_today: 0,
                    physical_write_today_day: 0,
                    daily_budget_sheds: 0,
                };
                log.start_segment(FIRST_SEGMENT_ID, Seq::new(0), Offset::ZERO)?;
                Ok(log)
            }
            Some(last_id) => Self::recover(fs, clock, config, &ids, last_id),
        }
    }

    /// Walks every segment in ascending order from a streaming recovery scan, validating the
    /// chain (each segment's stored id matches its file name, its base continues from its
    /// predecessor, its records are a contiguous sequence run, and every NON-final segment is
    /// sealed) and accumulating the in-memory slots plus the running byte and record-count totals.
    /// A corrupt or unreadable segment fails its scan here, not silently at read time. The
    /// per-segment retention metadata (record count, max timestamp) is recomputed from the scan so
    /// the reaper behaves identically after a reopen.
    fn scan_recover_chain(fs: &F, ids: &[u64]) -> Result<RecoveredChain, StorageError> {
        let mut next_base_offset = 0u64;
        let mut next_base_seq = 0u64;
        let mut durable_bytes = 0u64;
        let mut total_record_count = 0u64;
        let mut highest: Option<RecoveryScan> = None;
        let mut slots: Vec<SegmentSlot> = Vec::with_capacity(ids.len());
        let total = ids.len();
        for (i, &id) in ids.iter().enumerate() {
            let scan = SegmentReader::open(fs.open(&segment_file_name(id))?)?.scan_recovery()?;
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
            // Everything recovered is durable, so the flush mark is the recovered head.
            flushed_offset: next_offset,
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
            physical_bytes_written_today: 0,
            physical_write_today_day: 0,
            daily_budget_sheds: 0,
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
                // Record the silent loss before dropping it, so an operator can see that a
                // torn or unsynced tail was discarded at recovery, both as a raw byte count
                // and as a structured loss event carrying the span and the reason (#120). The
                // records-lost estimate is a lower bound: the torn or corrupt span is, by
                // definition, not fully parseable, but at least the frame at `valid_end` is gone.
                log.recovered_truncated_bytes = len - scan.valid_end;
                let reason = scan.tail_reason.unwrap_or(ReasonCode::TornTail);
                let event = LossEvent::span(last_id, scan.valid_end, len, 1, reason);
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

        // I3: fail closed if recovery would drop more than the bounded-loss caps allow (#120),
        // rather than accept unbounded silent loss. The per-event cap is one segment or 64 MiB,
        // whichever is smaller. The global cap is 1% of the durable bytes, FLOORED at the
        // per-event cap so a single in-cap event (the normal torn tail, even on a tiny log whose
        // 1% is under one byte) is always within bounds; without that floor the literal 1% would
        // freeze a normal small-log recovery.
        let per_event_cap = log
            .config
            .max_segment_bytes
            .min(LossReport::PER_EVENT_BYTE_CAP);
        let global_cap = LossReport::global_loss_cap_bytes(durable_bytes).max(per_event_cap);
        log.loss_report
            .check_caps(per_event_cap, global_cap)
            .map_err(StorageError::ExcessiveRecoveryLoss)?;
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
        let writer = SegmentWriter::create(file, header)?;
        writer.sync()?; // the header is durable...
        self.fs.sync_dir()?; // ...and so is its directory entry.
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
        });
        Ok(())
    }

    /// Seals the active segment and starts the next one, continuing the offset and
    /// sequence space. The old segment is sealed (durable footer) BEFORE the new segment
    /// becomes discoverable, so a crash in between is recovered by rolling forward.
    fn roll(&mut self) -> Result<(), StorageError> {
        let next_id = self
            .active_id
            .checked_add(1)
            .ok_or(StorageError::SegmentFull)?;
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
        // The segment footer is durable physical write volume (#118): `seal` wrote and fsynced the
        // 32-byte footer, so charge it to the wear total here (the per-record frames and this
        // segment's header were charged on append and `start_segment`).
        self.charge_physical(SEGMENT_FOOTER_LEN as u64);
        self.sealed_record_bytes = self.sealed_record_bytes.saturating_add(old_record_bytes);
        self.start_segment(next_id, self.next_seq, self.next_offset)
            .map_err(|_| StorageError::WriterFrozen)?;
        // Sealing fsynced every record in the old segment, so the flush mark advances to
        // the start of the new segment even without an explicit sync.
        self.flushed_offset = self.next_offset;
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
    /// nothing is written and no offset or sequence advances. Returns
    /// [`StorageError::SegmentFull`] if the offset or sequence space is exhausted or the
    /// record is too large to frame, [`StorageError::WriterFrozen`] if a prior fatal error
    /// froze the writer, or an IO error from the write.
    pub fn append(&mut self, record: &Append<'_>) -> Result<Offset, StorageError> {
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
        // write volume is at or over the budget, shed this produce with the SAME non-fatal
        // `AtCapacity` the byte cap uses, so it flows through the existing #10 drop-new path (the
        // engine counts it as `produce_rejected`) and durability is never weakened (the record is
        // dropped, never written unsynced). The day meter is rolled first so the decision is never
        // stale across a UTC day boundary. Like the byte cap, the at-or-over check requires the
        // meter to be NON-ZERO, so the FIRST write of each day always goes through even if the
        // budget is smaller than one record (the broker always makes daily progress).
        let budget = self.config.daily_physical_write_budget_bytes;
        if budget != 0 {
            self.roll_physical_day_if_needed();
            let today = self.physical_bytes_written_today;
            if today >= budget && today > 0 {
                self.daily_budget_sheds = self.daily_budget_sheds.saturating_add(1);
                return Err(StorageError::AtCapacity {
                    durable_bytes: today,
                    cap: budget,
                });
            }
        }

        // Soft size cap: roll before appending if the active segment has reached the cap,
        // but never roll an empty one (so an oversized record still gets written).
        let active = self.active()?;
        if active.write_pos() >= self.config.max_segment_bytes && active.record_count() > 0 {
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
        let view = RecordView {
            seq,
            timestamp_ms: record.timestamp_ms,
            flags: record.flags,
            key: record.key,
            headers: record.headers,
            payload: record.payload,
        };
        let writer = self.active.as_mut().ok_or(StorageError::WriterFrozen)?;
        // The encoded FRAME length is the writer's write-position delta across the append (the
        // segment writer advances `write_pos` by exactly the encoded record's byte length: header +
        // body + trailer). Measuring the delta avoids re-encoding the record just to size it.
        let pos_before = writer.write_pos();
        let offset = writer.append(&view)?;
        let frame_len = self
            .active
            .as_ref()
            .map_or(0, |w| w.write_pos().saturating_sub(pos_before));
        // The ids advance only after the write returns Ok.
        self.next_seq = next_seq;
        self.next_offset = next_offset;
        // Write-amplification accounting (#118), charged only after the append returned Ok (a failed
        // append wrote nothing). Logical = the user payload the application asked us to store (key +
        // headers + payload, no framing); physical = the encoded frame actually written to the
        // segment. `physical / logical` over the run is the flash write-amplification ratio.
        let logical = record
            .key
            .len()
            .saturating_add(record.headers.len())
            .saturating_add(record.payload.len());
        self.logical_bytes_written = self
            .logical_bytes_written
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
        if self.active()?.sync().is_err() {
            self.active = None;
            return Err(StorageError::WriterFrozen);
        }
        // All appended records are now durable and become visible to readers.
        self.flushed_offset = self.next_offset;
        Ok(())
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

    /// Whether the writer is still live (an active segment is open). The writer freezes
    /// (`active` becomes `None`) when a fatal `fdatasync` fails (see [`Log::sync`]) or a segment
    /// roll fails; this reports that degraded state without a failing write, so a health check
    /// can surface it. Reads keep serving the durable prefix from a frozen writer.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.active.is_some()
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
        let oldest = self.segments.first().map_or(0, |slot| slot.base_offset);
        if start_v < oldest {
            return Err(StorageError::OffsetOutOfRange {
                requested: start_v,
                oldest,
            });
        }
        let mut out = Vec::new();
        for slot in &self.segments[self.segment_index_for(start_v)..] {
            if slot.base_offset >= flushed {
                // This segment, and every later one, begins beyond the durable end.
                break;
            }
            let scan = SegmentReader::open(self.fs.open(&segment_file_name(slot.id))?)?.scan()?;
            for record in scan.records {
                let offset = record.offset.get();
                if offset < start_v {
                    continue; // before the requested start (only in the first segment)
                }
                if offset >= flushed || out.len() >= max {
                    return Ok(out);
                }
                out.push(record);
            }
        }
        Ok(out)
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
        while let Some(next_base) = self.segments.get(1).map(|slot| slot.base_offset) {
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
            // Its end is exactly the next segment's base (contiguous), so every record in it is
            // strictly below `next_base <= protect_below_offset`, hence needed by no consumer.
            if next_base > protect_below_offset {
                break;
            }
            let name = segment_file_name(oldest.id);
            // The reaped segment's durable RECORD bytes and COUNT, read the SAME way the running
            // totals were accumulated (`valid_end - SEGMENT_HEADER_LEN` and `record_count`), so
            // both decrements are exact. A streaming recovery scan avoids materializing payloads.
            let scan = SegmentReader::open(self.fs.open(&name)?)?.scan_recovery()?;
            let segment_record_bytes = scan.valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64);
            let segment_record_count = scan.record_count;
            // Unlink, then dir-sync so the removal is durable, BEFORE touching in-memory state:
            // if either fails the slot stays and the running totals are untouched, so memory never
            // claims a segment is gone while it survives on disk.
            self.fs.remove(&name)?;
            self.fs.sync_dir()?;
            self.segments.remove(0);
            self.sealed_record_bytes = self
                .sealed_record_bytes
                .saturating_sub(segment_record_bytes);
            self.total_record_count = self.total_record_count.saturating_sub(segment_record_count);
            outcome.segments_reaped = outcome.segments_reaped.saturating_add(1);
            outcome.bytes_reaped = outcome.bytes_reaped.saturating_add(segment_record_bytes);
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
        let name = segment_file_name(oldest.id);
        // Read the reaped segment's durable RECORD bytes and COUNT the SAME way the running totals
        // were accumulated (`valid_end - SEGMENT_HEADER_LEN` and `record_count`), so both
        // decrements are exact. A streaming recovery scan avoids materializing payloads.
        let scan = SegmentReader::open(self.fs.open(&name)?)?.scan_recovery()?;
        let segment_record_bytes = scan.valid_end.saturating_sub(SEGMENT_HEADER_LEN as u64);
        let segment_record_count = scan.record_count;
        // Unlink, then dir-sync so the removal is durable, BEFORE touching in-memory state: if
        // either fails the slot stays and the running totals are untouched, so memory never claims
        // a segment is gone while it survives on disk.
        self.fs.remove(&name)?;
        self.fs.sync_dir()?;
        self.segments.remove(0);
        self.sealed_record_bytes = self
            .sealed_record_bytes
            .saturating_sub(segment_record_bytes);
        self.total_record_count = self.total_record_count.saturating_sub(segment_record_count);
        Ok(Some(ReapOutcome {
            segments_reaped: 1,
            bytes_reaped: segment_record_bytes,
        }))
    }

    /// The OLDEST retained log offset: the oldest segment's `base_offset`, the first offset still
    /// present in the durable log. `0` for a fresh log or one that has never been reaped. After a
    /// reap (consumer-safe [`Log::reap`] or forced [`Log::reap_oldest_forced`]) this rises to the
    /// surviving oldest segment's base, so a consumer below it has had its records reclaimed. A
    /// read at an offset below this is [`StorageError::OffsetOutOfRange`].
    #[must_use]
    pub fn earliest_offset(&self) -> Offset {
        Offset::new(self.segments.first().map_or(0, |slot| slot.base_offset))
    }

    /// The index in `segments` of the segment whose range holds `offset` (the slot with
    /// the largest `base_offset` not exceeding `offset`). Callers guarantee `offset` is
    /// at least the oldest base offset.
    fn segment_index_for(&self, offset: u64) -> usize {
        match self
            .segments
            .binary_search_by(|slot| slot.base_offset.cmp(&offset))
        {
            Ok(index) => index,
            Err(0) => 0,
            Err(index) => index - 1,
        }
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
        assert_eq!(records[0].payload, b"durable");
        assert_eq!(records[1].payload, b"after");
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
    fn the_daily_write_budget_sheds_when_today_exceeds_it() {
        // The opt-in daily physical write budget (#118): once today's physical writes reach the
        // budget, the next produce is shed with the non-fatal AtCapacity (the #10 drop-new path) and
        // the shed counter ticks; durability is never weakened (nothing is written). The first write
        // of the day always goes through (the at-or-over check requires a non-zero meter), so the
        // broker always makes daily progress. A budget just above one record's physical cost lets one
        // record through, then sheds.
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
            err.is_at_capacity(),
            "an over-budget produce sheds with the non-fatal AtCapacity, got {err:?}"
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
        let w1 = SegmentWriter::create(f1, header_at(1, 2)).unwrap();
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
    fn a_failed_roll_freezes_the_writer() {
        let mut log = open_mem(small_config());
        // Pre-create the file the next roll targets, so its create_new fails mid-roll.
        log.filesystem().create_new(&segment_file_name(1)).unwrap();
        let mut roll_err = None;
        for i in 0..20u8 {
            if let Err(e) = log.append(&rec(&[i; 20])) {
                roll_err = Some(e);
                break;
            }
            log.sync().unwrap();
        }
        // The roll's create_new hit AlreadyExists, which froze the writer: the freezing
        // append surfaces the fatal `WriterFrozen`, not a soft IO error.
        assert!(matches!(roll_err, Some(StorageError::WriterFrozen)));
        // The writer is frozen: further writes refuse, getters stay sane (no panic).
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
        assert_eq!(records[0].payload, b"a");
        assert_eq!(records[2].payload, b"c");
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
        assert_eq!(records[0].payload, b"durable");
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
        assert_eq!(records[1].payload, b"b");
    }

    #[test]
    fn reads_serve_the_durable_prefix_from_a_frozen_writer() {
        let mut log = open_mem(small_config());
        // Pre-create the file the first roll targets, so that roll fails and freezes.
        log.filesystem().create_new(&segment_file_name(1)).unwrap();
        let mut froze = false;
        for i in 0..30u8 {
            if log.append(&rec(&[i; 20])).is_err() {
                froze = true;
                break;
            }
            log.sync().unwrap();
        }
        assert!(froze, "a roll should have been attempted and failed");
        assert!(matches!(
            log.append(&rec(b"x")),
            Err(StorageError::WriterFrozen)
        ));
        // Reads ignore the writer and still serve the flushed prefix.
        let records = log.read_from(Offset::ZERO, 100).unwrap();
        assert!(!records.is_empty());
        assert_eq!(records.len() as u64, log.flushed_offset().get());
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
}
