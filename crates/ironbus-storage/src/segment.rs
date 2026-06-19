// SPDX-License-Identifier: MIT OR Apache-2.0
//! Writing and reading a single log segment on top of the [`RandomAccessFile`] seam.
//!
//! A segment file is a 64-byte header, a contiguous run of record frames, and (once
//! sealed) a 32-byte footer. The active segment IS the write-ahead log: a record is
//! durable once it has been written and the file fdatasync'd. This module appends
//! records and scans them back, stopping cleanly at a torn or corrupt tail, which is
//! the foundation of recovery.

use crate::io::RandomAccessFile;
use crate::loss::{CapViolation, ReasonCode};
use ironbus_core::codec::{self, DecodeError, RecordView};
use ironbus_core::format::{
    COMPACTION_META_LEN, RECORD_HEADER_LEN, SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN,
};
use ironbus_core::segment::{CompactionMeta, SegmentError, SegmentFooter, SegmentHeader};
use ironbus_core::types::{Offset, RecordFlags, Seq};
use std::io;

/// An error from the segment storage layer.
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// An underlying IO error.
    Io(io::Error),
    /// A record frame failed to decode.
    Record(DecodeError),
    /// A segment header or footer failed to decode.
    Segment(SegmentError),
    /// A sealed footer's `segment_id` did not match its header.
    FooterSegmentMismatch {
        /// The `segment_id` in the header.
        header: u64,
        /// The `segment_id` in the footer.
        footer: u64,
    },
    /// The segment is full: its record count or byte length would overflow.
    SegmentFull,
    /// Recovery found a non-final segment that is not sealed, so two segments would be
    /// appendable at once.
    UnsealedPredecessor {
        /// The id of the unsealed predecessor.
        segment_id: u64,
    },
    /// Recovery found a segment whose stored id does not match its file name.
    SegmentIdMismatch {
        /// The segment id taken from the file name.
        file_id: u64,
        /// The segment id stored in the header.
        header_id: u64,
    },
    /// Recovery found a segment whose base does not continue from its predecessor, so
    /// the offset or sequence space has a gap or overlap.
    SegmentChainBroken {
        /// The id of the segment that broke the chain.
        segment_id: u64,
        /// The base offset the segment should have had.
        expected_base_offset: u64,
        /// The base offset it actually carried.
        found_base_offset: u64,
        /// The base sequence the segment should have had.
        expected_base_seq: u64,
        /// The base sequence it actually carried.
        found_base_seq: u64,
    },
    /// Recovery found a record whose sequence number breaks the contiguous run from the
    /// segment `base_seq`, so the segment is structurally inconsistent.
    RecoveredSequenceMismatch {
        /// The record index within the segment.
        index: usize,
        /// The sequence the record should have carried (`base_seq + index`).
        expected: u64,
        /// The sequence actually stored.
        found: u64,
    },
    /// The log writer is frozen: a fatal IO error left it without a valid active
    /// segment, so it refuses further writes rather than risk corruption.
    WriterFrozen,
    /// A read requested an offset older than the oldest record still retained.
    OffsetOutOfRange {
        /// The requested offset.
        requested: u64,
        /// The oldest offset still present in the log.
        oldest: u64,
    },
    /// Recovery would drop more than the bounded-loss caps allow, so it fails closed rather
    /// than accept unbounded silent loss (#120, I3).
    ExcessiveRecoveryLoss(CapViolation),
    /// The durable log is at or over its configured byte cap, so a produce was REJECTED (the
    /// drop-new shed of the spill-then-shed overflow policy, refs #10, #13): nothing was
    /// written and no offset or sequence advanced. This is a NORMAL, recoverable shed, NOT a
    /// fatal freeze (the writer stays live): a later produce succeeds once retention frees
    /// space. A producer is told promptly so it never silently drops and never hangs.
    AtCapacity {
        /// The log's current total durable record bytes when the produce was rejected.
        durable_bytes: u64,
        /// The configured cap (`max_total_bytes`) the log met or exceeded.
        cap: u64,
    },
    /// The OPT-IN daily PHYSICAL write budget (#118), the flash-wear governor, is set and today's
    /// physical write volume has reached it, so a produce was REJECTED: a clean PRE-WRITE drop-new
    /// reject (nothing written, no offset or sequence advanced, durability never weakened) that is
    /// FINAL. It is a DISTINCT variant from [`StorageError::AtCapacity`] on purpose: the byte-cap
    /// shed can be relieved by reclaiming disk (so `DropOldest` may force-reap and retry), but no
    /// reap ever lowers today's physical-write meter, so a budget shed must NEVER trigger the
    /// `DropOldest` reap-retry loop. The day meter resets at the UTC day boundary, so a later
    /// produce on the next day succeeds; the writer stays live (this is not a fatal freeze).
    DailyWriteBudgetExceeded {
        /// The physical bytes written so far today when the produce was rejected.
        bytes_today: u64,
        /// The configured daily physical write budget the meter met or exceeded.
        budget: u64,
    },
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "io error: {e}"),
            StorageError::Record(e) => write!(f, "record decode error: {e}"),
            StorageError::Segment(e) => write!(f, "segment decode error: {e}"),
            StorageError::FooterSegmentMismatch { header, footer } => {
                write!(
                    f,
                    "footer segment_id {footer} does not match header {header}"
                )
            }
            StorageError::SegmentFull => write!(f, "segment is full"),
            StorageError::UnsealedPredecessor { segment_id } => {
                write!(f, "predecessor segment {segment_id} is not sealed")
            }
            StorageError::SegmentIdMismatch { file_id, header_id } => {
                write!(
                    f,
                    "segment file {file_id} holds a header for segment {header_id}"
                )
            }
            StorageError::SegmentChainBroken {
                segment_id,
                expected_base_offset,
                found_base_offset,
                expected_base_seq,
                found_base_seq,
            } => write!(
                f,
                "segment {segment_id} base ({found_base_offset},{found_base_seq}) \
                 does not continue from ({expected_base_offset},{expected_base_seq})"
            ),
            StorageError::RecoveredSequenceMismatch {
                index,
                expected,
                found,
            } => write!(
                f,
                "record {index} has sequence {found}, expected {expected}"
            ),
            StorageError::WriterFrozen => write!(f, "log writer is frozen after a fatal error"),
            StorageError::OffsetOutOfRange { requested, oldest } => write!(
                f,
                "read offset {requested} is older than the oldest retained offset {oldest}"
            ),
            StorageError::ExcessiveRecoveryLoss(v) => {
                write!(f, "recovery exceeded the bounded-loss cap: {v}")
            }
            StorageError::AtCapacity { durable_bytes, cap } => write!(
                f,
                "durable log is at capacity ({durable_bytes} of {cap} bytes); produce rejected"
            ),
            StorageError::DailyWriteBudgetExceeded {
                bytes_today,
                budget,
            } => write!(
                f,
                "daily physical write budget reached ({bytes_today} of {budget} bytes today); \
                 produce rejected"
            ),
        }
    }
}
impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(e) => Some(e),
            StorageError::Record(e) => Some(e),
            StorageError::Segment(e) => Some(e),
            StorageError::ExcessiveRecoveryLoss(e) => Some(e),
            _ => None,
        }
    }
}
impl From<io::Error> for StorageError {
    fn from(e: io::Error) -> Self {
        StorageError::Io(e)
    }
}
impl From<DecodeError> for StorageError {
    fn from(e: DecodeError) -> Self {
        StorageError::Record(e)
    }
}
impl From<SegmentError> for StorageError {
    fn from(e: SegmentError) -> Self {
        StorageError::Segment(e)
    }
}

impl StorageError {
    /// Whether this is the durable-log byte-cap shed ([`StorageError::AtCapacity`]): a normal,
    /// recoverable, drop-new rejection, distinct from a transient IO failure or a fatal writer
    /// freeze. Callers use it to surface a stable, distinct signal to a producer (a shed is not
    /// a transient failure) without matching the message text.
    ///
    /// This is ONLY the genuine disk-full byte-cap shed: it deliberately does NOT include the
    /// daily-write-budget shed ([`StorageError::DailyWriteBudgetExceeded`]), because reclaiming
    /// disk can relieve the byte cap (so the `DropOldest` policy may force-reap and retry on it)
    /// but no reap ever relieves the daily budget. Use [`StorageError::is_daily_write_budget_exceeded`]
    /// for that distinct, final shed.
    #[must_use]
    pub fn is_at_capacity(&self) -> bool {
        matches!(self, StorageError::AtCapacity { .. })
    }

    /// Whether this is the OPT-IN daily-write-budget shed ([`StorageError::DailyWriteBudgetExceeded`]),
    /// the flash-wear governor firing: a clean PRE-WRITE drop-new reject that is FINAL. It is kept
    /// separate from [`StorageError::is_at_capacity`] so the engine can treat it as a final reject
    /// under EVERY overflow policy (a reap never lowers today's physical-write meter, so the
    /// `DropOldest` force-reap loop must never be entered for it).
    #[must_use]
    pub fn is_daily_write_budget_exceeded(&self) -> bool {
        matches!(self, StorageError::DailyWriteBudgetExceeded { .. })
    }
}

/// An owned copy of a decoded record (the codec yields a borrowed view; a scan owns
/// its bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedRecord {
    /// The log offset assigned to this record.
    pub offset: Offset,
    /// The record's sequence number.
    pub seq: Seq,
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Record flags as stored.
    pub flags: RecordFlags,
    /// The routing or ordering key (empty if none).
    pub key: Vec<u8>,
    /// The record headers blob (empty if none).
    pub headers: Vec<u8>,
    /// The record payload.
    pub payload: Vec<u8>,
}

impl OwnedRecord {
    fn from_view(offset: Offset, v: &RecordView<'_>) -> OwnedRecord {
        OwnedRecord {
            offset,
            seq: v.seq,
            timestamp_ms: v.timestamp_ms,
            flags: v.flags,
            key: v.key.to_vec(),
            headers: v.headers.to_vec(),
            payload: v.payload.to_vec(),
        }
    }
}

/// Appends records to a segment file. The caller assigns monotonic sequence numbers
/// and rolls to a new segment by size or age.
#[derive(Debug)]
pub struct SegmentWriter<F: RandomAccessFile> {
    file: F,
    header: SegmentHeader,
    write_pos: u64,
    record_count: u32,
    last_seq: Seq,
    /// The maximum producer timestamp (milliseconds since the Unix epoch) across every record
    /// appended so far, or `0` if the segment is empty. Timestamps are producer-supplied and NOT
    /// necessarily monotonic, so the MAX (not the last) is tracked: the age-retention reaper
    /// deletes a sealed segment only when ALL its records are older than the bound, which the max
    /// answers. Maintained on each [`SegmentWriter::append`] so the running value is O(1).
    max_timestamp_ms: u64,
    /// Encoded record bytes appended but NOT yet written to the file (#452): records are parked
    /// here and written with ONE `write_all_at` at a flush point (a `sync`, the visible-head
    /// raise via `flush_pending`, the seal, or the spill cap), so a group-commit window costs
    /// one write syscall instead of one per record. Sound by construction: every reader is
    /// gated on the log's `flushed_offset`, which only advances at those same flush points, so
    /// parked bytes are unreadable until they are in the file. Durability is untouched: `sync`
    /// writes the pending bytes BEFORE its `fdatasync`, so durable means exactly what it meant.
    pending: Vec<u8>,
    /// The file position where `pending` begins: everything below it is already in the file.
    pending_base: u64,
}

/// The spill cap for the writer's pending buffer (#452): a relaxed durability level can run a
/// long unsynced window, so the buffer flushes to the file (one write, NO fsync) whenever it
/// reaches this size, bounding the writer's heap at a constant instead of the unsynced window.
const PENDING_SPILL_BYTES: usize = 256 * 1024;

impl<F: RandomAccessFile> SegmentWriter<F> {
    /// Creates a new segment, writing the header at offset 0. The file should be
    /// freshly created (see [`crate::io::StdFile::create_new`]).
    ///
    /// # Errors
    /// Propagates IO errors writing the header.
    pub fn create(file: F, header: SegmentHeader) -> Result<SegmentWriter<F>, StorageError> {
        file.write_all_at(&header.encode(), 0)?;
        Ok(SegmentWriter {
            file,
            header,
            write_pos: SEGMENT_HEADER_LEN as u64,
            record_count: 0,
            last_seq: header.base_seq,
            max_timestamp_ms: 0,
            pending: Vec::new(),
            pending_base: SEGMENT_HEADER_LEN as u64,
        })
    }

    /// Resumes appending to an existing, already-validated segment at its recovered
    /// write head, without rewriting the header.
    ///
    /// Recovery scans the segment, truncates any torn tail, and calls this with the
    /// recovered state: `write_pos` is the byte offset just past the last intact record
    /// (`SegmentScan::valid_end`), `record_count` is how many records precede it,
    /// `last_seq` is that last record's sequence, or the header `base_seq` if the
    /// segment is empty, and `max_timestamp_ms` is the maximum record timestamp recovery
    /// observed (or `0` if the segment is empty). The caller guarantees those match the
    /// bytes on disk; this constructor performs no IO.
    #[must_use]
    pub fn resume(
        file: F,
        header: SegmentHeader,
        write_pos: u64,
        record_count: u32,
        last_seq: Seq,
        max_timestamp_ms: u64,
    ) -> SegmentWriter<F> {
        SegmentWriter {
            file,
            header,
            write_pos,
            record_count,
            last_seq,
            max_timestamp_ms,
            pending: Vec::new(),
            pending_base: write_pos,
        }
    }

    /// Creates a fresh COMPACTED (`version` = 2) segment for the key-compaction cleaner (#337),
    /// writing the v2 header at offset 0. The header MUST carry the
    /// [`ironbus_core::format::SEGMENT_FLAG_COMPACTED`] flag, so its `version` byte encodes as 2.
    /// Unlike [`SegmentWriter::create`] the records this writer appends keep their ORIGINAL,
    /// now-SPARSE offsets and sequences ([`SegmentWriter::append_at`]) rather than the dense
    /// `base_offset + record_count` an ordinary append assigns, and the writer is sealed with the
    /// trailing v2 metadata block ([`SegmentWriter::seal_compacted`]).
    ///
    /// # Errors
    /// Propagates IO errors writing the header.
    pub fn create_compacted(
        file: F,
        header: SegmentHeader,
    ) -> Result<SegmentWriter<F>, StorageError> {
        debug_assert!(
            header.is_compacted(),
            "create_compacted requires the COMPACTED flag so the header encodes version 2"
        );
        file.write_all_at(&header.encode(), 0)?;
        Ok(SegmentWriter {
            file,
            header,
            write_pos: SEGMENT_HEADER_LEN as u64,
            record_count: 0,
            last_seq: header.base_seq,
            max_timestamp_ms: 0,
            pending: Vec::new(),
            pending_base: SEGMENT_HEADER_LEN as u64,
        })
    }

    /// Appends one survivor record at its ORIGINAL offset and sequence into a COMPACTED segment
    /// (#337), so the compacted segment is SPARSE: offsets are never renumbered or reused, which
    /// preserves invariant I5. Unlike [`SegmentWriter::append`] this does NOT derive the offset
    /// from `base_offset + record_count` (the survivors are not dense), and it does NOT validate
    /// sequence continuity (the survivor sequences are sparse too); the caller (the cleaner) passes
    /// records already in ascending offset order with their verbatim original ids. The frame stores
    /// the record's own `seq` from the [`RecordView`], so the survivor's original sequence lands on
    /// disk verbatim.
    ///
    /// # Errors
    /// Returns [`StorageError::SegmentFull`] if the byte length would overflow or the record is too
    /// large to frame, or an IO error from the write.
    pub fn append_at(
        &mut self,
        offset: Offset,
        record: &RecordView<'_>,
    ) -> Result<Offset, StorageError> {
        if self.record_count == u32::MAX {
            return Err(StorageError::SegmentFull);
        }
        // Encode survivors into the SHARED pending buffer and group-commit, exactly like the
        // ordinary `append` (#452, #503): the cold compaction path previously allocated a fresh
        // `Vec` and issued one `write_all_at` PER survivor (O(survivors) allocations + write
        // syscalls). Encoding directly into `pending` and flushing once per spill window collapses
        // that to one write per spill. The on-disk bytes are unchanged: the same encoded frames
        // land contiguously at the same byte positions; only the syscall grouping differs. The
        // spill cap bounds the buffer's heap regardless of how many survivors a compaction keeps.
        // `seal_compacted` flushes the pending tail before the footer, so the records are durably
        // in the file ahead of the commit (the footer/meta ordering is preserved).
        let before = self.pending.len();
        if codec::encode(record, &mut self.pending).is_err() {
            self.pending.truncate(before);
            return Err(StorageError::SegmentFull);
        }
        // On a length-overflow or byte-position overflow, truncate the buffer back so a rejected
        // survivor leaves no partial frame behind (the same contract `append` upholds).
        let Some(end) = u64::try_from(self.pending.len() - before)
            .ok()
            .and_then(|len| self.write_pos.checked_add(len))
        else {
            self.pending.truncate(before);
            return Err(StorageError::SegmentFull);
        };
        self.write_pos = end;
        // Spill: bound the buffer regardless of the survivor count, one write per spill window.
        if self.pending.len() >= PENDING_SPILL_BYTES {
            self.flush_pending()?;
        }
        self.record_count += 1;
        self.last_seq = record.seq;
        self.max_timestamp_ms = self.max_timestamp_ms.max(record.timestamp_ms);
        Ok(offset)
    }

    /// Seals a COMPACTED segment (#337): writes the v2 footer (version 2) immediately followed by
    /// the 44-byte v2 compaction-metadata block as ONE contiguous final write, then a full
    /// `sync_all`. The footer and the block become durable together, so a crash that leaves a torn
    /// block (failing its own CRC) is indistinguishable from a crash before the compaction commit
    /// point and recovery treats it as such (the originals win). This is the storage half of the
    /// atomic swap; the caller dir-fsyncs the parent directory next (the commit point) and then
    /// retires the originals.
    ///
    /// `footer.segment_id` and `meta` must describe this segment and its covered source range. The
    /// caller guarantees `footer.record_count` and `footer.last_seq` match the survivors appended.
    ///
    /// # Errors
    /// Propagates the underlying IO error writing or syncing the trailing bytes.
    pub fn seal_compacted(
        mut self,
        footer: &SegmentFooter,
        meta: &CompactionMeta,
    ) -> Result<(), StorageError> {
        // The survivor records must be IN the file before the footer+meta trailing write, exactly
        // as `seal` flushes before its footer (#452, #503): `append_at` now group-commits survivors
        // through the shared `pending` buffer, so flush the tail here so the footer follows the
        // records on disk. The byte layout is unchanged — the same encoded frames precede the
        // footer at the same positions — and the footer/meta commit ordering is preserved.
        self.flush_pending()?;
        // One contiguous trailing write: the 32-byte v2 footer then the 44-byte metadata block,
        // so footer + block are durable at the same instant after the single `sync_all`.
        let mut trailer = [0u8; SEGMENT_FOOTER_LEN + COMPACTION_META_LEN];
        trailer[..SEGMENT_FOOTER_LEN].copy_from_slice(&footer.encode_v2());
        trailer[SEGMENT_FOOTER_LEN..].copy_from_slice(&meta.encode());
        self.file.write_all_at(&trailer, self.write_pos)?;
        self.file.sync_all()?;
        Ok(())
    }

    /// The log offset the NEXT appended record will receive. Saturates at
    /// `u64::MAX` if the offset space is exhausted; [`SegmentWriter::append`] refuses
    /// to mint a wrapped offset and returns [`StorageError::SegmentFull`] instead.
    #[must_use]
    pub fn next_offset(&self) -> Offset {
        Offset::new(
            self.header
                .base_offset
                .get()
                .saturating_add(u64::from(self.record_count)),
        )
    }

    /// The number of records appended so far.
    #[must_use]
    pub fn record_count(&self) -> u32 {
        self.record_count
    }

    /// The maximum producer timestamp (milliseconds since the Unix epoch) across every record
    /// appended so far, or `0` if the segment is empty. Tracked as the MAX (not the last) because
    /// producer timestamps are not necessarily monotonic; the age-retention reaper deletes a
    /// sealed segment only when ALL its records are older than the bound, which the max answers.
    #[must_use]
    pub fn max_timestamp_ms(&self) -> u64 {
        self.max_timestamp_ms
    }

    /// The current write position (the byte length of the segment so far).
    #[must_use]
    pub fn write_pos(&self) -> u64 {
        self.write_pos
    }

    /// Appends one record and returns the log offset it was assigned. The record's
    /// `flags` `HAS_KEY` bit is derived from the key by the codec.
    ///
    /// # Errors
    /// Returns [`StorageError::SegmentFull`] if the record count or byte length would
    /// overflow, [`StorageError::Record`] if the record is too large to frame, or an
    /// IO error from the write.
    pub fn append(&mut self, record: &RecordView<'_>) -> Result<Offset, StorageError> {
        if self.record_count == u32::MAX {
            return Err(StorageError::SegmentFull);
        }
        // Offsets are monotonic and never reused; refuse to wrap the offset space
        // rather than mint a duplicate id (see `Offset::checked_next`).
        let offset = self
            .header
            .base_offset
            .get()
            .checked_add(u64::from(self.record_count))
            .ok_or(StorageError::SegmentFull)?;
        // Encode DIRECTLY into the pending buffer (#452): no per-record write syscall and no
        // intermediate copy. The bytes reach the file at the next flush point; on encode failure
        // the buffer is truncated back so a rejected record leaves no partial frame behind.
        let before = self.pending.len();
        if codec::encode(record, &mut self.pending).is_err() {
            self.pending.truncate(before);
            return Err(StorageError::SegmentFull);
        }
        let len =
            u64::try_from(self.pending.len() - before).map_err(|_| StorageError::SegmentFull)?;
        let end = self
            .write_pos
            .checked_add(len)
            .ok_or(StorageError::SegmentFull)?;
        self.write_pos = end;
        // Spill: bound the buffer regardless of how long a relaxed durability level defers the
        // sync. One write per spill still reduces syscalls by spill/record-size to one.
        if self.pending.len() >= PENDING_SPILL_BYTES {
            self.flush_pending()?;
        }
        self.record_count += 1;
        self.last_seq = record.seq;
        // Track the MAX timestamp (not the last): producer timestamps are not monotonic, and the
        // age-retention reaper needs the newest record's timestamp to know when the whole segment
        // has aged out.
        self.max_timestamp_ms = self.max_timestamp_ms.max(record.timestamp_ms);
        Ok(Offset::new(offset))
    }

    /// Flushes appended records to durable storage (fdatasync). A record is durable
    /// once this returns.
    ///
    /// # Errors
    /// Propagates the underlying IO error. A fatal sync error must be treated as
    /// terminal by the caller (the writer is frozen read-only).
    pub fn sync(&mut self) -> Result<(), StorageError> {
        // The pending bytes must be IN the file before the fdatasync, or durable would not mean
        // what it says (#452). A flush failure is the same fatal class as a failed sync.
        self.flush_pending()?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Writes the pending appended records to the file with ONE `write_all_at` (#452), making
    /// them readable (page cache) but NOT durable (no fsync). Called from every flush point:
    /// `sync` (before its fdatasync), the log's visible-head raise, the seal, and the spill cap.
    ///
    /// # Errors
    /// Propagates the underlying IO error; the caller treats it as the fatal frozen-writer class.
    pub fn flush_pending(&mut self) -> Result<(), StorageError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.file.write_all_at(&self.pending, self.pending_base)?;
        self.pending_base = self.write_pos;
        self.pending.clear();
        Ok(())
    }

    /// Seals the segment by writing the footer and a full fsync, consuming the writer
    /// and returning the footer.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    pub fn seal(mut self) -> Result<SegmentFooter, StorageError> {
        // The footer must FOLLOW the records in the file (#452): flush the pending tail first.
        self.flush_pending()?;
        let footer = SegmentFooter {
            segment_id: self.header.segment_id,
            last_seq: self.last_seq,
            record_count: self.record_count,
        };
        self.file.write_all_at(&footer.encode(), self.write_pos)?;
        self.file.sync_all()?;
        Ok(footer)
    }
}

/// The result of scanning a segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentScan {
    /// The validated segment header.
    pub header: SegmentHeader,
    /// The records recovered, in order, up to the first torn or corrupt frame.
    pub records: Vec<OwnedRecord>,
    /// The sealed footer, if the segment was cleanly sealed.
    pub footer: Option<SegmentFooter>,
    /// `true` if every byte up to the footer or end was a valid record (no torn or
    /// corrupt tail was encountered).
    pub clean: bool,
    /// The byte offset at which the valid record region ends (the durable valid
    /// prefix length). For a sealed segment this is the start of the footer, so it
    /// excludes the trailing 32 footer bytes.
    pub valid_end: u64,
}

/// The metadata [`Log::recover`] needs to resume a segment, without materializing record
/// payloads. A streaming scan ([`SegmentReader::scan_recovery`]) produces it by reading
/// one record at a time, so recovery memory is bounded by the largest single record
/// instead of the whole record region (#156). `record_count`, `last_seq`, and `valid_end`
/// match what [`SegmentReader::scan`] would report; the per-record bytes are validated
/// (header and body CRC, sequence continuity) and then dropped.
#[derive(Debug, Clone)]
pub struct RecoveryScan {
    /// The validated segment header.
    pub header: SegmentHeader,
    /// The sealed footer, if the segment was cleanly sealed (same trust rules as `scan`).
    pub footer: Option<SegmentFooter>,
    /// How many valid records precede the first torn or corrupt frame.
    pub record_count: u64,
    /// The maximum producer timestamp (milliseconds since the Unix epoch) across the valid
    /// records, or `0` if there are none. Recovery recomputes the per-segment max so the
    /// age-retention reaper behaves identically after a reopen. The max (not the last) is tracked
    /// because producer timestamps are not necessarily monotonic.
    pub max_timestamp_ms: u64,
    /// The sequence of the last valid record, or the segment's `base_seq` if there are none.
    pub last_seq: Seq,
    /// `true` if every byte up to the footer or end was a valid record (no torn tail).
    pub clean: bool,
    /// Why the valid prefix ended early, if it did: the reason the bytes after `valid_end`
    /// were dropped (a torn tail or a corrupt frame). `None` for a clean or sealed segment.
    pub tail_reason: Option<ReasonCode>,
    /// The byte offset at which the valid record region ends (the durable prefix length).
    pub valid_end: u64,
}

/// The result of scanning a COMPACTED (`version` = 2) segment (#337): the validated v2 header, its
/// SPARSE survivor records (in ascending offset order, with their ORIGINAL offsets and sequences),
/// the v2 footer, and the trailing compaction-metadata block declaring the covered source range.
///
/// A compacted segment's records are SPARSE: the survivor sequences are not contiguous, so the
/// dense `seq == base_seq + index` continuity check the ordinary scan applies does NOT hold here.
/// Instead each frame is CRC-validated and its sequence is required only to be strictly INCREASING
/// and to fall within the covered sequence span; the covered offset/sequence spans come from the
/// trailing block, not from the survivor count. The block's own CRC gates trust: a torn or
/// mismatched block (or a missing/short one) makes the segment NOT a valid compacted segment, which
/// recovery treats as a crash before the compaction commit point (the originals win).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactedScan {
    /// The validated v2 segment header (the COMPACTED flag is set).
    pub header: SegmentHeader,
    /// The survivor records, in ascending offset order, with their original sparse offsets/seqs.
    pub records: Vec<OwnedRecord>,
    /// The v2 footer (record count and last survivor sequence).
    pub footer: SegmentFooter,
    /// The trailing v2 compaction-metadata block: the covered source offset/sequence spans and the
    /// highest covered source id, which recovery uses to resolve an overlapping range.
    pub meta: CompactionMeta,
    /// The byte offset at which the record region ends (the start of the footer).
    pub valid_end: u64,
    /// The maximum producer timestamp across the survivors (or `0` if empty), for the reaper.
    pub max_timestamp_ms: u64,
}

/// The result of [`SegmentReader::compacted_byte_positions`] (#481): each SPARSE survivor's
/// `(original log offset, frame START byte position)` in ascending offset order, paired with the
/// byte offset at which the survivor region ends (the footer start, the read-forward upper bound).
/// `None` (wrapped by the method's `Result<Option<_>, _>`) when the segment is not a valid compacted
/// segment, exactly as [`SegmentReader::scan_compacted`] returns `None`.
pub type CompactedPositions = (Vec<(u64, u64)>, u64);

/// The result of a frame-position walk (#483): see [`SegmentReader::walk_positions`]. Carries the
/// per-record frame START positions delimiting the valid prefix, plus the bytes consumed and the
/// clean/torn flag the seal check needs, without materializing record payloads.
struct PositionWalk {
    /// Each valid record's frame START byte position, in offset order.
    positions: Vec<u64>,
    /// The last valid record's sequence (`None` if the region held no record), for the seal check.
    last_seq: Option<Seq>,
    /// Bytes consumed relative to the walk's start offset (the valid prefix length).
    cursor: u64,
    /// `true` if the region decoded cleanly with no torn or corrupt tail.
    clean: bool,
}

/// The running result of a streaming body walk: see [`SegmentReader::scan_body_streaming`].
struct BodyWalk {
    /// Valid records seen before the first torn or corrupt frame.
    count: u64,
    /// The maximum producer timestamp across the valid records (or `0` if none).
    max_timestamp_ms: u64,
    /// The last valid record's sequence (or the caller's base seq if none).
    last_seq: Seq,
    /// Bytes consumed relative to the walk's start offset.
    cursor: u64,
    /// `true` if the region decoded cleanly with no torn or corrupt tail.
    clean: bool,
    /// Why the walk stopped early, if it did (torn tail or corrupt frame). `None` when clean.
    tail_reason: Option<ReasonCode>,
}

/// Reads a segment file: validates the header and scans its records.
#[derive(Debug)]
pub struct SegmentReader<F: RandomAccessFile> {
    file: F,
    header: SegmentHeader,
    file_len: u64,
}

impl<F: RandomAccessFile> SegmentReader<F> {
    /// Opens a segment, reading and validating its 64-byte header.
    ///
    /// # Errors
    /// Returns [`StorageError::Segment`] if the header is missing or invalid, or an
    /// IO error.
    pub fn open(file: F) -> Result<SegmentReader<F>, StorageError> {
        let file_len = file.len()?;
        if file_len < SEGMENT_HEADER_LEN as u64 {
            // Too short to hold a header: a typed structural error, not a raw IO EOF.
            return Err(StorageError::Segment(SegmentError::Truncated));
        }
        let mut hbuf = [0u8; SEGMENT_HEADER_LEN];
        file.read_exact_at(&mut hbuf, 0)?;
        let header = SegmentHeader::decode(&hbuf)?;
        Ok(SegmentReader {
            file,
            header,
            file_len,
        })
    }

    /// The validated header.
    #[must_use]
    pub fn header(&self) -> &SegmentHeader {
        &self.header
    }

    /// Scans the segment: reads the record region, decodes records in order, and
    /// stops at the first torn or corrupt frame, returning the records before that
    /// point as the durable valid prefix.
    ///
    /// A trailing footer is trusted as a seal only when it is consistent with the
    /// body: the record region must decode cleanly up to exactly the footer, and the
    /// footer's `record_count` and `last_seq` must match the recovered records. A
    /// footer that disagrees with the body, whether a torn sealed tail or 32 trailing
    /// bytes that merely look like a footer (coincidental or forged through record
    /// payload), is not trusted, and the segment is recovered as unsealed. Only a
    /// footer that sits exactly at the record-region boundary AND describes the body
    /// but names a different segment is a hard error: that is a recycled or mixed-up
    /// file, not an unsealed tail.
    ///
    /// # Errors
    /// Returns [`StorageError::FooterSegmentMismatch`] if a body-consistent footer
    /// names a different segment, or an IO error.
    pub fn scan(&self) -> Result<SegmentScan, StorageError> {
        let header_end = SEGMENT_HEADER_LEN as u64;
        let footer_len = SEGMENT_FOOTER_LEN as u64;

        // Decode the trailing 32 bytes as a footer CANDIDATE only. It is validated
        // against the record body below before being trusted, so neither coincidental
        // nor forged tail bytes can fake a seal and hide synced records.
        let candidate = if self.file_len >= header_end + footer_len {
            let mut fbuf = [0u8; SEGMENT_FOOTER_LEN];
            self.file
                .read_exact_at(&mut fbuf, self.file_len - footer_len)?;
            SegmentFooter::decode(&fbuf).ok()
        } else {
            None
        };

        if let Some(footer) = candidate {
            let body_end = self.file_len - footer_len;
            let (records, cursor, clean) = self.scan_body(header_end, body_end)?;
            let ends_at_footer = clean && header_end + cursor == body_end;
            let expected_last_seq = records.last().map_or(self.header.base_seq, |r| r.seq);
            let body_matches = u64::from(footer.record_count) == records.len() as u64
                && footer.last_seq == expected_last_seq;
            if ends_at_footer && body_matches {
                // The footer truly describes this body. It is a genuine seal only if
                // it is bound to this segment; a different id is a recycled/mixed file.
                if footer.segment_id != self.header.segment_id {
                    return Err(StorageError::FooterSegmentMismatch {
                        header: self.header.segment_id,
                        footer: footer.segment_id,
                    });
                }
                return Ok(SegmentScan {
                    header: self.header,
                    records,
                    footer: Some(footer),
                    clean: true,
                    valid_end: body_end,
                });
            }
            // The candidate does not describe the body: treat the segment as unsealed
            // and recover the valid prefix from the full file (the candidate bytes are
            // then just record data or a torn tail).
        }

        let (records, cursor, clean) = self.scan_body(header_end, self.file_len)?;
        Ok(SegmentScan {
            header: self.header,
            records,
            footer: None,
            clean,
            valid_end: header_end + cursor,
        })
    }

    /// Reads `[start, end)` and decodes records forward, stopping at the first torn or
    /// corrupt frame. Returns the records, the number of bytes consumed (relative to
    /// `start`), and whether the whole region decoded cleanly (no torn tail).
    fn scan_body(
        &self,
        start: u64,
        end: u64,
    ) -> Result<(Vec<OwnedRecord>, u64, bool), StorageError> {
        let body_len =
            usize::try_from(end.saturating_sub(start)).map_err(|_| StorageError::SegmentFull)?;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            self.file.read_exact_at(&mut body, start)?;
        }
        let mut records = Vec::new();
        let mut cursor = 0usize;
        let mut clean = true;
        while cursor < body.len() {
            // A torn or corrupt frame ends the valid prefix; recovery skips the rest.
            // The bounded-loss report is produced by a later layer.
            let Ok((view, consumed)) = codec::decode(&body[cursor..]) else {
                clean = false;
                break;
            };
            let offset = Offset::new(
                self.header
                    .base_offset
                    .get()
                    .saturating_add(records.len() as u64),
            );
            records.push(OwnedRecord::from_view(offset, &view));
            cursor += consumed;
        }
        Ok((records, cursor as u64, clean))
    }

    /// Walks the DENSE (v1) record region front to back and returns, for each valid record, the
    /// byte position at which its frame starts (#483). The Nth returned position is the file
    /// offset of the record whose log offset is `base_offset + N`, so the caller can build a
    /// resident `offset -> byte position` seek index. The walk decodes one frame at a time exactly
    /// as [`SegmentReader::scan`] does (same torn/corrupt-tail stop), so the positions delimit the
    /// SAME valid prefix `scan` would materialize; it stops at the first frame that does not decode.
    /// It validates each frame's HEADER CRC (the length field a position step depends on is inside
    /// that CRC-protected header), but it does NOT materialize or body-CRC the records — that full
    /// validation happens when [`SegmentReader::scan_from`] later reads the records the index points
    /// at. Returns the positions and the byte offset at which the valid prefix ends (`valid_end`),
    /// which equals what `scan` reports.
    ///
    /// The active (unsealed) segment is walked over the whole file; a sealed segment's trailing
    /// 32-byte footer is excluded first (a body-consistent seal), so a coincidental or torn footer
    /// is treated as record data exactly as in `scan`, keeping the index's valid prefix identical.
    ///
    /// # Errors
    /// Returns [`StorageError::FooterSegmentMismatch`] if a body-consistent footer names a
    /// different segment (the same recycled/mixed-file guard `scan` applies), or an IO error.
    pub fn record_byte_positions(&self) -> Result<(Vec<u64>, u64), StorageError> {
        let header_end = SEGMENT_HEADER_LEN as u64;
        let footer_len = SEGMENT_FOOTER_LEN as u64;

        // Mirror `scan`'s seal handling so the walked region is byte-identical: a trailing footer is
        // trusted (and excluded) only when it is consistent with the body. To decide that without a
        // second full materialization, walk the body once and reuse the result for both the seal
        // check and the position list.
        let candidate = if self.file_len >= header_end + footer_len {
            let mut fbuf = [0u8; SEGMENT_FOOTER_LEN];
            self.file
                .read_exact_at(&mut fbuf, self.file_len - footer_len)?;
            SegmentFooter::decode(&fbuf).ok()
        } else {
            None
        };

        if let Some(footer) = candidate {
            let body_end = self.file_len - footer_len;
            let walk = self.walk_positions(header_end, body_end)?;
            let ends_at_footer = walk.clean && header_end + walk.cursor == body_end;
            let expected_last_seq = walk.last_seq.unwrap_or(self.header.base_seq);
            let body_matches = u64::from(footer.record_count) == walk.positions.len() as u64
                && footer.last_seq == expected_last_seq;
            if ends_at_footer && body_matches {
                if footer.segment_id != self.header.segment_id {
                    return Err(StorageError::FooterSegmentMismatch {
                        header: self.header.segment_id,
                        footer: footer.segment_id,
                    });
                }
                return Ok((walk.positions, body_end));
            }
            // The candidate does not describe the body: treat the segment as unsealed and walk the
            // valid prefix from the full file, exactly as `scan` does.
        }

        let walk = self.walk_positions(header_end, self.file_len)?;
        Ok((walk.positions, header_end + walk.cursor))
    }

    /// Walks `[start, end)` decoding one frame at a time and collecting each frame's START position,
    /// stopping at the first torn or corrupt frame. The decode is the SAME CRC-gated step
    /// `scan_body` uses, so the prefix it accepts is identical.
    fn walk_positions(&self, start: u64, end: u64) -> Result<PositionWalk, StorageError> {
        let body_len =
            usize::try_from(end.saturating_sub(start)).map_err(|_| StorageError::SegmentFull)?;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            self.file.read_exact_at(&mut body, start)?;
        }
        let mut positions = Vec::new();
        let mut cursor = 0usize;
        let mut clean = true;
        let mut last_seq = None;
        while cursor < body.len() {
            let Ok((view, consumed)) = codec::decode(&body[cursor..]) else {
                clean = false;
                break;
            };
            positions.push(start + cursor as u64);
            last_seq = Some(view.seq);
            cursor += consumed;
        }
        Ok(PositionWalk {
            positions,
            last_seq,
            cursor: cursor as u64,
            clean,
        })
    }

    /// Reads up to `max` DENSE (v1) records starting at the file byte position `start_byte`,
    /// FULLY validating each materialized record (header AND body CRC, via the same
    /// `codec::decode` the scan uses) and stopping at the first torn or corrupt frame or after
    /// `max` records (#483). The record at `start_byte` is assigned log offset `start_offset` and
    /// each subsequent record the next consecutive offset, so the caller seeks an index-resolved
    /// byte position and reads forward WITHOUT rescanning the segment from its base. `start_byte`
    /// MUST be a real frame boundary (an index entry); reading mid-frame would fail the CRC and
    /// stop, never returning a bogus record.
    ///
    /// `read_end` bounds the read: no frame whose body would extend at or past it is materialized
    /// (the caller passes the segment's `valid_end` so a torn tail beyond the durable prefix is
    /// never read). Returns the records in offset order.
    ///
    /// # Errors
    /// Returns an IO error from reading the region. A torn or corrupt frame is NOT an error: it
    /// ends the returned prefix, exactly as `scan` stops at the first bad frame.
    pub fn scan_from(
        &self,
        start_byte: u64,
        start_offset: Offset,
        read_end: u64,
        max: usize,
    ) -> Result<Vec<OwnedRecord>, StorageError> {
        if max == 0 || start_byte >= read_end {
            return Ok(Vec::new());
        }
        let len = usize::try_from(read_end.saturating_sub(start_byte))
            .map_err(|_| StorageError::SegmentFull)?;
        let mut body = vec![0u8; len];
        self.file.read_exact_at(&mut body, start_byte)?;
        let mut records = Vec::with_capacity(max.min(64));
        let mut cursor = 0usize;
        let mut next_offset = start_offset.get();
        while cursor < body.len() && records.len() < max {
            // The SAME CRC-gated decode `scan_body` uses: a torn or corrupt frame ends the prefix.
            let Ok((view, consumed)) = codec::decode(&body[cursor..]) else {
                break;
            };
            records.push(OwnedRecord::from_view(Offset::new(next_offset), &view));
            next_offset = next_offset.saturating_add(1);
            cursor += consumed;
        }
        Ok(records)
    }

    /// Scans a COMPACTED (`version` = 2) segment (#337): validates the v2 header (the caller's
    /// [`SegmentReader::open`] already accepted it), reads its SPARSE survivor records, the v2
    /// footer, and the trailing 44-byte compaction-metadata block, and returns them as a
    /// [`CompactedScan`]. Returns `Ok(None)` when the segment is NOT a valid compacted segment
    /// (the header lacks the COMPACTED flag, or the trailing footer/block is torn, short, or
    /// CRC-mismatched), which recovery treats as a crash before the compaction commit point (the
    /// originals remain authoritative).
    ///
    /// Unlike the ordinary scan, the survivor sequences are NOT required to be contiguous (they are
    /// sparse), only CRC-valid and strictly INCREASING and within the covered sequence span. Each
    /// survivor's ORIGINAL log offset is reconstructed from its stored sequence and the constant
    /// offset-minus-sequence delta (`base_offset - base_seq`), which is invariant across the whole
    /// log because offsets and sequences advance in lockstep from the origin; a compacted segment
    /// keeps the same delta, so the survivor offsets are exact.
    ///
    /// # Errors
    /// Returns [`StorageError::FooterSegmentMismatch`] if the footer names a different segment,
    /// [`StorageError::RecoveredSequenceMismatch`] if a survivor's sequence is out of order or out
    /// of the covered span, or an IO error.
    pub fn scan_compacted(&self) -> Result<Option<CompactedScan>, StorageError> {
        if !self.header.is_compacted() {
            return Ok(None);
        }
        let header_end = SEGMENT_HEADER_LEN as u64;
        let footer_len = SEGMENT_FOOTER_LEN as u64;
        let block_len = COMPACTION_META_LEN as u64;
        // A compacted segment's final bytes are [records][footer(32)][meta block(44)]. Anything
        // shorter than header + footer + block cannot be a valid compacted segment.
        if self.file_len < header_end + footer_len + block_len {
            return Ok(None);
        }
        // Decode the trailing 44 bytes as the compaction-metadata block, and the 32 bytes before it
        // as the v2 footer. The block's own CRC gates trust: a torn/short/mismatched block means
        // this is not a committed compacted segment (treat as crash-before-commit).
        let block_start = self.file_len - block_len;
        let footer_start = block_start - footer_len;
        let mut mbuf = [0u8; COMPACTION_META_LEN];
        self.file.read_exact_at(&mut mbuf, block_start)?;
        let Ok(meta) = CompactionMeta::decode(&mbuf) else {
            return Ok(None);
        };
        let mut fbuf = [0u8; SEGMENT_FOOTER_LEN];
        self.file.read_exact_at(&mut fbuf, footer_start)?;
        let Ok(footer) = SegmentFooter::decode(&fbuf) else {
            return Ok(None);
        };

        // Read and validate the SPARSE survivor records. The offset-minus-seq delta is constant for
        // the whole log, so each survivor's original offset is `seq + delta` where `delta` is the
        // header's `base_offset - base_seq`. Sequences must be strictly increasing and within the
        // covered span; a CRC failure or an out-of-span/out-of-order sequence is a hard error (a
        // corrupt compacted segment is never silently served).
        let base_off = self.header.base_offset.get();
        let base_seq = self.header.base_seq.get();
        let body_len = usize::try_from(footer_start.saturating_sub(header_end))
            .map_err(|_| StorageError::SegmentFull)?;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            self.file.read_exact_at(&mut body, header_end)?;
        }
        let mut records: Vec<OwnedRecord> = Vec::new();
        let mut cursor = 0usize;
        let mut max_timestamp_ms = 0u64;
        let mut prev_seq: Option<u64> = None;
        while cursor < body.len() {
            let Ok((view, consumed)) = codec::decode(&body[cursor..]) else {
                // A torn or corrupt frame inside a committed compacted segment is corruption, not a
                // torn tail (the footer+block are present and CRC-valid past this point), so the
                // segment is structurally inconsistent: refuse it rather than serve a partial set.
                return Ok(None);
            };
            let seq = view.seq.get();
            // Strictly increasing and within the covered sequence span.
            if seq < base_seq || seq >= meta.covered_end_seq || prev_seq.is_some_and(|p| seq <= p) {
                return Err(StorageError::RecoveredSequenceMismatch {
                    index: records.len(),
                    expected: prev_seq.map_or(base_seq, |p| p + 1),
                    found: seq,
                });
            }
            prev_seq = Some(seq);
            // Reconstruct the original offset from the constant offset-minus-seq delta.
            let offset = Offset::new(base_off.wrapping_add(seq.wrapping_sub(base_seq)));
            max_timestamp_ms = max_timestamp_ms.max(view.timestamp_ms);
            records.push(OwnedRecord::from_view(offset, &view));
            cursor += consumed;
        }
        // The footer must describe THIS body and bind to THIS segment id.
        if footer.segment_id != self.header.segment_id {
            return Err(StorageError::FooterSegmentMismatch {
                header: self.header.segment_id,
                footer: footer.segment_id,
            });
        }
        if u64::from(footer.record_count) != records.len() as u64
            || cursor as u64 != footer_start - header_end
        {
            // The footer's record count or the body length disagrees with the decoded survivors:
            // the segment is not a self-consistent compacted segment.
            return Ok(None);
        }
        Ok(Some(CompactedScan {
            header: self.header,
            records,
            footer,
            meta,
            valid_end: footer_start,
            max_timestamp_ms,
        }))
    }

    // ---- #481 compacted seek-index primitives: compacted_byte_positions + scan_compacted_from ----

    /// Walks a COMPACTED (`version` = 2) segment ONCE and returns, for each SPARSE survivor, its
    /// reconstructed original log offset paired with its frame START byte position, plus the byte
    /// offset at which the record region ends (the footer start) (#481). This is the build half of
    /// the resident compacted seek index: it applies EXACTLY the same structural validation
    /// [`SegmentReader::scan_compacted`] does (the trailing footer + 44-byte compaction block must be
    /// present and CRC-valid, every frame must decode, each survivor sequence must be strictly
    /// increasing and within the covered span, the footer must bind to this segment and agree with
    /// the body), so it returns `Ok(None)` in precisely the cases `scan_compacted` returns `None`
    /// (not a committed compacted segment / structurally inconsistent) and the SAME hard errors
    /// otherwise. It differs only in WHAT it materializes: `(offset, byte_pos)` pairs in ascending
    /// offset order instead of the decoded records, so the caller can later SEEK to any survivor's
    /// frame and read forward via [`SegmentReader::scan_compacted_from`] instead of re-reading and
    /// re-decoding the whole survivor region on every poll.
    ///
    /// The returned positions delimit the SAME validated survivor set `scan_compacted` materializes,
    /// so a seek to any returned position with `scan_compacted_from` reproduces the exact records
    /// `scan_compacted` would have, and the FULL body-CRC validation of the records actually
    /// returned happens there (this walk decodes each frame, so it is already CRC-gated, but the
    /// authoritative per-record validation on the read path is `scan_compacted_from`'s decode).
    ///
    /// # Errors
    /// Returns [`StorageError::FooterSegmentMismatch`] if the footer names a different segment,
    /// [`StorageError::RecoveredSequenceMismatch`] if a survivor's sequence is out of order or out
    /// of the covered span (identical to `scan_compacted`), or an IO error.
    pub fn compacted_byte_positions(&self) -> Result<Option<CompactedPositions>, StorageError> {
        if !self.header.is_compacted() {
            return Ok(None);
        }
        let header_end = SEGMENT_HEADER_LEN as u64;
        let footer_len = SEGMENT_FOOTER_LEN as u64;
        let block_len = COMPACTION_META_LEN as u64;
        if self.file_len < header_end + footer_len + block_len {
            return Ok(None);
        }
        let block_start = self.file_len - block_len;
        let footer_start = block_start - footer_len;
        let mut mbuf = [0u8; COMPACTION_META_LEN];
        self.file.read_exact_at(&mut mbuf, block_start)?;
        let Ok(meta) = CompactionMeta::decode(&mbuf) else {
            return Ok(None);
        };
        let mut fbuf = [0u8; SEGMENT_FOOTER_LEN];
        self.file.read_exact_at(&mut fbuf, footer_start)?;
        let Ok(footer) = SegmentFooter::decode(&fbuf) else {
            return Ok(None);
        };

        let base_off = self.header.base_offset.get();
        let base_seq = self.header.base_seq.get();
        let body_len = usize::try_from(footer_start.saturating_sub(header_end))
            .map_err(|_| StorageError::SegmentFull)?;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            self.file.read_exact_at(&mut body, header_end)?;
        }
        // `(offset, frame-start byte position)` per survivor, in ascending offset order. The byte
        // position is `header_end + cursor` (the frame's absolute start in the file), the same
        // anchor `scan_compacted_from` seeks to.
        let mut positions: Vec<(u64, u64)> = Vec::new();
        let mut cursor = 0usize;
        let mut prev_seq: Option<u64> = None;
        while cursor < body.len() {
            let Ok((view, consumed)) = codec::decode(&body[cursor..]) else {
                // The same structural-inconsistency verdict `scan_compacted` reaches: a committed
                // compacted segment (footer + block present and CRC-valid) with a torn/corrupt frame
                // is refused wholesale rather than half-indexed.
                return Ok(None);
            };
            let seq = view.seq.get();
            if seq < base_seq || seq >= meta.covered_end_seq || prev_seq.is_some_and(|p| seq <= p) {
                return Err(StorageError::RecoveredSequenceMismatch {
                    index: positions.len(),
                    expected: prev_seq.map_or(base_seq, |p| p + 1),
                    found: seq,
                });
            }
            prev_seq = Some(seq);
            let offset = base_off.wrapping_add(seq.wrapping_sub(base_seq));
            positions.push((offset, header_end + cursor as u64));
            cursor += consumed;
        }
        if footer.segment_id != self.header.segment_id {
            return Err(StorageError::FooterSegmentMismatch {
                header: self.header.segment_id,
                footer: footer.segment_id,
            });
        }
        if u64::from(footer.record_count) != positions.len() as u64
            || cursor as u64 != footer_start - header_end
        {
            return Ok(None);
        }
        Ok(Some((positions, footer_start)))
    }

    /// Reads up to `max` SPARSE survivor records from a COMPACTED (`version` = 2) segment starting at
    /// the file byte position `start_byte`, FULLY validating each materialized record (header AND
    /// body CRC, via the same `codec::decode` the v2 scan uses) and stopping at the first torn or
    /// corrupt frame, after `max` records, or at `read_end` (#481). Each survivor's ORIGINAL log
    /// offset is reconstructed from its decoded sequence and the constant offset-minus-sequence delta
    /// (`base_off - base_seq`), EXACTLY as [`SegmentReader::scan_compacted`] does, so the records come
    /// back at their true sparse offsets. `start_byte` MUST be a survivor frame boundary (an index
    /// entry from [`SegmentReader::compacted_byte_positions`]); the structural validation
    /// (footer/block presence, whole-set sequence monotonicity) was already done when that index was
    /// built, so this forward read needs only the per-frame CRC the decode performs.
    ///
    /// `read_end` bounds the read at the survivor region end (the footer start the index reports), so
    /// the footer and trailing compaction block are never decoded as a record. Returns the survivors
    /// in ascending offset order; the caller applies the `start`/`flushed`/`max` log-level filter.
    ///
    /// # Errors
    /// Returns an IO error from reading the region. A torn or corrupt frame is NOT an error here: it
    /// ends the returned prefix, exactly as the dense `scan_from` stops at the first bad frame.
    pub fn scan_compacted_from(
        &self,
        start_byte: u64,
        base_off: u64,
        base_seq: u64,
        read_end: u64,
        max: usize,
    ) -> Result<Vec<OwnedRecord>, StorageError> {
        if max == 0 || start_byte >= read_end {
            return Ok(Vec::new());
        }
        let len = usize::try_from(read_end.saturating_sub(start_byte))
            .map_err(|_| StorageError::SegmentFull)?;
        let mut body = vec![0u8; len];
        self.file.read_exact_at(&mut body, start_byte)?;
        let mut records = Vec::with_capacity(max.min(64));
        let mut cursor = 0usize;
        while cursor < body.len() && records.len() < max {
            // The SAME CRC-gated decode `scan_compacted` uses: a torn or corrupt frame ends the read.
            let Ok((view, consumed)) = codec::decode(&body[cursor..]) else {
                break;
            };
            // Reconstruct the original sparse offset from the constant offset-minus-seq delta, the
            // identical reconstruction `scan_compacted` applies.
            let seq = view.seq.get();
            let offset = Offset::new(base_off.wrapping_add(seq.wrapping_sub(base_seq)));
            records.push(OwnedRecord::from_view(offset, &view));
            cursor += consumed;
        }
        Ok(records)
    }

    /// Like [`SegmentReader::scan`], but returns only the metadata [`Log::recover`] needs
    /// and reads one record at a time, so peak memory is the largest single record rather
    /// than the whole record region (#156). The footer is trusted under the exact same
    /// rules as `scan`; the body is validated identically (header and body CRC, sequence
    /// continuity) but record payloads are dropped instead of collected.
    ///
    /// # Errors
    /// Returns [`StorageError::FooterSegmentMismatch`] if a body-consistent footer names a
    /// different segment, [`StorageError::RecoveredSequenceMismatch`] if a valid frame
    /// carries an out-of-order sequence, or an IO error.
    pub fn scan_recovery(&self) -> Result<RecoveryScan, StorageError> {
        let header_end = SEGMENT_HEADER_LEN as u64;
        let footer_len = SEGMENT_FOOTER_LEN as u64;

        // Decode the trailing 32 bytes as a footer CANDIDATE only, validated against the
        // body below before being trusted (identical to `scan`).
        let candidate = if self.file_len >= header_end + footer_len {
            let mut fbuf = [0u8; SEGMENT_FOOTER_LEN];
            self.file
                .read_exact_at(&mut fbuf, self.file_len - footer_len)?;
            SegmentFooter::decode(&fbuf).ok()
        } else {
            None
        };

        if let Some(footer) = candidate {
            let body_end = self.file_len - footer_len;
            let walk = self.scan_body_streaming(header_end, body_end)?;
            let ends_at_footer = walk.clean && header_end + walk.cursor == body_end;
            let body_matches =
                u64::from(footer.record_count) == walk.count && footer.last_seq == walk.last_seq;
            if ends_at_footer && body_matches {
                if footer.segment_id != self.header.segment_id {
                    return Err(StorageError::FooterSegmentMismatch {
                        header: self.header.segment_id,
                        footer: footer.segment_id,
                    });
                }
                return Ok(RecoveryScan {
                    header: self.header,
                    footer: Some(footer),
                    record_count: walk.count,
                    max_timestamp_ms: walk.max_timestamp_ms,
                    last_seq: walk.last_seq,
                    clean: true,
                    tail_reason: None,
                    valid_end: body_end,
                });
            }
            // The candidate does not describe the body: recover the valid prefix from the
            // full file (the candidate bytes are then just record data or a torn tail).
        }

        let walk = self.scan_body_streaming(header_end, self.file_len)?;
        Ok(RecoveryScan {
            header: self.header,
            footer: None,
            record_count: walk.count,
            max_timestamp_ms: walk.max_timestamp_ms,
            last_seq: walk.last_seq,
            clean: walk.clean,
            tail_reason: walk.tail_reason,
            valid_end: header_end + walk.cursor,
        })
    }

    /// Streams `[start, end)` one record at a time, validating each frame and the
    /// sequence run, stopping at the first torn or corrupt frame. Peak memory is one
    /// record (a reused scratch buffer), never the whole region. Returns the valid
    /// record count, the maximum record timestamp, the last valid sequence, the bytes
    /// consumed, and whether the region decoded cleanly. A valid frame with an
    /// out-of-order sequence is a hard error, the same structural check `Log::recover`
    /// applies to a buffered scan.
    fn scan_body_streaming(&self, start: u64, end: u64) -> Result<BodyWalk, StorageError> {
        let mut scratch: Vec<u8> = Vec::new();
        let mut pos = start;
        let mut count = 0u64;
        let mut max_timestamp_ms = 0u64;
        let mut last_seq = self.header.base_seq;
        let mut tail_reason: Option<ReasonCode> = None;
        while pos < end {
            let remaining = end - pos;
            if remaining < RECORD_HEADER_LEN as u64 {
                // Fewer bytes than a record header: a torn tail, not a whole record.
                tail_reason = Some(ReasonCode::TornTail);
                break;
            }
            // Read just the header to learn the frame length without buffering the body.
            scratch.resize(RECORD_HEADER_LEN, 0);
            self.file.read_exact_at(&mut scratch, pos)?;
            let Ok(total) = codec::decoded_len(&scratch) else {
                // A bad magic, version, or header CRC: a corrupt header ends the valid prefix.
                tail_reason = Some(ReasonCode::CorruptRecordHeader);
                break;
            };
            if total as u64 > remaining {
                // The header is intact but the frame would run past the region: a torn tail
                // (the body was never fully written).
                tail_reason = Some(ReasonCode::TornTail);
                break;
            }
            // Read the rest of the frame after the header, then validate the whole record.
            scratch.resize(total, 0);
            self.file.read_exact_at(
                &mut scratch[RECORD_HEADER_LEN..],
                pos + RECORD_HEADER_LEN as u64,
            )?;
            let Ok((view, consumed)) = codec::decode(&scratch) else {
                // The header was intact but the body or trailer failed: a corrupt body.
                tail_reason = Some(ReasonCode::CorruptRecordBody);
                break;
            };
            // Sequence continuity: a CRC-valid frame with the wrong seq is a recycled or
            // mixed-up file, a hard error, not a torn tail (matches the buffered recover).
            let expected = self
                .header
                .base_seq
                .get()
                .checked_add(count)
                .ok_or(StorageError::SegmentFull)?;
            if view.seq.get() != expected {
                return Err(StorageError::RecoveredSequenceMismatch {
                    index: usize::try_from(count).map_err(|_| StorageError::SegmentFull)?,
                    expected,
                    found: view.seq.get(),
                });
            }
            last_seq = view.seq;
            // Accumulate the MAX timestamp across the valid prefix (not the last): producer
            // timestamps are not monotonic, so recovery must reconstruct the same max the writer
            // tracked, for the age-retention reaper.
            max_timestamp_ms = max_timestamp_ms.max(view.timestamp_ms);
            count += 1;
            pos += consumed as u64;
        }
        Ok(BodyWalk {
            count,
            max_timestamp_ms,
            last_seq,
            cursor: pos - start,
            clean: tail_reason.is_none(),
            tail_reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::InMemoryFile;
    use ironbus_core::format::{RECORD_HEADER_LEN, XXH3_PAYLOAD_THRESHOLD};
    use std::sync::Arc;

    fn header() -> SegmentHeader {
        SegmentHeader {
            segment_id: 1,
            base_seq: Seq::new(0),
            base_offset: Offset::new(0),
            created_unix_ms: 0,
            flags: 0,
        }
    }

    fn rec(seq: u64, payload: &[u8]) -> RecordView<'_> {
        RecordView {
            seq: Seq::new(seq),
            timestamp_ms: seq,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    #[test]
    fn write_then_scan_roundtrip() {
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        assert_eq!(w.append(&rec(0, b"one")).unwrap(), Offset::new(0));
        assert_eq!(w.append(&rec(1, b"two")).unwrap(), Offset::new(1));
        assert_eq!(w.append(&rec(2, b"three")).unwrap(), Offset::new(2));
        w.sync().unwrap();

        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert!(scan.clean);
        assert!(scan.footer.is_none());
        assert_eq!(scan.records.len(), 3);
        assert_eq!(scan.records[0].offset, Offset::new(0));
        assert_eq!(scan.records[0].payload, b"one");
        assert_eq!(scan.records[2].seq, Seq::new(2));
        assert_eq!(scan.records[2].payload, b"three");
    }

    #[test]
    fn seal_then_scan_reads_footer_and_records() {
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"a")).unwrap();
        w.append(&rec(1, b"b")).unwrap();
        let footer = w.seal().unwrap();
        assert_eq!(footer.record_count, 2);
        assert_eq!(footer.last_seq, Seq::new(1));

        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert!(scan.clean);
        assert_eq!(scan.footer, Some(footer));
        assert_eq!(scan.records.len(), 2);
    }

    #[test]
    fn empty_sealed_segment() {
        let file = Arc::new(InMemoryFile::new());
        let w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        let footer = w.seal().unwrap();
        assert_eq!(footer.record_count, 0);
        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert!(scan.clean);
        assert!(scan.footer.is_some());
        assert!(scan.records.is_empty());
    }

    #[test]
    fn torn_tail_yields_valid_prefix() {
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"good1")).unwrap();
        let after_first = w.write_pos();
        w.append(&rec(1, b"good2")).unwrap();
        w.sync().unwrap();
        // Corrupt a byte inside the second record's body.
        let mut bytes = file.snapshot();
        let body_byte = usize::try_from(after_first + RECORD_HEADER_LEN as u64 + 1).unwrap();
        bytes[body_byte] ^= 0x01;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();

        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert!(!scan.clean);
        assert_eq!(scan.records.len(), 1);
        assert_eq!(scan.records[0].payload, b"good1");
        assert_eq!(scan.valid_end, after_first);
    }

    // ---- #483 seek-index primitives: record_byte_positions + scan_from ----

    /// `record_byte_positions` must delimit the SAME valid prefix `scan` does, and seeking to each
    /// returned position with `scan_from` must reproduce the exact record `scan` materialized — for
    /// both an UNSEALED and a SEALED dense segment.
    fn assert_positions_and_scan_from_match_scan(file: &Arc<InMemoryFile>, base_offset: u64) {
        let reader = SegmentReader::open(Arc::clone(file)).unwrap();
        let scan = reader.scan().unwrap();
        let reader2 = SegmentReader::open(Arc::clone(file)).unwrap();
        let (positions, valid_end) = reader2.record_byte_positions().unwrap();
        assert_eq!(
            positions.len(),
            scan.records.len(),
            "one position per scanned record"
        );
        assert_eq!(valid_end, scan.valid_end, "valid_end matches scan");
        // Seek to EACH position and read forward one record: it must equal the scanned record at the
        // same index, with the right offset assigned.
        let reader3 = SegmentReader::open(Arc::clone(file)).unwrap();
        for (i, &pos) in positions.iter().enumerate() {
            let off = Offset::new(base_offset + i as u64);
            let got = reader3.scan_from(pos, off, valid_end, 1).unwrap();
            assert_eq!(got.len(), 1, "one record from a single-record seek");
            assert_eq!(got[0], scan.records[i], "seeked record matches scan at {i}");
            assert_eq!(got[0].offset, off, "offset assigned from the seek base");
        }
        // A seek from the FIRST position with a large max reads the whole valid prefix, byte-identical.
        if let Some(&first) = positions.first() {
            let all = reader3
                .scan_from(first, Offset::new(base_offset), valid_end, usize::MAX)
                .unwrap();
            assert_eq!(all, scan.records, "full forward read equals scan");
        }
    }

    #[test]
    fn record_byte_positions_and_scan_from_match_scan_unsealed_and_sealed() {
        // Unsealed (active) dense segment.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        for i in 0..7u64 {
            w.append(&rec(i, &[u8::try_from(i).unwrap(); 9])).unwrap();
        }
        w.sync().unwrap();
        assert_positions_and_scan_from_match_scan(&file, 0);

        // Sealed dense segment (the trailing footer is excluded by `record_byte_positions`).
        let sealed = Arc::new(InMemoryFile::new());
        let mut ws = SegmentWriter::create(Arc::clone(&sealed), header()).unwrap();
        for i in 0..5u64 {
            ws.append(&rec(i, &[u8::try_from(i + 1).unwrap(); 13]))
                .unwrap();
        }
        ws.seal().unwrap();
        assert_positions_and_scan_from_match_scan(&sealed, 0);
    }

    #[test]
    fn record_byte_positions_stops_at_a_torn_tail_exactly_like_scan() {
        // Corrupt the second record's body: the position list and `scan` must both stop after the
        // first record, and a seek to the first position reads only that one record.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"good1")).unwrap();
        let after_first = w.write_pos();
        w.append(&rec(1, b"good2")).unwrap();
        w.sync().unwrap();
        let mut bytes = file.snapshot();
        let body_byte = usize::try_from(after_first + RECORD_HEADER_LEN as u64 + 1).unwrap();
        bytes[body_byte] ^= 0x01;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();

        let reader = SegmentReader::open(Arc::clone(&file)).unwrap();
        let (positions, valid_end) = reader.record_byte_positions().unwrap();
        assert_eq!(
            positions.len(),
            1,
            "the torn tail ends the prefix at one record"
        );
        assert_eq!(
            valid_end, after_first,
            "valid_end stops at the first record's end"
        );
        // A seek bounded by valid_end reads only the good record; it never materializes the torn one.
        let reader2 = SegmentReader::open(Arc::clone(&file)).unwrap();
        let got = reader2
            .scan_from(positions[0], Offset::new(0), valid_end, 10)
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].payload, b"good1");
    }

    #[test]
    fn scan_from_full_crc_rejects_a_corrupt_seeked_frame() {
        // A position that lands on a record whose BODY is corrupt must yield NO record (the body CRC
        // fails in `codec::decode`), proving `scan_from` fully validates what it materializes rather
        // than trusting the index blindly.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"first")).unwrap();
        let second_pos = w.write_pos();
        w.append(&rec(1, b"second")).unwrap();
        let valid_end = w.write_pos();
        w.sync().unwrap();
        // Corrupt the SECOND record's body in place; its index position is still `second_pos`.
        let mut bytes = file.snapshot();
        let body_byte = usize::try_from(second_pos + RECORD_HEADER_LEN as u64 + 1).unwrap();
        bytes[body_byte] ^= 0x01;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        let reader = SegmentReader::open(Arc::clone(&file)).unwrap();
        // Seeking directly to the corrupt frame returns nothing: the CRC stops materialization.
        let got = reader
            .scan_from(second_pos, Offset::new(1), valid_end, 10)
            .unwrap();
        assert!(got.is_empty(), "a corrupt seeked frame is never returned");
    }

    #[test]
    fn scan_from_respects_max_and_empty_bounds() {
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        for i in 0..6u64 {
            w.append(&rec(i, &[u8::try_from(i).unwrap(); 7])).unwrap();
        }
        w.sync().unwrap();
        let reader = SegmentReader::open(Arc::clone(&file)).unwrap();
        let (positions, valid_end) = reader.record_byte_positions().unwrap();
        // max == 0 yields nothing; start_byte >= read_end yields nothing.
        assert!(reader
            .scan_from(positions[0], Offset::new(0), valid_end, 0)
            .unwrap()
            .is_empty());
        assert!(reader
            .scan_from(valid_end, Offset::new(6), valid_end, 10)
            .unwrap()
            .is_empty());
        // max caps the count read forward from a mid-segment position.
        let two = reader
            .scan_from(positions[2], Offset::new(2), valid_end, 2)
            .unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].offset, Offset::new(2));
        assert_eq!(two[1].offset, Offset::new(3));
    }

    #[test]
    fn power_loss_keeps_only_synced_records() {
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"durable")).unwrap();
        w.sync().unwrap();
        w.append(&rec(1, b"lost")).unwrap(); // not synced
        file.simulate_power_loss();

        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert_eq!(scan.records.len(), 1);
        assert_eq!(scan.records[0].payload, b"durable");
    }

    #[test]
    fn footer_from_wrong_segment_is_rejected() {
        // Build a segment, then overwrite its footer with one bound to a different id.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"x")).unwrap();
        w.seal().unwrap();
        let wrong = SegmentFooter {
            segment_id: 999,
            last_seq: Seq::new(0),
            record_count: 1,
        };
        let len = file.len().unwrap();
        file.write_all_at(&wrong.encode(), len - SEGMENT_FOOTER_LEN as u64)
            .unwrap();
        let err = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap_err();
        assert!(matches!(
            err,
            StorageError::FooterSegmentMismatch {
                header: 1,
                footer: 999
            }
        ));
    }

    #[test]
    fn footer_disagreeing_with_body_is_not_trusted() {
        // A footer bound to THIS segment but whose record_count lies must not be
        // trusted on content alone (M2): the scan cross-checks it against the body.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"a")).unwrap();
        w.append(&rec(1, b"b")).unwrap();
        w.seal().unwrap();
        let lying = SegmentFooter {
            segment_id: 1,
            last_seq: Seq::new(1),
            record_count: 7, // body has 2 records, not 7
        };
        let len = file.len().unwrap();
        file.write_all_at(&lying.encode(), len - SEGMENT_FOOTER_LEN as u64)
            .unwrap();

        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        // The lying footer is rejected; the two real records are still recovered and
        // the segment is reported as not-cleanly-sealed rather than a 7-record seal.
        assert!(scan.footer.is_none());
        assert!(!scan.clean);
        assert_eq!(scan.records.len(), 2);
        assert_eq!(scan.records[0].payload, b"a");
        assert_eq!(scan.records[1].payload, b"b");
    }

    #[test]
    fn footer_overlapping_record_data_is_not_trusted() {
        // A content-valid footer (correct segment id) overlaid on top of real record
        // bytes must not be accepted as a seal (M1): doing so would silently drop the
        // record it overlaps and falsely mark the segment sealed.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"small")).unwrap();
        // A large second record so the trailing 32 bytes fall well inside its frame.
        w.append(&rec(1, &[0x5a; 64])).unwrap();
        w.sync().unwrap();

        let forged = SegmentFooter {
            segment_id: 1,
            last_seq: Seq::new(1),
            record_count: 2,
        };
        let len = file.len().unwrap();
        file.write_all_at(&forged.encode(), len - SEGMENT_FOOTER_LEN as u64)
            .unwrap();

        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        // Not falsely sealed; the un-corrupted prefix (the first record) survives.
        assert!(scan.footer.is_none());
        assert!(!scan.clean);
        assert_eq!(scan.records[0].payload, b"small");
    }

    #[test]
    fn corrupt_footer_crc_still_recovers_records() {
        // A sealed segment whose footer CRC is damaged is recovered as unsealed: the
        // records survive even though the seal is unreadable (N1).
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"keep1")).unwrap();
        w.append(&rec(1, b"keep2")).unwrap();
        w.seal().unwrap();
        // Flip a byte inside the footer so SegmentFooter::decode fails.
        let mut bytes = file.snapshot();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();

        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert!(scan.footer.is_none());
        assert_eq!(scan.records.len(), 2);
        assert_eq!(scan.records[0].payload, b"keep1");
        assert_eq!(scan.records[1].payload, b"keep2");
    }

    #[test]
    fn short_file_is_typed_truncation_not_io() {
        // A file too short to hold a header surfaces a typed structural error (M4),
        // not a raw IO end-of-file, so recovery can distinguish the two.
        let file = Arc::new(InMemoryFile::new());
        file.write_all_at(&[0u8; 10], 0).unwrap();
        let err = SegmentReader::open(Arc::clone(&file)).unwrap_err();
        assert!(matches!(
            err,
            StorageError::Segment(SegmentError::Truncated)
        ));
    }

    #[test]
    fn offset_space_exhaustion_is_refused() {
        // Offsets are never reused; an append that would wrap the offset space is
        // refused rather than minting a duplicate id (M3).
        let h = SegmentHeader {
            segment_id: 1,
            base_seq: Seq::new(0),
            base_offset: Offset::new(u64::MAX),
            created_unix_ms: 0,
            flags: 0,
        };
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), h).unwrap();
        assert_eq!(w.append(&rec(0, b"x")).unwrap(), Offset::new(u64::MAX));
        assert!(matches!(
            w.append(&rec(1, b"y")),
            Err(StorageError::SegmentFull)
        ));
    }

    /// The streaming `scan_recovery` must agree with the buffered `scan` on everything
    /// recovery consumes: record count, last sequence, `valid_end`, `clean`, and the footer.
    fn assert_scans_agree(file: &Arc<InMemoryFile>) {
        let buffered = SegmentReader::open(Arc::clone(file))
            .unwrap()
            .scan()
            .unwrap();
        let streamed = SegmentReader::open(Arc::clone(file))
            .unwrap()
            .scan_recovery()
            .unwrap();
        assert_eq!(
            streamed.record_count,
            buffered.records.len() as u64,
            "record_count"
        );
        let expected_last = buffered
            .records
            .last()
            .map_or(buffered.header.base_seq, |r| r.seq);
        assert_eq!(streamed.last_seq, expected_last, "last_seq");
        // The streamed max timestamp must equal the buffered scan's max over the same valid
        // prefix (0 if empty), so recovery reconstructs exactly what the writer tracked.
        let expected_max_ts = buffered
            .records
            .iter()
            .map(|r| r.timestamp_ms)
            .max()
            .unwrap_or(0);
        assert_eq!(
            streamed.max_timestamp_ms, expected_max_ts,
            "max_timestamp_ms"
        );
        assert_eq!(streamed.valid_end, buffered.valid_end, "valid_end");
        assert_eq!(streamed.clean, buffered.clean, "clean");
        assert_eq!(streamed.footer, buffered.footer, "footer");
        assert_eq!(
            streamed.header.segment_id, buffered.header.segment_id,
            "header"
        );
    }

    #[test]
    fn scan_recovery_agrees_with_scan_across_shapes() {
        // Clean unsealed.
        let clean = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&clean), header()).unwrap();
        w.append(&rec(0, b"one")).unwrap();
        w.append(&rec(1, b"two")).unwrap();
        w.append(&rec(2, b"three")).unwrap();
        w.sync().unwrap();
        assert_scans_agree(&clean);

        // Sealed.
        let sealed = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&sealed), header()).unwrap();
        w.append(&rec(0, b"a")).unwrap();
        w.append(&rec(1, b"b")).unwrap();
        w.seal().unwrap();
        assert_scans_agree(&sealed);

        // Empty sealed.
        let empty = Arc::new(InMemoryFile::new());
        let w = SegmentWriter::create(Arc::clone(&empty), header()).unwrap();
        w.seal().unwrap();
        assert_scans_agree(&empty);

        // Header only, no records, unsealed.
        let bare = Arc::new(InMemoryFile::new());
        let _w = SegmentWriter::create(Arc::clone(&bare), header()).unwrap();
        assert_scans_agree(&bare);

        // Torn tail: chop a few bytes off the last record so it no longer decodes.
        let torn = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&torn), header()).unwrap();
        w.append(&rec(0, b"keep")).unwrap();
        w.append(&rec(1, b"gone")).unwrap();
        w.sync().unwrap();
        let len = torn.len().unwrap();
        torn.set_len(len - 3).unwrap();
        assert_scans_agree(&torn);

        // Corrupt body: flip a payload byte in the last record so its body CRC fails.
        let corrupt = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&corrupt), header()).unwrap();
        w.append(&rec(0, b"good")).unwrap();
        w.append(&rec(1, b"bad!")).unwrap();
        w.sync().unwrap();
        let mut bytes = corrupt.snapshot();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        corrupt.write_all_at(&bytes, 0).unwrap();
        assert_scans_agree(&corrupt);
    }

    #[test]
    fn scan_recovery_bounds_memory_to_one_record() {
        // A segment of many records is scanned without ever buffering the whole region:
        // recovery only reports count, last_seq, and valid_end, which still match scan.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        for i in 0..200u64 {
            w.append(&rec(i, b"payload-bytes")).unwrap();
        }
        w.sync().unwrap();
        let streamed = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan_recovery()
            .unwrap();
        assert_eq!(streamed.record_count, 200);
        assert_eq!(streamed.last_seq, Seq::new(199));
        assert!(streamed.clean);
        assert_scans_agree(&file);
    }

    #[test]
    fn scan_recovery_reads_an_over_threshold_xxh3_record() {
        // A record whose stored body reaches XXH3_PAYLOAD_THRESHOLD carries the second xxh3-64
        // checksum field in its frame (#146), making that frame larger than the trailer-only
        // layout. Both the buffered scan and the streaming recovery scan are purely total_len
        // driven, so they must walk the larger frame and recover the record intact. This pins the
        // xxh3-bearing frame end to end through the storage read and recovery paths (the codec
        // owns the byte layout, but the durability path must not under-test the larger frame),
        // sandwiched between sub-threshold records so a mis-sized walk would desync the tail.
        let big = vec![0xa5u8; XXH3_PAYLOAD_THRESHOLD as usize + 37];
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"small")).unwrap();
        w.append(&rec(1, &big)).unwrap();
        w.append(&rec(2, b"after")).unwrap();
        w.sync().unwrap();

        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert!(scan.clean);
        assert_eq!(scan.records.len(), 3);
        assert_eq!(scan.records[1].seq, Seq::new(1));
        assert_eq!(scan.records[1].payload, big.as_slice());
        assert_eq!(scan.records[2].payload, b"after");

        let streamed = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan_recovery()
            .unwrap();
        assert!(streamed.clean);
        assert_eq!(streamed.record_count, 3);
        assert_eq!(streamed.last_seq, Seq::new(2));
        assert_scans_agree(&file);
    }

    fn rec_at(seq: u64, ts: u64, payload: &[u8]) -> RecordView<'_> {
        RecordView {
            seq: Seq::new(seq),
            timestamp_ms: ts,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    #[test]
    fn writer_tracks_the_max_timestamp_not_the_last() {
        // Producer timestamps are not monotonic: the writer must keep the MAX across the segment,
        // not the last appended record's timestamp. An empty segment reports 0.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        assert_eq!(w.max_timestamp_ms(), 0, "empty segment");
        w.append(&rec_at(0, 100, b"a")).unwrap();
        assert_eq!(w.max_timestamp_ms(), 100);
        w.append(&rec_at(1, 300, b"b")).unwrap();
        assert_eq!(w.max_timestamp_ms(), 300);
        // A later record with an OLDER timestamp must not lower the running max.
        w.append(&rec_at(2, 50, b"c")).unwrap();
        assert_eq!(w.max_timestamp_ms(), 300, "max, not last");
        w.sync().unwrap();
        // Recovery reconstructs the same max from a streaming scan.
        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan_recovery()
            .unwrap();
        assert_eq!(scan.max_timestamp_ms, 300, "recovered max");
        assert_eq!(scan.record_count, 3);
    }

    #[test]
    fn scan_recovery_reports_a_recycled_frame_with_a_bad_seq() {
        // A CRC-valid frame whose sequence is out of order is a recycled or mixed file,
        // a hard error in recovery, not a silently truncated tail.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"first")).unwrap();
        // Append a second record carrying seq 5 instead of 1: a valid frame, wrong order.
        w.append(&rec(5, b"jump")).unwrap();
        w.sync().unwrap();
        let err = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan_recovery()
            .unwrap_err();
        assert!(matches!(
            err,
            StorageError::RecoveredSequenceMismatch {
                index: 1,
                expected: 1,
                found: 5,
            }
        ));
    }
}
