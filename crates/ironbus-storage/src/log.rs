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
}

impl LogConfig {
    /// The frozen v1 default segment size, 64 MiB.
    pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

    /// The smallest sane `max_segment_bytes`: the segment header and footer plus room for at
    /// least two minimum-size records, so a segment can always hold more than one record. A
    /// cap below this fragments the log into one-record segments and is rejected by
    /// [`LogConfig::new`].
    pub const MIN_MAX_SEGMENT_BYTES: u64 =
        (SEGMENT_HEADER_LEN + SEGMENT_FOOTER_LEN + 2 * (RECORD_HEADER_LEN + RECORD_TRAILER_LEN))
            as u64;

    /// Builds a [`LogConfig`], rejecting a `max_segment_bytes` below
    /// [`LogConfig::MIN_MAX_SEGMENT_BYTES`]. This is the validating path that keeps a
    /// degenerate cap (`0`, or a sub-header value) from silently fragmenting the log.
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
        Ok(LogConfig { max_segment_bytes })
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

/// An in-memory directory entry: a segment id and the log offset of its first record.
/// Held sorted by `base_offset` (which is monotonic with the id) so a read can binary
/// search for the segment that holds a given offset.
#[derive(Clone, Copy, Debug)]
struct SegmentSlot {
    id: u64,
    base_offset: u64,
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
    /// Bytes dropped from a torn or unsynced active-segment tail at recovery: the silent
    /// loss that recovery truncates to reach the last intact record. Zero for a fresh log
    /// or a clean recovery.
    recovered_truncated_bytes: u64,
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
                    recovered_truncated_bytes: 0,
                };
                log.start_segment(FIRST_SEGMENT_ID, Seq::new(0), Offset::ZERO)?;
                Ok(log)
            }
            Some(last_id) => Self::recover(fs, clock, config, &ids, last_id),
        }
    }

    fn recover(
        fs: F,
        clock: C,
        config: LogConfig,
        ids: &[u64],
        last_id: u64,
    ) -> Result<Log<F, C>, StorageError> {
        // Walk every segment in ascending order, validating the chain: each segment's
        // stored id matches its file name, its base continues from its predecessor, its
        // records are a contiguous sequence run, and every NON-final segment is sealed.
        // A corrupt or unreadable segment fails its scan here, not silently at read time.
        let mut next_base_offset = 0u64;
        let mut next_base_seq = 0u64;
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
            slots.push(SegmentSlot { id, base_offset });
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
            if is_last {
                highest = Some(scan);
            }
        }
        // `highest` is Some because `open` only calls `recover` with a non-empty list.
        let scan = highest.ok_or(StorageError::WriterFrozen)?;
        let header = scan.header;
        let next_offset = Offset::new(next_base_offset);
        let next_seq = Seq::new(next_base_seq);

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
            recovered_truncated_bytes: 0,
        };

        if scan.footer.is_some() {
            // Crash after sealing the highest segment but before the next was created:
            // roll forward and create it, continuing the offset and sequence space.
            let next_id = last_id.checked_add(1).ok_or(StorageError::SegmentFull)?;
            log.start_segment(next_id, next_seq, next_offset)?;
        } else {
            // The active segment is unsealed: drop any torn or unsynced tail and resume.
            // set_len changes the length, so it needs sync_all, not sync_data.
            let name = segment_file_name(last_id);
            let file = log.fs.open(&name)?;
            let len = file.len()?;
            if scan.valid_end < len {
                // Record the silent loss before dropping it, so an operator can see that a
                // torn or unsynced tail was discarded at recovery.
                log.recovered_truncated_bytes = len - scan.valid_end;
                file.set_len(scan.valid_end)?;
                file.sync_all()?;
            }
            let record_count =
                u32::try_from(scan.record_count).map_err(|_| StorageError::SegmentFull)?;
            let last_seq = scan.last_seq;
            log.active = Some(SegmentWriter::resume(
                file,
                header,
                scan.valid_end,
                record_count,
                last_seq,
            ));
        }
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
        self.active = Some(writer);
        self.active_id = id;
        self.segments.push(SegmentSlot {
            id,
            base_offset: base_offset.get(),
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
        old.seal().map_err(|_| StorageError::WriterFrozen)?;
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
    /// Returns [`StorageError::SegmentFull`] if the offset or sequence space is
    /// exhausted or the record is too large to frame, [`StorageError::WriterFrozen`] if
    /// a prior fatal error froze the writer, or an IO error from the write.
    pub fn append(&mut self, record: &Append<'_>) -> Result<Offset, StorageError> {
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
        let offset = self
            .active
            .as_mut()
            .ok_or(StorageError::WriterFrozen)?
            .append(&view)?;
        // The ids advance only after the write returns Ok.
        self.next_seq = next_seq;
        self.next_offset = next_offset;
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

    /// The current monotonic time from the log's clock, for the consumer's lease deadlines.
    #[must_use]
    pub fn now_monotonic(&self) -> u64 {
        self.clock.now_monotonic_nanos()
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
        });
        let big = vec![0xab; 4096];
        assert_eq!(log.append(&rec(&big)).unwrap(), Offset::new(0));
        log.sync().unwrap();
        // The next append rolls (the segment is now well past the cap).
        assert_eq!(log.append(&rec(b"small")).unwrap(), Offset::new(1));
        assert_eq!(log.active_segment_id(), 1);
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
}
