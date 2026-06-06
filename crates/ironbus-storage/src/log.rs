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
use crate::segment::{SegmentReader, SegmentWriter, StorageError};
use ironbus_core::clock::Clock;
use ironbus_core::codec::RecordView;
use ironbus_core::segment::SegmentHeader;
use ironbus_core::types::{Offset, RecordFlags, Seq};

/// The id of the first segment in a fresh log.
const FIRST_SEGMENT_ID: u64 = 0;

/// Tunables for a [`Log`].
#[derive(Clone, Copy, Debug)]
pub struct LogConfig {
    /// Soft cap on a segment's byte size. The active segment is sealed and a new one
    /// started before the first append that would begin at or beyond this size, so a
    /// segment may exceed it by at most the last record. An empty segment is never
    /// rolled, so a record larger than the cap still gets written (to its own segment).
    pub max_segment_bytes: u64,
}

impl LogConfig {
    /// The frozen v1 default segment size, 64 MiB.
    pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
}

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
        match segment_ids(&fs)?.last().copied() {
            None => {
                let mut log = Log {
                    fs,
                    clock,
                    config,
                    active: None,
                    active_id: FIRST_SEGMENT_ID,
                    next_offset: Offset::ZERO,
                    next_seq: Seq::new(0),
                };
                log.start_segment(FIRST_SEGMENT_ID, Seq::new(0), Offset::ZERO)?;
                Ok(log)
            }
            Some(active_id) => Self::recover(fs, clock, config, active_id),
        }
    }

    fn recover(
        fs: F,
        clock: C,
        config: LogConfig,
        active_id: u64,
    ) -> Result<Log<F, C>, StorageError> {
        let name = segment_file_name(active_id);
        let scan = SegmentReader::open(fs.open(&name)?)?.scan()?;
        let header = scan.header;
        let record_count =
            u32::try_from(scan.records.len()).map_err(|_| StorageError::SegmentFull)?;
        let base_seq = header.base_seq.get();
        let base_offset = header.base_offset.get();
        // Sequences are a contiguous run from base_seq; validate the recovered records.
        for (index, r) in scan.records.iter().enumerate() {
            let expected = base_seq
                .checked_add(index as u64)
                .ok_or(StorageError::SegmentFull)?;
            if r.seq.get() != expected {
                return Err(StorageError::RecoveredSequenceMismatch {
                    index,
                    expected,
                    found: r.seq.get(),
                });
            }
        }
        let next_seq = Seq::new(
            base_seq
                .checked_add(u64::from(record_count))
                .ok_or(StorageError::SegmentFull)?,
        );
        let next_offset = Offset::new(
            base_offset
                .checked_add(u64::from(record_count))
                .ok_or(StorageError::SegmentFull)?,
        );

        let mut log = Log {
            fs,
            clock,
            config,
            active: None,
            active_id,
            next_offset,
            next_seq,
        };

        if scan.footer.is_some() {
            // Crash after sealing the highest segment but before the next was created:
            // roll forward and create it, continuing the offset and sequence space.
            let next_id = active_id.checked_add(1).ok_or(StorageError::SegmentFull)?;
            log.start_segment(next_id, next_seq, next_offset)?;
        } else {
            // The active segment is unsealed: drop any torn or unsynced tail and resume.
            // set_len changes the length, so it needs sync_all, not sync_data.
            let file = log.fs.open(&name)?;
            if scan.valid_end < file.len()? {
                file.set_len(scan.valid_end)?;
                file.sync_all()?;
            }
            let last_seq = scan.records.last().map_or(header.base_seq, |r| r.seq);
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
        // Take the active writer out and seal it. From here, an error leaves `active`
        // as `None`, freezing the writer rather than risking a corrupt resume.
        let old = self.active.take().ok_or(StorageError::WriterFrozen)?;
        old.seal()?;
        self.start_segment(next_id, self.next_seq, self.next_offset)
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
    /// Propagates the IO error, or [`StorageError::WriterFrozen`] if the writer is
    /// frozen. A fatal sync must freeze the writer read-only.
    pub fn sync(&self) -> Result<(), StorageError> {
        self.active()?.sync()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use crate::segment::OwnedRecord;
    use ironbus_core::clock::ManualClock;

    // A small segment cap so rolling happens after a handful of records.
    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 128,
        }
    }

    fn open_mem(config: LogConfig) -> Log<InMemoryFs, ManualClock> {
        Log::open(InMemoryFs::new(), ManualClock::new(), config).unwrap()
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
