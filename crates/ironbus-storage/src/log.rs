// SPDX-License-Identifier: MIT OR Apache-2.0
//! The single durable, ordered log: open or recover a data directory, append records,
//! and survive a crash with a consistent prefix.
//!
//! This is the write path over one active segment. [`Log::open`] recovers the active
//! segment (truncating any torn or unsynced tail) or starts a fresh one; [`Log::append`]
//! assigns each record its monotonic log offset and sequence number and writes it to the
//! active segment; [`Log::sync`] makes the appended records durable. Sealing the active
//! segment and rolling to the next, and the read path, are separate later work.

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

/// A single durable, ordered log backed by one data directory.
///
/// One active segment receives appends; offsets and sequence numbers are monotonic and
/// never reused. The log is single-writer: one owner appends. The concurrent append
/// actor and lock-free readers are layered on later. This version manages exactly one
/// (unsealed) active segment; segment rolling is a follow-up.
#[derive(Debug)]
pub struct Log<F: Filesystem> {
    fs: F,
    active: SegmentWriter<F::File>,
    active_id: u64,
    next_seq: Seq,
}

impl<F: Filesystem> Log<F> {
    /// Opens the log in `fs`, recovering the active segment or creating a fresh one.
    ///
    /// Recovery scans the highest-numbered segment, truncates any torn or unsynced tail
    /// to the last intact record, and resumes appending after it. A fresh log creates
    /// segment 0, stamps its header with the wall clock, and dir-syncs it.
    ///
    /// # Errors
    /// Returns [`StorageError`] on an IO error or a structurally invalid segment.
    pub fn open(fs: F, clock: &dyn Clock) -> Result<Log<F>, StorageError> {
        match segment_ids(&fs)?.last().copied() {
            None => Self::create_fresh(fs, clock),
            Some(active_id) => Self::recover(fs, active_id),
        }
    }

    fn create_fresh(fs: F, clock: &dyn Clock) -> Result<Log<F>, StorageError> {
        let header = SegmentHeader {
            segment_id: FIRST_SEGMENT_ID,
            base_seq: Seq::new(0),
            base_offset: Offset::ZERO,
            created_unix_ms: clock.now_unix_millis(),
            flags: 0,
        };
        let file = fs.create_new(&segment_file_name(FIRST_SEGMENT_ID))?;
        let active = SegmentWriter::create(file, header)?;
        active.sync()?; // the header is durable...
        fs.sync_dir()?; // ...and so is its directory entry.
        Ok(Log {
            fs,
            active,
            active_id: FIRST_SEGMENT_ID,
            next_seq: Seq::new(0),
        })
    }

    fn recover(fs: F, active_id: u64) -> Result<Log<F>, StorageError> {
        let name = segment_file_name(active_id);
        // Scan the active segment to find the durable valid prefix.
        let scan = SegmentReader::open(fs.open(&name)?)?.scan()?;
        let header = scan.header;
        let record_count =
            u32::try_from(scan.records.len()).map_err(|_| StorageError::SegmentFull)?;
        let last_seq = scan.records.last().map_or(header.base_seq, |r| r.seq);
        let next_seq = match scan.records.last() {
            Some(r) => r.seq.checked_next().ok_or(StorageError::SegmentFull)?,
            None => header.base_seq,
        };
        // Drop any torn or unsynced tail so appends continue from an intact boundary.
        let file = fs.open(&name)?;
        if scan.valid_end < file.len()? {
            file.set_len(scan.valid_end)?;
            file.sync_data()?;
        }
        let active = SegmentWriter::resume(file, header, scan.valid_end, record_count, last_seq);
        Ok(Log {
            fs,
            active,
            active_id,
            next_seq,
        })
    }

    /// The log offset the next appended record will receive.
    #[must_use]
    pub fn next_offset(&self) -> Offset {
        self.active.next_offset()
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

    /// Appends one record, assigning it the next sequence number and log offset, and
    /// returns that offset. The record is durable only after [`Log::sync`].
    ///
    /// # Errors
    /// Returns [`StorageError::SegmentFull`] if the offset or sequence space is
    /// exhausted, or the record is too large to frame, or an IO error from the write.
    pub fn append(&mut self, record: &Append<'_>) -> Result<Offset, StorageError> {
        let seq = self.next_seq;
        let view = RecordView {
            seq,
            timestamp_ms: record.timestamp_ms,
            flags: record.flags,
            key: record.key,
            headers: record.headers,
            payload: record.payload,
        };
        // The sequence advances only after the write returns Ok: a failed append leaves
        // a torn tail recovery discards, and its sequence number is reused, not skipped.
        let offset = self.active.append(&view)?;
        self.next_seq = seq.checked_next().ok_or(StorageError::SegmentFull)?;
        Ok(offset)
    }

    /// Flushes appended records to durable storage (fdatasync). A record may be
    /// acknowledged once this returns.
    ///
    /// # Errors
    /// Propagates the IO error. A fatal sync must freeze the writer read-only.
    pub fn sync(&self) -> Result<(), StorageError> {
        self.active.sync()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use crate::segment::OwnedRecord;
    use ironbus_core::clock::ManualClock;

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    fn read_back(fs: &InMemoryFs, id: u64) -> Vec<OwnedRecord> {
        let file = fs.open(&segment_file_name(id)).unwrap();
        SegmentReader::open(file).unwrap().scan().unwrap().records
    }

    #[test]
    fn open_empty_creates_the_first_segment() {
        let clock = ManualClock::new();
        let log = Log::open(InMemoryFs::new(), &clock).unwrap();
        assert_eq!(log.active_segment_id(), FIRST_SEGMENT_ID);
        assert_eq!(log.next_offset(), Offset::ZERO);
        assert_eq!(log.next_seq(), Seq::new(0));
        assert!(log.filesystem().exists(&segment_file_name(0)).unwrap());
    }

    #[test]
    fn append_assigns_monotonic_offsets_and_sequences() {
        let clock = ManualClock::new();
        let mut log = Log::open(InMemoryFs::new(), &clock).unwrap();
        assert_eq!(log.append(&rec(b"a")).unwrap(), Offset::new(0));
        assert_eq!(log.append(&rec(b"b")).unwrap(), Offset::new(1));
        assert_eq!(log.append(&rec(b"c")).unwrap(), Offset::new(2));
        assert_eq!(log.next_offset(), Offset::new(3));
        assert_eq!(log.next_seq(), Seq::new(3));
        log.sync().unwrap();
        let records = read_back(log.filesystem(), 0);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].payload, b"c");
        assert_eq!(records[2].seq, Seq::new(2));
    }

    #[test]
    fn reopen_recovers_durable_records_and_continues() {
        let clock = ManualClock::new();
        let mut log = Log::open(InMemoryFs::new(), &clock).unwrap();
        log.append(&rec(b"one")).unwrap();
        log.append(&rec(b"two")).unwrap();
        log.sync().unwrap();
        let fs = log.into_filesystem();

        let mut log = Log::open(fs, &clock).unwrap();
        assert_eq!(log.next_offset(), Offset::new(2));
        assert_eq!(log.next_seq(), Seq::new(2));
        assert_eq!(log.append(&rec(b"three")).unwrap(), Offset::new(2));
        log.sync().unwrap();
        let records = read_back(log.filesystem(), 0);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].payload, b"three");
        assert_eq!(records[2].seq, Seq::new(2));
    }

    #[test]
    fn power_loss_drops_the_unsynced_tail_and_resumes() {
        let clock = ManualClock::new();
        let mut log = Log::open(InMemoryFs::new(), &clock).unwrap();
        log.append(&rec(b"durable")).unwrap();
        log.sync().unwrap();
        log.append(&rec(b"lost")).unwrap(); // never synced
        log.filesystem().simulate_power_loss();
        let fs = log.into_filesystem();

        let mut log = Log::open(fs, &clock).unwrap();
        // Only the synced record survived; its slot is the recovered head.
        assert_eq!(log.next_offset(), Offset::new(1));
        assert_eq!(log.next_seq(), Seq::new(1));
        // The unsynced record's offset and sequence are reused, not skipped.
        assert_eq!(log.append(&rec(b"after")).unwrap(), Offset::new(1));
        log.sync().unwrap();
        let records = read_back(log.filesystem(), 0);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].payload, b"durable");
        assert_eq!(records[1].payload, b"after");
        assert_eq!(records[1].seq, Seq::new(1));
    }

    #[test]
    fn reopen_an_empty_synced_log_is_clean() {
        let clock = ManualClock::new();
        let log = Log::open(InMemoryFs::new(), &clock).unwrap();
        let fs = log.into_filesystem();
        let log = Log::open(fs, &clock).unwrap();
        assert_eq!(log.next_offset(), Offset::ZERO);
        assert_eq!(log.next_seq(), Seq::new(0));
        assert!(read_back(log.filesystem(), 0).is_empty());
    }
}
