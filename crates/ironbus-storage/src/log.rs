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
        // A sealed segment cannot be the active (appendable) one here: resuming over it
        // would overwrite its footer. Rolling past a seal is follow-up work, so refuse.
        if scan.footer.is_some() {
            return Err(StorageError::ActiveSegmentSealed {
                segment_id: header.segment_id,
            });
        }
        let record_count =
            u32::try_from(scan.records.len()).map_err(|_| StorageError::SegmentFull)?;
        // Sequences are a contiguous run from base_seq, so validate the recovered
        // records and derive the next sequence as base_seq + record_count (kept in
        // lockstep with next_offset, which is base_offset + record_count). A record with
        // an out-of-run sequence means the segment is structurally inconsistent.
        let base_seq = header.base_seq.get();
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
        let last_seq = scan.records.last().map_or(header.base_seq, |r| r.seq);
        // Drop any torn or unsynced tail so appends continue from an intact boundary.
        // set_len changes the length, so it needs sync_all (fsync), not sync_data: the
        // RandomAccessFile contract does not promise sync_data persists a length change.
        let file = fs.open(&name)?;
        if scan.valid_end < file.len()? {
            file.set_len(scan.valid_end)?;
            file.sync_all()?;
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
        // Reserve the next sequence BEFORE writing. If the sequence space is exhausted
        // we refuse here, so a record is never durably written under a sequence we
        // cannot advance past (which would force the next append to reuse it).
        let next_seq = seq.checked_next().ok_or(StorageError::SegmentFull)?;
        let view = RecordView {
            seq,
            timestamp_ms: record.timestamp_ms,
            flags: record.flags,
            key: record.key,
            headers: record.headers,
            payload: record.payload,
        };
        // next_seq is committed only after the write returns Ok: a failed append leaves a
        // torn tail recovery discards, and its sequence number is reused, not skipped.
        let offset = self.active.append(&view)?;
        self.next_seq = next_seq;
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

    fn read_back<G: Filesystem>(fs: &G, id: u64) -> Vec<OwnedRecord> {
        let file = fs.open(&segment_file_name(id)).unwrap();
        SegmentReader::open(file).unwrap().scan().unwrap().records
    }

    // A raw record view, for hand-building a segment with chosen sequence numbers.
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

    #[test]
    fn open_errors_on_a_sealed_active_segment() {
        // Recovery must refuse a sealed segment rather than truncate its footer and
        // resume appending over it (which would silently unseal and corrupt it).
        let fs = InMemoryFs::new();
        let file = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w = SegmentWriter::create(file, header_at(0, 0)).unwrap();
        w.append(&view(0, b"x")).unwrap();
        w.seal().unwrap();

        let clock = ManualClock::new();
        let err = Log::open(fs, &clock).unwrap_err();
        assert!(matches!(
            err,
            StorageError::ActiveSegmentSealed { segment_id: 0 }
        ));
    }

    #[test]
    fn recovers_a_segment_with_a_non_zero_base() {
        // A segment whose base_seq / base_offset are non-zero recovers with next_seq and
        // next_offset continuing from base + record_count.
        let fs = InMemoryFs::new();
        let file = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w = SegmentWriter::create(file, header_at(0, 5)).unwrap();
        w.append(&view(5, b"a")).unwrap();
        w.append(&view(6, b"b")).unwrap();
        w.append(&view(7, b"c")).unwrap();
        w.sync().unwrap();
        drop(w);

        let clock = ManualClock::new();
        let mut log = Log::open(fs, &clock).unwrap();
        assert_eq!(log.next_seq(), Seq::new(8));
        assert_eq!(log.next_offset(), Offset::new(8));
        assert_eq!(log.append(&rec(b"d")).unwrap(), Offset::new(8));
    }

    #[test]
    fn rejects_a_segment_with_a_sequence_gap() {
        // A record whose sequence breaks the contiguous run from base_seq is a
        // structural inconsistency recovery reports rather than silently accepting.
        let fs = InMemoryFs::new();
        let file = fs.create_new(&segment_file_name(0)).unwrap();
        let mut w = SegmentWriter::create(file, header_at(0, 0)).unwrap();
        w.append(&view(0, b"a")).unwrap();
        w.append(&view(5, b"b")).unwrap(); // expected sequence 1
        w.sync().unwrap();
        drop(w);

        let clock = ManualClock::new();
        let err = Log::open(fs, &clock).unwrap_err();
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
    fn corrupt_synced_record_is_truncated_on_reopen() {
        let clock = ManualClock::new();
        let mut log = Log::open(InMemoryFs::new(), &clock).unwrap();
        log.append(&rec(b"good1")).unwrap();
        log.append(&rec(b"good2-with-a-longer-payload")).unwrap();
        log.sync().unwrap();

        // Corrupt the last byte (inside the second record) so it fails to decode.
        let name = segment_file_name(0);
        let f = log.filesystem().open(&name).unwrap();
        let len_before = f.len().unwrap();
        let mut bytes = f.snapshot();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        f.set_len(0).unwrap();
        f.write_all_at(&bytes, 0).unwrap();
        f.sync_data().unwrap();
        let fs = log.into_filesystem();

        let mut log = Log::open(fs, &clock).unwrap();
        // The corrupt record was dropped and its slot recovered.
        assert_eq!(log.next_offset(), Offset::new(1));
        assert_eq!(log.next_seq(), Seq::new(1));
        // The torn tail was actually truncated: the file is now shorter.
        let len_after = log.filesystem().open(&name).unwrap().len().unwrap();
        assert!(len_after < len_before, "file should shrink on truncation");
        assert_eq!(log.append(&rec(b"after")).unwrap(), Offset::new(1));
        log.sync().unwrap();
        let records = read_back(log.filesystem(), 0);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].payload, b"good1");
        assert_eq!(records[1].payload, b"after");
    }

    #[cfg(unix)]
    #[test]
    fn recovery_resumes_on_a_real_directory() {
        use crate::fs::StdFs;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let clock = ManualClock::new();

        let mut log = Log::open(StdFs::new(root.clone()), &clock).unwrap();
        log.append(&rec(b"alpha")).unwrap();
        log.append(&rec(b"beta")).unwrap();
        log.sync().unwrap();
        drop(log);

        let mut log = Log::open(StdFs::new(root.clone()), &clock).unwrap();
        assert_eq!(log.next_offset(), Offset::new(2));
        assert_eq!(log.append(&rec(b"gamma")).unwrap(), Offset::new(2));
        log.sync().unwrap();

        let records = read_back(&StdFs::new(root), 0);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].payload, b"gamma");
        assert_eq!(records[2].seq, Seq::new(2));
    }
}
