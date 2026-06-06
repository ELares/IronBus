// SPDX-License-Identifier: MIT OR Apache-2.0
//! A read-only reader for a stopped broker's data directory (#15, #90): decode and inspect the
//! durable records with no server running, reusing exactly the recovery decode path
//! ([`SegmentReader`]) so there is one authoritative interpretation of the bytes.
//!
//! Unlike [`crate::log::Log::open`], opening an [`OfflineReader`] NEVER mutates the directory:
//! it does not truncate a torn tail, roll a sealed segment forward, or create a new segment. It
//! bounds every read to the durable high-water mark (the longest valid record prefix), so a
//! torn or unsynced tail past that mark is reported as loss but never read as a record, even
//! when the file is physically longer. It also does NOT fail closed on excessive loss (the I3
//! cap that [`crate::log::Log`] recovery enforces): an inspector must be able to show a badly
//! corrupted directory, not refuse to open it. This backs the offline `peek` / `dump` / `info`
//! verbs (#92).

use crate::fs::Filesystem;
use crate::io::RandomAccessFile;
use crate::loss::{LossEvent, LossReport, ReasonCode};
use crate::naming::{segment_file_name, segment_ids};
use crate::segment::{OwnedRecord, SegmentReader, StorageError};
use ironbus_core::types::Offset;

/// A read-only view of a data directory's durable records (#90).
#[derive(Debug)]
pub struct OfflineReader<F: Filesystem> {
    fs: F,
    /// The validated segment ids, ascending.
    segment_ids: Vec<u64>,
    /// The durable high-water mark: the offset just past the last durable record. Every record
    /// the reader yields has an offset strictly below this; no durable record exists at or
    /// above it.
    durable_head: Offset,
    /// What the durable prefix dropped to reach the last intact record (a torn or corrupt
    /// active tail), in the same shape recovery reports. Empty for a clean directory.
    loss_report: LossReport,
}

impl<F: Filesystem> OfflineReader<F> {
    /// Opens a data directory read-only, validating the segment chain and computing the durable
    /// high-water mark and the loss report WITHOUT modifying anything.
    ///
    /// The chain is validated exactly as recovery validates it: each segment's stored id
    /// matches its file name, each base continues from its predecessor, and every non-final
    /// segment is sealed. A broken chain returns the same typed [`StorageError`] recovery does,
    /// so the offline view and online recovery agree on what is a valid directory. The records
    /// are decoded only on demand by [`OfflineReader::read_segment`], so opening is O(segments),
    /// not O(records).
    ///
    /// # Errors
    /// Propagates an IO error, or a chain error ([`StorageError::SegmentIdMismatch`],
    /// [`StorageError::SegmentChainBroken`], [`StorageError::UnsealedPredecessor`]).
    pub fn open(fs: F) -> Result<OfflineReader<F>, StorageError> {
        let ids = segment_ids(&fs)?;
        let total = ids.len();
        let mut next_base_offset = 0u64;
        let mut next_base_seq = 0u64;
        let mut loss_report = LossReport::new();
        for (i, &id) in ids.iter().enumerate() {
            let name = segment_file_name(id);
            // Capture the physical length before the reader consumes the file handle, so a torn
            // tail past the valid prefix can be reported as loss.
            let physical_len = fs.open(&name)?.len()?;
            let scan = SegmentReader::open(fs.open(&name)?)?.scan_recovery()?;
            let header = scan.header;
            if header.segment_id != id {
                return Err(StorageError::SegmentIdMismatch {
                    file_id: id,
                    header_id: header.segment_id,
                });
            }
            let base_offset = header.base_offset.get();
            let base_seq = header.base_seq.get();
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
            // Only the active (final, unsealed) segment can carry a torn or corrupt tail past
            // its valid prefix; a sealed segment's `valid_end` is its footer start, with no
            // loss. Record the dropped span exactly as recovery would, but without truncating
            // it: the bytes stay on disk for an operator to inspect.
            if is_last && scan.footer.is_none() && scan.valid_end < physical_len {
                let reason = scan.tail_reason.unwrap_or(ReasonCode::TornTail);
                loss_report.push(LossEvent::span(id, scan.valid_end, physical_len, 1, reason));
            }
        }
        Ok(OfflineReader {
            fs,
            segment_ids: ids,
            durable_head: Offset::new(next_base_offset),
            loss_report,
        })
    }

    /// The durable high-water mark: the offset just past the last durable record. Every record
    /// the reader yields has an offset strictly below this.
    #[must_use]
    pub fn durable_head(&self) -> Offset {
        self.durable_head
    }

    /// The loss the durable prefix dropped to reach the last intact record (a torn or corrupt
    /// active tail), in the same structured shape recovery reports. Empty for a clean
    /// directory. Unlike recovery, the offline reader does not fail closed on excessive loss.
    #[must_use]
    pub fn loss_report(&self) -> &LossReport {
        &self.loss_report
    }

    /// The validated segment ids, ascending. Iterate them to read the whole directory one
    /// segment at a time via [`OfflineReader::read_segment`].
    #[must_use]
    pub fn segment_ids(&self) -> &[u64] {
        &self.segment_ids
    }

    /// Decodes the durable records of one segment, in order, reusing the recovery decode path
    /// ([`SegmentReader::scan`]). The records stop at the segment's durable valid prefix, so a
    /// torn or unsynced tail is never returned. Reading one segment at a time bounds memory to
    /// a single segment's records rather than the whole directory.
    ///
    /// # Errors
    /// Propagates an IO error (including a segment id not present in the directory) or a decode
    /// error from the segment header.
    pub fn read_segment(&self, id: u64) -> Result<Vec<OwnedRecord>, StorageError> {
        let scan = SegmentReader::open(self.fs.open(&segment_file_name(id))?)?.scan()?;
        Ok(scan.records)
    }

    /// Consumes the reader and returns its filesystem, so the caller (e.g. a test or a later
    /// online open) can reuse it.
    #[must_use]
    pub fn into_filesystem(self) -> F {
        self.fs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use crate::log::{Append, Log, LogConfig};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;

    fn append(log: &mut Log<InMemoryFs, ManualClock>, payload: &[u8]) {
        log.append(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        })
        .unwrap();
    }

    /// Reads every durable record across the reader's segments, in order.
    fn all_records(reader: &OfflineReader<InMemoryFs>) -> Vec<OwnedRecord> {
        let mut out = Vec::new();
        for &id in reader.segment_ids() {
            out.extend(reader.read_segment(id).unwrap());
        }
        out
    }

    #[test]
    fn an_empty_directory_reads_nothing() {
        let reader = OfflineReader::open(InMemoryFs::new()).unwrap();
        assert_eq!(reader.durable_head(), Offset::ZERO);
        assert!(reader.segment_ids().is_empty());
        assert!(reader.loss_report().is_empty());
        assert!(all_records(&reader).is_empty());
    }

    #[test]
    fn it_reads_a_clean_multi_segment_log_in_order() {
        // A tiny segment cap forces several rolls, so the reader must stitch the chain.
        let config = LogConfig::new(LogConfig::MIN_MAX_SEGMENT_BYTES).unwrap();
        let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), config).unwrap();
        for i in 0..8u8 {
            append(&mut log, &[i; 8]);
        }
        log.sync().unwrap();
        let expected_head = log.flushed_offset();
        let fs = log.into_filesystem();

        let reader = OfflineReader::open(fs).unwrap();
        assert!(
            reader.segment_ids().len() > 1,
            "the tiny cap should have rolled several segments, got {}",
            reader.segment_ids().len()
        );
        assert_eq!(reader.durable_head(), expected_head);
        assert!(
            reader.loss_report().is_empty(),
            "a clean log reports no loss"
        );
        let records = all_records(&reader);
        assert_eq!(u64::try_from(records.len()).unwrap(), expected_head.get());
        for (i, r) in records.iter().enumerate() {
            let want = u8::try_from(i).unwrap();
            assert_eq!(
                r.offset,
                Offset::new(u64::from(want)),
                "offsets are contiguous"
            );
            assert_eq!(r.payload, vec![want; 8]);
        }
    }

    #[test]
    fn the_reader_agrees_with_online_recovery_on_the_same_bytes() {
        let config = LogConfig::new(LogConfig::MIN_MAX_SEGMENT_BYTES).unwrap();
        let mut log = Log::open(InMemoryFs::new(), ManualClock::new(), config).unwrap();
        for i in 0..6u8 {
            append(&mut log, &[i; 8]);
        }
        log.sync().unwrap();
        let fs = log.into_filesystem();

        // Read offline first (read-only), capturing its view.
        let reader = OfflineReader::open(fs).unwrap();
        let offline_head = reader.durable_head();
        let offline_records = all_records(&reader);
        let offline_loss = reader.loss_report().clone();
        let fs = reader.into_filesystem();

        // Now recover online on the very same bytes; the durable prefix, the records, and the
        // loss must match, so the offline reader and recovery interpret the bytes identically.
        let recovered = Log::open(fs, ManualClock::new(), config).unwrap();
        assert_eq!(offline_head, recovered.flushed_offset());
        assert_eq!(offline_loss, *recovered.loss_report());
        let online_records = recovered
            .read_from(Offset::ZERO, usize::try_from(offline_head.get()).unwrap())
            .unwrap();
        assert_eq!(offline_records, online_records);
    }

    #[test]
    fn a_torn_tail_is_bounded_reported_and_left_untouched() {
        let mut log =
            Log::open(InMemoryFs::new(), ManualClock::new(), LogConfig::default()).unwrap();
        for i in 0..4u8 {
            append(&mut log, &[i; 8]);
        }
        log.sync().unwrap();
        let fs = log.into_filesystem();

        // Tear three bytes off the last record so its frame no longer parses: the durable
        // prefix is the first three records, and the file is physically longer than that.
        let file = fs.open(&segment_file_name(0)).unwrap();
        let torn_len = file.len().unwrap() - 3;
        file.set_len(torn_len).unwrap();
        file.sync_data().unwrap();

        let reader = OfflineReader::open(fs).unwrap();
        // The reader bounds to the durable prefix: the torn record (offset 3) is excluded.
        assert_eq!(reader.durable_head(), Offset::new(3));
        let records = all_records(&reader);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].offset, Offset::new(2));

        // The dropped span is reported, exactly as recovery would: one torn-tail event in
        // segment 0 ending at the physical (torn) length.
        let report = reader.loss_report();
        assert_eq!(report.events.len(), 1);
        let e = report.events[0];
        assert_eq!(e.reason_code, ReasonCode::TornTail);
        assert_eq!(e.segment_id, 0);
        assert_eq!(e.byte_offset_end, torn_len);
        assert!(e.byte_offset_start < torn_len);

        // Read-only: the reader did NOT truncate the torn tail (online recovery would have).
        // The file is still its physically-torn length, proving the inspector never wrote.
        let after_len = reader
            .into_filesystem()
            .open(&segment_file_name(0))
            .unwrap()
            .len()
            .unwrap();
        assert_eq!(
            after_len, torn_len,
            "the offline reader must not mutate the file"
        );
    }
}
