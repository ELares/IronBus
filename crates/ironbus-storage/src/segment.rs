// SPDX-License-Identifier: MIT OR Apache-2.0
//! Writing and reading a single log segment on top of the [`RandomAccessFile`] seam.
//!
//! A segment file is a 64-byte header, a contiguous run of record frames, and (once
//! sealed) a 32-byte footer. The active segment IS the write-ahead log: a record is
//! durable once it has been written and the file fdatasync'd. This module appends
//! records and scans them back, stopping cleanly at a torn or corrupt tail, which is
//! the foundation of recovery.

use crate::io::RandomAccessFile;
use ironbus_core::codec::{self, DecodeError, RecordView};
use ironbus_core::format::{SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN};
use ironbus_core::segment::{SegmentError, SegmentFooter, SegmentHeader};
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
        }
    }
}
impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(e) => Some(e),
            StorageError::Record(e) => Some(e),
            StorageError::Segment(e) => Some(e),
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
}

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
        })
    }

    /// Resumes appending to an existing, already-validated segment at its recovered
    /// write head, without rewriting the header.
    ///
    /// Recovery scans the segment, truncates any torn tail, and calls this with the
    /// recovered state: `write_pos` is the byte offset just past the last intact record
    /// (`SegmentScan::valid_end`), `record_count` is how many records precede it, and
    /// `last_seq` is that last record's sequence, or the header `base_seq` if the
    /// segment is empty. The caller guarantees those match the bytes on disk; this
    /// constructor performs no IO.
    #[must_use]
    pub fn resume(
        file: F,
        header: SegmentHeader,
        write_pos: u64,
        record_count: u32,
        last_seq: Seq,
    ) -> SegmentWriter<F> {
        SegmentWriter {
            file,
            header,
            write_pos,
            record_count,
            last_seq,
        }
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
        let mut buf = Vec::new();
        codec::encode(record, &mut buf).map_err(|_| StorageError::SegmentFull)?;
        let len = u64::try_from(buf.len()).map_err(|_| StorageError::SegmentFull)?;
        let end = self
            .write_pos
            .checked_add(len)
            .ok_or(StorageError::SegmentFull)?;
        self.file.write_all_at(&buf, self.write_pos)?;
        self.write_pos = end;
        self.record_count += 1;
        self.last_seq = record.seq;
        Ok(Offset::new(offset))
    }

    /// Flushes appended records to durable storage (fdatasync). A record is durable
    /// once this returns.
    ///
    /// # Errors
    /// Propagates the underlying IO error. A fatal sync error must be treated as
    /// terminal by the caller (the writer is frozen read-only).
    pub fn sync(&self) -> Result<(), StorageError> {
        self.file.sync_data()?;
        Ok(())
    }

    /// Seals the segment by writing the footer and a full fsync, consuming the writer
    /// and returning the footer.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    pub fn seal(self) -> Result<SegmentFooter, StorageError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::InMemoryFile;
    use ironbus_core::format::RECORD_HEADER_LEN;
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
}
