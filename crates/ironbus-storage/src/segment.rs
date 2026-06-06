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

    /// The log offset the NEXT appended record will receive.
    #[must_use]
    pub fn next_offset(&self) -> Offset {
        Offset::new(
            self.header
                .base_offset
                .get()
                .wrapping_add(u64::from(self.record_count)),
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
        let mut buf = Vec::new();
        codec::encode(record, &mut buf).map_err(|_| StorageError::SegmentFull)?;
        let len = u64::try_from(buf.len()).map_err(|_| StorageError::SegmentFull)?;
        let end = self
            .write_pos
            .checked_add(len)
            .ok_or(StorageError::SegmentFull)?;
        self.file.write_all_at(&buf, self.write_pos)?;
        let offset = self.next_offset();
        self.write_pos = end;
        self.record_count += 1;
        self.last_seq = record.seq;
        Ok(offset)
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
    /// The byte offset at which scanning stopped (the durable, valid prefix length).
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
        let mut hbuf = [0u8; SEGMENT_HEADER_LEN];
        file.read_exact_at(&mut hbuf, 0)?;
        let header = SegmentHeader::decode(&hbuf)?;
        let file_len = file.len()?;
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

    /// Scans the segment: detects a sealed footer (bound to this segment), reads the
    /// record region, and decodes records in order, stopping at the first torn or
    /// corrupt frame. The records before that point are the durable valid prefix.
    ///
    /// # Errors
    /// Returns an error if the footer belongs to a different segment, or on IO error.
    pub fn scan(&self) -> Result<SegmentScan, StorageError> {
        let header_end = SEGMENT_HEADER_LEN as u64;
        let (footer, body_end) = self.detect_footer(header_end)?;

        let body_len = usize::try_from(body_end.saturating_sub(header_end))
            .map_err(|_| StorageError::SegmentFull)?;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            self.file.read_exact_at(&mut body, header_end)?;
        }

        let mut records = Vec::new();
        let mut cursor = 0usize;
        let mut clean = true;
        loop {
            if cursor >= body.len() {
                break;
            }
            // A torn or corrupt frame ends the valid prefix; recovery skips the
            // rest. The bounded-loss report is produced by a later layer.
            let Ok((view, consumed)) = codec::decode(&body[cursor..]) else {
                clean = false;
                break;
            };
            let offset = Offset::new(
                self.header
                    .base_offset
                    .get()
                    .wrapping_add(records.len() as u64),
            );
            records.push(OwnedRecord::from_view(offset, &view));
            cursor += consumed;
        }

        Ok(SegmentScan {
            header: self.header,
            records,
            footer,
            clean,
            valid_end: header_end + cursor as u64,
        })
    }

    /// Looks for a sealed footer in the last 32 bytes. Returns the footer (if the
    /// segment is sealed and the footer is bound to this segment) and the byte offset
    /// at which the record region ends.
    fn detect_footer(&self, header_end: u64) -> Result<(Option<SegmentFooter>, u64), StorageError> {
        let footer_len = SEGMENT_FOOTER_LEN as u64;
        if self.file_len < header_end + footer_len {
            return Ok((None, self.file_len.max(header_end)));
        }
        let mut fbuf = [0u8; SEGMENT_FOOTER_LEN];
        self.file
            .read_exact_at(&mut fbuf, self.file_len - footer_len)?;
        match SegmentFooter::decode(&fbuf) {
            Ok(footer) => {
                if footer.segment_id != self.header.segment_id {
                    return Err(StorageError::FooterSegmentMismatch {
                        header: self.header.segment_id,
                        footer: footer.segment_id,
                    });
                }
                Ok((Some(footer), self.file_len - footer_len))
            }
            // Not a footer: an active (unsealed) segment whose tail is record data.
            Err(_) => Ok((None, self.file_len)),
        }
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
}
