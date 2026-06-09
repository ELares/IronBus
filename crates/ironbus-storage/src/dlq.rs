// SPDX-License-Identifier: MIT OR Apache-2.0
//! The durable dead-letter (DLQ) SINK and its crash-atomic, exactly-once move (#63).
//!
//! When the engine decides a message is poison (it exceeded `MaxDeliver`), the message must end
//! up in EXACTLY ONE durable place: written to this sink for later inspection, and committed-past
//! in its source consumer group so it never redelivers. This module is the durable side of that
//! move.
//!
//! The sink is a SECOND segmented [`Log`](crate::log::Log) rooted at a `dlq/` subdirectory of the
//! data directory (via [`crate::fs::Filesystem::subdir`]), so a poison record uses the exact same
//! framed, CRC32C'd, recoverable segment format as the main log and is readable by the SAME
//! [`SegmentReader`](crate::segment::SegmentReader) / [`OfflineReader`](crate::offline::OfflineReader)
//! code, with no second format to maintain.
//!
//! ## What a DLQ record preserves and carries
//! Each DLQ record preserves the ORIGINAL record verbatim (its key, payload, and the original
//! enqueue `timestamp_ms`) and carries the dead-letter metadata: the SOURCE offset, the consumer
//! GROUP, and the ATTEMPT count (deliveries) at which the message was poisoned. The metadata is
//! encoded as a fixed, self-describing prefix of the DLQ record's `headers` blob, ahead of the
//! original headers, so a single segment record holds both (see [`encode_dlq_headers`] for the
//! exact byte layout). The DLQ record's `timestamp_ms`, `key`, and `payload` are the original's.
//!
//! ## Exactly-once across a crash (the idempotency key)
//! The reconciliation key is `(group, source_offset, attempt)`. The DLQ Log itself is the durable
//! record of what has been dead-lettered: on open, [`DlqSink::open`] scans the DLQ segments and
//! rebuilds, per group, the HIGHEST source offset already dead-lettered. The engine consults that
//! high-water mark before appending: a `(group, offset)` already at or below the group's recorded
//! high-water mark is NOT re-appended (it is already in the sink), so a message that was appended
//! to the DLQ and then re-poisoned after a crash (because its source cursor commit had not yet
//! become durable) is committed-past WITHOUT a duplicate DLQ write. There is therefore no separate
//! sidecar file to keep consistent with the sink: the sink is the single source of truth, and a
//! reopen reconstructs the high-water mark from it.

use crate::fs::Filesystem;
use crate::log::{Append, Log, LogConfig};
use crate::naming::segment_file_name;
use crate::offline::OfflineReader;
use crate::segment::{OwnedRecord, SegmentReader, StorageError};
use ironbus_core::clock::Clock;
use ironbus_core::types::{Offset, RecordFlags};
use std::collections::BTreeMap;

/// The subdirectory of the data directory that holds the dead-letter sink's segments.
pub const DLQ_SUBDIR: &str = "dlq";

/// The 4-byte magic that opens a DLQ record's metadata header, also pinning the v1 metadata
/// layout. A header that does not begin with this is not a DLQ record this build understands.
pub const DLQ_HEADER_MAGIC: [u8; 4] = *b"DLQ1";

/// The fixed size of the dead-letter metadata header that prefixes a DLQ record's `headers` blob,
/// ahead of the original record's headers: `magic`(4) + `source_offset`(8) + `attempt`(4) +
/// `group_len`(2) + `orig_headers_len`(2).
pub const DLQ_META_LEN: usize = 4 + 8 + 4 + 2 + 2;

/// The fully decoded contents of one DLQ record: the original record (rebuilt verbatim) plus the
/// dead-letter metadata it was poisoned with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DlqEntry {
    /// The DLQ log offset this entry occupies in the sink (its position in the DLQ, not the
    /// source offset).
    pub dlq_offset: Offset,
    /// The consumer group the message was poisoned in.
    pub group: String,
    /// The SOURCE log offset the poison message had in the main log.
    pub source_offset: u64,
    /// The attempt (delivery) count at which the message was dead-lettered.
    pub attempt: u32,
    /// The original record's producer timestamp, milliseconds since the Unix epoch (preserved).
    pub timestamp_ms: u64,
    /// The original record's routing/ordering key (preserved verbatim).
    pub key: Vec<u8>,
    /// The original record's headers blob (preserved verbatim, metadata stripped).
    pub headers: Vec<u8>,
    /// The original record's payload (preserved verbatim).
    pub payload: Vec<u8>,
    /// The stored DLQ record's flags. The payload is preserved VERBATIM (compressed if the original
    /// was, since the sink never decodes it), so the `COMPRESSED` bit here MUST be carried back to a
    /// redriven record or the consumer would receive a compressed stream labeled uncompressed. The
    /// re-derivable bits (`HAS_KEY`, `HAS_XXH3`) are recomputed by the main-log append, so a redrive
    /// masks this to the content flags it must preserve.
    pub original_flags: RecordFlags,
}

/// Encodes the dead-letter metadata header followed by the original headers, the blob that becomes
/// a DLQ record's `headers` field. The layout (all little-endian) is:
///
/// | bytes      | field                                   |
/// |------------|-----------------------------------------|
/// | `[0, 4)`   | magic [`DLQ_HEADER_MAGIC`]               |
/// | `[4, 12)`  | source offset (u64)                     |
/// | `[12, 16)` | attempt / deliveries (u32)              |
/// | `[16, 18)` | group name length `g` (u16)             |
/// | `[18, 20)` | original headers length `h` (u16)       |
/// | `[20, 20+g)`        | the group name bytes            |
/// | `[20+g, 20+g+h)`    | the original headers            |
///
/// Returns `None` if the group name or the original headers are longer than `u16::MAX` (the
/// length fields cannot describe them); both come from the wire `PUB` path, which is already
/// `u16`-bounded, so a real record never trips this.
#[must_use]
pub fn encode_dlq_headers(
    group: &str,
    source_offset: u64,
    attempt: u32,
    original_headers: &[u8],
) -> Option<Vec<u8>> {
    let group_len = u16::try_from(group.len()).ok()?;
    let headers_len = u16::try_from(original_headers.len()).ok()?;
    let mut out = Vec::with_capacity(DLQ_META_LEN + group.len() + original_headers.len());
    out.extend_from_slice(&DLQ_HEADER_MAGIC);
    out.extend_from_slice(&source_offset.to_le_bytes());
    out.extend_from_slice(&attempt.to_le_bytes());
    out.extend_from_slice(&group_len.to_le_bytes());
    out.extend_from_slice(&headers_len.to_le_bytes());
    out.extend_from_slice(group.as_bytes());
    out.extend_from_slice(original_headers);
    Some(out)
}

/// The dead-letter metadata parsed out of a DLQ record's `headers` blob: the source offset, the
/// attempt, the group, and the byte range of the original headers within the blob.
struct DlqMeta {
    source_offset: u64,
    attempt: u32,
    group: String,
    original_headers: Vec<u8>,
}

/// Reads `n` little-endian bytes at `at` as a `u64`/`u32`/`u16`, or `None` if `blob` is too short.
fn read_u64(blob: &[u8], at: usize) -> Option<u64> {
    blob.get(at..at + 8)
        .and_then(|s| <[u8; 8]>::try_from(s).ok())
        .map(u64::from_le_bytes)
}
fn read_u32(blob: &[u8], at: usize) -> Option<u32> {
    blob.get(at..at + 4)
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map(u32::from_le_bytes)
}
fn read_u16(blob: &[u8], at: usize) -> Option<usize> {
    blob.get(at..at + 2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map(|b| usize::from(u16::from_le_bytes(b)))
}

/// Decodes the dead-letter metadata header of a DLQ record's `headers` blob, returning `None` for
/// a blob that does not begin with [`DLQ_HEADER_MAGIC`] or whose declared lengths run past its end
/// (a foreign or corrupt record). The metadata block and the trailing original headers must fit
/// exactly, so a malformed record is rejected rather than misread.
fn decode_dlq_headers(blob: &[u8]) -> Option<DlqMeta> {
    if blob.get(0..4)? != DLQ_HEADER_MAGIC {
        return None;
    }
    let source_offset = read_u64(blob, 4)?;
    let attempt = read_u32(blob, 12)?;
    let group_len = read_u16(blob, 16)?;
    let headers_len = read_u16(blob, 18)?;
    let group_start = DLQ_META_LEN;
    let headers_start = group_start.checked_add(group_len)?;
    let headers_end = headers_start.checked_add(headers_len)?;
    // The blob must be EXACTLY the metadata plus the two declared spans: a longer or shorter blob
    // is malformed, so decode fails closed rather than guessing.
    if blob.len() != headers_end {
        return None;
    }
    let group = String::from_utf8(blob.get(group_start..headers_start)?.to_vec()).ok()?;
    let original_headers = blob.get(headers_start..headers_end)?.to_vec();
    Some(DlqMeta {
        source_offset,
        attempt,
        group,
        original_headers,
    })
}

/// Decodes one stored DLQ [`OwnedRecord`] into a [`DlqEntry`], or `None` if its headers are not a
/// valid DLQ metadata block (a foreign or corrupt record is skipped, never misreported).
#[must_use]
pub fn decode_entry(record: &OwnedRecord) -> Option<DlqEntry> {
    let meta = decode_dlq_headers(&record.headers)?;
    Some(DlqEntry {
        dlq_offset: record.offset,
        group: meta.group,
        source_offset: meta.source_offset,
        attempt: meta.attempt,
        timestamp_ms: record.timestamp_ms,
        key: record.key.clone(),
        headers: meta.original_headers,
        payload: record.payload.clone(),
        original_flags: record.flags,
    })
}

/// The durable dead-letter sink: a second segmented [`Log`] plus the per-group high-water mark of
/// the highest source offset already dead-lettered, for idempotent appends (#63).
pub struct DlqSink<F: Filesystem, C: Clock> {
    log: Log<F, C>,
    /// The highest SOURCE offset already dead-lettered, per consumer group, reconstructed at open
    /// from the durable DLQ records and advanced on each append. The engine consults this to skip
    /// a duplicate append for a `(group, source_offset)` already in the sink.
    highest_source_offset: BTreeMap<String, u64>,
    /// The number of records durably appended to the sink across its lifetime (the DLQ depth at
    /// open plus every append since), for the operator's `ironbus_dlq_records_total` metric.
    records: u64,
}

impl<F: Filesystem, C: Clock> std::fmt::Debug for DlqSink<F, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DlqSink")
            .field("records", &self.records)
            .field("highest_source_offset", &self.highest_source_offset)
            .finish_non_exhaustive()
    }
}

impl<F: Filesystem, C: Clock> DlqSink<F, C> {
    /// Opens (recovering, or creating fresh) the dead-letter sink rooted at the `dlq/`
    /// subdirectory of `parent_fs`, rebuilding the per-group dead-lettered high-water mark by
    /// scanning the durable DLQ records. The subdirectory is created on demand by
    /// [`Filesystem::subdir`].
    ///
    /// # Errors
    /// Propagates a storage error from creating the subdirectory, opening the DLQ log, or scanning
    /// its records.
    pub fn open(parent_fs: &F, clock: C, config: LogConfig) -> Result<DlqSink<F, C>, StorageError> {
        let dlq_fs = parent_fs.subdir(DLQ_SUBDIR).map_err(StorageError::Io)?;
        let log = Log::open(dlq_fs, clock, config)?;
        let mut sink = DlqSink {
            log,
            highest_source_offset: BTreeMap::new(),
            records: 0,
        };
        sink.rebuild_high_water_mark()?;
        Ok(sink)
    }

    /// Scans every durable DLQ record (reusing the recovery decode path) and rebuilds the per-group
    /// highest dead-lettered source offset plus the total record count. Called once at open; the
    /// DLQ is the single durable source of truth for what has been dead-lettered, so this is what
    /// makes the move idempotent across a crash without a separate sidecar.
    fn rebuild_high_water_mark(&mut self) -> Result<(), StorageError> {
        self.highest_source_offset.clear();
        self.records = 0;
        let flushed = self.log.flushed_offset().get();
        if flushed == 0 {
            return Ok(());
        }
        // The DLQ log is small relative to the main log (only poison records), and recovery already
        // walked the segments; read them back through the same segment reader to decode metadata.
        let ids = crate::naming::segment_ids(self.log.filesystem()).map_err(StorageError::Io)?;
        for id in ids {
            let scan =
                SegmentReader::open(self.log.filesystem().open(&segment_file_name(id))?)?.scan()?;
            for record in &scan.records {
                if record.offset.get() >= flushed {
                    break;
                }
                if let Some(meta) = decode_dlq_headers(&record.headers) {
                    self.records = self.records.saturating_add(1);
                    let entry = self
                        .highest_source_offset
                        .entry(meta.group)
                        .or_insert(meta.source_offset);
                    *entry = (*entry).max(meta.source_offset);
                }
            }
        }
        Ok(())
    }

    /// Whether `(group, source_offset)` is ALREADY in the durable DLQ: true when `source_offset`
    /// is at or below the group's recorded high-water mark. The engine calls this to make the move
    /// idempotent: a redelivered-then-re-poisoned message already in the sink is committed-past
    /// WITHOUT a second append. Source offsets only ever rise for a group, so the high-water mark
    /// is a sound dedupe key.
    #[must_use]
    pub fn already_dead_lettered(&self, group: &str, source_offset: u64) -> bool {
        self.highest_source_offset
            .get(group)
            .is_some_and(|&hwm| source_offset <= hwm)
    }

    /// Appends one poison record to the sink and makes it durable (fsync) BEFORE returning, then
    /// advances the in-memory high-water mark. This is the durable half of the crash-atomic move:
    /// the caller appends-and-fsyncs HERE first, and only then commits the source group's cursor
    /// past the message, so a crash between the two leaves the source uncommitted and the record
    /// already durable in the DLQ; on reopen the high-water mark (rebuilt from this very record)
    /// suppresses the duplicate append.
    ///
    /// The original record's `key`, `payload`, and `timestamp_ms` are preserved verbatim; the
    /// dead-letter metadata and the original headers are packed into the DLQ record's headers via
    /// [`encode_dlq_headers`].
    ///
    /// # Errors
    /// Returns [`StorageError::SegmentFull`] if the metadata could not be framed (an original
    /// header or group name longer than `u16::MAX`, unreachable from the wire), or a storage error
    /// from the append or its durability barrier. On any error nothing is recorded as
    /// dead-lettered (the high-water mark and count do not move), so the caller MUST NOT commit the
    /// source cursor: the move did not happen.
    pub fn append_poison(
        &mut self,
        group: &str,
        source: &OwnedRecord,
        attempt: u32,
    ) -> Result<Offset, StorageError> {
        let source_offset = source.offset.get();
        let headers = encode_dlq_headers(group, source_offset, attempt, &source.headers)
            // A group name or header blob over u16::MAX cannot be framed; the wire bounds both, so
            // this is unreachable in practice, surfaced as the structural SegmentFull rather than a
            // panic so the move simply does not happen and the source is not committed.
            .ok_or(StorageError::SegmentFull)?;
        // Preserve HAS_KEY consistency: the codec derives the key flag from the key length and
        // overwrites it, so clear the original HAS_KEY bit and let the log re-derive it from the
        // (preserved) key. The other flags (e.g. COMPRESSED) are carried through unchanged.
        let flags = RecordFlags::from_bits(source.flags.bits() & !RecordFlags::HAS_KEY.bits());
        let offset = self.log.append(&Append {
            timestamp_ms: source.timestamp_ms,
            flags,
            key: &source.key,
            headers: &headers,
            payload: &source.payload,
        })?;
        // Make the poison record durable BEFORE the caller commits the source cursor: this ordering
        // is the crash-safety contract. A failed durability barrier freezes the DLQ writer and is
        // surfaced, so the caller does not commit the source past an un-fsynced DLQ record.
        self.log.sync()?;
        let entry = self
            .highest_source_offset
            .entry(group.to_string())
            .or_insert(source_offset);
        *entry = (*entry).max(source_offset);
        self.records = self.records.saturating_add(1);
        Ok(offset)
    }

    /// The number of records durably written to the sink (the DLQ depth): the records present at
    /// open plus every append since. Exposed for the `ironbus_dlq_records_total` metric.
    #[must_use]
    pub fn records(&self) -> u64 {
        self.records
    }

    /// The highest dead-lettered source offset recorded for `group`, or `None` if the group has
    /// never had a message dead-lettered. For tests and inspection.
    #[must_use]
    pub fn highest_for_group(&self, group: &str) -> Option<u64> {
        self.highest_source_offset.get(group).copied()
    }

    /// Borrows the underlying DLQ log (for inspection and tests).
    #[must_use]
    pub fn log(&self) -> &Log<F, C> {
        &self.log
    }
}

/// Reads back every durable record in a stopped broker's DLQ sink, decoded into [`DlqEntry`]s, with
/// no server running and WITHOUT mutating the directory, reusing the read-only
/// [`OfflineReader`]. This backs the offline `dump --dlq` verb (#63). A record whose headers are
/// not a valid DLQ metadata block is skipped (it is foreign to the sink), never misreported.
///
/// `parent_fs` is the data directory; the DLQ lives in its `dlq/` subdirectory. An ABSENT DLQ
/// subdirectory (no message was ever dead-lettered) reads as an empty list, not an error.
///
/// # Errors
/// Propagates an IO error or a chain error from the offline reader. A missing `dlq/` subdirectory
/// is NOT an error (it yields an empty list).
pub fn read_dlq_entries<F: Filesystem>(parent_fs: &F) -> Result<Vec<DlqEntry>, StorageError> {
    // The DLQ subdir may not exist yet (nothing was ever dead-lettered): treat that as empty,
    // never an error, so `dump --dlq` on a clean directory shows nothing. Probe WITHOUT creating
    // it (the inspector must never mutate the directory), so a read of a poison-free data dir does
    // not materialize a `dlq/` subdirectory.
    if !parent_fs
        .subdir_exists(DLQ_SUBDIR)
        .map_err(StorageError::Io)?
    {
        return Ok(Vec::new());
    }
    let dlq_fs = parent_fs.subdir(DLQ_SUBDIR).map_err(StorageError::Io)?;
    let reader = OfflineReader::open(dlq_fs)?;
    let mut entries = Vec::new();
    for &id in reader.segment_ids() {
        for record in reader.read_segment(id)? {
            if let Some(entry) = decode_entry(&record) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::Seq;

    fn config() -> LogConfig {
        LogConfig::default()
    }

    fn source_record(offset: u64, key: &[u8], headers: &[u8], payload: &[u8]) -> OwnedRecord {
        OwnedRecord {
            offset: Offset::new(offset),
            seq: Seq::new(offset),
            timestamp_ms: 1234 + offset,
            flags: RecordFlags::EMPTY,
            key: key.to_vec(),
            headers: headers.to_vec(),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn headers_round_trip_through_encode_decode() {
        let blob = encode_dlq_headers("orders", 42, 6, b"orig-headers").unwrap();
        assert_eq!(&blob[0..4], &DLQ_HEADER_MAGIC);
        let meta = decode_dlq_headers(&blob).unwrap();
        assert_eq!(meta.source_offset, 42);
        assert_eq!(meta.attempt, 6);
        assert_eq!(meta.group, "orders");
        assert_eq!(meta.original_headers, b"orig-headers");
    }

    #[test]
    fn decode_rejects_a_foreign_or_malformed_header() {
        // Wrong magic.
        assert!(decode_dlq_headers(b"XXXXrest").is_none());
        // Too short to even hold the fixed metadata.
        assert!(decode_dlq_headers(b"DLQ1").is_none());
        // Declared lengths that run past the end of the blob.
        let mut blob = encode_dlq_headers("g", 1, 1, b"h").unwrap();
        blob.pop(); // now one byte short of the declared spans
        assert!(decode_dlq_headers(&blob).is_none());
    }

    #[test]
    fn appended_poison_preserves_the_original_and_is_durable_on_reopen() {
        let fs = InMemoryFs::new();
        let mut sink = DlqSink::open(&fs, ManualClock::new(), config()).unwrap();
        let src = source_record(7, b"k", b"hdr", b"the-payload");
        sink.append_poison("orders", &src, 6).unwrap();
        assert_eq!(sink.records(), 1);
        assert_eq!(sink.highest_for_group("orders"), Some(7));

        // Reopen the sink: the high-water mark and count come back from the durable records alone.
        let reopened = DlqSink::open(&fs, ManualClock::new(), config()).unwrap();
        assert_eq!(reopened.records(), 1);
        assert_eq!(reopened.highest_for_group("orders"), Some(7));
        assert!(reopened.already_dead_lettered("orders", 7));
        assert!(!reopened.already_dead_lettered("orders", 8));
        assert!(!reopened.already_dead_lettered("other", 7));

        // The offline read path returns the original record verbatim plus the metadata.
        let entries = read_dlq_entries(&fs).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.group, "orders");
        assert_eq!(e.source_offset, 7);
        assert_eq!(e.attempt, 6);
        assert_eq!(e.timestamp_ms, src.timestamp_ms);
        assert_eq!(e.key, b"k");
        assert_eq!(e.headers, b"hdr");
        assert_eq!(e.payload, b"the-payload");
    }

    #[test]
    fn an_absent_dlq_reads_as_empty() {
        // No sink was ever opened, so the dlq/ subdir does not exist: a read shows nothing.
        let fs = InMemoryFs::new();
        assert!(read_dlq_entries(&fs).unwrap().is_empty());
    }

    #[test]
    fn the_high_water_mark_is_per_group_and_takes_the_maximum() {
        let fs = InMemoryFs::new();
        let mut sink = DlqSink::open(&fs, ManualClock::new(), config()).unwrap();
        sink.append_poison("a", &source_record(2, b"", b"", b"p"), 6)
            .unwrap();
        sink.append_poison("a", &source_record(5, b"", b"", b"p"), 6)
            .unwrap();
        sink.append_poison("b", &source_record(3, b"", b"", b"p"), 6)
            .unwrap();
        assert_eq!(sink.highest_for_group("a"), Some(5));
        assert_eq!(sink.highest_for_group("b"), Some(3));
        // Idempotency reads against the per-group maximum.
        assert!(sink.already_dead_lettered("a", 5));
        assert!(sink.already_dead_lettered("a", 2));
        assert!(!sink.already_dead_lettered("a", 6));
        assert!(!sink.already_dead_lettered("b", 4));
    }
}
