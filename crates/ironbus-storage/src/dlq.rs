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
//! The reconciliation key is the EXACT `(group, source_offset)`. The DLQ Log itself is the durable
//! record of what has been dead-lettered: on open, [`DlqSink::open`] scans the DLQ segments and
//! rebuilds, per group, the SET of source offsets already dead-lettered. The engine consults that
//! set before appending: a `(group, offset)` whose EXACT offset is already in the set is NOT
//! re-appended (it is already in the sink), so a message that was appended to the DLQ and then
//! re-poisoned after a crash (because its source cursor commit had not yet become durable) is
//! committed-past WITHOUT a duplicate DLQ write. The membership is EXACT, never `offset <= max`
//! (#800): poison messages do not cross the max-deliver threshold in ascending order, so a high-water
//! mark would silently drop a lower offset dead-lettered after a higher one — leaving it in ZERO
//! durable places, the exact loss the DLQ exists to prevent. Each per-group set is bounded by the
//! source group's in-flight/ahead window: [`DlqSink::prune_below`] drops offsets below the source
//! cursor's committed watermark (which can never redeliver or re-poison). There is therefore no
//! separate sidecar file to keep consistent with the sink: the sink is the single source of truth,
//! and a reopen reconstructs the exact set from it.

use crate::fs::Filesystem;
use crate::log::{Append, Log, LogConfig};
use crate::naming::segment_file_name;
use crate::offline::OfflineReader;
use crate::segment::{OwnedRecord, SegmentReader, StorageError};
use ironbus_core::clock::Clock;
use ironbus_core::types::{Offset, RecordFlags};
use std::collections::{BTreeMap, BTreeSet};

/// The subdirectory of the data directory that holds the DEFAULT dead-letter sink's segments. A
/// dead-letter EXCHANGE (V2-M4, #551) routes to a CONFIGURABLE subdir instead (the target name), so
/// this is only the default sink when no DLX is configured — kept byte-identical to today.
pub const DLQ_SUBDIR: &str = "dlq";

/// The 4-byte magic that opens a v1 DLQ record's metadata header, also pinning the v1 metadata
/// layout. A header that does not begin with a recognized DLQ magic is not a DLQ record this build
/// understands. v1 carries no reason byte; it decodes as [`DeadLetterReason::MaxDeliverExceeded`]
/// (the only dead-letter trigger before #551), so every existing v1 record reads back identically.
pub const DLQ_HEADER_MAGIC: [u8; 4] = *b"DLQ1";

/// The 4-byte magic that opens a v2 DLQ record's metadata header (V2-M4, #551). v2 is v1 plus a
/// leading reason byte, written ONLY by the reason-carrying [`DlqSink::append_dead_letter`]. The
/// reason-less [`DlqSink::append_poison`] still writes v1, so the existing max-deliver-to-`dlq/`
/// path is byte-identical and a reader handles both.
pub const DLQ_HEADER_MAGIC_V2: [u8; 4] = *b"DLQ2";

/// Why a message was dead-lettered (V2-M4, #551 — `RabbitMQ` DLX-parity: a dead-letter records its
/// trigger). A v1 record (no reason byte) decodes as [`DeadLetterReason::MaxDeliverExceeded`], the
/// only trigger before #551, so existing records read back unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum DeadLetterReason {
    /// The message was delivered more than `max_deliver` times (the original, default trigger).
    #[default]
    MaxDeliverExceeded = 0,
    /// The message's per-message or per-stream TTL expired before it was consumed (#549).
    TtlExpired = 1,
    /// A consumer explicitly REJECTED the message (`RabbitMQ` `basic.reject`/`nack` to the DLX).
    Rejected = 2,
}

impl DeadLetterReason {
    /// The on-disk reason byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decodes a reason byte, or `None` for an unknown (future) reason (decoded fail-closed so a
    /// newer record's reason is never silently misreported as `MaxDeliverExceeded`).
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<DeadLetterReason> {
        match b {
            0 => Some(DeadLetterReason::MaxDeliverExceeded),
            1 => Some(DeadLetterReason::TtlExpired),
            2 => Some(DeadLetterReason::Rejected),
            _ => None,
        }
    }

    /// A short, stable label for the operator-facing DLQ view and metrics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            DeadLetterReason::MaxDeliverExceeded => "max-deliver-exceeded",
            DeadLetterReason::TtlExpired => "ttl-expired",
            DeadLetterReason::Rejected => "rejected",
        }
    }
}

/// The fixed size of the dead-letter metadata header that prefixes a DLQ record's `headers` blob,
/// ahead of the original record's headers: `magic`(4) + `source_offset`(8) + `attempt`(4) +
/// `group_len`(2) + `orig_headers_len`(2).
pub const DLQ_META_LEN: usize = 4 + 8 + 4 + 2 + 2;

/// The fixed size of a v2 (#551) dead-letter metadata header: [`DLQ_META_LEN`] plus a 1-byte reason
/// inserted after the magic. `magic`(4) + `reason`(1) + `source_offset`(8) + `attempt`(4) +
/// `group_len`(2) + `orig_headers_len`(2).
pub const DLQ_META_V2_LEN: usize = DLQ_META_LEN + 1;

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
    /// WHY the message was dead-lettered (#551). A v1 record (written before #551, or by the
    /// reason-less `append_poison` path) decodes as [`DeadLetterReason::MaxDeliverExceeded`].
    pub reason: DeadLetterReason,
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

/// Encodes a v2 (#551) DLQ metadata header that ADDS a reason byte after the magic, otherwise the
/// same layout as [`encode_dlq_headers`]: `magic`(4) + `reason`(1) + `source_offset`(8) +
/// `attempt`(4) + `group_len`(2) + `orig_headers_len`(2) + group + original headers. Written only by
/// the reason-carrying [`DlqSink::append_dead_letter`]; the reason-less [`DlqSink::append_poison`]
/// keeps emitting v1 so the existing path is byte-identical. Returns `None` on the same length
/// overflow as the v1 encoder.
#[must_use]
pub fn encode_dlq_headers_v2(
    group: &str,
    source_offset: u64,
    attempt: u32,
    reason: DeadLetterReason,
    original_headers: &[u8],
) -> Option<Vec<u8>> {
    let group_len = u16::try_from(group.len()).ok()?;
    let headers_len = u16::try_from(original_headers.len()).ok()?;
    let mut out = Vec::with_capacity(DLQ_META_V2_LEN + group.len() + original_headers.len());
    out.extend_from_slice(&DLQ_HEADER_MAGIC_V2);
    out.push(reason.as_byte());
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
    reason: DeadLetterReason,
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
    let magic = blob.get(0..4)?;
    // v2 (#551) inserts a reason byte after the magic, shifting every field by one; v1 has none and
    // decodes as MaxDeliverExceeded (the only pre-#551 trigger), so a v1 record reads back unchanged.
    let (reason, fixed_len) = if magic == DLQ_HEADER_MAGIC {
        (DeadLetterReason::MaxDeliverExceeded, DLQ_META_LEN)
    } else if magic == DLQ_HEADER_MAGIC_V2 {
        // A v2 record with an unknown (future) reason byte fails closed rather than being misread.
        (DeadLetterReason::from_byte(*blob.get(4)?)?, DLQ_META_V2_LEN)
    } else {
        return None;
    };
    // The numeric fields start right after the magic for v1, and after magic+reason for v2.
    let off = fixed_len - DLQ_META_LEN; // 0 for v1, 1 for v2
    let source_offset = read_u64(blob, 4 + off)?;
    let attempt = read_u32(blob, 12 + off)?;
    let group_len = read_u16(blob, 16 + off)?;
    let headers_len = read_u16(blob, 18 + off)?;
    let group_start = fixed_len;
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
        reason,
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
        reason: meta.reason,
        timestamp_ms: record.timestamp_ms,
        // `DlqEntry` is the cold operator-facing dead-letter view (not the consume hot read path), so
        // its key/payload stay owned `Vec`s: the `record` blobs are now `Bytes` (#480), so make the
        // owning copy LOCALLY here rather than widen `DlqEntry`. This keeps the per-record-read win on
        // the hot path while the DLQ decode keeps its existing owned-`Vec` contract.
        key: record.key.to_vec(),
        headers: meta.original_headers,
        payload: record.payload.to_vec(),
        original_flags: record.flags,
    })
}

/// The durable dead-letter sink: a second segmented [`Log`] plus the per-group set of source
/// offsets already dead-lettered, for idempotent appends (#63).
pub struct DlqSink<F: Filesystem, C: Clock> {
    log: Log<F, C>,
    /// The EXACT set of SOURCE offsets already dead-lettered, per consumer group, reconstructed at
    /// open from the durable DLQ records and extended on each append (#800). The engine consults this
    /// to skip a duplicate append for a `(group, source_offset)` already in the sink. It is EXACT
    /// membership, NOT a high-water mark: poison messages do NOT cross the max-deliver (or TTL-expiry)
    /// threshold in ascending source-offset order — a higher offset can be dead-lettered while a lower
    /// one is still leased — so `offset <= max` would wrongly suppress the lower offset's append,
    /// dropping it from the sink entirely (zero durable places). Each per-group set is bounded by the
    /// source group's in-flight/ahead window (`max_in_flight`): [`DlqSink::prune_below`] drops every
    /// offset below the source cursor's committed watermark, which can never redeliver or re-poison.
    dead_lettered: BTreeMap<String, BTreeSet<u64>>,
    /// The number of records durably appended to the sink across its lifetime (the DLQ depth at
    /// open plus every append since), for the operator's `ironbus_dlq_records_total` metric.
    records: u64,
    /// The subdirectory this sink is rooted at (the dead-letter EXCHANGE target, #551). The DEFAULT
    /// sink uses [`DLQ_SUBDIR`] (`dlq/`, byte-identical to today); a configured DLX uses its own
    /// target subdir, so a stream/group can route dead letters somewhere other than the fixed sink.
    subdir: String,
}

impl<F: Filesystem, C: Clock> std::fmt::Debug for DlqSink<F, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DlqSink")
            .field("records", &self.records)
            .field("dead_lettered", &self.dead_lettered)
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
        DlqSink::open_at(parent_fs, DLQ_SUBDIR, clock, config)
    }

    /// Opens (recovering, or creating fresh) a dead-letter sink rooted at the `subdir` subdirectory
    /// of `parent_fs` — the dead-letter EXCHANGE target (#551). [`DlqSink::open`] is this with the
    /// default [`DLQ_SUBDIR`], so the existing fixed-DLQ behavior is byte-identical; a configured DLX
    /// names a different `subdir` to route dead letters to a separate sink. The on-disk format and
    /// the idempotent high-water-mark rebuild are identical for every target.
    ///
    /// # Errors
    /// Propagates a storage error from creating the subdirectory, opening the DLQ log, or scanning
    /// its records.
    pub fn open_at(
        parent_fs: &F,
        subdir: &str,
        clock: C,
        config: LogConfig,
    ) -> Result<DlqSink<F, C>, StorageError> {
        let dlq_fs = parent_fs.subdir(subdir).map_err(StorageError::Io)?;
        let log = Log::open(dlq_fs, clock, config)?;
        let mut sink = DlqSink {
            log,
            dead_lettered: BTreeMap::new(),
            records: 0,
            subdir: subdir.to_string(),
        };
        sink.rebuild_dead_lettered_set()?;
        Ok(sink)
    }

    /// The subdirectory this sink (dead-letter exchange target) is rooted at (#551).
    #[must_use]
    pub fn subdir(&self) -> &str {
        &self.subdir
    }

    /// Scans every durable DLQ record (reusing the recovery decode path) and rebuilds the per-group
    /// EXACT set of dead-lettered source offsets plus the total record count. Called once at open; the
    /// DLQ is the single durable source of truth for what has been dead-lettered, so this is what
    /// makes the move idempotent across a crash without a separate sidecar — and recovering the exact
    /// set (not just a max) is what lets a lower offset re-poisoned after a crash be recognized as
    /// already-present without suppressing a genuinely-new lower offset (#800).
    fn rebuild_dead_lettered_set(&mut self) -> Result<(), StorageError> {
        self.dead_lettered.clear();
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
                    self.dead_lettered
                        .entry(meta.group)
                        .or_default()
                        .insert(meta.source_offset);
                }
            }
        }
        Ok(())
    }

    /// Whether `(group, source_offset)` is ALREADY in the durable DLQ: true when this EXACT source
    /// offset is in the group's dead-lettered set. The engine calls this to make the move idempotent:
    /// a redelivered-then-re-poisoned message already in the sink is committed-past WITHOUT a second
    /// append. The check is EXACT membership, NOT `offset <= max` (#800): the ONLY legitimate
    /// duplicate is the SAME source offset re-poisoned after a crash that fsynced the DLQ record but
    /// not the source cursor, so a lower offset never-yet-dead-lettered must return `false` even when
    /// a HIGHER one is already recorded — otherwise it would be dropped from the sink entirely.
    #[must_use]
    pub fn already_dead_lettered(&self, group: &str, source_offset: u64) -> bool {
        self.dead_lettered
            .get(group)
            .is_some_and(|set| set.contains(&source_offset))
    }

    /// Drops every dead-lettered source offset BELOW `committed` for `group` (#800): once the source
    /// group's cursor has committed past an offset, that record can never redeliver or re-poison, so
    /// its exact-membership entry is no longer needed for idempotency. The engine calls this each time
    /// it advances a group's cursor past a dead-letter, bounding each per-group set by the in-flight/
    /// ahead window (`max_in_flight`) instead of letting it grow with every dead-letter ever written.
    /// Pruning against the IN-MEMORY watermark is safe across a crash: the durable DLQ is the source of
    /// truth and [`DlqSink::rebuild_dead_lettered_set`] restores the exact set on reopen.
    pub fn prune_below(&mut self, group: &str, committed: u64) {
        if let Some(set) = self.dead_lettered.get_mut(group) {
            // Keep only offsets at or above the committed watermark (offsets `< committed` are durably
            // committed-past). `split_off` returns the `>= committed` tail; the `< committed` head is
            // dropped with the old set.
            *set = set.split_off(&committed);
            if set.is_empty() {
                self.dead_lettered.remove(group);
            }
        }
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
        // The reason-LESS path writes a v1 header (no reason byte), so an existing max-deliver
        // dead-letter to the default `dlq/` sink is byte-identical to before #551.
        let headers = encode_dlq_headers(group, source.offset.get(), attempt, &source.headers)
            // A group name or header blob over u16::MAX cannot be framed; the wire bounds both, so
            // this is unreachable in practice, surfaced as the structural SegmentFull rather than a
            // panic so the move simply does not happen and the source is not committed.
            .ok_or(StorageError::SegmentFull)?;
        self.append_encoded(group, source, &headers)
    }

    /// The reason-carrying dead-letter append (V2-M4, #551): like [`append_poison`](Self::append_poison)
    /// but records the [`DeadLetterReason`] (max-deliver / TTL-expired / rejected) in a v2 metadata
    /// header, so a dead-letter is a fully reported event regardless of WHY it died. Used by a
    /// configured dead-letter EXCHANGE; the reason-less `append_poison` keeps writing v1 for the
    /// default fixed-DLQ max-deliver path, so that path stays byte-identical.
    ///
    /// The crash-safety contract (append-and-fsync the dead-letter record HERE before the caller
    /// commits the source cursor) and the idempotent per-group high-water mark are identical to
    /// `append_poison`.
    ///
    /// # Errors
    /// Same as [`append_poison`](Self::append_poison).
    pub fn append_dead_letter(
        &mut self,
        group: &str,
        source: &OwnedRecord,
        attempt: u32,
        reason: DeadLetterReason,
    ) -> Result<Offset, StorageError> {
        let headers =
            encode_dlq_headers_v2(group, source.offset.get(), attempt, reason, &source.headers)
                .ok_or(StorageError::SegmentFull)?;
        self.append_encoded(group, source, &headers)
    }

    /// Appends one dead-letter record (with its already-encoded metadata `headers` blob) to the sink,
    /// fsyncs it BEFORE returning, and advances the per-group high-water mark + record count. This is
    /// the shared durable core of [`append_poison`](Self::append_poison) and
    /// [`append_dead_letter`](Self::append_dead_letter); the only difference between them is the v1 vs
    /// v2 metadata encoding, computed by the caller.
    fn append_encoded(
        &mut self,
        group: &str,
        source: &OwnedRecord,
        headers: &[u8],
    ) -> Result<Offset, StorageError> {
        let source_offset = source.offset.get();
        // Preserve HAS_KEY consistency: the codec derives the key flag from the key length and
        // overwrites it, so clear the original HAS_KEY bit and let the log re-derive it from the
        // (preserved) key. The other flags (e.g. COMPRESSED) are carried through unchanged.
        let flags = RecordFlags::from_bits(source.flags.bits() & !RecordFlags::HAS_KEY.bits());
        let offset = self.log.append(&Append {
            timestamp_ms: source.timestamp_ms,
            flags,
            key: &source.key,
            headers,
            payload: &source.payload,
        })?;
        // Make the dead-letter record durable BEFORE the caller commits the source cursor: this
        // ordering is the crash-safety contract. A failed durability barrier freezes the DLQ writer
        // and is surfaced, so the caller does not commit the source past an un-fsynced record.
        self.log.sync()?;
        self.dead_lettered
            .entry(group.to_string())
            .or_default()
            .insert(source_offset);
        self.records = self.records.saturating_add(1);
        Ok(offset)
    }

    /// The number of records durably written to the sink (the DLQ depth): the records present at
    /// open plus every append since. Exposed for the `ironbus_dlq_records_total` metric.
    #[must_use]
    pub fn records(&self) -> u64 {
        self.records
    }

    /// The highest dead-lettered source offset CURRENTLY tracked for `group` (the max of its
    /// not-yet-pruned exact set), or `None` if the group has no tracked dead-letters. For tests and
    /// inspection. Note this reflects the live (pruned) set, not an all-time high-water mark.
    #[must_use]
    pub fn highest_for_group(&self, group: &str) -> Option<u64> {
        self.dead_lettered
            .get(group)
            .and_then(|set| set.iter().next_back().copied())
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
    read_dead_letter_entries(parent_fs, DLQ_SUBDIR)
}

/// Reads back every durable record in a dead-letter sink rooted at `subdir` (the configurable
/// dead-letter EXCHANGE target, #551), decoded into [`DlqEntry`]s, read-only and WITHOUT mutating
/// the directory. [`read_dlq_entries`] is this with the default [`DLQ_SUBDIR`]. An ABSENT `subdir`
/// reads as an empty list, not an error.
///
/// # Errors
/// Propagates an IO error or a chain error from the offline reader. A missing `subdir` is NOT an
/// error (it yields an empty list).
pub fn read_dead_letter_entries<F: Filesystem>(
    parent_fs: &F,
    subdir: &str,
) -> Result<Vec<DlqEntry>, StorageError> {
    // The subdir may not exist yet (nothing was ever dead-lettered there): treat that as empty,
    // never an error, so `dump --dlq` on a clean directory shows nothing. Probe WITHOUT creating
    // it (the inspector must never mutate the directory), so a read of a poison-free data dir does
    // not materialize the subdirectory.
    if !parent_fs.subdir_exists(subdir).map_err(StorageError::Io)? {
        return Ok(Vec::new());
    }
    let dlq_fs = parent_fs.subdir(subdir).map_err(StorageError::Io)?;
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
    use bytes::Bytes;
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
            key: Bytes::copy_from_slice(key),
            headers: Bytes::copy_from_slice(headers),
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn headers_round_trip_through_encode_decode() {
        let blob = encode_dlq_headers("orders", 42, 6, b"orig-headers").unwrap();
        assert_eq!(&blob[0..4], &DLQ_HEADER_MAGIC);
        let meta = decode_dlq_headers(&blob).unwrap();
        assert_eq!(meta.source_offset, 42);
        assert_eq!(meta.attempt, 6);
        // A v1 (reason-less) record decodes as the original max-deliver trigger.
        assert_eq!(meta.reason, DeadLetterReason::MaxDeliverExceeded);
        assert_eq!(meta.group, "orders");
        assert_eq!(meta.original_headers, b"orig-headers");
    }

    #[test]
    fn v2_headers_round_trip_with_each_reason() {
        for reason in [
            DeadLetterReason::MaxDeliverExceeded,
            DeadLetterReason::TtlExpired,
            DeadLetterReason::Rejected,
        ] {
            let blob = encode_dlq_headers_v2("orders", 42, 6, reason, b"orig-headers").unwrap();
            assert_eq!(&blob[0..4], &DLQ_HEADER_MAGIC_V2);
            let meta = decode_dlq_headers(&blob).unwrap();
            assert_eq!(meta.source_offset, 42);
            assert_eq!(meta.attempt, 6);
            assert_eq!(meta.reason, reason);
            assert_eq!(meta.group, "orders");
            assert_eq!(meta.original_headers, b"orig-headers");
        }
    }

    #[test]
    fn v2_decode_fails_closed_on_an_unknown_reason() {
        let mut blob =
            encode_dlq_headers_v2("g", 1, 1, DeadLetterReason::TtlExpired, b"h").unwrap();
        blob[4] = 0xFF; // an unknown future reason byte
        assert!(
            decode_dlq_headers(&blob).is_none(),
            "an unknown reason is not silently misreported as max-deliver"
        );
    }

    #[test]
    fn v1_records_remain_byte_identical() {
        // The exact bytes a v1 record produces must not change: assert the full layout explicitly so
        // any accidental drift to the default fixed-DLQ format is caught.
        let blob = encode_dlq_headers("g", 0x0102_0304_0506_0708, 0x0A0B_0C0D, b"hh").unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"DLQ1");
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        expected.extend_from_slice(&0x0A0B_0C0Du32.to_le_bytes());
        expected.extend_from_slice(&1u16.to_le_bytes()); // group_len
        expected.extend_from_slice(&2u16.to_le_bytes()); // headers_len
        expected.extend_from_slice(b"g");
        expected.extend_from_slice(b"hh");
        assert_eq!(blob, expected);
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
        assert_eq!(e.reason, DeadLetterReason::MaxDeliverExceeded);
        assert_eq!(e.timestamp_ms, src.timestamp_ms);
        assert_eq!(e.key, b"k");
        assert_eq!(e.headers, b"hdr");
        assert_eq!(e.payload, b"the-payload");
    }

    #[test]
    fn append_dead_letter_records_the_reason_and_a_configurable_target() {
        // A dead-letter EXCHANGE (#551): route to a NON-default subdir and record the reason.
        let fs = InMemoryFs::new();
        let mut dlx = DlqSink::open_at(&fs, "dlx-expired", ManualClock::new(), config()).unwrap();
        assert_eq!(dlx.subdir(), "dlx-expired");
        let src = source_record(9, b"k", b"hdr", b"body");
        dlx.append_dead_letter("orders", &src, 1, DeadLetterReason::TtlExpired)
            .unwrap();
        assert_eq!(dlx.records(), 1);

        // The DEFAULT dlq/ subdir was never touched: a DLX routes elsewhere.
        assert!(!fs.subdir_exists(DLQ_SUBDIR).unwrap());
        assert!(read_dlq_entries(&fs).unwrap().is_empty());

        // Read the configured target back: the reason is recorded.
        let entries = read_dead_letter_entries(&fs, "dlx-expired").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, DeadLetterReason::TtlExpired);
        assert_eq!(entries[0].source_offset, 9);
        assert_eq!(entries[0].group, "orders");
    }

    #[test]
    fn an_absent_dlq_reads_as_empty() {
        // No sink was ever opened, so the dlq/ subdir does not exist: a read shows nothing.
        let fs = InMemoryFs::new();
        assert!(read_dlq_entries(&fs).unwrap().is_empty());
    }

    #[test]
    fn dedup_is_exact_offset_membership_not_a_high_water_mark() {
        // #800: idempotency is EXACT-offset membership, not `offset <= max`. A lower source offset
        // that was never dead-lettered must read `false` even after a HIGHER one is recorded — the
        // poison-message order is not ascending (a higher offset can cross max-deliver while a lower
        // one is still leased), so a high-water mark would drop the lower offset from the sink.
        let fs = InMemoryFs::new();
        let mut sink = DlqSink::open(&fs, ManualClock::new(), config()).unwrap();
        // Dead-letter the HIGHER offset 5 first (the lower offset 2 is still leased upstream).
        sink.append_poison("a", &source_record(5, b"", b"", b"p"), 6)
            .unwrap();
        sink.append_poison("b", &source_record(3, b"", b"", b"p"), 6)
            .unwrap();
        // The exact offset 5 is in the sink; the never-dead-lettered lower offset 2 is NOT (pre-#800
        // this returned `true` because 2 <= 5, silently suppressing offset 2's later append).
        assert!(sink.already_dead_lettered("a", 5));
        assert!(
            !sink.already_dead_lettered("a", 2),
            "a lower never-dead-lettered offset is not suppressed by a higher recorded one"
        );
        assert!(!sink.already_dead_lettered("a", 6));
        assert!(!sink.already_dead_lettered("b", 4));

        // Now the lower offset 2 reaches dead-letter: it IS appended and becomes exact-present.
        sink.append_poison("a", &source_record(2, b"", b"", b"p"), 6)
            .unwrap();
        assert!(sink.already_dead_lettered("a", 2));
        assert_eq!(sink.records(), 3);
        assert_eq!(sink.highest_for_group("a"), Some(5));

        // Pruning below the source cursor's committed watermark bounds the set: once the cursor has
        // committed past offsets < 3, only offset 5 remains tracked for "a".
        sink.prune_below("a", 3);
        assert!(
            !sink.already_dead_lettered("a", 2),
            "2 pruned below the watermark"
        );
        assert!(
            sink.already_dead_lettered("a", 5),
            "5 is still ahead of the watermark"
        );
        // Pruning past everything drops the group entry entirely.
        sink.prune_below("a", 6);
        assert_eq!(sink.highest_for_group("a"), None);
    }
}
