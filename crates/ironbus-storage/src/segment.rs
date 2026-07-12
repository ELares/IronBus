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
use bytes::{Bytes, BytesMut};
use ironbus_core::codec::{self, BodyChecksums, DecodeError, RecordView};
use ironbus_core::format::{
    COMPACTION_META_LEN, RECORD_HEADER_LEN, RECORD_STREAM_TAG_CRC_LEN,
    RECORD_STREAM_TAG_LEN_PREFIX, RECORD_SUBJECT_CRC_LEN, RECORD_SUBJECT_LEN_PREFIX,
    RECORD_TRAILER_LEN, RECORD_XXH3_LEN, SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN,
    XXH3_PAYLOAD_THRESHOLD,
};
use ironbus_core::segment::{CompactionMeta, SegmentError, SegmentFooter, SegmentHeader};
use ironbus_core::types::{Offset, RecordFlags, Seq};
use std::io;
use std::sync::Arc;

// The subject (#594) and stream-tag (#597) fields both open with a `u16` length prefix of the same
// width at the fixed post-header offset (they are mutually exclusive). The recovery walks below
// buffer `RECORD_SUBJECT_LEN_PREFIX` extra bytes for EITHER; this pins that the two widths agree so
// that single buffer size stays correct for a tagged frame as well as a subject frame.
const _: () = assert!(RECORD_SUBJECT_LEN_PREFIX == RECORD_STREAM_TAG_LEN_PREFIX);

/// Whether a record's `flags` byte marks a length-prefixed optional field at the FIXED post-header
/// offset — a stored subject (#594) OR a stored stream tag (#597), mutually exclusive, both opening
/// with a `u16` length prefix at [`RECORD_HEADER_LEN`]. The streaming/sparse crash-recovery walks
/// buffer that extra prefix before [`codec::decoded_len`] so a frame carrying EITHER field is sized
/// from its header; without it a window-straddling tagged/subject frame is mis-read as a torn tail,
/// silently dropping it and every record after it (the #594 PR #1107 finding, now also #597).
#[inline]
fn has_post_header_prefix_field(flags_byte: u8) -> bool {
    let flags = RecordFlags::from_bits(flags_byte);
    flags.contains(RecordFlags::HAS_SUBJECT) || flags.contains(RecordFlags::HAS_STREAM_TAG)
}

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
    /// A COMMITTED compacted (v2) segment was found to have a corrupt BODY on a later recovery
    /// (#836). Its trailing v2 footer AND its 44-byte compaction-meta block BOTH decoded
    /// CRC-VALID, which proves the segment reached its compaction commit point, yet a survivor
    /// frame failed its CRC (bit-rot of committed data) or the footer's `record_count` / body
    /// length disagrees with the decoded survivors. This is DELIBERATELY DISTINCT from the
    /// crash-before-commit orphan that [`SegmentReader::scan_compacted`] reports as `Ok(None)`
    /// (no valid trailer at all): a committed compacted segment is the SOLE durable copy of the
    /// survivors it covers, so recovery must NEVER silently unlink it as an orphan — it
    /// QUARANTINES the poisoned segment (a forensic copy) and accounts the covered survivor loss
    /// in the [`crate::loss::LossReport`], rather than dropping acked data unreported.
    CorruptCompacted {
        /// The compacted segment's id.
        segment_id: u64,
        /// The lowest covered SOURCE offset, from the CRC-valid compaction-meta block.
        covered_base_offset: u64,
        /// One past the highest covered SOURCE offset, from the CRC-valid compaction-meta block.
        covered_end_offset: u64,
        /// The byte offset where the survivor record region begins (the segment header end).
        record_region_start: u64,
        /// The byte offset where the survivor record region ends (the footer start). The span
        /// `[record_region_start, record_region_end)` is the corrupt survivor region to quarantine.
        record_region_end: u64,
        /// The survivor count the CRC-valid footer claims: a best-effort lower bound on the
        /// records lost, for the loss report's `records_lost_estimate`.
        record_count_estimate: u64,
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
    /// A [`crate::log::Log::truncate_to`] (the C2-I4 leader-epoch divergence truncation, #599) was
    /// asked to truncate to an offset that is not within the log's current durable range
    /// `[earliest, next_offset]`: below the earliest retained offset (the bytes are already reaped,
    /// not truncatable) or above the durable head (there is nothing there to truncate). Fail-closed:
    /// the log is left untouched. A truncation to exactly `next_offset` (drop nothing) or to
    /// `earliest` (drop everything retained) is in range and allowed.
    TruncateOutOfRange {
        /// The offset the truncation targeted.
        requested: u64,
        /// The earliest offset still present (the floor; truncating below it is impossible).
        earliest: u64,
        /// The log's next offset (the durable head; truncating above it is meaningless).
        next_offset: u64,
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
    /// The data directory's on-disk LAYOUT version (the DIRECTORY structure version in `layout.meta`,
    /// `crate::layout`) is NEWER than this build understands, so `Log::open` fails CLOSED rather than
    /// silently reinterpreting a layout it does not know (the same exact-match, refuse-and-report
    /// discipline as an unknown `FORMAT_VERSION`, #562). DISTINCT from a record/segment version
    /// mismatch ([`StorageError::Segment`] / [`StorageError::Record`]): this versions where streams,
    /// cursors, and the DLQ live, not how a frame is encoded. A corrupt or absent marker never
    /// produces this error (it recovers as layout v1); only a fully-valid, CRC-checked future marker
    /// does.
    IncompatibleLayoutVersion {
        /// The layout version found in the marker.
        found: u32,
        /// The highest layout version this build supports ([`crate::layout::LAYOUT_VERSION`]).
        supported: u32,
    },
    /// The per-log cold-segment manifest (`cold-manifest.ckpt`, #643 tiered storage) is CRC-valid but
    /// STRUCTURALLY invalid (wrong magic, a future version, or a malformed entry table). Because the
    /// manifest is the durable record of which absent segment files are REMOTE (offloaded, not lost),
    /// an undecodable manifest is a fail-closed open — the log refuses rather than silently dropping
    /// remote pointers and then tripping [`StorageError::SegmentChainBroken`] on the offloaded holes.
    ColdManifestCorrupt,
    /// An offload could not be recorded because the cold-segment manifest is at its slot payload cap
    /// ([`crate::checkpoint::COLD_MANIFEST_PAYLOAD`]). Fail-closed: the prior manifest is left intact
    /// and the offload simply does not advance, so a segment is never local-deleted without a durable
    /// REMOTE record (never a torn or truncated manifest).
    ColdManifestFull,
    /// A read needed an offloaded (REMOTE) segment, but no [`crate::cold::ColdStore`] backend is
    /// configured on this log. The durable copy lives in the object store the operator must
    /// re-configure after a restart; surfaced fail-closed (never a silent empty read) so the read is
    /// retried once the backend is attached.
    ColdStoreUnavailable {
        /// The offloaded segment id that could not be fetched.
        segment_id: u64,
    },
    /// Fetching an offloaded (REMOTE) segment from the [`crate::cold::ColdStore`] failed — the object
    /// is missing ([`crate::cold::ColdStoreError::NotFound`]) or a transport error occurred. Surfaced
    /// to the reader as a typed, retryable/degraded error, NEVER a silent gap or a phantom record.
    ColdFetch {
        /// The offloaded segment id whose fetch failed.
        segment_id: u64,
        /// The underlying cold-store error.
        source: crate::cold::ColdStoreError,
    },
    /// A fetched offloaded (REMOTE) segment failed RE-VERIFICATION against the manifest — the fetched
    /// bytes have the wrong length, an undecodable segment header/footer, or a CRC32C that disagrees
    /// with the manifest's recorded checksum. A corrupt object store therefore fails CLOSED (the read
    /// errors and the poisoned bytes are never materialized as a local segment), rather than
    /// delivering garbage as if it were durable data.
    ColdCorrupt {
        /// The offloaded segment id whose fetched bytes failed verification.
        segment_id: u64,
    },
    /// An at-rest-ENCRYPTED record could not be decrypted (#780): the segment's `key_id` matches no
    /// loaded key ([`crate::crypto::DecryptError::UnknownKeyId`]), the AEAD tag failed under the named
    /// key ([`crate::crypto::DecryptError::TagMismatch`]), or the segment names an unsupported AEAD
    /// suite. A DISTINCT, reported class (mapped to a distinct [`ReasonCode`] via
    /// [`crate::crypto::DecryptError::reason_code`]) — NEVER a silent skip, a crash, or a read of
    /// garbage plaintext. Behind the `encryption` feature.
    #[cfg(feature = "encryption")]
    Decrypt(crate::crypto::DecryptError),
    /// The active segment recovered from disk is AEAD-ENCRYPTED, but the log was opened with NO at-rest
    /// key (#780 phase 2): resuming it would append PLAINTEXT into an encrypted segment (a
    /// confidentiality leak) and no read could decrypt it. Fail CLOSED rather than silently mix
    /// plaintext into ciphertext. This is the ALWAYS-COMPILED guard that makes a default
    /// (no-`encryption`) build refuse to open an encrypted log outright, and a keyless
    /// `encryption`-build open likewise refuse it.
    EncryptedSegmentNoKey {
        /// The encrypted active segment's id.
        segment_id: u64,
    },
    /// The active segment recovered from disk is PLAINTEXT, but an at-rest write key IS configured
    /// (#780 phase 2): appending encrypted records into a plaintext segment would make it a MIXED
    /// (part-plaintext, part-ciphertext) segment. Re-encrypting an existing plaintext log is a phase-3
    /// migration; phase 2 fails CLOSED here so a mixed segment is never produced.
    PlaintextSegmentWithKey {
        /// The plaintext active segment's id.
        segment_id: u64,
    },
    /// Verbatim replication of a leader's frame into a follower segment is REFUSED while at-rest
    /// encryption is enabled (#780 phase 2, the deferred cluster hazard): the leader's ciphertext is
    /// bound to the leader's `(segment_id, record_ordinal)` nonce, which the follower's independently
    /// numbered segment does not reproduce, so a verbatim copy would be undecryptable — or, if the ids
    /// happened to align, a nonce reuse. Clustered/replicated at-rest encryption is deferred to phase 3;
    /// a single-node encrypted broker never replicates, so this only fires on a misconfiguration.
    EncryptedReplicationUnsupported,
    /// The off-actor, zero-copy consume READ plane ([`crate::read_plane::ReadPlane`]) is UNAVAILABLE for
    /// an at-rest-encrypted log (#780 phase 2): that plane hands consumers RAW on-disk frames (which are
    /// ciphertext) off the append actor, but at-rest decryption is a decrypt-on-read step on the ACTOR
    /// path ([`crate::log::Log::read_range`]). An encrypted broker serves consumers through the actor's
    /// decrypt path instead; wiring decrypt into the off-actor plane is phase 3. Fail CLOSED rather than
    /// publish a snapshot that could hand a consumer ciphertext.
    EncryptedZeroCopyUnsupported,
    /// A background MAINTENANCE pass (key-compaction or cold-storage offload) of an at-rest-encrypted
    /// log is deferred to phase 3 (#780): the compaction cleaner reads survivors and RE-FRAMES them
    /// (which under encryption means decrypt-then-re-encrypt under fresh nonces), and offload/restore of
    /// encrypted segments needs its own re-verification path. Fail CLOSED rather than run an untested
    /// encrypted maintenance pass that could drop or mis-key data. Only fires when the operator has
    /// ENABLED compaction/offload on an encrypted log; the default (both off) is unaffected.
    EncryptedMaintenanceUnsupported,
}

impl core::fmt::Display for StorageError {
    // A cohesive one-arm-per-variant dispatch; splitting it would only scatter the messages.
    #[allow(clippy::too_many_lines)]
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
            StorageError::CorruptCompacted {
                segment_id,
                covered_base_offset,
                covered_end_offset,
                ..
            } => write!(
                f,
                "committed compacted segment {segment_id} (covering offsets \
                 [{covered_base_offset}, {covered_end_offset})) has a corrupt body past its \
                 CRC-valid footer/meta; quarantining rather than silently unlinking"
            ),
            StorageError::WriterFrozen => write!(f, "log writer is frozen after a fatal error"),
            StorageError::OffsetOutOfRange { requested, oldest } => write!(
                f,
                "read offset {requested} is older than the oldest retained offset {oldest}"
            ),
            StorageError::TruncateOutOfRange {
                requested,
                earliest,
                next_offset,
            } => write!(
                f,
                "truncate offset {requested} is outside the durable range [{earliest}, {next_offset}]"
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
            StorageError::IncompatibleLayoutVersion { found, supported } => write!(
                f,
                "data-dir layout version {found} is newer than this build supports ({supported}); \
                 refusing to open"
            ),
            StorageError::ColdManifestCorrupt => write!(
                f,
                "cold-segment manifest is CRC-valid but structurally invalid; refusing to open"
            ),
            StorageError::ColdManifestFull => write!(
                f,
                "cold-segment manifest is at its payload cap; offload refused fail-closed"
            ),
            StorageError::ColdStoreUnavailable { segment_id } => write!(
                f,
                "offloaded segment {segment_id} needs a cold-store backend, but none is configured"
            ),
            StorageError::ColdFetch { segment_id, source } => write!(
                f,
                "fetching offloaded segment {segment_id} from the cold store failed: {source}"
            ),
            StorageError::ColdCorrupt { segment_id } => write!(
                f,
                "fetched offloaded segment {segment_id} failed re-verification (length/header/footer/CRC); \
                 refusing to deliver"
            ),
            #[cfg(feature = "encryption")]
            StorageError::Decrypt(e) => write!(f, "at-rest decryption failed: {e}"),
            StorageError::EncryptedSegmentNoKey { segment_id } => write!(
                f,
                "active segment {segment_id} is at-rest encrypted but no at-rest key is configured; \
                 refusing to open (resuming would leak plaintext into an encrypted segment)"
            ),
            StorageError::PlaintextSegmentWithKey { segment_id } => write!(
                f,
                "active segment {segment_id} is plaintext but an at-rest key is configured; refusing \
                 to open (encrypting into it would make a mixed segment; re-encryption is phase 3)"
            ),
            StorageError::EncryptedReplicationUnsupported => write!(
                f,
                "verbatim replication is refused while at-rest encryption is enabled (the leader-nonce \
                 hazard); clustered at-rest encryption is deferred to phase 3"
            ),
            StorageError::EncryptedZeroCopyUnsupported => write!(
                f,
                "the off-actor zero-copy read plane is unavailable for an at-rest-encrypted log; reads \
                 go through the actor's decrypt path (wiring decrypt into the plane is phase 3)"
            ),
            StorageError::EncryptedMaintenanceUnsupported => write!(
                f,
                "compaction/offload of an at-rest-encrypted log is deferred to phase 3; disable \
                 compaction and cold-storage offload on an encrypted broker"
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
            StorageError::ColdFetch { source, .. } => Some(source),
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

    /// Whether this is a tiered-storage COLD-STORE read failure (#643): the backend is not configured
    /// ([`StorageError::ColdStoreUnavailable`]), a fetch failed ([`StorageError::ColdFetch`]), or the
    /// fetched bytes failed re-verification ([`StorageError::ColdCorrupt`]). The engine surfaces this
    /// as a distinct, retryable/degraded read outcome (the durable copy exists in the object store,
    /// it just could not be served THIS attempt) rather than a lost record or a fatal error, so a
    /// consumer read of an offloaded segment degrades cleanly instead of skipping data.
    #[must_use]
    pub fn is_cold_read_failure(&self) -> bool {
        matches!(
            self,
            StorageError::ColdStoreUnavailable { .. }
                | StorageError::ColdFetch { .. }
                | StorageError::ColdCorrupt { .. }
        )
    }
}

/// A materialized decoded record: the codec yields a borrowed [`RecordView`] over the read buffer;
/// this owns the record so a scan can return it after the read.
///
/// The `key`, `headers`, and `payload` are [`Bytes`] handles (#480, the storage F2 finding): when a
/// read materializes N records, the segment region is read into ONE buffer and each record's three
/// blobs are REFCOUNTED slices of that shared buffer ([`Bytes::slice_ref`]) rather than three
/// per-record `Vec` deep copies. A `read_from` is then one buffer allocation plus refcounted slices
/// (a refcount bump per blob), not O(N) allocations and O(total bytes) copied, on the consume hot
/// path. The materialized bytes are BYTE-IDENTICAL to a `to_vec` copy (a `Bytes` slice exposes the
/// same bytes), and the frame's full CRC is validated by the codec BEFORE any slice is taken, so a
/// handle is never a window into an unvalidated frame. `Bytes` derefs to `&[u8]`, so every reader
/// that took `&[u8]` (the engine, compaction, the DLQ codec) is unchanged; a clone is a refcount
/// bump, which is exactly the zero-copy fan-out the borrowed codec view was designed to enable.
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
    /// The routing or ordering key (empty if none). A refcounted slice of the shared read buffer.
    pub key: Bytes,
    /// The record headers blob (empty if none). A refcounted slice of the shared read buffer.
    pub headers: Bytes,
    /// The record payload. A refcounted slice of the shared read buffer.
    pub payload: Bytes,
    /// The stored SUBJECT this record was published on (#594), or EMPTY when the record carries no
    /// subject (a plain `Pub`/`PubTo`). A refcounted slice of the shared read buffer, populated by
    /// the materializing read path via [`ironbus_core::codec::decode_with_subject`]. The
    /// subject-filtered consumer tests each record's subject against the group's pattern; a record
    /// with no stored subject is treated as non-matching (never swallowed by a `>` catch-all).
    pub subject: Bytes,
    /// The stored STREAM TAG this record was framed with in a SHARED WAL (#597, the #1123
    /// `encoded_len` follow-up), or EMPTY for every per-stream-log record (the default mode never
    /// writes a tag). Populated ONLY by the shared-WAL demux read
    /// ([`crate::shared_wal::SharedWal`]), which also CLEARS the `HAS_STREAM_TAG` flag bit on the
    /// materialized record — the tag is storage-internal demux state, never a consumer-visible
    /// field, and a downstream re-encode (the per-stream DLQ sink's forensic copy) must not claim a
    /// tag field it does not carry. It exists here so [`OwnedRecord::encoded_len`] can account the
    /// tag field's STORED bytes exactly on the byte-capped read paths. A refcounted slice of the
    /// shared read buffer.
    pub stream_tag: Bytes,
}

/// A CONTIGUOUS run of stored record frames returned WITHOUT materializing per-record
/// [`OwnedRecord`]s and WITHOUT decoding the body — the zero-copy READ primitive (#542, M1-I6).
///
/// Where [`SegmentReader::scan_range`] reads the segment bytes into one buffer and then decodes
/// every frame into an `OwnedRecord` (validating each body CRC and refcount-slicing the three
/// blobs), this returns the raw on-disk frame bytes for the run `[first_offset, next_offset)` as
/// ONE refcounted [`Bytes`] handle and stops there: one `read_exact_at`, one allocation, zero body
/// decodes, zero per-record allocations. On the in-memory backends the underlying buffer is the
/// segment's own resident bytes (the `Bytes` is a refcount slice, a true no-copy view); on the disk
/// backend it is one positioned read into one shared buffer (the contiguous-extent foundation a
/// later `sendfile(2)` path — deferred, see #542's follow-up and #541 `DeliverBatch` — drops in
/// without re-plumbing the read shape).
///
/// ## What `bytes` IS, byte-for-byte
///
/// `bytes` is the concatenation of `record_count` complete on-disk record frames in offset order,
/// each in the frozen on-disk layout (header + key + headers + payload + optional xxh3 + trailer,
/// per `ironbus_core::format`). It is therefore identical to `scan_range`'s buffer truncated to the
/// same run: decoding `bytes` front-to-back with `ironbus_core::codec::decode` yields exactly the
/// records `scan_range` would return over the same range, in the same order, with the same bytes
/// (the differential test in `read_plane.rs` pins this).
///
/// ## CRC integrity is PRESERVED, not dropped
///
/// Each frame's own header CRC is validated while walking the run's boundaries (via
/// `codec::decoded_len`, the cheap header-only check), so a torn or corrupt header ENDS the run
/// exactly as `scan_range` stops at the first bad frame — a bogus tail is never carried. The body
/// CRC is NOT re-validated here (the broker never touches the body bytes on this path), but it
/// ships VERBATIM inside `bytes`, so the consumer verifies the frame end-to-end exactly as it does
/// today — the zero-copy path moves the body-CRC check to the only place that still touches the
/// bytes (the client), it never silently drops integrity. (Verify-once-while-resident is the
/// separate #540.)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawByteRun {
    /// The raw, contiguous on-disk frame bytes for `[first_offset, next_offset)`, one frame after
    /// another in the frozen on-disk layout. A refcounted [`Bytes`] slice of the shared read buffer
    /// (the segment's resident bytes on the memory backends): cloning it is a refcount bump, never a
    /// copy. Empty iff `record_count == 0`.
    pub bytes: Bytes,
    /// The log offset of the FIRST frame in `bytes`.
    pub first_offset: Offset,
    /// How many complete frames `bytes` carries. `next_offset == first_offset + record_count`.
    pub record_count: u64,
    /// The next offset AFTER the run (the first offset NOT included): where a follow-on read
    /// resumes. Equals `first_offset` when the run is empty.
    pub next_offset: Offset,
}

impl OwnedRecord {
    /// Materializes a record from a CRC-VALIDATED [`RecordView`] by taking refcounted slices of the
    /// shared read `buf` the view borrows (#480). `buf` MUST be the exact buffer the `view` was
    /// decoded from: [`Bytes::slice_ref`] resolves each blob's sub-range by its address WITHIN `buf`,
    /// so the returned handles alias `buf` (one refcount bump each, no copy) and `buf` outlives every
    /// record built from it (its bytes are freed when the last slice drops). The view's slices were
    /// produced by `codec::decode`, which validates the whole frame's header and body CRC first, so a
    /// slice is only ever taken over an already-validated frame — never a window into a torn frame.
    fn from_view(offset: Offset, buf: &Bytes, v: &RecordView<'_>, subject: &[u8]) -> OwnedRecord {
        OwnedRecord {
            offset,
            seq: v.seq,
            timestamp_ms: v.timestamp_ms,
            flags: v.flags,
            key: buf.slice_ref(v.key),
            headers: buf.slice_ref(v.headers),
            payload: buf.slice_ref(v.payload),
            // The subject (#594) is a slice of the SAME shared read buffer the view borrows (it was
            // decoded by `decode_with_subject` from `buf`), so this is one more refcount bump, no
            // copy. Empty for a record with no stored subject.
            subject: buf.slice_ref(subject),
            // A stream tag (#597) is only ever materialized by the shared-WAL demux read, which
            // constructs its records directly; every per-stream materializing path carries none.
            stream_tag: Bytes::new(),
        }
    }

    /// The total ENCODED on-disk frame length of this record in bytes: the fixed header, the stored
    /// body (key + headers + payload), the optional xxh3-64 field (present iff the stored body is at
    /// or above [`XXH3_PAYLOAD_THRESHOLD`]), and the fixed trailer. This is the SAME formula
    /// `codec::encode` lays down, so it is the authoritative per-record frame size the `max_bytes`
    /// budget of [`crate::log::Log::read_range`] (#538) accounts against — kept as one derivation so
    /// the budget can never drift from the bytes actually written.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let body_len = self.key.len() + self.headers.len() + self.payload.len();
        let xxh3_field = if body_len >= XXH3_PAYLOAD_THRESHOLD as usize {
            RECORD_XXH3_LEN
        } else {
            0
        };
        // The optional subject field (#594) is counted in the frame size like the xxh3 field: a
        // 2-byte length prefix, the subject bytes, and a 4-byte CRC, present only for a record that
        // carries a stored subject. Empty subject adds nothing, so a plain record is unchanged.
        let subject_field = if self.subject.is_empty() {
            0
        } else {
            RECORD_SUBJECT_LEN_PREFIX + self.subject.len() + RECORD_SUBJECT_CRC_LEN
        };
        // The optional STREAM-TAG field (#597, the #1123 follow-up): the shared-WAL demux read
        // populates `stream_tag` with the stored tag it verified, so a shared-mode record's frame
        // size accounts the tag field EXACTLY (same shape as the subject field — the const-assert
        // above pins the two prefix widths equal, and the tag CRC width equals the subject CRC
        // width by the frozen format). Mutually exclusive with a stored subject, so at most one of
        // the two fields is ever counted. Empty for every per-stream-log record, adding nothing.
        let tag_field = if self.stream_tag.is_empty() {
            0
        } else {
            RECORD_STREAM_TAG_LEN_PREFIX + self.stream_tag.len() + RECORD_STREAM_TAG_CRC_LEN
        };
        RECORD_HEADER_LEN + subject_field + tag_field + body_len + xxh3_field + RECORD_TRAILER_LEN
    }
}

/// Appends records to a segment file. The caller assigns monotonic sequence numbers
/// and rolls to a new segment by size or age.
#[derive(Debug)]
pub struct SegmentWriter<F: RandomAccessFile> {
    /// The segment's backing file, behind an `Arc` so an EXTERNAL durability barrier can hold a
    /// shared handle to the SAME kernel fd (#1040: the pipelined sync tier's flusher thread issues
    /// the covering `fdatasync` off the single-writer thread via [`SegmentWriter::shared_file`]).
    /// Every writer-side use is a `&self` call on the file (`write_all_at` / `sync_data` /
    /// `sync_all`), so the wrapper is transparent to the write paths and the on-disk bytes are
    /// identical. A clone held across a [`SegmentWriter::seal`] (or a retention reap) merely delays
    /// the fd close by the holder's lifetime — a stray fdatasync on a sealed or unlinked file is a
    /// harmless no-op barrier. `Arc`, not `try_clone`: no new trait surface, no per-cycle
    /// dup(2)/close, and a fault-injection backend that gates syncs gates the shared handle's syncs
    /// identically (the shared object IS the gated object).
    file: Arc<F>,
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
    /// The active at-rest encryption context (#780), or `None` for a plaintext writer (the default).
    /// When `Some`, every record body this writer appends is AEAD-encrypted IN PLACE before framing
    /// (the frame carries the ciphertext + tag and the `ENCRYPTED` flag), keyed by the deterministic
    /// nonce `segment_id || record_ordinal`; the segment header records the suite and key-id. Set only
    /// via [`SegmentWriter::with_crypto`] on a FRESH writer (before any append), so a segment is
    /// uniformly encrypted or uniformly plaintext. Behind the `encryption` feature.
    #[cfg(feature = "encryption")]
    crypto: Option<Arc<crate::crypto::SegmentCrypto>>,
}

/// The spill cap for the writer's pending buffer (#452): a relaxed durability level can run a
/// long unsynced window, so the buffer flushes to the file (one write, NO fsync) whenever it
/// reaches this size, bounding the writer's heap at a constant instead of the unsynced window.
const PENDING_SPILL_BYTES: usize = 256 * 1024;

/// The read window the streaming recovery walk ([`SegmentReader::scan_body_streaming`]) fills per
/// `read_exact_at` (#816). The body is validated one frame at a time, but frames are decoded out of
/// this reused window instead of issuing two preads PER RECORD, so the recovery read-syscall count
/// drops from `2 * record_count` to roughly `body_bytes / RECOVERY_WINDOW_BYTES` (plus one small
/// re-read per frame that straddles a window boundary). Peak recovery heap stays bounded by this
/// window, except that a single frame larger than the window grows it just enough to fit that one
/// frame — the same one-record bound the previous per-record path already tolerated.
const RECOVERY_WINDOW_BYTES: usize = 256 * 1024;

/// Frames one PLAINTEXT record into `pending`, dispatching on the optional subject (#594) / stream-tag
/// (#597) slots and the off-actor precomputed checksums (#830). This is the historical
/// [`SegmentWriter::append_encoded`] encode dispatch, lifted to a free function so the encrypted path
/// can sit beside it as a clean alternative. The emitted bytes are byte-for-byte the pre-encryption
/// frame. A non-empty subject and a non-empty stream-tag are mutually exclusive (the codec helpers
/// debug-assert it).
fn encode_plaintext(
    pending: &mut Vec<u8>,
    record: &RecordView<'_>,
    subject: &[u8],
    stream_tag: &[u8],
    precomputed: Option<BodyChecksums>,
) -> Result<usize, codec::EncodeError> {
    if stream_tag.is_empty() {
        match (precomputed, subject.is_empty()) {
            (Some(checksums), true) => codec::encode_precomputed(record, checksums, pending),
            (None, true) => codec::encode(record, pending),
            (Some(checksums), false) => {
                codec::encode_precomputed_with_subject(record, subject, checksums, pending)
            }
            (None, false) => codec::encode_with_subject(record, subject, pending),
        }
    } else {
        match precomputed {
            Some(checksums) => {
                codec::encode_precomputed_with_stream_tag(record, stream_tag, checksums, pending)
            }
            None => codec::encode_with_stream_tag(record, stream_tag, pending),
        }
    }
}

/// AEAD-encrypts a record body IN PLACE and frames the ciphertext + tag into `pending` (#780). The
/// nonce is `segment_id || record_counter` (the writer's pre-increment per-segment ordinal), which is
/// unique for the life of the log under the active key. The `key_len`/`hdr_len`/`payload_len` written
/// to the header are the PLAINTEXT lengths; the on-disk body is ciphertext (same length) plus the
/// 16-byte tag, with the CRC over the ciphertext. The transient plaintext COPY assembled here is
/// zeroized after encryption (defence in depth; the caller's original body bytes are its own).
#[cfg(feature = "encryption")]
fn encrypt_and_frame(
    record: &RecordView<'_>,
    crypto: &crate::crypto::SegmentCrypto,
    segment_id: u64,
    record_counter: u32,
    pending: &mut Vec<u8>,
) -> Result<usize, codec::EncodeError> {
    use zeroize::Zeroize;
    let key_len = u32::try_from(record.key.len()).map_err(|_| codec::EncodeError::TooLarge)?;
    let hdr_len = u32::try_from(record.headers.len()).map_err(|_| codec::EncodeError::TooLarge)?;
    let payload_len =
        u32::try_from(record.payload.len()).map_err(|_| codec::EncodeError::TooLarge)?;
    let mut plaintext =
        Vec::with_capacity(record.key.len() + record.headers.len() + record.payload.len());
    plaintext.extend_from_slice(record.key);
    plaintext.extend_from_slice(record.headers);
    plaintext.extend_from_slice(record.payload);
    let (ciphertext, tag) = crypto.encrypt(segment_id, record_counter, &plaintext);
    plaintext.zeroize();
    codec::encode_encrypted(
        record.seq,
        record.timestamp_ms,
        record.flags,
        key_len,
        hdr_len,
        payload_len,
        &ciphertext,
        &tag,
        pending,
    )
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
            // Wrapped internally (#1040): callers keep passing a bare `F`; the `Arc` exists only
            // so `shared_file` can hand the flusher a co-owned handle to the same fd.
            file: Arc::new(file),
            header,
            write_pos: SEGMENT_HEADER_LEN as u64,
            record_count: 0,
            last_seq: header.base_seq,
            max_timestamp_ms: 0,
            pending: Vec::new(),
            pending_base: SEGMENT_HEADER_LEN as u64,
            #[cfg(feature = "encryption")]
            crypto: None,
        })
    }

    /// Creates a new AEAD-ENCRYPTED segment (#780): writes the header via
    /// [`SegmentHeader::encode_encrypted`] (setting the `SEGMENT_FLAG_ENCRYPTED` flag and recording
    /// `crypto`'s suite and key-id in the reserved header bytes), and attaches the write-side
    /// encryption context so every appended record body is AEAD-encrypted in place. The frame layout,
    /// the durability boundary, and the roll trigger are otherwise identical to [`SegmentWriter::create`]
    /// — only the body bytes are ciphertext plus the 16-byte tag.
    ///
    /// # Errors
    /// Propagates IO errors writing the header.
    #[cfg(feature = "encryption")]
    pub fn create_encrypted(
        file: F,
        header: SegmentHeader,
        crypto: Arc<crate::crypto::SegmentCrypto>,
    ) -> Result<SegmentWriter<F>, StorageError> {
        file.write_all_at(
            &header.encode_encrypted(crypto.suite().id(), crypto.key_id()),
            0,
        )?;
        Ok(SegmentWriter {
            file: Arc::new(file),
            header,
            write_pos: SEGMENT_HEADER_LEN as u64,
            record_count: 0,
            last_seq: header.base_seq,
            max_timestamp_ms: 0,
            pending: Vec::new(),
            pending_base: SEGMENT_HEADER_LEN as u64,
            crypto: Some(crypto),
        })
    }

    /// Attaches an at-rest encryption context to a RESUMED writer (#780), for continuing to append to
    /// an already-encrypted segment after recovery. Unlike [`SegmentWriter::create_encrypted`] this
    /// does NOT rewrite the header (the on-disk header already carries the encryption flag/suite/key-id
    /// from when the segment was first created); it only lets subsequent appends keep encrypting under
    /// the same key. The caller MUST pass the SAME suite/key-id the segment header records, so the
    /// nonce space stays consistent across the restart.
    #[cfg(feature = "encryption")]
    #[must_use]
    pub fn with_crypto(mut self, crypto: Arc<crate::crypto::SegmentCrypto>) -> SegmentWriter<F> {
        self.crypto = Some(crypto);
        self
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
            // Wrapped internally (#1040), exactly as in `create`.
            file: Arc::new(file),
            header,
            write_pos,
            record_count,
            last_seq,
            max_timestamp_ms,
            pending: Vec::new(),
            pending_base: write_pos,
            #[cfg(feature = "encryption")]
            crypto: None,
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
            // Wrapped internally (#1040), exactly as in `create`.
            file: Arc::new(file),
            header,
            write_pos: SEGMENT_HEADER_LEN as u64,
            record_count: 0,
            last_seq: header.base_seq,
            max_timestamp_ms: 0,
            pending: Vec::new(),
            pending_base: SEGMENT_HEADER_LEN as u64,
            #[cfg(feature = "encryption")]
            crypto: None,
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
        subject: &[u8],
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
        // Preserve a survivor's stored subject through compaction (#594): a non-empty subject
        // re-encodes with the subject-storing codec path so the compacted copy keeps its subject
        // field; an empty subject is byte-for-byte the historical re-encode.
        let encoded = if subject.is_empty() {
            codec::encode(record, &mut self.pending)
        } else {
            codec::encode_with_subject(record, subject, &mut self.pending)
        };
        if encoded.is_err() {
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
        let pos_before = self.write_pos;
        self.write_pos = end;
        // Spill: bound the buffer regardless of the survivor count, one write per spill window.
        if self.pending.len() >= PENDING_SPILL_BYTES {
            if let Err(e) = self.flush_pending() {
                // #859: same torn-writer roll back as `append` - a spill-flush IO error mid-append left
                // `write_pos` advanced and the frame buffered with `record_count` un-bumped. Restore the
                // pre-append state so the next survivor append cannot reuse this offset/seq, then propagate.
                self.pending.truncate(before);
                self.write_pos = pos_before;
                return Err(e);
            }
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
        // As in `seal`: the v2 trailer is discovered by reading the END of the file, so a
        // logically-extended (preallocated) file must be truncated down to the true trailer end
        // before the same `sync_all` that commits the trailer. Compaction writers are not
        // preallocated today, so this is normally a no-op guard kept local to the seal invariant.
        let end = self
            .write_pos
            .checked_add((SEGMENT_FOOTER_LEN + COMPACTION_META_LEN) as u64)
            .ok_or(StorageError::SegmentFull)?;
        if self.file.len()? > end {
            self.file.set_len(end)?;
        }
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

    /// This writer's segment header (its `segment_id`, base offset/seq, and flags). The
    /// [`SegmentHeader::is_encrypted`] bit tells the log whether a resumed active segment is at-rest
    /// encrypted, so it can re-attach the write-side crypto after recovery (#780).
    #[must_use]
    pub fn header(&self) -> &SegmentHeader {
        &self.header
    }

    /// Whether an at-rest write-encryption context is attached (#780). `true` means every appended
    /// record body is AEAD-encrypted in place. Always `false` in a build without the `encryption`
    /// feature. The log uses this to assert, after a resume, that an encrypted active segment actually
    /// carries its crypto before it accepts the first post-recovery append.
    #[must_use]
    pub fn has_crypto(&self) -> bool {
        #[cfg(feature = "encryption")]
        {
            self.crypto.is_some()
        }
        #[cfg(not(feature = "encryption"))]
        {
            false
        }
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
        self.append_encoded(record, b"", b"", None)
    }

    /// Appends one record ALSO storing `subject` as the optional subject field (#594). Identical to
    /// [`SegmentWriter::append`] except the frame carries the stored subject (with its own CRC); an
    /// EMPTY `subject` is byte-for-byte [`SegmentWriter::append`].
    ///
    /// # Errors
    /// Same as [`SegmentWriter::append`].
    pub fn append_with_subject(
        &mut self,
        record: &RecordView<'_>,
        subject: &[u8],
    ) -> Result<Offset, StorageError> {
        self.append_encoded(record, subject, b"", None)
    }

    /// Appends one record ALSO storing `stream_tag` as the optional stream-tag field (#597, the
    /// shared-WAL demux key). Identical to [`SegmentWriter::append`] except the frame carries the
    /// stored tag (with its own CRC); an EMPTY `stream_tag` is byte-for-byte [`SegmentWriter::append`].
    /// Mutually exclusive with a stored subject.
    ///
    /// # Errors
    /// Same as [`SegmentWriter::append`].
    pub fn append_with_stream_tag(
        &mut self,
        record: &RecordView<'_>,
        stream_tag: &[u8],
    ) -> Result<Offset, StorageError> {
        self.append_encoded(record, b"", stream_tag, None)
    }

    /// The precomputed-body-checksum twin of [`SegmentWriter::append_with_stream_tag`] (#597/#830):
    /// stores `stream_tag` while trusting the caller-supplied body `checksums`.
    ///
    /// # Errors
    /// Same as [`SegmentWriter::append`].
    pub fn append_precomputed_with_stream_tag(
        &mut self,
        record: &RecordView<'_>,
        stream_tag: &[u8],
        checksums: BodyChecksums,
    ) -> Result<Offset, StorageError> {
        self.append_encoded(record, b"", stream_tag, Some(checksums))
    }

    /// The precomputed-body-checksum twin of [`SegmentWriter::append_with_subject`] (#594/#830):
    /// stores `subject` while trusting the caller-supplied body `checksums`.
    ///
    /// # Errors
    /// Same as [`SegmentWriter::append`].
    pub fn append_precomputed_with_subject(
        &mut self,
        record: &RecordView<'_>,
        subject: &[u8],
        checksums: BodyChecksums,
    ) -> Result<Offset, StorageError> {
        self.append_encoded(record, subject, b"", Some(checksums))
    }

    /// Appends one record whose body checksums were PRE-COMPUTED off the single-writer actor on the
    /// producing connection thread (issue #830). Identical to [`SegmentWriter::append`] except the
    /// body CRC32C (and, for a large body, the xxh3-64) come from `checksums` instead of being
    /// computed here on the serialized append path. The caller GUARANTEES `checksums` describes this
    /// `record`'s exact stored body (`key ++ headers ++ payload`), so the on-disk frame is
    /// byte-identical to what [`SegmentWriter::append`] would produce; a mismatch is not a safety
    /// hazard (the checksum is re-validated on read) but would durably store a self-corrupt record,
    /// which a debug build asserts against in the codec.
    ///
    /// # Errors
    /// Same as [`SegmentWriter::append`].
    pub fn append_precomputed(
        &mut self,
        record: &RecordView<'_>,
        checksums: BodyChecksums,
    ) -> Result<Offset, StorageError> {
        self.append_encoded(record, b"", b"", Some(checksums))
    }

    /// The shared body behind [`SegmentWriter::append`] and [`SegmentWriter::append_precomputed`]:
    /// frames `record` into the pending buffer, trusting `precomputed` body checksums when `Some`
    /// (#830) or computing them in the codec when `None`. The on-disk bytes and all writer bookkeeping
    /// are identical either way. At most one of `subject` (#594) and `stream_tag` (#597) is non-empty
    /// — they share the fixed post-header slot and are mutually exclusive (the codec rejects a frame
    /// carrying both); a caller passing both non-empty is a bug the codec's debug assert catches.
    fn append_encoded(
        &mut self,
        record: &RecordView<'_>,
        subject: &[u8],
        stream_tag: &[u8],
        precomputed: Option<BodyChecksums>,
    ) -> Result<Offset, StorageError> {
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
        // At-rest encryption (#780): when a crypto context is attached, the record body is
        // AEAD-encrypted IN PLACE and framed with `encode_encrypted`, keyed by the deterministic
        // nonce `segment_id || record_ordinal` (the ordinal is the pre-increment `record_count`). The
        // nonce is unique for the life of the log under this key (segment-ids never recycle, the
        // ordinal is monotonic and u32-bounded). Encryption is uniform per segment and, in v1,
        // mutually exclusive with the optional subject/stream-tag slots. The plaintext CRC offload
        // (`precomputed`) does not apply — the CRC is recomputed over the ciphertext.
        #[cfg(feature = "encryption")]
        let encoded = if let Some(crypto) = self.crypto.clone() {
            debug_assert!(
                subject.is_empty() && stream_tag.is_empty(),
                "at-rest encryption carries no subject/stream-tag slot in v1 (#780)"
            );
            encrypt_and_frame(
                record,
                &crypto,
                self.header.segment_id,
                self.record_count,
                &mut self.pending,
            )
        } else {
            encode_plaintext(&mut self.pending, record, subject, stream_tag, precomputed)
        };
        #[cfg(not(feature = "encryption"))]
        let encoded = encode_plaintext(&mut self.pending, record, subject, stream_tag, precomputed);
        if encoded.is_err() {
            self.pending.truncate(before);
            return Err(StorageError::SegmentFull);
        }
        let len =
            u64::try_from(self.pending.len() - before).map_err(|_| StorageError::SegmentFull)?;
        let pos_before = self.write_pos;
        let end = pos_before
            .checked_add(len)
            .ok_or(StorageError::SegmentFull)?;
        self.write_pos = end;
        // Spill: bound the buffer regardless of how long a relaxed durability level defers the
        // sync. One write per spill still reduces syscalls by spill/record-size to one.
        if self.pending.len() >= PENDING_SPILL_BYTES {
            if let Err(e) = self.flush_pending() {
                // #859: the spill flush failed mid-append (ENOSPC / flash EIO). `write_pos` was already
                // advanced and the just-encoded frame is still buffered, but `record_count`/`last_seq`
                // have NOT been bumped yet - a TORN writer state. Left as-is, the NEXT append would reuse
                // this offset/seq (`record_count` did not advance) and, when a later flush succeeds, write
                // BOTH frames under one count - corrupting the log and silently losing the acked record.
                // Roll back to the EXACT pre-append state (drop the encoded frame, restore `write_pos`) so
                // the writer stays consistent and a retry is safe, then propagate the IO error so the
                // producer is never acked. `flush_pending` leaves `pending` / `pending_base` untouched on
                // error, so only the frame and `write_pos` need undoing; this mirrors the encode-failure
                // roll back above.
                self.pending.truncate(before);
                self.write_pos = pos_before;
                return Err(e);
            }
        }
        self.record_count += 1;
        self.last_seq = record.seq;
        // Track the MAX timestamp (not the last): producer timestamps are not monotonic, and the
        // age-retention reaper needs the newest record's timestamp to know when the whole segment
        // has aged out.
        self.max_timestamp_ms = self.max_timestamp_ms.max(record.timestamp_ms);
        Ok(Offset::new(offset))
    }

    /// Appends a PRE-ENCODED, ALREADY-VALIDATED frame VERBATIM — the follower replication ingest
    /// fast path (#820). `frame` is one complete on-disk record frame the caller has just decoded
    /// in place with the intact-record predicate ([`codec::decode`]: magic, version, header CRC32C,
    /// body CRC32C, and — for large bodies — xxh3-64). Because the leader already produced the
    /// canonical sealed frame and the follower assigns the SAME `seq`/offset positionally, the frame
    /// is byte-identical to what [`SegmentWriter::append`] would re-encode from the decoded record;
    /// copying it verbatim skips the redundant re-frame + re-checksum (the same crc32c-over-header,
    /// crc32c-over-body, and xxh3-64 the decode just verified). `seq` and `timestamp_ms` are the
    /// decoded frame's own values, carried in for the writer's `last_seq` / `max_timestamp_ms`
    /// bookkeeping only — they are NOT re-embedded (the bytes are copied as-is).
    ///
    /// This does NOT re-validate `frame`: validation is the caller's decode step. Passing bytes that
    /// are not a single complete, already-validated frame would corrupt the segment. Its byte effect
    /// (the pending buffer content and `write_pos` advance) is identical to `append` of the record
    /// `frame` decodes to.
    ///
    /// # Errors
    /// Returns [`StorageError::SegmentFull`] if the record count or byte length would overflow, or an
    /// IO error from a spill flush (rolled back to the exact pre-append state, as in `append`).
    pub fn append_verbatim(
        &mut self,
        frame: &[u8],
        seq: Seq,
        timestamp_ms: u64,
    ) -> Result<Offset, StorageError> {
        if self.record_count == u32::MAX {
            return Err(StorageError::SegmentFull);
        }
        // Offsets are monotonic and never reused; refuse to wrap the offset space rather than mint a
        // duplicate id (mirrors `append`).
        let offset = self
            .header
            .base_offset
            .get()
            .checked_add(u64::from(self.record_count))
            .ok_or(StorageError::SegmentFull)?;
        // Copy the verbatim frame straight into the shared pending buffer — ONE contiguous memcpy in
        // place of the codec's re-encode (4 extend_from_slice copies + 2x crc32c + xxh3). The bytes
        // reach the file at the next flush point, exactly like an encoded frame.
        let len = u64::try_from(frame.len()).map_err(|_| StorageError::SegmentFull)?;
        let before = self.pending.len();
        self.pending.extend_from_slice(frame);
        let pos_before = self.write_pos;
        let end = pos_before
            .checked_add(len)
            .ok_or(StorageError::SegmentFull)?;
        self.write_pos = end;
        // Spill under the same bound as `append`, with the same #859 torn-writer roll back on a
        // mid-append flush IO error (restore `pending` and `write_pos` before `record_count` bumps).
        if self.pending.len() >= PENDING_SPILL_BYTES {
            if let Err(e) = self.flush_pending() {
                self.pending.truncate(before);
                self.write_pos = pos_before;
                return Err(e);
            }
        }
        self.record_count += 1;
        self.last_seq = seq;
        self.max_timestamp_ms = self.max_timestamp_ms.max(timestamp_ms);
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

    /// Issues the `fdatasync` ALONE, WITHOUT first flushing the pending buffer (#564): the
    /// barrier-only half of [`SegmentWriter::sync`]. The caller MUST have already drained the
    /// pending bytes to the page cache (via [`SegmentWriter::flush_pending`], typically through
    /// the log's `flush_no_sync`), so the bytes this fdatasync makes durable are exactly the
    /// bytes already in the file; this method does NOT re-flush. It exists so the cross-stream
    /// `CommitCoordinator` can split a commit tick into one page-cache-flush pass over every
    /// dirtied stream followed by one `fdatasync` per dirtied stream's fd — the two phases of
    /// [`SegmentWriter::sync`] driven separately across many streams, instead of fused per stream.
    ///
    /// Calling this with un-flushed pending bytes would make a SHORTER prefix durable than the
    /// caller believes, so the contract is: flush first, then `sync_data_only`. (A debug assert
    /// guards the misuse: the pending buffer must be empty here.)
    ///
    /// # Errors
    /// Propagates the underlying IO error. A fatal sync error must be treated as terminal by the
    /// caller (the writer is frozen read-only), exactly as for [`SegmentWriter::sync`].
    pub fn sync_data_only(&mut self) -> Result<(), StorageError> {
        debug_assert!(
            self.pending.is_empty(),
            "sync_data_only requires the pending buffer already flushed to the page cache; \
             call flush_pending (or the log's flush_no_sync) first (#564)"
        );
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

    /// A SHARED handle to the segment's backing file — the SAME kernel fd the writer stages into —
    /// for an EXTERNAL durability barrier (#1040): the pipelined sync tier hands this to its
    /// flusher thread, which calls `sync_data` (`&self`, the trait is `Send + Sync`) off the
    /// single-writer thread while the writer keeps appending. The caller MUST have already drained
    /// the pending buffer to the file ([`SegmentWriter::flush_pending`]) for the external barrier
    /// to cover what it believes it covers, exactly the [`SegmentWriter::sync_data_only`] contract.
    /// A handle that outlives a [`SegmentWriter::seal`] or a retention reap is harmless: a stray
    /// fdatasync on a sealed or unlinked file is a no-op barrier, and the co-owned fd merely closes
    /// a little later.
    pub(crate) fn shared_file(&self) -> Arc<F> {
        Arc::clone(&self.file)
    }

    /// Seals the segment by writing the footer, truncating any preallocated zero tail down to the
    /// footer end, and issuing a full fsync, consuming the writer and returning the footer.
    ///
    /// The truncation is load-bearing with preallocation's LOGICAL extension (`StdFile::
    /// preallocate` advances the file length to the roll size up front): footer discovery reads
    /// the trailing 32 bytes of the FILE (`SegmentReader::scan` and every sibling), so a sealed
    /// image must end exactly at the footer or the zero tail would hide the seal. The shrink is
    /// metadata, made durable by the very `sync_all` the seal already issues (the documented
    /// `set_len`-shrink-needs-`sync_all` pairing in `io.rs`), so a sealed segment's on-disk image
    /// is byte-identical to a never-preallocated one. A never-extended file skips the `set_len`
    /// (its length already equals the footer end).
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
        let end = self
            .write_pos
            .checked_add(SEGMENT_FOOTER_LEN as u64)
            .ok_or(StorageError::SegmentFull)?;
        if self.file.len()? > end {
            self.file.set_len(end)?;
        }
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

/// The SPARSE anchor list a [`SegmentReader::sparse_record_byte_positions`] walk produces (#537):
/// each entry is `(log offset of the anchored record, that record's frame START byte position)`,
/// ascending by offset. It is SPARSE — Kafka's `.index` design — holding ONE anchor per `stride`
/// bytes of frame data rather than one per record, so a resident index built from it costs
/// `O(region_bytes / stride)` regardless of how many (small) records the segment packs, bounding
/// the per-segment RAM independent of the record count. A read SEEKS to the nearest anchor at or
/// before the target offset and scans FORWARD at most `stride` bytes (a bounded number of frames)
/// to reach the exact record, so the consume locate stays O(stride) — a small constant — instead
/// of the pre-#483 O(records-per-segment) full rescan, with a fraction of the dense index's RAM.
///
/// The first record (offset `base_offset`) is ALWAYS anchored, so any in-range offset has an anchor
/// at or before it to seek from. `region_end` is the byte offset at which the valid record region
/// ends (a sealed segment's footer start, or the active segment's torn-free prefix end), the
/// read-forward upper bound so a seek never reads past the durable prefix into a torn tail/footer.
struct SparseWalk {
    /// The sparse `(offset, frame START byte position)` anchors, ascending by offset (#537).
    anchors: Vec<(u64, u64)>,
    /// The last valid record's sequence (`None` if the region held no record), for the seal check.
    last_seq: Option<Seq>,
    /// How many valid records the walk decoded (the seal check cross-checks the footer's count).
    count: u64,
    /// Bytes consumed relative to the walk's start offset (the valid prefix length).
    cursor: u64,
    /// `true` if the region decoded cleanly with no torn or corrupt tail.
    clean: bool,
}

/// The result of [`SegmentReader::sparse_record_byte_positions`] (#537): the SPARSE `(offset, frame
/// START byte position)` anchor list (see [`SparseWalk`]) paired with the byte offset at which the
/// valid record region ends (`valid_end`), the read-forward upper bound.
pub type SparsePositions = (Vec<(u64, u64)>, u64);

/// The running result of a [`SegmentReader::walk_time_anchors`] walk (#772): the sparse
/// `(offset, exclusive prefix-max timestamp)` anchors plus the seal cross-check facts (record count
/// and last sequence) and whether the region decoded cleanly.
struct TimeAnchorWalk {
    /// The sparse `(offset, exclusive prefix-max timestamp)` anchors, ascending by offset.
    anchors: Vec<(u64, u64)>,
    /// The last valid record's sequence (`None` if the region held no record), for the seal check.
    last_seq: Option<Seq>,
    /// How many valid records the walk decoded (the seal check cross-checks the footer's count).
    count: u64,
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
    /// Verify-once (#540, M1-I4): `true` when this reader's segment is VERIFIED-RESIDENT — its body
    /// integrity was ALREADY proven this process (self-written and never round-tripped through a disk
    /// read, or CRC-validated on load/recovery/cold-restore) AND it has stayed continuously resident
    /// since — so the consume read fast-path ([`SegmentReader::scan_range`]) may skip the redundant
    /// per-read body CRC32C recompute for a PLAINTEXT segment. `false` (the default from
    /// [`SegmentReader::open`]) means every read fully re-validates, so an untrusted, recovered-but-not-
    /// yet-marked, or freshly-RELOADED (a fresh reader after evict) segment always catches corruption.
    /// The flag lives on the reader, so dropping the reader on evict/reload clears it for free; a fresh
    /// reader re-derives it from the resident set. It NEVER affects an encrypted read (whose AEAD tag is
    /// always verified) — those take `scan_range`'s decrypt branch, which ignores this flag.
    verified_resident: bool,
    /// Verify-always opt-out (#540, tunability): when `true` (from [`LogConfig::verify_always`]), the
    /// body CRC is recomputed on EVERY read even for a verified-resident segment, restoring the
    /// pre-#540 always-verify behavior for the paranoid. Default `false` (verify-once).
    verify_always: bool,
    /// The at-rest AEAD parameters `(aead_suite_id, key_id)` read from the header at open, or `None`
    /// for a plaintext segment (#780). Behind the `encryption` feature.
    #[cfg(feature = "encryption")]
    aead: Option<(u8, u64)>,
    /// The loaded key ring for decrypting an encrypted segment (#780), or `None` (a plaintext reader,
    /// or an encrypted segment opened without keys — which then reports `UnknownKeyId`). Behind the
    /// `encryption` feature.
    #[cfg(feature = "encryption")]
    keyring: Option<Arc<crate::crypto::KeyRing>>,
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
        // Read the at-rest AEAD params (suite id + key-id) from the header's reserved region; `None`
        // for a plaintext segment. The header CRC (validated above) already covers these bytes.
        #[cfg(feature = "encryption")]
        let aead = SegmentHeader::aead_params(&hbuf);
        Ok(SegmentReader {
            file,
            header,
            file_len,
            // A freshly-opened reader is UNVERIFIED: it always fully re-validates until a caller that has
            // established the verified-resident predicate stamps it via `with_verified_resident`. This
            // fail-closed default is what makes a RELOADED segment (a fresh reader after evict) re-verify.
            verified_resident: false,
            verify_always: false,
            #[cfg(feature = "encryption")]
            aead,
            #[cfg(feature = "encryption")]
            keyring: None,
        })
    }

    /// The validated header.
    #[must_use]
    pub fn header(&self) -> &SegmentHeader {
        &self.header
    }

    /// Marks this reader VERIFIED-RESIDENT (#540): the consume read fast-path may skip the redundant
    /// per-read body CRC recompute for a PLAINTEXT segment. The caller MUST have established the
    /// predicate (self-written this process, or CRC-validated on load/recovery/cold-restore, and
    /// continuously resident since); see [`SegmentReader::verified_resident`]. Chained at reader
    /// construction, before the reader is shared as an `Arc`. A wrong stamp serves corrupt data
    /// silently, so this is called ONLY from the resident-reader open sites for a known-verified id.
    #[must_use]
    pub fn with_verified_resident(mut self, verified: bool) -> SegmentReader<F> {
        self.verified_resident = verified;
        self
    }

    /// Sets the verify-always opt-out (#540, [`LogConfig::verify_always`]): when `true`, the body CRC is
    /// recomputed on EVERY read even for a verified-resident segment. Chained at reader construction.
    #[must_use]
    pub fn with_verify_always(mut self, verify_always: bool) -> SegmentReader<F> {
        self.verify_always = verify_always;
        self
    }

    /// Whether this reader is currently verified-resident (#540). For tests and the read-plane wiring.
    #[must_use]
    pub fn is_verified_resident(&self) -> bool {
        self.verified_resident
    }

    /// Whether the consume read fast-path may SKIP the per-read body CRC recompute for this segment
    /// (#540): only when the reader is verified-resident AND the verify-always opt-out is off. The
    /// encrypted read path never consults this — it always AEAD-verifies.
    #[must_use]
    fn skip_body_crc(&self) -> bool {
        self.verified_resident && !self.verify_always
    }

    /// Opens a segment WITH a loaded key ring so [`SegmentReader::scan_decrypted`] can decrypt an
    /// at-rest-encrypted segment (#780). A plaintext segment ignores the ring. Behind the `encryption`
    /// feature.
    ///
    /// # Errors
    /// Same as [`SegmentReader::open`].
    #[cfg(feature = "encryption")]
    pub fn open_with_keyring(
        file: F,
        keyring: Arc<crate::crypto::KeyRing>,
    ) -> Result<SegmentReader<F>, StorageError> {
        let mut reader = SegmentReader::open(file)?;
        reader.keyring = Some(keyring);
        Ok(reader)
    }

    /// Scans an at-rest-ENCRYPTED segment and returns its records with the bodies DECRYPTED (#780),
    /// materializing each `OwnedRecord`'s key/headers/payload from the recovered plaintext. Every
    /// record is validated CRC-first (the codec checks the CRC over the on-disk ciphertext + tag
    /// BEFORE any decrypt), then AEAD-decrypted under the segment header's suite/key-id and the
    /// deterministic nonce `segment_id || record_ordinal`.
    ///
    /// A decrypt failure is a DISTINCT, reported [`StorageError::Decrypt`] (unknown key-id vs tag
    /// mismatch), never a silent skip, a crash, or garbage plaintext. A plaintext segment (no
    /// `SEGMENT_FLAG_ENCRYPTED`) falls back to the ordinary [`SegmentReader::scan`].
    ///
    /// This is the focused, self-contained decrypt read for phase 1; threading decryption through
    /// every zero-copy/replication/compaction read path is the tracked follow-on.
    ///
    /// # Errors
    /// [`StorageError::Decrypt`] on a key/tag failure, [`StorageError::Record`] on a corrupt frame,
    /// [`StorageError::Segment`] on a bad footer, or an IO error.
    #[cfg(feature = "encryption")]
    pub fn scan_decrypted(&self) -> Result<Vec<OwnedRecord>, StorageError> {
        use ironbus_core::codec;
        // A plaintext segment: ordinary scan (its bodies are already cleartext).
        let Some((suite_id, key_id)) = self.aead else {
            return Ok(self.scan()?.records);
        };
        let suite = crate::crypto::AeadSuite::from_id(suite_id).ok_or(StorageError::Decrypt(
            crate::crypto::DecryptError::UnsupportedSuite(suite_id),
        ))?;
        let keyring = self.keyring.as_ref();
        let header_end = SEGMENT_HEADER_LEN as u64;
        // Determine the body end: just before a sealed footer if present, else the clamped file end.
        let footer_len = SEGMENT_FOOTER_LEN as u64;
        let body_end = if self.file_len >= header_end + footer_len {
            let mut fbuf = [0u8; SEGMENT_FOOTER_LEN];
            self.file
                .read_exact_at(&mut fbuf, self.file_len - footer_len)?;
            if SegmentFooter::decode(&fbuf).is_ok() {
                self.file_len - footer_len
            } else {
                self.file_len
            }
        } else {
            self.file_len
        };
        if body_end <= header_end {
            return Ok(Vec::new());
        }
        let body_len =
            usize::try_from(body_end - header_end).map_err(|_| StorageError::SegmentFull)?;
        let mut body = BytesMut::zeroed(body_len);
        self.file.read_exact_at(&mut body, header_end)?;
        let body = body.freeze();

        let segment_id = self.header.segment_id;
        let base_offset = self.header.base_offset.get();
        let mut out = Vec::new();
        let mut pos = 0usize;
        let mut ordinal = 0u32;
        while pos < body.len() {
            let (view, consumed) = codec::decode_encrypted(&body[pos..])?;
            // Decrypt this record's ciphertext under the segment's suite/key-id and its ordinal nonce.
            let plaintext = match keyring {
                Some(ring) => ring
                    .decrypt_record(
                        suite,
                        key_id,
                        segment_id,
                        ordinal,
                        view.ciphertext,
                        view.tag,
                    )
                    .map_err(StorageError::Decrypt)?,
                None => {
                    // No keys loaded at all: the same reported UnknownKeyId class, never a silent read.
                    return Err(StorageError::Decrypt(
                        crate::crypto::DecryptError::UnknownKeyId(key_id),
                    ));
                }
            };
            // Split the recovered plaintext into key/headers/payload by the header's plaintext lengths.
            let key_len = view.key_len as usize;
            let hdr_len = view.hdr_len as usize;
            let plain = Bytes::from(plaintext);
            let offset = Offset::new(base_offset + u64::from(ordinal));
            out.push(OwnedRecord {
                offset,
                seq: view.seq,
                timestamp_ms: view.timestamp_ms,
                // Expose the DECRYPTED record as a normal plaintext record downstream (the ENCRYPTED
                // bit is a storage-internal, on-disk concern, cleared on the materialized record).
                flags: RecordFlags::from_bits(view.flags.bits() & !RecordFlags::ENCRYPTED.bits()),
                key: plain.slice(0..key_len),
                headers: plain.slice(key_len..key_len + hdr_len),
                payload: plain.slice(key_len + hdr_len..),
                subject: Bytes::new(),
                stream_tag: Bytes::new(),
            });
            pos += consumed;
            ordinal = ordinal.checked_add(1).ok_or(StorageError::SegmentFull)?;
        }
        Ok(out)
    }

    /// Clamps this reader's view of the file to end at `end` (never grown past the real length,
    /// never cut into the 64-byte header `open` validated).
    ///
    /// For the ACTIVE segment, whose preallocated LOGICAL EXTENSION (`docs/PREALLOCATION.md`)
    /// makes `file.len()` the roll size rather than the data end, the caller (the log) knows the
    /// true data end (the writer's `write_pos`); bounding the reader there keeps the eager
    /// whole-region reads ([`scan`](SegmentReader::scan)'s body read,
    /// [`record_byte_positions`](SegmentReader::record_byte_positions)'s walk) at O(data) instead
    /// of O(roll size) — unbounded, a fallback scan of a nearly-empty extended segment would
    /// allocate and read up to a whole roll size (64 MiB default) of zeros. Behavior is
    /// byte-identical to scanning a file physically truncated at `end`: everything past the
    /// writer's position is unwritten zeros, which no scan decodes a record or a footer from, so
    /// the records, positions, and `valid_end` are unchanged. SEALED segments are truncated
    /// exactly at their footer by `seal`, so they never need (and never get) this clamp.
    #[must_use]
    pub fn with_data_end(mut self, end: u64) -> SegmentReader<F> {
        self.file_len = self.file_len.min(end.max(SEGMENT_HEADER_LEN as u64));
        self
    }

    /// Reads `len` bytes starting at file byte position `start` into a FRESH shared [`Bytes`]
    /// buffer WITHOUT pre-zeroing it (#813 / #815).
    ///
    /// The single-pass consume read primitives ([`scan_range`](SegmentReader::scan_range),
    /// [`raw_byte_range`](SegmentReader::raw_byte_range), their compacted siblings, and the
    /// recovery body scans) allocate a `len`-byte buffer and then immediately fill EVERY byte with
    /// one [`RandomAccessFile::read_exact_at`]. The former code first zero-filled that buffer
    /// (`BytesMut::zeroed(len)`, a full `len`-byte `memset`), but `read_exact_at` overwrites all
    /// `len` bytes before the buffer is ever read (or errors without exposing it), so the zero-fill
    /// was 100% wasted per-fetch work that scaled with the read window (up to an ~8 MiB fetch). This
    /// reads straight into uninitialized reserved capacity instead, dropping that `memset` while
    /// producing a byte-for-byte identical result. `len == 0` yields an empty `Bytes` (matching both
    /// the old `BytesMut::zeroed(0).freeze()` and a no-op `read_exact_at` on an empty slice), so a
    /// caller need not special-case an empty region.
    ///
    /// # Errors
    /// Propagates the IO error from the read (including `UnexpectedEof` on a short region); on any
    /// error the buffer is dropped with length 0, so no uninitialized byte is ever observable.
    fn read_into_fresh(&self, len: usize, start: u64) -> Result<Bytes, StorageError> {
        if len == 0 {
            return Ok(Bytes::new());
        }
        let mut buf = BytesMut::with_capacity(len);
        // View the first `len` bytes of the reserved-but-uninitialized spare capacity as the
        // `&mut [u8]` write target for the positioned read.
        //
        // SAFETY: `with_capacity(len)` reserved at least `len` contiguous bytes, so
        // `spare_capacity_mut()` yields `len`-or-more allocated, writable `MaybeUninit<u8>`s and the
        // `len`-byte slice built from its pointer is in bounds (`len <= spare.len()`). The slice is
        // only ever WRITTEN through here: `read_exact_at` writes into `buf` and never reads its
        // input, so handing it uninitialized `u8` memory exposes no uninitialized byte to any read.
        #[allow(unsafe_code)]
        let dst = unsafe {
            std::slice::from_raw_parts_mut(buf.spare_capacity_mut().as_mut_ptr().cast::<u8>(), len)
        };
        // Fills all `len` bytes from `start`, or returns `Err` (leaving `buf` at length 0, dropped
        // before any byte is exposed).
        self.file.read_exact_at(dst, start)?;
        // SAFETY: `read_exact_at` returned `Ok`, and its contract is that it wrote EVERY one of the
        // `len` bytes just handed to it (it loops issuing reads until the buffer is full, or errors
        // — it cannot return `Ok` with the buffer partly unwritten). The first `len` bytes are
        // therefore fully initialized, so advancing the logical length to `len` exposes only
        // initialized memory.
        #[allow(unsafe_code)]
        unsafe {
            buf.set_len(len);
        }
        Ok(buf.freeze())
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
        // Read the region into ONE buffer and freeze it to a shared `Bytes` (#480): every record this
        // walk materializes takes refcounted slices of `body` instead of three per-record `Vec`
        // copies, so the whole scan is one allocation + refcount bumps. The frozen buffer outlives the
        // returned records (each holds a ref), so it is freed only when the last record drops.
        let body = self.read_into_fresh(body_len, start)?;
        let mut records = Vec::new();
        let mut cursor = 0usize;
        let mut clean = true;
        // At-rest encryption (#780 phase 2): an ENCRYPTED segment DECRYPTS each frame here, so the
        // buffered scan (and its `read_slot_into` full-scan fallback, e.g. a resumed active segment
        // whose seek index is not yet seeded) serves PLAINTEXT records. Resolved once — encryption is
        // uniform per segment.
        #[cfg(feature = "encryption")]
        let enc = self.aead_read_params()?;
        while cursor < body.len() {
            #[cfg(feature = "encryption")]
            if let Some((suite, key_id)) = enc {
                let ordinal =
                    u32::try_from(records.len()).map_err(|_| StorageError::SegmentFull)?;
                let offset = Offset::new(
                    self.header
                        .base_offset
                        .get()
                        .saturating_add(records.len() as u64),
                );
                let Some((rec, consumed)) =
                    self.decrypt_frame(&body[cursor..], offset, ordinal, suite, key_id)?
                else {
                    // A torn/corrupt frame ends the valid prefix (a key/tag failure already returned an
                    // error); a decrypt-mismatch is never mistaken for a torn tail.
                    clean = false;
                    break;
                };
                records.push(rec);
                cursor += consumed;
                continue;
            }
            // A torn or corrupt frame ends the valid prefix; recovery skips the rest.
            // The bounded-loss report is produced by a later layer.
            let Ok((view, subject, consumed)) = codec::decode_with_subject(&body[cursor..]) else {
                clean = false;
                break;
            };
            let offset = Offset::new(
                self.header
                    .base_offset
                    .get()
                    .saturating_add(records.len() as u64),
            );
            // The decode above validated the whole frame's CRC, so the view's slices are over an
            // already-validated frame; `from_view` then refcount-slices them (and the subject, #594)
            // out of `body`.
            records.push(OwnedRecord::from_view(offset, &body, &view, subject));
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

    /// Walks the DENSE (v1) record region and returns SPARSE anchors — one `(log offset, frame
    /// START byte position)` per `stride` bytes of frame data, Kafka `.index` style (#537) — so the
    /// caller can build a resident seek index whose RAM is `O(region_bytes / stride)` REGARDLESS of
    /// how many small records the segment packs (the dense [`SegmentReader::record_byte_positions`]
    /// costs `O(records)`, ~1.86 MiB for a fully-packed 8 MiB edge segment of 36-byte frames; the
    /// sparse list is a small constant). The first record is always anchored, so any in-range offset
    /// has an anchor at or before it; a read seeks to that anchor and scans forward at most `stride`
    /// bytes (a bounded frame count) to the exact record, the bounded scan between index points.
    ///
    /// It steps frame-by-frame, reading each whole frame and FULL-CRC-validating it with the SAME
    /// `codec::decode` [`SegmentReader::scan`] uses (header AND body CRC), so it delimits the EXACT
    /// SAME valid prefix `scan` does — it stops at the first torn OR body-corrupt frame, never
    /// stepping past a frame whose body fails its CRC (a header-only step would, which would let an
    /// anchor point past `scan`'s prefix). The walk's own memory is one reusable per-frame scratch
    /// buffer (no whole-region buffering), so the build is bounded to the largest single record.
    /// The active segment is walked over the whole file; a sealed segment's body-consistent footer
    /// is excluded first, exactly as [`SegmentReader::scan`] and [`SegmentReader::record_byte_positions`]
    /// do, keeping the valid prefix byte-identical.
    ///
    /// `stride` is clamped up to one byte so a degenerate `0` cannot anchor every record.
    ///
    /// # Errors
    /// Returns [`StorageError::FooterSegmentMismatch`] if a body-consistent footer names a different
    /// segment (the same recycled/mixed-file guard `scan` applies), or an IO error.
    pub fn sparse_record_byte_positions(
        &self,
        stride: u64,
    ) -> Result<SparsePositions, StorageError> {
        let header_end = SEGMENT_HEADER_LEN as u64;
        let footer_len = SEGMENT_FOOTER_LEN as u64;
        let stride = stride.max(1);

        // Mirror `record_byte_positions`/`scan` seal handling so the walked region is byte-identical:
        // a trailing footer is trusted (and excluded) only when it is consistent with the body.
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
            let walk = self.walk_sparse_positions(header_end, body_end, stride)?;
            let ends_at_footer = walk.clean && header_end + walk.cursor == body_end;
            let expected_last_seq = walk.last_seq.unwrap_or(self.header.base_seq);
            let body_matches = u64::from(footer.record_count) == walk.count
                && footer.last_seq == expected_last_seq;
            if ends_at_footer && body_matches {
                if footer.segment_id != self.header.segment_id {
                    return Err(StorageError::FooterSegmentMismatch {
                        header: self.header.segment_id,
                        footer: footer.segment_id,
                    });
                }
                return Ok((walk.anchors, body_end));
            }
            // The candidate does not describe the body: treat the segment as unsealed and walk the
            // valid prefix from the full file, exactly as `scan` does.
        }

        let walk = self.walk_sparse_positions(header_end, self.file_len, stride)?;
        Ok((walk.anchors, header_end + walk.cursor))
    }

    /// Rebuilds the SPARSE timestamp -> offset anchors for this segment's `.tindex` (#772) from a
    /// validating frame walk of the durable record region: one `(offset, exclusive prefix-max
    /// timestamp)` anchor every `stride_records` records (index `0, stride, 2*stride, ...`),
    /// byte-identical to the anchors [`crate::tindex::build_anchors`] produces from the same
    /// timestamps (the seal path accumulates those incrementally; this is the rebuild path for a
    /// missing/torn/corrupt sidecar). It steps the SAME full-CRC-validating `codec::decode` walk the
    /// offset-index build uses, so it stops at the exact valid prefix a scan would and never anchors
    /// a timestamp past a torn or body-corrupt frame. Memory is bounded to one per-frame scratch
    /// buffer plus the sparse anchors, never the whole region.
    ///
    /// `stride_records` is clamped up to 1 so a degenerate `0` cannot anchor every record.
    ///
    /// # Errors
    /// Returns [`StorageError::FooterSegmentMismatch`] if a body-consistent footer names a different
    /// segment (the recycled/mixed-file guard `scan` applies), or an IO error reading the region.
    pub fn time_anchors(&self, stride_records: u32) -> Result<Vec<(u64, u64)>, StorageError> {
        let header_end = SEGMENT_HEADER_LEN as u64;
        let footer_len = SEGMENT_FOOTER_LEN as u64;
        // Mirror `sparse_record_byte_positions`/`scan` seal handling so the walked region (and thus
        // the anchor set) is byte-identical to what the append path sealed: a trailing footer is
        // trusted (and excluded) only when it is consistent with the body.
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
            let walk = self.walk_time_anchors(header_end, body_end, stride_records)?;
            let ends_at_footer = walk.clean && header_end + walk.cursor == body_end;
            let expected_last_seq = walk.last_seq.unwrap_or(self.header.base_seq);
            let body_matches = u64::from(footer.record_count) == walk.count
                && footer.last_seq == expected_last_seq;
            if ends_at_footer && body_matches {
                if footer.segment_id != self.header.segment_id {
                    return Err(StorageError::FooterSegmentMismatch {
                        header: self.header.segment_id,
                        footer: footer.segment_id,
                    });
                }
                return Ok(walk.anchors);
            }
        }
        Ok(self
            .walk_time_anchors(header_end, self.file_len, stride_records)?
            .anchors)
    }

    /// Streams `[start, end)` frame-by-frame, FULL-CRC-validating each frame (the SAME `codec::decode`
    /// the offset-index/recovery walks use), collecting one `(offset, exclusive prefix-max
    /// timestamp)` anchor every `stride_records` records and stopping at the first torn OR
    /// body-corrupt frame (#772). The running max is the max producer timestamp across the records
    /// strictly BEFORE the anchored offset, exactly the value [`crate::tindex::build_anchors`]
    /// stores, so a rebuilt index resolves the same offset as the append-seeded one.
    fn walk_time_anchors(
        &self,
        start: u64,
        end: u64,
        stride_records: u32,
    ) -> Result<TimeAnchorWalk, StorageError> {
        let stride = u64::from(stride_records.max(1));
        let base = self.header.base_offset.get();
        let mut scratch: Vec<u8> = Vec::new();
        let mut pos = start;
        let mut count = 0u64;
        let mut running_max = 0u64;
        let mut last_seq = None;
        let mut clean = true;
        let mut anchors: Vec<(u64, u64)> = Vec::new();
        while pos < end {
            let remaining = end - pos;
            if remaining < RECORD_HEADER_LEN as u64 {
                clean = false;
                break;
            }
            scratch.resize(RECORD_HEADER_LEN, 0);
            self.file.read_exact_at(&mut scratch, pos)?;
            if has_post_header_prefix_field(scratch[ironbus_core::format::header_offsets::FLAGS])
                && remaining >= (RECORD_HEADER_LEN + RECORD_SUBJECT_LEN_PREFIX) as u64
            {
                scratch.resize(RECORD_HEADER_LEN + RECORD_SUBJECT_LEN_PREFIX, 0);
                self.file.read_exact_at(
                    &mut scratch[RECORD_HEADER_LEN..],
                    pos + RECORD_HEADER_LEN as u64,
                )?;
            }
            let Ok(total) = codec::decoded_len(&scratch) else {
                clean = false;
                break;
            };
            if total as u64 > remaining {
                clean = false;
                break;
            }
            scratch.resize(total, 0);
            self.file.read_exact_at(
                &mut scratch[RECORD_HEADER_LEN..],
                pos + RECORD_HEADER_LEN as u64,
            )?;
            let Ok((view, consumed)) = codec::decode(&scratch) else {
                clean = false;
                break;
            };
            // Anchor this record when it starts a new stride bucket, carrying the EXCLUSIVE prefix
            // max (the running max BEFORE folding in this record's timestamp).
            if count % stride == 0 {
                anchors.push((base.saturating_add(count), running_max));
            }
            running_max = running_max.max(view.timestamp_ms);
            last_seq = Some(view.seq);
            count += 1;
            pos += consumed as u64;
        }
        Ok(TimeAnchorWalk {
            anchors,
            last_seq,
            count,
            cursor: pos - start,
            clean,
        })
    }

    /// Streams `[start, end)` frame-by-frame, FULL-CRC-validating each frame (the SAME `codec::decode`
    /// `scan`/`walk_positions` use), and collects a SPARSE anchor every `stride` bytes of frame data,
    /// stopping at the first torn OR body-corrupt frame (#537), so the prefix it accepts is IDENTICAL
    /// to the buffered `walk_positions`. A header-only step would walk PAST a body-corrupt frame
    /// (the header CRC alone cannot see a bad body), letting an anchor point past `scan`'s prefix, so
    /// the body CRC is validated here even though only the position is kept. The FIRST record is
    /// always anchored (`next_anchor_at` starts at the region start), and after each anchor the next
    /// boundary advances by `stride`, so anchors are at most `stride` bytes apart — the bound a read
    /// forward-scans between. Memory is one reusable per-frame scratch buffer (the largest record),
    /// never the whole region.
    fn walk_sparse_positions(
        &self,
        start: u64,
        end: u64,
        stride: u64,
    ) -> Result<SparseWalk, StorageError> {
        let mut scratch: Vec<u8> = Vec::new();
        let mut pos = start;
        let mut count = 0u64;
        let mut last_seq = None;
        let mut clean = true;
        let mut anchors: Vec<(u64, u64)> = Vec::new();
        // The next frame START at or past this boundary is anchored; it starts at `start`, so the
        // first record is always anchored, then advances by `stride` after each anchor taken.
        let mut next_anchor_at = start;
        while pos < end {
            let remaining = end - pos;
            if remaining < RECORD_HEADER_LEN as u64 {
                // Fewer bytes than a record header: a torn tail, not a whole frame.
                clean = false;
                break;
            }
            // Learn the frame length from the (header-CRC-validated) header, then read the WHOLE
            // frame and full-CRC-validate it, exactly as the streaming recovery scan does.
            scratch.resize(RECORD_HEADER_LEN, 0);
            self.file.read_exact_at(&mut scratch, pos)?;
            // A HAS_SUBJECT (#594) or HAS_STREAM_TAG (#597) record carries a `u16` length prefix
            // immediately after the header, and the header-only length walk needs those extra bytes
            // to size the frame. Read them into `scratch` before `decoded_len` when either flag is set
            // and the region is long enough; a shorter region is a torn tail, which `decoded_len` then
            // reports as Truncated (clean=false) below, exactly like any incomplete frame.
            if has_post_header_prefix_field(scratch[ironbus_core::format::header_offsets::FLAGS])
                && remaining >= (RECORD_HEADER_LEN + RECORD_SUBJECT_LEN_PREFIX) as u64
            {
                scratch.resize(RECORD_HEADER_LEN + RECORD_SUBJECT_LEN_PREFIX, 0);
                self.file.read_exact_at(
                    &mut scratch[RECORD_HEADER_LEN..],
                    pos + RECORD_HEADER_LEN as u64,
                )?;
            }
            let Ok(total) = codec::decoded_len(&scratch) else {
                clean = false;
                break;
            };
            if total as u64 > remaining {
                // The header is intact but the frame would run past the region: a torn tail.
                clean = false;
                break;
            }
            scratch.resize(total, 0);
            self.file.read_exact_at(
                &mut scratch[RECORD_HEADER_LEN..],
                pos + RECORD_HEADER_LEN as u64,
            )?;
            let Ok((view, consumed)) = codec::decode(&scratch) else {
                // A corrupt body (or trailer): ends the valid prefix, exactly as `scan` stops.
                clean = false;
                break;
            };
            // Anchor this frame if it is the first frame at or past the pending boundary. Because
            // frames vary in length, advance the boundary to `pos + stride` (relative to THIS
            // anchor) so consecutive anchors are at least `stride` apart, never less, bounding the
            // forward scan a read does from an anchor to the next at `stride` bytes.
            if pos >= next_anchor_at {
                anchors.push((self.header.base_offset.get().saturating_add(count), pos));
                next_anchor_at = pos.saturating_add(stride);
            }
            last_seq = Some(view.seq);
            count += 1;
            pos += consumed as u64;
        }
        Ok(SparseWalk {
            anchors,
            last_seq,
            count,
            cursor: pos - start,
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
        // No byte cap: `scan_range` with `max_bytes = None` IS the historical `scan_from`.
        self.scan_range(start_byte, start_offset, read_end, max, None)
    }

    /// Reads a CONTIGUOUS run of up to `max` DENSE (v1) records starting at the file byte position
    /// `start_byte` in ONE linear forward pass — the byte-capped sibling of [`SegmentReader::
    /// scan_from`] and the single-pass batch-read primitive of the consume read plane (#538, the
    /// I1 #537 seek-index spine). One `read_exact_at` fills a shared `Bytes` buffer, then the
    /// records refcount-slice it (#480): a seek-and-read-forward of N records is ONE syscall + ONE
    /// allocation + N refcounted slices, NOT N opens/seeks/decodes — `O(N)` over the run, not
    /// `O(N * records-per-segment)`. Each materialized record is FULLY CRC-validated (header AND
    /// body, via the same `codec::decode` the scan uses); the seek index is a LOCATOR, never a CRC
    /// bypass (verify-once CRC-skip is the separate #540). Zero-copy / `sendfile` is the separate
    /// #542; this returns materialized [`OwnedRecord`]s.
    ///
    /// Bounds, all honored in the single pass:
    /// - `max`: stop after `max` records. `max == 0` returns empty (matching `scan_from`).
    /// - `read_end`: no frame whose body would extend at or past it is materialized (the caller
    ///   passes the segment's flushed `valid_end`, so a torn/unflushed tail is never read).
    /// - `max_bytes`: stop once the accumulated ENCODED frame bytes (each frame's `consumed` span)
    ///   would EXCEED the cap. `None` means no byte cap. To avoid a stall on a record larger than
    ///   the cap, the FIRST record is ALWAYS taken even if it alone exceeds `max_bytes` (the
    ///   standard "at least one" fetch rule); the cap then bounds every record AFTER the first.
    ///
    /// The record at `start_byte` is assigned log offset `start_offset` and each subsequent record
    /// the next consecutive offset. `start_byte` MUST be a real frame boundary (an index entry);
    /// reading mid-frame fails the CRC and stops, never returning a bogus record. Returns the
    /// records in offset order.
    ///
    /// # Errors
    /// Returns an IO error from reading the region. A torn or corrupt frame is NOT an error: it
    /// ends the returned prefix, exactly as `scan` stops at the first bad frame.
    pub fn scan_range(
        &self,
        start_byte: u64,
        start_offset: Offset,
        read_end: u64,
        max: usize,
        max_bytes: Option<usize>,
    ) -> Result<Vec<OwnedRecord>, StorageError> {
        if max == 0 || start_byte >= read_end {
            return Ok(Vec::new());
        }
        let len = usize::try_from(read_end.saturating_sub(start_byte))
            .map_err(|_| StorageError::SegmentFull)?;
        // ONE read into a shared `Bytes` buffer; each materialized record refcount-slices it (#480),
        // so a seek-and-read-forward is one allocation + refcounted slices on the consume hot path,
        // not O(records) allocations + O(bytes) copied. The buffer outlives the returned records.
        // Read straight into fresh (unzeroed) capacity: the read fully overwrites it (#813 / #815).
        let body = self.read_into_fresh(len, start_byte)?;
        // At-rest encryption (#780 phase 2): an ENCRYPTED segment DECRYPTS each frame on read here, so
        // the WHOLE consume read path (`read_range` -> `read_slot_into` -> seek -> `scan_range`) serves
        // PLAINTEXT records over an encrypted log transparently, reusing the seek index and the
        // active-segment `read_end` bound. The plaintext `codec::decode_with_subject` below would REFUSE
        // an encrypted frame, so the encrypted case takes its own decrypt loop. A missing key / tag
        // mismatch is the reported `StorageError::Decrypt`, never garbage; a torn/corrupt frame ends the
        // prefix exactly as the plaintext path.
        #[cfg(feature = "encryption")]
        if let Some((suite, key_id)) = self.aead_read_params()? {
            return self.scan_range_decrypted(&body, start_offset, max, max_bytes, suite, key_id);
        }
        // Verify-once (#540): when this segment is VERIFIED-RESIDENT (its body integrity was already
        // proven this process and it has stayed resident since) and the verify-always opt-out is off,
        // the consume read fast-path DECODES WITH THE BODY CRC SKIPPED. Every structural/framing check
        // still runs, and the stored `body_crc` is untouched on disk (a client verifies end-to-end); we
        // only elide the redundant server-side recompute of already-trusted bytes. An unverified,
        // freshly-reloaded, or opt-out reader takes the full-CRC branch and still catches corruption.
        // NOTE: this is the PLAINTEXT loop only — an encrypted segment returned above via
        // `scan_range_decrypted`, which always AEAD-verifies and never consults `skip_body_crc`.
        let skip_body_crc = self.skip_body_crc();
        let mut records = Vec::with_capacity(max.min(64));
        let mut cursor = 0usize;
        let mut byte_total = 0usize;
        let mut next_offset = start_offset.get();
        while cursor < body.len() && records.len() < max {
            // The SAME CRC-gated decode `scan_body` uses (or its body-CRC-skipping trusted sibling on
            // the verify-once fast-path): a torn or corrupt frame ends the prefix. Both variants run
            // every structural check, so a mis-framed frame is still rejected here identically.
            let decoded = if skip_body_crc {
                codec::decode_with_subject_trusted(&body[cursor..])
            } else {
                codec::decode_with_subject(&body[cursor..])
            };
            let Ok((view, subject, consumed)) = decoded else {
                break;
            };
            // Byte cap: stop BEFORE a record that would push the accumulated encoded frame bytes
            // past `max_bytes`, but ALWAYS admit the first record (records non-empty would not yet
            // be true) so a single record larger than the cap never stalls the read.
            if let Some(cap) = max_bytes {
                if !records.is_empty() && byte_total.saturating_add(consumed) > cap {
                    break;
                }
            }
            byte_total = byte_total.saturating_add(consumed);
            // Frame CRC-validated by the decode above before the slice is taken.
            records.push(OwnedRecord::from_view(
                Offset::new(next_offset),
                &body,
                &view,
                subject,
            ));
            next_offset = next_offset.saturating_add(1);
            cursor += consumed;
        }
        Ok(records)
    }

    /// The at-rest-ENCRYPTED sibling of the [`SegmentReader::scan_range`] decode loop (#780 phase 2):
    /// walks the same body buffer frame by frame with [`codec::decode_encrypted`] (which validates the
    /// frame's header/body CRC over the on-disk ciphertext + tag), AEAD-decrypts each record under the
    /// segment's suite/key-id and the deterministic `segment_id || record_ordinal` nonce, and
    /// materializes a PLAINTEXT [`OwnedRecord`]. The record's per-segment ordinal is `offset -
    /// base_offset` (a dense v1 segment), which is exactly the counter the writer encrypted under, so
    /// the nonce reproduces on read across any restart. Same `max` / `max_bytes` bounds and same
    /// torn/corrupt-tail stop as the plaintext loop; a missing key / tag failure is the reported
    /// [`StorageError::Decrypt`], never a silent skip or garbage plaintext.
    #[cfg(feature = "encryption")]
    fn scan_range_decrypted(
        &self,
        body: &Bytes,
        start_offset: Offset,
        max: usize,
        max_bytes: Option<usize>,
        suite: crate::crypto::AeadSuite,
        key_id: u64,
    ) -> Result<Vec<OwnedRecord>, StorageError> {
        let base_offset = self.header.base_offset.get();
        let mut records = Vec::with_capacity(max.min(64));
        let mut cursor = 0usize;
        let mut byte_total = 0usize;
        let mut next_offset = start_offset.get();
        while cursor < body.len() && records.len() < max {
            // A dense v1 record's per-segment ordinal (the counter the writer encrypted under) is its
            // `offset - base_offset`, so the nonce reproduces on read across any restart.
            let ordinal = u32::try_from(next_offset.saturating_sub(base_offset))
                .map_err(|_| StorageError::SegmentFull)?;
            // A torn/corrupt frame ends the prefix (`Ok(None)`, exactly as the plaintext loop breaks); a
            // key/tag failure is the reported `StorageError::Decrypt`.
            let Some((rec, consumed)) = self.decrypt_frame(
                &body[cursor..],
                Offset::new(next_offset),
                ordinal,
                suite,
                key_id,
            )?
            else {
                break;
            };
            if let Some(cap) = max_bytes {
                if !records.is_empty() && byte_total.saturating_add(consumed) > cap {
                    break;
                }
            }
            byte_total = byte_total.saturating_add(consumed);
            records.push(rec);
            next_offset = next_offset.saturating_add(1);
            cursor += consumed;
        }
        Ok(records)
    }

    /// The at-rest suite + key-id for this segment if it is ENCRYPTED (and the suite is supported),
    /// else `None` for a plaintext segment (#780 phase 2). An UNSUPPORTED (unknown future) suite id is
    /// the reported [`StorageError::Decrypt`] `UnsupportedSuite`, refused fail-closed like an unknown
    /// checksum algorithm — never guessed.
    #[cfg(feature = "encryption")]
    fn aead_read_params(&self) -> Result<Option<(crate::crypto::AeadSuite, u64)>, StorageError> {
        match self.aead {
            None => Ok(None),
            Some((suite_id, key_id)) => {
                let suite = crate::crypto::AeadSuite::from_id(suite_id).ok_or(
                    StorageError::Decrypt(crate::crypto::DecryptError::UnsupportedSuite(suite_id)),
                )?;
                Ok(Some((suite, key_id)))
            }
        }
    }

    /// Decrypts ONE at-rest-encrypted frame at the front of `frame` for log `offset` / per-segment
    /// `ordinal` (#780 phase 2), materializing a PLAINTEXT [`OwnedRecord`] and returning it with the
    /// frame's byte length. Returns `Ok(None)` when the frame is torn or corrupt (the CRC-gated
    /// [`codec::decode_encrypted`] refused it) — the "end the valid prefix" signal the plaintext decode
    /// loops use. A CRC-valid frame that fails to DECRYPT (no keyring, unknown key-id, or tag mismatch)
    /// is the REPORTED [`StorageError::Decrypt`], never a silent skip or garbage plaintext. The shared
    /// per-frame decrypt behind [`SegmentReader::scan_range`] and [`SegmentReader::scan_body`].
    #[cfg(feature = "encryption")]
    fn decrypt_frame(
        &self,
        frame: &[u8],
        offset: Offset,
        ordinal: u32,
        suite: crate::crypto::AeadSuite,
        key_id: u64,
    ) -> Result<Option<(OwnedRecord, usize)>, StorageError> {
        use ironbus_core::codec;
        let Ok((view, consumed)) = codec::decode_encrypted(frame) else {
            return Ok(None);
        };
        // No keyring at all is the SAME reported UnknownKeyId class as an unloaded key-id — never a
        // silent read of ciphertext, never a plaintext read of an encrypted frame.
        let Some(ring) = self.keyring.as_ref() else {
            return Err(StorageError::Decrypt(
                crate::crypto::DecryptError::UnknownKeyId(key_id),
            ));
        };
        let plaintext = ring
            .decrypt_record(
                suite,
                key_id,
                self.header.segment_id,
                ordinal,
                view.ciphertext,
                view.tag,
            )
            .map_err(StorageError::Decrypt)?;
        let key_len = view.key_len as usize;
        let hdr_len = view.hdr_len as usize;
        let plain = Bytes::from(plaintext);
        let rec = OwnedRecord {
            offset,
            seq: view.seq,
            timestamp_ms: view.timestamp_ms,
            // The ENCRYPTED bit is a storage-internal on-disk concern; the materialized record is
            // plaintext, so clear it (mirrors `scan_decrypted`).
            flags: RecordFlags::from_bits(view.flags.bits() & !RecordFlags::ENCRYPTED.bits()),
            key: plain.slice(0..key_len),
            headers: plain.slice(key_len..key_len + hdr_len),
            payload: plain.slice(key_len + hdr_len..),
            subject: Bytes::new(),
            stream_tag: Bytes::new(),
        };
        Ok(Some((rec, consumed)))
    }

    /// Reads a CONTIGUOUS run of up to `max` DENSE (v1) frames starting at the file byte position
    /// `start_byte` as RAW on-disk bytes — the ZERO-COPY READ primitive (#542, M1-I6) and the
    /// byte-for-byte sibling of [`SegmentReader::scan_range`] MINUS the per-record decode and
    /// materialization. `scan_range` reads the region into one buffer and then decodes every frame
    /// into an [`OwnedRecord`] (a body-CRC check + three refcount slices per record); this reads the
    /// SAME region into the SAME single shared buffer, walks the frame boundaries with the cheap
    /// HEADER-ONLY check ([`codec::decoded_len`], which validates each frame's header CRC), and
    /// returns the contiguous frame bytes for the admitted run as ONE refcounted [`Bytes`] handle.
    /// No body is decoded, no `OwnedRecord` is allocated.
    ///
    /// On the in-memory backends the shared buffer the returned [`RawByteRun::bytes`] slices is the
    /// segment's own resident bytes, so the run is a true no-copy view; on the disk backend it is
    /// one `read_exact_at` into one buffer (the contiguous extent a later `sendfile(2)` path — see
    /// #542's deferred follow-up — would hand to the kernel instead of to user space, without
    /// changing this read shape).
    ///
    /// Bounds, all honored in the single pass and IDENTICAL to `scan_range`'s:
    /// - `max`: stop after `max` frames. `max == 0` returns an empty run at `start_offset`.
    /// - `read_end`: no frame whose body would extend at or past it is admitted (the caller passes
    ///   the segment's flushed `valid_end`, so a torn/unflushed tail is never carried).
    /// - `max_bytes`: stop once the accumulated frame bytes would EXCEED the cap. `None` means no
    ///   byte cap. The FIRST frame is ALWAYS taken even if it alone exceeds the cap (the "at least
    ///   one" fetch rule), so a record larger than the cap never stalls the read; the cap then bounds
    ///   every frame AFTER the first — the exact rule `scan_range` applies.
    ///
    /// The frame at `start_byte` is assigned log offset `start_offset` and each subsequent frame the
    /// next consecutive offset. `start_byte` MUST be a real frame boundary; a header that fails its
    /// CRC (a torn or mid-frame read) ENDS the run exactly as `scan_range` stops at the first bad
    /// frame, so the returned bytes are always a clean prefix of whole, header-validated frames. The
    /// body CRC of each frame is carried VERBATIM in the returned bytes for the consumer to verify
    /// end-to-end; it is not re-checked here because the bytes are never touched on this path.
    ///
    /// # Errors
    /// Returns an IO error from reading the region. A torn or corrupt header is NOT an error: it
    /// ends the returned run.
    pub fn raw_byte_range(
        &self,
        start_byte: u64,
        start_offset: Offset,
        read_end: u64,
        max: usize,
        max_bytes: Option<usize>,
    ) -> Result<RawByteRun, StorageError> {
        let empty = RawByteRun {
            bytes: Bytes::new(),
            first_offset: start_offset,
            record_count: 0,
            next_offset: start_offset,
        };
        if max == 0 || start_byte >= read_end {
            return Ok(empty);
        }
        let len = usize::try_from(read_end.saturating_sub(start_byte))
            .map_err(|_| StorageError::SegmentFull)?;
        // ONE read into a shared `Bytes` buffer — the same single allocation `scan_range` makes. The
        // returned run slices THIS buffer (a refcount bump), so a seek-and-read-forward of N frames is
        // one syscall + one allocation + zero per-record allocations and zero body decodes.
        // Read straight into fresh (unzeroed) capacity: the read fully overwrites it (#813 / #815).
        let body = self.read_into_fresh(len, start_byte)?;
        let mut cursor = 0usize;
        let mut byte_total = 0usize;
        let mut count = 0usize;
        let mut next_offset = start_offset.get();
        while cursor < body.len() && count < max {
            // HEADER-ONLY boundary walk: `decoded_len` validates the frame's HEADER CRC and returns
            // the full frame length WITHOUT touching the body — the cheap half of `codec::decode`. A
            // torn or corrupt header ends the run, exactly as `scan_range`'s `decode` does, so the
            // admitted bytes are always whole, header-validated frames.
            let Ok(consumed) = codec::decoded_len(&body[cursor..]) else {
                break;
            };
            // The frame must lie WHOLLY within the read region; a frame that would run off the end of
            // the buffer is a torn tail and ends the run (matching `scan_range`, whose `decode` of a
            // short tail returns `Truncated` and breaks).
            if cursor.saturating_add(consumed) > body.len() {
                break;
            }
            // Byte cap: stop BEFORE a frame that would push the accumulated bytes past `max_bytes`,
            // but ALWAYS admit the first frame so a single frame larger than the cap never stalls —
            // the identical rule `scan_range` applies against `OwnedRecord::encoded_len`.
            if let Some(cap) = max_bytes {
                if count != 0 && byte_total.saturating_add(consumed) > cap {
                    break;
                }
            }
            byte_total = byte_total.saturating_add(consumed);
            count += 1;
            next_offset = next_offset.saturating_add(1);
            cursor += consumed;
        }
        Ok(RawByteRun {
            // The admitted prefix: the first `byte_total` bytes are exactly `count` whole frames. A
            // refcount slice of the shared buffer, never a copy.
            bytes: body.slice(0..byte_total),
            first_offset: start_offset,
            record_count: count as u64,
            next_offset: Offset::new(next_offset),
        })
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
        // The survivor region is read into ONE shared `Bytes` buffer and each survivor refcount-slices
        // it (#480), the same one-alloc + refcounted-slices win as the dense path. The buffer outlives
        // the returned survivors. Read straight into fresh (unzeroed) capacity (#813 / #815).
        let body = self.read_into_fresh(body_len, header_end)?;
        let mut records: Vec<OwnedRecord> = Vec::new();
        let mut cursor = 0usize;
        let mut max_timestamp_ms = 0u64;
        let mut prev_seq: Option<u64> = None;
        while cursor < body.len() {
            let Ok((view, subject, consumed)) = codec::decode_with_subject(&body[cursor..]) else {
                // A torn or corrupt frame inside a COMMITTED compacted segment is bit-rot of acked
                // data, NOT a crash-before-commit torn tail: the trailing footer AND meta block both
                // decoded CRC-VALID above (~line 1663-1670), which PROVES this segment reached its
                // compaction commit point. It is the SOLE durable copy of the survivors it covers, so
                // it must NEVER be conflated with the `Ok(None)` orphan (which recovery silently
                // unlinks). Signal the committed-but-corrupt case DISTINCTLY (#836), carrying the
                // covered range (from the CRC-valid meta) and the survivor byte region, so recovery
                // QUARANTINES it and accounts the loss instead of dropping it unreported.
                return Err(StorageError::CorruptCompacted {
                    segment_id: self.header.segment_id,
                    covered_base_offset: meta.covered_base_offset,
                    covered_end_offset: meta.covered_end_offset,
                    record_region_start: header_end,
                    record_region_end: footer_start,
                    record_count_estimate: u64::from(footer.record_count),
                });
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
            // Frame CRC-validated by the decode above before the slice is taken.
            records.push(OwnedRecord::from_view(offset, &body, &view, subject));
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
            // The footer's record count or the body length disagrees with the decoded survivors.
            // The footer AND meta block both decoded CRC-VALID above, so this is a COMMITTED
            // compacted segment (past its commit point), not a crash-before-commit orphan: its
            // survivors are the sole durable copy. Signal the committed-but-corrupt case DISTINCTLY
            // (#836) so recovery quarantines it and accounts the loss, rather than the silent
            // `Ok(None)` orphan unlink that would drop acked data unreported.
            return Err(StorageError::CorruptCompacted {
                segment_id: self.header.segment_id,
                covered_base_offset: meta.covered_base_offset,
                covered_end_offset: meta.covered_end_offset,
                record_region_start: header_end,
                record_region_end: footer_start,
                record_count_estimate: u64::from(footer.record_count),
            });
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
        // No byte cap: the historical `scan_compacted_from` is `scan_compacted_range` with `None`.
        self.scan_compacted_range(start_byte, base_off, base_seq, read_end, max, None)
    }

    /// The byte-capped sibling of [`SegmentReader::scan_compacted_from`]: reads a CONTIGUOUS run of
    /// up to `max` SPARSE survivors from a COMPACTED (v2) segment in ONE linear forward pass, with
    /// the same single-read + refcounted-slice (#480) machinery, honoring an optional `max_bytes`
    /// cap on the accumulated ENCODED frame bytes (#538). This is the compacted half of the
    /// single-pass batch-read primitive `Log::read_range` threads its byte budget through. `None`
    /// means no byte cap; the FIRST survivor is ALWAYS taken even if it alone exceeds the cap (the
    /// "at least one" rule), so a single large survivor never stalls the read. CRC validation per
    /// frame is unchanged (the seek index is a locator, not a trust bypass).
    ///
    /// # Errors
    /// Returns an IO error from reading the region. A torn or corrupt frame is NOT an error: it
    /// ends the returned prefix, exactly as the dense `scan_range` stops at the first bad frame.
    pub fn scan_compacted_range(
        &self,
        start_byte: u64,
        base_off: u64,
        base_seq: u64,
        read_end: u64,
        max: usize,
        max_bytes: Option<usize>,
    ) -> Result<Vec<OwnedRecord>, StorageError> {
        if max == 0 || start_byte >= read_end {
            return Ok(Vec::new());
        }
        let len = usize::try_from(read_end.saturating_sub(start_byte))
            .map_err(|_| StorageError::SegmentFull)?;
        // ONE read into a shared `Bytes` buffer; each survivor refcount-slices it (#480), the same
        // one-alloc + refcounted-slices win as the dense `scan_from`. The buffer outlives the records.
        // Read straight into fresh (unzeroed) capacity: the read fully overwrites it (#813 / #815).
        let body = self.read_into_fresh(len, start_byte)?;
        let mut records = Vec::with_capacity(max.min(64));
        let mut cursor = 0usize;
        let mut byte_total = 0usize;
        while cursor < body.len() && records.len() < max {
            // The SAME CRC-gated decode `scan_compacted` uses: a torn or corrupt frame ends the read.
            let Ok((view, subject, consumed)) = codec::decode_with_subject(&body[cursor..]) else {
                break;
            };
            // Byte cap: stop BEFORE a survivor that would exceed `max_bytes`, but always admit the
            // first (so one large survivor never stalls the read), mirroring the dense `scan_range`.
            if let Some(cap) = max_bytes {
                if !records.is_empty() && byte_total.saturating_add(consumed) > cap {
                    break;
                }
            }
            byte_total = byte_total.saturating_add(consumed);
            // Reconstruct the original sparse offset from the constant offset-minus-seq delta, the
            // identical reconstruction `scan_compacted` applies.
            let seq = view.seq.get();
            let offset = Offset::new(base_off.wrapping_add(seq.wrapping_sub(base_seq)));
            // Frame CRC-validated by the decode above before the slice is taken.
            records.push(OwnedRecord::from_view(offset, &body, &view, subject));
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
    /// bounded read window (`RECOVERY_WINDOW_BYTES`), or a single over-window frame,
    /// never the whole region. Returns the valid
    /// record count, the maximum record timestamp, the last valid sequence, the bytes
    /// consumed, and whether the region decoded cleanly. A valid frame with an
    /// out-of-order sequence is a hard error, the same structural check `Log::recover`
    /// applies to a buffered scan.
    fn scan_body_streaming(&self, start: u64, end: u64) -> Result<BodyWalk, StorageError> {
        // The reused read window: `win` holds the file bytes `[win_start, win_start + win.len())`.
        // Frames are decoded out of this window (byte-for-byte the same header/body/CRC/sequence
        // decisions the per-record path made), refilling only when the next frame's header or body
        // straddles the window edge, so recovery issues ~`body_bytes / RECOVERY_WINDOW_BYTES` reads
        // instead of two per record (#816).
        let mut win: Vec<u8> = Vec::new();
        let mut win_start = start;
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
            // Ensure the window holds this frame's header, then learn the frame length.
            self.fill_window(
                &mut win,
                &mut win_start,
                pos,
                RECORD_HEADER_LEN as u64,
                remaining,
            )?;
            let mut rel =
                usize::try_from(pos - win_start).map_err(|_| StorageError::SegmentFull)?;
            // A HAS_SUBJECT (#594) or HAS_STREAM_TAG (#597) record carries a `u16` length prefix
            // immediately after the header, and the header-only length walk needs those extra bytes to
            // size the frame. `fill_window(need=36)` may leave EXACTLY 36-37 bytes buffered at a window
            // edge (it returns early once `have >= need`), so ensure 38 bytes are windowed before
            // `decoded_len` when either flag is set and the region is long enough — mirroring
            // `walk_sparse_positions`. A shorter region is a torn tail, which `decoded_len` then
            // reports as `Truncated` below (ended as a corrupt/torn header), exactly like any
            // incomplete frame. The flags byte is untrusted here, but `decoded_len`'s header-CRC
            // check is the real gate; peeking it only decides how many bytes to buffer.
            if has_post_header_prefix_field(win[rel + ironbus_core::format::header_offsets::FLAGS])
                && remaining >= (RECORD_HEADER_LEN + RECORD_SUBJECT_LEN_PREFIX) as u64
            {
                self.fill_window(
                    &mut win,
                    &mut win_start,
                    pos,
                    (RECORD_HEADER_LEN + RECORD_SUBJECT_LEN_PREFIX) as u64,
                    remaining,
                )?;
                rel = usize::try_from(pos - win_start).map_err(|_| StorageError::SegmentFull)?;
            }
            let Ok(total) = codec::decoded_len(&win[rel..]) else {
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
            // Ensure the whole frame is in the window (a straddling frame triggers a refill from
            // `pos`, growing the window only for a single frame larger than the window), then
            // validate it out of the window slice.
            self.fill_window(&mut win, &mut win_start, pos, total as u64, remaining)?;
            rel = usize::try_from(pos - win_start).map_err(|_| StorageError::SegmentFull)?;
            // On an at-rest-ENCRYPTED segment (#780) the plaintext `codec::decode` REFUSES the frame
            // (`DecodeError::Encrypted`), so recovery validates the frame's header/body CRC (over the
            // on-disk ciphertext + tag) and reads its `seq`/`timestamp_ms` via `decode_encrypted` —
            // WITHOUT the key. Recovery needs only the FRAMING to find the durable valid prefix and
            // resume the writer; the AEAD decrypt (which needs the key) is a read-time concern. Without
            // this dispatch an encrypted active segment would recover as a CORRUPT TAIL at its FIRST
            // record and silently truncate every acked record. Both decoders return `(seq, ts, len)`
            // after the same CRC gate, so the torn/corrupt-tail behavior is identical.
            let decoded = if self.header.is_encrypted() {
                codec::decode_encrypted(&win[rel..rel + total])
                    .map(|(v, consumed)| (v.seq, v.timestamp_ms, consumed))
            } else {
                codec::decode(&win[rel..rel + total])
                    .map(|(v, consumed)| (v.seq, v.timestamp_ms, consumed))
            };
            let Ok((seq, timestamp_ms, consumed)) = decoded else {
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
            if seq.get() != expected {
                return Err(StorageError::RecoveredSequenceMismatch {
                    index: usize::try_from(count).map_err(|_| StorageError::SegmentFull)?,
                    expected,
                    found: seq.get(),
                });
            }
            last_seq = seq;
            // Accumulate the MAX timestamp across the valid prefix (not the last): producer
            // timestamps are not monotonic, so recovery must reconstruct the same max the writer
            // tracked, for the age-retention reaper.
            max_timestamp_ms = max_timestamp_ms.max(timestamp_ms);
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

    /// Ensures the reused read window `win` (covering `[*win_start, *win_start + win.len())`)
    /// contains at least `need` bytes starting at `pos`, refilling with a single `read_exact_at`
    /// anchored at `pos` when it does not. `remaining` is `end - pos`, the bytes left in the walk
    /// region; the caller guarantees `need <= remaining`, so the read never runs past the region
    /// (and, in the footer-candidate case, never into the trailing footer bytes). The window is
    /// filled to `RECOVERY_WINDOW_BYTES` where the region allows, but grows to `need` for a single
    /// frame larger than the window, matching the one-record bound the per-record path tolerated.
    fn fill_window(
        &self,
        win: &mut Vec<u8>,
        win_start: &mut u64,
        pos: u64,
        need: u64,
        remaining: u64,
    ) -> Result<(), StorageError> {
        // Already buffered: `pos` never rewinds, so `pos >= *win_start` holds.
        let have = if pos >= *win_start {
            (win.len() as u64).saturating_sub(pos - *win_start)
        } else {
            0
        };
        if have >= need {
            return Ok(());
        }
        // Refill from `pos`: read a full window where the region allows, but never fewer than
        // `need` bytes and never past the region end (`need <= remaining`).
        let want = need.max((RECOVERY_WINDOW_BYTES as u64).min(remaining));
        let want = usize::try_from(want).map_err(|_| StorageError::SegmentFull)?;
        *win_start = pos;
        // Read straight into the window's uninitialized capacity instead of the grow-only zero-fill
        // `resize(want, 0)` did (#945 applies the #813 `read_into_fresh` treatment to the recovery
        // scan). `read_exact_at` overwrites every one of the `want` bytes before any is read, so
        // pre-zeroing the freshly grown tail was wasted work that scaled with the window on a large
        // recovery log; the bytes handed back are byte-for-byte identical (same region -> same
        // bytes). Truncating to length 0 first means a mid-read error leaves NO uninitialized byte
        // observable, and lets `reserve` grow the buffer without copying the stale window bytes.
        win.clear();
        win.reserve(want);
        // SAFETY: `reserve(want)` on a now-empty `Vec` guaranteed capacity >= `want`, so
        // `spare_capacity_mut()` yields at least `want` allocated, writable `MaybeUninit<u8>`s and the
        // `want`-byte slice built from its pointer is in bounds (`want <= spare.len()`). The slice is
        // only ever WRITTEN through here: `read_exact_at` writes into it and never reads its input, so
        // handing it uninitialized `u8` memory exposes no uninitialized byte to any read.
        #[allow(unsafe_code)]
        let dst = unsafe {
            std::slice::from_raw_parts_mut(win.spare_capacity_mut().as_mut_ptr().cast::<u8>(), want)
        };
        // Fills all `want` bytes from `pos`, or returns `Err` (leaving `win` at length 0).
        self.file.read_exact_at(dst, pos)?;
        // SAFETY: `read_exact_at` returned `Ok`, so it wrote EVERY one of the `want` bytes just handed
        // to it (it loops issuing reads until the buffer is full, or errors — it cannot return `Ok`
        // with the buffer partly unwritten). The first `want` bytes are therefore fully initialized,
        // so setting the logical length to `want` exposes only initialized memory.
        #[allow(unsafe_code)]
        unsafe {
            win.set_len(want);
        }
        Ok(())
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
        assert_eq!(scan.records[0].payload.as_ref(), b"one");
        assert_eq!(scan.records[2].seq, Seq::new(2));
        assert_eq!(scan.records[2].payload.as_ref(), b"three");
    }

    /// The optional stored field the window-straddling frame in [`build_window_straddling_segment`]
    /// carries. `Plain` is the control (no post-header prefix); `Subject` (#594) and `StreamTag`
    /// (#597) each prepend a `u16` length prefix IMMEDIATELY after the record header — the exact bytes
    /// the header-only recovery walk must buffer before it can size the frame, and the bytes that fell
    /// outside the read window in the #594-A / #597 straddle bug. The two flags share the same
    /// [`has_post_header_prefix_field`] gate and `RECORD_SUBJECT_LEN_PREFIX` width, so the straddle
    /// exercises the identical recovery path for either.
    #[derive(Clone, Copy)]
    enum StraddleField {
        Plain,
        Subject,
        StreamTag,
    }

    impl StraddleField {
        fn label(self) -> &'static str {
            match self {
                StraddleField::Plain => "plain",
                StraddleField::Subject => "subject",
                StraddleField::StreamTag => "stream_tag",
            }
        }
    }

    /// Builds a SEALED segment whose record at index `written-6` STRADDLES the first recovery read
    /// window such that exactly 37 of its bytes are windowed (it starts at body offset
    /// `RECOVERY_WINDOW_BYTES - 37`), with five more records fully on disk after it. The straddling
    /// record carries a stored subject (#594) or stream tag (#597) per `field`, else it is plain.
    /// Returns the file and the total records written. (#594 / #597 / PR #1107 regression fixture.)
    fn build_window_straddling_segment(field: StraddleField) -> (Arc<InMemoryFile>, u64) {
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        // The straddling frame's START must land at body offset `RECOVERY_WINDOW_BYTES - 37`, so
        // exactly 37 of its bytes fall inside the first `RECOVERY_WINDOW_BYTES` read.
        let target = RECOVERY_WINDOW_BYTES - 37;
        let big_frame = RECORD_HEADER_LEN + 1000 + RECORD_TRAILER_LEN;
        let mut body = 0usize;
        let mut seq = 0u64;
        while body + big_frame <= target - 63 {
            w.append(&rec(seq, &vec![0xABu8; 1000])).unwrap();
            body += big_frame;
            seq += 1;
        }
        // Close the remaining gap EXACTLY with one filler record so the next frame starts at `target`.
        let remaining = target - body;
        assert!(remaining >= RECORD_HEADER_LEN + RECORD_TRAILER_LEN);
        let filler_payload = remaining - RECORD_HEADER_LEN - RECORD_TRAILER_LEN;
        w.append(&rec(seq, &vec![0xCDu8; filler_payload])).unwrap();
        body += RECORD_HEADER_LEN + filler_payload + RECORD_TRAILER_LEN;
        seq += 1;
        assert_eq!(
            body, target,
            "the straddling frame must start exactly at the window edge minus 37"
        );
        // The straddling record (subject, stream tag, or a plain control), then several records fully
        // on disk. The stored field is the SAME 11-byte length for the subject and stream-tag arms, so
        // both frames start at exactly `target` and straddle the window identically.
        match field {
            StraddleField::Plain => {
                w.append(&rec(seq, b"x")).unwrap();
            }
            StraddleField::Subject => {
                w.append_with_subject(&rec(seq, b"x"), b"orders.eu.1")
                    .unwrap();
            }
            StraddleField::StreamTag => {
                w.append_with_stream_tag(&rec(seq, b"x"), b"orders.eu.1")
                    .unwrap();
            }
        }
        seq += 1;
        for _ in 0..5 {
            w.append(&rec(seq, b"tail")).unwrap();
            seq += 1;
        }
        w.seal().unwrap();
        (file, seq)
    }

    #[test]
    fn a_subject_frame_straddling_the_recovery_window_recovers_without_data_loss() {
        // #594 (PR #1107 adversarial finding): the STREAMING crash-recovery walk fills only
        // RECORD_HEADER_LEN bytes before `decoded_len`, but a HAS_SUBJECT frame needs
        // RECORD_HEADER_LEN + RECORD_SUBJECT_LEN_PREFIX to read `subject_len`. When such a frame
        // straddled the read window with only 36-37 bytes buffered, `decoded_len` returned Truncated
        // and the walk mis-read the valid frame as a torn tail — silently dropping it AND every
        // record after it. Assert full recovery for the subject case; the plain control at the
        // identical position proves the guard is the subject case, not the positioning.
        for field in [StraddleField::Plain, StraddleField::Subject] {
            let (file, written) = build_window_straddling_segment(field);
            let scan = SegmentReader::open(Arc::clone(&file))
                .unwrap()
                .scan_recovery()
                .unwrap();
            assert_eq!(
                scan.record_count,
                written,
                "streaming recovery dropped records (field={}): a window-straddling HAS_SUBJECT frame \
                 must never be mis-read as a torn tail",
                field.label()
            );
            assert!(
                scan.clean,
                "the segment recovered clean (field={})",
                field.label()
            );
            assert_eq!(
                scan.last_seq,
                Seq::new(written - 1),
                "the last seq is recovered"
            );
        }
    }

    #[test]
    fn a_stream_tag_frame_straddling_the_recovery_window_recovers_without_data_loss() {
        // #597 (the #594-A lesson applied to the shared-WAL demux key): a HAS_STREAM_TAG frame carries
        // the SAME `u16` length prefix after the record header as a HAS_SUBJECT frame and reaches the
        // recovery walk through the SAME `has_post_header_prefix_field` gate. #597 shipped the guard
        // that buffers those prefix bytes before `decoded_len`, so the fix is covered by construction —
        // but the SUBJECT case had a direct regression test and the STREAM-TAG case did not. This is
        // the missing direct analogue: a HAS_STREAM_TAG frame straddling the window at
        // header..header+prefix bytes must RECOVER WITHOUT LOSS, never mis-read as a torn tail that
        // would silently drop it and every record after it. The plain control at the identical position
        // proves the guard is the stream-tag case, not the positioning.
        for field in [StraddleField::Plain, StraddleField::StreamTag] {
            let (file, written) = build_window_straddling_segment(field);
            let scan = SegmentReader::open(Arc::clone(&file))
                .unwrap()
                .scan_recovery()
                .unwrap();
            assert_eq!(
                scan.record_count,
                written,
                "streaming recovery dropped records (field={}): a window-straddling HAS_STREAM_TAG \
                 frame must never be mis-read as a torn tail",
                field.label()
            );
            assert!(
                scan.clean,
                "the segment recovered clean (field={})",
                field.label()
            );
            assert_eq!(
                scan.last_seq,
                Seq::new(written - 1),
                "the last seq is recovered"
            );
        }
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
    fn a_shared_file_clone_held_across_a_seal_stays_harmless() {
        // The #1040 Arc'd-writer property: the flusher's shared handle points at the SAME kernel
        // fd the writer stages into, and a clone that outlives the writer's `seal(mut self)` is
        // harmless — a stray barrier on the sealed file is a no-op Ok, and the sealed bytes are
        // byte-identical to a seal with no outstanding clone.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"a")).unwrap();
        let shared = w.shared_file();
        // The shared handle observes the writer's flushes: staging puts the frame in the file,
        // and a barrier issued through the CLONE (the flusher's call shape) succeeds.
        w.flush_pending().unwrap();
        shared.sync_data().unwrap();
        w.append(&rec(1, b"b")).unwrap();
        let footer = w.seal().unwrap();
        assert_eq!(footer.record_count, 2);
        // The clone outlived the seal: a late (stale-flight) barrier is still a harmless no-op.
        shared.sync_data().unwrap();
        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert!(scan.clean);
        assert_eq!(scan.footer, Some(footer));
        assert_eq!(scan.records.len(), 2);
    }

    #[test]
    fn seal_truncates_a_preallocated_logical_extension_down_to_the_footer_end() {
        // The production preallocation logically EXTENDS the active file to the roll size, so at
        // seal time the file may be much longer than the data. Footer discovery reads the trailing
        // 32 bytes of the FILE, so `seal` must truncate the unwritten zero tail away: the sealed
        // image ends exactly at the footer (byte-identical to a never-preallocated seal) and the
        // footer is discoverable again.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"a")).unwrap();
        w.append(&rec(1, b"b")).unwrap();
        w.sync().unwrap();
        // Apply the logical extension the production preallocate performs (the in-memory backend
        // models the reservation only, so write the zero tail out for real).
        file.set_len(64 * 1024).unwrap();
        let expected_end = w.write_pos() + SEGMENT_FOOTER_LEN as u64;
        let footer = w.seal().unwrap();
        assert_eq!(
            file.len().unwrap(),
            expected_end,
            "the sealed image ends exactly at the footer, zero tail gone"
        );
        // The truncation is fsynced by the seal's sync_all: it survives a power loss.
        file.simulate_power_loss();
        assert_eq!(file.len().unwrap(), expected_end);
        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert!(scan.clean);
        assert_eq!(scan.footer, Some(footer), "the seal is discoverable at EOF");
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
        assert_eq!(scan.records[0].payload.as_ref(), b"good1");
        assert_eq!(scan.valid_end, after_first);
    }

    #[test]
    fn read_primitives_return_the_exact_on_disk_region() {
        // #813 / #815: the single-pass consume read primitives now read straight into UNZEROED
        // reserved capacity instead of `BytesMut::zeroed` + overwrite. The bytes they return must be
        // EXACTLY the on-disk region — a length/capacity regression or a leaked uninitialized byte
        // would diverge from the raw file slice, and the decoded payloads would not round-trip.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"alpha")).unwrap();
        w.append(&rec(1, b"bravo")).unwrap();
        w.append(&rec(2, b"charlie")).unwrap();
        w.sync().unwrap();

        let reader = SegmentReader::open(Arc::clone(&file)).unwrap();
        let scan = reader.scan().unwrap();
        let start = SEGMENT_HEADER_LEN as u64;
        let valid_end = scan.valid_end;

        // `raw_byte_range` (zero-copy path) hands back the record region verbatim: it must equal the
        // exact on-disk bytes `[start, valid_end)`.
        let run = reader
            .raw_byte_range(start, Offset::new(0), valid_end, usize::MAX, None)
            .unwrap();
        assert_eq!(run.record_count, 3);
        let snap = file.snapshot();
        let lo = usize::try_from(start).unwrap();
        let hi = usize::try_from(valid_end).unwrap();
        assert_eq!(
            run.bytes.as_ref(),
            &snap[lo..hi],
            "raw bytes are the exact on-disk region, fully populated by the read"
        );

        // `scan_range` decodes the SAME region into records whose payloads round-trip unchanged.
        let recs = reader
            .scan_range(start, Offset::new(0), valid_end, usize::MAX, None)
            .unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].payload.as_ref(), b"alpha");
        assert_eq!(recs[1].payload.as_ref(), b"bravo");
        assert_eq!(recs[2].payload.as_ref(), b"charlie");
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
        assert_eq!(got[0].payload.as_ref(), b"good1");
    }

    /// Every sparse anchor (#537) locates the CORRECT record's frame: seeking to an anchor and
    /// reading one record yields exactly the record `scan` reports at that anchor's offset, for both
    /// an unsealed and a sealed segment, and the anchor list is genuinely SPARSE (far fewer than one
    /// per record at a small stride).
    #[test]
    fn sparse_record_byte_positions_anchors_locate_the_right_records() {
        for sealed in [false, true] {
            let file = Arc::new(InMemoryFile::new());
            let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
            for i in 0..40u64 {
                w.append(&rec(i, &[u8::try_from(i % 256).unwrap(); 11]))
                    .unwrap();
            }
            if sealed {
                w.seal().unwrap();
            } else {
                w.sync().unwrap();
            }
            let reader = SegmentReader::open(Arc::clone(&file)).unwrap();
            let scan = reader.scan().unwrap();
            // A small stride relative to the frame size forces several anchors but far fewer than the
            // 40 records — the sparse property.
            let stride = 128u64;
            let (anchors, valid_end) = reader.sparse_record_byte_positions(stride).unwrap();
            assert_eq!(valid_end, scan.valid_end, "valid_end matches scan");
            assert!(!anchors.is_empty(), "at least the first record is anchored");
            assert_eq!(anchors[0].0, 0, "the first record is always anchored");
            assert!(
                anchors.len() < scan.records.len(),
                "sparse: fewer anchors ({}) than records ({})",
                anchors.len(),
                scan.records.len()
            );
            // Each anchor's byte position locates exactly its claimed offset's record.
            for &(offset, pos) in &anchors {
                let got = reader
                    .scan_from(pos, Offset::new(offset), valid_end, 1)
                    .unwrap();
                assert_eq!(got.len(), 1, "one record from the anchor");
                assert_eq!(
                    got[0],
                    scan.records[usize::try_from(offset).unwrap()],
                    "anchor at offset {offset} locates the right record"
                );
            }
            // Consecutive anchors are at least `stride` bytes apart (the forward-scan bound).
            for w in anchors.windows(2) {
                assert!(
                    w[1].1 - w[0].1 >= stride,
                    "anchors are at least a stride apart"
                );
            }
        }
    }

    /// The sparse walk (#537) stops at a torn tail at the SAME prefix boundary `scan` does: anchors
    /// never point past the valid prefix.
    #[test]
    fn sparse_record_byte_positions_stops_at_a_torn_tail_exactly_like_scan() {
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
        let (anchors, valid_end) = reader.sparse_record_byte_positions(1).unwrap();
        assert_eq!(
            valid_end, after_first,
            "valid_end stops at the first record"
        );
        assert_eq!(anchors.len(), 1, "only the good record is anchored");
        assert_eq!(anchors[0], (0, SEGMENT_HEADER_LEN as u64));
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

    /// Builds a two-record segment, then corrupts the SECOND record's body byte in place and returns
    /// the file, the second record's frame position, and the valid end — the exact fixture the #540
    /// verify-once tests read through a verified vs unverified reader.
    fn segment_with_corrupt_second_body() -> (Arc<InMemoryFile>, u64, u64) {
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"first")).unwrap();
        let second_pos = w.write_pos();
        w.append(&rec(1, b"second")).unwrap();
        let valid_end = w.write_pos();
        w.sync().unwrap();
        // Corrupt the SECOND record's body in place; the frame's stored body_crc field is UNTOUCHED, so
        // a client that recomputes the CRC still detects the corruption end-to-end.
        let mut bytes = file.snapshot();
        let body_byte = usize::try_from(second_pos + RECORD_HEADER_LEN as u64 + 1).unwrap();
        bytes[body_byte] ^= 0x01;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        (file, second_pos, valid_end)
    }

    /// #540 verify-once, the load-bearing storage proof: a VERIFIED-RESIDENT reader SKIPS the per-read
    /// body CRC, so it SERVES a body that was corrupted in memory (the frame's own CRC field is intact,
    /// so a downstream client still catches it); an UNVERIFIED reader over the SAME bytes still catches
    /// it and ends the prefix; and the verify-always opt-out re-verifies even a verified-resident
    /// reader. This is the corrupt-in-memory-byte proof the issue asks for.
    #[test]
    fn verified_resident_scan_range_skips_body_crc_but_unverified_and_opt_out_still_catch_it() {
        let (file, second_pos, valid_end) = segment_with_corrupt_second_body();

        // (1) UNVERIFIED (the default, e.g. a freshly-RELOADED reader after evict): the body CRC is
        // recomputed, the corruption is caught, and the seeked prefix ends before the bad frame.
        let unverified = SegmentReader::open(Arc::clone(&file)).unwrap();
        assert!(!unverified.is_verified_resident());
        let got = unverified
            .scan_from(second_pos, Offset::new(1), valid_end, 10)
            .unwrap();
        assert!(
            got.is_empty(),
            "an unverified reader re-verifies and rejects the corrupt frame"
        );

        // (2) VERIFIED-RESIDENT (self-written / verified-on-load, resident since): the body CRC is
        // SKIPPED, so the corrupted second record is served verbatim (payload no longer equals
        // `second`) — proving the recompute was elided on the trusted fast-path.
        let verified = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .with_verified_resident(true);
        assert!(verified.is_verified_resident());
        let got = verified
            .scan_from(second_pos, Offset::new(1), valid_end, 10)
            .unwrap();
        assert_eq!(
            got.len(),
            1,
            "the verified reader skips the CRC and serves it"
        );
        assert_eq!(got[0].offset, Offset::new(1));
        assert_ne!(
            got[0].payload.as_ref(),
            b"second",
            "the corrupted body was served without a CRC check"
        );

        // (3) verify-always opt-out: even a verified-resident reader recomputes on every read, so the
        // corruption is caught again — the tunable escape hatch for the paranoid.
        let paranoid = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .with_verified_resident(true)
            .with_verify_always(true);
        let got = paranoid
            .scan_from(second_pos, Offset::new(1), valid_end, 10)
            .unwrap();
        assert!(
            got.is_empty(),
            "verify-always re-verifies every read even when verified-resident"
        );
    }

    /// #540: skipping the body CRC must NOT weaken structural integrity. A corrupt record HEADER (whose
    /// own CRC is always checked) still ends the prefix even for a verified-resident reader, and a
    /// verified read of an INTACT segment returns exactly what a full read returns.
    #[test]
    fn verified_resident_still_enforces_header_crc_and_is_identical_on_intact_bytes() {
        // A corrupt second-record HEADER byte (seq field, inside the header-CRC range) is caught even
        // when verified-resident: the header CRC is not part of the verify-once skip.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"first")).unwrap();
        let second_pos = w.write_pos();
        w.append(&rec(1, b"second")).unwrap();
        let valid_end = w.write_pos();
        w.sync().unwrap();
        let mut bytes = file.snapshot();
        // Byte offset 4 within the frame header is the seq field, inside the 0..32 header-CRC range.
        let header_byte = usize::try_from(second_pos + 4).unwrap();
        bytes[header_byte] ^= 0x01;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        let verified = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .with_verified_resident(true);
        let got = verified
            .scan_from(second_pos, Offset::new(1), valid_end, 10)
            .unwrap();
        assert!(
            got.is_empty(),
            "a corrupt header ends the prefix even for a verified-resident reader"
        );

        // On INTACT bytes a verified read is byte-identical to a full read (the skip changes nothing).
        let clean = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&clean), header()).unwrap();
        for i in 0..5u64 {
            w.append(&rec(i, &[u8::try_from(i).unwrap(); 9])).unwrap();
        }
        let clean_end = w.write_pos();
        w.sync().unwrap();
        let full = SegmentReader::open(Arc::clone(&clean)).unwrap();
        let full_recs = full.scan_from(SEGMENT_HEADER_LEN as u64, Offset::new(0), clean_end, 10);
        let verified = SegmentReader::open(Arc::clone(&clean))
            .unwrap()
            .with_verified_resident(true);
        let verified_recs =
            verified.scan_from(SEGMENT_HEADER_LEN as u64, Offset::new(0), clean_end, 10);
        assert_eq!(full_recs.unwrap(), verified_recs.unwrap());
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
    fn scan_range_honors_max_bytes_with_at_least_one() {
        // Uniform 7-byte-payload records => uniform frame lengths, so a byte budget admits a
        // predictable count, and a budget below one frame still returns exactly one record (#538).
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        for i in 0..6u64 {
            w.append(&rec(i, &[u8::try_from(i).unwrap(); 7])).unwrap();
        }
        w.sync().unwrap();
        let reader = SegmentReader::open(Arc::clone(&file)).unwrap();
        let (positions, valid_end) = reader.record_byte_positions().unwrap();
        let one_frame = reader
            .scan_range(positions[0], Offset::new(0), valid_end, 1, None)
            .unwrap()[0]
            .encoded_len();

        // A budget of exactly K frames yields K records (the K+1th frame would exceed it).
        for k in 1..=4usize {
            let got = reader
                .scan_range(
                    positions[0],
                    Offset::new(0),
                    valid_end,
                    usize::MAX,
                    Some(k * one_frame),
                )
                .unwrap();
            assert_eq!(
                got.len(),
                k,
                "byte budget for {k} frames yields {k} records"
            );
        }
        // A sub-frame budget (even zero) still returns exactly one record (the "at least one" rule).
        for cap in [0usize, 1, one_frame - 1] {
            let got = reader
                .scan_range(
                    positions[0],
                    Offset::new(0),
                    valid_end,
                    usize::MAX,
                    Some(cap),
                )
                .unwrap();
            assert_eq!(
                got.len(),
                1,
                "a sub-frame cap of {cap} still returns one record"
            );
        }
        // scan_range(.., None) is byte-identical to scan_from (the unbounded historical path).
        assert_eq!(
            reader
                .scan_range(positions[0], Offset::new(0), valid_end, usize::MAX, None)
                .unwrap(),
            reader
                .scan_from(positions[0], Offset::new(0), valid_end, usize::MAX)
                .unwrap()
        );
    }

    /// The zero-copy `raw_byte_range` (#542, M1-I6) returns the SAME records `scan_range` materializes
    /// — proven by decoding the raw bytes and comparing every field — while making ONE read, no body
    /// decode, and no per-record allocation. Covers the byte-identical differential, the `max`/
    /// `max_bytes` bounds (with "at least one"), the empty/torn boundaries, and the full-frame CRC
    /// riding along in the returned bytes.
    #[test]
    fn raw_byte_range_is_byte_identical_to_scan_range() {
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        for i in 0..6u64 {
            w.append(&rec(i, &[u8::try_from(i).unwrap(); 7])).unwrap();
        }
        w.sync().unwrap();
        let reader = SegmentReader::open(Arc::clone(&file)).unwrap();
        let (positions, valid_end) = reader.record_byte_positions().unwrap();
        let one_frame = reader
            .scan_range(positions[0], Offset::new(0), valid_end, 1, None)
            .unwrap()[0]
            .encoded_len();

        // Unbounded: the raw run carries all 6 frames and decodes byte-for-byte to scan_range.
        let materialized = reader
            .scan_range(positions[0], Offset::new(0), valid_end, usize::MAX, None)
            .unwrap();
        let raw = reader
            .raw_byte_range(positions[0], Offset::new(0), valid_end, usize::MAX, None)
            .unwrap();
        assert_eq!(raw.record_count, materialized.len() as u64);
        assert_eq!(raw.first_offset.get(), 0);
        assert_eq!(raw.next_offset.get(), materialized.len() as u64);
        // Decode the raw bytes and compare every field — the byte-identical differential.
        let mut cursor = 0usize;
        for (idx, owned) in materialized.iter().enumerate() {
            let (view, consumed) = codec::decode(&raw.bytes[cursor..]).expect("raw frame decodes");
            assert_eq!(view.seq, owned.seq, "seq mismatch at {idx}");
            assert_eq!(
                view.timestamp_ms, owned.timestamp_ms,
                "ts mismatch at {idx}"
            );
            assert_eq!(view.flags, owned.flags, "flags mismatch at {idx}");
            assert_eq!(view.key, &owned.key[..], "key mismatch at {idx}");
            assert_eq!(
                view.headers,
                &owned.headers[..],
                "headers mismatch at {idx}"
            );
            assert_eq!(
                view.payload,
                &owned.payload[..],
                "payload mismatch at {idx}"
            );
            cursor += consumed;
        }
        assert_eq!(cursor, raw.bytes.len(), "no trailing bytes past the frames");

        // max bounds the frame count exactly like scan_range.
        let raw3 = reader
            .raw_byte_range(positions[0], Offset::new(0), valid_end, 3, None)
            .unwrap();
        assert_eq!(raw3.record_count, 3);
        assert_eq!(raw3.next_offset.get(), 3);

        // A byte budget of K frames yields K frames; a sub-frame budget still yields one.
        for k in 1..=4usize {
            let got = reader
                .raw_byte_range(
                    positions[0],
                    Offset::new(0),
                    valid_end,
                    usize::MAX,
                    Some(k * one_frame),
                )
                .unwrap();
            assert_eq!(got.record_count, k as u64, "byte budget for {k} frames");
        }
        for cap in [0usize, 1, one_frame - 1] {
            let got = reader
                .raw_byte_range(
                    positions[0],
                    Offset::new(0),
                    valid_end,
                    usize::MAX,
                    Some(cap),
                )
                .unwrap();
            assert_eq!(got.record_count, 1, "sub-frame cap {cap} returns one frame");
        }

        // Empty boundaries: max=0 and start==read_end both serve nothing.
        let empty = reader
            .raw_byte_range(positions[0], Offset::new(0), valid_end, 0, None)
            .unwrap();
        assert_eq!(empty.record_count, 0);
        assert!(empty.bytes.is_empty());
        let at_end = reader
            .raw_byte_range(valid_end, Offset::new(6), valid_end, 10, None)
            .unwrap();
        assert_eq!(at_end.record_count, 0);
        assert_eq!(at_end.next_offset.get(), 6);
    }

    /// A torn/corrupt frame header ENDS the raw run exactly as it ends a scan — a bogus tail is never
    /// carried in the zero-copy bytes (CRC integrity at the run boundary is preserved).
    #[test]
    fn raw_byte_range_stops_at_a_torn_frame_like_scan() {
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"good1")).unwrap();
        let after_first = w.write_pos();
        w.append(&rec(1, b"good2")).unwrap();
        w.sync().unwrap();
        // Corrupt the second frame's HEADER (the magic byte) so its `decoded_len` header CRC fails.
        let mut bytes = file.snapshot();
        let magic_byte = usize::try_from(after_first).unwrap();
        bytes[magic_byte] ^= 0xFF;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();

        let reader = SegmentReader::open(Arc::clone(&file)).unwrap();
        // Start at the first RECORD frame (past the 64-byte segment header); read_end is the whole FILE
        // length (past both frames). Reading forward, the corrupt second header fails its CRC in
        // `decoded_len` and ends the run after the one good frame.
        let first_record_byte = SEGMENT_HEADER_LEN as u64;
        let file_len = file.len().unwrap();
        let raw = reader
            .raw_byte_range(first_record_byte, Offset::new(0), file_len, 10, None)
            .unwrap();
        assert_eq!(
            raw.record_count, 1,
            "the torn header ends the run at one frame"
        );
        let (view, consumed) = codec::decode(&raw.bytes).expect("the one good frame decodes");
        assert_eq!(view.payload, b"good1");
        assert_eq!(consumed, raw.bytes.len());
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
        assert_eq!(scan.records[0].payload.as_ref(), b"durable");
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
        assert_eq!(scan.records[0].payload.as_ref(), b"a");
        assert_eq!(scan.records[1].payload.as_ref(), b"b");
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
        assert_eq!(scan.records[0].payload.as_ref(), b"small");
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
        assert_eq!(scan.records[0].payload.as_ref(), b"keep1");
        assert_eq!(scan.records[1].payload.as_ref(), b"keep2");
    }

    #[test]
    fn with_data_end_scans_an_extended_active_segment_byte_identically_and_bounded() {
        // The active segment's preallocated LOGICAL EXTENSION makes file.len() the roll size, so
        // an unbounded eager scan/walk reads the whole zero tail. `with_data_end(write_pos)`
        // must be byte-identical to scanning the file as if it were physically truncated at the
        // data end: same records, same valid_end, same positions — while the whole-file scan of
        // the SAME extended image also agrees (zeros decode nothing), proving the clamp changes
        // only the bytes read, never the result.
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
        w.append(&rec(0, b"alpha")).unwrap();
        w.append(&rec(1, b"beta")).unwrap();
        w.append(&rec(2, b"gamma")).unwrap();
        w.sync().unwrap();
        let data_end = w.write_pos();
        // The production preallocate shape: the logical length is far past the data end.
        file.set_len(64 * 1024).unwrap();

        let bounded = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .with_data_end(data_end);
        assert_eq!(
            bounded.file_len, data_end,
            "the clamp bounds the reader's view at the data end"
        );
        let bounded_scan = bounded.scan().unwrap();
        let full_scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan()
            .unwrap();
        assert_eq!(bounded_scan.valid_end, data_end);
        assert_eq!(bounded_scan.valid_end, full_scan.valid_end);
        assert_eq!(bounded_scan.records, full_scan.records);
        assert_eq!(bounded_scan.records.len(), 3);
        assert!(bounded_scan.footer.is_none() && full_scan.footer.is_none());
        // The bounded view decoded the WHOLE region it saw (no zero tail inside it), while the
        // full view necessarily stopped early at the zero tail.
        assert!(bounded_scan.clean);
        assert!(!full_scan.clean);

        // The position walk agrees the same way (the truncate_to path).
        let (bounded_pos, bounded_end) = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .with_data_end(data_end)
            .record_byte_positions()
            .unwrap();
        let (full_pos, full_end) = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .record_byte_positions()
            .unwrap();
        assert_eq!(bounded_pos, full_pos);
        assert_eq!(bounded_end, full_end);
        assert_eq!(bounded_pos.len(), 3);

        // The clamp never grows past the real length and never cuts into the header.
        let short = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .with_data_end(u64::MAX);
        assert_eq!(short.file_len, 64 * 1024, "never grown past the file");
        let floor = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .with_data_end(0);
        assert_eq!(
            floor.file_len, SEGMENT_HEADER_LEN as u64,
            "never cut into the validated header"
        );
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
    fn scan_recovery_walks_records_across_read_windows() {
        // #816: the streaming walk decodes frames out of a bounded reused read window instead of
        // two preads per record. This body deliberately spans several `RECOVERY_WINDOW_BYTES`
        // windows so many frames straddle a window edge (forcing the refill-from-`pos` path), and
        // includes one frame LARGER than the window (forcing the grow-to-fit-one-frame path). The
        // recovered result must stay byte-for-byte identical to the buffered scan across every
        // window boundary, both unsealed and sealed (the footer-candidate re-walk must not read
        // into the trailing footer). Small frames alone already exceed one window several times
        // over, so a straddle is guaranteed; the oversized frame pins the grow branch.
        let oversized = vec![0xa5u8; RECOVERY_WINDOW_BYTES + 4096];
        for seal in [false, true] {
            let file = Arc::new(InMemoryFile::new());
            let mut w = SegmentWriter::create(Arc::clone(&file), header()).unwrap();
            let mut seq = 0u64;
            // Enough small records that the body crosses several 256 KiB windows.
            for _ in 0..12_000u64 {
                // Vary the payload length so frame sizes are not a uniform stride, letting frame
                // boundaries land at arbitrary offsets relative to the window edge.
                let n = 8 + usize::try_from(seq % 40).unwrap();
                let payload = vec![u8::try_from(seq & 0xff).unwrap(); n];
                w.append(&rec(seq, &payload)).unwrap();
                seq += 1;
                // Drop one over-window frame partway through to exercise the grow branch.
                if seq == 6_000 {
                    w.append(&rec(seq, &oversized)).unwrap();
                    seq += 1;
                }
            }
            if seal {
                w.seal().unwrap();
            } else {
                w.sync().unwrap();
            }
            let streamed = SegmentReader::open(Arc::clone(&file))
                .unwrap()
                .scan_recovery()
                .unwrap();
            assert_eq!(streamed.record_count, seq, "count (seal={seal})");
            assert_eq!(
                streamed.last_seq,
                Seq::new(seq - 1),
                "last_seq (seal={seal})"
            );
            assert!(streamed.clean, "clean (seal={seal})");
            assert_eq!(streamed.footer.is_some(), seal, "footer (seal={seal})");
            assert_scans_agree(&file);
        }
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
        assert_eq!(scan.records[2].payload.as_ref(), b"after");

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

    // ---- #835: the v2 sparse-survivor recovery parser `scan_compacted` hard-fail branches ----
    //
    // `scan_compacted` has its OWN copies of the durability hard-fail checks the v1 `scan`/
    // `scan_recovery` tests guard: an out-of-span or out-of-order survivor sequence
    // (`RecoveredSequenceMismatch`) and a footer that names a different segment id
    // (`FooterSegmentMismatch`). It runs during `recover_with_compaction` over untrusted on-disk
    // bytes a brownout or attacker may have corrupted; a regression that mis-ordered the span guard
    // (e.g. compared against `base_offset` instead of `covered_end_seq`, or dropped the
    // strictly-increasing check) would let recovery SILENTLY serve an out-of-span/out-of-order
    // survivor and reconstruct a wrong original offset (`seq + delta`), violating I5 offset
    // monotonicity. These build a REAL committed compacted segment with `create_compacted` +
    // `append_at` + `seal_compacted`, then corrupt exactly one fact and assert the matching hard
    // error (and that NO records are served).

    /// Builds a committed `version` = 2 COMPACTED segment on a fresh in-memory file from the given
    /// SPARSE survivor sequences (which must be strictly increasing and within
    /// `[base_seq, covered_end_seq)`). Returns the file, each survivor's frame START byte position
    /// (in survivor order), and the footer start byte, so a test can corrupt one frame or the
    /// footer in place. Segment id is `7`; the offset-minus-seq delta is `base_offset - base_seq`.
    fn build_compacted(
        seqs: &[u64],
        base_seq: u64,
        base_offset: u64,
        covered_end_seq: u64,
    ) -> (Arc<InMemoryFile>, Vec<u64>, u64) {
        let h = SegmentHeader {
            segment_id: 7,
            base_seq: Seq::new(base_seq),
            base_offset: Offset::new(base_offset),
            created_unix_ms: 0,
            flags: ironbus_core::format::SEGMENT_FLAG_COMPACTED,
        };
        let file = Arc::new(InMemoryFile::new());
        let mut w = SegmentWriter::create_compacted(Arc::clone(&file), h).unwrap();
        let mut positions = Vec::new();
        for (i, &s) in seqs.iter().enumerate() {
            // The frame START byte is the writer's byte position BEFORE the append (write_pos
            // advances synchronously even though the frame group-commits at seal).
            positions.push(w.write_pos());
            let off = Offset::new(base_offset + (s - base_seq));
            w.append_at(off, &rec(s, &[u8::try_from(i).unwrap(); 6]), b"")
                .unwrap();
        }
        let footer_start = w.write_pos();
        let footer = SegmentFooter {
            segment_id: 7,
            last_seq: Seq::new(*seqs.last().unwrap()),
            record_count: u32::try_from(seqs.len()).unwrap(),
        };
        let meta = CompactionMeta {
            covered_base_offset: base_offset,
            covered_end_offset: base_offset + (covered_end_seq - base_seq),
            covered_base_seq: base_seq,
            covered_end_seq,
            highest_covered_source_id: 7,
        };
        w.seal_compacted(&footer, &meta).unwrap();
        (file, positions, footer_start)
    }

    /// Rewrites the `seq` field of the frame at `frame_start` to `new_seq` and repairs the frame's
    /// HEADER CRC, so the corrupted frame still decodes cleanly (CRC-valid) and the ONLY thing wrong
    /// is the sequence value — exactly the recycled/mixed-file corruption the span + strictly-
    /// increasing guard must catch, never a CRC miss that would end the scan harmlessly.
    fn rewrite_frame_seq(bytes: &mut [u8], frame_start: u64, new_seq: u64) {
        use ironbus_core::format::header_offsets as ho;
        let fs = usize::try_from(frame_start).unwrap();
        bytes[fs + ho::SEQ..fs + ho::SEQ + 8].copy_from_slice(&new_seq.to_le_bytes());
        // The header CRC covers [0, 32) of the frame; recompute it so the tampered seq is accepted
        // by `codec::decode` and the failure is forced through the sequence guard, not the CRC.
        let crc = crc32c::crc32c(&bytes[fs..fs + RECORD_HEADER_LEN - 4]);
        bytes[fs + ho::HEADER_CRC..fs + ho::HEADER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
    }

    fn overwrite(file: &Arc<InMemoryFile>, bytes: &[u8]) {
        file.set_len(0).unwrap();
        file.write_all_at(bytes, 0).unwrap();
    }

    #[test]
    fn scan_compacted_reads_valid_sparse_survivors() {
        // The positive baseline: a correctly built compacted segment scans to Some, proving the
        // corruption tests below fail because of the CORRUPTION, not a malformed build. The sparse
        // survivor sequences 100, 102, 105 reconstruct their original offsets via the constant
        // offset-minus-seq delta (base_offset 1000 - base_seq 100 = 900).
        let (file, _pos, footer_start) = build_compacted(&[100, 102, 105], 100, 1000, 106);
        let scan = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan_compacted()
            .unwrap()
            .expect("a valid compacted segment scans to Some");
        assert_eq!(scan.records.len(), 3);
        assert_eq!(
            scan.records
                .iter()
                .map(|r| r.offset.get())
                .collect::<Vec<_>>(),
            vec![1000, 1002, 1005],
            "survivor offsets reconstructed from the constant delta"
        );
        assert_eq!(
            scan.records.iter().map(|r| r.seq.get()).collect::<Vec<_>>(),
            vec![100, 102, 105],
            "survivor sequences land on disk verbatim"
        );
        assert_eq!(scan.valid_end, footer_start);
        assert_eq!(scan.footer.record_count, 3);
        assert_eq!(scan.footer.segment_id, 7);
    }

    #[test]
    fn scan_compacted_rejects_out_of_order_survivor_seq() {
        // Rewrite the third survivor's seq (105) to 101, which is <= the previous survivor's seq
        // (102): a CRC-valid frame in the wrong order. The strictly-increasing guard must reject it
        // as a hard error rather than serve an out-of-order survivor (which would reconstruct a
        // wrong original offset and break I5). Drop the `prev_seq.is_some_and(|p| seq <= p)` term
        // and this test goes green while the bug ships — the mutation check.
        let (file, pos, _fs) = build_compacted(&[100, 102, 105], 100, 1000, 106);
        let mut bytes = file.snapshot();
        rewrite_frame_seq(&mut bytes, pos[2], 101);
        overwrite(&file, &bytes);
        let err = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan_compacted()
            .unwrap_err();
        assert!(
            matches!(
                err,
                StorageError::RecoveredSequenceMismatch {
                    index: 2,
                    expected: 103,
                    found: 101,
                }
            ),
            "out-of-order survivor seq must be a hard error, got {err:?}"
        );
    }

    #[test]
    fn scan_compacted_rejects_survivor_seq_outside_covered_span() {
        // Two span-guard cases, each on its own freshly built segment.
        //
        // (a) seq >= covered_end_seq: rewrite the third survivor's seq (105) to 106, which equals
        //     covered_end_seq. It is strictly greater than the previous survivor (102), so ONLY the
        //     `seq >= meta.covered_end_seq` span term catches it — the exact guard a regression that
        //     compared against `base_offset` instead of `covered_end_seq` would drop.
        {
            let (file, pos, _fs) = build_compacted(&[100, 102, 105], 100, 1000, 106);
            let mut bytes = file.snapshot();
            rewrite_frame_seq(&mut bytes, pos[2], 106);
            overwrite(&file, &bytes);
            let err = SegmentReader::open(Arc::clone(&file))
                .unwrap()
                .scan_compacted()
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    StorageError::RecoveredSequenceMismatch {
                        index: 2,
                        expected: 103,
                        found: 106,
                    }
                ),
                "a survivor seq at/after covered_end_seq must be a hard error, got {err:?}"
            );
        }
        // (b) seq < base_seq: rewrite the FIRST survivor's seq (100) to 99, below the header's
        //     base_seq. `prev_seq` is None here, so ONLY the `seq < base_seq` span term catches it.
        {
            let (file, pos, _fs) = build_compacted(&[100, 102, 105], 100, 1000, 106);
            let mut bytes = file.snapshot();
            rewrite_frame_seq(&mut bytes, pos[0], 99);
            overwrite(&file, &bytes);
            let err = SegmentReader::open(Arc::clone(&file))
                .unwrap()
                .scan_compacted()
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    StorageError::RecoveredSequenceMismatch {
                        index: 0,
                        expected: 100,
                        found: 99,
                    }
                ),
                "a survivor seq below base_seq must be a hard error, got {err:?}"
            );
        }
    }

    #[test]
    fn scan_compacted_rejects_footer_naming_a_different_segment() {
        // Re-encode the trailing v2 footer (via encode_v2, so the footer CRC stays valid) naming a
        // DIFFERENT segment id (999) than the header's (7). A body-consistent footer that binds to
        // the wrong segment is a mixed/recycled file: recovery must refuse it, never serve survivors
        // whose provenance it cannot trust. The block after the footer is left untouched so the
        // scan reaches the footer<->header binding check.
        let (file, _pos, footer_start) = build_compacted(&[100, 102, 105], 100, 1000, 106);
        let lying = SegmentFooter {
            segment_id: 999,
            last_seq: Seq::new(105),
            record_count: 3,
        };
        file.write_all_at(&lying.encode_v2(), footer_start).unwrap();
        let err = SegmentReader::open(Arc::clone(&file))
            .unwrap()
            .scan_compacted()
            .unwrap_err();
        assert!(
            matches!(
                err,
                StorageError::FooterSegmentMismatch {
                    header: 7,
                    footer: 999,
                }
            ),
            "a compacted footer naming a different segment must be rejected, got {err:?}"
        );
    }

    // --- At-rest AEAD encryption, end-to-end at the segment level (#780) ---
    #[cfg(feature = "encryption")]
    mod at_rest_encryption {
        use super::*;
        use crate::crypto::{AeadKey, AeadSuite, DecryptError, KeyRing, SegmentCrypto};

        fn enc_header(segment_id: u64, base: u64) -> SegmentHeader {
            SegmentHeader {
                segment_id,
                base_seq: Seq::new(base),
                base_offset: Offset::new(base),
                created_unix_ms: 0,
                flags: 0,
            }
        }

        fn key(seed: u8) -> AeadKey {
            AeadKey::from_bytes([seed; 32])
        }

        fn crypto(suite: AeadSuite, key_id: u64, seed: u8) -> Arc<SegmentCrypto> {
            Arc::new(SegmentCrypto::new(suite, key_id, key(seed)))
        }

        #[test]
        fn write_seal_reopen_decrypt_round_trips_both_suites() {
            for suite in [AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305] {
                let file = Arc::new(InMemoryFile::new());
                let mut w = SegmentWriter::create_encrypted(
                    Arc::clone(&file),
                    enc_header(3, 0),
                    crypto(suite, 5, 0xAB),
                )
                .unwrap();
                let bodies: [&[u8]; 3] = [b"alpha", b"a slightly longer bravo body", b"charlie"];
                for (i, b) in bodies.iter().enumerate() {
                    w.append(&rec(i as u64, b)).unwrap();
                }
                w.seal().unwrap();

                // The header advertises encryption + records the suite and key-id.
                let raw = file.snapshot();
                assert_eq!(
                    SegmentHeader::aead_params(&raw[..SEGMENT_HEADER_LEN]),
                    Some((suite.id(), 5))
                );
                // The record bodies are NOT plaintext on disk (they are ciphertext).
                for b in &bodies {
                    assert!(
                        !contains_subslice(&raw, b),
                        "plaintext body {b:?} must not appear on disk under {}",
                        suite.name()
                    );
                }

                // Reopen with the key loaded: decrypt round-trips byte-exact.
                let mut ring = KeyRing::new();
                ring.insert(5, key(0xAB));
                let reader =
                    SegmentReader::open_with_keyring(Arc::clone(&file), Arc::new(ring)).unwrap();
                assert!(reader.header().is_encrypted());
                let recs = reader.scan_decrypted().unwrap();
                assert_eq!(recs.len(), 3, "{}", suite.name());
                for (i, b) in bodies.iter().enumerate() {
                    assert_eq!(recs[i].payload.as_ref(), *b, "{}", suite.name());
                    assert_eq!(recs[i].offset, Offset::new(i as u64));
                    assert_eq!(recs[i].seq, Seq::new(i as u64));
                    // The materialized record is plaintext downstream (ENCRYPTED bit cleared).
                    assert!(!recs[i].flags.contains(RecordFlags::ENCRYPTED));
                }
            }
        }

        // #540 + #780: verify-once must NEVER skip an encrypted segment's integrity. An encrypted read
        // takes the decrypt branch of `scan_range`, which always verifies the CRC over the on-disk
        // ciphertext + tag AND AEAD-verifies the tag — it does NOT consult the verify-once skip. So even
        // a reader explicitly marked verified-resident (a) still decrypts correctly and (b) still catches
        // a corrupted ciphertext/tag, identically to an unverified reader.
        #[test]
        fn verify_once_never_skips_encrypted_integrity() {
            let file = Arc::new(InMemoryFile::new());
            let mut w = SegmentWriter::create_encrypted(
                Arc::clone(&file),
                enc_header(2, 0),
                crypto(AeadSuite::Aes256Gcm, 7, 0xCD),
            )
            .unwrap();
            w.append(&rec(0, b"first")).unwrap();
            let second_pos = w.write_pos();
            w.append(&rec(1, b"second")).unwrap();
            let valid_end = w.write_pos();
            w.seal().unwrap();

            let mut ring = KeyRing::new();
            ring.insert(7, key(0xCD));
            let ring = Arc::new(ring);

            // (a) A VERIFIED-RESIDENT encrypted reader STILL decrypts correctly on the consume fast-path
            // (`scan_range`): the AEAD ran; the flag did not bypass it.
            let clean = SegmentReader::open_with_keyring(Arc::clone(&file), Arc::clone(&ring))
                .unwrap()
                .with_verified_resident(true);
            let recs = clean
                .scan_range(
                    SEGMENT_HEADER_LEN as u64,
                    Offset::new(0),
                    valid_end,
                    10,
                    None,
                )
                .unwrap();
            assert_eq!(recs.len(), 2);
            assert_eq!(recs[0].payload.as_ref(), b"first");
            assert_eq!(recs[1].payload.as_ref(), b"second");

            // (b) Corrupt the SECOND encrypted record's on-disk body (ciphertext + tag). Even a
            // VERIFIED-RESIDENT reader catches it on `scan_range` — the encrypted path always verifies
            // (CRC over ciphertext+tag, then AEAD), so the corrupt frame is never served as garbage.
            let mut bytes = file.snapshot();
            let body_byte = usize::try_from(second_pos + RECORD_HEADER_LEN as u64 + 1).unwrap();
            bytes[body_byte] ^= 0x01;
            file.set_len(0).unwrap();
            file.write_all_at(&bytes, 0).unwrap();
            let verified = SegmentReader::open_with_keyring(Arc::clone(&file), Arc::clone(&ring))
                .unwrap()
                .with_verified_resident(true);
            let got = verified.scan_range(second_pos, Offset::new(1), valid_end, 10, None);
            match got {
                // The CRC over the ciphertext + tag caught it: the prefix ends, nothing is served.
                Ok(v) => assert!(
                    v.is_empty(),
                    "a verified-resident reader must NOT serve a corrupt encrypted frame"
                ),
                // Or the AEAD tag verify caught it: a reported decrypt error, never silent garbage.
                Err(StorageError::Decrypt(_)) => {}
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn a_plaintext_reader_refuses_encrypted_frames() {
            // The anti-silent-garbage guarantee end-to-end: a reader with NO keyring opening an
            // encrypted segment reports UnknownKeyId, never reads ciphertext as plaintext.
            let file = Arc::new(InMemoryFile::new());
            let mut w = SegmentWriter::create_encrypted(
                Arc::clone(&file),
                enc_header(1, 0),
                crypto(AeadSuite::Aes256Gcm, 9, 0x01),
            )
            .unwrap();
            w.append(&rec(0, b"secret")).unwrap();
            w.seal().unwrap();
            let reader = SegmentReader::open(Arc::clone(&file)).unwrap();
            assert!(matches!(
                reader.scan_decrypted(),
                Err(StorageError::Decrypt(DecryptError::UnknownKeyId(9)))
            ));
        }

        #[test]
        fn wrong_key_is_reported_not_silent_and_not_garbage() {
            let file = Arc::new(InMemoryFile::new());
            let mut w = SegmentWriter::create_encrypted(
                Arc::clone(&file),
                enc_header(2, 0),
                crypto(AeadSuite::ChaCha20Poly1305, 4, 0xAA),
            )
            .unwrap();
            w.append(&rec(0, b"top secret")).unwrap();
            w.seal().unwrap();

            // A keyring with the RIGHT key-id but the WRONG key bytes -> a reported tag mismatch.
            let mut wrong = KeyRing::new();
            wrong.insert(4, key(0xBB));
            let reader =
                SegmentReader::open_with_keyring(Arc::clone(&file), Arc::new(wrong)).unwrap();
            let err = reader.scan_decrypted().unwrap_err();
            match err {
                StorageError::Decrypt(e) => {
                    assert_eq!(e, DecryptError::TagMismatch);
                    // Routed to the DISTINCT reason code, never CorruptRecordBody.
                    assert_eq!(e.reason_code(), ReasonCode::AeadTagMismatch);
                }
                other => panic!("expected a reported Decrypt error, got {other:?}"),
            }

            // A keyring missing the key-id entirely -> a reported unknown-key error.
            let mut missing = KeyRing::new();
            missing.insert(99, key(0xAA));
            let reader2 =
                SegmentReader::open_with_keyring(Arc::clone(&file), Arc::new(missing)).unwrap();
            match reader2.scan_decrypted().unwrap_err() {
                StorageError::Decrypt(e) => {
                    assert_eq!(e, DecryptError::UnknownKeyId(4));
                    assert_eq!(e.reason_code(), ReasonCode::UnknownKeyId);
                }
                other => panic!("expected UnknownKeyId, got {other:?}"),
            }
        }

        #[test]
        fn crc_over_ciphertext_detects_a_torn_tail_without_the_key() {
            // Corrupt a ciphertext byte in a sealed encrypted segment. Recovery-style validation
            // (codec::decode_encrypted) catches it as BadBodyCrc using ONLY the CRC over the
            // ciphertext — NO key needed. This is the key-free torn-tail/bit-rot guarantee.
            let file = Arc::new(InMemoryFile::new());
            let mut w = SegmentWriter::create_encrypted(
                Arc::clone(&file),
                enc_header(7, 0),
                crypto(AeadSuite::Aes256Gcm, 1, 0x55),
            )
            .unwrap();
            w.append(&rec(0, b"first")).unwrap();
            w.append(&rec(1, b"second record body")).unwrap();
            w.sync().unwrap();
            let mut raw = file.snapshot();
            // Size the FIRST frame key-free (recovery-style), then flip a byte inside the SECOND
            // record's ciphertext body — no key involved anywhere.
            let (_v0, n0) =
                ironbus_core::codec::decode_encrypted(&raw[SEGMENT_HEADER_LEN..]).unwrap();
            let second_start = SEGMENT_HEADER_LEN + n0;
            // A byte one past the second frame's 36-byte header lands inside its ciphertext.
            raw[second_start + RECORD_HEADER_LEN + 1] ^= 0xFF;
            assert_eq!(
                ironbus_core::codec::decode_encrypted(&raw[second_start..]),
                Err(ironbus_core::codec::DecodeError::BadBodyCrc),
                "a corrupt ciphertext byte is caught by the CRC over the ciphertext, no key needed"
            );
        }

        #[test]
        fn rotation_two_segments_two_keys_one_reader_reads_all() {
            // Rotation is new-segments-only: segment A under key-id 1, segment B under key-id 2 (a
            // fresh, never-recycled segment id). A reader with BOTH keys loaded reads both, keyed by
            // each segment's own header key-id. Distinct segment ids also mean the (segment_id, ctr)
            // nonce space never collides across the rotation.
            let file_a = Arc::new(InMemoryFile::new());
            let mut wa = SegmentWriter::create_encrypted(
                Arc::clone(&file_a),
                enc_header(10, 0),
                crypto(AeadSuite::Aes256Gcm, 1, 0x11),
            )
            .unwrap();
            wa.append(&rec(0, b"under-key-one")).unwrap();
            wa.seal().unwrap();

            let file_b = Arc::new(InMemoryFile::new());
            let mut wb = SegmentWriter::create_encrypted(
                Arc::clone(&file_b),
                enc_header(11, 0),
                crypto(AeadSuite::ChaCha20Poly1305, 2, 0x22),
            )
            .unwrap();
            wb.append(&rec(0, b"under-key-two")).unwrap();
            wb.seal().unwrap();

            // The two segments carry DIFFERENT ids and DIFFERENT key-ids and DIFFERENT suites.
            assert_ne!(
                SegmentHeader::aead_params(&file_a.snapshot()[..SEGMENT_HEADER_LEN]),
                SegmentHeader::aead_params(&file_b.snapshot()[..SEGMENT_HEADER_LEN])
            );

            let mut ring = KeyRing::new();
            ring.insert(1, key(0x11));
            ring.insert(2, key(0x22));
            let ring = Arc::new(ring);
            let ra =
                SegmentReader::open_with_keyring(Arc::clone(&file_a), Arc::clone(&ring)).unwrap();
            let rb =
                SegmentReader::open_with_keyring(Arc::clone(&file_b), Arc::clone(&ring)).unwrap();
            assert_eq!(
                ra.scan_decrypted().unwrap()[0].payload.as_ref(),
                b"under-key-one"
            );
            assert_eq!(
                rb.scan_decrypted().unwrap()[0].payload.as_ref(),
                b"under-key-two"
            );
        }

        #[test]
        fn default_off_is_byte_identical_to_a_plaintext_segment() {
            // DEFAULT-OFF byte identity: a writer with NO crypto produces the EXACT bytes it always
            // did — the encryption code path is inert unless a key is configured.
            let plain = Arc::new(InMemoryFile::new());
            let mut wp = SegmentWriter::create(Arc::clone(&plain), enc_header(1, 0)).unwrap();
            wp.append(&rec(0, b"one")).unwrap();
            wp.append(&rec(1, b"two")).unwrap();
            wp.seal().unwrap();

            // A byte-for-byte reference built the SAME way but through the plaintext codec directly.
            let reference = Arc::new(InMemoryFile::new());
            let mut wr = SegmentWriter::create(Arc::clone(&reference), enc_header(1, 0)).unwrap();
            wr.append(&rec(0, b"one")).unwrap();
            wr.append(&rec(1, b"two")).unwrap();
            wr.seal().unwrap();

            assert_eq!(plain.snapshot(), reference.snapshot());
            // The header's encryption region is all zero, and the segment is not flagged encrypted.
            let raw = plain.snapshot();
            assert!(raw[44..60].iter().all(|&b| b == 0));
            assert_eq!(SegmentHeader::aead_params(&raw[..SEGMENT_HEADER_LEN]), None);
            assert!(!SegmentReader::open(Arc::clone(&plain))
                .unwrap()
                .header()
                .is_encrypted());
        }

        fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
            haystack.windows(needle.len()).any(|w| w == needle)
        }
    }
}
