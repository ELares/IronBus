// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cross-replica divergence DETECTION + self-heal: the recovery differentiator (V2-C4, #611/#612/#613).
//!
//! This is where IronBus's single-node I3 contract (recovery is BOUNDED, REPORTED, and FAIL-CLOSED;
//! `docs/RECOVERY.md`) becomes a CLUSTER-WIDE weapon. Where C2 (#590/#599) replicates the log and
//! truncates a follower's divergent epoch tail on a leader CHANGE, this module is the complementary
//! mechanism: it catches SILENT corruption and SILENT drift between replicas that share an epoch and
//! should be byte-identical but are not — the two NATS recovery failures that have no fix today:
//!
//! * **Silent replica drift that never self-heals** ([nats-server #5576]): NATS computes the divergence
//!   signal (`errFirstSequenceMismatch`) but never ACTS on it, so "the actual stream data \[can\] be
//!   completely out of sync" and a replica returns "with a stream containing no data at all while
//!   reporting it as current". IronBus acts on the signal.
//! * **Minority corruption that PERMANENTLY DELETES the stream** ([nats-server #7556]): a single-bit
//!   error on a MINORITY "can cause Jetstream to completely delete all data" and "the cluster somehow
//!   never recovered quorum". IronBus does the opposite by construction: a minority's corrupt segment
//!   is QUARANTINED (copy-then-drop, never deleted) and re-synced from a clean majority, the partition
//!   stays available, and a minority fault can neither delete data nor lose quorum.
//!
//! ## The primitive already exists — no new on-disk format
//!
//! Every sealed IronBus segment already carries a FOOTER `(segment_id, last_seq, record_count)` plus a
//! footer CRC ([`ironbus_core::segment::SegmentFooter`]), and every record frame already carries a
//! header CRC32C + body CRC32C (+ xxh3-64 for large bodies). C4 only READS those durable bytes — it
//! adds NO new on-disk format. A replica summarizes each of its sealed segments as a cheap
//! [`SegmentFingerprint`] — the footer triple, the footer CRC, and a `content_hash` (xxh3-64 over the
//! segment's verbatim on-disk record bytes). Two replicas in the same lineage MUST agree on the
//! fingerprint of every committed segment; a mismatch is a DETECTED divergence.
//!
//! ## What C4 adds (this module) — one log / partition
//!
//! 1. **DETECTION (C4-I1, #611).** [`fingerprint_log`] computes a replica's per-segment fingerprints
//!    from its own durable bytes; [`SegmentFingerprints`] bundles them with the replica's committed
//!    high-watermark. A replica advertises them over the peer transport (the bounded, validated
//!    [`FrameType::SegmentFingerprints`] wire tag 39 codec below), and [`compare_fingerprints`]
//!    compares its own against the quorum/leader's in O(segments), emitting a typed
//!    [`DivergenceReport`] of [`DivergenceDetected`] events (which segment, and WHICH field —
//!    `footer_crc` / `last_seq` / `record_count` / `content_hash` — diverged). This is the signal NATS
//!    COMPUTES but never ACTS ON ([#5576]). A clean cluster detects NOTHING (no false positive).
//! 2. **AUTO-RESYNC (C4-I2, #612, #798).** [`plan_resync`] turns a [`DivergenceReport`] into a bounded,
//!    reported [`ResyncPlan`]: truncate to the start of the FIRST divergent segment, then re-fetch the
//!    clean CRC-validated bytes from the quorum (the existing C2 [`Follower`] fetch path), converging
//!    byte-identical. The divergent suffix — a corrupt or drifted COMMITTED segment INCLUDED — is
//!    dropped and refetched, NOT clamped above the committed high-watermark (#798): a resync always has
//!    a clean quorum leader to restore the dropped committed bytes, so dropping-and-refetching is
//!    non-lossy and is the only way to repair committed-prefix corruption; an over-clamp instead left
//!    the corrupt committed bytes live. Committed data is still never silently lost — [`execute_resync`]
//!    REFUSES a leader whose high-watermark is below the committed HW (it cannot restore what the
//!    truncate drops) and re-fingerprints against the leader, FAILING CLOSED unless the replica actually
//!    converged. The plan is bounded by the I3 caps ([`ResyncBounds`]); over the cap it FAILS CLOSED
//!    ([`ResyncError`]) rather than silently serving a divergent log. [`execute_resync`] runs the plan
//!    and returns a typed [`ResyncReport`].
//! 3. **QUARANTINE-REPAIR, NEVER DELETE (C4-I3, #613).** When a divergent segment on a MINORITY is
//!    locally CORRUPT (its own footer or a record CRC fails — distinct from a clean drift), the
//!    repair COPY-THEN-DROPS the corrupt segment into the existing capped forensic
//!    [`QuarantineStore`](ironbus_storage::quarantine::QuarantineStore) and then re-syncs from a clean
//!    majority. The partition STAYS AVAILABLE off the clean majority; the corrupt bytes are PRESERVED
//!    in quarantine; nothing is ever deleted. This generalizes IronBus's existing SINGLE-NODE
//!    quarantine (a corrupt segment captured on local recovery) to the CROSS-REPLICA case.
//!
//! ## Preserved guarantees
//!
//! * **Single-node is byte-for-byte unaffected.** Like every other C1-C3 issue this is a TESTABLE
//!   LAYER with an in-process harness; with no cluster config a broker never advertises fingerprints,
//!   never compares, and never resyncs, so the n=1 binary and its on-disk layout are unchanged. The
//!   single-node quarantine/recovery path is untouched — C4 only ADDS the cross-replica entry point.
//! * **Committed data is never silently LOST.** The C2-I4 [`EpochAwareFollower::reconcile_with_leader`]
//!   reconcile path still clamps its truncation at or above the committed high-watermark (#691). The C4
//!   AUTO-RESYNC path deliberately does NOT (#798): it drops and re-fetches the divergent COMMITTED
//!   region from the clean quorum leader (the only way to repair committed-prefix corruption), but
//!   never loses it — [`execute_resync`] refuses a leader behind the committed HW and fails closed
//!   unless the replica re-fingerprints byte-identical to the leader. A drop with no clean restore is
//!   never reported as a heal.
//! * **Recovery stays a pure function of durable bytes.** A fingerprint is computed only from the
//!   on-disk frames; the compare is a pure function of two fingerprint sets; the resync plan is a pure
//!   function of the report. Side effects (truncate, fetch, quarantine) are explicit and bounded.
//! * **The peer codec is bounded + validated.** An advertised fingerprint set is decoded under a hard
//!   count cap ([`MAX_FINGERPRINTS`]); a malformed / over-long / oversized advertisement is rejected
//!   with a typed error, never trusted — untrusted peer bytes, exactly as the C1/C2 wires treat them.
//!
//! ## Deferred (flagged, NOT in this module)
//!
//! * **Leader-completeness election restriction** (C4-I4, #614): a corrupt/stale replica must be
//!   INELIGIBLE to win a partition leadership. That is the ELECTION layer; this module is the
//!   silent-corruption/drift DETECTION + REPAIR mechanism. Complementary, separate issue.
//! * **CI1-CI4 cluster recovery invariants doc + checkers** (C4-I5, #615): the ratified, pure-function
//!   cluster contract mirroring `invariants.rs`. Separate issue.
//! * **`serve`-path wiring**: a real cluster dialer advertising fingerprints on a timer and driving the
//!   resync is the follow-up, exactly as the C1/C2/C3 layers deferred their `serve` wiring.
//!
//! [nats-server #5576]: https://github.com/nats-io/nats-server/issues/5576
//! [nats-server #7556]: https://github.com/nats-io/nats-server/issues/7556
//! [#5576]: https://github.com/nats-io/nats-server/issues/5576
//! [#7556]: https://github.com/nats-io/nats-server/issues/7556

use ironbus_core::clock::Clock;
use ironbus_core::segment::{SegmentError, SegmentFooter};
use ironbus_core::types::Offset;
use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType,
};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::io::RandomAccessFile;
use ironbus_storage::log::Log;
use ironbus_storage::loss::{LossEvent, ReasonCode};
use ironbus_storage::quarantine::QuarantineStore;
use ironbus_storage::segment::StorageError;

use crate::cluster::replication::{Follower, ReplicationError, ReplicationLeader};

/// The hard maximum number of per-segment fingerprints a single advertisement may carry. Bounds the
/// untrusted peer bytes the decode path will buffer and trust: a replica with more sealed segments
/// than this advertises in batches (the cap is generous head-room — a 64 MiB-segment log at this many
/// segments is petabytes — while keeping one advertisement small and the decode allocation bounded).
pub const MAX_FINGERPRINTS: u32 = 1 << 20;

/// The fixed little-endian byte length of one encoded [`SegmentFingerprint`]:
/// `segment_id: u64` + `last_seq: u64` + `record_count: u32` + `footer_crc: u32` + `content_hash: u64`.
const FINGERPRINT_LEN: usize = 8 + 8 + 4 + 4 + 8;

/// The fixed little-endian byte length of a [`SegmentFingerprints`] HEADER (the fingerprints follow):
/// `committed_hw: u64` + `count: u32`.
const FINGERPRINTS_HEADER_LEN: usize = 8 + 4;

/// Read a little-endian `u64` from `b` at byte offset `at`. The caller length-checks `b` first, so
/// this is panic-free (a fixed 8-byte window of an already-bounds-checked slice).
#[inline]
fn read_u64_le(b: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(buf)
}

/// Read a little-endian `u32` from `b` at byte offset `at`. The caller length-checks `b` first.
#[inline]
fn read_u32_le(b: &[u8], at: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(buf)
}

/// A cheap, O(1)-to-compare SUMMARY of one sealed segment — the per-segment fingerprint two replicas
/// cross-check (#611). It is computed ENTIRELY from the segment's durable bytes (the footer the writer
/// already wrote, plus a hash of the verbatim on-disk record frames), so it adds NO new on-disk
/// format and a fingerprint is a pure function of what is on disk.
///
/// The four discriminating fields catch every class of divergence:
/// * `record_count` / `last_seq` — the footer triple: a replica that is SHORT or LONG, or whose last
///   record has a different sequence, diverges here (the cheap, O(1) drift signal).
/// * `footer_crc` — the segment writer's own footer checksum: a corrupt footer diverges here.
/// * `content_hash` — an xxh3-64 over the segment's verbatim on-disk record-frame bytes: two segments
///   with the SAME footer triple but DIFFERENT record bytes (silent body corruption / a substituted
///   record at the same offset — the drift the footer count alone cannot see) diverge here.
///
/// Equality is the WHOLE fingerprint: two fingerprints are equal iff all four fields match, which (the
/// content hash being a strong 64-bit hash over the exact bytes) holds iff the segments are
/// byte-identical in practice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SegmentFingerprint {
    /// The segment id (from the footer/header). The fingerprints of two replicas are matched by id.
    pub segment_id: u64,
    /// The sequence number of the last record in the sealed segment (footer `last_seq`).
    pub last_seq: u64,
    /// The number of records in the sealed segment (footer `record_count`).
    pub record_count: u32,
    /// The segment's own footer CRC32C (over the footer's covered range). A corrupt footer changes it.
    pub footer_crc: u32,
    /// An xxh3-64 over the segment's verbatim on-disk record-frame bytes — catches a body-corrupt or
    /// substituted record that leaves the footer triple unchanged (the silent-drift class).
    pub content_hash: u64,
}

impl SegmentFingerprint {
    /// Encodes this fingerprint to its fixed-layout little-endian bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; FINGERPRINT_LEN] {
        let mut out = [0u8; FINGERPRINT_LEN];
        out[0..8].copy_from_slice(&self.segment_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.last_seq.to_le_bytes());
        out[16..20].copy_from_slice(&self.record_count.to_le_bytes());
        out[20..24].copy_from_slice(&self.footer_crc.to_le_bytes());
        out[24..32].copy_from_slice(&self.content_hash.to_le_bytes());
        out
    }

    /// Decodes one fingerprint from exactly [`FINGERPRINT_LEN`] bytes.
    fn decode(b: &[u8]) -> SegmentFingerprint {
        // The caller has already bounds-checked `b.len() >= FINGERPRINT_LEN`.
        SegmentFingerprint {
            segment_id: read_u64_le(b, 0),
            last_seq: read_u64_le(b, 8),
            record_count: read_u32_le(b, 16),
            footer_crc: read_u32_le(b, 20),
            content_hash: read_u64_le(b, 24),
        }
    }
}

/// A replica's advertised per-segment fingerprints for one partition log, plus its committed
/// high-watermark (#691) — everything a peer needs to DETECT divergence against this replica without
/// shipping any record bytes. The fingerprints are in ascending `segment_id` order (the order
/// [`fingerprint_log`] produces them); `committed_hw` lets the comparer clamp any resync truncation at
/// or above it, so committed data is never the thing that gets dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentFingerprints {
    /// The replica's committed high-watermark (its quorum-committed / flushed offset). A divergence in
    /// a segment fully below this is committed-data corruption the repair must heal from the quorum
    /// WITHOUT dropping committed data (the truncation is clamped at or above this).
    pub committed_hw: u64,
    /// The per-segment fingerprints, ascending by `segment_id`.
    pub fingerprints: Vec<SegmentFingerprint>,
}

impl SegmentFingerprints {
    /// Encodes the advertisement to its `[committed_hw][count][fingerprint...]` body bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let count = u32::try_from(self.fingerprints.len()).unwrap_or(u32::MAX);
        let mut out =
            Vec::with_capacity(FINGERPRINTS_HEADER_LEN + self.fingerprints.len() * FINGERPRINT_LEN);
        out.extend_from_slice(&self.committed_hw.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        for fp in &self.fingerprints {
            out.extend_from_slice(&fp.encode());
        }
        out
    }

    /// Decodes an advertisement from its body bytes, BOUNDING the carried count against
    /// [`MAX_FINGERPRINTS`] before allocating — an oversized or malformed advertisement (a hostile or
    /// buggy peer) is rejected with a typed error, never buffered or trusted.
    ///
    /// # Errors
    /// - [`DivergenceError::MalformedAdvertisement`] if `body` is too short for the header, the
    ///   declared count exceeds [`MAX_FINGERPRINTS`], or the body length does not match the count.
    pub fn decode(body: &[u8]) -> Result<SegmentFingerprints, DivergenceError> {
        if body.len() < FINGERPRINTS_HEADER_LEN {
            return Err(DivergenceError::MalformedAdvertisement { len: body.len() });
        }
        let committed_hw = read_u64_le(body, 0);
        let count = read_u32_le(body, 8);
        if count > MAX_FINGERPRINTS {
            return Err(DivergenceError::TooManyFingerprints { count });
        }
        let count = count as usize;
        let want = FINGERPRINTS_HEADER_LEN + count * FINGERPRINT_LEN;
        if body.len() != want {
            return Err(DivergenceError::MalformedAdvertisement { len: body.len() });
        }
        let mut fingerprints = Vec::with_capacity(count);
        let mut at = FINGERPRINTS_HEADER_LEN;
        for _ in 0..count {
            fingerprints.push(SegmentFingerprint::decode(&body[at..at + FINGERPRINT_LEN]));
            at += FINGERPRINT_LEN;
        }
        Ok(SegmentFingerprints {
            committed_hw,
            fingerprints,
        })
    }

    /// Frames this advertisement under the bounded `[len][type=SegmentFingerprints][body]` envelope
    /// (wire tag 39) — the same wire discipline the C1/C2 peer transports use.
    ///
    /// # Errors
    /// [`DivergenceError::Frame`] if the body would exceed the absolute frame cap.
    pub fn to_frame(&self) -> Result<Vec<u8>, DivergenceError> {
        let mut out = Vec::new();
        encode_frame(FrameType::SegmentFingerprints, &self.encode(), &mut out)?;
        Ok(out)
    }

    /// Decodes ONE framed advertisement off the front of `buf`, returning the decoded
    /// [`SegmentFingerprints`] and the bytes consumed, or `None` if `buf` does not yet hold a complete
    /// frame. The frame length is bounded BEFORE the body is read; an unexpected frame type is a typed
    /// error (a peer must not mix message types on this channel).
    ///
    /// # Errors
    /// - [`DivergenceError::Frame`] on a malformed / oversized envelope.
    /// - [`DivergenceError::UnexpectedFrameType`] if the framed type is not
    ///   [`FrameType::SegmentFingerprints`].
    /// - The [`SegmentFingerprints::decode`] errors on a malformed body.
    pub fn decode_frame(
        buf: &[u8],
    ) -> Result<Option<(SegmentFingerprints, usize)>, DivergenceError> {
        match decode_frame_with_cap(buf, ironbus_proto::frame::MAX_FRAME_LEN)? {
            FrameDecode::Incomplete { .. } => Ok(None),
            FrameDecode::Frame {
                type_tag,
                body,
                consumed,
            } => {
                if FrameType::from_u8(type_tag) != Some(FrameType::SegmentFingerprints) {
                    return Err(DivergenceError::UnexpectedFrameType { tag: type_tag });
                }
                let adv = SegmentFingerprints::decode(body)?;
                Ok(Some((adv, consumed)))
            }
        }
    }
}

/// Which field of a segment fingerprint disagreed between two replicas — the LOCALIZED reason a
/// segment is divergent, surfaced in the [`DivergenceDetected`] event so an operator (and the repair
/// planner) knows whether this is length drift, footer corruption, or silent body corruption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DivergenceField {
    /// The footer `record_count` differs: one replica is short or long for this segment.
    RecordCount,
    /// The footer `last_seq` differs: the last record's sequence disagrees (a substituted tail).
    LastSeq,
    /// The footer CRC differs while the triple matched: the footer itself is corrupt on one side.
    FooterCrc,
    /// Only the content hash differs (the footer triple AND footer CRC matched): silent record-body
    /// corruption or a substituted record at the same offset — the drift the footer cannot see.
    ContentHash,
    /// One replica HAS this segment and the other does not (a missing / extra committed segment).
    MissingSegment,
}

impl DivergenceField {
    /// A stable lower-snake-case label for a metric series / log field.
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            DivergenceField::RecordCount => "record_count",
            DivergenceField::LastSeq => "last_seq",
            DivergenceField::FooterCrc => "footer_crc",
            DivergenceField::ContentHash => "content_hash",
            DivergenceField::MissingSegment => "missing_segment",
        }
    }
}

/// One DETECTED cross-replica divergence: a segment whose fingerprint disagrees with the quorum's,
/// and WHICH field disagreed. This is the typed signal NATS computes but never acts on (#5576) — the
/// repair planner consumes a set of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DivergenceDetected {
    /// The id of the divergent segment.
    pub segment_id: u64,
    /// The first field that disagreed (checked `record_count` → `last_seq` → `footer_crc` →
    /// `content_hash`, so the CHEAPEST/most-structural reason is reported first).
    pub field: DivergenceField,
    /// This replica's fingerprint for the segment, if it holds it (`None` when the quorum has a
    /// committed segment this replica is missing).
    pub local: Option<SegmentFingerprint>,
    /// The quorum's fingerprint for the segment, if the quorum holds it (`None` when this replica has
    /// an extra segment the quorum does not).
    pub quorum: Option<SegmentFingerprint>,
}

/// The typed, REPORTED outcome of comparing one replica's fingerprints against the quorum's (#611):
/// the set of detected divergences (empty = byte-identical = NO false positive) and the lowest
/// divergent segment id (the first segment the resync must heal from). NEVER a silent verdict.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DivergenceReport {
    /// The detected divergences, ascending by `segment_id`. Empty when this replica AGREES with the
    /// quorum on every committed segment (a clean cluster — no false positive).
    pub divergences: Vec<DivergenceDetected>,
    /// The quorum's committed high-watermark, carried through for observability and the resync bound
    /// (how far the re-fetch must reach). It is NOT used to clamp the truncation: #798 drops and
    /// re-fetches the whole divergent region, committed prefix included, because the clean quorum leader
    /// restores it and [`execute_resync`] verifies convergence.
    pub quorum_committed_hw: u64,
}

impl DivergenceReport {
    /// `true` if no divergence was detected — the replica is byte-identical to the quorum on every
    /// committed segment. The no-false-positive property: a clean cluster reports this.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.divergences.is_empty()
    }

    /// The id of the LOWEST divergent segment (the first segment the resync must re-fetch from), or
    /// `None` when clean.
    #[must_use]
    pub fn first_divergent_segment(&self) -> Option<u64> {
        self.divergences.iter().map(|d| d.segment_id).min()
    }
}

/// An error in the C4 divergence-detection / self-heal path. Like [`ReplicationError`] it wraps a
/// non-`Clone` [`StorageError`], so it derives only `Debug` (the layer never compares errors for
/// equality — callers `match` on the variant); use [`matches!`] / a `match` to inspect it.
#[derive(Debug)]
#[non_exhaustive]
pub enum DivergenceError {
    /// An advertised fingerprint set's body was too short or its length did not match its declared
    /// count — a malformed / truncated / over-long advertisement, rejected (never guessed at).
    MalformedAdvertisement {
        /// The body length that was seen.
        len: usize,
    },
    /// An advertisement declared more fingerprints than [`MAX_FINGERPRINTS`] — an oversized or hostile
    /// advertisement, rejected before any allocation.
    TooManyFingerprints {
        /// The declared count.
        count: u32,
    },
    /// A framed peer message carried an unexpected frame type (not [`FrameType::SegmentFingerprints`]).
    UnexpectedFrameType {
        /// The raw type tag seen.
        tag: u8,
    },
    /// A reported resync would exceed the I3 bounds (`ResyncBounds`): the divergence is too large to
    /// auto-repair, so the replica FAILS CLOSED rather than silently serving a divergent log.
    ResyncTooLarge {
        /// The records the resync would have to re-fetch.
        records: u64,
        /// The records cap that was exceeded.
        cap: u64,
    },
    /// Reading a replica's own durable bytes to compute a fingerprint failed (an IO / storage error).
    Storage(StorageError),
    /// Framing/decoding an advertisement envelope failed.
    Frame(FrameError),
}

impl core::fmt::Display for DivergenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DivergenceError::MalformedAdvertisement { len } => {
                write!(f, "malformed fingerprint advertisement body of {len} bytes")
            }
            DivergenceError::TooManyFingerprints { count } => {
                write!(
                    f,
                    "advertisement declared {count} fingerprints, over the cap"
                )
            }
            DivergenceError::UnexpectedFrameType { tag } => {
                write!(
                    f,
                    "unexpected peer frame type {tag} on the fingerprint channel"
                )
            }
            DivergenceError::ResyncTooLarge { records, cap } => {
                write!(f, "resync of {records} records exceeds the bound of {cap}")
            }
            DivergenceError::Storage(e) => write!(f, "storage error computing a fingerprint: {e}"),
            DivergenceError::Frame(e) => write!(f, "fingerprint frame error: {e}"),
        }
    }
}

impl std::error::Error for DivergenceError {}

impl From<StorageError> for DivergenceError {
    fn from(e: StorageError) -> Self {
        DivergenceError::Storage(e)
    }
}

impl From<FrameError> for DivergenceError {
    fn from(e: FrameError) -> Self {
        DivergenceError::Frame(e)
    }
}

/// Computes a replica's per-segment fingerprints for one partition log, ENTIRELY from its durable
/// bytes (#611). For each SEALED segment below the log's flushed head it reads the segment's verbatim
/// on-disk record-frame bytes (via the same zero-copy raw read the C2 leader serves with), hashes them
/// (xxh3-64) for the `content_hash`, reads the footer for the `(last_seq, record_count, footer_crc)`,
/// and bundles them with the replica's committed high-watermark.
///
/// Only SEALED segments are fingerprinted: the active (un-sealed) segment has no footer yet and is
/// above the committed frontier, so it is not part of the committed prefix two replicas must agree on.
/// The fingerprints are ascending by `segment_id`.
///
/// This is a READ-ONLY pure function of the durable bytes — it never mutates the log and never trusts
/// anything but what is on disk. The single-node binary never calls it (no cluster ⇒ no advertisement).
///
/// # Errors
/// [`DivergenceError::Storage`] if reading a segment's bytes or footer fails.
pub fn fingerprint_log<F: Filesystem, C: Clock>(
    log: &Log<F, C>,
) -> Result<SegmentFingerprints, DivergenceError> {
    let committed_hw = log.flushed_offset().get();
    let fs = log.filesystem();
    // Enumerate the segment FILES in the data directory (flat; the quarantine subdir is invisible to a
    // flat list). Parse each name to its segment id, keep only those whose whole record range is below
    // the committed head (a sealed, committed segment), and fingerprint them ascending by id.
    let mut ids: Vec<(u64, String)> = match fs.list() {
        Ok(names) => names
            .into_iter()
            .filter_map(|name| segment_id_of(&name).map(|id| (id, name)))
            .collect(),
        Err(e) => return Err(DivergenceError::Storage(StorageError::Io(e))),
    };
    ids.sort_by_key(|(id, _)| *id);

    let mut fingerprints = Vec::with_capacity(ids.len());
    for (id, name) in ids {
        // The active segment is the only one without a footer; skip it (it is above the committed
        // prefix). A segment that is too short to hold a footer (the active one, freshly rolled) is
        // skipped the same way.
        let file = fs
            .open(&name)
            .map_err(|e| DivergenceError::Storage(StorageError::Io(e)))?;
        let len = file
            .len()
            .map_err(|e| DivergenceError::Storage(StorageError::Io(e)))?;
        let Some(fp) = read_segment_fingerprint(&file, id, len)? else {
            continue;
        };
        fingerprints.push(fp);
    }
    Ok(SegmentFingerprints {
        committed_hw,
        fingerprints,
    })
}

/// Parses a segment file's id from its name, or `None` for any non-segment file (e.g. a cursor
/// checkpoint, a subdir entry). Mirrors [`segment_file_name`]'s `seg-<016x>.log` shape.
fn segment_id_of(name: &str) -> Option<u64> {
    let body = name.strip_prefix("seg-")?.strip_suffix(".log")?;
    if body.len() != 16 || !body.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u64::from_str_radix(body, 16).ok()
}

/// The segment-footer length: a sealed segment ends with this many bytes of footer.
const FOOTER_LEN: usize = ironbus_core::format::SEGMENT_FOOTER_LEN;
/// The segment-header length: the record frames begin after this many bytes.
const HEADER_LEN: usize = ironbus_core::format::SEGMENT_HEADER_LEN;

/// Reads one SEALED segment file's fingerprint from its bytes: the footer triple + footer CRC (from
/// the last [`FOOTER_LEN`] bytes), and an xxh3-64 over the verbatim record-frame bytes (the bytes
/// between the [`HEADER_LEN`]-byte header and the footer). Returns `None` if the file is too short to
/// hold a header+footer (an active/unsealed or empty segment), or if the footer does not decode (an
/// unsealed segment whose trailing bytes are not a footer).
///
/// The content hash is over the segment's record bytes EXACTLY as written, so two replicas that wrote
/// the same records produce the same hash, and a single flipped byte anywhere in the record region
/// changes it — the silent-corruption signal.
fn read_segment_fingerprint<R: RandomAccessFile>(
    file: &R,
    segment_id: u64,
    len: u64,
) -> Result<Option<SegmentFingerprint>, DivergenceError> {
    let min = (HEADER_LEN + FOOTER_LEN) as u64;
    if len < min {
        return Ok(None);
    }
    let len_usize = usize::try_from(len).map_err(|_| {
        DivergenceError::Storage(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "segment length does not fit usize",
        )))
    })?;
    // Read the whole segment file once: the footer (tail) and the record region (between header and
    // footer). A sealed committed segment is bounded by the segment-size cap, so this is one bounded read.
    let mut buf = vec![0u8; len_usize];
    file.read_exact_at(&mut buf, 0)
        .map_err(|e| DivergenceError::Storage(StorageError::Io(e)))?;
    let footer_start = len_usize - FOOTER_LEN;
    let footer = match SegmentFooter::decode(&buf[footer_start..]) {
        Ok(f) => f,
        // The trailing bytes are not a valid footer: this is an active/unsealed segment (or a torn
        // tail). It is not part of the committed prefix two replicas cross-check, so skip it here.
        // (A footer that is CORRUPT but still the right shape is caught by the footer-CRC field
        // mismatch in the compare; a footer that does not decode at all is simply not yet sealed.)
        Err(SegmentError::BadCrc) => {
            // A footer with the right magic/version but a bad CRC: the footer IS corrupt. Fingerprint
            // it with a deliberately-poisoned footer_crc so the cross-replica compare flags it (rather
            // than silently dropping a corrupt-but-sealed segment from the comparison).
            return Ok(Some(corrupt_footer_fingerprint(
                segment_id,
                &buf,
                footer_start,
            )));
        }
        Err(_) => return Ok(None),
    };
    let footer_crc = footer_crc_of(&buf[footer_start..]);
    let content_hash = xxhash_rust::xxh3::xxh3_64(&buf[HEADER_LEN..footer_start]);
    Ok(Some(SegmentFingerprint {
        segment_id,
        last_seq: footer.last_seq.get(),
        record_count: footer.record_count,
        footer_crc,
        content_hash,
    }))
}

/// The footer CRC32C stored in the footer's last 4 bytes. The footer is fixed-length; the CRC is its
/// final little-endian `u32` (matching [`SegmentFooter::encode`]'s layout).
fn footer_crc_of(footer_bytes: &[u8]) -> u32 {
    // The footer CRC is the last 4 bytes of the FOOTER_LEN-byte footer.
    read_u32_le(footer_bytes, FOOTER_LEN - 4)
}

/// Builds a fingerprint for a segment whose footer has the right shape but a BAD CRC (a corrupt
/// footer): the footer triple is unreadable, so it is left at sentinel zeros and the stored (corrupt)
/// footer CRC + the content hash are carried, so the cross-replica compare detects the divergence
/// instead of silently dropping the segment.
fn corrupt_footer_fingerprint(
    segment_id: u64,
    buf: &[u8],
    footer_start: usize,
) -> SegmentFingerprint {
    let content_hash = xxhash_rust::xxh3::xxh3_64(&buf[HEADER_LEN..footer_start]);
    SegmentFingerprint {
        segment_id,
        last_seq: 0,
        record_count: 0,
        footer_crc: footer_crc_of(&buf[footer_start..]),
        content_hash,
    }
}

/// Compares THIS replica's fingerprints against the QUORUM's (#611), producing a typed
/// [`DivergenceReport`]. O(segments): walk the two ascending-by-id fingerprint lists in lock-step, and
/// for each matched segment id check `record_count` → `last_seq` → `footer_crc` → `content_hash` in
/// that order (cheapest/most-structural first), recording the FIRST field that disagrees. A segment
/// only one side holds (below both committed heads) is a `MissingSegment` divergence.
///
/// A clean cluster (identical fingerprints) yields an EMPTY report — the no-false-positive property:
/// agreement is never reported as divergence.
#[must_use]
pub fn compare_fingerprints(
    local: &SegmentFingerprints,
    quorum: &SegmentFingerprints,
) -> DivergenceReport {
    let mut divergences = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    let la = &local.fingerprints;
    let qa = &quorum.fingerprints;
    while i < la.len() || j < qa.len() {
        match (la.get(i), qa.get(j)) {
            (Some(l), Some(q)) if l.segment_id == q.segment_id => {
                if let Some(field) = first_divergent_field(l, q) {
                    divergences.push(DivergenceDetected {
                        segment_id: l.segment_id,
                        field,
                        local: Some(*l),
                        quorum: Some(*q),
                    });
                }
                i += 1;
                j += 1;
            }
            (Some(l), Some(q)) if l.segment_id < q.segment_id => {
                // This replica has a committed segment whose id the quorum's set skips: an EXTRA
                // local segment the quorum does not hold. Flag it only when the quorum has committed
                // data at all (an empty cluster is never a divergence — the no-false-positive rule).
                if is_committed_mismatch(quorum.committed_hw) {
                    divergences.push(DivergenceDetected {
                        segment_id: l.segment_id,
                        field: DivergenceField::MissingSegment,
                        local: Some(*l),
                        quorum: None,
                    });
                }
                i += 1;
            }
            (Some(_l), Some(q)) => {
                // q.segment_id < l.segment_id: the quorum has a committed segment this replica is
                // MISSING. That is a divergence to heal (re-fetch the missing segment).
                divergences.push(DivergenceDetected {
                    segment_id: q.segment_id,
                    field: DivergenceField::MissingSegment,
                    local: None,
                    quorum: Some(*q),
                });
                j += 1;
            }
            (Some(l), None) => {
                // Trailing local-only segments: extra segments above the quorum's set. Only a committed
                // quorum (hw > 0) makes an extra local segment a divergence; otherwise it is un-replicated
                // local data above the quorum's frontier, not drift.
                if is_committed_mismatch(quorum.committed_hw) {
                    divergences.push(DivergenceDetected {
                        segment_id: l.segment_id,
                        field: DivergenceField::MissingSegment,
                        local: Some(*l),
                        quorum: None,
                    });
                }
                i += 1;
            }
            (None, Some(q)) => {
                // Trailing quorum-only segments: committed segments this replica is missing.
                divergences.push(DivergenceDetected {
                    segment_id: q.segment_id,
                    field: DivergenceField::MissingSegment,
                    local: None,
                    quorum: Some(*q),
                });
                j += 1;
            }
            (None, None) => break,
        }
    }
    DivergenceReport {
        divergences,
        quorum_committed_hw: quorum.committed_hw,
    }
}

/// The first field of two same-id fingerprints that disagrees, in cheapest-first order, or `None` if
/// they are identical. Equal fingerprints (a clean segment) return `None` — agreement is never a
/// divergence (the no-false-positive core).
fn first_divergent_field(
    l: &SegmentFingerprint,
    q: &SegmentFingerprint,
) -> Option<DivergenceField> {
    if l.record_count != q.record_count {
        Some(DivergenceField::RecordCount)
    } else if l.last_seq != q.last_seq {
        Some(DivergenceField::LastSeq)
    } else if l.footer_crc != q.footer_crc {
        Some(DivergenceField::FooterCrc)
    } else if l.content_hash != q.content_hash {
        Some(DivergenceField::ContentHash)
    } else {
        None
    }
}

/// Whether a ONE-SIDED segment (one replica holds it, the other does not) should be flagged as a
/// `MissingSegment` divergence. The fingerprint carries no per-segment base offset (the footer does
/// not store one), so the rule is intentionally conservative on the committed/uncommitted boundary: a
/// one-sided segment is a divergence whenever the OTHER replica has committed ANY data
/// (`other_committed_hw > 0`) — a genuine missing/extra committed segment to repair. A brand-new
/// cluster with no committed data (`hw == 0`) reports nothing, preserving the no-false-positive
/// property for an empty cluster.
fn is_committed_mismatch(other_committed_hw: u64) -> bool {
    other_committed_hw > 0
}

/// The I3-style bounds on how much a single auto-resync may re-fetch before it must FAIL CLOSED (#612,
/// #613). A divergence larger than these is not auto-repaired (it is surfaced as a typed
/// [`DivergenceError::ResyncTooLarge`]) — bounded, reported, never silently served. The default mirrors
/// the single-node I3 caps' spirit (one bounded region per event): a generous but finite record cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResyncBounds {
    /// The maximum number of records a single resync may re-fetch from the quorum. `0` means unbounded
    /// (not recommended outside tests). Over this, the resync fails closed.
    pub max_records: u64,
}

impl Default for ResyncBounds {
    fn default() -> Self {
        // 16 Mi records is a generous-but-finite default: a real divergence is at most a handful of
        // segments, so any plan larger than this is a misconfiguration / a divergence too large to
        // auto-heal, and failing closed is correct.
        ResyncBounds {
            max_records: 16 * 1024 * 1024,
        }
    }
}

/// A bounded, reported PLAN to heal a detected divergence by re-syncing from the quorum (#612): the
/// offset to truncate the divergent suffix to, and the count of records the re-fetch will replace. A
/// pure function of the [`DivergenceReport`] — the side effects (truncate + fetch) are run by
/// [`execute_resync`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResyncPlan {
    /// The offset to truncate to before re-fetching: the START of the first divergent segment (#798).
    /// The divergent suffix — committed region INCLUDED — is dropped and re-fetched from the clean
    /// quorum leader; there is no committed-HW clamp (a resync always has a clean leader to restore the
    /// dropped committed bytes, and [`execute_resync`] verifies convergence and refuses a leader that is
    /// behind the committed HW, so committed data is never silently lost).
    pub truncate_to: u64,
    /// How many records the re-fetch will replace (the records above `truncate_to` on this replica at
    /// plan time). Bounded by [`ResyncBounds`].
    pub records_to_refetch: u64,
    /// The quorum's committed high-watermark this resync must preserve (carried from the
    /// [`DivergenceReport`]). [`execute_resync`] FAILS CLOSED before truncating if the leader's
    /// high-watermark is below this — a leader that cannot restore all the committed data the truncate
    /// would drop. The defense-in-depth guard that replaces the removed truncate clamp (#798 review).
    pub quorum_committed_hw: u64,
}

/// A typed, REPORTED record of an executed auto-resync (#612): never a silent repair. It states what
/// the resync truncated and re-fetched so the cluster surfaces a `ResyncReport` event/metric (the beat
/// over NATS #5576, where a divergent replica silently returns and never reconciles).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResyncReport {
    /// The offset the divergent suffix was truncated to (= the plan's `truncate_to`).
    pub truncated_to: u64,
    /// How many records were dropped from the divergent suffix (the truncation's `records_dropped`).
    pub records_dropped: u64,
    /// How many records were re-fetched from the quorum to converge.
    pub records_refetched: u64,
    /// Whether a corrupt segment was QUARANTINED (copy-then-drop) as part of the repair (the C4-I3
    /// minority-corruption path) — `true` only when the repair captured corrupt bytes to the forensic
    /// store before re-syncing. The corrupt bytes are preserved; nothing was deleted.
    pub quarantined: bool,
    /// The bytes captured into the forensic quarantine store (the corrupt segment's bytes), `0` when
    /// no quarantine happened.
    pub quarantined_bytes: u64,
}

/// Errors specific to executing a resync.
pub type ResyncError = DivergenceError;

/// Plans an auto-resync from a [`DivergenceReport`] (#612). The truncation target is the start offset
/// of the FIRST divergent segment, so EVERY divergent segment — including a corrupt or drifted COMMITTED
/// one — is dropped and re-fetched (#798). The plan's record count is bounded by `bounds`; over the cap
/// this FAILS CLOSED with [`DivergenceError::ResyncTooLarge`] rather than planning an unbounded repair.
///
/// WHY committed data IS dropped here (the #798 fix): a resync ALWAYS has a clean quorum LEADER to
/// re-fetch from, so dropping the divergent committed region and re-fetching the leader's bytes is
/// NON-lossy and is the only way to repair committed-prefix corruption/drift — exactly the advertised
/// C4-I3 case. Clamping the truncation at the committed high-watermark (the previous behaviour) lifted it
/// ABOVE a corrupt committed segment, so the truncate dropped nothing, the re-fetch was a no-op, and the
/// corrupt committed bytes stayed live and were served as committed data. The "never drop committed data"
/// invariant is sound ONLY when there is NO clean source to restore it; in a resync there always is.
/// [`execute_resync`] re-fingerprints against the leader and FAILS CLOSED if convergence is not reached,
/// so a plan that would drop nothing can never be reported as a successful heal.
///
/// `first_divergent_offset` is the log offset at which the first divergent segment begins on THIS
/// replica (the caller derives it from its own segment directory — the fingerprint does not carry a
/// base offset). `log_end` is this replica's current next offset. A clean report plans nothing.
///
/// # Errors
/// [`DivergenceError::ResyncTooLarge`] if the records to re-fetch exceed `bounds.max_records`.
pub fn plan_resync(
    report: &DivergenceReport,
    first_divergent_offset: u64,
    log_end: u64,
    bounds: ResyncBounds,
) -> Result<Option<ResyncPlan>, DivergenceError> {
    if report.is_clean() {
        return Ok(None);
    }
    // Drop and re-fetch the WHOLE divergent suffix from the first divergent segment — committed region
    // included (#798). No committed-high-watermark clamp: a resync has a clean leader to restore it, and
    // `execute_resync`'s post-resync re-fingerprint verifies the result converged.
    let truncate_to = first_divergent_offset;
    let records_to_refetch = log_end.saturating_sub(truncate_to);
    if bounds.max_records != 0 && records_to_refetch > bounds.max_records {
        return Err(DivergenceError::ResyncTooLarge {
            records: records_to_refetch,
            cap: bounds.max_records,
        });
    }
    Ok(Some(ResyncPlan {
        truncate_to,
        records_to_refetch,
        // Carry the committed HW the resync must preserve, so `execute_resync` can refuse a leader that
        // is behind it (the defense-in-depth guard that replaces the removed truncate clamp, #798 review).
        quorum_committed_hw: report.quorum_committed_hw,
    }))
}

/// Executes a planned auto-resync against the quorum LEADER (#612): truncate this replica's divergent
/// suffix to the plan's `truncate_to` (bounded + reported), then re-fetch the clean CRC-validated bytes
/// from the leader through the existing C2 [`Follower`] fetch path until caught up to the leader's
/// high-watermark, converging BYTE-IDENTICAL. Returns a typed [`ResyncReport`].
///
/// The follower is the divergent replica's own log wrapped as a [`Follower`]; the leader is a clean
/// quorum member. The truncate uses the bounded, reported [`Log::truncate_to`](ironbus_storage::log::Log::truncate_to)
/// (the same primitive C2-I4 uses), so committed data below the clamp is never dropped. The re-fetch
/// re-validates every frame's CRC on ingest (the C2-I1 fail-closed property), so a divergent replica
/// never ingests an unvalidated byte and converges to the leader's exact frames.
///
/// # Errors
/// [`ReplicationError`] if the truncation or the re-fetch fails (the re-fetch fails closed on any
/// corrupt frame from the leader).
pub fn execute_resync<F: Filesystem, C: Clock>(
    follower: &mut Follower<F, C>,
    leader_log: &Log<F, C>,
    plan: &ResyncPlan,
    max_records_per_fetch: u32,
    max_bytes_per_fetch: u32,
) -> Result<ResyncReport, ReplicationError> {
    // 1. LEADER-BEHIND GUARD (#798 review), checked BEFORE any truncation: refuse a leader whose
    //    high-watermark is below the quorum's committed HW the resync must preserve. Removing the old
    //    committed-HW truncate clamp (the #798 fix) also removed the only defense against a leader that
    //    is behind; without this guard, truncating to `truncate_to` and re-fetching only up to a short
    //    `leader_hw` would drop committed data `[leader_hw, committed_hw)` that the leader cannot
    //    restore, and the post-resync compare would then read CLEAN against the leader's shorter prefix
    //    — committed data silently lost and reported as a successful heal. Fail closed instead, leaving
    //    the divergent (but still-complete) follower untouched for a retry against a complete leader.
    let leader = ReplicationLeader::new(leader_log);
    let leader_hw = leader.high_watermark().get();
    if leader_hw < plan.quorum_committed_hw {
        return Err(ReplicationError::ResyncLeaderBehind {
            leader_hw,
            committed_hw: plan.quorum_committed_hw,
        });
    }

    // 2. Truncate the divergent suffix to the target (bounded + reported). The Follower's log keeps the
    //    common prefix `[earliest, truncate_to)` untouched and drops only `[truncate_to, end)`.
    let truncation = follower
        .log_mut()
        .truncate_to(Offset::new(plan.truncate_to))?;

    // 3. Re-fetch from the clean leader until caught up to its high-watermark, converging byte-identical.
    let mut refetched = 0u64;
    // Bounded loop: each fetch below the HW makes progress (at least one record), so it terminates well
    // within hw+1 iterations from the truncated head.
    for _ in 0..(leader_hw + 2) {
        if follower.next_fetch_offset().get() >= leader_hw {
            break;
        }
        let req = follower.fetch_request(max_records_per_fetch, max_bytes_per_fetch);
        let resp = leader.serve_fetch(&req)?;
        let outcome = follower.apply_fetch_response(&resp)?;
        refetched += outcome.appended;
        if outcome.appended == 0 {
            // No progress below the HW would be a leader-side anomaly; stop rather than spin.
            break;
        }
    }

    // 4. POST-RESYNC CONVERGENCE CHECK (#798): re-fingerprint this replica against the leader and FAIL
    //    CLOSED if it STILL diverges. A resync is only a successful heal if the replica is now
    //    byte-identical to the clean quorum leader over the committed prefix. Without this check, a plan
    //    that truncated nothing (the old committed-high-watermark clamp left a corrupt committed segment
    //    in place) or a leader that served a short prefix would be reported as a successful repair while
    //    the replica is still divergent — the silent-unhealed-divergence-reported-as-success bug. The
    //    re-fingerprint is the same READ-ONLY durable-bytes comparison the detection path uses.
    let follower_fp = fingerprint_log(follower.log()).map_err(resync_fingerprint_err)?;
    let leader_fp = fingerprint_log(leader_log).map_err(resync_fingerprint_err)?;
    let post = compare_fingerprints(&follower_fp, &leader_fp);
    if !resync_has_converged(&post, follower.next_fetch_offset().get(), leader_hw) {
        return Err(ReplicationError::ResyncDidNotConverge {
            remaining: post.divergences.len(),
        });
    }

    Ok(ResyncReport {
        truncated_to: truncation.truncated_to,
        records_dropped: truncation.records_dropped,
        records_refetched: refetched,
        quarantined: false,
        quarantined_bytes: 0,
    })
}

/// Maps a fingerprint read error from the post-resync convergence check (#798) into the resync's
/// [`ReplicationError`] channel. [`fingerprint_log`] only ever returns [`DivergenceError::Storage`], but
/// map any other variant to a framed error rather than panicking on a future variant.
fn resync_fingerprint_err(e: DivergenceError) -> ReplicationError {
    match e {
        DivergenceError::Storage(s) => ReplicationError::Storage(s),
        other => ReplicationError::Frame {
            what: format!("resync convergence re-fingerprint failed: {other}"),
        },
    }
}

/// Whether a post-resync re-fingerprint compare means the replica CONVERGED byte-identical to the
/// leader's committed prefix (#798 review SHOULD-FIX 1). The raw [`DivergenceReport::is_clean`] is too
/// strict here because of a SEALING ASYMMETRY at the flushed frontier: a re-fetch is contiguous up to
/// `leader_hw`, but a [`Log`] only seals a segment on the NEXT append, so when the leader's flushed
/// frontier sits exactly on a sealed-segment boundary (it rolled on a record ABOVE its hw that the
/// follower never fetches), the leader carries ONE trailing SEALED segment the follower fills but cannot
/// seal. The follower holds the SAME frames (in its unsealed active segment, which the fingerprint
/// skips), so that one-sided trailing segment is NOT a real divergence — failing closed on it would
/// turn every legitimate resync that lands on a roll boundary into a false `ResyncDidNotConverge`.
///
/// Convergence therefore requires BOTH:
/// * the follower has caught up to the leader's high-watermark (`follower_next_offset >= leader_hw`),
///   so no committed data is actually missing — this is exactly what makes a leader-only trailing
///   segment provably the benign sealing artifact rather than a genuinely short follower; AND
/// * every remaining divergence is that benign artifact: a LEADER-ONLY (`local: None`, `quorum: Some`)
///   [`DivergenceField::MissingSegment`]. Segment ids are base offsets and the re-fetch is contiguous,
///   so once the follower reached `leader_hw` a middle gap is impossible; any FIELD mismatch on a shared
///   segment, or a FOLLOWER-only extra sealed segment, remains a genuine unhealed divergence.
fn resync_has_converged(
    post: &DivergenceReport,
    follower_next_offset: u64,
    leader_hw: u64,
) -> bool {
    if follower_next_offset < leader_hw {
        // The follower never reached the leader's frontier: committed data is genuinely missing, so a
        // leader-only trailing segment here is NOT the benign artifact. Fail closed.
        return false;
    }
    post.divergences.iter().all(|d| {
        matches!(d.field, DivergenceField::MissingSegment)
            && d.local.is_none()
            && d.quorum.is_some()
    })
}

/// The C4-I3 minority-corruption REPAIR (#613): when a divergent segment is locally CORRUPT, COPY its
/// bytes into the forensic [`QuarantineStore`] (copy-then-drop — the corrupt bytes are PRESERVED), then
/// run the auto-resync to re-fetch the clean segment from the quorum. The partition STAYS AVAILABLE off
/// the clean majority and NOTHING is ever deleted — the direct beat over NATS #7556, where a minority
/// single-bit error makes nodes permanently DELETE the stream dir.
///
/// `corrupt_segment_id` / `corrupt_span` identify the corrupt byte region to capture (the divergent
/// segment's bytes, from the divergence localization). `quarantine` is the replica's existing forensic
/// store (the SAME one single-node recovery uses — generalized to the cross-replica case). The capture
/// is best-effort and capped (a span larger than the cap is skipped, never written); it never blocks
/// the repair. After capture, [`execute_resync`] truncates + re-fetches the clean bytes from the leader.
///
/// # Errors
/// [`ReplicationError`] from the underlying [`execute_resync`].
#[allow(clippy::too_many_arguments)]
pub fn quarantine_and_resync<F: Filesystem, C: Clock, R: RandomAccessFile>(
    follower: &mut Follower<F, C>,
    leader_log: &Log<F, C>,
    quarantine: &mut QuarantineStore<F>,
    corrupt_source: &R,
    corrupt_segment_id: u64,
    corrupt_span: (u64, u64),
    plan: &ResyncPlan,
    max_records_per_fetch: u32,
    max_bytes_per_fetch: u32,
) -> Result<ResyncReport, ReplicationError> {
    // 1. COPY-THEN-DROP: capture the corrupt segment's bytes into the forensic store BEFORE the resync
    //    truncates them away. This is a COPY (the source is read read-only); the resync's truncation is
    //    what removes the corrupt bytes from the live log, and the clean bytes are re-fetched. The
    //    corrupt evidence survives in quarantine; nothing is deleted.
    let (start, end) = corrupt_span;
    let event = LossEvent::span(
        corrupt_segment_id,
        start,
        end,
        // A best-effort lower bound on records lost; the exact count of a corrupt span is unknown.
        1,
        ReasonCode::CorruptRecordBody,
    );
    let captured = quarantine.capture(corrupt_source, &event);

    // 2. Re-sync the clean bytes from the quorum (truncate + re-fetch, byte-identical).
    let mut report = execute_resync(
        follower,
        leader_log,
        plan,
        max_records_per_fetch,
        max_bytes_per_fetch,
    )?;
    report.quarantined = captured > 0;
    report.quarantined_bytes = captured;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::io::RandomAccessFile;
    use ironbus_storage::log::{Append, LogConfig};

    /// A small segment cap so a handful of records rolls to MULTIPLE sealed segments — the cross-replica
    /// fingerprint compare is only meaningful across segment boundaries, and the byte-identity resync
    /// must cross them too. A finite quarantine cap so the C4-I3 copy-then-drop is exercised under a bound.
    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
        .with_max_quarantine_bytes(64 * 1024)
    }

    fn open_log(fs: InMemoryFs) -> Log<InMemoryFs, ManualClock> {
        Log::open(fs, ManualClock::new(), small_config()).expect("log opens")
    }

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 42,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    /// Read the FULL on-disk bytes of every segment file in a log's filesystem, keyed by name — the
    /// ground truth for the byte-identity assertion (two logs are byte-identical iff they hold the same
    /// segment files with the same bytes).
    fn dump_segments(log: &Log<InMemoryFs, ManualClock>) -> Vec<(String, Vec<u8>)> {
        let fs = log.filesystem();
        let mut out = Vec::new();
        for name in fs.list().expect("list") {
            if segment_id_of(&name).is_none() {
                continue;
            }
            let file = fs.open(&name).expect("open");
            let len = usize::try_from(file.len().expect("len")).expect("fits");
            let mut buf = vec![0u8; len];
            file.read_exact_at(&mut buf, 0).expect("read");
            out.push((name, buf));
        }
        out.sort();
        out
    }

    /// Append `payloads` to a fresh log, sync, and return it (committed up to the flushed head).
    fn log_with(payloads: &[&[u8]]) -> Log<InMemoryFs, ManualClock> {
        let mut log = open_log(InMemoryFs::new());
        for p in payloads {
            log.append(&rec(p)).unwrap();
        }
        log.sync().unwrap();
        log
    }

    // ===== C4-I1 DETECTION =====

    #[test]
    fn a_clean_cluster_detects_no_divergence_no_false_positive() {
        // Two replicas wrote the SAME records: their fingerprints are byte-identical, so the compare
        // detects NOTHING. This is the no-false-positive property — agreement is never drift.
        let leader = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot",
        ]);
        let replica = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot",
        ]);

        let leader_fp = fingerprint_log(&leader).expect("fingerprint leader");
        let replica_fp = fingerprint_log(&replica).expect("fingerprint replica");

        // Both replicas have the same SEALED segments with identical fingerprints.
        assert!(
            !leader_fp.fingerprints.is_empty(),
            "rolled to >=1 sealed segment"
        );
        assert_eq!(leader_fp.fingerprints, replica_fp.fingerprints);

        let report = compare_fingerprints(&replica_fp, &leader_fp);
        assert!(
            report.is_clean(),
            "a clean cluster must report no divergence"
        );
        assert_eq!(report.first_divergent_segment(), None);
    }

    #[test]
    fn a_divergent_segment_is_detected_and_reported_not_silent() {
        // The leader and a divergent replica share a prefix but the replica wrote DIFFERENT records in a
        // later segment (silent drift): same offsets, different bytes. The footer triple and/or the
        // content hash disagree -> a DETECTED, typed, reported divergence (the signal NATS computes but
        // ignores, #5576).
        let leader = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot",
        ]);
        let divergent = log_with(&[b"alpha", b"bravo", b"charlie", b"XXXXX", b"YYYYY", b"ZZZZZ"]);

        let leader_fp = fingerprint_log(&leader).expect("fp");
        let divergent_fp = fingerprint_log(&divergent).expect("fp");

        let report = compare_fingerprints(&divergent_fp, &leader_fp);
        assert!(
            !report.is_clean(),
            "the divergence must be DETECTED, not silent"
        );
        assert!(!report.divergences.is_empty());
        // It localized to a specific segment and a specific field (content/last_seq/crc), reported.
        let first = report.divergences.first().unwrap();
        assert!(matches!(
            first.field,
            DivergenceField::ContentHash
                | DivergenceField::LastSeq
                | DivergenceField::RecordCount
                | DivergenceField::FooterCrc
        ));
        assert!(report.first_divergent_segment().is_some());
    }

    #[test]
    fn a_short_replica_is_detected_as_missing_segment() {
        // A replica that is SHORT (fewer committed segments than the quorum) is detected: the quorum
        // holds a committed segment the replica lacks -> MissingSegment.
        let leader = log_with(&[
            b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h", b"i", b"j", b"k", b"l",
        ]);
        let short = log_with(&[b"a", b"b", b"c", b"d"]);

        let leader_fp = fingerprint_log(&leader).expect("fp");
        let short_fp = fingerprint_log(&short).expect("fp");
        assert!(short_fp.fingerprints.len() < leader_fp.fingerprints.len());

        let report = compare_fingerprints(&short_fp, &leader_fp);
        assert!(!report.is_clean());
        assert!(report
            .divergences
            .iter()
            .any(|d| d.field == DivergenceField::MissingSegment
                && d.quorum.is_some()
                && d.local.is_none()));
    }

    // ===== the fingerprint wire codec: bounded + validated =====

    #[test]
    fn fingerprints_round_trip_over_the_bounded_frame() {
        let leader = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot",
        ]);
        let fp = fingerprint_log(&leader).expect("fp");
        let frame = fp.to_frame().expect("frame");
        let (decoded, consumed) = SegmentFingerprints::decode_frame(&frame)
            .expect("decode")
            .expect("complete frame");
        assert_eq!(decoded, fp);
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn an_oversized_advertisement_is_rejected_before_allocation() {
        // A hostile body declares a huge fingerprint count: rejected with a typed error, never buffered.
        let mut body = Vec::new();
        body.extend_from_slice(&0u64.to_le_bytes()); // committed_hw
        body.extend_from_slice(&(MAX_FINGERPRINTS + 1).to_le_bytes()); // count over the cap
        let err = SegmentFingerprints::decode(&body).unwrap_err();
        assert!(matches!(err, DivergenceError::TooManyFingerprints { .. }));
    }

    #[test]
    fn a_malformed_advertisement_body_is_rejected() {
        // A body whose length disagrees with its declared count is rejected (never guessed at).
        let mut body = Vec::new();
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&2u32.to_le_bytes()); // claims 2 fingerprints
                                                     // ...but carries zero fingerprint bytes.
        let err = SegmentFingerprints::decode(&body).unwrap_err();
        assert!(matches!(
            err,
            DivergenceError::MalformedAdvertisement { .. }
        ));
    }

    // ===== C4-I2 AUTO-RESYNC: converge byte-identical, bounded + reported =====

    #[test]
    fn a_divergent_replica_auto_resyncs_and_converges_byte_identical() {
        // The leader is the clean quorum. The divergent replica shares the first 3 records but wrote
        // different later records (silent drift). Detection finds the divergence; the resync truncates
        // the divergent suffix and re-fetches the leader's clean bytes -> BYTE-IDENTICAL to the leader.
        let leader = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf",
        ]);
        let divergent_log = log_with(&[
            b"alpha", b"bravo", b"charlie", b"XXXXX", b"YYYYY", b"ZZZZZ", b"WWWW",
        ]);

        let leader_fp = fingerprint_log(&leader).expect("fp");
        let divergent_fp = fingerprint_log(&divergent_log).expect("fp");
        let report = compare_fingerprints(&divergent_fp, &leader_fp);
        assert!(!report.is_clean(), "divergence detected");

        // Plan the resync. The first divergent segment begins at the offset of the first record that
        // differs (record index 3 here); the leader is the source of truth, so truncate to where the
        // divergence starts and re-fetch the clean bytes from the leader (#798: no committed-HW clamp —
        // a resync always has a clean leader to restore whatever it drops).
        let log_end = divergent_log.next_offset().get();
        let plan = plan_resync(&report, 3, log_end, ResyncBounds::default())
            .expect("plan ok")
            .expect("a plan");
        assert!(plan.records_to_refetch > 0);

        // Execute: wrap the divergent replica's log as a follower and resync from the clean leader.
        let mut follower = Follower::new(divergent_log);
        let resync = execute_resync(&mut follower, &leader, &plan, 4, 4096).expect("resync");

        // REPORTED: a typed ResyncReport, never a silent repair.
        assert!(
            resync.records_dropped > 0,
            "the divergent suffix was dropped"
        );
        assert!(resync.records_refetched > 0, "clean bytes were re-fetched");
        assert!(!resync.quarantined, "a clean drift does not quarantine");

        // CONVERGED BYTE-IDENTICAL: every sealed segment on the follower matches the leader's.
        assert_eq!(
            follower.next_fetch_offset().get(),
            leader.flushed_offset().get()
        );
        assert_eq!(
            dump_segments(follower.log()),
            dump_segments(&leader),
            "the resynced replica is byte-identical to the clean leader"
        );
    }

    #[test]
    fn a_resync_over_the_bound_fails_closed_not_silently_served() {
        // A divergence whose re-fetch would exceed the I3 bound FAILS CLOSED with a typed error rather
        // than planning an unbounded repair (bounded + reported, never silently serve a divergent log).
        let leader = log_with(&[b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"]);
        let divergent_log = log_with(&[b"a", b"b", b"X", b"Y", b"Z", b"W", b"V", b"U"]);
        let leader_fp = fingerprint_log(&leader).expect("fp");
        let divergent_fp = fingerprint_log(&divergent_log).expect("fp");
        let report = compare_fingerprints(&divergent_fp, &leader_fp);
        assert!(!report.is_clean());

        let log_end = divergent_log.next_offset().get();
        // A tiny bound of 1 record forces the fail-closed path (the divergent suffix is > 1 record).
        let bounds = ResyncBounds { max_records: 1 };
        let err = plan_resync(&report, 2, log_end, bounds).unwrap_err();
        assert!(matches!(err, DivergenceError::ResyncTooLarge { .. }));
    }

    // ===== committed data is never dropped =====

    #[test]
    fn a_committed_divergence_below_the_hw_is_dropped_and_refetched_not_clamped() {
        // #798: a divergence (drift or corruption) that begins BELOW the committed high-watermark must be
        // dropped and re-fetched from the clean leader, NOT clamped above. The previous behaviour clamped
        // the truncate target at or above the committed HW, which lifted it ABOVE a committed divergence
        // so the truncate dropped nothing, the re-fetch was a no-op, and the corrupt/drifted committed
        // bytes stayed live and were served as committed data — a silent, unhealed divergence.
        let leader = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf", b"hotel",
            b"india", b"juliet", b"kilo", b"lima",
        ]);
        let divergent_log = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"WWWWW", b"VVVVV",
            b"UUUUU", b"TTTTT", b"SSSSS", b"RRRRR",
        ]);
        let leader_fp = fingerprint_log(&leader).expect("fp");
        let divergent_fp = fingerprint_log(&divergent_log).expect("fp");
        let report = compare_fingerprints(&divergent_fp, &leader_fp);
        assert!(
            !report.is_clean(),
            "the sealed-segment divergence is detected"
        );

        // The first divergent segment begins at offset 3 — BELOW the leader's committed HW (12). The plan
        // truncates to exactly that offset (no clamp): committed data IS in the dropped suffix, because the
        // clean leader will restore it. Pre-#798 the truncate would have clamped to the HW and dropped
        // nothing.
        let log_end = divergent_log.next_offset().get();
        let first_divergent_offset = 3u64;
        let plan = plan_resync(
            &report,
            first_divergent_offset,
            log_end,
            ResyncBounds::default(),
        )
        .expect("plan")
        .expect("a plan");
        assert_eq!(
            plan.truncate_to, first_divergent_offset,
            "the truncate target is the first divergent offset, NOT clamped to the committed HW (#798)"
        );

        // Execute the resync: the committed divergent region is dropped and re-fetched, and the replica
        // converges BYTE-IDENTICAL to the leader. execute_resync's post-resync convergence check
        // (#798) would FAIL CLOSED if the repair had left any divergence.
        let mut follower = Follower::new(divergent_log);
        let resync =
            execute_resync(&mut follower, &leader, &plan, 4, 4096).expect("resync converges");
        assert!(
            resync.records_dropped > 0,
            "the divergent committed region was dropped"
        );
        assert!(
            resync.records_refetched > 0,
            "clean bytes were re-fetched from the leader"
        );
        assert_eq!(
            dump_segments(follower.log()),
            dump_segments(&leader),
            "the committed divergence below the HW is repaired byte-identical (#798)"
        );
    }

    #[test]
    fn a_resync_that_truncates_nothing_fails_closed_instead_of_reporting_a_false_heal() {
        // #798: the convergence guard. A resync plan that would truncate nothing while the replica is
        // still divergent (the shape the OLD committed-HW clamp produced for a committed-prefix
        // corruption) must FAIL CLOSED — never return Ok with quarantined=true while the corrupt bytes
        // remain live. We hand execute_resync a hand-built plan whose truncate target is the log end (drop
        // nothing) and assert the post-resync re-fingerprint catches the surviving divergence.
        let leader = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf",
        ]);
        let divergent_log = log_with(&[
            b"alpha", b"bravo", b"ZZZZZ", b"delta", b"echo", b"foxtrot", b"golf",
        ]);
        let leader_fp = fingerprint_log(&leader).expect("fp");
        let divergent_fp = fingerprint_log(&divergent_log).expect("fp");
        let report = compare_fingerprints(&divergent_fp, &leader_fp);
        assert!(!report.is_clean(), "the committed divergence is detected");

        let log_end = divergent_log.next_offset().get();
        // The buggy-clamp shape: truncate_to lifted to the log end, so the truncate drops nothing and the
        // re-fetch is a no-op — exactly what the pre-#798 clamp produced for a sub-HW divergence. The
        // leader IS the clean quorum (its hw == the committed HW), so the leader-behind guard passes and
        // the failure is purely the convergence check catching the surviving divergence.
        let bad_plan = ResyncPlan {
            truncate_to: log_end,
            records_to_refetch: 0,
            quorum_committed_hw: report.quorum_committed_hw,
        };
        let mut follower = Follower::new(divergent_log);
        let err = execute_resync(&mut follower, &leader, &bad_plan, 4, 4096)
            .expect_err("a resync that drops nothing must fail closed, not report a heal");
        assert!(
            matches!(err, ReplicationError::ResyncDidNotConverge { remaining } if remaining > 0),
            "the surviving divergence is reported, not a false success: {err:?}"
        );
    }

    #[test]
    fn a_resync_converges_when_the_leader_frontier_sits_on_a_sealed_segment_boundary() {
        // #798 review SHOULD-FIX 1: a re-fetch is contiguous up to `leader_hw`, but a Log seals a segment
        // only on the NEXT append. When the leader's flushed frontier sits EXACTLY on a sealed-segment
        // boundary, the leader holds one trailing SEALED segment the follower fills but cannot seal, so a
        // naive `is_clean()` convergence check fails CLOSED on a legitimate, fully-healed resync.
        //
        // Build that exact leader: append 5 records with NO trailing sync. The 5th append (offset 4) rolls
        // and seals segment 0 at boundary 4 and advances the flushed frontier to 4, while record 4 sits
        // UNFLUSHED in the new active segment. So the leader's hw (4) lands on the sealed boundary, with one
        // sealed segment and the rolling record above the hw (the segment cap is 4 records here).
        let mut leader = open_log(InMemoryFs::new());
        for i in 0..5u32 {
            leader.append(&rec(format!("good{i}").as_bytes())).unwrap();
        }
        assert_eq!(
            leader.flushed_offset().get(),
            4,
            "the leader hw lands on the sealed-segment boundary"
        );
        let leader_fp = fingerprint_log(&leader).expect("fp");
        assert_eq!(
            leader_fp.fingerprints.len(),
            1,
            "exactly one sealed segment at the frontier"
        );

        // A divergent replica that differs from offset 0, so the resync truncates to 0 and re-fetches the
        // leader's committed `[0, 4)`. Those 4 records fill the follower's first segment but never roll it
        // (the rolling 5th record is above the leader's hw and is never served), so the follower ends with
        // the SAME committed frames but ZERO sealed segments — the sealing asymmetry, not a real gap.
        let divergent_log = log_with(&[b"BAD0", b"BAD1", b"BAD2", b"BAD3", b"BAD4"]);
        let divergent_fp = fingerprint_log(&divergent_log).expect("fp");
        let report = compare_fingerprints(&divergent_fp, &leader_fp);
        assert!(!report.is_clean(), "the offset-0 divergence is detected");

        let log_end = divergent_log.next_offset().get();
        let plan = plan_resync(&report, 0, log_end, ResyncBounds::default())
            .expect("plan ok")
            .expect("a plan");

        let mut follower = Follower::new(divergent_log);
        // BEFORE the fix this returned `Err(ResyncDidNotConverge)` purely from the sealing asymmetry; the
        // follower is genuinely byte-identical to the leader's committed prefix, so it must report success.
        let resync = execute_resync(&mut follower, &leader, &plan, 8, 4096)
            .expect("the sealing-boundary asymmetry must NOT be reported as a failed convergence");
        assert!(
            resync.records_refetched > 0,
            "the clean prefix was re-fetched"
        );
        assert_eq!(
            follower.next_fetch_offset().get(),
            leader.flushed_offset().get(),
            "the follower caught up to the leader's frontier"
        );
        assert_eq!(
            fingerprint_log(follower.log()).expect("fp").fingerprints.len(),
            0,
            "the follower holds the same frames but with its tail UNSEALED (the artifact we tolerate)"
        );
    }

    #[test]
    fn resync_convergence_tolerates_only_the_trailing_seal_artifact() {
        // A direct unit test of the convergence predicate's branches (#798 review SHOULD-FIX 1): the
        // benign leader-only trailing seal is tolerated ONLY when the follower has caught up; a field
        // mismatch on a shared segment, a follower-only extra segment, or a short follower is NOT.
        let fp = |id: u64| SegmentFingerprint {
            segment_id: id,
            last_seq: id,
            record_count: 4,
            footer_crc: 1,
            content_hash: id,
        };
        let leader_only_trailing = DivergenceReport {
            divergences: vec![DivergenceDetected {
                segment_id: 8,
                field: DivergenceField::MissingSegment,
                local: None,
                quorum: Some(fp(8)),
            }],
            quorum_committed_hw: 8,
        };
        // Caught up + only the leader-only trailing MissingSegment => CONVERGED (the benign artifact).
        assert!(resync_has_converged(&leader_only_trailing, 8, 8));
        // The SAME report but the follower never reached the hw => a genuinely short follower, NOT the
        // artifact => fail closed.
        assert!(!resync_has_converged(&leader_only_trailing, 6, 8));
        // A clean report (no divergences) is always converged.
        let clean = DivergenceReport {
            divergences: vec![],
            quorum_committed_hw: 8,
        };
        assert!(resync_has_converged(&clean, 8, 8));
        // A FIELD divergence on a shared segment is a real unhealed state, even when caught up.
        let field = DivergenceReport {
            divergences: vec![DivergenceDetected {
                segment_id: 4,
                field: DivergenceField::ContentHash,
                local: Some(fp(4)),
                quorum: Some(fp(4)),
            }],
            quorum_committed_hw: 8,
        };
        assert!(!resync_has_converged(&field, 8, 8));
        // A FOLLOWER-only extra sealed segment (local present, quorum absent) is NOT the benign artifact.
        let follower_only = DivergenceReport {
            divergences: vec![DivergenceDetected {
                segment_id: 8,
                field: DivergenceField::MissingSegment,
                local: Some(fp(8)),
                quorum: None,
            }],
            quorum_committed_hw: 8,
        };
        assert!(!resync_has_converged(&follower_only, 8, 8));
    }

    #[test]
    fn a_resync_against_a_leader_behind_the_committed_hw_fails_closed_and_keeps_committed_data() {
        // #798 review SHOULD-FIX 2: dropping the truncate clamp removed the only defense against a leader
        // that is BEHIND. A resync handed a leader whose hw is below the quorum's committed HW must FAIL
        // CLOSED before truncating — it cannot restore the committed data the truncate would drop — and
        // leave the (still-complete) follower untouched for a retry against a complete leader.
        let complete_leader = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf",
        ]);
        // A BEHIND leader: fewer committed records, so its hw is below the quorum's committed HW.
        let behind_leader = log_with(&[b"alpha", b"bravo", b"charlie", b"delta"]);
        let divergent_log = log_with(&[
            b"alpha", b"bravo", b"XXXXX", b"delta", b"echo", b"foxtrot", b"golf",
        ]);

        // The report (and so the plan's `quorum_committed_hw`) is computed against the COMPLETE leader, so
        // it carries the full committed HW the resync must preserve.
        let complete_fp = fingerprint_log(&complete_leader).expect("fp");
        let divergent_fp = fingerprint_log(&divergent_log).expect("fp");
        let report = compare_fingerprints(&divergent_fp, &complete_fp);
        assert!(!report.is_clean(), "divergence detected");
        let log_end = divergent_log.next_offset().get();
        let plan = plan_resync(&report, 2, log_end, ResyncBounds::default())
            .expect("plan ok")
            .expect("a plan");
        assert!(
            plan.quorum_committed_hw > behind_leader.flushed_offset().get(),
            "the test needs a leader genuinely behind the committed HW"
        );

        // Execute against the BEHIND leader: the guard must fire BEFORE any truncation.
        let before = dump_segments(&divergent_log);
        let mut follower = Follower::new(divergent_log);
        let err = execute_resync(&mut follower, &behind_leader, &plan, 4, 4096)
            .expect_err("a leader behind the committed HW must fail closed");
        assert!(
            matches!(
                err,
                ReplicationError::ResyncLeaderBehind { leader_hw, committed_hw }
                    if leader_hw == behind_leader.flushed_offset().get()
                        && committed_hw == plan.quorum_committed_hw
            ),
            "the guard names the behind leader and the committed HW: {err:?}"
        );
        assert_eq!(
            dump_segments(follower.log()),
            before,
            "a fail-closed leaves the follower's committed data UNTOUCHED for a retry"
        );
    }

    #[test]
    fn quarantine_and_resync_fails_closed_and_never_reports_a_quarantine_on_non_convergence() {
        // #798 review NIT 4: `quarantine_and_resync` runs `execute_resync` with `?`, so a non-converging
        // resync propagates the error BEFORE `report.quarantined`/`quarantined_bytes` are ever set — the
        // fail-closed guarantee is structural. Pin it: feed the truncate-nothing plan shape and assert it
        // returns the convergence error, not a `ResyncReport` claiming a successful quarantine-repair.
        let leader = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf",
        ]);
        let divergent_log = log_with(&[
            b"alpha", b"bravo", b"ZZZZZ", b"delta", b"echo", b"foxtrot", b"golf",
        ]);
        let leader_fp = fingerprint_log(&leader).expect("fp");
        let divergent_fp = fingerprint_log(&divergent_log).expect("fp");
        let report = compare_fingerprints(&divergent_fp, &leader_fp);
        assert!(!report.is_clean(), "the committed divergence is detected");

        let log_end = divergent_log.next_offset().get();
        // The truncate-nothing shape (the pre-#798 clamp): the convergence check must reject it.
        let bad_plan = ResyncPlan {
            truncate_to: log_end,
            records_to_refetch: 0,
            quorum_committed_hw: report.quorum_committed_hw,
        };
        let fs = divergent_log.filesystem().clone();
        let corrupt_source = open_log(InMemoryFs::new());
        let source_file = {
            // Any readable segment file works as the (here-unused) forensic source; the resync fails before
            // the capture matters. Reuse the divergent log's first segment.
            let name = fs
                .list()
                .unwrap()
                .into_iter()
                .find(|n| segment_id_of(n).is_some())
                .expect("a segment file");
            fs.open(&name).unwrap()
        };
        let _ = &corrupt_source;
        let mut quarantine = QuarantineStore::open(&fs, 64 * 1024).expect("quarantine opens");

        let mut follower = Follower::new(divergent_log);
        let err = quarantine_and_resync(
            &mut follower,
            &leader,
            &mut quarantine,
            &source_file,
            0,
            (HEADER_LEN as u64, HEADER_LEN as u64 + 8),
            &bad_plan,
            4,
            4096,
        )
        .expect_err("a non-converging quarantine-resync must fail closed, not report a repair");
        assert!(
            matches!(err, ReplicationError::ResyncDidNotConverge { remaining } if remaining > 0),
            "the surviving divergence is surfaced, never a false quarantine-repair: {err:?}"
        );
    }

    // ===== C4-I3 MINORITY QUARANTINE-REPAIR: never delete, stay available =====

    #[test]
    fn a_minority_corrupt_segment_is_quarantined_and_resynced_never_deleted() {
        // The clean MAJORITY is the leader. A MINORITY replica's sealed segment is CORRUPTED on disk
        // (a flipped byte in the record region). The repair COPY-THEN-DROPS the corrupt segment into the
        // forensic quarantine (the corrupt bytes are PRESERVED), then re-syncs the clean bytes from the
        // majority. The partition stays available; NOTHING is deleted.
        let leader = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf",
        ]);

        // Build the minority replica byte-identical to the leader first (so the ONLY difference is the
        // injected corruption — a true minority single-bit fault, not a different write history).
        let mut minority_log = open_log(InMemoryFs::new());
        for p in [
            b"alpha".as_slice(),
            b"bravo",
            b"charlie",
            b"delta",
            b"echo",
            b"foxtrot",
            b"golf",
        ] {
            minority_log.append(&rec(p)).unwrap();
        }
        minority_log.sync().unwrap();

        // Pick the FIRST sealed segment and corrupt a byte deep in its record region (past the header).
        let fs = minority_log.filesystem().clone();
        let seg_names: Vec<String> = fs
            .list()
            .unwrap()
            .into_iter()
            .filter(|n| segment_id_of(n).is_some())
            .collect();
        let target = {
            // The smallest segment id is the oldest sealed segment.
            let mut ids: Vec<(u64, String)> = seg_names
                .iter()
                .map(|n| (segment_id_of(n).unwrap(), n.clone()))
                .collect();
            ids.sort();
            ids.first().unwrap().1.clone()
        };
        let corrupt_id = segment_id_of(&target).unwrap();
        let file = fs.open(&target).unwrap();
        let seg_len = file.len().unwrap();
        let corrupt_at = HEADER_LEN as u64 + 4; // inside the record region
                                                // Capture the to-be-corrupted span for the forensic copy (a small bounded region).
        let corrupt_span = (
            corrupt_at,
            (corrupt_at + 8).min(seg_len.saturating_sub(FOOTER_LEN as u64)),
        );
        // Flip a byte on disk: silent corruption of a previously-durable segment on the minority.
        let mut one = [0u8; 1];
        file.read_exact_at(&mut one, corrupt_at).unwrap();
        one[0] ^= 0xFF;
        file.write_all_at(&one, corrupt_at).unwrap();

        // DETECTION: the minority's content hash now differs from the majority's for that segment.
        let leader_fp = fingerprint_log(&leader).expect("fp");
        let minority_fp = fingerprint_log(&minority_log).expect("fp");
        let report = compare_fingerprints(&minority_fp, &leader_fp);
        assert!(!report.is_clean(), "the minority corruption is DETECTED");
        assert!(
            report
                .divergences
                .iter()
                .any(|d| d.segment_id == corrupt_id),
            "the corrupt segment is the divergent one"
        );

        // REPAIR: open the forensic quarantine on the minority's data dir, capture the corrupt bytes,
        // then truncate + re-fetch the clean bytes from the majority. The truncate target is the start of
        // the corrupt segment (offset 0) — which is COMMITTED data (the leader has 7 committed records),
        // and #798 drops + re-fetches it from the clean leader rather than clamping above it. The
        // convergence check inside execute_resync then verifies the repair actually converged.
        let corrupt_source = fs.open(&target).unwrap();
        let mut quarantine = QuarantineStore::open(&fs, 64 * 1024).expect("quarantine opens");
        let bytes_before = quarantine.bytes();

        let log_end = minority_log.next_offset().get();
        let plan = plan_resync(&report, 0, log_end, ResyncBounds::default())
            .expect("plan")
            .expect("a plan");

        let mut follower = Follower::new(minority_log);
        let resync = quarantine_and_resync(
            &mut follower,
            &leader,
            &mut quarantine,
            &corrupt_source,
            corrupt_id,
            corrupt_span,
            &plan,
            4,
            4096,
        )
        .expect("quarantine + resync");

        // QUARANTINED (copy-then-drop): the corrupt bytes were captured, NOT deleted.
        assert!(resync.quarantined, "the corrupt segment was quarantined");
        assert!(resync.quarantined_bytes > 0);
        assert!(quarantine.bytes() > bytes_before, "the forensic store grew");

        // STILL AVAILABLE + re-synced BYTE-IDENTICAL: after the repair the minority matches the majority.
        assert_eq!(
            follower.next_fetch_offset().get(),
            leader.flushed_offset().get()
        );
        assert_eq!(
            dump_segments(follower.log()),
            dump_segments(&leader),
            "the repaired minority is byte-identical to the clean majority (re-synced, not deleted)"
        );

        // The corrupt evidence is PRESERVED in the quarantine subdirectory (never deleted).
        let q_fs = follower.log().filesystem().subdir("quarantine").unwrap();
        let q_blobs: Vec<String> = q_fs
            .list()
            .unwrap()
            .into_iter()
            .filter(|n| n.starts_with("q-") && n.contains(".bin"))
            .collect();
        assert!(
            !q_blobs.is_empty(),
            "the corrupt bytes are preserved as a forensic blob"
        );
    }

    // ===== single-node is unaffected =====

    #[test]
    fn single_node_fingerprint_is_a_pure_read_and_changes_no_bytes() {
        // Fingerprinting is a READ-ONLY pure function of the durable bytes: computing it leaves the log
        // byte-for-byte unchanged (the single-node binary's on-disk layout is never touched by C4).
        let log = log_with(&[
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot",
        ]);
        let before = dump_segments(&log);
        let _fp = fingerprint_log(&log).expect("fp");
        let after = dump_segments(&log);
        assert_eq!(before, after, "fingerprinting changed no on-disk bytes");
        // A log compared against ITSELF detects nothing — a single replica is never self-divergent.
        let fp = fingerprint_log(&log).expect("fp");
        assert!(compare_fingerprints(&fp, &fp).is_clean());
    }
}
