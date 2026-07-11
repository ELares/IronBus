// SPDX-License-Identifier: MIT OR Apache-2.0
//! A crash-safe checkpoint for small durable state (the committed consumer cursor, and
//! the resilience counters).
//!
//! The checkpoint is two fixed-size slots. Each write goes to the slot the sequence
//! number selects, alternating, and is CRC32C-protected over its sequence, length, and
//! payload. On recovery the higher-sequence slot whose CRC validates wins; a slot torn by
//! a crash mid-write fails its CRC and is ignored, so the previous slot survives. The
//! checkpoint may therefore regress to an earlier value after a crash, never to a torn or
//! invented one: for an at-least-once cursor that just means some already-processed
//! messages redeliver, which is safe. It never advances past a value that was not fully,
//! durably written.
//!
//! The per-slot payload cap is a const generic, so the same crash-safe machinery serves the
//! small cursor snapshot ([`MAX_PAYLOAD`], the default) and the slightly larger resilience-counter
//! snapshot ([`COUNTERS_PAYLOAD`], #98) without duplicating the dual-slot logic.

use crate::io::RandomAccessFile;
use crate::segment::StorageError;
use ironbus_core::segment::SegmentError;

/// The most payload bytes the cursor checkpoint slot holds (the committed watermark plus the
/// acked-ahead set). Also the DEFAULT payload cap for a [`Checkpoint`], so the existing cursor
/// callers are unchanged.
pub const MAX_PAYLOAD: usize = 64;

/// The per-slot payload cap for the resilience-counters checkpoint (#98, #307): a version byte plus
/// the fixed set of `u64` counters, with generous headroom for future fields. The current snapshot is
/// 1 + 8 * 15 = 121 bytes (the 11 #306 operational counters plus the four #307 recovery-loss fields);
/// 256 leaves room for ~16 more `u64` counters before the cap is reached.
/// (The cap matters: a snapshot that exceeds it would make `write` return `Truncated`, which the
/// graceful-shutdown flush propagates, so the cap must stay comfortably ahead of the field count.)
/// The counters snapshot is an OBSERVABILITY aid, never correctness state, so a torn or missing one
/// recovers as all-zeros and never blocks broker startup.
pub const COUNTERS_PAYLOAD: usize = 256;

/// The per-slot payload cap for the durable per-message ATTEMPT-COUNT checkpoint (#358): the
/// in-flight `{offset -> attempt_count}` map a poison record's `MaxDeliver` count survives an
/// unclean restart through. The snapshot is a small header plus 12 bytes per in-flight offset, and
/// the in-flight set is bounded by `max_in_flight` per group, so the map is bounded too. At the
/// default `max_in_flight` of 1024 the snapshot is `9 + 1024 * 12` ~= 12 KiB; this 32 KiB cap holds
/// roughly 2700 in-flight attempt counts before the server drops the overflow tail (which only
/// resets those few offsets to attempt 1, an at-least-once-safe loss, never a correctness break).
/// It stays under the slot's `u16` length field (65535), so a snapshot at the cap still frames.
pub const ATTEMPTS_PAYLOAD: usize = 32 * 1024;

/// The per-slot payload cap for the durable idempotent-producer SEQUENCE checkpoint (V2-M8,
/// #638/#639): the `(producer_id, epoch, last_seq, last_offset)` high-water per active producer that
/// makes effectively-once dedup survive a broker restart AND a long offline gap (the beat over
/// NATS's time-bounded `Nats-Msg-Id` window). One fixed high-water per producer (NOT per message),
/// so the snapshot is O(active producers): each entry is `2 + producer_id (<= 256) + 24` bytes, at
/// most ~282 bytes. This 60 KiB cap holds ~210 worst-case entries (far more with short `producer_id`s)
/// and, like the attempt-count checkpoint, the server keeps the most-recently-active producers that
/// FIT and drops the overflow tail — which only resets those few producers to at-least-once after a
/// restart (a later publish reads fresh), never a correctness break. It stays under the slot's `u16`
/// length field (65535), so a snapshot at the cap still frames.
pub const PRODUCER_SEQ_PAYLOAD: usize = 60 * 1024;

/// The per-slot payload cap for the durable METADATA-RAFT SNAPSHOT checkpoint (V2-C1, #660): a
/// serialized raft `Snapshot` (its index/term/`ConfState` metadata plus the metadata
/// state-machine's snapshot bytes — members / placements / committed-HW / config). The metadata
/// state is small BY CONSTRUCTION (a cluster's control plane, NOT per-record data), so even a
/// large cluster's snapshot is a few KiB; this 60 KiB cap holds a control plane with thousands of
/// placements/members/config entries with generous headroom, and stays under the slot's `u16`
/// length field (65535) so a snapshot at the cap still frames. The snapshot is persisted to BOTH
/// slots alternately with the SAME dual-slot CRC discipline as the other checkpoints, so a crash
/// mid-write reverts to the prior durable snapshot — NEVER a torn one — which (paired with the
/// retained log tail) is what makes metadata compaction crash-safe (#660 non-negotiable 3).
pub const METADATA_SNAPSHOT_PAYLOAD: usize = 60 * 1024;

/// The per-slot payload cap for the shared-WAL REAP (demux-floor) checkpoint (#597 wiring): the
/// `(logical earliest shared offset, {stream -> reaped-record base count})` snapshot the shared-WAL
/// global retention reap writes (and fsyncs) BEFORE any segment is unlinked, so a restart rebuilds
/// each stream's per-stream POSITIONS exactly even though the reaped prefix's tagged records are
/// gone. Each entry is `2 + stream name (<= 64) + 8` bytes, at most 74 bytes; this 60 KiB cap
/// (the slot `u16` length field bounds a payload at 65535 bytes, like the other large checkpoints)
/// holds ~830 worst-case entries and several thousand with typical short names. Unlike the tolerant
/// checkpoints above, this payload is LOAD-BEARING for demux correctness, so an
/// undecodable-but-CRC-valid payload fails the open closed (see `ironbus_storage::shared_wal`); the
/// dual-slot discipline still means a TORN write reverts to the prior durable snapshot, which is
/// always consistent because the matching unlink only ever runs AFTER its snapshot is durable. A
/// snapshot that would exceed the cap is NOT written and the reap simply does not advance past its
/// current floor (retention stalls, bounded and documented — never a torn or truncated snapshot).
pub const SHARED_WAL_REAP_PAYLOAD: usize = 60 * 1024;

/// The per-slot payload cap for the durable subject->stream BINDING TABLE checkpoint (#1106): the
/// full `(pattern -> stream)` registry, rewritten and fsynced on EVERY binding mutation BEFORE the
/// `BindSubject` ack, so an acked bind always survives a restart. Bindings mutate rarely (a bind is
/// an admin-scoped routing declaration, and no unbind verb exists yet, so the table only grows), so
/// the full-table rewrite costs nothing at bind frequency and buys the simplest possible recovery:
/// decode one snapshot, rebuild the trie once. Each entry is `4 + pattern + 4 + stream name (<= 64)`
/// bytes — the codec length-prefixes BOTH the pattern and the stream name with a `u32`, so 8 bytes of
/// per-entry framing over a 9-byte-minimum entry (a 1-byte pattern bound to the default `""` stream).
/// After the 5-byte header (a version byte + a `u32` entry count), this 60 KiB cap (under the slot's
/// `u16` length field, like the other large checkpoints) holds ~6.8k worst-case minimal entries and
/// ~1400-1600 typical ones (a ~20-byte pattern + a ~12-byte stream name). Unlike the tolerant
/// cursor checkpoints, this payload is LOAD-BEARING for routing correctness (an acked bind silently
/// dropped would re-open the exact NoStream-after-restart gap #1106 closes), so a
/// CRC-valid-but-undecodable snapshot fails the open closed (see `ironbus-server`'s engine open);
/// the dual-slot discipline still means a TORN (never-acked) write reverts to the prior durable
/// table. A bind whose resulting snapshot would exceed the cap is REFUSED fail-closed with a typed
/// error and the previous table stays installed — never a torn or truncated snapshot.
pub const BINDINGS_PAYLOAD: usize = 60 * 1024;

/// The per-slot payload cap for the durable per-log COLD-SEGMENT MANIFEST (#643, V2-M10 tiered
/// storage): the set of offloaded sealed segments and their fetch-verification metadata, rewritten
/// and fsynced on every offload (BEFORE the local file is deleted) and every reap of a remote
/// segment. Each entry is a fixed 53 bytes (six `u64` fields + a `u32` CRC + a flags byte) after a
/// 9-byte header (magic + version + `u32` count), so this 60 KiB cap (under the slot's `u16` length
/// field like the other large checkpoints) holds ~1150 offloaded segments — at a 64 MiB default
/// segment size, ~70 GiB of tiered data per log. Like the shared-WAL reap floor and the binding
/// table (and UNLIKE the tolerant cursor family) the payload is LOAD-BEARING: an acked REMOTE
/// transition that a restart could not read back would strand a local-deleted segment, so a
/// CRC-valid-but-undecodable snapshot fails the log open closed (see [`crate::cold::ColdManifest`]);
/// the dual-slot discipline still reverts a TORN write to the prior durable manifest, which is
/// always consistent because a local file is unlinked only AFTER its manifest entry is durable. An
/// offload whose resulting manifest would exceed the cap is REFUSED fail-closed and the offload
/// simply does not advance — never a torn or truncated manifest.
pub const COLD_MANIFEST_PAYLOAD: usize = 60 * 1024;

const SEQ_LEN: usize = 8;
const LEN_LEN: usize = 2;
const CRC_LEN: usize = 4;
/// The fixed per-slot framing overhead (sequence + payload length + CRC), so a slot is
/// `SLOT_OVERHEAD + PAYLOAD_CAP` bytes.
const SLOT_OVERHEAD: usize = SEQ_LEN + LEN_LEN + CRC_LEN;

/// The classification of a single slot (#1142). The key distinction the old `Option` lacked is
/// [`SlotDecode::Corrupt`] vs [`SlotDecode::Empty`]: a slot carrying a NONZERO sequence but failing
/// its length bound or CRC was WRITTEN (so its corruption is meaningful), whereas a zero-sequence or
/// short slot was never written. That separation is what lets [`SlotCheckpoint::open`] distinguish
/// provable external damage (both slots `Corrupt`) from a fresh/torn-first file.
enum SlotDecode {
    /// Never written: a zero sequence, or a slot from a short/truncated file.
    Empty,
    /// Written (nonzero sequence) but invalid: an out-of-range length or a CRC mismatch. A torn or
    /// bit-rotted slot.
    Corrupt,
    /// A fully valid slot: `(sequence, payload)`.
    Valid(u64, Vec<u8>),
}

/// Reads `[seq, len, payload]` from a `CAP`-payload slot and classifies it. A nonzero sequence, an
/// in-range length, and a matching CRC over the meaningful bytes is [`SlotDecode::Valid`]; a zero
/// sequence or short slot is [`SlotDecode::Empty`] (never written); a nonzero sequence that then
/// fails its length bound or CRC is [`SlotDecode::Corrupt`] (written but torn/damaged).
fn decode_slot<const CAP: usize>(slot: &[u8]) -> SlotDecode {
    if slot.len() != SLOT_OVERHEAD + CAP {
        return SlotDecode::Empty; // a short/truncated file: treat as never-written
    }
    let seq = u64::from_le_bytes(slot[0..SEQ_LEN].try_into().expect("SEQ_LEN bytes present"));
    if seq == 0 {
        return SlotDecode::Empty; // sequence 0 means "never written"
    }
    // The slot carries a nonzero sequence, so it WAS written: any failure below is a written-but-
    // invalid (Corrupt) slot, distinct from a never-written one.
    let len = usize::from(u16::from_le_bytes(
        slot[SEQ_LEN..SEQ_LEN + LEN_LEN]
            .try_into()
            .expect("LEN_LEN bytes present"),
    ));
    if len > CAP {
        return SlotDecode::Corrupt;
    }
    let payload_start = SEQ_LEN + LEN_LEN;
    let crc_start = payload_start + CAP;
    let stored_crc = u32::from_le_bytes(
        slot[crc_start..crc_start + CRC_LEN]
            .try_into()
            .expect("CRC_LEN bytes present"),
    );
    // The CRC covers the sequence, the length field, and the meaningful payload bytes
    // (the padding and the CRC field itself are excluded).
    if crc32c::crc32c(&slot[0..payload_start + len]) != stored_crc {
        return SlotDecode::Corrupt;
    }
    SlotDecode::Valid(seq, slot[payload_start..payload_start + len].to_vec())
}

fn encode_slot<const CAP: usize>(seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut slot = vec![0u8; SLOT_OVERHEAD + CAP];
    slot[0..SEQ_LEN].copy_from_slice(&seq.to_le_bytes());
    // payload.len() <= CAP is guaranteed by the caller, so this conversion fits.
    debug_assert!(payload.len() <= CAP, "encode_slot payload over cap");
    let len = payload.len();
    let len_field = u16::try_from(len).unwrap_or(u16::MAX);
    slot[SEQ_LEN..SEQ_LEN + LEN_LEN].copy_from_slice(&len_field.to_le_bytes());
    let payload_start = SEQ_LEN + LEN_LEN;
    slot[payload_start..payload_start + len].copy_from_slice(payload);
    let crc = crc32c::crc32c(&slot[0..payload_start + len]);
    let crc_start = payload_start + CAP;
    slot[crc_start..crc_start + CRC_LEN].copy_from_slice(&crc.to_le_bytes());
    slot
}

/// A two-slot crash-safe checkpoint over a [`RandomAccessFile`], with a const-generic per-slot
/// payload cap (`PAYLOAD_CAP`). Two concrete aliases are exported: [`Checkpoint`] (the cursor
/// checkpoint, [`MAX_PAYLOAD`]) and [`CountersCheckpoint`] (the resilience-counters checkpoint,
/// [`COUNTERS_PAYLOAD`], #98). Pinning the cap through an alias keeps every call site free of an
/// explicit const generic, so `Checkpoint::open` infers exactly as before the cap became generic.
#[derive(Debug)]
pub struct SlotCheckpoint<F: RandomAccessFile, const PAYLOAD_CAP: usize> {
    file: F,
    next_seq: u64,
}

/// The crash-safe checkpoint for the committed consumer cursor (the historical checkpoint): a
/// [`MAX_PAYLOAD`]-per-slot [`SlotCheckpoint`].
pub type Checkpoint<F> = SlotCheckpoint<F, MAX_PAYLOAD>;

/// The crash-safe checkpoint for the resilience COUNTERS (#98): a [`COUNTERS_PAYLOAD`]-per-slot
/// [`SlotCheckpoint`]. It is an OBSERVABILITY aid only: a torn or missing snapshot recovers as
/// all-zeros and never blocks broker startup or touches the durable log, cursors, or DLQ.
pub type CountersCheckpoint<F> = SlotCheckpoint<F, COUNTERS_PAYLOAD>;

/// The crash-safe checkpoint for the durable per-message ATTEMPT-COUNT map (#358): an
/// [`ATTEMPTS_PAYLOAD`]-per-slot [`SlotCheckpoint`]. It reuses the identical dual-slot CRC
/// discipline as the cursor and counters checkpoints, so a torn write reverts to the prior slot and
/// a torn or missing snapshot recovers as "no carried counts" (every in-flight message resumes at
/// attempt 1, the pre-#358 behavior) without ever blocking startup.
pub type AttemptsCheckpoint<F> = SlotCheckpoint<F, ATTEMPTS_PAYLOAD>;

/// The crash-safe checkpoint for the durable idempotent-producer SEQUENCE high-water map (V2-M8,
/// #638/#639): a [`PRODUCER_SEQ_PAYLOAD`]-per-slot [`SlotCheckpoint`]. It reuses the identical
/// dual-slot CRC discipline as the cursor, counters, and attempt-count checkpoints — a torn write
/// reverts to the prior slot and a torn or missing snapshot recovers as "no carried high-waters"
/// (every producer resumes at-least-once, the safe degrade) without ever blocking startup. Restoring
/// it is what makes a replayed retry across a broker restart STILL deduped, and because the bound is
/// SEQUENCE state (not wall-clock), a long offline gap never drops it — the beat over NATS.
pub type ProducerSeqCheckpoint<F> = SlotCheckpoint<F, PRODUCER_SEQ_PAYLOAD>;

/// The crash-safe checkpoint for the durable METADATA-RAFT SNAPSHOT (V2-C1, #660): a
/// [`METADATA_SNAPSHOT_PAYLOAD`]-per-slot [`SlotCheckpoint`]. It reuses the identical dual-slot CRC
/// discipline as the cursor, counters, attempt-count, and producer-seq checkpoints — a torn write
/// reverts to the prior durable snapshot and a torn or missing one recovers as "no snapshot" (the
/// node then recovers purely from the full retained log, the pre-#660 behavior) without ever
/// blocking startup. Persisting the snapshot here BEFORE the metadata log prefix is truncated is
/// what makes compaction crash-safe: a crash mid-compaction leaves either the prior snapshot + the
/// full log, or the new snapshot + the (un-truncated or truncated) log — never a gap where neither
/// holds the committed state.
pub type MetadataSnapshotCheckpoint<F> = SlotCheckpoint<F, METADATA_SNAPSHOT_PAYLOAD>;

/// The crash-safe checkpoint for the shared-WAL REAP (demux-floor) snapshot (#597 wiring): a
/// [`SHARED_WAL_REAP_PAYLOAD`]-per-slot [`SlotCheckpoint`]. The write-then-unlink discipline (the
/// snapshot is fsynced BEFORE any shared-log segment is unlinked) is what keeps every stream's
/// per-stream positions exact across a crash anywhere in a global reap; see
/// [`crate::shared_wal::SharedWal`].
pub type SharedWalReapCheckpoint<F> = SlotCheckpoint<F, SHARED_WAL_REAP_PAYLOAD>;

/// The crash-safe checkpoint for the durable subject->stream BINDING TABLE (#1106): a
/// [`BINDINGS_PAYLOAD`]-per-slot [`SlotCheckpoint`]. It reuses the identical dual-slot CRC
/// discipline as the other checkpoints — a torn (never-acked) write reverts to the prior durable
/// table — but, like the shared-WAL reap checkpoint and UNLIKE the tolerant cursor family, its
/// payload is LOAD-BEARING routing state: the write-then-ack discipline (the snapshot is fsynced
/// BEFORE the `BindSubject` ack) is what guarantees an acked bind still routes after a restart, so
/// a CRC-valid-but-undecodable snapshot fails the engine open closed rather than silently emptying
/// the routing table.
pub type BindingsCheckpoint<F> = SlotCheckpoint<F, BINDINGS_PAYLOAD>;

/// The crash-safe checkpoint for the durable per-log COLD-SEGMENT MANIFEST (#643, V2-M10 tiered
/// storage): a [`COLD_MANIFEST_PAYLOAD`]-per-slot [`SlotCheckpoint`]. It reuses the identical
/// dual-slot CRC discipline as the other checkpoints — a torn (never-committed) write reverts to the
/// prior durable manifest — and, like [`BindingsCheckpoint`], its payload is LOAD-BEARING: the
/// write-then-delete discipline (the manifest records a segment REMOTE and is fsynced BEFORE its
/// local file is unlinked) is what guarantees an offloaded segment is never stranded across a crash.
pub type ColdManifestCheckpoint<F> = SlotCheckpoint<F, COLD_MANIFEST_PAYLOAD>;

/// The classification a checkpoint file receives on [`SlotCheckpoint::open`] (#1142): the tri-state
/// that separates a value that recovered, a checkpoint that was never durably written, and one that
/// is EXTERNALLY DAMAGED (bit rot / a lost extent), which the old two-state `Option` collapsed into
/// the same `None` as a fresh file.
///
/// The distinction is provable from the dual-slot crash model. Each [`SlotCheckpoint::write`] touches
/// exactly one slot (`slot = seq % 2`), so a crash mid-write tears AT MOST one slot; its sibling stays
/// either durable-valid or zero-sequence ("never written"). Therefore:
/// - a torn slot with a valid sibling recovers the sibling → [`RecoveredCheckpoint::Valid`];
/// - a torn FIRST write (one corrupt slot, the other still zero-sequence) → [`RecoveredCheckpoint::Empty`]
///   (a legitimate crash outcome, NOT damage);
/// - BOTH slots carrying a nonzero sequence yet BOTH failing their CRC is impossible from any crash,
///   so it is provably external damage → [`RecoveredCheckpoint::Damaged`].
///
/// `Damaged` is DETECTABLE (distinguishable from a fresh/absent file) but, per #1142, non-fatal by
/// default: the caller surfaces it (a `warn!` + the `ironbus_checkpoint_damaged_total{artifact}`
/// counter via [`record_checkpoint_damage`]) and then recovers as empty, turning a formerly SILENT
/// empty-recovery into a LOUD, observable data-availability event without turning it into a
/// broker-won't-start regression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveredCheckpoint {
    /// A fully-valid slot recovered this payload (the highest durable sequence).
    Valid(Vec<u8>),
    /// No slot was ever durably written: a fresh, absent, or short file, OR exactly one slot torn by
    /// a crash with no valid sibling (a torn first write). Recover as empty; NOT an error, no warning.
    Empty,
    /// Both slots carry a nonzero sequence yet both fail their CRC — impossible from any crash, so
    /// EXTERNAL damage. Surfaced (warn + metric) and then recovered as empty by the caller.
    Damaged,
}

impl RecoveredCheckpoint {
    /// The recovered payload if a valid slot was found, else `None`. Both `Empty` and `Damaged` map
    /// to `None` (the pre-#1142 behavior), so a call site that only needs the value — and observes
    /// damage separately, or is a write-handle re-open where a prior read already observed it — reads
    /// exactly as before.
    #[must_use]
    pub fn into_option(self) -> Option<Vec<u8>> {
        match self {
            RecoveredCheckpoint::Valid(payload) => Some(payload),
            RecoveredCheckpoint::Empty | RecoveredCheckpoint::Damaged => None,
        }
    }

    /// Whether the file was classified as externally damaged (both slots nonzero-seq, both CRC-bad).
    #[must_use]
    pub fn is_damaged(&self) -> bool {
        matches!(self, RecoveredCheckpoint::Damaged)
    }
}

/// The bounded, append-only vocabulary of on-disk checkpoint artifacts, for the
/// `ironbus_checkpoint_damaged_total{artifact}` counter (#1142). One label per [`SlotCheckpoint`]
/// consumer, mirroring the frozen [`crate::loss::ReasonCode`]-style discipline: a new variant goes at
/// the END so the counter-array index order never shifts. The label strings are frozen alongside the
/// metric name (a rename is a gated taxonomy change).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointArtifact {
    /// A consumer-cursor checkpoint (`cursor.ckpt` / `cursor-<hex>.ckpt`).
    Cursor,
    /// A durable per-message attempt-count checkpoint (`attempts*.ckpt`, #358).
    Attempts,
    /// The resilience-counters observability checkpoint (`counters.ckpt`, #98).
    Counters,
    /// The idempotent-producer sequence high-water checkpoint (`producer-seq.ckpt`, V2-M8).
    ProducerSeq,
    /// The metadata-raft snapshot checkpoint (`metadata snapshot`, V2-C1).
    MetadataSnapshot,
    /// The shared-WAL reap (demux-floor) checkpoint (`reap.ckpt`, #597).
    SharedWalReap,
    /// The subject->stream binding-table checkpoint (`bindings.ckpt`, #1106).
    Bindings,
    /// The geo/leaf origin-replication cursor checkpoint (`OriginCursorStore`, cluster).
    GeoCursor,
    /// The per-log cold-segment manifest checkpoint (`cold-manifest.ckpt`, #643 tiered storage).
    ColdManifest,
}

impl CheckpointArtifact {
    /// Every artifact in a fixed order; the index into the damage-counter array. Append-only.
    pub const ALL: [CheckpointArtifact; 9] = [
        CheckpointArtifact::Cursor,
        CheckpointArtifact::Attempts,
        CheckpointArtifact::Counters,
        CheckpointArtifact::ProducerSeq,
        CheckpointArtifact::MetadataSnapshot,
        CheckpointArtifact::SharedWalReap,
        CheckpointArtifact::Bindings,
        CheckpointArtifact::GeoCursor,
        CheckpointArtifact::ColdManifest,
    ];

    /// This artifact's index into [`CheckpointArtifact::ALL`]. A total match in `ALL` order, so it is
    /// infallible and stays in sync with the array.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            CheckpointArtifact::Cursor => 0,
            CheckpointArtifact::Attempts => 1,
            CheckpointArtifact::Counters => 2,
            CheckpointArtifact::ProducerSeq => 3,
            CheckpointArtifact::MetadataSnapshot => 4,
            CheckpointArtifact::SharedWalReap => 5,
            CheckpointArtifact::Bindings => 6,
            CheckpointArtifact::GeoCursor => 7,
            CheckpointArtifact::ColdManifest => 8,
        }
    }

    /// The frozen Prometheus `artifact` label value.
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            CheckpointArtifact::Cursor => "cursor",
            CheckpointArtifact::Attempts => "attempts",
            CheckpointArtifact::Counters => "counters",
            CheckpointArtifact::ProducerSeq => "producer_seq",
            CheckpointArtifact::MetadataSnapshot => "metadata_snapshot",
            CheckpointArtifact::SharedWalReap => "shared_wal_reap",
            CheckpointArtifact::Bindings => "bindings",
            CheckpointArtifact::GeoCursor => "geo_cursor",
            CheckpointArtifact::ColdManifest => "cold_manifest",
        }
    }
}

/// The process-wide, monotonic `ironbus_checkpoint_damaged_total{artifact}` counter store (#1142),
/// one cell per [`CheckpointArtifact`]. Damage is detected at OPEN time, spread across several crates
/// (the engine, the shared WAL, the cluster origin cursors, the metadata store), so a process-global
/// is the low-coupling place to accumulate it without threading a return through every open signature;
/// it is exactly Prometheus counter semantics (a monotonic, process-lifetime total for the one broker
/// this process is). It is NOT part of any durable snapshot, so the on-disk formats are unchanged.
// Nine explicit cells (MSRV 1.78 predates inline-const array repeat).
static CHECKPOINT_DAMAGED: [core::sync::atomic::AtomicU64; CheckpointArtifact::ALL.len()] = [
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
    core::sync::atomic::AtomicU64::new(0),
];

/// Records one externally-damaged-checkpoint detection for `artifact`, bumping the monotonic
/// `ironbus_checkpoint_damaged_total{artifact}` counter (#1142). Saturating; safe to call from any
/// crate/thread on the recovery-read path.
pub fn record_checkpoint_damage(artifact: CheckpointArtifact) {
    CHECKPOINT_DAMAGED[artifact.index()].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// The current `ironbus_checkpoint_damaged_total{artifact}` value for `artifact` (#1142), for the
/// `/metrics` render and tests.
#[must_use]
pub fn checkpoint_damaged_total(artifact: CheckpointArtifact) -> u64 {
    CHECKPOINT_DAMAGED[artifact.index()].load(core::sync::atomic::Ordering::Relaxed)
}

/// Resets the damage counters to zero. Test-only: the store is a process-global, so a test that
/// asserts an ABSOLUTE damage count resets first (parallel tests otherwise accumulate). Prefer a
/// read-delta assertion where possible.
#[cfg(test)]
pub fn reset_checkpoint_damage() {
    for cell in &CHECKPOINT_DAMAGED {
        cell.store(0, core::sync::atomic::Ordering::Relaxed);
    }
}

impl<F: RandomAccessFile, const PAYLOAD_CAP: usize> SlotCheckpoint<F, PAYLOAD_CAP> {
    /// Bytes per slot for this cap: sequence, payload length, payload, CRC.
    const SLOT_LEN: usize = SLOT_OVERHEAD + PAYLOAD_CAP;
    /// The whole checkpoint file is two slots.
    const FILE_LEN: u64 = (Self::SLOT_LEN * 2) as u64;

    /// Opens a checkpoint file, reading both slots to CLASSIFY it (#1142): the higher-sequence valid
    /// slot recovers as [`RecoveredCheckpoint::Valid`]; a fresh/absent/short file — or a torn first
    /// write with no valid sibling — recovers as [`RecoveredCheckpoint::Empty`]; and a file whose BOTH
    /// slots carry a nonzero sequence yet BOTH fail their CRC recovers as [`RecoveredCheckpoint::Damaged`]
    /// (provable external damage — impossible from any crash, since a write touches one slot).
    ///
    /// The caller owns the file's existence: it must create the file (e.g. via
    /// [`crate::fs::Filesystem::create_new`]) and fsync the parent directory (so the file
    /// survives a power loss right after creation) before opening it here.
    ///
    /// # Errors
    /// Propagates an IO error.
    pub fn open(
        file: F,
    ) -> Result<(SlotCheckpoint<F, PAYLOAD_CAP>, RecoveredCheckpoint), StorageError> {
        let slot_len = Self::SLOT_LEN;
        let len = file.len()?;
        let mut buf = vec![0u8; slot_len * 2];
        if len >= Self::FILE_LEN {
            file.read_exact_at(&mut buf, 0)?;
        }
        let a = decode_slot::<PAYLOAD_CAP>(&buf[0..slot_len]);
        let b = decode_slot::<PAYLOAD_CAP>(&buf[slot_len..slot_len * 2]);
        // Whether each slot was WRITTEN-but-invalid, captured before the by-value match consumes them.
        // Both slots corrupt is the external-damage signature (see below).
        let both_corrupt = matches!(a, SlotDecode::Corrupt) && matches!(b, SlotDecode::Corrupt);
        // The higher valid sequence wins; a torn slot with a valid sibling recovers the sibling.
        let best = match (a, b) {
            (SlotDecode::Valid(sa, pa), SlotDecode::Valid(sb, pb)) => {
                if sa >= sb {
                    Some((sa, pa))
                } else {
                    Some((sb, pb))
                }
            }
            (SlotDecode::Valid(s, p), _) | (_, SlotDecode::Valid(s, p)) => Some((s, p)),
            _ => None,
        };
        let (next_seq, recovered) = if let Some((seq, payload)) = best {
            (
                seq.checked_add(1).ok_or(StorageError::SegmentFull)?,
                RecoveredCheckpoint::Valid(payload),
            )
        } else {
            // No valid slot. Each `write` touches exactly one slot (`slot = seq % 2`), so a crash
            // tears AT MOST one slot while its sibling stays durable-valid or zero-sequence. Both
            // slots carrying a nonzero sequence yet both failing CRC is therefore IMPOSSIBLE from any
            // crash — it is provable external damage (bit rot / a lost extent), and is distinguishable
            // from a fresh/absent file or a torn first write (one corrupt slot, one still zero-seq),
            // which stay `Empty`. Damage recovers as empty here too (the caller surfaces it loudly);
            // `next_seq` starts at 1 so the next two writes heal both slots.
            let recovered = if both_corrupt {
                RecoveredCheckpoint::Damaged
            } else {
                RecoveredCheckpoint::Empty
            };
            (1, recovered)
        };
        Ok((SlotCheckpoint { file, next_seq }, recovered))
    }

    /// Durably writes a new checkpoint payload (fsync). The previous value remains intact
    /// in the other slot until this one is durable, so a crash mid-write never loses it.
    ///
    /// # Errors
    /// Returns [`StorageError::Segment`] with [`SegmentError::Truncated`] if the payload
    /// exceeds `PAYLOAD_CAP`, or an IO error.
    pub fn write(&mut self, payload: &[u8]) -> Result<(), StorageError> {
        if payload.len() > PAYLOAD_CAP {
            return Err(StorageError::Segment(SegmentError::Truncated));
        }
        let seq = self.next_seq;
        let slot_index = seq % 2;
        let offset = slot_index * Self::SLOT_LEN as u64;
        let slot = encode_slot::<PAYLOAD_CAP>(seq, payload);
        self.file.write_all_at(&slot, offset)?;
        self.file.sync_all()?;
        self.next_seq = seq.checked_add(1).ok_or(StorageError::SegmentFull)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::InMemoryFile;
    use proptest::prelude::*;
    use std::sync::Arc;

    // These tests exercise the DEFAULT (cursor) payload cap, so they bind the const-generic slot
    // helpers and length constants at `MAX_PAYLOAD` for the byte-offset arithmetic below.
    const SLOT_LEN: usize = SLOT_OVERHEAD + MAX_PAYLOAD;
    const CHECKPOINT_LEN: u64 = (SLOT_LEN * 2) as u64;

    fn decode_slot(slot: &[u8]) -> Option<(u64, Vec<u8>)> {
        match super::decode_slot::<MAX_PAYLOAD>(slot) {
            SlotDecode::Valid(seq, payload) => Some((seq, payload)),
            SlotDecode::Empty | SlotDecode::Corrupt => None,
        }
    }

    fn encode_slot(seq: u64, payload: &[u8]) -> Vec<u8> {
        super::encode_slot::<MAX_PAYLOAD>(seq, payload)
    }

    fn fresh() -> Arc<InMemoryFile> {
        Arc::new(InMemoryFile::new())
    }

    fn reopen(file: &Arc<InMemoryFile>) -> Option<Vec<u8>> {
        let cp: (Checkpoint<Arc<InMemoryFile>>, _) = Checkpoint::open(Arc::clone(file)).unwrap();
        cp.1.into_option()
    }

    /// The tri-state classification a reopen produces, for the #1142 damage tests.
    fn reopen_state(file: &Arc<InMemoryFile>) -> RecoveredCheckpoint {
        let cp: (Checkpoint<Arc<InMemoryFile>>, _) = Checkpoint::open(Arc::clone(file)).unwrap();
        cp.1
    }

    #[test]
    fn a_fresh_checkpoint_recovers_nothing() {
        assert_eq!(reopen(&fresh()), None);
    }

    #[test]
    fn write_then_reopen_round_trips() {
        let file = fresh();
        let (mut cp, recovered) = Checkpoint::open(Arc::clone(&file)).unwrap();
        assert_eq!(recovered, RecoveredCheckpoint::Empty);
        cp.write(b"hello").unwrap();
        assert_eq!(reopen(&file), Some(b"hello".to_vec()));
    }

    #[test]
    fn the_latest_of_several_writes_wins() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        for v in [&b"one"[..], b"two", b"three", b"four"] {
            cp.write(v).unwrap();
        }
        assert_eq!(reopen(&file), Some(b"four".to_vec()));
    }

    #[test]
    fn an_empty_payload_round_trips() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"").unwrap();
        assert_eq!(reopen(&file), Some(Vec::new()));
    }

    #[test]
    fn a_payload_over_the_cap_is_rejected() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        let big = vec![0u8; MAX_PAYLOAD + 1];
        assert!(matches!(
            cp.write(&big),
            Err(StorageError::Segment(SegmentError::Truncated))
        ));
    }

    #[test]
    fn a_torn_newest_slot_falls_back_to_the_previous_value() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"first").unwrap(); // seq 1 -> slot 1
        cp.write(b"second").unwrap(); // seq 2 -> slot 0
                                      // Corrupt slot 0 (the newest, seq 2): flip a payload byte.
        let mut bytes = file.snapshot();
        bytes[SEQ_LEN + LEN_LEN] ^= 0xff;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        // Recovery regresses to the previous durable value, never a torn one.
        assert_eq!(reopen(&file), Some(b"first".to_vec()));
    }

    #[test]
    fn both_slots_corrupt_is_detected_as_external_damage() {
        // Both slots carry a nonzero sequence (seq 1 and seq 2) yet both fail CRC. A crash tears at
        // most one slot, so this is IMPOSSIBLE from any crash — it is provable external damage (#1142).
        // It is DETECTED as `Damaged` (distinct from a fresh file's `Empty`) yet still recovers as
        // empty via `into_option`, preserving the pre-#1142 control flow.
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"a").unwrap(); // seq 1 -> slot 1
        cp.write(b"b").unwrap(); // seq 2 -> slot 0
        let mut bytes = file.snapshot();
        // Corrupt a CRC-covered payload byte in BOTH slots.
        bytes[SEQ_LEN + LEN_LEN] ^= 0xff;
        bytes[SLOT_LEN + SEQ_LEN + LEN_LEN] ^= 0xff;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(reopen_state(&file), RecoveredCheckpoint::Damaged);
        assert_eq!(reopen(&file), None, "damage still recovers as empty");
    }

    #[test]
    fn a_torn_first_write_is_empty_not_damaged() {
        // The crash-model corner the loose "any corrupt slot" rule would false-alarm on: the FIRST
        // write (seq 1 -> slot 1) is torn by a crash, leaving slot 1 corrupt and slot 0 still
        // zero-sequence (never written). This is a LEGITIMATE crash outcome, so it MUST classify as
        // `Empty`, NOT `Damaged` — else a real power loss during the first checkpoint would raise a
        // false external-damage alarm (#1142).
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"only").unwrap(); // seq 1 -> slot 1; slot 0 stays all-zero
        let mut bytes = file.snapshot();
        // Corrupt slot 1 (the only written slot); slot 0 remains zero-sequence.
        bytes[SLOT_LEN + SEQ_LEN + LEN_LEN] ^= 0xff;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(
            reopen_state(&file),
            RecoveredCheckpoint::Empty,
            "a torn first write with a zero-seq sibling is Empty, never Damaged"
        );
    }

    #[test]
    fn a_torn_single_slot_with_a_valid_sibling_is_valid_not_damaged() {
        // Two durable writes, then ONE slot torn (the crash model's at-most-one-torn invariant). The
        // valid sibling must recover as `Valid` — never `Damaged` — so a real crash never trips the
        // external-damage signal.
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"first").unwrap(); // seq 1 -> slot 1
        cp.write(b"second").unwrap(); // seq 2 -> slot 0
        let mut bytes = file.snapshot();
        bytes[SEQ_LEN + LEN_LEN] ^= 0xff; // corrupt only slot 0 (the newest)
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(
            reopen_state(&file),
            RecoveredCheckpoint::Valid(b"first".to_vec()),
            "a torn single slot recovers its valid sibling, never Damaged"
        );
    }

    #[test]
    fn an_absent_or_fresh_file_is_empty_not_damaged() {
        // A brand-new (absent/zero-length) file, and a freshly-created zero-seq file, both classify
        // as `Empty` with no warning — the never-false-alarm floor.
        assert_eq!(reopen_state(&fresh()), RecoveredCheckpoint::Empty);
        let file = fresh();
        // Materialize a full-size all-zero file (both slots zero-sequence), as create+truncate would.
        file.write_all_at(&[0u8; SLOT_LEN * 2], 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(reopen_state(&file), RecoveredCheckpoint::Empty);
    }

    #[test]
    fn the_damage_counter_is_bumped_per_artifact() {
        // The `ironbus_checkpoint_damaged_total{artifact}` counter increments once per recorded
        // damage, per artifact. A read-delta assertion, robust against the process-global being
        // touched by other tests running in parallel.
        let before = checkpoint_damaged_total(CheckpointArtifact::Bindings);
        record_checkpoint_damage(CheckpointArtifact::Bindings);
        record_checkpoint_damage(CheckpointArtifact::Bindings);
        assert_eq!(
            checkpoint_damaged_total(CheckpointArtifact::Bindings),
            before + 2
        );
        // Distinct artifacts count independently.
        let cursor_before = checkpoint_damaged_total(CheckpointArtifact::Cursor);
        record_checkpoint_damage(CheckpointArtifact::Cursor);
        assert_eq!(
            checkpoint_damaged_total(CheckpointArtifact::Cursor),
            cursor_before + 1
        );
    }

    #[test]
    fn every_artifact_label_is_distinct_and_indexed() {
        // The frozen taxonomy invariant: `ALL` order matches `index()`, and every label is unique.
        for (i, artifact) in CheckpointArtifact::ALL.iter().enumerate() {
            assert_eq!(artifact.index(), i);
        }
        let mut labels: Vec<&str> = CheckpointArtifact::ALL
            .iter()
            .map(|a| a.metric_label())
            .collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), CheckpointArtifact::ALL.len());
    }

    #[test]
    fn power_loss_on_an_unsynced_write_falls_back_to_the_prior_durable_slot() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"v1").unwrap(); // seq 1 -> slot 1, synced
        cp.write(b"v2").unwrap(); // seq 2 -> slot 0, synced
                                  // An in-flight seq-3 write to its alternating slot (slot 1), NOT synced.
        let in_flight = encode_slot(3, b"v3-lost");
        file.write_all_at(&in_flight, SLOT_LEN as u64).unwrap(); // seq 3 -> slot 1
        file.simulate_power_loss();
        // The lost write reverts slot 1 to its durable seq-1 value; recovery picks the
        // higher durable sequence (slot 0, seq 2), exercising the real fallback.
        assert_eq!(reopen(&file), Some(b"v2".to_vec()));
    }

    #[test]
    fn consecutive_writes_alternate_slots() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"s1").unwrap(); // seq 1 -> slot 1
        cp.write(b"s2").unwrap(); // seq 2 -> slot 0
        let bytes = file.snapshot();
        // The two writes landed in DIFFERENT slots (so one torn write never destroys both).
        assert_eq!(decode_slot(&bytes[0..SLOT_LEN]), Some((2, b"s2".to_vec())));
        assert_eq!(
            decode_slot(&bytes[SLOT_LEN..SLOT_LEN * 2]),
            Some((1, b"s1".to_vec()))
        );
    }

    #[test]
    fn a_max_size_payload_round_trips() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        let payload = vec![0x5a; MAX_PAYLOAD];
        cp.write(&payload).unwrap();
        assert_eq!(reopen(&file), Some(payload));
    }

    #[test]
    fn a_corrupted_length_field_is_rejected() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"value").unwrap(); // seq 1 -> slot 1
        let mut bytes = file.snapshot();
        bytes[SLOT_LEN + SEQ_LEN] ^= 0xff; // flip the length field in slot 1
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(
            reopen(&file),
            None,
            "a tampered length fails the CRC or the bound"
        );
    }

    #[test]
    fn a_corrupted_sequence_is_rejected() {
        let file = fresh();
        let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
        cp.write(b"value").unwrap(); // seq 1 -> slot 1
        let mut bytes = file.snapshot();
        bytes[SLOT_LEN + 1] ^= 0xff; // flip a high sequence byte in slot 1 (CRC covers seq)
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(reopen(&file), None);
    }

    proptest! {
        /// Arbitrary single-byte corruption anywhere in the checkpoint file can only LOSE
        /// the cursor or return a genuinely-written value, never fabricate one. For any short
        /// run of writes followed by one flipped byte at an arbitrary offset (which lands in
        /// the payload region for some inputs and the seq/len/crc region for others, so the
        /// corruption-tolerance logic is reached across the input space), `Checkpoint::open`
        /// must not panic and must return either `None` or a payload byte-equal to one that
        /// was actually written. A torn, partial, or invented payload is a failure.
        #[test]
        fn single_byte_corruption_never_fabricates_a_payload(
            payloads in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 0..=MAX_PAYLOAD),
                1..6,
            ),
            idx in any::<prop::sample::Index>(),
            xor in 1u8..=255,
        ) {
            let file = fresh();
            let (mut cp, _) = Checkpoint::open(Arc::clone(&file)).unwrap();
            for p in &payloads {
                cp.write(p).unwrap();
            }

            // Flip one byte at an arbitrary offset anywhere in the fixed-size file.
            let mut bytes = file.snapshot();
            prop_assert_eq!(bytes.len() as u64, CHECKPOINT_LEN);
            let pos = idx.index(bytes.len());
            bytes[pos] ^= xor;
            file.set_len(0).unwrap();
            file.write_all_at(&bytes, 0).unwrap();
            file.sync_data().unwrap();

            // open must not panic; whatever it returns must be a value we actually wrote, and a
            // SINGLE-byte flip must NEVER classify as external Damage — a lone flip corrupts at most
            // one slot, so the crash-model invariant (both-slots-corrupt is impossible from a crash)
            // holds and no false damage alarm can fire (#1142).
            let recovered = Checkpoint::open(Arc::clone(&file)).unwrap().1;
            prop_assert!(
                !recovered.is_damaged(),
                "a single-byte flip must not be classified as external damage",
            );
            if let Some(payload) = recovered.into_option() {
                prop_assert!(
                    payloads.iter().any(|p| p == &payload),
                    "fabricated a payload never written: {payload:?}",
                );
            }
        }
    }

    // The larger-cap counters checkpoint (#98) reuses the identical dual-slot crash-safe
    // machinery, so a handful of tests confirm the bigger slot round-trips and stays torn-safe.

    #[test]
    fn a_counters_checkpoint_round_trips_a_full_size_payload() {
        let file = fresh();
        let (mut cp, recovered) = CountersCheckpoint::open(Arc::clone(&file)).unwrap();
        assert_eq!(recovered, RecoveredCheckpoint::Empty);
        let payload = vec![0x42; COUNTERS_PAYLOAD];
        cp.write(&payload).unwrap();
        let reopened = CountersCheckpoint::open(Arc::clone(&file)).unwrap().1;
        assert_eq!(reopened.into_option(), Some(payload));
    }

    #[test]
    fn a_counters_checkpoint_over_its_cap_is_rejected() {
        let file = fresh();
        let (mut cp, _) = CountersCheckpoint::open(Arc::clone(&file)).unwrap();
        let big = vec![0u8; COUNTERS_PAYLOAD + 1];
        assert!(matches!(
            cp.write(&big),
            Err(StorageError::Segment(SegmentError::Truncated))
        ));
    }

    #[test]
    fn a_torn_counters_slot_falls_back_to_the_previous_value() {
        let file = fresh();
        let (mut cp, _) = CountersCheckpoint::open(Arc::clone(&file)).unwrap();
        cp.write(&[1u8; COUNTERS_PAYLOAD]).unwrap(); // seq 1 -> slot 1
        cp.write(&[2u8; COUNTERS_PAYLOAD]).unwrap(); // seq 2 -> slot 0
        let counters_slot_len = SLOT_OVERHEAD + COUNTERS_PAYLOAD;
        // Corrupt slot 0 (the newest, seq 2): flip a CRC-covered payload byte.
        let mut bytes = file.snapshot();
        bytes[SEQ_LEN + LEN_LEN] ^= 0xff;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        assert_eq!(bytes.len(), counters_slot_len * 2);
        // Recovery regresses to the previous durable value, never a torn one.
        assert_eq!(
            CountersCheckpoint::open(Arc::clone(&file))
                .unwrap()
                .1
                .into_option(),
            Some(vec![1u8; COUNTERS_PAYLOAD])
        );
    }

    #[test]
    fn a_fresh_counters_checkpoint_recovers_nothing() {
        let file = fresh();
        assert_eq!(
            CountersCheckpoint::open(Arc::clone(&file))
                .unwrap()
                .1
                .into_option(),
            None
        );
    }

    // The attempt-count checkpoint (#358) reuses the identical dual-slot crash-safe machinery with
    // a still-larger slot, so a handful of tests confirm the big slot round-trips and stays
    // torn-safe, exactly as the counters checkpoint above.

    #[test]
    fn an_attempts_checkpoint_round_trips_a_full_size_payload() {
        let file = fresh();
        let (mut cp, recovered) = AttemptsCheckpoint::open(Arc::clone(&file)).unwrap();
        assert_eq!(recovered, RecoveredCheckpoint::Empty);
        let payload = vec![0x42; ATTEMPTS_PAYLOAD];
        cp.write(&payload).unwrap();
        let reopened = AttemptsCheckpoint::open(Arc::clone(&file)).unwrap().1;
        assert_eq!(reopened.into_option(), Some(payload));
    }

    #[test]
    fn an_attempts_checkpoint_over_its_cap_is_rejected() {
        let file = fresh();
        let (mut cp, _) = AttemptsCheckpoint::open(Arc::clone(&file)).unwrap();
        let big = vec![0u8; ATTEMPTS_PAYLOAD + 1];
        assert!(matches!(
            cp.write(&big),
            Err(StorageError::Segment(SegmentError::Truncated))
        ));
    }

    #[test]
    fn a_torn_attempts_slot_falls_back_to_the_previous_value() {
        let file = fresh();
        let (mut cp, _) = AttemptsCheckpoint::open(Arc::clone(&file)).unwrap();
        cp.write(&[1u8; 64]).unwrap(); // seq 1 -> slot 1
        cp.write(&[2u8; 64]).unwrap(); // seq 2 -> slot 0
                                       // Corrupt slot 0 (the newest, seq 2): flip a CRC-covered payload byte.
        let mut bytes = file.snapshot();
        bytes[SEQ_LEN + LEN_LEN] ^= 0xff;
        file.set_len(0).unwrap();
        file.write_all_at(&bytes, 0).unwrap();
        file.sync_data().unwrap();
        // Recovery regresses to the previous durable value, never a torn one.
        assert_eq!(
            AttemptsCheckpoint::open(Arc::clone(&file))
                .unwrap()
                .1
                .into_option(),
            Some(vec![1u8; 64])
        );
    }

    // The C1 offset-commit path over the direct-write backend: the checkpoint's per-write
    // `write_all_at` + `sync_all` land on a `DirectFile` in direct mode. The dual-slot design is a
    // BACK-PATCH pattern (alternating slot writes RMW a shared block), the exact O_DIRECT read-
    // modify-write hazard — so this runs the checkpoint end to end on a real `DirectFile` (unix, so
    // macOS CI too) and asserts the dual-slot crash-safety still recovers the latest durable value.
    #[cfg(unix)]
    #[test]
    fn checkpoint_over_directfile_round_trips_and_stays_torn_safe() {
        use crate::io::DirectFile;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor.ckpt");
        {
            let f = DirectFile::create_new(&path).unwrap();
            let (mut cp, recovered) = Checkpoint::open(f).unwrap();
            assert_eq!(
                recovered,
                RecoveredCheckpoint::Empty,
                "a fresh direct-mode checkpoint recovers nothing"
            );
            // Several alternating-slot writes: each slot write RMWs the shared boundary block.
            for v in [&b"one"[..], b"two", b"three", b"four", b"five"] {
                cp.write(v).unwrap();
            }
        }
        // Reopen (a real fd close + reopen): the LATEST durable value survives, both slots intact.
        let g = DirectFile::open(&path).unwrap();
        let (_cp, recovered) = Checkpoint::open(g).unwrap();
        assert_eq!(
            recovered,
            RecoveredCheckpoint::Valid(b"five".to_vec()),
            "direct-mode checkpoint recovers the latest value"
        );
    }
}
