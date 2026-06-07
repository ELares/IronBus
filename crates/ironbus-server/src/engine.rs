// SPDX-License-Identifier: MIT OR Apache-2.0
//! The single-topic queue engine: the synchronous heart that wires the durable log to the
//! consumer primitives.
//!
//! It owns a [`Log`] (durable storage) plus, for one work-group, an [`AckCursor`]
//! (committed offset), a [`LeaseTable`] (in-flight visibility-timeout leases), and a
//! [`DeliveryConfig`] (max-deliver and backoff). [`Engine::produce`] appends a message and
//! makes it durable before returning; [`Engine::poll`] hands out the next deliverable
//! message under a fencing token; [`Engine::ack`] commits it. A message left unacked past
//! its visibility timeout is redelivered on a later poll, and a message that exceeds
//! max-deliver is parked (skipped, the dead-letter advisory) rather than looping forever.
//!
//! The engine is synchronous and deterministic: the caller supplies monotonic time
//! (`now`, nanoseconds) on each call, so it is fully testable without a runtime. The async
//! network server wraps it; one append actor owns the engine, which keeps the single-writer
//! rule. Delivery flow control is a sliding window of `max_in_flight` offsets above the
//! committed cursor (the max-ack-pending bound), so in-flight work never grows unbounded.

use crate::metrics::LatencyHistogram;
use crate::registry::MetricRegistry;
use ironbus_core::clock::Clock;
use ironbus_core::cursor::AckCursor;
use ironbus_core::delivery::{DeliveryConfig, Disposition};
use ironbus_core::keyshared::{KeyOrdering, KeyRouter, MemberId, RouteDecision};
use ironbus_core::lease::{
    AckOutcome, Claim, ExtendOutcome, LeaseConfig, LeaseTable, LeaseToken, NackOutcome,
};
use ironbus_core::types::Offset;
use ironbus_storage::checkpoint::{Checkpoint, CountersCheckpoint, MAX_PAYLOAD};
use ironbus_storage::dlq::{DlqSink, DLQ_SUBDIR};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::{Append, Log, LogConfig, RetentionBounds};
use ironbus_storage::loss::LossReport;
use ironbus_storage::segment::{OwnedRecord, StorageError};
use std::collections::BTreeMap;

/// What the engine does with a produce that would exceed the durable-log byte cap
/// ([`LogConfig::max_total_bytes`]): the overflow policy (#82). The default, [`DiskFullPolicy::DropNew`],
/// is the historical drop-new shed; [`DiskFullPolicy::DropOldest`] is the opt-in telemetry-style
/// reclamation that frees space by deleting the OLDEST sealed segment (even one a slow consumer
/// has not consumed) and then accepts the produce.
///
/// `Block` (stall the producer until space frees) and `Refuse` are out of scope for v1: the README
/// froze `block` as opt-in-only and we do not add a producer stall here. Only the two drop policies
/// ship; the enum is `#[non_exhaustive]` so a later block variant is not a breaking change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiskFullPolicy {
    /// Reject the over-cap produce (the drop-new shed): nothing is written, the producer is told
    /// promptly via the non-fatal [`StorageError::AtCapacity`], and the `produce_rejected` counter
    /// increments. This is the historical behavior and the DEFAULT, so an unconfigured engine is
    /// unchanged. Durable topics use it: the newest data is shed once the cap is hit, the older
    /// already-accepted data is preserved.
    #[default]
    DropNew,
    /// Reclaim space then accept the over-cap produce by force-reaping the OLDEST sealed segment,
    /// IGNORING consumer-safety: it may delete records below a slow group's cursor (so that group
    /// gets a one-time truncation on its next poll, #84). Telemetry topics use it: the freshest
    /// data matters most, so the oldest is dropped to make room rather than rejecting the producer.
    /// If only the active segment remains (nothing left to force out), it FALLS BACK to the
    /// drop-new rejection, so a single oversized in-flight set cannot wedge the log empty.
    DropOldest,
}

/// Tunables for an [`Engine`].
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// The storage log configuration.
    pub log: LogConfig,
    /// The lease (visibility timeout and hard cap) configuration.
    pub lease: LeaseConfig,
    /// The delivery (max-deliver and backoff) configuration.
    pub delivery: DeliveryConfig,
    /// The max-ack-pending window: at most this many offsets above the committed cursor
    /// may be in flight at once. Bounds in-flight work and the poll scan.
    pub max_in_flight: u32,
    /// The per-CONSUMER (per-connection) standing in-flight credit (refs #65, #9, #10): the most
    /// un-acked messages a single connection may hold at once, independent of the per-GROUP
    /// `max_in_flight` window. It is the consumer-side half of credit-based flow control (MQTT
    /// Receive Maximum / `JetStream` `MaxAckPending`): a Flow fetch delivers at most
    /// `min(requested_credit, ceiling - already_held, whatever the group makes available)`, so the
    /// EFFECTIVE bound is the min of the producer-side group window and this consumer ceiling.
    ///
    /// Enforced per session (one connection), not per group, so in a competing group one slow
    /// consumer that fills its own ceiling and stops acking pins ONLY its own credit and cannot
    /// reduce a peer's available deliveries (the per-consumer isolation from #10). A consumer at
    /// zero remaining credit gets zero deliveries from a Flow until it acks, nacks, terms, or one
    /// of its leases expires and is redelivered elsewhere, freeing the slot.
    ///
    /// The default is a small, memory-justified number ([`DEFAULT_CONSUMER_CREDIT`] = 64), NOT the
    /// MQTT absent-value 65535: at the #19 working point (10k msg/s x 5 ms service = 50 in-flight by
    /// Little's Law) 64 gives ~28% headroom. A value of `0` is treated as 1 (a hard floor of one, so
    /// a consumer always makes progress) by [`Engine::open`]. The parallel per-consumer BYTE budget
    /// is [`EngineConfig::consumer_credit_bytes`]; the `max_deliver`-to-DLQ poison cap lives in
    /// [`DeliveryConfig`].
    pub consumer_credit: u32,
    /// The per-CONSUMER (per-connection) standing in-flight BYTE budget (refs #65, #275, #10, #20):
    /// the most un-acked PAYLOAD bytes a single connection may hold at once, the RAM-side companion
    /// to the message-count credit ([`EngineConfig::consumer_credit`]). A large-payload consumer must
    /// not blow the RAM ceiling despite a small in-flight message count, so the EFFECTIVE per-Flow
    /// bound is `min(message credits remaining, byte credits remaining)`, with a hard floor of ONE
    /// message: a single message larger than the whole budget is still delivered (so it never wedges
    /// the consumer), but no further message is sent until bytes free up.
    ///
    /// Like the message credit, it is enforced per session and DERIVED from the connection-scoped
    /// in-flight set's total bytes (not a separately mutated counter, so it cannot drift): a delivery
    /// occupies its bytes; an ack, a successful nack/term, the per-batch prune of committed offsets,
    /// and the start-of-Flow prune of leases the engine no longer holds all restore them. A
    /// redelivered message re-occupies its bytes exactly once. A message's byte size is its key plus
    /// headers plus payload length, matching the produced-bytes accounting.
    ///
    /// The default is [`DEFAULT_CONSUMER_CREDIT_BYTES`] (8 MiB). A value of `0` means UNLIMITED (the
    /// byte budget is OFF, only the message credit binds), matching the `0` = unlimited / off
    /// convention of the other byte bounds ([`EngineConfig::max_retained_bytes`],
    /// `LogConfig::max_total_bytes`).
    pub consumer_credit_bytes: u64,
    /// Checkpoint the committed cursor after it advances at least this many offsets since the
    /// last checkpoint, bounding how many messages a crash redelivers. A value of 0 is treated
    /// as 1 (checkpoint on every advance). A clean disconnect also flushes the cursor.
    pub checkpoint_interval: u64,
    /// The consumer-safe size-retention bound (refs #13, #80): after a successful produce, the
    /// engine reclaims disk by deleting whole old SEALED segments while the durable log exceeds
    /// this many RECORD bytes, but NEVER a segment any consumer still needs (it protects below
    /// the minimum committed offset across every group). `0` means UNLIMITED (retention is OFF),
    /// which is the default, so existing behavior is unchanged. This is the drain side of the
    /// overflow policy that complements the byte-cap shed (`LogConfig::max_total_bytes`): the cap
    /// sheds new produces when full, retention frees space as consumers drain. See
    /// [`Log::reap_to_size`].
    pub max_retained_bytes: u64,
    /// The consumer-safe AGE-retention bound in MILLISECONDS (refs #13, #80): after a successful
    /// produce, the engine reclaims disk by deleting whole old SEALED segments whose every record
    /// is older than this many milliseconds (a segment's MAXIMUM record timestamp is below
    /// `now - max_age_ms`, where `now` comes from the engine clock seam), but NEVER a segment any
    /// consumer still needs. `0` means DISABLED, the default, so existing behavior is unchanged.
    /// Composes with `max_retained_bytes` and `max_messages`: a sealed segment is deleted if ANY
    /// enabled bound says it should be. Milliseconds (not a `Duration`) so the CLI takes a bare
    /// integer with no duration-parser dependency. See [`Log::reap`].
    pub max_age_ms: u64,
    /// The consumer-safe COUNT-retention bound (refs #13, #80): after a successful produce, the
    /// engine reclaims disk by deleting whole old SEALED segments while the log's TOTAL record
    /// count exceeds this many messages, oldest first, but NEVER a segment any consumer still
    /// needs. `0` means DISABLED, the default, so existing behavior is unchanged. Composes with
    /// `max_retained_bytes` and `max_age_ms`: a sealed segment is deleted if ANY enabled bound
    /// says it should be. See [`Log::reap`].
    pub max_messages: u64,
    /// The disk-full overflow policy (#82): what an over-cap produce does when the durable-log byte
    /// cap ([`LogConfig::max_total_bytes`]) is hit. [`DiskFullPolicy::DropNew`] (the default) is the
    /// historical drop-new shed, so an existing config is unchanged; [`DiskFullPolicy::DropOldest`]
    /// opts in to force-reaping the oldest sealed segment to make room and then accepting the
    /// produce. It has no effect unless `max_total_bytes` is set (with no cap, no produce is ever
    /// over-cap, so neither policy ever triggers).
    pub disk_full_policy: DiskFullPolicy,
    /// The most work-groups one engine may hold at once, INCLUDING the durable default group `""`
    /// (refs #240, #9, #10): bounds total consumer-state memory once the wire can name groups, so
    /// an unauthenticated client cannot exhaust memory by naming endless groups (each group is an
    /// `AckCursor` plus a `LeaseTable`). A new NAMED group past this cap is rejected with
    /// [`EngineError::TooManyGroups`] before anything is allocated; the default group is never
    /// counted against the cap and never rejected, so the engine is always usable.
    ///
    /// `0` means UNLIMITED (the cap is OFF), matching the `0` = unlimited / off convention of the
    /// other bounds ([`EngineConfig::max_retained_bytes`], [`EngineConfig::max_age_ms`],
    /// [`EngineConfig::max_messages`], and `LogConfig::max_total_bytes`). The default is
    /// [`DEFAULT_MAX_GROUPS`] (1024), a non-zero defensible bound: a single edge broker is not
    /// expected to fan out to thousands of distinct consumer groups, and 1024 distinct
    /// `AckCursor`/`LeaseTable` pairs is a few hundred KiB of state, so the cap is generous for
    /// real use yet still closes the denial-of-service vector.
    pub max_groups: usize,
    /// How long a NAMED, NON-default work-group may sit IDLE before it is EVICTED (reclaimed from
    /// memory), in MILLISECONDS (refs #277, #240, #9): the deferred lifecycle half of #240. The cap
    /// (`max_groups`) BOUNDS the number of live groups; this RECLAIMS the idle ones, so a long-lived
    /// broker does not accumulate per-group state (an `AckCursor` plus a `LeaseTable`) for groups no
    /// consumer touches any more. Eviction is a RUNTIME reclaim only: the durable `cursor-<hex>.ckpt`
    /// is NEVER deleted, so a later re-subscribe resumes from it (it does not redeliver the whole log).
    ///
    /// A group is evicted on a sweep ([`Engine::sweep_idle_groups`], driven from the produce and poll
    /// seams against the clock seam, NOT a background thread) only if ALL of these hold, so eviction
    /// can never lose a consumer's committed position:
    /// - it is a NAMED group (the default group `""` is NEVER evicted),
    /// - it is FULLY CAUGHT UP (`committed == flushed`, the durable head, with no acked-ahead set), so
    ///   re-creating it at the head redelivers NOTHING it had acked,
    /// - it has NO in-flight leases (its `LeaseTable` is empty), so no consumer is mid-work, and
    /// - it has been IDLE (no poll / ack / nack / progress / term touching it) for at least this many
    ///   milliseconds, measured on the engine clock seam.
    ///
    /// A group that is BEHIND the head is NEVER evicted (evicting it then re-creating it at offset 0
    /// or at its checkpoint could only ever lose its position or redeliver), so a behind group is, by
    /// definition, not idle in the meaningful sense. `0` means DISABLED (never evict), the DEFAULT,
    /// matching the `0` = off convention of the other bounds; an operator opts in by setting a
    /// non-zero window. See [`Engine::sweep_idle_groups`] and [`EngineConfig::max_groups`].
    pub group_idle_evict_ms: u64,
}

/// An error from the engine.
#[derive(Debug)]
pub enum EngineError {
    /// A storage-layer error (append, sync, recovery, or read).
    Storage(StorageError),
    /// `max_in_flight` was zero, which would deliver nothing: rejected at open.
    ZeroMaxInFlight,
    /// The lease generation space is exhausted (after `u64::MAX` grants, unreachable in any
    /// real deployment): the engine refuses to deliver rather than silently wedge.
    GenerationExhausted,
    /// An internal invariant broke: a deliverable offset had no record in the log.
    MissingRecord {
        /// The offset that should have held a record.
        offset: u64,
    },
    /// A new work-group could not be created: the per-engine group cap is reached (#240).
    TooManyGroups {
        /// The cap that was reached.
        max: usize,
    },
    /// A work-group name was empty, too long, or held a non-graphic-ASCII byte (#240).
    InvalidGroupName,
    /// A cumulative ack (ack-all-up-to-offset) was requested on a competing work-group (#63).
    /// Cumulative ack is the `JetStream` `AckAll` trap on a shared, out-of-order-draining cursor:
    /// acking up to an offset would commit past peers' still-in-flight messages and silently drop
    /// them. It is therefore offered only to broadcast consumers (a group of one that sees every
    /// message in order) and hard-rejected for any competing or `key_shared` work-group.
    CumulativeAckOnWorkGroup,
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EngineError::Storage(e) => write!(f, "storage error: {e}"),
            EngineError::ZeroMaxInFlight => write!(f, "max_in_flight must be greater than zero"),
            EngineError::GenerationExhausted => write!(f, "lease generation space is exhausted"),
            EngineError::MissingRecord { offset } => {
                write!(f, "no record at deliverable offset {offset}")
            }
            EngineError::TooManyGroups { max } => {
                write!(f, "work-group limit {max} reached")
            }
            EngineError::InvalidGroupName => {
                write!(
                    f,
                    "invalid work-group name (1 to {MAX_GROUP_NAME_LEN} graphic ASCII bytes)"
                )
            }
            EngineError::CumulativeAckOnWorkGroup => write!(
                f,
                "cumulative ack is not allowed on a competing work-group (broadcast consumers only)"
            ),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EngineError::Storage(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StorageError> for EngineError {
    fn from(e: StorageError) -> Self {
        EngineError::Storage(e)
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        EngineError::Storage(StorageError::Io(e))
    }
}

impl EngineError {
    /// Whether this error leaves the engine permanently unusable, the writer is frozen or
    /// an internal invariant broke, so a caller should stop rather than keep retrying.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            EngineError::GenerationExhausted
                | EngineError::MissingRecord { .. }
                | EngineError::Storage(StorageError::WriterFrozen)
        )
    }

    /// Whether this is the durable-log byte-cap shed (the non-fatal drop-new rejection): a
    /// produce was refused because the log is at its byte cap, distinct from a transient
    /// failure or a fatal freeze. The session uses it to reply a stable, distinct message so a
    /// producer can tell a shed from a transient failure. It is never fatal.
    #[must_use]
    pub fn is_at_capacity(&self) -> bool {
        matches!(self, EngineError::Storage(e) if e.is_at_capacity())
    }
}

/// A message handed to a consumer by [`Engine::poll`], plus the token to ack it with.
#[derive(Clone, Debug)]
pub struct Delivery {
    /// The log offset of the message.
    pub offset: Offset,
    /// The fencing token to carry on the ack.
    pub token: LeaseToken,
    /// How many times this message has now been delivered (starts at 1).
    pub deliveries: u32,
    /// The message itself.
    pub record: OwnedRecord,
}

/// The result of a [`Engine::poll`].
#[derive(Clone, Debug)]
pub enum Poll {
    /// A message to deliver to a consumer.
    Message(Delivery),
    /// A message that exceeded max-deliver was parked (committed past, not redelivered).
    /// The caller emits the dead-letter advisory and, later, writes it to the DLQ topic.
    Parked {
        /// The offset that was parked.
        offset: Offset,
        /// The parked message.
        record: OwnedRecord,
    },
    /// The group's cursor fell BELOW the oldest retained record because the disk-full drop-oldest
    /// policy force-reaped old segments out from under it (#82, #84). The engine has just reset the
    /// group's cursor UP to `earliest_retained` (so delivery resumes at the oldest record still
    /// present) and surfaces this ONCE so the caller emits the in-band truncation advisory; the
    /// consumer learns it lost the span `[old_cursor, earliest_retained)` rather than silently
    /// skipping it. The next poll delivers normally from `earliest_retained`; the same gap never
    /// re-truncates (the reset moved the cursor up to it).
    Truncated {
        /// The new earliest-retained offset the group's cursor was reset to.
        earliest_retained: Offset,
        /// How many records the group skipped: `earliest_retained - old_cursor`.
        skipped: u64,
    },
    /// Nothing is deliverable right now (all caught up, or the in-flight window is full).
    Idle,
}

/// The result of an [`Engine::ack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckResult {
    /// The ack matched the current lease; the message is committed.
    Acked,
    /// The token was stale (already acked, or redelivered); the ack was ignored.
    Fenced,
}

/// The outcome of [`Engine::nack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NackResult {
    /// The message was requeued for redelivery (immediately, or after the requested delay).
    Requeued,
    /// The token was stale (already acked, or redelivered); the nack was ignored.
    Fenced,
}

/// The outcome of [`Engine::progress`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressResult {
    /// The lease deadline was extended by one visibility window.
    Extended,
    /// The hard cap from the attempt start has been reached; the lease cannot be extended
    /// further and will expire (and the message redeliver) on schedule.
    CapReached,
    /// The token was stale (already acked, or redelivered); the progress was ignored.
    Fenced,
}

/// A single-topic, single-work-group queue engine.
/// Monotonic operational counters exposed via `/metrics`. They are an OBSERVABILITY aid, not
/// correctness state: each only ever increases (so Prometheus reads them as a counter, never a
/// gauge that could roll backward). They are DURABLE across a clean restart (#98): the engine
/// snapshots them to a CRC'd `counters.ckpt` on the checkpoint cadence and the graceful-shutdown
/// flush, and seeds them from that snapshot at [`Engine::open`], so a restart no longer zeroes the
/// operational history. Because the snapshot is taken on a cadence (NOT fsynced on every
/// increment, which would kill throughput), a crash between an increment and the next snapshot
/// loses at most the increments since the last snapshot: the resumed value is a MONOTONIC LOWER
/// BOUND, acceptable for observability. A torn or missing snapshot recovers as all-zeros and NEVER
/// blocks startup or touches the durable log, cursors, or DLQ.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Messages appended by `produce`.
    pub produced: u64,
    /// Logical message bytes appended by `produce` (key + headers + payload, excluding the
    /// record framing). A throughput and flash-wear signal alongside the record count.
    pub produced_bytes: u64,
    /// Produces REJECTED because the durable log was at or over its byte cap (the drop-new
    /// shed, refs #10, #13): nothing was written and no offset advanced. A rejected produce is
    /// NOT counted in `produced` or `produced_bytes`; this is the operator's shed-rate signal.
    pub produce_rejected: u64,
    /// Message deliveries handed out by `poll` (a redelivery counts again).
    pub delivered: u64,
    /// Deliveries that were a redelivery (the message had been delivered before).
    pub redelivered: u64,
    /// Messages dead-lettered (parked past `MaxDeliver`); the resilience drop signal.
    pub dead_lettered: u64,
    /// Below-earliest TRUNCATION events served to a consumer (#82, #84): each is one
    /// [`Poll::Truncated`] returned because a group's cursor had fallen below the oldest retained
    /// record (its data was force-reaped out from under it by the disk-full drop-oldest policy) and
    /// the engine reset the cursor up to `earliest_retained`. The resilience SKIP signal: a consumer
    /// silently losing a span would be the silent-loss this taxonomy forbids, so the skip is counted
    /// the moment it is surfaced. Distinct from `recovery_*` (startup torn-tail loss): this is a
    /// runtime skip served to a LIVE consumer. Each event spans `truncated_records` records.
    pub truncations: u64,
    /// RECORDS skipped by below-earliest truncations (#82, #84): the sum of the `skipped` span over
    /// every [`Poll::Truncated`] event, the record-count complement of `truncations`. The operator's
    /// "how much did consumers lose to force-reap" signal. Saturating.
    ///
    /// CONSUMER-TRUNCATION-derived (#307): this count comes from a force-reap-driven, transient,
    /// consumer-cursor-dependent runtime event. It is NOT in the durable `LossReport` and NOT
    /// replay-derivable from the log, so it is NOT reconciled on open: like the operational counters
    /// it keeps #306's snapshot-only MONOTONIC LOWER BOUND (a `kill -9` can lose the post-snapshot
    /// increments). The replay-reconcilable RECOVERY-LOSS records live in `records_skipped`.
    pub truncated_records: u64,
    /// Commits via `ack` (a `term` commits through the same path and is counted here).
    pub acks: u64,
    /// Whole old SEALED segments reclaimed by consumer-safe retention, by the size, age, or count bound (refs #13, #80):
    /// each reap unlinks a fully-consumed oldest segment to free disk once the durable log is
    /// over its retention bound. Zero unless `max_retained_bytes` is set; the operator's
    /// space-reclamation signal. Saturating.
    pub segments_reaped: u64,
    /// Whole old SEALED segments FORCE-reaped by the disk-full drop-oldest policy (#82): each
    /// forced reap unlinks the oldest sealed segment to make room for an over-cap produce, IGNORING
    /// consumer-safety (it may delete records a slow group has not consumed, which then sees a
    /// one-time truncation, #84). Distinct from `segments_reaped` (consumer-safe retention): this
    /// is the data-loss-bearing reclamation an operator watches when running `DropOldest`. Zero
    /// under the default `DropNew` policy. Saturating.
    pub segments_force_reaped: u64,
    /// RECOVERY-LOSS records the durable log implies (#307, #98): the record-count of the loss the
    /// last recovery dropped (a torn tail or corrupt-skip span the durable `LossReport` records),
    /// distinct from the CONSUMER-TRUNCATION `truncated_records`. RECOVERY-LOSS-derived, so it is
    /// genuinely REPLAY-RECONSTRUCTABLE: reconciled on open to
    /// `max(snapshot, loss_report.total_records_lost_estimate())`, giving a strict cross-restart
    /// MONOTONIC NON-DECREASING guarantee even across a `kill -9` (the durable loss report survives,
    /// so the post-snapshot increment is re-derived on the next open). It has NO runtime increment:
    /// it exists only to be reconciled from the durable log. Exposed as the `ironbus_records_skipped`
    /// gauge (NOT `_total`, so it stays out of the frozen counter set). Saturating; never lowered.
    pub records_skipped: u64,
    /// RECOVERY-LOSS BYTES the durable log implies (#307, #98): the byte-span complement of
    /// `records_skipped`, the bytes the last recovery dropped. RECOVERY-LOSS-derived, so it is
    /// genuinely REPLAY-RECONSTRUCTABLE: reconciled on open to
    /// `max(snapshot, loss_report.total_bytes_skipped())`, so it is "not lower than before the crash"
    /// even across a `kill -9` (the durable loss report survives). It has NO runtime increment. It is
    /// the durable, monotonic recovery-loss byte total, distinct from the per-recovery
    /// `ironbus_recovery_loss_bytes` GAUGE (which reports only the LAST recovery). Exposed as the
    /// `ironbus_bytes_skipped` gauge. Saturating; never lowered by reconciliation (always a `max`).
    pub bytes_skipped: u64,
    /// The HIGHEST log offset any skip/loss event reached (#307, #98): a watermark, not a sum.
    ///
    /// It has TWO contributions with DIFFERENT durability guarantees. At runtime it is raised to
    /// `max(self, earliest_retained)` on a below-earliest CONSUMER TRUNCATION (a transient,
    /// non-replay-derivable event, so that contribution keeps #306's snapshot-only lower bound). On
    /// open it is RECONCILED to `max(checkpoint, replay)` where the replay value is the RECOVERY head
    /// the durable log recovered to when it dropped a torn tail (a recovery-loss-derived, durable,
    /// replay-reconstructable UPPER BOUND on the highest skipped offset). The reconciliation never
    /// lowers it (always a `max`), so the watermark is monotonic non-decreasing; the recovery-derived
    /// contribution is genuinely restored across a `kill -9`, the consumer-truncation contribution is
    /// only a snapshot lower bound. Exposed as `ironbus_last_skip_offset`.
    pub last_skip_offset: u64,
    /// Reconciliation/repair events on open (#307): incremented once each time [`Engine::open`]
    /// RECONCILES the durable counters snapshot with what the durable log / loss report implies and
    /// the replay value RAISES a RECOVERY-LOSS value (`records_skipped`, `bytes_skipped`, or the
    /// recovery-head component of `last_skip_offset`) above the snapshot (so the snapshot alone would
    /// have resumed too low). Zero when the snapshot already dominated the replay (the common
    /// clean-shutdown case). It tracks ONLY the replay-reconcilable recovery-loss family, never the
    /// snapshot-only `truncated_records`. Exposed as `ironbus_counter_checkpoint_repair_total`, the
    /// frozen-taxonomy `_total` counter an operator watches to see the checkpoint-plus-replay lower
    /// bound actually firing after a hard crash. Saturating.
    pub counter_checkpoint_repairs: u64,
}

/// The durable counters-snapshot format version (#98). A future field addition bumps this only if
/// the decode rule must change; today the format is forward-compatible by construction (a shorter
/// payload zero-fills missing trailing fields, a longer one ignores extra trailing bytes), so a
/// version mismatch is tolerated, not rejected: the snapshot is an observability aid, and refusing
/// to read a newer snapshot would lose history for no safety gain.
const COUNTERS_SNAPSHOT_VERSION: u8 = 1;

/// The number of `u64` counter fields serialized, in the fixed wire order below. Adding a counter
/// appends one field here (and at the end of [`Counters::encode_snapshot`] /
/// [`Counters::decode_snapshot`]), so an old snapshot still decodes (the new trailing field reads
/// as zero) and a new snapshot still decodes on an old binary (the trailing field is ignored).
/// The skip/loss reconciliation family (#307) appended four trailing fields (`records_skipped`,
/// `bytes_skipped`, `last_skip_offset`, `counter_checkpoint_repairs`), so a `counters.ckpt` written
/// before #307 still decodes (the four new fields read as zero) and reconciliation re-derives the
/// replay-reconcilable recovery-loss values from the durable loss report on the next open.
const COUNTERS_FIELD_COUNT: usize = 15;

impl Counters {
    /// Serializes the counters into a small versioned little-endian byte string for the durable
    /// snapshot (#98): a 1-byte version then the fixed set of `u64`s in a frozen order. The result
    /// is `1 + 8 * COUNTERS_FIELD_COUNT` bytes, well under the counters checkpoint slot cap, so it
    /// always fits one slot.
    fn encode_snapshot(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 8 * COUNTERS_FIELD_COUNT);
        buf.push(COUNTERS_SNAPSHOT_VERSION);
        // The frozen field order. Appending a NEW counter goes at the END so older snapshots stay
        // decodable (the missing trailing field reads as zero).
        for v in [
            self.produced,
            self.produced_bytes,
            self.produce_rejected,
            self.delivered,
            self.redelivered,
            self.dead_lettered,
            self.truncations,
            self.truncated_records,
            self.acks,
            self.segments_reaped,
            self.segments_force_reaped,
            // The skip/loss reconciliation family (#307) is appended LAST so an older snapshot still
            // decodes (these read as zero) and reconciliation re-derives the recovery-loss ones from
            // the durable loss report.
            self.records_skipped,
            self.bytes_skipped,
            self.last_skip_offset,
            self.counter_checkpoint_repairs,
        ] {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        buf
    }

    /// Reconstructs the counters from a durable snapshot payload, TOLERANTLY: a payload that is
    /// empty, too short, the wrong version, or carries trailing bytes never errors. A missing
    /// trailing `u64` field reads as zero (forward/backward compatible across a field addition);
    /// extra trailing bytes are ignored. This is the never-block-recovery contract (#98): the
    /// counters are an observability aid, so a corrupt or partial snapshot degrades to fewer (or
    /// zero) recovered fields rather than failing the broker open. The CRC and torn-slot fallback
    /// are handled one layer down by the checkpoint, so a payload that reaches here already passed
    /// its CRC; this decode is the second belt that a wrong-shaped-but-CRC-valid payload (e.g. a
    /// future or downgraded format) still cannot panic or corrupt anything.
    fn decode_snapshot(payload: &[u8]) -> Counters {
        // Reads the i-th u64 field (0-based) after the 1-byte version, or 0 if the payload is too
        // short to contain it.
        let field = |i: usize| -> u64 {
            let start = 1 + i * 8;
            payload
                .get(start..start + 8)
                .and_then(|s| <[u8; 8]>::try_from(s).ok())
                .map_or(0, u64::from_le_bytes)
        };
        Counters {
            produced: field(0),
            produced_bytes: field(1),
            produce_rejected: field(2),
            delivered: field(3),
            redelivered: field(4),
            dead_lettered: field(5),
            truncations: field(6),
            truncated_records: field(7),
            acks: field(8),
            segments_reaped: field(9),
            segments_force_reaped: field(10),
            // The skip/loss reconciliation family (#307), appended at the END: a pre-#307 snapshot
            // is too short to contain these, so `field` reads them as zero (the tolerant decode),
            // and reconciliation on open re-derives the recovery-loss ones from the durable loss
            // report.
            records_skipped: field(11),
            bytes_skipped: field(12),
            last_skip_offset: field(13),
            counter_checkpoint_repairs: field(14),
        }
    }
}

/// A snapshot of one work-group's consumer position, for the metrics endpoint (#16): an
/// operator sees committed offset, lag, and in-flight depth broken down by cursor (#15).
#[derive(Clone, Debug)]
pub struct GroupConsumerStat {
    /// The work-group name (`""` is the default group).
    pub group: String,
    /// The group's committed offset (every offset below it is acked in this group).
    pub committed: u64,
    /// The group's in-flight (delivered, not yet acked) message count.
    pub in_flight: usize,
}

/// A read-only echo of the engine's EFFECTIVE configuration bounds, for the introspection
/// endpoint (#99). Every field is a plain copy of a value [`Engine::open`] was configured with:
/// it carries NO secret material and NO mutating handle, so it is safe to expose on the read-only
/// `/admin` surface. Each `0` keeps the codebase's `0` = unlimited/off convention.
#[derive(Clone, Copy, Debug)]
pub struct EngineConfigSnapshot {
    /// The durable-log total-byte hard cap (`0` = unlimited).
    pub max_total_bytes: u64,
    /// The per-segment soft byte cap.
    pub max_segment_bytes: u64,
    /// The consumer-safe size-retention bound in RECORD bytes (`0` = off).
    pub max_retained_bytes: u64,
    /// The consumer-safe age-retention bound in milliseconds (`0` = off).
    pub max_age_ms: u64,
    /// The consumer-safe count-retention bound in records (`0` = off).
    pub max_messages: u64,
    /// The per-group max-ack-pending in-flight window.
    pub max_in_flight: u32,
    /// The per-consumer in-flight message credit ceiling (already floored to at least 1).
    pub consumer_credit: u32,
    /// The per-consumer in-flight byte budget (`0` = unlimited).
    pub consumer_credit_bytes: u64,
    /// The max-deliver poison cap before a message is dead-lettered.
    pub max_deliver: u32,
    /// The cap on the number of live work-groups, the default included (`0` = unlimited).
    pub max_groups: usize,
    /// The idle-eviction window for a named group in NANOSECONDS (`0` = disabled).
    pub group_idle_evict_nanos: u64,
    /// The lease visibility timeout in nanoseconds.
    pub visibility_nanos: u64,
    /// The lease hard cap (the longest a single attempt's lease may be extended) in nanoseconds.
    pub hard_cap_nanos: u64,
    /// The disk-full overflow policy (`DropNew` or `DropOldest`).
    pub disk_full_policy: DiskFullPolicy,
}

/// The durable, unnamed default work-group: the one the wire protocol uses today, the one
/// persisted in `cursor.ckpt`. Named groups (#9) are independent in-memory cursors.
const DEFAULT_GROUP: &str = "";

/// The build version string for the metric registry's `ironbus_build_info` (#97), the crate
/// version baked in at compile time.
fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The default per-consumer in-flight credit (refs #65, #10): the most un-acked messages one
/// connection may hold at once before a Flow stops delivering to it. A small, memory-justified
/// number (NOT the MQTT absent-value 65535): by Little's Law at the #19 working point (10k msg/s
/// x 5 ms service = 50 concurrent) 64 leaves ~28% headroom for variance. See
/// [`EngineConfig::consumer_credit`].
pub const DEFAULT_CONSUMER_CREDIT: u32 = 64;

/// The default per-consumer in-flight BYTE budget (refs #65, #275, #10, #20): the most un-acked
/// PAYLOAD bytes one connection may hold at once before a Flow stops delivering to it, the RAM-side
/// companion to [`DEFAULT_CONSUMER_CREDIT`]. 8 MiB: at the 64-message default that is a 128 KiB
/// average message before the byte budget binds before the message count, generous for the small
/// records an edge broker carries yet a firm RAM ceiling for a large-payload consumer. A single
/// message larger than this is still delivered (the hard floor of one), so the budget never wedges a
/// consumer. `0` means UNLIMITED (the byte budget is off). See [`EngineConfig::consumer_credit_bytes`].
pub const DEFAULT_CONSUMER_CREDIT_BYTES: u64 = 8 * 1024 * 1024;

/// The default cap on the number of live work-groups per engine, INCLUDING the durable default
/// (refs #240, #9, #10): bounds total consumer-state memory once the wire can name groups, so an
/// unauthenticated client cannot exhaust memory by naming endless groups. A non-zero, defensible
/// default (`0` would mean unlimited): a single edge broker is not expected to fan out to thousands
/// of distinct consumer groups, and 1024 `AckCursor`/`LeaseTable` pairs is a modest, bounded amount
/// of state. See [`EngineConfig::max_groups`] (where `0` = unlimited).
pub const DEFAULT_MAX_GROUPS: usize = 1024;

/// The default idle window after which a fully-caught-up, lease-free NAMED work-group is evicted
/// from memory (refs #277, #240), in MILLISECONDS. `0` means DISABLED (never evict), the default:
/// named groups are only just becoming wire-reachable, eviction is a reclaim not a correctness
/// requirement, and the SAFE default is to leave it off so an operator opts in deliberately (it
/// matches the `0` = off convention of the other bounds). See [`EngineConfig::group_idle_evict_ms`].
pub const DEFAULT_GROUP_IDLE_EVICT_MS: u64 = 0;

/// The longest a named work-group name may be (#240): bounds per-name memory.
const MAX_GROUP_NAME_LEN: usize = 128;

/// Validates a new work-group name: 1 to [`MAX_GROUP_NAME_LEN`] graphic-ASCII bytes (no
/// spaces, control bytes, or non-ASCII), so a client cannot exhaust memory or smuggle
/// control characters through a name. The default group (`""`) is pre-created and never
/// validated here.
fn validate_group_name(name: &str) -> Result<(), EngineError> {
    let len = name.len();
    if len == 0 || len > MAX_GROUP_NAME_LEN || !name.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(EngineError::InvalidGroupName);
    }
    Ok(())
}

/// The filename prefix and suffix of a named work-group's durable cursor checkpoint. The
/// default group uses `cursor.ckpt` (note `cursor.`, not `cursor-`), so it never matches the
/// named pattern and the two never collide.
const GROUP_CKPT_PREFIX: &str = "cursor-";
const GROUP_CKPT_SUFFIX: &str = ".ckpt";

/// Lowercase-hex-encodes bytes, for embedding a graphic-ASCII work-group name in a safe,
/// reversible filename (a name may contain `/`, `:`, etc., which are unsafe in a path).
fn hex_encode(bytes: &[u8]) -> String {
    // A 16-entry table indexed by a nibble (0..=15): no `Option`, no fallback, and the index
    // is provably in bounds, so the encoding cannot silently produce a wrong digit.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Decodes lowercase or uppercase hex back to bytes, or `None` if the input is not even-length
/// valid hex.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = char::from(bytes[i]).to_digit(16)?;
        let lo = char::from(bytes[i + 1]).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
        i += 2;
    }
    Some(out)
}

/// The durable checkpoint filename for a named work-group: `cursor-<hex(name)>.ckpt`.
fn group_checkpoint_name(group: &str) -> String {
    format!(
        "{GROUP_CKPT_PREFIX}{}{GROUP_CKPT_SUFFIX}",
        hex_encode(group.as_bytes())
    )
}

/// Recovers the work-group name from a checkpoint filename, or `None` if it is not a named-group
/// checkpoint (e.g. the default `cursor.ckpt`, a segment file, or a malformed name).
fn parse_group_checkpoint_name(name: &str) -> Option<String> {
    let mid = name
        .strip_prefix(GROUP_CKPT_PREFIX)?
        .strip_suffix(GROUP_CKPT_SUFFIX)?;
    if mid.is_empty() {
        return None;
    }
    String::from_utf8(hex_decode(mid)?).ok()
}

/// Builds the checkpoint payload for a cursor: the full [`AckCursor`] snapshot (committed
/// watermark plus the acked-ahead set) when it fits a checkpoint slot, else the watermark plus
/// the leading acked-ahead runs that fit. Dropping the overflow runs only redelivers those
/// already-acked messages after a crash (at-least-once safe); it never loses an ack below the
/// watermark. The in-flight window bounds how large the ahead set can grow.
fn snapshot_payload(cursor: &AckCursor) -> Vec<u8> {
    let mut buf = Vec::new();
    cursor.encode_snapshot(&mut buf);
    if buf.len() <= MAX_PAYLOAD {
        return buf;
    }
    // A slot holds MAX_PAYLOAD bytes: the fixed snapshot header and crc, plus 16 per run.
    let max_runs = MAX_PAYLOAD.saturating_sub(AckCursor::SNAPSHOT_MIN_LEN) / 16;
    let kept: Vec<(u64, u64)> = cursor
        .ahead_ranges()
        .iter()
        .copied()
        .take(max_runs)
        .collect();
    let capped = AckCursor::resume_with_ahead(cursor.committed(), kept)
        .unwrap_or_else(|_| AckCursor::resume(cursor.committed()));
    let mut out = Vec::new();
    capped.encode_snapshot(&mut out);
    out
}

/// Reconstructs a work-group cursor from a recovered checkpoint payload, clamped to the durable
/// log head `flushed`: the committed watermark can never legitimately exceed the head, and every
/// acked-ahead range must reference a durable record. The current format is the full snapshot
/// (#235); a payload too short to be a snapshot is the legacy committed-only format (#182), its
/// leading 8 little-endian bytes the committed offset. Clamping down is at-least-once-safe.
fn resume_cursor_from_snapshot(recovered: Option<&[u8]>, flushed: u64) -> AckCursor {
    let recovered_cursor = match recovered {
        Some(p) if p.len() >= AckCursor::SNAPSHOT_MIN_LEN => AckCursor::decode_snapshot(p).ok(),
        Some(p) => {
            let committed = p
                .get(..8)
                .and_then(|s| <[u8; 8]>::try_from(s).ok())
                .map_or(0, u64::from_le_bytes);
            Some(AckCursor::resume(Offset::new(committed)))
        }
        None => None,
    };
    let recovered_committed = recovered_cursor.as_ref().map_or(0, |c| c.committed().get());
    debug_assert!(
        recovered_committed <= flushed,
        "checkpoint committed {recovered_committed} exceeds the durable head {flushed}"
    );
    let committed = recovered_committed.min(flushed);
    let ahead: Vec<(u64, u64)> = recovered_cursor
        .as_ref()
        .map(|c| {
            c.ahead_ranges()
                .iter()
                .copied()
                .filter(|&(start, end)| start > committed && end <= flushed)
                .collect()
        })
        .unwrap_or_default();
    // Filtering a valid ahead set keeps it valid, so `resume_with_ahead` succeeds; fall back to
    // a bare resume rather than panic if a future change ever violates that.
    AckCursor::resume_with_ahead(Offset::new(committed), ahead)
        .unwrap_or_else(|_| AckCursor::resume(Offset::new(committed)))
}

/// Per-work-group consumer state over the shared log: an independent committed cursor and
/// in-flight lease table. A broadcast subscriber is a group of one (it sees every message);
/// a competing group is shared by several members (each message goes to one member). The
/// lease generation space is per-group, so a [`LeaseToken`] is only meaningful within the
/// group it was delivered from.
///
/// A group is plain competing by default (`router: None`, [`KeyOrdering::None`]). Opting it
/// into `key_shared` (#64) attaches a [`KeyRouter`]: the same cursor and lease table still
/// drain the log, but delivery is filtered through the router so a key routes to one live
/// member and per-key order is preserved.
struct WorkGroup {
    cursor: AckCursor,
    leases: LeaseTable,
    /// The `key_shared` router (#64), or `None` for the default [`KeyOrdering::None`] (plain
    /// competing distribution). When present, [`Engine::poll_in_member`] routes each record's
    /// key to one live member and enforces per-key serialization; when absent, delivery is the
    /// unchanged claim-the-next-deliverable competing path.
    router: Option<KeyRouter>,
    /// The engine-clock-seam (monotonic, nanoseconds) timestamp of this group's LAST ACTIVITY
    /// (#277): updated whenever a poll, ack, nack, progress, or term touches the group. The idle
    /// eviction sweep ([`Engine::sweep_idle_groups`]) measures the idle window against it. Seeded
    /// at the group's creation time so a freshly-created group is not instantly evictable. A
    /// purely monotonic timestamp is enough because the sweep only ever subtracts it from a later
    /// `now`, never compares it across wall-clock boundaries.
    last_activity: u64,
}

impl WorkGroup {
    fn new(config: LeaseConfig, now: u64) -> WorkGroup {
        WorkGroup {
            cursor: AckCursor::new(),
            leases: LeaseTable::new(config),
            router: None,
            last_activity: now,
        }
    }
}

pub struct Engine<F: Filesystem, C: Clock> {
    log: Log<F, C>,
    /// Per-work-group consumer state, keyed by group name. The default group (`""`) is the
    /// durable one (checkpointed to `cursor.ckpt`); named groups are independent
    /// broadcast/competing cursors, in-memory for now (durable per-group state is #60).
    groups: BTreeMap<String, WorkGroup>,
    /// The lease configuration, kept to build a new group's lease table on first use.
    lease_config: LeaseConfig,
    delivery: DeliveryConfig,
    max_in_flight: u32,
    /// The per-CONSUMER (per-connection) standing in-flight credit ceiling (refs #65, #9, #10),
    /// floored to 1 at open. The engine itself does NOT decrement it (the engine is shared by
    /// every connection and has no per-connection identity); it advertises this ceiling to each
    /// [`crate::session::Session`], which tracks its own remaining credit against its
    /// connection-scoped `leased` set (#175). See [`EngineConfig::consumer_credit`].
    consumer_credit: u32,
    /// The per-CONSUMER (per-connection) standing in-flight BYTE budget (refs #65, #275, #10), the
    /// RAM-side companion to `consumer_credit`. Like the message credit, the engine itself does NOT
    /// decrement it; it advertises the budget to each [`crate::session::Session`], which derives its
    /// remaining byte budget from the total bytes of its connection-scoped `leased` set. `0` means
    /// unlimited (only the message credit binds). See [`EngineConfig::consumer_credit_bytes`].
    consumer_credit_bytes: u64,
    checkpoint: Checkpoint<F::File>,
    checkpoint_interval: u64,
    /// The durable resilience-counters checkpoint (#98): a CRC'd dual-slot `counters.ckpt` written
    /// on the cursor-checkpoint cadence and the graceful-shutdown flush, recovered at
    /// [`Engine::open`] to seed `counters`. It is strictly an OBSERVABILITY aid: a torn or missing
    /// snapshot recovers as all-zeros and never blocks open or affects the durable log, cursors, or
    /// DLQ. It is NOT fsynced per increment (that would kill throughput), so the resumed counters
    /// are a monotonic LOWER BOUND, losing at most the increments since the last snapshot on a crash.
    counters_checkpoint: CountersCheckpoint<F::File>,
    /// The consumer-safe retention bounds (size, age, count) the produce path enforces against the
    /// minimum committed offset (refs #13, #80). All `0` (the default) means retention is off, so
    /// the produce path never reaps. See [`EngineConfig::max_retained_bytes`],
    /// [`EngineConfig::max_age_ms`], and [`EngineConfig::max_messages`].
    retention: RetentionBounds,
    /// The disk-full overflow policy (#82): `DropNew` (the default) sheds an over-cap produce,
    /// `DropOldest` force-reaps the oldest sealed segment to make room then accepts it. See
    /// [`EngineConfig::disk_full_policy`].
    disk_full_policy: DiskFullPolicy,
    /// The cap on the number of live work-groups, including the default (refs #240, #9, #10):
    /// a new NAMED group past this is rejected with [`EngineError::TooManyGroups`] before it is
    /// allocated. `0` means unlimited. See [`EngineConfig::max_groups`].
    max_groups: usize,
    /// The idle window in NANOSECONDS after which a fully-caught-up, lease-free NAMED group is
    /// evicted from memory (#277): the configured `group_idle_evict_ms` converted to nanoseconds at
    /// open (the clock seam is in nanoseconds). `0` means DISABLED (never evict). The sweep
    /// ([`Engine::sweep_idle_groups`]) runs from the produce and poll seams. See
    /// [`EngineConfig::group_idle_evict_ms`].
    group_idle_evict_nanos: u64,
    last_checkpointed: u64,
    /// The last durably-checkpointed committed offset per NAMED work-group (#60), for the
    /// interval gate. The default group uses `last_checkpointed`; named groups checkpoint to
    /// their own `cursor-<hex>.ckpt` files.
    group_last_checkpointed: BTreeMap<String, u64>,
    counters: Counters,
    /// The fsync (durability barrier) latency distribution observed on produce.
    fsync: LatencyHistogram,
    /// The bounded, allocation-free metric registry (#97): the fixed-bucket fsync-duration and
    /// append-latency histograms, the capped per-consumer lag registry (incremental on append and
    /// commit), and the self-monitoring series (build info, start time, monotonic-derived uptime).
    /// Updated on the produce (append) and ack (commit) hot paths and rendered on `/metrics`. It
    /// has a HARD memory ceiling independent of the record count or disk size, so leaving metrics on
    /// permanently is affordable on a few-hundred-MB edge node.
    registry: MetricRegistry,
    /// The log offset of the most recently dead-lettered (parked past `MaxDeliver`) message,
    /// or `None` if none has been dead-lettered. A gauge-style companion to the
    /// `dead_lettered` counter.
    last_dead_lettered: Option<Offset>,
    /// The durable dead-letter SINK (#63): a second segmented log under the `dlq/` subdirectory
    /// holding every poison record for later inspection. Opened LAZILY on the first dead-letter
    /// (so a broker that never dead-letters never creates the subdirectory), or eagerly by
    /// [`Engine::open`] when the subdirectory already exists, so the per-group dead-lettered
    /// high-water mark (the idempotency key) is rebuilt before the first poison redelivers.
    dlq: Option<DlqSink<F, C>>,
    /// The [`LogConfig`] the DLQ sink's log is opened with: the same segment sizing as the main
    /// log, but with NO total-byte cap (a poison record must never be shed, it is the durable
    /// evidence of a dropped message).
    dlq_config: LogConfig,
    /// The set of group names CONFIGURED to use `key_shared` ordering (#64), declared server-side
    /// (NOT on the wire). Empty by default, so every group is plain competing
    /// ([`KeyOrdering::None`]) unless an operator opts it in. A session consults
    /// [`Engine::is_configured_key_shared`] on SUB and, for a configured group, puts it into
    /// `key_shared` mode and joins as a member. Held separate from the live per-group router so the
    /// declared config survives a group that has no current members.
    key_shared_groups: std::collections::BTreeSet<String>,
}

/// The file name of the work-group's durable committed-cursor checkpoint.
const CURSOR_CHECKPOINT: &str = "cursor.ckpt";

/// The file name of the durable resilience-counters checkpoint (#98). It never collides with the
/// cursor checkpoints (`cursor.ckpt` and `cursor-<hex>.ckpt`).
const COUNTERS_CHECKPOINT: &str = "counters.ckpt";

// The engine requires `C: Clone` so it can hand the secondary durable DLQ sink (#63) its own clock
// (see `Log::clock_clone`). Every shipped clock (`ManualClock`, `Arc<ManualClock>`, `SystemClock`)
// is `Clone`, so this is not a usability regression.
impl<F: Filesystem, C: Clock + Clone> Engine<F, C> {
    /// Opens the engine, recovering the durable log and the durable consumer cursor (its
    /// committed watermark plus the acked-ahead set), so a restart resumes from the last
    /// checkpoint and redelivers only genuinely unacked offsets, not the acked-ahead ones.
    /// The lease table starts empty, so anything that was merely in flight (delivered but
    /// unacked) at the crash redelivers, which is safe at-least-once behavior.
    ///
    /// # Errors
    /// Returns [`EngineError::ZeroMaxInFlight`] for a zero window, or a storage error from
    /// opening the log or the cursor checkpoint.
    pub fn open(fs: F, clock: C, config: EngineConfig) -> Result<Engine<F, C>, EngineError> {
        if config.max_in_flight == 0 {
            return Err(EngineError::ZeroMaxInFlight);
        }
        let log = Log::open(fs, clock, config.log)?;

        // Open (creating if absent) the cursor checkpoint through the log's filesystem.
        let checkpoint_file = {
            let fs = log.filesystem();
            if fs.exists(CURSOR_CHECKPOINT)? {
                fs.open(CURSOR_CHECKPOINT)?
            } else {
                let file = fs.create_new(CURSOR_CHECKPOINT)?;
                fs.sync_dir()?; // the new file's directory entry must be durable
                file
            }
        };
        let (checkpoint, recovered) = Checkpoint::open(checkpoint_file)?;

        // Open and recover the durable resilience-counters checkpoint (#98), seeding the in-memory
        // counters from the last snapshot (or all-zeros if it is missing or torn) AND reconciling the
        // recovery-loss family with the durable log / loss report (#307). Factored out to keep `open`
        // readable; the never-block-recovery contract and the checkpoint-plus-replay max live there.
        let (counters_checkpoint, counters) = Self::open_counters_checkpoint(&log)?;

        let flushed = log.flushed_offset().get();
        // The open-time monotonic instant, used to seed each group's last-activity (#277), so a
        // group recovered at open is treated as just-active and the idle eviction sweep cannot
        // reclaim it before it has had a full idle window of inactivity after the restart.
        let opened_at = log.now_monotonic();
        // The broker start time as Unix SECONDS for `ironbus_start_time_seconds` (#97), read ONCE
        // from the clock seam (never a raw `SystemTime::now`); uptime derives from `opened_at`.
        let start_time_unix_seconds = log.now_unix_millis() / 1_000;
        // The default group's durable cursor, from `cursor.ckpt`, clamped to the head.
        let cursor = resume_cursor_from_snapshot(recovered.as_deref(), flushed);
        let default_committed = cursor.committed().get();
        let mut groups = BTreeMap::new();
        groups.insert(
            DEFAULT_GROUP.to_string(),
            WorkGroup {
                cursor,
                leases: LeaseTable::new(config.lease),
                router: None,
                last_activity: opened_at,
            },
        );
        // Discover and resume each NAMED work-group from its own `cursor-<hex>.ckpt` (#60),
        // so a broadcast or competing group keeps its position across a restart instead of
        // redelivering the whole log. Recovery is deliberately NOT bounded by `max_groups`: the
        // cap gates only NEW group creation (the `poll_in` allocation path), never the resume of
        // groups that are already durable on disk. Capping recovery would silently DROP the
        // committed cursors of the groups past the cap whenever an operator LOWERS `--max-groups`
        // below the on-disk group count, resetting those groups to offset 0 and redelivering the
        // whole already-acked log. Loading every existing group unconditionally keeps a config
        // change from corrupting durable state; the cap still bounds unbounded runtime growth from
        // wire-named groups created after open.
        let mut group_last_checkpointed = BTreeMap::new();
        {
            let fs = log.filesystem();
            for name in fs.list()? {
                let Some(gname) = parse_group_checkpoint_name(&name) else {
                    continue;
                };
                if validate_group_name(&gname).is_err() || groups.contains_key(&gname) {
                    continue;
                }
                let (_, recovered) = Checkpoint::open(fs.open(&name)?)?;
                let gcursor = resume_cursor_from_snapshot(recovered.as_deref(), flushed);
                group_last_checkpointed.insert(gname.clone(), gcursor.committed().get());
                groups.insert(
                    gname,
                    WorkGroup {
                        cursor: gcursor,
                        leases: LeaseTable::new(config.lease),
                        router: None,
                        last_activity: opened_at,
                    },
                );
            }
        }

        // The DLQ sink's log shares the main log's segment sizing but is NEVER byte-capped: a
        // poison record is the durable evidence of a dropped message and must not itself be shed.
        let dlq_config = LogConfig {
            max_segment_bytes: config.log.max_segment_bytes,
            max_total_bytes: 0,
            // The DLQ is already the durable forensic sink for dropped messages; it needs no second
            // forensic quarantine of its own.
            max_quarantine_bytes: 0,
        };
        // Eagerly open (recovering its high-water mark) the DLQ sink IF its subdirectory already
        // exists from a prior run, so the idempotency key is present before the first poison
        // redelivers after a crash. A fresh data directory has no `dlq/` yet, so the sink stays
        // unopened (lazy) and the no-poison path never creates it.
        let dlq = if Self::dlq_dir_exists(&log) {
            Some(DlqSink::open(
                log.filesystem(),
                log.clock_clone(),
                dlq_config,
            )?)
        } else {
            None
        };

        let mut engine = Engine {
            log,
            groups,
            group_last_checkpointed,
            lease_config: config.lease,
            delivery: config.delivery,
            max_in_flight: config.max_in_flight,
            // Floor the per-consumer credit to 1 (#65): a zero ceiling would deliver nothing to any
            // connection, wedging every consumer. The hard floor of one guarantees forward progress.
            consumer_credit: config.consumer_credit.max(1),
            // The per-consumer BYTE budget (#275) is NOT floored: `0` means unlimited (the byte
            // budget is off, only the message credit binds), matching the other byte bounds. A
            // non-zero budget never wedges a consumer because the session always delivers at least
            // ONE message even if it exceeds the budget (the floor-of-one in `handle_flow`).
            consumer_credit_bytes: config.consumer_credit_bytes,
            checkpoint,
            checkpoint_interval: config.checkpoint_interval,
            counters_checkpoint,
            retention: RetentionBounds {
                max_bytes: config.max_retained_bytes,
                max_age_ms: config.max_age_ms,
                max_messages: config.max_messages,
            },
            disk_full_policy: config.disk_full_policy,
            max_groups: config.max_groups,
            // The idle-eviction window (#277), converted from milliseconds to the clock seam's
            // nanoseconds and saturated rather than overflowed. `0` (disabled) stays 0, so the
            // sweep is a no-op unless an operator opts in.
            group_idle_evict_nanos: config.group_idle_evict_ms.saturating_mul(1_000_000),
            last_checkpointed: default_committed,
            // Seeded from the durable counters snapshot (#98), all-zeros if it was missing or torn.
            counters,
            fsync: LatencyHistogram::default(),
            // The bounded metric registry (#97), from the clock seam; its head and per-consumer
            // floors are seeded from the recovered state after construction.
            registry: MetricRegistry::new(crate_version(), start_time_unix_seconds, opened_at),
            last_dead_lettered: None,
            dlq,
            dlq_config,
            // Empty by default: no group is key_shared until an operator configures one (#64), so an
            // unconfigured engine is plain competing everywhere and unchanged.
            key_shared_groups: std::collections::BTreeSet::new(),
        };
        engine.seed_registry_from_recovered_state(flushed);
        Ok(engine)
    }

    /// Seeds the metric registry from the recovered durable state (#97), so the per-consumer lag
    /// series is correct from the FIRST scrape after a restart, not zeroed. The durable head is the
    /// flushed offset (a record count), and each recovered group's commit floor is its committed
    /// offset; offsets in this codebase are record counts, so they map directly to the registry's
    /// record-count head and per-consumer floor. The default group `""` is included.
    fn seed_registry_from_recovered_state(&mut self, flushed: u64) {
        self.registry.seed_head(flushed);
        for (name, g) in &self.groups {
            self.registry
                .set_consumer_committed(name.as_bytes(), g.cursor.committed().get());
        }
    }

    /// Whether the `dlq/` subdirectory already exists, so a prior run dead-lettered at least one
    /// message. Used by [`Engine::open`] to decide whether to eagerly open the sink (rebuilding the
    /// idempotency high-water mark) versus deferring to the lazy open on the first dead-letter.
    /// This is a non-creating probe ([`Filesystem::subdir_exists`]), so `Engine::open` on a fresh
    /// data directory never materializes the DLQ subdirectory.
    fn dlq_dir_exists(log: &Log<F, C>) -> bool {
        log.filesystem().subdir_exists(DLQ_SUBDIR).unwrap_or(false)
    }

    /// Opens (creating if absent) the durable resilience-counters checkpoint (#98) and recovers the
    /// last snapshot, returning the checkpoint handle plus the seeded [`Counters`]. A restart
    /// resumes the operational history instead of zeroing it. The recovered counters are a MONOTONIC
    /// LOWER BOUND: the snapshot is written on a cadence, not per increment, so a crash loses at
    /// most the increments since the last snapshot.
    ///
    /// The counters are strictly an OBSERVABILITY aid, never correctness state, so this NEVER fails
    /// the open on a damaged snapshot: a torn slot is discarded by `CountersCheckpoint::open` (the
    /// CRC dual-slot fallback) and a wrong-shaped-but-CRC-valid payload decodes as all-zeros via the
    /// tolerant `Counters::decode_snapshot`. It does not touch the durable log, cursors, or DLQ. The
    /// only errors it can return are genuine IO failures from creating or reading the file (the same
    /// failures that would already have failed opening the log itself), not a corrupt snapshot.
    ///
    /// After seeding, it reconciles the RECOVERY-LOSS counter family with the durable log / loss
    /// report (#307) via [`Engine::reconcile_skip_loss_counters`], so the recovered value is "not lower
    /// than before the crash" even across a `kill -9`. That step is a pure in-memory `max` (it never
    /// lowers a counter and never fails recovery), so the never-block-recovery contract is preserved.
    /// The CONSUMER-TRUNCATION `truncated_records` is not replay-derivable and keeps its snapshot-only
    /// lower bound.
    ///
    /// # Errors
    /// Propagates a genuine IO error from creating or opening the counters checkpoint file.
    fn open_counters_checkpoint(
        log: &Log<F, C>,
    ) -> Result<(CountersCheckpoint<F::File>, Counters), EngineError> {
        let counters_file = {
            let fs = log.filesystem();
            if fs.exists(COUNTERS_CHECKPOINT)? {
                fs.open(COUNTERS_CHECKPOINT)?
            } else {
                let file = fs.create_new(COUNTERS_CHECKPOINT)?;
                fs.sync_dir()?; // the new file's directory entry must be durable
                file
            }
        };
        let (counters_checkpoint, recovered) = CountersCheckpoint::open(counters_file)?;
        let mut counters = recovered
            .as_deref()
            .map_or_else(Counters::default, Counters::decode_snapshot);
        // Checkpoint-plus-replay reconciliation for the RECOVERY-LOSS family (#307): raise the
        // snapshot's recovery-loss values (records/bytes skipped and the offset watermark) to at least
        // what the just-recovered durable log / loss report implies, so a hard crash that lost the
        // post-snapshot increments still resumes a value never lower than before the crash. A pure
        // `max` over already-recovered values, so it cannot fail recovery. The consumer-truncation
        // `truncated_records` is NOT replay-derivable and is deliberately left at its snapshot value.
        Self::reconcile_skip_loss_counters(
            &mut counters,
            log.loss_report(),
            log.flushed_offset().get(),
        );
        Ok((counters_checkpoint, counters))
    }

    /// Checkpoint-plus-replay reconciliation for the RECOVERY-LOSS counter family (#307), the
    /// explicit, unified form of the lower bound #306 left implicit. The durable counters snapshot
    /// (#306) is a MONOTONIC LOWER BOUND: a `kill -9` between the last cadence snapshot and the crash
    /// loses the increments in that window, so the snapshot alone can resume a counter LOWER than it
    /// stood at crash time. This reconciliation raises each RECOVERY-LOSS value to
    /// `max(snapshot, replay)` where the replay value is what the durable log / loss report implies,
    /// restoring a strict cross-restart MONOTONIC NON-DECREASING property for that family.
    ///
    /// HONEST SCOPE (#307): only the RECOVERY-LOSS-derived counters are reconciled, because only they
    /// are replay-reconstructable from a durable artifact (the `LossReport`). The replay sources are
    /// the just-recovered durable artifacts (no extra IO):
    /// - `records_skipped` is raised to at least the loss report's total estimated records lost.
    /// - `bytes_skipped` is raised to at least the loss report's total bytes skipped (the same total
    ///   the `ironbus_recovery_loss_bytes` gauge family is repopulated from in `health.rs`).
    /// - `last_skip_offset` is raised to `max(checkpoint, replay)`, where the replay value is the
    ///   durable head recovery landed on when it dropped a torn tail (a recovery loss reached up to
    ///   the recovered head, an UPPER BOUND on the highest skipped offset). With NO recovery loss the
    ///   replay offset is `0`, so a clean log leaves the snapshot untouched. (Its runtime
    ///   CONSUMER-TRUNCATION contribution, `max(self, earliest)`, is not replay-derivable and so keeps
    ///   only the snapshot lower bound.)
    ///
    /// DELIBERATELY NOT reconciled: `truncated_records` (and `truncations`) are CONSUMER-TRUNCATION
    /// counts, a transient force-reap-driven runtime quantity that is NOT in the durable `LossReport`
    /// and NOT replay-derivable. Maxing it against a RECOVERY torn-tail estimate would conflate two
    /// different quantities (and could spuriously raise a consumer-truncation count from an unrelated
    /// recovery loss). Like the operational counters, it retains #306's snapshot-only lower bound.
    ///
    /// It is a pure `max` over in-memory values, so it can only RAISE a counter, never lower one
    /// (preserving #306's lower bound), and it can NEVER fail recovery: a missing or malformed loss
    /// report degrades to an empty report (replay all-zeros) and the snapshot value stands. When a
    /// replay value actually raises a snapshot value, `counter_checkpoint_repairs` is incremented
    /// once (the `ironbus_counter_checkpoint_repair_total` signal), so an operator can see the
    /// lower-bound recovery firing after a hard crash; a snapshot that already dominates the replay
    /// (the clean-shutdown case) increments nothing.
    fn reconcile_skip_loss_counters(counters: &mut Counters, loss: &LossReport, flushed: u64) {
        let replay_records = loss.total_records_lost_estimate();
        let replay_bytes = loss.total_bytes_skipped();
        // A recovery loss reached up to the recovered head, so the head is the highest skipped offset;
        // with no loss there is no recovery skip offset to replay, so the snapshot value stands.
        let replay_offset = if loss.is_empty() { 0 } else { flushed };

        // Only the RECOVERY-LOSS-derived counters are reconciled. `truncated_records`
        // (consumer-truncation) is intentionally left at its snapshot value.
        let reconciled_records = counters.records_skipped.max(replay_records);
        let reconciled_bytes = counters.bytes_skipped.max(replay_bytes);
        let reconciled_offset = counters.last_skip_offset.max(replay_offset);

        // A repair is any reconciled value strictly above the snapshot value: the snapshot alone
        // would have resumed too low, so the replay raised it. Detected BEFORE the assignment.
        let repaired = reconciled_records > counters.records_skipped
            || reconciled_bytes > counters.bytes_skipped
            || reconciled_offset > counters.last_skip_offset;

        counters.records_skipped = reconciled_records;
        counters.bytes_skipped = reconciled_bytes;
        counters.last_skip_offset = reconciled_offset;
        if repaired {
            counters.counter_checkpoint_repairs =
                counters.counter_checkpoint_repairs.saturating_add(1);
        }
    }

    /// Durably records the current committed offset, so a later [`Engine::open`] resumes
    /// from here. The checkpoint is an optimization: it may lag the true committed cursor
    /// (a crash then redelivers a few already-processed messages, which at-least-once
    /// permits), but it never records an offset that was not committed.
    ///
    /// # Errors
    /// Propagates a storage error from writing the checkpoint.
    pub fn checkpoint_cursor(&mut self) -> Result<(), EngineError> {
        let Some(group) = self.groups.get(DEFAULT_GROUP) else {
            return Ok(());
        };
        let committed = group.cursor.committed().get();
        // Persist when the watermark advanced OR there is an acked-ahead set to capture: an
        // out-of-order ack moves the ahead set without advancing the watermark, and the
        // clean-disconnect flush is the right place to record it so those acks are not
        // redelivered after a restart. A forced checkpoint with nothing new (a connection
        // close that did no acking) stays a no-op. Only the default group is durable today.
        let has_ahead = !group.cursor.ahead_ranges().is_empty();
        if committed > self.last_checkpointed || has_ahead {
            let payload = self.cursor_checkpoint_payload();
            self.checkpoint.write(&payload)?;
            self.last_checkpointed = committed;
        }
        Ok(())
    }

    /// Builds the checkpoint payload for the current cursor: the full [`AckCursor`] snapshot
    /// (the committed watermark plus the acked-ahead set) when it fits a checkpoint slot,
    /// else the watermark plus the leading acked-ahead runs that fit. Dropping the overflow
    /// runs only redelivers those already-acked messages after a crash (at-least-once safe);
    /// it never loses an ack below the watermark. A pathological ahead set (many disjoint
    /// out-of-order acks) is the only case that overflows; the in-flight window bounds it.
    fn cursor_checkpoint_payload(&self) -> Vec<u8> {
        self.groups
            .get(DEFAULT_GROUP)
            .map_or_else(Vec::new, |g| snapshot_payload(&g.cursor))
    }

    /// Checkpoints the committed cursor if it has advanced at least `checkpoint_interval`
    /// offsets since the last checkpoint, returning whether a checkpoint was written. This
    /// bounds how many messages a crash redelivers to roughly `checkpoint_interval` while
    /// keeping the checkpoint write rate far below one per ack (edge flash endurance).
    ///
    /// # Errors
    /// Propagates a storage error from writing the checkpoint.
    pub fn maybe_checkpoint(&mut self) -> Result<bool, EngineError> {
        let committed = self
            .groups
            .get(DEFAULT_GROUP)
            .map_or(0, |g| g.cursor.committed().get());
        if committed.saturating_sub(self.last_checkpointed) >= self.checkpoint_interval.max(1) {
            let payload = self.cursor_checkpoint_payload();
            self.checkpoint.write(&payload)?;
            self.last_checkpointed = committed;
            // Piggyback the resilience-counters snapshot on the cursor-checkpoint cadence (#98), so
            // the counters become durable on the same low-frequency rhythm without a per-increment
            // fsync. Best-effort: a counters write failure only loses some observability history on
            // a later crash, never correctness, so it must NOT fail the cursor checkpoint that just
            // succeeded. The counters are an observability aid, not durable correctness state.
            let _ = self.checkpoint_counters();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Durably snapshots the current resilience [`Counters`] to `counters.ckpt` (#98), so a later
    /// [`Engine::open`] resumes the operational history instead of zeroing it. It uses the SAME
    /// crash-safe dual-slot CRC discipline as the cursor checkpoint: a torn write reverts to the
    /// prior slot, and on recovery a torn or missing snapshot decodes as all-zeros, so it can never
    /// block startup.
    ///
    /// This is deliberately NOT called on every counter increment (an fsync per produce/ack would
    /// destroy throughput). It is called on the cursor-checkpoint cadence ([`Engine::maybe_checkpoint`])
    /// and the graceful-shutdown flush ([`Engine::checkpoint_all_groups`]), so the resumed counters
    /// are a MONOTONIC LOWER BOUND that loses at most the increments since the last snapshot on a
    /// crash, which observability tolerates.
    ///
    /// # Errors
    /// Propagates a storage error from writing the snapshot. Callers that piggyback it on a cursor
    /// checkpoint IGNORE this error on purpose (lost history, not lost correctness); the explicit
    /// shutdown flush surfaces it so a disk failure is not silently swallowed there.
    pub fn checkpoint_counters(&mut self) -> Result<(), EngineError> {
        let payload = self.counters.encode_snapshot();
        self.counters_checkpoint.write(&payload)?;
        Ok(())
    }

    /// Durably records a work-group's committed cursor (#60), so a later [`Engine::open`]
    /// resumes that group from here. The default group writes `cursor.ckpt` (delegating to
    /// [`Engine::checkpoint_cursor`]); a named group writes its own `cursor-<hex>.ckpt`. Like the
    /// default, it is a lagging optimization: a crash redelivers a few already-processed
    /// messages (at-least-once), never an offset that was not committed. The clean-disconnect
    /// flush is the right caller.
    ///
    /// # Errors
    /// Propagates a storage error from writing the checkpoint.
    pub fn checkpoint_group(&mut self, group: &str) -> Result<(), EngineError> {
        if group == DEFAULT_GROUP {
            return self.checkpoint_cursor();
        }
        let Some(g) = self.groups.get(group) else {
            return Ok(());
        };
        let committed = g.cursor.committed().get();
        let has_ahead = !g.cursor.ahead_ranges().is_empty();
        let last = self
            .group_last_checkpointed
            .get(group)
            .copied()
            .unwrap_or(0);
        if committed > last || has_ahead {
            self.write_group_checkpoint(group, committed)?;
        }
        Ok(())
    }

    /// Like [`Engine::maybe_checkpoint`] but for a named work-group (#60): checkpoints it if its
    /// committed cursor advanced at least `checkpoint_interval` since its last checkpoint, so a
    /// crash redelivers a bounded tail per group. The default group delegates to
    /// [`Engine::maybe_checkpoint`].
    ///
    /// # Errors
    /// Propagates a storage error from writing the checkpoint.
    pub fn maybe_checkpoint_group(&mut self, group: &str) -> Result<bool, EngineError> {
        if group == DEFAULT_GROUP {
            return self.maybe_checkpoint();
        }
        let Some(g) = self.groups.get(group) else {
            return Ok(false);
        };
        let committed = g.cursor.committed().get();
        let last = self
            .group_last_checkpointed
            .get(group)
            .copied()
            .unwrap_or(0);
        if committed.saturating_sub(last) >= self.checkpoint_interval.max(1) {
            self.write_group_checkpoint(group, committed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Forces a durable checkpoint of EVERY live work-group's committed cursor (the default group
    /// and every named group), so a clean operator shutdown persists all cursors before exit and a
    /// restart does not redeliver acked messages (refs #195). Each group is checkpointed via
    /// [`Engine::checkpoint_group`], which is a no-op for a group whose watermark has not advanced
    /// since its last checkpoint (and skips the in-memory-only named groups whose durable per-group
    /// state is #60). Unlike [`Engine::maybe_checkpoint_group`] this is not interval-gated: it is the
    /// final flush a SIGTERM/SIGINT handler triggers, where a few extra checkpoint writes are cheap
    /// against the cost of redelivering already-acked messages. On the first per-group write error it
    /// stops and propagates, so a disk failure is surfaced rather than swallowed.
    ///
    /// It is also the graceful-shutdown flush point for the resilience COUNTERS (#98): the final
    /// counters snapshot is written here AFTER every cursor is flushed, so a restart after a clean
    /// stop shows the final counts, not a stale cadence snapshot. The counters flush is explicit
    /// (its error is surfaced) but runs LAST, so a counters disk failure never prevents the
    /// correctness-critical cursor flush from completing first.
    ///
    /// # Errors
    /// Propagates the first storage error from writing a group's checkpoint, or from the final
    /// counters snapshot.
    pub fn checkpoint_all_groups(&mut self) -> Result<(), EngineError> {
        // Snapshot the names first so the checkpoint calls (which take `&mut self`) do not borrow
        // the live `groups` map across the loop.
        let names: Vec<String> = self.groups.keys().cloned().collect();
        for name in names {
            self.checkpoint_group(&name)?;
        }
        // Flush the resilience counters LAST, so the cursor flushes (correctness) always complete
        // first. A restart after this clean stop resumes the final counts (#98).
        self.checkpoint_counters()?;
        Ok(())
    }

    /// Writes a named work-group's cursor snapshot to its `cursor-<hex>.ckpt`, creating the file
    /// (and syncing the directory) on first use. The checkpoint file is reopened per write so
    /// the crash-safe two-slot sequence continues correctly.
    fn write_group_checkpoint(&mut self, group: &str, committed: u64) -> Result<(), EngineError> {
        let payload = match self.groups.get(group) {
            Some(g) => snapshot_payload(&g.cursor),
            None => return Ok(()),
        };
        let name = group_checkpoint_name(group);
        let file = {
            let fs = self.log.filesystem();
            if fs.exists(&name)? {
                fs.open(&name)?
            } else {
                let f = fs.create_new(&name)?;
                fs.sync_dir()?; // the new file's directory entry must be durable
                f
            }
        };
        let (mut cp, _) = Checkpoint::open(file)?;
        cp.write(&payload)?;
        self.group_last_checkpointed
            .insert(group.to_string(), committed);
        Ok(())
    }

    /// Ensures a NAMED work-group is live in memory, RESUMING it from its durable `cursor-<hex>.ckpt`
    /// if one is present, else creating it fresh at offset 0 (#277, #60). This is the re-creation
    /// counterpart to [`Engine::open`]'s group recovery: a group EVICTED at runtime (idle sweep or
    /// explicit Unsub) left its checkpoint durably at the head, so re-creating it here resumes at the
    /// head and redelivers nothing it had acked, exactly the never-lose-committed-position invariant.
    /// A group that was never durable (never checkpointed) is created at offset 0, the unchanged
    /// first-poll behavior.
    ///
    /// A no-op if the group is already live or is the default group (always present). The caller has
    /// already validated the name and the cap, so this only allocates. The recovered committed offset
    /// seeds the per-group checkpoint-interval bookkeeping so a resumed group does not redundantly
    /// re-checkpoint its head on the next interval.
    ///
    /// # Errors
    /// Propagates a storage error from opening or reading the group's checkpoint file.
    fn ensure_group(&mut self, group: &str, now: u64) -> Result<(), EngineError> {
        if self.groups.contains_key(group) {
            return Ok(());
        }
        let flushed = self.log.flushed_offset().get();
        let name = group_checkpoint_name(group);
        // Resume from the durable checkpoint if present (the evicted-then-re-created path), else
        // start fresh at offset 0 (a genuinely new group). Clamped to the head exactly as `open`.
        let cursor = {
            let fs = self.log.filesystem();
            if fs.exists(&name)? {
                let (_, recovered) = Checkpoint::open(fs.open(&name)?)?;
                resume_cursor_from_snapshot(recovered.as_deref(), flushed)
            } else {
                AckCursor::new()
            }
        };
        self.group_last_checkpointed
            .insert(group.to_string(), cursor.committed().get());
        self.groups.insert(
            group.to_string(),
            WorkGroup {
                cursor,
                leases: LeaseTable::new(self.lease_config),
                router: None,
                last_activity: now,
            },
        );
        Ok(())
    }

    /// Appends a message and makes it durable before returning its offset (so a producer's
    /// ack is post-fsync).
    ///
    /// When the durable-log byte cap is hit, the overflow policy ([`EngineConfig::disk_full_policy`])
    /// decides the behavior. Under [`DiskFullPolicy::DropNew`] (the default) the over-cap produce is
    /// rejected (the drop-new shed, behavior unchanged). Under [`DiskFullPolicy::DropOldest`] the
    /// engine first tries the consumer-safe reaper, then force-reaps the OLDEST sealed segment
    /// (ignoring consumer-safety, #82) to make room, and retries the append; a consumer whose
    /// cursor was force-reaped away sees a one-time truncation on its next poll (#84). If only the
    /// active segment remains (nothing left to force out), `DropOldest` falls back to the drop-new
    /// rejection, so a single oversized in-flight set cannot wedge the log empty.
    ///
    /// # Errors
    /// Propagates a storage error from the append or sync. A produce rejected because the
    /// durable log is at its byte cap surfaces the non-fatal [`StorageError::AtCapacity`]
    /// (wrapped in [`EngineError::Storage`]) and increments the `produce_rejected` counter;
    /// nothing is appended and `produced` / `produced_bytes` do not move. Under `DropOldest` this
    /// rejection only happens in the wedge-guard fall-back (only the active segment remains).
    pub fn produce(&mut self, message: &Append<'_>) -> Result<Offset, EngineError> {
        // Time the WHOLE durable append (append + fsync) for the registry's append-latency
        // histogram (#97), via the clock seam so the deterministic sim stays reproducible. Read the
        // start before the append; on a shed/error it is simply unused.
        let append_started = self.log.now_monotonic();
        let offset = match self.append_with_policy(message) {
            Ok(offset) => offset,
            Err(e) => {
                // The drop-new shed: count the rejection (a shed-rate signal) but advance no
                // produce statistics, since nothing was written. Other storage errors fall
                // through unchanged; only the at-capacity shed is a counted rejection.
                if e.is_at_capacity() {
                    self.counters.produce_rejected =
                        self.counters.produce_rejected.saturating_add(1);
                }
                return Err(EngineError::Storage(e));
            }
        };
        // Time the durability barrier itself (the fsync), via the clock seam so the
        // deterministic sim stays reproducible (logical time does not advance in-memory).
        let started = self.log.now_monotonic();
        self.log.sync()?;
        let fsync_nanos = self.log.now_monotonic().saturating_sub(started);
        self.fsync.observe(fsync_nanos);
        // Mirror the fsync into the registry's fixed-bucket `ironbus_fsync_duration_seconds`, record
        // the whole-append latency, and advance the durable head so every consumer's lag (head minus
        // its commit floor) rises (#97). All three are O(1) and allocation-free.
        self.registry.observe_fsync_nanos(fsync_nanos);
        self.registry
            .observe_append_nanos(self.log.now_monotonic().saturating_sub(append_started));
        self.registry.record_appended();
        self.counters.produced += 1;
        let bytes = message.key.len() + message.headers.len() + message.payload.len();
        self.counters.produced_bytes = self
            .counters
            .produced_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        // Consumer-safe retention (refs #13, #80): after the record is durable, reclaim disk by the size, age, or count bound,
        // by deleting whole old SEALED segments while the log is over the retention bound, but
        // never one any consumer still needs. Run on the produce path so space is freed exactly as
        // the log grows; it is a no-op unless the bound is set. The protect floor is the MINIMUM
        // committed offset across every group, so the slowest group's records are never reaped.
        self.reap_for_retention()?;
        // Idle named-group eviction sweep (#277): the produce seam is the second deterministic tick
        // (the poll seam is the first), so a broker that produces but is not being polled still
        // reclaims idle groups against the clock seam. The sweep is a no-op when the window is
        // disabled (`group_idle_evict_ms == 0`). A produce ADVANCES the head, so any group that was
        // caught up is now behind and (correctly) not evictable until it catches up again; the sweep
        // here therefore reclaims only groups that were already idle AND caught up before this append.
        let now = self.log.now_monotonic();
        self.sweep_idle_groups(now)?;
        Ok(offset)
    }

    /// Appends `message` honoring the disk-full overflow policy (#82), returning the storage-level
    /// result so [`Engine::produce`] keeps its existing rejection-counting and statistics path.
    ///
    /// Under [`DiskFullPolicy::DropNew`] (the default) this is exactly `log.append`: an over-cap
    /// produce returns [`StorageError::AtCapacity`] and nothing is reaped, so the historical
    /// behavior is byte-for-byte unchanged.
    ///
    /// Under [`DiskFullPolicy::DropOldest`], on an `AtCapacity` rejection it reclaims space and
    /// retries: first the consumer-safe reap (in case retention is also configured and frees space
    /// without data loss), then, if the log is still over cap, [`Log::reap_oldest_forced`] to delete
    /// the OLDEST sealed segment (which may drop a slow group's unconsumed records). The loop is
    /// bounded: if the consumer-safe reap and the forced reap both free nothing (only the active
    /// segment remains), it returns the original `AtCapacity`, so `produce` falls back to the
    /// drop-new rejection and a single oversized in-flight set cannot wedge the log empty. Each
    /// forced reap increments `segments_force_reaped`.
    fn append_with_policy(&mut self, message: &Append<'_>) -> Result<Offset, StorageError> {
        match self.log.append(message) {
            Ok(offset) => Ok(offset),
            // Only the at-capacity shed is reclaimable; any other storage error (a frozen writer,
            // an oversized record) propagates unchanged, and under DropNew the rejection is final.
            Err(e) if e.is_at_capacity() && self.disk_full_policy == DiskFullPolicy::DropOldest => {
                self.make_room_then_append(message, e)
            }
            Err(e) => Err(e),
        }
    }

    /// The `DropOldest` reclaim-then-retry loop for an over-cap produce (#82). On entry the append
    /// already failed with `at_capacity`. It repeatedly frees space (a consumer-safe reap first,
    /// then a forced oldest-segment reap) and retries the append, until the append succeeds or no
    /// reap can free anything (only the active segment remains), in which case it returns the last
    /// `AtCapacity` so the caller falls back to the drop-new rejection (the wedge guard).
    fn make_room_then_append(
        &mut self,
        message: &Append<'_>,
        at_capacity: StorageError,
    ) -> Result<Offset, StorageError> {
        let mut last = at_capacity;
        loop {
            // Prefer the consumer-safe reaper: if retention is also configured, it may free a
            // fully-consumed segment with NO data loss. The protect floor is the slowest group's
            // committed offset, so this never drops a needed record.
            let protect_below = self.min_committed_offset();
            let safe = self.log.reap(self.retention, protect_below)?;
            self.counters.segments_reaped = self
                .counters
                .segments_reaped
                .saturating_add(safe.segments_reaped);
            // If the consumer-safe reap freed nothing, force out the OLDEST sealed segment, even
            // one a slow consumer still needs (it sees a one-time truncation on its next poll, #84).
            let mut forced_this_pass = false;
            if safe.segments_reaped == 0 {
                match self.log.reap_oldest_forced()? {
                    Some(_) => {
                        self.counters.segments_force_reaped =
                            self.counters.segments_force_reaped.saturating_add(1);
                        forced_this_pass = true;
                    }
                    // Only the active segment remains: nothing left to free, so the wedge guard
                    // returns the rejection and `produce` sheds (drop-new fall-back).
                    None => return Err(last),
                }
            }
            // Retry the append now that space was freed. A success ends the loop; another
            // at-capacity means one freed segment was not enough, so loop and free more (the loop
            // terminates because each pass either frees a segment or hits the active-only guard).
            match self.log.append(message) {
                Ok(offset) => return Ok(offset),
                Err(e) if e.is_at_capacity() => {
                    last = e;
                    // Defensive: if neither reaper made progress this pass, stop rather than spin.
                    if safe.segments_reaped == 0 && !forced_this_pass {
                        return Err(last);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Reclaims disk by reaping fully-consumed old sealed segments when the durable log trips any
    /// enabled retention bound (size, age, or count) (refs #13, #80). A no-op when every bound is
    /// `0` (the default, retention off). The protect floor is the minimum committed offset across
    /// ALL consumer groups (the default group `""` always exists, so the min is well-defined), so
    /// a record any group has not yet consumed is never reaped. The age bound reads `now` from the
    /// engine clock seam (shared with the log), so the deterministic sim drives it. Counts the
    /// reaped segments (saturating), regardless of which bound triggered.
    ///
    /// A reap is best-effort space reclamation, but a real IO error from a sync or unlink is a
    /// storage error: it propagates rather than being swallowed, since [`Log::reap`] keeps
    /// `segments` and the running byte/count totals consistent with disk on a partial failure (the
    /// in-memory removal happens only after the durable unlink), so propagating never corrupts
    /// state. It is called only after the produce already succeeded and was counted, so a reap
    /// error does not undo a durable record.
    fn reap_for_retention(&mut self) -> Result<(), EngineError> {
        if self.retention == RetentionBounds::default() {
            return Ok(());
        }
        let protect_below = self.min_committed_offset();
        let outcome = self.log.reap(self.retention, protect_below)?;
        self.counters.segments_reaped = self
            .counters
            .segments_reaped
            .saturating_add(outcome.segments_reaped);
        Ok(())
    }

    /// The minimum committed offset across every work-group: the protect floor for retention, so
    /// the slowest group's unconsumed records are never reaped. The default group (`""`) always
    /// exists, so the iterator is never empty; a fresh group sits at offset 0, which keeps the
    /// floor at 0 (reaping nothing) until it has consumed something, exactly the safe behavior.
    fn min_committed_offset(&self) -> u64 {
        self.groups
            .values()
            .map(|g| g.cursor.committed().get())
            .min()
            .unwrap_or(0)
    }

    /// Evicts (reclaims the in-memory state of) every NAMED work-group that has been IDLE past the
    /// configured window AND is safe to drop, against the engine clock seam `now` (#277). This is
    /// the deterministic, NON-threaded lifecycle sweep that completes #240: the cap (`max_groups`)
    /// bounds the number of live groups, this reclaims the idle ones, so a long-lived broker does
    /// not accumulate per-group `AckCursor` + `LeaseTable` state for groups no consumer touches.
    ///
    /// It runs from the produce and poll seams (never a background thread), so eviction is fully
    /// clock-driven and deterministic. A no-op when the window is disabled (`group_idle_evict_nanos
    /// == 0`), so an unconfigured broker is byte-for-byte unchanged.
    ///
    /// The NEVER-LOSE-COMMITTED-POSITION invariant: a group is evicted ONLY if it is
    /// - NAMED (the default group `""` is never evicted; it is the durable wire group), AND
    /// - PLAIN COMPETING (no `key_shared` router; a `key_shared` group carries live-member state and
    ///   is left to its membership lifecycle), AND
    /// - FULLY CAUGHT UP: its committed cursor is at the durable head (`committed == flushed`) with
    ///   NO acked-ahead set, so once its durable `cursor-<hex>.ckpt` is persisted AT THE HEAD,
    ///   re-creating the group resumes from that checkpoint and redelivers NOTHING it had acked, AND
    /// - LEASE-FREE: its `LeaseTable` holds no lease, so no consumer is mid-work, AND
    /// - IDLE: no poll / ack / nack / progress / term has touched it for at least the window.
    ///
    /// A group that is BEHIND the head is NEVER evicted: evicting then re-creating a behind group
    /// could only lose its position or redeliver, so a behind group is by definition not idle in the
    /// meaningful sense.
    ///
    /// Before dropping a group from memory the sweep DURABLY CHECKPOINTS it at the head (it was
    /// caught up, so the checkpoint records the head), so BOTH an in-process re-subscribe (which
    /// re-creates the group by resuming that checkpoint, see [`Engine::group_entry`]) AND a restart
    /// resume exactly where it left off. The checkpoint file is KEPT, never deleted: deleting it
    /// would reset a re-created group to offset 0 and redeliver the whole already-acked log. If the
    /// checkpoint write fails, the group is KEPT in memory (not evicted), so a disk error can never
    /// cost a committed position. Evicting frees the group's slot against the `max_groups` cap
    /// immediately.
    ///
    /// # Errors
    /// Propagates a storage error from durably checkpointing an evicted group at the head.
    fn sweep_idle_groups(&mut self, now: u64) -> Result<(), EngineError> {
        // Disabled: never evict. The common path is a single comparison, so the sweep is cheap on
        // every produce/poll when the operator has not opted in.
        if self.group_idle_evict_nanos == 0 {
            return Ok(());
        }
        let flushed = self.log.flushed_offset().get();
        let window = self.group_idle_evict_nanos;
        // Collect the evictable names first (an immutable borrow), then evict them (a mutable
        // borrow): a BTreeMap cannot be mutated while iterated. The evictable set is bounded by the
        // group cap, so the temporary vector is small.
        let evictable: Vec<String> = self
            .groups
            .iter()
            .filter(|&(name, g)| Self::is_evictable(name, g, flushed, now, window))
            .map(|(name, _)| name.clone())
            .collect();
        for name in evictable {
            self.evict_group(&name)?;
        }
        Ok(())
    }

    /// Durably persists a caught-up group's cursor at the head and then drops it from memory (#277):
    /// the shared eviction step used by both the idle sweep and the explicit-`Unsub` reclaim. The
    /// caller has already proven `group` is evictable (named, plain competing, caught up at the head
    /// with no acked-ahead set, lease-free), so this only persists and removes.
    ///
    /// The ordering is the safety contract: write (and fsync) the `cursor-<hex>.ckpt` at the head
    /// FIRST, only THEN remove the in-memory group. A failure to persist propagates WITHOUT removing
    /// the group, so a disk error never costs a committed position; the group stays live and the
    /// next sweep retries. The checkpoint file is kept (never deleted), so a later re-`Sub` resumes
    /// from the head and redelivers nothing.
    ///
    /// # Errors
    /// Propagates a storage error from writing the group's checkpoint.
    fn evict_group(&mut self, group: &str) -> Result<(), EngineError> {
        let committed = match self.groups.get(group) {
            Some(g) => g.cursor.committed().get(),
            None => return Ok(()),
        };
        // Persist the cursor at the head BEFORE removing the group. `write_group_checkpoint` is
        // unconditional (unlike the interval/has-advanced gate of `checkpoint_group`), so the
        // checkpoint is durably at the head even if no interval checkpoint had fired since the group
        // caught up. Only after this succeeds do we drop the in-memory state.
        self.write_group_checkpoint(group, committed)?;
        self.groups.remove(group);
        self.group_last_checkpointed.remove(group);
        Ok(())
    }

    /// Whether a single work-group is safe to evict on an idle sweep (#277): the predicate behind
    /// [`Engine::sweep_idle_groups`], factored out so the rule is stated and tested in one place.
    /// See that method for the never-lose-committed-position invariant each clause upholds.
    fn is_evictable(name: &str, group: &WorkGroup, flushed: u64, now: u64, window: u64) -> bool {
        // The default group is the durable wire group: never evicted.
        if name == DEFAULT_GROUP {
            return false;
        }
        // A key_shared group carries live-member routing state: leave it to its membership
        // lifecycle (leave-on-unsub / disconnect), not the idle sweep.
        if group.router.is_some() {
            return false;
        }
        // Fully caught up: committed at the head with no acked-ahead set. A BEHIND group (committed
        // below the head, or holding an out-of-order acked-ahead set above the head it has not yet
        // bridged) is never evicted, so re-creation can never lose its position or redeliver.
        let committed = group.cursor.committed().get();
        if committed != flushed || !group.cursor.ahead_ranges().is_empty() {
            return false;
        }
        // No in-flight lease: no consumer is mid-work (a lease, even an expired-but-unreclaimed one,
        // keeps the group alive so its in-flight bookkeeping is never dropped under a holder).
        if group.leases.in_flight() != 0 {
            return false;
        }
        // Idle for at least the window, measured on the monotonic clock seam. `saturating_sub`
        // guards a non-monotonic `now` (it never under-reports the idle span into a false eviction).
        now.saturating_sub(group.last_activity) >= window
    }

    /// Drives the idle-group eviction sweep from the engine's own clock seam (#277), the
    /// caller-supplied-`now`-free entry point. The server runs this from the same actor that owns
    /// the engine, so eviction stays clock-driven and single-writer, never a background thread.
    /// Equivalent to [`Engine::sweep_idle_groups`] at the current monotonic time; a no-op when the
    /// idle window is disabled.
    ///
    /// # Errors
    /// Propagates a storage error from durably checkpointing an evicted group at the head.
    pub fn sweep_idle_groups_now(&mut self) -> Result<(), EngineError> {
        let now = self.log.now_monotonic();
        self.sweep_idle_groups(now)
    }

    /// Evicts a SPECIFIC named work-group RIGHT NOW if it is safe to drop (#277), used by the
    /// explicit-`Unsub` path: when a connection leaves a named group and it is fully caught up with
    /// no in-flight leases, that group is immediately reclaimable, so it need not wait out the idle
    /// window. It enforces EVERY position-safety clause of the idle sweep (named, plain competing,
    /// fully caught up with no acked-ahead set, lease-free) EXCEPT the idle-window clause, which the
    /// explicit Unsub stands in for. As in the sweep, the group is durably checkpointed at the head
    /// before it is dropped, and the `cursor-<hex>.ckpt` is KEPT, so a later re-`Sub` resumes at the
    /// head and redelivers nothing.
    ///
    /// A no-op (returns `false`) when the feature is disabled (`group_idle_evict_ms == 0`), when the
    /// group is unknown, when any safety clause fails (e.g. it still has in-flight leases that have
    /// not yet drained or expired), or when the head-checkpoint write fails (the group is kept, so a
    /// disk error never costs a committed position; the natural idle sweep reclaims it later once it
    /// qualifies). Returns `true` if the group was evicted.
    pub fn evict_group_if_idle(&mut self, group: &str) -> bool {
        // Disabled means the lifecycle policy is off entirely: do not reclaim even on an explicit
        // Unsub, so an operator who has not opted in sees byte-for-byte unchanged behavior.
        if self.group_idle_evict_nanos == 0 {
            return false;
        }
        let flushed = self.log.flushed_offset().get();
        let evictable = match self.groups.get(group) {
            // `now == last_activity` with a window of 0 makes the idle clause vacuously true, so the
            // predicate reduces to exactly the position-safety clauses; the explicit Unsub is what
            // authorizes skipping the idle wait.
            Some(g) => Self::is_evictable(group, g, flushed, g.last_activity, 0),
            None => false,
        };
        // Persist-then-drop. A checkpoint write error leaves the group live (the `is_ok`), so the
        // explicit reclaim, like the sweep, never trades a committed position for a disk hiccup.
        evictable && self.evict_group(group).is_ok()
    }

    /// Claims and returns the next deliverable message, or [`Poll::Idle`] if none is
    /// available within the in-flight window. A poison message (over max-deliver) is parked
    /// and reported as [`Poll::Parked`].
    ///
    /// # Errors
    /// Returns [`EngineError::GenerationExhausted`] if the lease space is exhausted, or a
    /// storage error from reading the record.
    pub fn poll(&mut self, now: u64) -> Result<Poll, EngineError> {
        self.poll_in(DEFAULT_GROUP, now)
    }

    /// Like [`Engine::poll`] but for a named work-group (#9): the group has its own committed
    /// cursor and in-flight lease set over the shared log, so a broadcast subscriber sees every
    /// message and a competing group shares the work, each independent of the others. The group
    /// is created (at offset 0) on first use. The returned token is only meaningful within
    /// `group` (the lease generation space is per-group).
    ///
    /// # Errors
    /// As [`Engine::poll`].
    pub fn poll_in(&mut self, group: &str, now: u64) -> Result<Poll, EngineError> {
        // Mark the group being polled active FIRST (if it is already live), so the sweep below never
        // evicts the very group this poll is about to drain (#277): a poll IS activity, so refreshing
        // its last-activity before the sweep keeps a self-poll of an otherwise-idle group from
        // needlessly evicting-and-re-creating it.
        if let Some(g) = self.groups.get_mut(group) {
            g.last_activity = now;
        }
        // Sweep idle named groups against the clock seam at the START of every poll (#277), BEFORE
        // the cap gate below, so an evicted slot is freed in time to admit a new group on this same
        // poll: a group at a previously-full cap can be (re-)created the moment an idle peer is
        // reclaimed. The just-refreshed `group` is never evicted here, nor is the default group, a
        // behind group, or a group with in-flight leases.
        self.sweep_idle_groups(now)?;
        // Create a new group only if it is well-named and the group cap allows it (#240):
        // this bounds memory once the wire can name groups. The default group and any
        // existing group are exempt (already present, so they never hit this gate); a
        // `max_groups` of `0` means unlimited, so the cap check is skipped entirely.
        if !self.groups.contains_key(group) {
            validate_group_name(group)?;
            if self.max_groups != 0 && self.groups.len() >= self.max_groups {
                return Err(EngineError::TooManyGroups {
                    max: self.max_groups,
                });
            }
            // Allocate the group, RESUMING from its durable checkpoint if one is present (#277): a
            // group EVICTED earlier in this process left its `cursor-<hex>.ckpt` at the head, so the
            // re-creation resumes at the head and redelivers nothing it had acked. A genuinely new
            // group has no checkpoint and starts at offset 0 (the unchanged first-poll behavior).
            self.ensure_group(group, now)?;
        }
        // The oldest record still in the durable log: it rises above 0 only once the disk-full
        // drop-oldest policy (#82) has force-reaped a prefix. Read it BEFORE borrowing the group
        // mutably (it borrows the log immutably).
        let earliest = self.log.earliest_offset().get();
        let lease_config = self.lease_config;
        let g = self
            .groups
            .entry(group.to_string())
            .or_insert_with(|| WorkGroup::new(lease_config, now));
        // Stamp last-activity again (#277): redundant for a group refreshed before the sweep, but it
        // also covers a freshly created/resumed group and the `or_insert_with` fallback, so EVERY
        // poll (deliverable or idle) keeps the polled group alive against the next sweep.
        g.last_activity = now;
        let committed = g.cursor.committed().get();
        // Below-earliest truncation signal (#84): if this group's next-deliverable offset (its
        // committed cursor) is below the oldest retained record, its data was force-reaped out from
        // under it. Reset the cursor UP to `earliest` (resuming at the oldest record still present,
        // dropping the now-meaningless acked-ahead set and in-flight leases that referenced reaped
        // records) and surface the truncation ONCE. After the reset `committed == earliest`, so a
        // subsequent poll is no longer below earliest and never re-truncates the same gap.
        if committed < earliest {
            let skipped = earliest - committed;
            g.cursor = AckCursor::resume(Offset::new(earliest));
            g.leases = LeaseTable::new(lease_config);
            // Count the skip the moment it is surfaced (#96): a consumer losing this span must never
            // be silent. One truncation event, spanning `skipped` records.
            self.counters.truncations = self.counters.truncations.saturating_add(1);
            self.counters.truncated_records =
                self.counters.truncated_records.saturating_add(skipped);
            // Raise the skip-offset watermark to the offset this consumer skipped up to (#307): the
            // CONSUMER-TRUNCATION contribution to the high-water mark. This runtime increment is not
            // replay-derivable, so it keeps #306's snapshot-only lower bound; the recovery-head
            // contribution is what `reconcile_skip_loss_counters` restores across a crash.
            self.counters.last_skip_offset = self.counters.last_skip_offset.max(earliest);
            // The reset advanced this group's committed cursor UP to `earliest`, so push the new
            // floor to the lag registry (#97), keeping the consumer-lag series correct after a
            // below-earliest truncation (the `g` borrow has ended).
            self.sync_consumer_lag(group, earliest);
            return Ok(Poll::Truncated {
                earliest_retained: Offset::new(earliest),
                skipped,
            });
        }
        let flushed = self.log.flushed_offset().get();
        // The delivery window: at most `max_in_flight` offsets above the committed cursor,
        // and never past the durable end.
        let window_end = committed
            .saturating_add(u64::from(self.max_in_flight))
            .min(flushed);

        let mut offset = committed;
        // The poison message (claimed but over max-deliver) to dead-letter, captured so the
        // crash-atomic DLQ move runs OUTSIDE the borrow of `g` (the DLQ append needs `&mut self`
        // for the sink, which cannot coexist with the live `&mut self.groups` borrow).
        let mut dead_letter: Option<(Offset, LeaseToken, u32, OwnedRecord)> = None;
        while offset < window_end {
            let off = Offset::new(offset);
            if g.cursor.is_acked(off) {
                offset += 1;
                continue;
            }
            match g.leases.claim(off, now) {
                Claim::InFlight => {
                    offset += 1;
                }
                Claim::Exhausted => return Err(EngineError::GenerationExhausted),
                Claim::Granted { token, deliveries } => {
                    let Some(record) = self.log.read_from(off, 1)?.into_iter().next() else {
                        // Unreachable: `off` is below the flushed offset, so a record exists.
                        // Surface it loudly rather than silently stalling if an invariant breaks.
                        return Err(EngineError::MissingRecord { offset });
                    };
                    match self.delivery.disposition(deliveries) {
                        Disposition::Deliver => {
                            self.counters.delivered += 1;
                            if deliveries > 1 {
                                self.counters.redelivered += 1;
                            }
                            return Ok(Poll::Message(Delivery {
                                offset: off,
                                token,
                                deliveries,
                                record,
                            }));
                        }
                        Disposition::DeadLetter => {
                            // Capture and break: the durable DLQ move and the cursor commit happen
                            // below, after the `g` borrow is released. The lease is dropped here so
                            // the in-flight bookkeeping is correct regardless of the move's result.
                            g.leases.ack(&token);
                            dead_letter = Some((off, token, deliveries, record));
                            break;
                        }
                    }
                }
            }
        }
        match dead_letter {
            Some((off, _token, deliveries, record)) => {
                self.dead_letter_in(group, off, deliveries, record)
            }
            None => Ok(Poll::Idle),
        }
    }

    /// Performs the crash-atomic, EXACTLY-ONCE dead-letter move for a poison message in `group` at
    /// source offset `off` after `attempt` deliveries (#63), then commits the source group's cursor
    /// past it and returns [`Poll::Parked`].
    ///
    /// The ordering is the crash-safety contract: APPEND the poison record to the durable DLQ sink
    /// and FSYNC it, THEN commit the source cursor. A crash between the two leaves the source
    /// uncommitted (it redelivers and is re-poisoned on the next run) and the DLQ record already
    /// durable; on reopen the per-group dead-lettered high-water mark, rebuilt from the DLQ itself,
    /// makes the re-poison a no-op append so the message is committed-past WITHOUT a duplicate DLQ
    /// write. The reconciliation key is `(group, source_offset, attempt)`: an offset at or below
    /// the group's high-water mark is already in the sink, so it is committed-past without a second
    /// append.
    ///
    /// The lease has already been dropped by the caller, so on success the message holds no lease
    /// and never redelivers.
    fn dead_letter_in(
        &mut self,
        group: &str,
        off: Offset,
        attempt: u32,
        record: OwnedRecord,
    ) -> Result<Poll, EngineError> {
        // Idempotency: if this (group, source offset) is already durably in the DLQ (at or below
        // the group's recorded high-water mark), do NOT append a second copy. This is the path a
        // redelivered-then-re-poisoned message takes after a crash that landed between the DLQ
        // append and the cursor commit: the sink already has it, so we only commit past it.
        let already = self.dlq_sink()?.already_dead_lettered(group, off.get());
        if !already {
            // APPEND to the DLQ and FSYNC, BEFORE committing the source cursor. A storage error
            // (including a frozen DLQ writer) propagates WITHOUT committing the source, so the move
            // simply did not happen and the message redelivers, never lost and never half-moved.
            self.dlq_sink()?.append_poison(group, &record, attempt)?;
        }
        // The DLQ record is now durable (or was already), so commit the source cursor past the
        // poison message: drop nothing, never redeliver. This is the second, ordered durability
        // step; only after the append's fsync does the source advance.
        let Some(g) = self.groups.get_mut(group) else {
            // Unreachable: poll_in created/looked up the group before reaching here.
            return Err(EngineError::MissingRecord { offset: off.get() });
        };
        g.cursor.ack(off);
        // key_shared (#64): committing past a poison offset frees its key (the poll path already
        // cleared it, so this is idempotent belt-and-suspenders). A no-op for a competing group.
        if let Some(router) = g.router.as_mut() {
            router.clear_offset(off);
        }
        // Committing past the poison advances this group's cursor, so push the new floor to the lag
        // registry (#97), keeping the consumer-lag series correct after a dead-letter.
        let committed = g.cursor.committed().get();
        self.sync_consumer_lag(group, committed);
        self.counters.dead_lettered += 1;
        self.last_dead_lettered = Some(off);
        Ok(Poll::Parked {
            offset: off,
            record,
        })
    }

    /// Lazily opens (recovering its per-group high-water mark) the durable DLQ sink on first use,
    /// returning a mutable borrow. The sink is created on the first dead-letter, so a broker that
    /// never dead-letters never creates the `dlq/` subdirectory (the no-poison path never touches
    /// it). After a restart that already has a `dlq/` directory, [`Engine::open`] eagerly opens it
    /// so the high-water mark is present before the first poison redelivers.
    fn dlq_sink(&mut self) -> Result<&mut DlqSink<F, C>, EngineError> {
        if self.dlq.is_none() {
            let sink = DlqSink::open(
                self.log.filesystem(),
                self.log.clock_clone(),
                self.dlq_config,
            )?;
            self.dlq = Some(sink);
        }
        // Just-assigned above when None, so this is always Some.
        self.dlq
            .as_mut()
            .ok_or(EngineError::MissingRecord { offset: 0 })
    }

    /// Like [`Engine::poll`] but reads the current monotonic time from the engine's own
    /// clock, so the caller does not have to supply it.
    ///
    /// # Errors
    /// As [`Engine::poll`].
    pub fn poll_now(&mut self) -> Result<Poll, EngineError> {
        self.poll_now_in(DEFAULT_GROUP)
    }

    /// Like [`Engine::poll_now`] but for a named work-group (#9): reads the engine's own
    /// monotonic clock and polls `group`.
    ///
    /// # Errors
    /// As [`Engine::poll_in`].
    pub fn poll_now_in(&mut self, group: &str) -> Result<Poll, EngineError> {
        let now = self.log.now_monotonic();
        self.poll_in(group, now)
    }

    /// Declares the set of group names that use `key_shared` ordering (#64), server-side. A
    /// session puts a configured group into `key_shared` mode (and joins it as a member) the first
    /// time a consumer subscribes; an unconfigured group stays plain competing. Replacing the set
    /// only affects groups configured AFTER the call (already-`key_shared` groups keep their live
    /// router); this is the startup-config seam, so the server sets it once when it opens.
    pub fn set_configured_key_shared_groups<I>(&mut self, groups: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.key_shared_groups = groups.into_iter().collect();
    }

    /// Whether `group` is CONFIGURED (server-side) to use `key_shared` ordering (#64). Distinct
    /// from [`Engine::key_ordering_in`], which reports whether the group's LIVE state currently has
    /// a router attached: a session reads this on SUB to decide whether to enable the mode.
    #[must_use]
    pub fn is_configured_key_shared(&self, group: &str) -> bool {
        self.key_shared_groups.contains(group)
    }

    /// Sets a work-group's ordering mode (#64): [`KeyOrdering::None`] (the default, plain
    /// competing distribution) or [`KeyOrdering::KeyShared`] (per-key routing). Switching to
    /// `key_shared` attaches a fresh [`KeyRouter`] (no members yet); switching back to `None`
    /// drops it, reverting to plain competing distribution. The group is created if absent
    /// (subject to the same name and cap checks as [`Engine::poll_in`]), so the server can put a
    /// group into `key_shared` mode before any consumer polls it.
    ///
    /// This is the v1 mode-wiring seam: the mode is server-side per-group configuration, NOT a
    /// wire-negotiated field, so the frozen `Sub` frame (whose body is exactly the group name) is
    /// unchanged. A wire-negotiated `key_ordering` on `Sub`/`Connect` is a tracked follow-up.
    ///
    /// # Errors
    /// Returns [`EngineError::InvalidGroupName`] or [`EngineError::TooManyGroups`] if a new group
    /// would have to be created and fails the name or cap check.
    pub fn set_key_ordering_in(
        &mut self,
        group: &str,
        ordering: KeyOrdering,
    ) -> Result<(), EngineError> {
        if !self.groups.contains_key(group) {
            validate_group_name(group)?;
            if self.max_groups != 0 && self.groups.len() >= self.max_groups {
                return Err(EngineError::TooManyGroups {
                    max: self.max_groups,
                });
            }
        }
        let now = self.log.now_monotonic();
        let lease_config = self.lease_config;
        let g = self
            .groups
            .entry(group.to_string())
            .or_insert_with(|| WorkGroup::new(lease_config, now));
        match ordering {
            // Attach a router only if the group is not already key_shared, so re-applying the mode
            // never wipes the live-member set or the in-flight key map.
            KeyOrdering::KeyShared => {
                if g.router.is_none() {
                    g.router = Some(KeyRouter::new());
                }
            }
            KeyOrdering::None => g.router = None,
        }
        Ok(())
    }

    /// A work-group's current ordering mode (#64). A group that has never been configured (or one
    /// reverted to plain competing) reports [`KeyOrdering::None`].
    #[must_use]
    pub fn key_ordering_in(&self, group: &str) -> KeyOrdering {
        match self.groups.get(group) {
            Some(g) if g.router.is_some() => KeyOrdering::KeyShared,
            _ => KeyOrdering::None,
        }
    }

    /// Registers `member` as a live member of a `key_shared` group (#64): the consumer joined, so
    /// its keys may now route to it. A no-op for a group that is not `key_shared` (plain competing
    /// distribution has no member set). Returns `true` if the live-member set changed.
    pub fn join_member_in(&mut self, group: &str, member: MemberId) -> bool {
        self.groups
            .get_mut(group)
            .and_then(|g| g.router.as_mut())
            .is_some_and(|r| r.join(member))
    }

    /// Removes `member` from a `key_shared` group's live-member set (#64): the consumer left or
    /// disconnected, so its keys re-route to their new owners. Any record still in flight to the
    /// departed member stays leased and drains or expires through the lease layer before its key
    /// frees, which is the drain-or-expire guard. A no-op for a non-`key_shared` group. Returns
    /// `true` if the live-member set changed.
    pub fn leave_member_in(&mut self, group: &str, member: MemberId) -> bool {
        self.groups
            .get_mut(group)
            .and_then(|g| g.router.as_mut())
            .is_some_and(|r| r.leave(member))
    }

    /// The number of busy keys (delivered-but-unacked, one per key) in a `key_shared` group (#64),
    /// or `0` for a plain competing group. A cheap per-group hot-spot signal #16 can surface.
    #[must_use]
    pub fn busy_keys_in(&self, group: &str) -> usize {
        self.groups
            .get(group)
            .and_then(|g| g.router.as_ref())
            .map_or(0, KeyRouter::busy_keys)
    }

    /// The current `key_shared` routing decision for delivering `offset` (carrying `key`) to
    /// `member` in `group` (#64), or `None` for a group that is not `key_shared`. A read-only probe
    /// of the live router: an operator (or a test) can ask whether a key currently routes to a
    /// member without polling. Reflects the CURRENT live-member set and in-flight key map.
    #[must_use]
    pub fn route_decision_in(
        &self,
        group: &str,
        member: MemberId,
        key: &[u8],
        offset: Offset,
    ) -> Option<RouteDecision> {
        self.groups
            .get(group)
            .and_then(|g| g.router.as_ref())
            .map(|r| r.decide(member, key, offset))
    }

    /// Like [`Engine::poll_in`] but member-aware, for a `key_shared` group (#64): claims and
    /// returns the next record whose key routes to `member` under the group's CURRENT live-member
    /// set, preserving per-key order. A record's key maps to one member by rendezvous hash; a
    /// record with an EMPTY key keeps plain competing distribution (any member may take it). The
    /// per-key serialization gate plus the lease layer guarantee a member never receives a key's
    /// next record until the prior one drains or its lease expires, even across a rebalance.
    ///
    /// For a group that is NOT `key_shared`, `member` is irrelevant and this behaves EXACTLY like
    /// [`Engine::poll_in`] (plain competing distribution), so a caller can route every poll through
    /// here without affecting a `KeyOrdering::None` group.
    ///
    /// # Errors
    /// As [`Engine::poll_in`].
    pub fn poll_in_member(
        &mut self,
        group: &str,
        member: MemberId,
        now: u64,
    ) -> Result<Poll, EngineError> {
        // A non-key_shared group is the unchanged competing path: route straight to `poll_in` so
        // the default KeyOrdering::None behavior is byte-for-byte the existing code (it sweeps idle
        // groups and marks activity there).
        if self.key_ordering_in(group) == KeyOrdering::None {
            return self.poll_in(group, now);
        }
        // Sweep idle named groups at the start of a key_shared poll too (#277), so the seam fires
        // regardless of which poll entry point a consumer uses. A key_shared group is never itself
        // evicted (it carries live-member state), so polling one only ever reclaims OTHER idle
        // plain groups.
        self.sweep_idle_groups(now)?;
        // The group exists and is key_shared (the check above created/looked it up), so the cap and
        // name gates have already passed via set_key_ordering_in.
        let earliest = self.log.earliest_offset().get();
        let lease_config = self.lease_config;
        let g = self
            .groups
            .entry(group.to_string())
            .or_insert_with(|| WorkGroup::new(lease_config, now));
        // Mark the key_shared group active (#277); it is never evicted, but keeping its timestamp
        // current is consistent and cheap.
        g.last_activity = now;
        let committed = g.cursor.committed().get();
        // The same below-earliest truncation signal as poll_in (#84): reset the cursor up to the
        // oldest retained record and surface the truncation once. The router's in-flight key map is
        // also cleared, since the leases it referenced are gone.
        if committed < earliest {
            let skipped = earliest - committed;
            g.cursor = AckCursor::resume(Offset::new(earliest));
            g.leases = LeaseTable::new(lease_config);
            if let Some(router) = g.router.as_mut() {
                router.retain_above(Offset::new(earliest));
            }
            // The same skip count as the plain-competing path (#96): one event, `skipped` records.
            self.counters.truncations = self.counters.truncations.saturating_add(1);
            self.counters.truncated_records =
                self.counters.truncated_records.saturating_add(skipped);
            // Raise the skip-offset watermark to the offset this consumer skipped up to (#307), the
            // same CONSUMER-TRUNCATION contribution the plain-competing path maintains (snapshot-only,
            // not replay-derivable; the recovery-head contribution is restored on reconcile).
            self.counters.last_skip_offset = self.counters.last_skip_offset.max(earliest);
            // The reset advanced this group's committed cursor UP to `earliest`, so push the new
            // floor to the lag registry (#97), keeping the consumer-lag series correct (#84).
            self.sync_consumer_lag(group, earliest);
            return Ok(Poll::Truncated {
                earliest_retained: Offset::new(earliest),
                skipped,
            });
        }
        // Prune any in-flight key entry at or below the committed cursor: a committed offset is
        // acked, so its key is no longer busy. This keeps the per-key map bounded to the in-flight
        // window (mirrors how the session prunes its `leased` map past the committed cursor) and
        // also frees a key whose owner left and whose record was committed past elsewhere.
        if let Some(router) = g.router.as_mut() {
            router.retain_above(Offset::new(committed));
        }
        let flushed = self.log.flushed_offset().get();
        let window_end = committed
            .saturating_add(u64::from(self.max_in_flight))
            .min(flushed);
        let mut offset = committed;
        let mut dead_letter: Option<(Offset, LeaseToken, u32, OwnedRecord)> = None;
        while offset < window_end {
            let off = Offset::new(offset);
            if g.cursor.is_acked(off) {
                offset += 1;
                continue;
            }
            // An offset already actively leased (to this or another member) is skipped without
            // reading its record: only a free or expired offset is a routing candidate.
            if !g.leases.is_claimable(off, now) {
                offset += 1;
                continue;
            }
            // Read the record to learn its key, then ask the router whether THIS member may take
            // it now. The read is over a single offset; only candidate (claimable) offsets are read.
            let Some(record) = self.log.read_from(off, 1)?.into_iter().next() else {
                return Err(EngineError::MissingRecord { offset });
            };
            let Some(router) = g.router.as_ref() else {
                // Unreachable: the mode check above proved the router is present.
                return Err(EngineError::MissingRecord { offset });
            };
            match router.decide(member, &record.key, off) {
                // Not this member's key, or the key is busy with an earlier in-flight record: skip
                // it and keep scanning. A skipped offset stays unclaimed for its true owner.
                RouteDecision::NotOwner | RouteDecision::KeyBusy => {
                    offset += 1;
                    continue;
                }
                RouteDecision::Deliver => {}
            }
            // Routed to this member and the key is free: commit the claim now.
            match g.leases.claim(off, now) {
                // Raced to in-flight between the peek and the claim (no concurrency here, so this is
                // belt-and-suspenders): skip it.
                Claim::InFlight => {
                    offset += 1;
                }
                Claim::Exhausted => return Err(EngineError::GenerationExhausted),
                Claim::Granted { token, deliveries } => match self.delivery.disposition(deliveries)
                {
                    Disposition::Deliver => {
                        // Mark the key busy so its next record is not routed until this drains.
                        if let Some(router) = g.router.as_mut() {
                            router.mark_in_flight(&record.key, off);
                        }
                        self.counters.delivered += 1;
                        if deliveries > 1 {
                            self.counters.redelivered += 1;
                        }
                        return Ok(Poll::Message(Delivery {
                            offset: off,
                            token,
                            deliveries,
                            record,
                        }));
                    }
                    Disposition::DeadLetter => {
                        // Drop the lease and the key's in-flight entry, then dead-letter outside the
                        // group borrow exactly as poll_in does.
                        g.leases.ack(&token);
                        if let Some(router) = g.router.as_mut() {
                            router.clear_offset(off);
                        }
                        dead_letter = Some((off, token, deliveries, record));
                        break;
                    }
                },
            }
        }
        match dead_letter {
            Some((off, _token, deliveries, record)) => {
                self.dead_letter_in(group, off, deliveries, record)
            }
            None => Ok(Poll::Idle),
        }
    }

    /// Like [`Engine::poll_in_member`] but reads the engine's own monotonic clock (#64).
    ///
    /// # Errors
    /// As [`Engine::poll_in_member`].
    pub fn poll_now_in_member(
        &mut self,
        group: &str,
        member: MemberId,
    ) -> Result<Poll, EngineError> {
        let now = self.log.now_monotonic();
        self.poll_in_member(group, member, now)
    }

    /// Pushes `group`'s current committed offset (a record count) to the metric registry's
    /// per-consumer lag series (#97), so the scrape reads `head - committed` without ever walking
    /// the log. Called at EVERY committed-advancing site (ack, dead-letter commit, below-earliest
    /// truncation reset). O(1) and allocation-free for an existing consumer; the registry floor is
    /// monotonic, so a stale lower value is ignored. The first call for a new group claims a fixed
    /// series slot (or folds into `__overflow__` at the cap).
    fn sync_consumer_lag(&mut self, group: &str, committed: u64) {
        self.registry
            .set_consumer_committed(group.as_bytes(), committed);
    }

    /// Acks the message named by `token`: removes its lease (fenced if stale) and advances
    /// the committed cursor over any newly contiguous prefix.
    pub fn ack(&mut self, token: &LeaseToken) -> AckResult {
        self.ack_in(DEFAULT_GROUP, token)
    }

    /// Acks `token` in a named work-group (#9): commits it in that group's cursor and frees
    /// its lease slot, independent of every other group. The token must be one delivered by
    /// [`Engine::poll_in`] for the same `group` (generations are per-group).
    pub fn ack_in(&mut self, group: &str, token: &LeaseToken) -> AckResult {
        // The ack marks the group active (#277), so a group being drained is never reclaimed by
        // the idle sweep mid-stream. Read the clock seam before the mutable group borrow.
        let now = self.log.now_monotonic();
        // Never create a group on ack: a consumer must `poll_in` (which is capped) before
        // it can ack, so an ack on an unknown group is a fence, not a new allocation.
        let Some(g) = self.groups.get_mut(group) else {
            return AckResult::Fenced;
        };
        g.last_activity = now;
        match g.leases.ack(token) {
            AckOutcome::Acked => {
                g.cursor.ack(token.offset);
                // key_shared (#64): the key this offset held is now free, so its next record may
                // route. A no-op for a plain competing group (no router). A nack does NOT clear
                // it: the same offset redelivers, so the key stays busy and per-key order holds.
                if let Some(router) = g.router.as_mut() {
                    router.clear_offset(token.offset);
                }
                self.counters.acks += 1;
                // Maintain this consumer's lag INCREMENTALLY on commit (#97): push the new committed
                // offset (a record count) to the registry so the scrape reads `head - committed`
                // without ever walking the log. Read it before the borrow ends.
                let committed = g.cursor.committed().get();
                self.sync_consumer_lag(group, committed);
                AckResult::Acked
            }
            AckOutcome::Fenced => AckResult::Fenced,
        }
    }

    /// Cumulative ack (ack-all-up-to-`offset`) in a named work-group: the `JetStream` `AckAll`
    /// trap, HARD-REJECTED here (#63). A competing or `key_shared` work-group shares one commit
    /// cursor while its members drain out of order, so acking up to an offset would commit past
    /// (and silently drop) messages still in flight to peers. Cumulative ack is therefore offered
    /// only to BROADCAST consumers (a group of one that sees every message in order), and IronBus
    /// has no broadcast-consumer cursor yet, so this guard rejects EVERY cumulative ack with the
    /// typed [`EngineError::CumulativeAckOnWorkGroup`]. It exists so a caller (the wire layer, a
    /// client, a future broadcast path) has a single, typed, non-panicking rejection point rather
    /// than a bare TODO. The broadcast cumulative-ack feature is tracked as a follow-up (#288).
    ///
    /// # Errors
    /// Always returns [`EngineError::CumulativeAckOnWorkGroup`]: no group is a broadcast consumer
    /// today, so a cumulative ack is never valid.
    pub fn cumulative_ack_in(&mut self, _group: &str, _up_to: Offset) -> Result<(), EngineError> {
        // Every live group is a competing/key_shared work-group; none is a broadcast consumer, so
        // cumulative ack is unconditionally rejected. When the broadcast consumer cursor lands, the
        // broadcast branch commits its own single-member cursor up to `up_to` here.
        Err(EngineError::CumulativeAckOnWorkGroup)
    }

    /// Cumulative ack in the default work-group, rejected as [`Engine::cumulative_ack_in`].
    ///
    /// # Errors
    /// Always returns [`EngineError::CumulativeAckOnWorkGroup`] (the default group is a work-group).
    pub fn cumulative_ack(&mut self, up_to: Offset) -> Result<(), EngineError> {
        self.cumulative_ack_in(DEFAULT_GROUP, up_to)
    }

    /// Nacks the message named by `token`, requeueing it for redelivery and fencing the
    /// nacking holder. `delay_ms` follows the wire convention: `u64::MAX` means no explicit
    /// delay, so the server applies its configured backoff schedule for this attempt; any
    /// other value is an explicit delay in milliseconds (0 = immediate) that overrides the
    /// schedule. The `MaxDeliver` / dead-letter decision is made by [`Engine::poll`] when the
    /// message is next claimed, so a message nacked past its cap is parked, not looped.
    ///
    /// # Errors
    /// Returns [`EngineError::GenerationExhausted`] if the lease generation space is spent.
    pub fn nack(&mut self, token: &LeaseToken, delay_ms: u64) -> Result<NackResult, EngineError> {
        self.nack_in(DEFAULT_GROUP, token, delay_ms)
    }

    /// Nacks `token` in a named work-group (#9), requeueing it for redelivery within that
    /// group only. See [`Engine::nack`] for the `delay_ms` convention.
    ///
    /// # Errors
    /// Returns [`EngineError::GenerationExhausted`] if the lease generation space is spent.
    pub fn nack_in(
        &mut self,
        group: &str,
        token: &LeaseToken,
        delay_ms: u64,
    ) -> Result<NackResult, EngineError> {
        let now = self.log.now_monotonic();
        // u64::MAX is the wire sentinel for "no explicit delay": fall back to the configured
        // backoff schedule. Any other value is an explicit delay in milliseconds (0 = retry
        // immediately), converted to nanoseconds and saturated rather than overflowed.
        let explicit_nanos = (delay_ms != u64::MAX).then(|| delay_ms.saturating_mul(1_000_000));
        // Never create a group on nack (see `ack_in`): unknown group is a fence.
        let Some(g) = self.groups.get_mut(group) else {
            return Ok(NackResult::Fenced);
        };
        // The nack marks the group active (#277): a consumer requeueing work is still using it.
        g.last_activity = now;
        let attempt = g.leases.deliveries(token).unwrap_or(0);
        let delay_nanos = self.delivery.effective_nack_delay(attempt, explicit_nanos);
        Ok(match g.leases.nack(token, now, delay_nanos) {
            NackOutcome::Requeued { .. } => NackResult::Requeued,
            NackOutcome::Fenced => NackResult::Fenced,
            NackOutcome::Exhausted => return Err(EngineError::GenerationExhausted),
        })
    }

    /// Terminates delivery of the message named by `token`: an intentional drop that commits
    /// past it so it never redelivers and is NOT dead-lettered. Mechanically a commit, like
    /// [`Engine::ack`], and distinct only in the caller's intent (a future metrics or
    /// dead-letter-policy split can diverge them); sharing the commit path keeps the cursor
    /// and lease invariants identical to a normal ack.
    pub fn term(&mut self, token: &LeaseToken) -> AckResult {
        self.term_in(DEFAULT_GROUP, token)
    }

    /// Terminates `token` in a named work-group (#9): an intentional drop that commits past
    /// it in that group without dead-lettering. Mechanically a commit, like
    /// [`Engine::ack_in`].
    pub fn term_in(&mut self, group: &str, token: &LeaseToken) -> AckResult {
        self.ack_in(group, token)
    }

    /// Extends the lease named by `token` by one visibility window (the consumer is still
    /// working), clamped to the hard cap from the attempt start. A stale token is fenced; a
    /// lease already at its cap returns [`ProgressResult::CapReached`].
    pub fn progress(&mut self, token: &LeaseToken) -> ProgressResult {
        self.progress_in(DEFAULT_GROUP, token)
    }

    /// Extends the lease named by `token` in a named work-group (#9) by one visibility
    /// window. See [`Engine::progress`].
    pub fn progress_in(&mut self, group: &str, token: &LeaseToken) -> ProgressResult {
        let now = self.log.now_monotonic();
        // Never create a group on progress (see `ack_in`): unknown group is a fence.
        let Some(g) = self.groups.get_mut(group) else {
            return ProgressResult::Fenced;
        };
        // Extending a lease marks the group active (#277): a consumer reporting progress is working.
        g.last_activity = now;
        match g.leases.extend(token, now) {
            ExtendOutcome::Extended(_) => ProgressResult::Extended,
            ExtendOutcome::CapReached => ProgressResult::CapReached,
            ExtendOutcome::Fenced => ProgressResult::Fenced,
        }
    }

    /// The committed offset: every offset below it is acked, and where a restart resumes.
    #[must_use]
    pub fn committed_offset(&self) -> Offset {
        self.committed_offset_in(DEFAULT_GROUP)
    }

    /// The committed offset of a named work-group (#9), or offset 0 for a group that has
    /// never been polled (it would start at the beginning of the log).
    #[must_use]
    pub fn committed_offset_in(&self, group: &str) -> Offset {
        self.groups
            .get(group)
            .map_or(Offset::ZERO, |g| g.cursor.committed())
    }

    /// The durable log head: the offset of the next record to be written. Consumer lag is
    /// this minus the committed offset.
    #[must_use]
    pub fn flushed_offset(&self) -> Offset {
        self.log.flushed_offset()
    }

    /// The OLDEST retained log offset: the oldest segment's base offset, the first offset still
    /// present in the durable log (#82, #84). `0` for a log that has never been reaped. It rises
    /// above 0 only once the disk-full drop-oldest policy or consumer-safe retention has reclaimed
    /// a prefix of old segments. A consumer whose committed cursor is below this has had its records
    /// reclaimed out from under it, so its next poll returns a one-time [`Poll::Truncated`].
    #[must_use]
    pub fn earliest_retained_offset(&self) -> Offset {
        self.log.earliest_offset()
    }

    /// The log's current total durable RECORD bytes (the quantity the durable-log byte cap,
    /// `LogConfig::max_total_bytes`, is measured against). An operator can compare it to the
    /// configured cap to see headroom before the drop-new shed triggers.
    #[must_use]
    pub fn durable_record_bytes(&self) -> u64 {
        self.log.durable_record_bytes()
    }

    /// The log's total durable RECORD COUNT (the quantity the count-retention bound,
    /// [`EngineConfig::max_messages`], is measured against). An operator can compare it to the
    /// configured count bound to see headroom before retention reaps.
    #[must_use]
    pub fn durable_record_count(&self) -> u64 {
        self.log.durable_record_count()
    }

    /// Bytes dropped from a torn or unsynced tail at recovery (startup): the raw
    /// recovery-loss signal an operator can surface, zero on a clean start.
    #[must_use]
    pub fn recovered_truncated_bytes(&self) -> u64 {
        self.log.recovered_truncated_bytes()
    }

    /// The structured loss report from recovery (#120): the byte spans dropped to reach the
    /// last intact record, with their reasons. Empty for a fresh log or a clean recovery. The
    /// metrics endpoint reads it for the per-reason recovery-loss series.
    #[must_use]
    pub fn loss_report(&self) -> &LossReport {
        self.log.loss_report()
    }

    /// Total bytes copied into the forensic quarantine store at the last recovery (#134): the
    /// corrupt regions a corruption skip dropped, captured (copy-not-move, capped) under
    /// `quarantine/` for offline analysis. Zero on a clean start or when the only loss was a clean
    /// torn tail. Exposed on `/metrics` as the `ironbus_quarantine_bytes` gauge.
    #[must_use]
    pub fn quarantined_bytes(&self) -> u64 {
        self.log.quarantined_bytes()
    }

    /// A snapshot of the operational counters (monotonic since process start).
    #[must_use]
    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// A snapshot of the fsync (durability barrier) latency histogram observed on produce.
    #[must_use]
    pub fn fsync_histogram(&self) -> LatencyHistogram {
        self.fsync
    }

    /// The bounded metric registry (#97): the fixed-bucket fsync-duration and append-latency
    /// histograms, the capped per-consumer lag registry, and the self-monitoring series. The
    /// `/metrics` rendering reads it under the engine lock to emit those series. The uptime series
    /// pairs this with [`Engine::now_monotonic`] (the live clock-seam reading).
    #[must_use]
    pub fn registry(&self) -> &MetricRegistry {
        &self.registry
    }

    /// The engine's current monotonic time (nanoseconds) from the clock seam, for the registry's
    /// monotonic-derived `ironbus_uptime_seconds` at scrape time. Routed through the seam (never a
    /// raw `Instant::now`), so the deterministic sim stays reproducible.
    #[must_use]
    pub fn now_monotonic(&self) -> u64 {
        self.log.now_monotonic()
    }

    /// The log offset of the most recently dead-lettered (parked past `MaxDeliver`) message,
    /// or `None` if none has been dead-lettered. Pairs with the `dead_lettered` counter to
    /// report not just how many messages were dropped but which one most recently.
    #[must_use]
    pub fn last_dead_lettered_offset(&self) -> Option<Offset> {
        self.last_dead_lettered
    }

    /// The number of records durably written to the DLQ sink (the dead-letter depth, #63): the
    /// records present when the sink was opened plus every poison record appended since. Zero when
    /// nothing has been dead-lettered (the sink is then never even opened). Exposed on `/metrics`
    /// as `ironbus_dlq_records_total`. Unlike `dead_lettered` (an in-memory counter reset on
    /// restart), this is reconstructed from the durable sink, so it survives a restart.
    #[must_use]
    pub fn dlq_records(&self) -> u64 {
        self.dlq.as_ref().map_or(0, DlqSink::records)
    }

    /// The number of messages currently in flight (leased, not yet acked).
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.groups.values().map(|g| g.leases.in_flight()).sum()
    }

    /// Whether a work-group is currently LIVE in memory (#277): the default group `""` always is,
    /// and a named group is live from its first poll until it is evicted by the idle sweep (or the
    /// explicit-`Unsub` reclaim). A test or an operator uses it to observe that an idle group's slot
    /// was freed against the `max_groups` cap; it never creates a group.
    #[must_use]
    pub fn has_group(&self, group: &str) -> bool {
        self.groups.contains_key(group)
    }

    /// The number of work-groups currently live in memory (#277), INCLUDING the durable default
    /// group, the quantity the `max_groups` cap is measured against. Falls as the idle sweep
    /// reclaims caught-up groups, so a new group can be created at a previously-full cap.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// The per-CONSUMER (per-connection) standing in-flight credit ceiling (refs #65, #9, #10):
    /// the most un-acked messages one connection may hold at once. Already floored to at least 1.
    /// A [`crate::session::Session`] reads this once and enforces it against its own
    /// connection-scoped `leased` set (#175); the engine is shared by every connection and so does
    /// not itself decrement per-connection credit. The effective delivery bound on a Flow is the
    /// MIN of this ceiling and the per-group `max_in_flight` window. See
    /// [`EngineConfig::consumer_credit`].
    #[must_use]
    pub fn consumer_credit(&self) -> u32 {
        self.consumer_credit
    }

    /// The per-CONSUMER (per-connection) standing in-flight BYTE budget (refs #65, #275, #10): the
    /// most un-acked payload bytes one connection may hold at once, the RAM-side companion to
    /// [`Engine::consumer_credit`]. A [`crate::session::Session`] reads this once and enforces it
    /// against the total bytes of its connection-scoped `leased` set, so the effective per-Flow bound
    /// is `min(message credits remaining, byte credits remaining)` with a hard floor of one message.
    /// `0` means UNLIMITED (the byte budget is off, only the message credit binds). See
    /// [`EngineConfig::consumer_credit_bytes`].
    #[must_use]
    pub fn consumer_credit_bytes(&self) -> u64 {
        self.consumer_credit_bytes
    }

    /// Whether `token` still names an ACTIVE (live and NOT yet expired) lease in `group` owned by
    /// exactly this `(offset, generation)` at the engine's current monotonic time (refs #65, #175):
    /// `true` only if the offset is currently leased, its generation matches the token, AND its
    /// visibility window has not elapsed. It is `false` once the lease was acked, nacked, termed, or
    /// redelivered under a new generation (a generation mismatch), AND also once the lease has merely
    /// EXPIRED (the deadline has passed) even though its generation still matches, because an expired
    /// lease is reclaimable and no longer actively held by its current holder. It is `false` for an
    /// unknown group.
    ///
    /// A [`crate::session::Session`] uses this to keep its per-consumer credit consistent with true,
    /// ACTIVE ownership: a `leased` entry the engine no longer holds actively is a slot the session
    /// must free, because the message it once held has been committed, redelivered elsewhere, or has
    /// expired (so it is about to be redelivered to whoever next polls, possibly the same consumer).
    /// This is the redelivery-accounting seam that frees the original consumer's slot the moment one
    /// of its leases expires, so the redelivery is recounted against whoever next claims it. It reads
    /// the engine clock seam and never mutates engine state.
    #[must_use]
    pub fn holds_active_lease_in(&self, group: &str, token: &LeaseToken) -> bool {
        let now = self.log.now_monotonic();
        self.groups
            .get(group)
            .is_some_and(|g| g.leases.holds_active(token, now))
    }

    /// Per-work-group consumer stats for the metrics endpoint (#16): committed offset and
    /// in-flight depth for each group, so an operator sees lag broken down by cursor (#15).
    /// The lag itself is derived against the durable head ([`Engine::flushed_offset`]).
    #[must_use]
    pub fn group_consumer_stats(&self) -> Vec<GroupConsumerStat> {
        self.groups
            .iter()
            .map(|(group, g)| GroupConsumerStat {
                group: group.clone(),
                committed: g.cursor.committed().get(),
                in_flight: g.leases.in_flight(),
            })
            .collect()
    }

    /// Whether the broker is healthy: the durable log writer is not frozen. A frozen writer
    /// (after a fatal fsync or a failed segment roll) keeps serving reads but refuses writes,
    /// so it is not ready.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.log.is_writable()
    }

    /// The number of segments the durable log currently holds (sealed predecessors plus the one
    /// active segment). A read-only operational gauge for the introspection endpoint (#99): it
    /// falls as retention or a forced reap reclaims old segments.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.log.segment_count()
    }

    /// A read-only echo of the engine's EFFECTIVE configuration bounds for the introspection
    /// endpoint (#99): the durable-log byte cap, segment size, retention bounds, per-consumer
    /// credit, lease windows, delivery cap, and the group/in-flight caps. This is a pure copy of
    /// the values [`Engine::open`] was configured with (NO secret material, NO mutating handle), so
    /// an operator can confirm what the broker is actually running with. Every `0` keeps the
    /// codebase's `0` = unlimited/off convention.
    #[must_use]
    pub fn config_snapshot(&self) -> EngineConfigSnapshot {
        let log = self.log.config();
        EngineConfigSnapshot {
            max_total_bytes: log.max_total_bytes,
            max_segment_bytes: log.max_segment_bytes,
            max_retained_bytes: self.retention.max_bytes,
            max_age_ms: self.retention.max_age_ms,
            max_messages: self.retention.max_messages,
            max_in_flight: self.max_in_flight,
            consumer_credit: self.consumer_credit,
            consumer_credit_bytes: self.consumer_credit_bytes,
            max_deliver: self.delivery.max_deliver(),
            max_groups: self.max_groups,
            group_idle_evict_nanos: self.group_idle_evict_nanos,
            visibility_nanos: self.lease_config.visibility_nanos,
            hard_cap_nanos: self.lease_config.hard_cap_nanos,
            disk_full_policy: self.disk_full_policy,
        }
    }

    /// Consumes the engine and returns its filesystem, so the log can be reopened.
    #[must_use]
    pub fn into_filesystem(self) -> F {
        self.log.into_filesystem()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::types::RecordFlags;
    use ironbus_storage::fs::InMemoryFs;

    fn config(max_in_flight: u32, max_deliver: u32) -> EngineConfig {
        EngineConfig {
            log: LogConfig::default(),
            // 30 ns visibility, 100 ns cap, so tests advance time in small integers.
            lease: LeaseConfig {
                visibility_nanos: 30,
                hard_cap_nanos: 100,
            },
            delivery: DeliveryConfig::new(max_deliver, false, vec![]).unwrap(),
            max_in_flight,
            consumer_credit: DEFAULT_CONSUMER_CREDIT,
            consumer_credit_bytes: DEFAULT_CONSUMER_CREDIT_BYTES,
            checkpoint_interval: 1024,
            max_retained_bytes: 0,
            max_age_ms: 0,
            max_messages: 0,
            disk_full_policy: DiskFullPolicy::DropNew,
            max_groups: DEFAULT_MAX_GROUPS,
            // Eviction OFF by default in the shared test config (#277); the eviction tests build a
            // config with a non-zero window explicitly so the golden-path tests stay unaffected.
            group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
        }
    }

    fn open(config: EngineConfig) -> Engine<InMemoryFs, ManualClock> {
        Engine::open(InMemoryFs::new(), ManualClock::new(), config).unwrap()
    }

    // Opens an engine over a shared `ManualClock` the test can drive, for the age-retention path.
    fn open_with_clock(
        config: EngineConfig,
        clock: std::sync::Arc<ManualClock>,
    ) -> Engine<InMemoryFs, std::sync::Arc<ManualClock>> {
        Engine::open(InMemoryFs::new(), clock, config).unwrap()
    }

    fn produce(e: &mut Engine<InMemoryFs, ManualClock>, payload: &[u8]) -> Offset {
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        })
        .unwrap()
    }

    fn message(poll: Poll) -> Delivery {
        match poll {
            Poll::Message(d) => d,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    #[test]
    fn produce_poll_ack_advances_the_cursor() {
        let mut e = open(config(10, 5));
        assert_eq!(produce(&mut e, b"a"), Offset::new(0));
        assert_eq!(produce(&mut e, b"b"), Offset::new(1));

        let d0 = message(e.poll(0).unwrap());
        assert_eq!(d0.offset, Offset::new(0));
        assert_eq!(d0.record.payload, b"a");
        assert_eq!(d0.deliveries, 1);
        assert_eq!(e.ack(&d0.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(1));

        let d1 = message(e.poll(0).unwrap());
        assert_eq!(d1.offset, Offset::new(1));
        assert_eq!(e.ack(&d1.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(2));

        assert!(matches!(e.poll(0).unwrap(), Poll::Idle));
    }

    #[test]
    fn the_registry_consumer_lag_is_maintained_incrementally_on_produce_and_ack() {
        // The #97 per-consumer lag series, exercised through the real produce/ack path: the head
        // advances on produce, the default consumer's commit floor advances on ack, and lag is
        // `head - committed`, never scanned. The registry reads must match the engine's own
        // committed/flushed view.
        let mut e = open(config(10, 5));
        // Helper: the lag of the default consumer ("") as the registry reports it.
        let default_lag = |e: &Engine<InMemoryFs, ManualClock>| -> u64 {
            let mut lag = None;
            e.registry().consumer_lag().for_each_series(|consumer, l| {
                if consumer.is_empty() {
                    lag = Some(l);
                }
            });
            lag.expect("the default consumer series always exists")
        };
        assert_eq!(default_lag(&e), 0, "no records, no lag");
        produce(&mut e, b"a");
        produce(&mut e, b"b");
        produce(&mut e, b"c");
        // Three records produced, none committed: the registry head is 3, so default lag is 3.
        assert_eq!(e.registry().consumer_lag().head(), 3);
        assert_eq!(default_lag(&e), 3);
        // Ack two records: the default consumer's floor rises to 2, so lag drops to 1, with NO log
        // scan (the floor moved incrementally).
        let d0 = message(e.poll(0).unwrap());
        assert_eq!(e.ack(&d0.token), AckResult::Acked);
        let d1 = message(e.poll(0).unwrap());
        assert_eq!(e.ack(&d1.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(2));
        assert_eq!(default_lag(&e), 1, "head 3 - committed 2 = 1");
        // The registry lag equals the engine's own flushed - committed view (the existing scan-free
        // gauge), proving the incremental series agrees with the source of truth.
        let engine_lag = e.flushed_offset().get() - e.committed_offset().get();
        assert_eq!(default_lag(&e), engine_lag);
    }

    #[test]
    fn the_registry_is_seeded_from_recovered_state_on_reopen() {
        // After a restart the per-consumer lag series must be correct from the FIRST scrape, not
        // zeroed: the head is seeded to the recovered flushed offset and the default group's floor
        // to its recovered committed offset.
        let fs = {
            let mut e = open(config(10, 5));
            for p in [b"a", b"b", b"c", b"d"] {
                produce(&mut e, p);
            }
            // Ack one so the recovered committed offset is non-zero.
            let d = message(e.poll(0).unwrap());
            assert_eq!(e.ack(&d.token), AckResult::Acked);
            // Make the committed cursor durable (the graceful-shutdown flush), so the reopen resumes
            // it; the checkpoint interval is too coarse to fire on a single ack.
            e.checkpoint_all_groups().unwrap();
            e.into_filesystem()
        };
        let e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        // The head is seeded to 4 (four durable records), the default floor to 1 (one acked), so the
        // recovered lag is 3 from the first scrape.
        assert_eq!(e.registry().consumer_lag().head(), 4);
        let mut lag = None;
        e.registry().consumer_lag().for_each_series(|consumer, l| {
            if consumer.is_empty() {
                lag = Some(l);
            }
        });
        assert_eq!(lag, Some(3), "recovered head 4 - recovered committed 1");
    }

    #[test]
    fn an_in_flight_message_is_not_redelivered_until_it_expires() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        let d = message(e.poll(0).unwrap());
        // Still within the visibility window: nothing else to deliver.
        assert!(matches!(e.poll(10).unwrap(), Poll::Idle));
        // Past the 30 ns window: redelivered with a higher delivery count and a new token.
        let d2 = message(e.poll(40).unwrap());
        assert_eq!(d2.offset, Offset::new(0));
        assert_eq!(d2.deliveries, 2);
        assert_ne!(d2.token.generation, d.token.generation);
        // The original token can no longer ack (fenced); the redelivered one can.
        assert_eq!(e.ack(&d.token), AckResult::Fenced);
        assert_eq!(e.ack(&d2.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(1));
    }

    #[test]
    fn out_of_order_acks_advance_the_cursor_over_the_contiguous_prefix() {
        let mut e = open(config(10, 5));
        for p in [b"a", b"b", b"c"] {
            produce(&mut e, p);
        }
        let d0 = message(e.poll(0).unwrap());
        let d1 = message(e.poll(0).unwrap());
        let d2 = message(e.poll(0).unwrap());
        // Ack out of order: 1, then 2, then 0.
        e.ack(&d1.token);
        assert_eq!(
            e.committed_offset(),
            Offset::new(0),
            "0 still unacked, cannot advance"
        );
        e.ack(&d2.token);
        assert_eq!(e.committed_offset(), Offset::new(0));
        e.ack(&d0.token);
        assert_eq!(
            e.committed_offset(),
            Offset::new(3),
            "0 acked: jumps over 1 and 2"
        );
    }

    #[test]
    fn the_in_flight_window_bounds_delivery() {
        let mut e = open(config(2, 5)); // max 2 in flight
        for p in [b"a", b"b", b"c", b"d"] {
            produce(&mut e, p);
        }
        let d0 = message(e.poll(0).unwrap());
        let _d1 = message(e.poll(0).unwrap());
        // Window full (offsets 0 and 1 in flight); nothing more even though c, d exist.
        assert!(matches!(e.poll(0).unwrap(), Poll::Idle));
        assert_eq!(e.in_flight(), 2);
        // Acking 0 slides the window forward; offset 2 becomes deliverable.
        e.ack(&d0.token);
        let d2 = message(e.poll(0).unwrap());
        assert_eq!(d2.offset, Offset::new(2));
    }

    #[test]
    fn a_message_over_max_deliver_is_parked() {
        let mut e = open(config(10, 1)); // max_deliver 1
        produce(&mut e, b"poison");
        assert_eq!(
            e.last_dead_lettered_offset(),
            None,
            "none dead-lettered yet"
        );
        // First delivery.
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.deliveries, 1);
        // Expire without acking; the second delivery exceeds max_deliver and is parked.
        match e.poll(40).unwrap() {
            Poll::Parked { offset, record } => {
                assert_eq!(offset, Offset::new(0));
                assert_eq!(record.payload, b"poison");
            }
            other => panic!("expected Parked, got {other:?}"),
        }
        // The dead-lettered offset is now reported alongside the counter.
        assert_eq!(e.last_dead_lettered_offset(), Some(Offset::new(0)));
        assert_eq!(e.counters().dead_lettered, 1);
        // The poison message is committed past and never redelivers.
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert!(matches!(e.poll(80).unwrap(), Poll::Idle));
    }

    #[test]
    fn produce_records_one_fsync_observation_each() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        produce(&mut e, b"b");
        let h = e.fsync_histogram();
        assert_eq!(h.count(), 2, "one fsync observation per produce");
        // The manual clock does not advance during the in-memory sync, so each latency is 0,
        // which falls in the first (and so every cumulative) bucket.
        assert_eq!(h.sum_nanos(), 0);
        assert_eq!(h.cumulative_buckets()[0], 2);
    }

    #[test]
    fn open_rejects_a_zero_in_flight_window() {
        // `matches!` avoids needing `Engine: Debug` for the Ok side.
        assert!(matches!(
            Engine::open(InMemoryFs::new(), ManualClock::new(), config(0, 5)),
            Err(EngineError::ZeroMaxInFlight)
        ));
    }

    #[test]
    fn the_default_max_deliver_parks_only_on_the_sixth_claim() {
        // max_deliver = 5: delivered exactly 5 times, parked on the 6th claim.
        let mut e = open(config(10, 5));
        produce(&mut e, b"poison");
        let mut now = 0u64;
        for expected in 1..=5u32 {
            let d = message(e.poll(now).unwrap());
            assert_eq!(d.deliveries, expected);
            now += 40; // expire each attempt without acking
        }
        // The sixth claim exceeds max_deliver and parks.
        match e.poll(now).unwrap() {
            Poll::Parked { offset, .. } => assert_eq!(offset, Offset::new(0)),
            other => panic!("expected Parked on the 6th, got {other:?}"),
        }
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert_eq!(e.in_flight(), 0, "a parked message holds no lease");
    }

    #[test]
    fn a_full_retry_then_ack_cycle_works() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"x");
        let d1 = message(e.poll(0).unwrap());
        assert_eq!(d1.deliveries, 1);
        let d2 = message(e.poll(40).unwrap()); // expired, redelivered
        assert_eq!(d2.deliveries, 2);
        let d3 = message(e.poll(80).unwrap()); // expired again, redelivered
        assert_eq!(d3.deliveries, 3);
        // Finally ack the latest token; earlier tokens are fenced.
        assert_eq!(e.ack(&d1.token), AckResult::Fenced);
        assert_eq!(e.ack(&d2.token), AckResult::Fenced);
        assert_eq!(e.ack(&d3.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert_eq!(e.in_flight(), 0);
    }

    #[test]
    fn in_flight_never_exceeds_the_window_under_out_of_order_churn() {
        let mut e = open(config(3, 5)); // window of 3
        for _ in 0..20 {
            produce(&mut e, b"m");
        }
        let mut now = 0u64;
        let mut held: Vec<LeaseToken> = Vec::new();
        for round in 0..40 {
            // Deliver as much as the window allows.
            while let Poll::Message(d) = e.poll(now).unwrap() {
                held.push(d.token);
            }
            assert!(
                e.in_flight() <= 3,
                "in_flight {} exceeded the window",
                e.in_flight()
            );
            // Ack one held token out of order (the middle one), if any.
            if !held.is_empty() {
                let idx = (round * 7 + 1) % held.len();
                let tok = held.remove(idx);
                e.ack(&tok);
            }
            now += 5;
        }
        assert!(e.in_flight() <= 3);
    }

    #[test]
    fn checkpoint_then_reopen_resumes_from_the_committed_offset() {
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        // Consume and ack the first two, then checkpoint the cursor.
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token);
        let d1 = message(e.poll(0).unwrap());
        e.ack(&d1.token);
        assert_eq!(e.committed_offset(), Offset::new(2));
        e.checkpoint_cursor().unwrap();
        let fs = e.into_filesystem();

        // Reopen: the committed cursor resumes at 2, so only the uncommitted tail (c)
        // redelivers, NOT a and b, and nothing in [2, flushed) is skipped.
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(2));
        // Drain the whole window: exactly offset 2 ("c") is deliverable.
        let mut delivered = Vec::new();
        while let Poll::Message(d) = e.poll(0).unwrap() {
            delivered.push((d.offset.get(), d.record.payload.clone()));
        }
        assert_eq!(
            delivered,
            vec![(2, b"c".to_vec())],
            "only the uncommitted tail redelivers"
        );
    }

    #[test]
    fn checkpoint_all_groups_flushes_every_live_group_for_a_graceful_shutdown() {
        // #195: the graceful-shutdown flush must persist EVERY live work-group's committed cursor
        // (the default group and every named group), so a restart after a clean stop redelivers
        // nothing. The checkpoint interval is the default 1024, so a single ack per group does NOT
        // trigger any interval checkpoint; only checkpoint_all_groups makes the cursors durable.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        // Default group: consume and ack offset 0 (committed = 1), no interval checkpoint fires.
        let d_default = message(e.poll(0).unwrap());
        assert_eq!(e.ack(&d_default.token), AckResult::Acked);
        // Named group "work": consume and ack offsets 0 and 1 (its committed = 2), independently.
        for _ in 0..2 {
            let d = message(e.poll_in("work", 0).unwrap());
            assert_eq!(e.ack_in("work", &d.token), AckResult::Acked);
        }
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert_eq!(e.committed_offset_in("work"), Offset::new(2));

        // The single graceful-shutdown flush persists both groups' cursors at once.
        e.checkpoint_all_groups().unwrap();
        let fs = e.into_filesystem();

        // Reopen: BOTH cursors resumed from where they were acked, so neither group redelivers an
        // acked message. The default group resumes at 1, the named group at 2.
        let e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(
            e.committed_offset(),
            Offset::new(1),
            "checkpoint_all_groups flushed the default group's cursor"
        );
        assert_eq!(
            e.committed_offset_in("work"),
            Offset::new(2),
            "checkpoint_all_groups flushed the named group's cursor too"
        );
    }

    #[test]
    fn messages_produced_after_a_checkpoint_survive_and_deliver_after_reopen() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token); // committed = 1
        e.checkpoint_cursor().unwrap();
        // Produce more AFTER the checkpoint; these are durable but uncommitted.
        produce(&mut e, b"b");
        produce(&mut e, b"c");
        let fs = e.into_filesystem();

        // Reopen: resume at 1, and the post-checkpoint tail (b, c) must all survive.
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(1));
        let mut delivered = Vec::new();
        while let Poll::Message(d) = e.poll(0).unwrap() {
            delivered.push((d.offset.get(), d.record.payload.clone()));
        }
        assert_eq!(
            delivered,
            vec![(1, b"b".to_vec()), (2, b"c".to_vec())],
            "no produced-and-durable message is lost across the restart"
        );
    }

    #[test]
    fn a_fully_consumed_checkpointed_queue_is_idle_after_reopen() {
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b"] {
            produce(&mut e, p);
        }
        for _ in 0..2 {
            let d = message(e.poll(0).unwrap());
            e.ack(&d.token);
        }
        assert_eq!(e.committed_offset(), Offset::new(2));
        e.checkpoint_cursor().unwrap();
        let fs = e.into_filesystem();

        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(2));
        assert!(
            matches!(e.poll(0).unwrap(), Poll::Idle),
            "nothing left to deliver"
        );
    }

    #[test]
    fn a_stale_checkpoint_only_redelivers_the_uncheckpointed_tail() {
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        // Ack 0, checkpoint (committed=1), then ack 1 WITHOUT a second checkpoint.
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token);
        e.checkpoint_cursor().unwrap();
        let d1 = message(e.poll(0).unwrap());
        e.ack(&d1.token);
        assert_eq!(e.committed_offset(), Offset::new(2));
        let fs = e.into_filesystem();

        // The checkpoint lagged at 1, so reopen resumes at 1 and redelivers b (already
        // processed) and c: a lagging checkpoint costs duplicates, never loss.
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(1));
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.offset, Offset::new(1));
        assert_eq!(d.record.payload, b"b");
    }

    #[test]
    fn an_out_of_order_acked_ahead_set_survives_a_checkpoint_and_reopen() {
        // Ack offsets 1, 2, 3 but leave a gap at 0: the committed watermark stays at 0 while
        // the acked-ahead set holds [1, 4). After a checkpoint and reopen, only the gap (0)
        // redelivers; the acked-ahead messages do NOT, because the snapshot persisted them.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c", b"d"] {
            produce(&mut e, p);
        }
        // Poll all four, holding their tokens, then ack 1, 2, 3 (not 0).
        let mut tokens = Vec::new();
        for _ in 0..4 {
            tokens.push(message(e.poll(0).unwrap()).token);
        }
        for i in [1usize, 2, 3] {
            assert_eq!(e.ack(&tokens[i]), AckResult::Acked);
        }
        assert_eq!(
            e.committed_offset(),
            Offset::new(0),
            "the gap at 0 holds the watermark"
        );
        e.checkpoint_cursor().unwrap();
        let fs = e.into_filesystem();

        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(0));
        // Drain: only offset 0 ("a") is deliverable; 1..4 are acked-ahead and skipped.
        let mut delivered = Vec::new();
        loop {
            match e.poll(0).unwrap() {
                Poll::Message(d) => {
                    delivered.push((d.offset.get(), d.record.payload.clone()));
                    e.ack(&d.token);
                }
                Poll::Idle => break,
                Poll::Parked { offset, .. } => panic!("unexpected park at {}", offset.get()),
                Poll::Truncated { .. } => panic!("unexpected truncation"),
            }
        }
        assert_eq!(
            delivered,
            vec![(0, b"a".to_vec())],
            "only the gap redelivers; the persisted acked-ahead set is not"
        );
        // Acking the gap collapses the whole prefix: the queue is fully consumed.
        assert_eq!(e.committed_offset(), Offset::new(4));
    }

    #[test]
    fn an_acked_ahead_set_larger_than_the_checkpoint_slot_degrades_safely() {
        // Produce 20 and ack every odd offset (1, 3, ... 19), leaving even gaps. The cursor
        // then holds 10 disjoint acked-ahead runs, more than a 64-byte checkpoint slot fits.
        // The checkpoint keeps the watermark plus the leading runs that fit and drops the
        // rest: the dropped acks safely redeliver, the kept ones do not, and nothing below
        // the watermark is ever lost.
        let mut e = open(config(20, 5));
        for i in 0..20u8 {
            produce(&mut e, &[i]);
        }
        let mut tokens = Vec::new();
        for _ in 0..20 {
            tokens.push(message(e.poll(0).unwrap()).token);
        }
        for i in (1..20usize).step_by(2) {
            assert_eq!(e.ack(&tokens[i]), AckResult::Acked);
        }
        assert_eq!(e.committed_offset(), Offset::new(0));
        let default_runs = e.groups[DEFAULT_GROUP].cursor.ahead_runs();
        assert!(
            default_runs > 3,
            "the test needs more runs than the slot holds, got {default_runs}"
        );
        e.checkpoint_cursor().unwrap();
        let fs = e.into_filesystem();

        let mut e = Engine::open(fs, ManualClock::new(), config(20, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(0));
        let mut redelivered = std::collections::BTreeSet::new();
        loop {
            match e.poll(0).unwrap() {
                Poll::Message(d) => {
                    redelivered.insert(d.offset.get());
                    e.ack(&d.token);
                }
                Poll::Idle => break,
                Poll::Parked { offset, .. } => panic!("unexpected park at {}", offset.get()),
                Poll::Truncated { .. } => panic!("unexpected truncation"),
            }
        }
        // A 64-byte slot holds the leading 3 acked-ahead runs (offsets 1, 3, 5), so those are
        // NOT redelivered; every other acked offset was dropped from the snapshot and safely
        // redelivers, as does every even gap.
        for kept in [1u64, 3, 5] {
            assert!(
                !redelivered.contains(&kept),
                "kept acked-ahead {kept} must not redeliver"
            );
        }
        for dropped in [7u64, 9, 19] {
            assert!(
                redelivered.contains(&dropped),
                "dropped acked-ahead {dropped} must safely redeliver"
            );
        }
        assert!(redelivered.contains(&0), "the even gaps redeliver");
        // The fully drained queue commits everything: no offset below the watermark is lost.
        assert_eq!(e.committed_offset(), Offset::new(20));
    }

    #[test]
    fn a_legacy_committed_only_checkpoint_still_resumes() {
        // A pre-snapshot (#182) checkpoint stored only the 8-byte committed offset. The new
        // open path must still read it: a payload shorter than a snapshot is the legacy form.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c", b"d"] {
            produce(&mut e, p);
        }
        let fs = e.into_filesystem();
        // Overwrite the checkpoint with a legacy committed-only payload (committed = 2).
        {
            let file = fs.open(CURSOR_CHECKPOINT).unwrap();
            let (mut cp, _) = Checkpoint::open(file).unwrap();
            cp.write(&2u64.to_le_bytes()).unwrap();
        }
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(
            e.committed_offset(),
            Offset::new(2),
            "the legacy 8-byte committed offset resumes"
        );
        let mut delivered = Vec::new();
        while let Poll::Message(d) = e.poll(0).unwrap() {
            delivered.push(d.offset.get());
            e.ack(&d.token);
        }
        assert_eq!(
            delivered,
            vec![2, 3],
            "only the uncommitted tail redelivers"
        );
    }

    #[test]
    fn a_both_slots_torn_checkpoint_falls_back_to_redeliver_from_zero() {
        // The #164 "both-slots-torn checkpoint" crash class, gated end-to-end through the
        // engine (refs #21). The cursor checkpoint is a two-slot file (#235): a single torn
        // write can only damage one slot, so recovery falls back to the other. This models
        // the worse case where BOTH slots are corrupt at once (media rot, or a double fault),
        // and asserts the engine fails SAFE: open never errors or panics, the unreadable
        // cursor is discarded, and every durable record redelivers from zero exactly once
        // (at-least-once: duplicates are allowed, a lost ack is not).
        use ironbus_storage::io::RandomAccessFile;

        // Drive a queue so BOTH checkpoint slots hold a real, distinct snapshot: ack two and
        // checkpoint (writes one slot), then ack two more and checkpoint (writes the other).
        fn drive(e: &mut Engine<InMemoryFs, ManualClock>) {
            for p in [&b"a"[..], b"b", b"c", b"d"] {
                produce(e, p);
            }
            for _ in 0..2 {
                let d = message(e.poll(0).unwrap());
                e.ack(&d.token);
            }
            e.checkpoint_cursor().unwrap(); // seq 1 -> one slot, committed = 2
            for _ in 0..2 {
                let d = message(e.poll(0).unwrap());
                e.ack(&d.token);
            }
            e.checkpoint_cursor().unwrap(); // seq 2 -> the other slot, committed = 4
        }

        // Control: the identical lifecycle with an INTACT checkpoint resumes at the head and
        // redelivers nothing. This proves the fallback below is caused by the corruption, not
        // by the checkpoint never having been meaningful (guards against a vacuous pass).
        let mut control = open(config(10, 5));
        drive(&mut control);
        assert_eq!(control.committed_offset(), Offset::new(4));
        let mut reopened =
            Engine::open(control.into_filesystem(), ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(
            reopened.committed_offset(),
            Offset::new(4),
            "an intact checkpoint resumes at the committed head"
        );
        assert!(
            matches!(reopened.poll(0).unwrap(), Poll::Idle),
            "an intact checkpoint redelivers nothing"
        );

        // Now corrupt BOTH slots of the on-disk cursor.ckpt: flip the first payload byte of
        // each slot so each slot's crc32c fails and decodes to nothing.
        let mut victim = open(config(10, 5));
        drive(&mut victim);
        let fs = victim.into_filesystem();
        let ckpt = fs.open(CURSOR_CHECKPOINT).unwrap();
        let mut bytes = ckpt.snapshot();
        assert!(
            bytes.len() >= 24 && bytes.len() % 2 == 0,
            "the checkpoint is two equal fixed-size slots"
        );
        let slot = bytes.len() / 2;
        bytes[10] ^= 0xff; // a crc-covered payload byte in the first slot
        bytes[slot + 10] ^= 0xff; // and in the second slot
        ckpt.write_all_at(&bytes, 0).unwrap();
        ckpt.sync_all().unwrap();

        // Reopen over the doubly-torn checkpoint: it must open cleanly (no error, no panic),
        // discard the unreadable cursor, and redeliver every durable record from zero, each
        // as a fresh first delivery.
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(
            e.committed_offset(),
            Offset::new(0),
            "a both-slots-torn checkpoint discards the cursor and resumes from zero"
        );
        let mut delivered = Vec::new();
        while let Poll::Message(d) = e.poll(0).unwrap() {
            assert_eq!(
                d.deliveries, 1,
                "redelivery from zero is a fresh first delivery"
            );
            delivered.push((d.offset.get(), d.record.payload.clone()));
            e.ack(&d.token);
        }
        assert_eq!(
            delivered,
            vec![
                (0, b"a".to_vec()),
                (1, b"b".to_vec()),
                (2, b"c".to_vec()),
                (3, b"d".to_vec()),
            ],
            "every durable record redelivers after the checkpoint is lost"
        );
        assert_eq!(e.committed_offset(), Offset::new(4));
    }

    #[test]
    fn named_groups_consume_the_log_independently() {
        // Two named groups each see every message and advance their own cursor: broadcast
        // fan-out over the single log (#9). The default group is untouched by either.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        // Group "x" consumes and acks all three.
        for expected in 0..3u64 {
            let d = message(e.poll_in("x", 0).unwrap());
            assert_eq!(d.offset, Offset::new(expected));
            assert_eq!(e.ack_in("x", &d.token), AckResult::Acked);
        }
        assert_eq!(e.committed_offset_in("x"), Offset::new(3));
        // Group "y" is independent: it has consumed nothing and still sees the whole log.
        assert_eq!(e.committed_offset_in("y"), Offset::new(0));
        let d = message(e.poll_in("y", 0).unwrap());
        assert_eq!(
            d.offset,
            Offset::new(0),
            "y starts at the beginning, independent of x"
        );
        // The default (durable) group is also independent and untouched.
        assert_eq!(e.committed_offset(), Offset::new(0));
        assert!(matches!(e.poll(0).unwrap(), Poll::Message(_)));
    }

    #[test]
    fn named_group_leases_are_independent_across_groups() {
        // A message leased (delivered, unacked) in one group is still deliverable in another:
        // each group has its own in-flight set, so groups do not block each other (#9).
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        let dx = message(e.poll_in("x", 0).unwrap());
        assert_eq!(dx.offset, Offset::new(0));
        // y can still claim offset 0; x's lease does not block it.
        let dy = message(e.poll_in("y", 0).unwrap());
        assert_eq!(dy.offset, Offset::new(0));
        // in_flight counts both groups' leases.
        assert_eq!(e.in_flight(), 2);
        // Each group commits its own delivery independently.
        assert_eq!(e.ack_in("x", &dx.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in("x"), Offset::new(1));
        assert_eq!(
            e.committed_offset_in("y"),
            Offset::new(0),
            "acking in x does not commit y"
        );
        assert_eq!(e.ack_in("y", &dy.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in("y"), Offset::new(1));
        assert_eq!(e.in_flight(), 0);
    }

    #[test]
    fn cumulative_ack_is_rejected_on_a_work_group() {
        // Cumulative ack (ack-all-up-to-offset) is the JetStream AckAll trap on a shared,
        // out-of-order-draining cursor: it is hard-rejected for competing work-groups (#63).
        // Every live group today is a work-group, so the guard rejects every cumulative ack
        // with the typed error and never panics.
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        produce(&mut e, b"b");
        // The default group is a work-group: rejected.
        assert!(matches!(
            e.cumulative_ack(Offset::new(2)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        // A named competing group: rejected.
        assert!(matches!(
            e.cumulative_ack_in("x", Offset::new(1)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        // A key_shared group is still a work-group: rejected.
        e.set_key_ordering_in("k", KeyOrdering::KeyShared).unwrap();
        assert!(matches!(
            e.cumulative_ack_in("k", Offset::new(1)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        // The rejection commits nothing: per-message acks still drive the cursor as before.
        let d = message(e.poll(0).unwrap());
        assert_eq!(e.ack(&d.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(1));
    }

    #[test]
    fn the_cumulative_ack_rejection_renders_a_distinct_message() {
        // The typed error has a self-describing Display, distinct from the other engine errors,
        // so the wire layer can surface a stable reason.
        let msg = EngineError::CumulativeAckOnWorkGroup.to_string();
        assert!(msg.contains("cumulative ack"), "{msg}");
        assert!(msg.contains("broadcast"), "{msg}");
    }

    // A config with an explicit work-group cap (#240), so a test exercises the bound without
    // having to allocate `DEFAULT_MAX_GROUPS` groups.
    fn config_with_max_groups(max_groups: usize) -> EngineConfig {
        EngineConfig {
            max_groups,
            ..config(10, 5)
        }
    }

    #[test]
    fn a_new_group_past_the_cap_is_rejected() {
        // The group cap bounds memory once the wire can name groups (#240). The default group
        // already counts against the cap, so with `max_groups == 4` three NAMED groups fit; one
        // more is rejected with the typed error and allocates nothing.
        let mut e = open(config_with_max_groups(4));
        produce(&mut e, b"a");
        for i in 0..3 {
            let name = format!("g{i}");
            // Each first poll of a fresh group is fine (delivers offset 0, or idle).
            e.poll_in(&name, 0).unwrap();
        }
        assert_eq!(e.groups.len(), 4, "default + 3 named groups fill the cap");
        let err = e.poll_in("one-too-many", 0).unwrap_err();
        assert!(
            matches!(err, EngineError::TooManyGroups { max } if max == 4),
            "the cap rejects a new group, got {err}"
        );
        // The rejected group allocated nothing: the count did not grow and the name is absent.
        assert_eq!(e.groups.len(), 4, "the rejected group was not allocated");
        assert!(!e.groups.contains_key("one-too-many"));
        // Re-polling an already-live group does NOT count again (it is not a new allocation).
        assert!(e.poll_in("g0", 0).is_ok());
        assert_eq!(e.groups.len(), 4, "re-polling a live group does not grow");
        // The default group is exempt: it works even though the cap is full.
        assert!(e.poll(0).is_ok());
        assert!(e.poll_in("", 0).is_ok());
    }

    #[test]
    fn the_default_group_is_exempt_even_below_a_cap_of_one() {
        // `max_groups == 1` leaves no room for any named group, yet the default group `""` is
        // never counted against the cap and never rejected, so the engine is always usable; the
        // first NAMED group is rejected.
        let mut e = open(config_with_max_groups(1));
        produce(&mut e, b"a");
        assert!(e.poll(0).is_ok(), "the default group always works");
        assert!(e.poll_in("", 0).is_ok(), "the default group is exempt");
        assert!(matches!(
            e.poll_in("any", 0).unwrap_err(),
            EngineError::TooManyGroups { max: 1 }
        ));
        assert_eq!(e.groups.len(), 1, "only the default group exists");
    }

    #[test]
    fn a_zero_cap_means_unlimited_groups() {
        // `0` = unlimited, matching the `0` = off convention of the other bounds. Far more than
        // the non-zero default may be created without rejection.
        let mut e = open(config_with_max_groups(0));
        produce(&mut e, b"a");
        for i in 0..(DEFAULT_MAX_GROUPS + 16) {
            let name = format!("g{i}");
            e.poll_in(&name, 0).unwrap();
        }
        assert_eq!(
            e.groups.len(),
            DEFAULT_MAX_GROUPS + 16 + 1,
            "default + all named"
        );
    }

    #[test]
    fn lowering_the_group_cap_still_recovers_every_durable_group() {
        // Recovery must load EVERY durable named group regardless of `max_groups`: the cap gates
        // only NEW group creation, never the resume of groups already on disk. Otherwise an
        // operator who LOWERS --max-groups below the on-disk group count would silently reset the
        // dropped groups to offset 0 and redeliver the whole already-acked log. Create three named
        // groups committed to distinct offsets under a generous cap, then reopen under a cap of 2
        // (below the three) and assert all three keep their committed cursors.
        let mut e = open(config_with_max_groups(100));
        for p in [&b"0"[..], b"1", b"2", b"3"] {
            produce(&mut e, p);
        }
        // Advance each group to a distinct committed offset, then make it durable.
        for (group, acks) in [("g-a", 1u32), ("g-b", 2), ("g-c", 3)] {
            for _ in 0..acks {
                let d = message(e.poll_in(group, 0).unwrap());
                e.ack_in(group, &d.token);
            }
            e.checkpoint_group(group).unwrap();
        }
        assert_eq!(e.committed_offset_in("g-a"), Offset::new(1));
        assert_eq!(e.committed_offset_in("g-b"), Offset::new(2));
        assert_eq!(e.committed_offset_in("g-c"), Offset::new(3));
        let fs = e.into_filesystem();

        // Reopen under a cap of 2 (default plus room for only one named under the old, buggy
        // recovery that applied the cap to the resume scan): every group must still recover, none
        // reset to 0.
        let e = Engine::open(fs, ManualClock::new(), config_with_max_groups(2)).unwrap();
        assert_eq!(e.committed_offset_in("g-a"), Offset::new(1), "g-a survived");
        assert_eq!(e.committed_offset_in("g-b"), Offset::new(2), "g-b survived");
        assert_eq!(e.committed_offset_in("g-c"), Offset::new(3), "g-c survived");
        assert_eq!(
            e.groups.len(),
            4,
            "default plus three recovered groups, despite a cap of 2"
        );
    }

    #[test]
    fn an_invalid_group_name_is_rejected_before_allocation() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        let too_long = "g".repeat(MAX_GROUP_NAME_LEN + 1);
        for bad in [too_long.as_str(), "has space", "ctrl\tchar", "café"] {
            assert!(
                matches!(
                    e.poll_in(bad, 0).unwrap_err(),
                    EngineError::InvalidGroupName
                ),
                "name {bad:?} must be rejected"
            );
        }
        // None of the rejected names allocated a group: only the default exists.
        assert_eq!(e.groups.len(), 1);
        // A well-formed name is accepted.
        assert!(e.poll_in("valid-name_1.2:3", 0).is_ok());
        assert_eq!(e.groups.len(), 2);
        // A name exactly at the length boundary (MAX_GROUP_NAME_LEN graphic-ASCII bytes) is
        // accepted; one byte longer is rejected (covered by `too_long` above).
        let at_boundary = "g".repeat(MAX_GROUP_NAME_LEN);
        assert!(
            e.poll_in(&at_boundary, 0).is_ok(),
            "the max-length name is valid"
        );
        assert_eq!(e.groups.len(), 3);
    }

    #[test]
    fn ack_nack_progress_on_an_unknown_group_never_create_it() {
        // Acking/nacking/progressing a group that was never polled is a fence, and crucially
        // does NOT allocate the group (only the capped poll_in path creates groups) (#240).
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        let d = message(e.poll_in("x", 0).unwrap()); // creates x, holds a token for x
        assert_eq!(e.ack_in("ghost", &d.token), AckResult::Fenced);
        assert_eq!(e.nack_in("ghost", &d.token, 0).unwrap(), NackResult::Fenced);
        assert_eq!(e.progress_in("ghost", &d.token), ProgressResult::Fenced);
        // groups holds only the default and x; ghost was never created.
        assert_eq!(e.groups.len(), 2);
        assert!(!e.groups.contains_key("ghost"));
    }

    #[test]
    fn a_named_group_cursor_survives_a_restart() {
        // A named work-group's committed cursor is durable (#60): after a clean-disconnect
        // flush and reopen, the group resumes past acked messages instead of redelivering the
        // whole log, while the default group is independent.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        for expected in 0..2u64 {
            let d = message(e.poll_in("orders", 0).unwrap());
            assert_eq!(d.offset, Offset::new(expected));
            assert_eq!(e.ack_in("orders", &d.token), AckResult::Acked);
        }
        assert_eq!(e.committed_offset_in("orders"), Offset::new(2));
        e.checkpoint_group("orders").unwrap();
        let fs = e.into_filesystem();

        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        // The named group resumes at 2; only the uncommitted tail (offset 2) redelivers there.
        assert_eq!(e.committed_offset_in("orders"), Offset::new(2));
        let d = message(e.poll_in("orders", 0).unwrap());
        assert_eq!(d.offset, Offset::new(2));
        // The default group consumed nothing and resumes at 0, independent of "orders".
        assert_eq!(e.committed_offset(), Offset::new(0));
    }

    #[test]
    fn multiple_named_groups_resume_independently() {
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c", b"d"] {
            produce(&mut e, p);
        }
        // "fast" acks three, "slow" acks one.
        for expected in 0..3u64 {
            let d = message(e.poll_in("fast", 0).unwrap());
            assert_eq!(d.offset, Offset::new(expected));
            e.ack_in("fast", &d.token);
        }
        let d = message(e.poll_in("slow", 0).unwrap());
        e.ack_in("slow", &d.token);
        e.checkpoint_group("fast").unwrap();
        e.checkpoint_group("slow").unwrap();
        let fs = e.into_filesystem();

        let e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset_in("fast"), Offset::new(3));
        assert_eq!(e.committed_offset_in("slow"), Offset::new(1));
    }

    #[test]
    fn a_named_groups_out_of_order_ack_survives_a_restart() {
        // The named-group snapshot carries the acked-ahead set too (#60, #235): an out-of-order
        // ack leaving a gap survives a restart, so only the gap redelivers, not the acked-ahead.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        let mut tokens = Vec::new();
        for _ in 0..3 {
            tokens.push(message(e.poll_in("g", 0).unwrap()).token);
        }
        // Ack 1 and 2 but not 0: committed stays 0, ahead = [1, 3).
        assert_eq!(e.ack_in("g", &tokens[1]), AckResult::Acked);
        assert_eq!(e.ack_in("g", &tokens[2]), AckResult::Acked);
        assert_eq!(e.committed_offset_in("g"), Offset::new(0));
        e.checkpoint_group("g").unwrap();
        let fs = e.into_filesystem();

        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset_in("g"), Offset::new(0));
        // Only the gap (offset 0) redelivers; 1 and 2 are acked-ahead and skipped.
        let mut delivered = Vec::new();
        loop {
            match e.poll_in("g", 0).unwrap() {
                Poll::Message(d) => {
                    delivered.push(d.offset.get());
                    e.ack_in("g", &d.token);
                }
                Poll::Idle => break,
                Poll::Parked { offset, .. } => panic!("unexpected park at {}", offset.get()),
                Poll::Truncated { .. } => panic!("unexpected truncation"),
            }
        }
        assert_eq!(
            delivered,
            vec![0],
            "only the gap redelivers in the named group"
        );
        assert_eq!(e.committed_offset_in("g"), Offset::new(3));
    }

    #[test]
    fn reopen_recovers_the_durable_log_and_redelivers_uncommitted_messages() {
        let mut e = open(config(10, 5));
        for p in [b"a", b"b"] {
            produce(&mut e, p);
        }
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token); // ack 0, but the cursor is not durable yet
        let fs = e.into_filesystem();

        // Reopen: the log is recovered, but the committed cursor resets, so everything
        // redelivers (at-least-once; the durable cursor is follow-up work).
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(0));
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.offset, Offset::new(0));
        assert_eq!(d.record.payload, b"a");
        let d_b = message(e.poll(0).unwrap());
        assert_eq!(d_b.record.payload, b"b");
    }

    #[cfg(unix)]
    #[test]
    fn durable_cursor_resumes_on_a_real_directory() {
        use ironbus_storage::fs::StdFs;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let put = |e: &mut Engine<StdFs, ManualClock>, payload: &[u8]| {
            e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            })
            .unwrap();
        };

        let mut e =
            Engine::open(StdFs::new(root.clone()), ManualClock::new(), config(10, 5)).unwrap();
        put(&mut e, b"a");
        put(&mut e, b"b");
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token);
        e.checkpoint_cursor().unwrap();
        drop(e);

        let mut e = Engine::open(StdFs::new(root), ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(1));
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.offset, Offset::new(1));
        assert_eq!(d.record.payload, b"b");
    }

    #[cfg(unix)]
    #[test]
    fn a_named_group_cursor_resumes_on_a_real_directory() {
        use ironbus_storage::fs::StdFs;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let put = |e: &mut Engine<StdFs, ManualClock>, payload: &[u8]| {
            e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            })
            .unwrap();
        };
        // A group name with path-unsafe characters (`/` and `:`) proves the hex filename
        // encoding: the checkpoint must never be a path-traversal or an invalid filename.
        let group = "team/a:1";
        let mut e =
            Engine::open(StdFs::new(root.clone()), ManualClock::new(), config(10, 5)).unwrap();
        put(&mut e, b"a");
        put(&mut e, b"b");
        let d0 = message(e.poll_in(group, 0).unwrap());
        e.ack_in(group, &d0.token);
        e.checkpoint_group(group).unwrap();
        drop(e);

        let mut e = Engine::open(StdFs::new(root), ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset_in(group), Offset::new(1));
        let d = message(e.poll_in(group, 0).unwrap());
        assert_eq!(d.offset, Offset::new(1));
        assert_eq!(d.record.payload, b"b");
        // The default group is unaffected on the same real directory.
        assert_eq!(e.committed_offset(), Offset::new(0));
    }

    #[test]
    fn group_checkpoint_filename_round_trips_and_excludes_others() {
        // The hex filename round-trips any (graphic-ASCII, path-unsafe) name.
        for g in ["orders", "team/a:1", "x", "A.B-C_d"] {
            let name = group_checkpoint_name(g);
            assert_eq!(parse_group_checkpoint_name(&name).as_deref(), Some(g));
        }
        // The default cursor file, segment files, an empty name, and bad hex are NOT named-group
        // checkpoints, so discovery never resurrects a spurious group from them.
        assert_eq!(parse_group_checkpoint_name("cursor.ckpt"), None);
        assert_eq!(
            parse_group_checkpoint_name("seg-0000000000000000.log"),
            None
        );
        assert_eq!(parse_group_checkpoint_name("cursor-.ckpt"), None);
        assert_eq!(parse_group_checkpoint_name("cursor-zz.ckpt"), None);
        assert_eq!(parse_group_checkpoint_name("cursor-abc.ckpt"), None);
    }

    #[test]
    fn a_nacked_message_redelivers_with_an_escalated_delivery_count() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"work");
        // poll_now and nack share the engine's own clock, so a zero-delay nack is reclaimable
        // at the same instant and redelivers on the next poll.
        let d0 = message(e.poll_now().unwrap());
        assert_eq!(d0.deliveries, 1);
        assert_eq!(e.nack(&d0.token, 0).unwrap(), NackResult::Requeued);
        // The nacking token is fenced: a late ack cannot commit the unprocessed message.
        assert_eq!(e.ack(&d0.token), AckResult::Fenced);
        // Redelivered: same offset, escalated delivery count, a fresh generation.
        let d1 = message(e.poll_now().unwrap());
        assert_eq!(d1.offset, d0.offset);
        assert_eq!(d1.deliveries, 2);
        assert_ne!(d1.token.generation, d0.token.generation);
        // The fresh token commits normally.
        assert_eq!(e.ack(&d1.token), AckResult::Acked);
        assert_eq!(e.committed_offset().get(), 1);
    }

    #[test]
    fn a_stale_nack_is_fenced() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"work");
        let d0 = message(e.poll_now().unwrap());
        e.ack(&d0.token); // commit, so the token is now stale
        assert_eq!(e.nack(&d0.token, 0).unwrap(), NackResult::Fenced);
    }

    #[test]
    fn term_drops_the_message_without_redelivery() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"drop-me");
        let d = message(e.poll_now().unwrap());
        // Term is an intentional drop: it commits past the message (cursor advances) so it
        // never redelivers, the same mechanism as ack.
        assert_eq!(e.term(&d.token), AckResult::Acked);
        assert_eq!(e.committed_offset().get(), 1);
        assert!(matches!(e.poll_now().unwrap(), Poll::Idle));
        // A stale term is fenced (no double-commit).
        assert_eq!(e.term(&d.token), AckResult::Fenced);
    }

    #[test]
    fn progress_extends_the_lease_then_caps_at_the_hard_cap() {
        // config(_, _) sets visibility 30 ns, hard cap 100 ns. Use an Arc<ManualClock> the
        // test advances, since progress reads the engine's own clock.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(
            InMemoryFs::new(),
            std::sync::Arc::clone(&clock),
            config(10, 5),
        )
        .unwrap();
        // The produce test helper is monomorphic over ManualClock, so inline it for this
        // Arc<ManualClock> engine.
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"slow",
        })
        .unwrap();
        // Deliver at t=0: deadline 30, attempt_start 0, hard cap at t=100.
        let d = message(e.poll_now().unwrap());
        // At t=25, progress extends the deadline to 55 (< cap), so it stays in flight.
        clock.advance_monotonic_nanos(25);
        assert_eq!(e.progress(&d.token), ProgressResult::Extended);
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "still leased after extend"
        );
        // At t=100 (attempt_start + hard cap), progress can no longer extend.
        clock.advance_monotonic_nanos(75);
        assert_eq!(e.progress(&d.token), ProgressResult::CapReached);
        // A stale token is fenced.
        e.ack(&d.token);
        assert_eq!(e.progress(&d.token), ProgressResult::Fenced);
    }

    #[test]
    fn nack_with_no_delay_applies_the_backoff_schedule() {
        // backoff [50] ns for the first attempt: a nack with no client delay defers redelivery
        // to now + 50 rather than redelivering immediately.
        let mut cfg = config(10, 5);
        cfg.delivery = DeliveryConfig::new(5, false, vec![50]).unwrap();
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(InMemoryFs::new(), std::sync::Arc::clone(&clock), cfg).unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"x",
        })
        .unwrap();
        let d = message(e.poll_now().unwrap());
        assert_eq!(d.deliveries, 1);
        // u64::MAX = no explicit delay, so the schedule governs (50 ns for attempt 1).
        assert_eq!(e.nack(&d.token, u64::MAX).unwrap(), NackResult::Requeued);
        // The backoff deadline (now + 50) is in the future, so nothing redelivers yet.
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "backoff defers redelivery"
        );
        // Past the backoff window it redelivers, with the attempt count escalated.
        clock.advance_monotonic_nanos(50);
        let d2 = message(e.poll_now().unwrap());
        assert_eq!(d2.offset, d.offset);
        assert_eq!(d2.deliveries, 2);
    }

    #[test]
    fn an_explicit_nack_delay_overrides_the_backoff_schedule() {
        // backoff [50] ns, but the client asks for 1 ms (1_000_000 ns); the client wins.
        let mut cfg = config(10, 5);
        cfg.delivery = DeliveryConfig::new(5, false, vec![50]).unwrap();
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(InMemoryFs::new(), std::sync::Arc::clone(&clock), cfg).unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"x",
        })
        .unwrap();
        let d = message(e.poll_now().unwrap());
        assert_eq!(e.nack(&d.token, 1).unwrap(), NackResult::Requeued);
        // Advancing past the backoff (50 ns) is not enough: the client's 1 ms delay governs.
        clock.advance_monotonic_nanos(50);
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "an explicit client delay overrides the backoff schedule"
        );
        // At the client's 1 ms mark it does redeliver, proving the explicit delay governed.
        clock.advance_monotonic_nanos(1_000_000 - 50);
        let d2 = message(e.poll_now().unwrap());
        assert_eq!(d2.offset, d.offset);
        assert_eq!(d2.deliveries, 2);
    }

    #[test]
    fn the_backoff_schedule_escalates_across_attempts() {
        // schedule [50, 200]: attempt 1 -> 50, attempt 2 -> 200, later clamps to 200.
        let mut cfg = config(10, 9);
        cfg.delivery = DeliveryConfig::new(9, false, vec![50, 200]).unwrap();
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(InMemoryFs::new(), std::sync::Arc::clone(&clock), cfg).unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"x",
        })
        .unwrap();
        // Attempt 1 nack: schedule[0] = 50.
        let d1 = message(e.poll_now().unwrap());
        assert_eq!(d1.deliveries, 1);
        e.nack(&d1.token, u64::MAX).unwrap();
        assert!(matches!(e.poll_now().unwrap(), Poll::Idle));
        clock.advance_monotonic_nanos(50);
        // Attempt 2 nack: schedule[1] = 200 (escalated), so 50 more is NOT enough.
        let d2 = message(e.poll_now().unwrap());
        assert_eq!(d2.deliveries, 2);
        e.nack(&d2.token, u64::MAX).unwrap();
        clock.advance_monotonic_nanos(50);
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "attempt 2 waits the longer schedule[1]"
        );
        clock.advance_monotonic_nanos(150);
        let d3 = message(e.poll_now().unwrap());
        assert_eq!(d3.deliveries, 3);
    }

    #[test]
    fn counters_track_delivery_and_redelivery() {
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(
            InMemoryFs::new(),
            std::sync::Arc::clone(&clock),
            config(10, 5),
        )
        .unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"x",
        })
        .unwrap();
        assert_eq!(e.counters().produced, 1);

        // First delivery (visibility 30 ns).
        let d1 = message(e.poll_now().unwrap());
        assert_eq!(d1.deliveries, 1);
        assert_eq!(e.counters().delivered, 1);
        assert_eq!(e.counters().redelivered, 0);

        // Let the lease expire, then re-poll: the SAME message is delivered a second time, so
        // `delivered` is 2 (once per delivery) and `redelivered` is 1.
        clock.advance_monotonic_nanos(40);
        let d2 = message(e.poll_now().unwrap());
        assert_eq!(d2.deliveries, 2);
        assert_eq!(e.counters().delivered, 2);
        assert_eq!(e.counters().redelivered, 1);
    }

    #[test]
    fn counters_track_a_dead_letter() {
        let clock = std::sync::Arc::new(ManualClock::new());
        // max_deliver = 1: the second delivery attempt is dead-lettered.
        let mut e = Engine::open(
            InMemoryFs::new(),
            std::sync::Arc::clone(&clock),
            config(10, 1),
        )
        .unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"poison",
        })
        .unwrap();
        // First delivery (attempt 1, within the cap).
        let _ = message(e.poll_now().unwrap());
        assert_eq!(e.counters().delivered, 1);
        // Expire and re-poll: attempt 2 exceeds max_deliver, so it is parked, not delivered.
        clock.advance_monotonic_nanos(40);
        assert!(matches!(e.poll_now().unwrap(), Poll::Parked { .. }));
        assert_eq!(e.counters().dead_lettered, 1);
        assert_eq!(
            e.counters().delivered,
            1,
            "the parked poison attempt is not a delivery"
        );
        assert_eq!(
            e.counters().redelivered,
            0,
            "the parked poison attempt is counted only in dead_lettered"
        );
    }

    // ---- Durable resilience counters (#98) ----

    /// Drives produce/poll/ack/dead-letter on a fresh engine to bump several counters, returning
    /// the engine so a test can checkpoint and reopen it over the shared in-memory filesystem.
    fn drive_counters(e: &mut Engine<InMemoryFs, std::sync::Arc<ManualClock>>) {
        // Three good messages: produced = 3, produced_bytes = 3, delivered = 3, acks = 3.
        for p in [&b"a"[..], b"b", b"c"] {
            e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: p,
            })
            .unwrap();
        }
        for _ in 0..3 {
            let d = message(e.poll_now().unwrap());
            assert_eq!(e.ack(&d.token), AckResult::Acked);
        }
    }

    #[test]
    fn counters_persist_across_a_reopen() {
        // Produce/deliver/ack to bump several counters, dead-letter one to bump dead_lettered,
        // checkpoint, reopen on the SHARED in-memory fs, and assert the counters RESUMED (not
        // zeroed). This is the headline #98 contract: a restart no longer zeroes the history.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(
            InMemoryFs::new(),
            std::sync::Arc::clone(&clock),
            config(10, 1),
        )
        .unwrap();
        drive_counters(&mut e);
        // Dead-letter one poison message (max_deliver = 1): produced = 4, dead_lettered = 1.
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"poison",
        })
        .unwrap();
        let _ = message(e.poll_now().unwrap()); // attempt 1
        clock.advance_monotonic_nanos(40);
        assert!(matches!(e.poll_now().unwrap(), Poll::Parked { .. })); // attempt 2 -> parked
        let before = e.counters();
        assert_eq!(before.produced, 4);
        // 3 good deliveries plus the poison's first (within-cap) delivery attempt; the parked
        // second attempt is dead_lettered, not delivered.
        assert_eq!(before.delivered, 4);
        assert_eq!(before.acks, 3);
        assert_eq!(before.dead_lettered, 1);

        // The graceful-shutdown flush persists the counters (and cursors).
        e.checkpoint_all_groups().unwrap();
        let fs = e.into_filesystem();

        // Reopen on the same fs: the counters resume from the snapshot, byte-for-byte.
        let e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 1)).unwrap();
        assert_eq!(
            e.counters(),
            before,
            "the resilience counters resumed from the durable snapshot, not zeroed"
        );
    }

    #[test]
    fn a_missing_counters_file_opens_with_zero_counters() {
        // A data directory with a durable cursor but NO counters.ckpt (a pre-#98 broker, or one
        // that crashed before its first counters snapshot) opens cleanly with zero counters: the
        // missing snapshot is never a hard failure.
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        let d = message(e.poll(0).unwrap());
        e.ack(&d.token);
        e.checkpoint_cursor().unwrap(); // writes cursor.ckpt
        let fs = e.into_filesystem();
        // Delete the counters checkpoint so the reopen finds it absent.
        fs.remove(COUNTERS_CHECKPOINT).unwrap();
        assert!(!fs.exists(COUNTERS_CHECKPOINT).unwrap());

        let e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(
            e.counters(),
            Counters::default(),
            "a missing counters snapshot recovers as all-zeros"
        );
        // The cursor is unaffected: it resumed normally.
        assert_eq!(e.committed_offset(), Offset::new(1));
    }

    #[test]
    fn a_torn_counters_file_opens_with_zero_counters_and_the_log_is_unaffected() {
        // A corrupt counters.ckpt (BOTH slots torn) must NOT block open or panic, and must not
        // affect the durable log or the cursor: the counters degrade to zero, everything else
        // recovers exactly. This is the never-block-recovery safety contract (#98).
        use ironbus_storage::io::RandomAccessFile;
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b"] {
            produce(&mut e, p);
        }
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token); // committed = 1
                          // Persist both the cursor and the counters.
        e.checkpoint_cursor().unwrap();
        e.checkpoint_counters().unwrap();
        let before_counters = e.counters();
        assert!(before_counters.produced >= 2, "counters were bumped");
        let fs = e.into_filesystem();

        // Corrupt EVERY byte region of counters.ckpt so neither slot's CRC can validate.
        let ckpt = fs.open(COUNTERS_CHECKPOINT).unwrap();
        let mut bytes = ckpt.snapshot();
        assert!(!bytes.is_empty(), "the counters checkpoint was written");
        for b in &mut bytes {
            *b ^= 0xff;
        }
        ckpt.set_len(0).unwrap();
        ckpt.write_all_at(&bytes, 0).unwrap();
        ckpt.sync_all().unwrap();

        // Open must SUCCEED (never a hard error), recover zero counters, and leave the log and
        // cursor untouched.
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(
            e.counters(),
            Counters::default(),
            "a torn counters snapshot recovers as all-zeros, never a hard failure"
        );
        // The cursor resumed from its (intact) checkpoint: committed = 1, only the tail redelivers.
        assert_eq!(e.committed_offset(), Offset::new(1));
        let mut delivered = Vec::new();
        while let Poll::Message(d) = e.poll(0).unwrap() {
            delivered.push(d.offset.get());
        }
        assert_eq!(
            delivered,
            vec![1],
            "the durable log and cursor are unaffected by the torn counters file"
        );
    }

    #[test]
    fn the_graceful_shutdown_flush_persists_the_latest_counts() {
        // A clean stop (checkpoint_all_groups) flushes the LATEST counters, so a restart after the
        // clean stop shows the final counts, not a stale cadence snapshot. The default checkpoint
        // interval (1024) means no interval checkpoint fires for this small workload, so ONLY the
        // shutdown flush makes the counters durable.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(
            InMemoryFs::new(),
            std::sync::Arc::clone(&clock),
            config(10, 5),
        )
        .unwrap();
        drive_counters(&mut e); // produced/delivered/acks = 3 each, no interval checkpoint fires
        let final_counts = e.counters();
        e.checkpoint_all_groups().unwrap(); // the graceful-shutdown flush
        let fs = e.into_filesystem();

        let e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 5)).unwrap();
        assert_eq!(
            e.counters(),
            final_counts,
            "the graceful-shutdown flush persisted the final counts"
        );
        assert_eq!(e.counters().produced, 3);
        assert_eq!(e.counters().acks, 3);
    }

    #[test]
    fn the_increment_path_does_not_fsync_per_increment() {
        // The counters snapshot must NOT be written on every counter increment (an fsync per
        // produce/ack would kill throughput): only the cadence and shutdown flush persist it. This
        // pins that a produce/poll/ack does NOT touch counters.ckpt, by capturing its on-disk bytes
        // before and after a burst of increments WITHOUT a checkpoint call. The probe handle
        // ALIASES the same in-memory disk the engine writes to (a cloned `InMemoryFs`).
        let clock = std::sync::Arc::new(ManualClock::new());
        let probe = InMemoryFs::new();
        let mut e =
            Engine::open(probe.clone(), std::sync::Arc::clone(&clock), config(10, 5)).unwrap();
        // Read the freshly-created (never-written) counters.ckpt bytes via the probe handle.
        let snapshot_after_open = probe.open(COUNTERS_CHECKPOINT).unwrap().snapshot();
        // A burst of increments WITHOUT any checkpoint call.
        drive_counters(&mut e);
        assert_eq!(e.counters().produced, 3, "the in-memory counters DID move");
        let snapshot_after_increments = probe.open(COUNTERS_CHECKPOINT).unwrap().snapshot();
        assert_eq!(
            snapshot_after_open, snapshot_after_increments,
            "an increment must NOT write counters.ckpt (no per-increment fsync)"
        );
        // And after an explicit checkpoint, the on-disk snapshot DOES change (proving the test is
        // not vacuous: the write path works, it is just not on the increment path).
        e.checkpoint_counters().unwrap();
        let snapshot_after_checkpoint = probe.open(COUNTERS_CHECKPOINT).unwrap().snapshot();
        assert_ne!(
            snapshot_after_increments, snapshot_after_checkpoint,
            "an explicit checkpoint DOES write counters.ckpt"
        );
    }

    #[test]
    fn the_counters_snapshot_round_trips_every_field() {
        // The encode/decode round-trips every counter field, and the tolerant decode treats a short
        // or empty payload as zero-filled (the never-block-recovery decode contract).
        let counters = Counters {
            produced: 11,
            produced_bytes: 222,
            produce_rejected: 3,
            delivered: 44,
            redelivered: 5,
            dead_lettered: 6,
            truncations: 7,
            truncated_records: 88,
            acks: 99,
            segments_reaped: 10,
            segments_force_reaped: 11,
            // The skip/loss reconciliation family (#307), appended at the end of the snapshot.
            records_skipped: 77,
            bytes_skipped: 4096,
            last_skip_offset: 1234,
            counter_checkpoint_repairs: 2,
        };
        let encoded = counters.encode_snapshot();
        assert_eq!(Counters::decode_snapshot(&encoded), counters);
        // An empty or too-short payload decodes to all-zeros, never panics.
        assert_eq!(Counters::decode_snapshot(&[]), Counters::default());
        assert_eq!(Counters::decode_snapshot(&[1, 2, 3]), Counters::default());
        // Trailing garbage past the known fields is ignored (forward compatibility).
        let mut padded = encoded.clone();
        padded.extend_from_slice(&[0xAB; 16]);
        assert_eq!(Counters::decode_snapshot(&padded), counters);
    }

    // --- Checkpoint-plus-replay reconciliation for the skip/loss family (#307) ---

    use ironbus_storage::io::RandomAccessFile;
    use ironbus_storage::loss::{LossEvent, ReasonCode};
    use ironbus_storage::naming::segment_file_name;

    /// Tears `tear` bytes off the END of segment 0 on `fs` (an unsynced/torn tail), so a reopen
    /// recovers a non-empty loss report whose `total_bytes_skipped` is the dropped span. Returns the
    /// pre-tear segment length so a test can size the loss exactly. Mirrors the log-level torn-tail
    /// recipe (the bytes dropped are the pre-recovery length minus the post-recovery length).
    fn tear_segment_tail(fs: &InMemoryFs, tear: u64) -> u64 {
        let file = fs.open(&segment_file_name(0)).unwrap();
        let len = file.len().unwrap();
        let torn_len = len.saturating_sub(tear);
        file.set_len(torn_len).unwrap();
        file.sync_data().unwrap();
        len
    }

    #[test]
    fn reconciliation_raises_skip_loss_above_the_snapshot_and_counts_a_repair() {
        // A fresh engine has an all-zero counters snapshot (nothing was checkpointed yet). After a
        // crash tears the durable tail, the durable LOSS REPORT implies bytes were skipped, so on
        // reopen the reconciliation raises `bytes_skipped` and `last_skip_offset` above the (zero)
        // snapshot and counts exactly one repair. This is the explicit, unified form of the lower
        // bound #306 left implicit.
        let fs = InMemoryFs::new();
        let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
        for _ in 0..4 {
            produce(&mut e, &[0xab; 16]);
        }
        let flushed_before = e.flushed_offset().get();
        // Drop the engine WITHOUT flushing the counters snapshot (a hard crash), then tear the tail.
        drop(e);
        tear_segment_tail(&fs, 3);

        let reopened = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        let c = reopened.counters();
        // The durable loss report drove the reconciliation above the zero snapshot.
        let replay_records = reopened.loss_report().total_records_lost_estimate();
        let replay_bytes = reopened.loss_report().total_bytes_skipped();
        assert!(
            replay_bytes > 0,
            "the torn tail produced a non-empty loss report"
        );
        assert_eq!(
            c.records_skipped, replay_records,
            "records_skipped reconciled up to the durable loss report records total"
        );
        assert_eq!(
            c.bytes_skipped, replay_bytes,
            "bytes_skipped reconciled up to the durable loss report total"
        );
        assert!(
            c.last_skip_offset > 0 && c.last_skip_offset <= flushed_before,
            "last_skip_offset is the recovered head the loss reached, got {}",
            c.last_skip_offset
        );
        assert_eq!(
            c.counter_checkpoint_repairs, 1,
            "exactly one repair: the replay raised a skip/loss value above the snapshot"
        );
    }

    #[test]
    fn last_skip_offset_is_the_max_of_checkpoint_and_replay() {
        // The reconciled `last_skip_offset` is exactly max(checkpoint snapshot, replay). The
        // reconciliation helper is exercised directly over both orderings so the `max` is pinned in
        // both directions, independent of how a crash happened to land.
        let flushed = 7u64;
        let mut report = LossReport::new();
        // One torn-tail event: replay records = 2, replay bytes = 64 - 16 = 48. A non-empty report
        // makes the replay offset the recovered head (`flushed`).
        report.push(LossEvent::span(0, 16, 64, 2, ReasonCode::TornTail));
        let replay_offset = flushed;
        let replay_records = report.total_records_lost_estimate();
        let replay_bytes = report.total_bytes_skipped();

        // Checkpoint BELOW the replay on `last_skip_offset` (records/bytes already dominate, so this
        // case isolates the OFFSET max): the replay offset wins and a repair is counted.
        let mut low = Counters {
            records_skipped: replay_records + 100,
            bytes_skipped: replay_bytes + 100,
            last_skip_offset: replay_offset - 1,
            ..Counters::default()
        };
        Engine::<InMemoryFs, ManualClock>::reconcile_skip_loss_counters(&mut low, &report, flushed);
        assert_eq!(
            low.last_skip_offset, replay_offset,
            "max(checkpoint, replay) picks the larger replay offset"
        );
        assert_eq!(
            low.counter_checkpoint_repairs, 1,
            "raising the offset counts one repair"
        );

        // Checkpoint ABOVE the replay on EVERY recovery-loss value: the snapshot wins everywhere,
        // NEVER lowered, and no repair fires.
        let mut high = Counters {
            records_skipped: replay_records + 5,
            bytes_skipped: replay_bytes + 5,
            last_skip_offset: replay_offset + 5,
            ..Counters::default()
        };
        Engine::<InMemoryFs, ManualClock>::reconcile_skip_loss_counters(
            &mut high, &report, flushed,
        );
        assert_eq!(
            high.last_skip_offset,
            replay_offset + 5,
            "max keeps the larger snapshot (never lowered below #306's bound)"
        );
        assert_eq!(high.records_skipped, replay_records + 5);
        assert_eq!(high.bytes_skipped, replay_bytes + 5);
        assert_eq!(
            high.counter_checkpoint_repairs, 0,
            "no repair when the snapshot already dominates the replay"
        );

        // The CONSUMER-TRUNCATION counter `truncated_records` is DELIBERATELY not reconciled: a
        // snapshot value below any replay survives untouched (no recovery-loss estimate may raise it).
        let mut consumer = Counters {
            truncated_records: 3,
            records_skipped: replay_records + 5,
            bytes_skipped: replay_bytes + 5,
            last_skip_offset: replay_offset + 5,
            ..Counters::default()
        };
        Engine::<InMemoryFs, ManualClock>::reconcile_skip_loss_counters(
            &mut consumer,
            &report,
            flushed,
        );
        assert_eq!(
            consumer.truncated_records, 3,
            "truncated_records is consumer-truncation-derived and is never reconciled from the loss report"
        );
        assert_eq!(
            consumer.counter_checkpoint_repairs, 0,
            "leaving truncated_records alone counts no repair"
        );
    }

    #[test]
    fn reconciliation_does_not_repair_when_the_snapshot_already_dominates() {
        // A clean shutdown that flushed the counters snapshot has skip/loss values at least as high
        // as any replay can imply (the log is intact, so the replay is empty). On reopen the
        // reconciliation is a no-op: nothing is raised and no repair is counted.
        let fs = InMemoryFs::new();
        let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
        for _ in 0..4 {
            produce(&mut e, &[0xab; 16]);
        }
        // A graceful shutdown flush persists the (zero skip/loss) counters snapshot.
        e.checkpoint_all_groups().unwrap();
        drop(e);

        let reopened = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        let c = reopened.counters();
        assert!(
            reopened.loss_report().is_empty(),
            "a clean reopen has an empty loss report"
        );
        assert_eq!(c.bytes_skipped, 0, "no replay to raise the snapshot");
        assert_eq!(c.last_skip_offset, 0);
        assert_eq!(
            c.counter_checkpoint_repairs, 0,
            "a snapshot that dominates the replay counts no repair"
        );
    }

    #[test]
    fn a_missing_loss_report_degrades_to_the_snapshot_value_and_does_not_fail_recovery() {
        // The never-block-recovery contract for the read side (#307): an ABSENT loss report (a clean
        // log, the empty-report degenerate case) must leave the snapshot value standing and must NOT
        // fail recovery. Driven directly so the "snapshot stands, open succeeds" path is unambiguous.
        let snapshot = Counters {
            truncated_records: 42,
            records_skipped: 33,
            bytes_skipped: 1000,
            last_skip_offset: 5,
            counter_checkpoint_repairs: 3,
            ..Counters::default()
        };
        let mut reconciled = snapshot;
        let empty = LossReport::new();
        // An empty (or effectively missing) loss report: replay is all-zeros, so the snapshot stands.
        Engine::<InMemoryFs, ManualClock>::reconcile_skip_loss_counters(
            &mut reconciled,
            &empty,
            99,
        );
        assert_eq!(
            reconciled, snapshot,
            "an empty/missing loss report degrades to the snapshot, raising nothing"
        );

        // And end to end: a torn counters file (decodes to zero) plus an intact log still opens, with
        // the skip/loss family at zero (snapshot zero, replay empty), recovery never failing.
        let fs = InMemoryFs::new();
        {
            let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
            produce(&mut e, &[0xab; 16]);
            e.checkpoint_all_groups().unwrap();
        }
        // Corrupt the counters checkpoint payload so it decodes to all-zeros (a damaged snapshot).
        {
            let cf = fs.open(COUNTERS_CHECKPOINT).unwrap();
            let mut bytes = cf.snapshot();
            for b in bytes.iter_mut().skip(10).take(8) {
                *b ^= 0xff;
            }
            cf.set_len(0).unwrap();
            cf.write_all_at(&bytes, 0).unwrap();
            cf.sync_data().unwrap();
        }
        let reopened = Engine::open(fs, ManualClock::new(), config(10, 5))
            .expect("a corrupt counters file never fails recovery");
        let c = reopened.counters();
        assert_eq!(c.records_skipped, 0);
        assert_eq!(c.bytes_skipped, 0);
        assert_eq!(c.last_skip_offset, 0);
        assert_eq!(c.counter_checkpoint_repairs, 0);
    }

    #[test]
    fn reconciled_skip_loss_counters_never_resume_lower_across_an_arbitrary_crash() {
        // The strict cross-restart MONOTONIC NON-DECREASING property for the RECOVERY-LOSS family
        // (#307), with REAL TEETH: each iteration first establishes a NON-ZERO recovery-loss value in
        // the durable snapshot, then loses a post-snapshot crash the way a `kill -9` would, and proves
        // the reconciled value on reopen is still at least the pre-crash value.
        //
        // The recipe (over a grid of record-count x tear-size crash points, no proptest dependency):
        //   1. Produce records, tear the durable tail, and reopen. Recovery drops the torn tail and
        //      DURABLY truncates the segment (set_len + sync), so the loss report on THIS open is
        //      non-empty and reconciliation raises records_skipped / bytes_skipped / last_skip_offset
        //      above zero.
        //   2. Checkpoint that recovered state: the durable snapshot now holds the NON-ZERO
        //      recovery-loss values. This is `before` (the value at the moment of the next crash).
        //   3. A `kill -9`: drop WITHOUT another flush. Because step 1 already truncated the torn tail
        //      on disk, the log is now CLEAN, so the replay loss report on the next open is EMPTY
        //      (replay == 0, strictly BELOW the non-zero snapshot).
        //   4. Reopen. The reconciliation is max(snapshot, replay) = max(non-zero, 0) = non-zero, so
        //      `after >= before`. Crucially, a `.min()` reconciliation would compute
        //      min(non-zero, 0) == 0 < before and FAIL this test: the assertions are non-trivial.
        let mut exercised = 0u32;
        for records in 2u8..=8 {
            for tear in [1u64, 2, 3, 5, 8, 13] {
                let fs = InMemoryFs::new();
                {
                    let mut e =
                        Engine::open(fs.clone(), ManualClock::new(), config(64, 5)).unwrap();
                    for _ in 0..records {
                        produce(&mut e, &[0xcd; 24]);
                    }
                    drop(e);
                }
                let seg_len = fs.open(&segment_file_name(0)).unwrap().len().unwrap();
                // Only tear within the segment body (never below the header), so the log still opens.
                if tear >= seg_len {
                    continue;
                }
                tear_segment_tail(&fs, tear);

                // Step 1+2: reopen recovers the torn tail (non-empty loss report), reconciliation
                // raises the recovery-loss family above zero, and the checkpoint persists it.
                let before = {
                    let mut e1 =
                        Engine::open(fs.clone(), ManualClock::new(), config(64, 5)).unwrap();
                    let c1 = e1.counters();
                    // The first recovery actually produced a non-zero recovery loss, so the pre-crash
                    // values this test must preserve are genuinely > 0 (not the vacuous `>= 0`).
                    assert!(
                        c1.records_skipped > 0 && c1.bytes_skipped > 0 && c1.last_skip_offset > 0,
                        "the torn tail seeded a non-zero recovery-loss snapshot \
                         (records={records}, tear={tear}): {c1:?}"
                    );
                    e1.checkpoint_all_groups().unwrap();
                    // Step 3 (the `kill -9`): drop WITHOUT another flush. The tail was already
                    // truncated, so the reopened log is clean and the replay drops to zero.
                    c1
                };

                // Step 4: reopen against the now-clean log. The replay loss report is empty.
                let reopened = Engine::open(fs, ManualClock::new(), config(64, 5)).unwrap();
                assert!(
                    reopened.loss_report().is_empty(),
                    "the second reopen sees a clean log: the torn tail was durably truncated \
                     (records={records}, tear={tear})"
                );
                let after = reopened.counters();
                // The replay this open offers is strictly below the snapshot, so a `.min()` would
                // REGRESS every value to 0. The `max` keeps the snapshot: the non-trivial property.
                assert!(
                    after.records_skipped >= before.records_skipped && before.records_skipped > 0,
                    "records_skipped regressed: {} < {} (records={records}, tear={tear}); \
                     a .min() reconciliation would drop it to the empty replay",
                    after.records_skipped,
                    before.records_skipped
                );
                assert!(
                    after.bytes_skipped >= before.bytes_skipped && before.bytes_skipped > 0,
                    "bytes_skipped regressed: {} < {} (records={records}, tear={tear})",
                    after.bytes_skipped,
                    before.bytes_skipped
                );
                assert!(
                    after.last_skip_offset >= before.last_skip_offset
                        && before.last_skip_offset > 0,
                    "last_skip_offset regressed: {} < {} (records={records}, tear={tear})",
                    after.last_skip_offset,
                    before.last_skip_offset
                );
                exercised += 1;
            }
        }
        // The grid must actually exercise the non-zero recovery-loss path (guards against a future
        // refactor making every iteration `continue` and silently re-vacuating the test).
        assert!(
            exercised >= 30,
            "the crash grid exercised too few non-zero recovery-loss crash points: {exercised}"
        );
    }

    #[test]
    fn consumer_truncation_records_keep_only_the_snapshot_lower_bound() {
        // The WEAKER property for the CONSUMER-TRUNCATION counter `truncated_records` (#307): it is a
        // force-reap-driven runtime quantity that is NOT in the durable loss report and NOT
        // replay-derivable, so unlike the recovery-loss family it gets ONLY #306's snapshot-only
        // lower bound, not full cross-restart monotonicity. This test asserts exactly that weaker
        // bound: a value that was produced by the REAL force-reap path and snapshotted survives a
        // clean reopen, and the recovery-loss reconciliation never touches it.
        let one = one_record_bytes();
        let fs = InMemoryFs::new();
        let truncated_before;
        {
            let mut e = Engine::open(
                fs.clone(),
                ManualClock::new(),
                config_disk_full(4 * one, DiskFullPolicy::DropOldest),
            )
            .unwrap();
            // Drive a genuine below-earliest truncation: a stuck consumer leases offset 0, the
            // producer races past the byte cap (force-reaping the stuck consumer's records), then its
            // next poll surfaces the one-time truncation that increments `truncated_records`.
            produce(&mut e, &[0xab; 16]);
            assert!(matches!(e.poll_in("stuck", 0).unwrap(), Poll::Message(_)));
            for _ in 0..20 {
                produce(&mut e, &[0xab; 16]);
            }
            match e.poll_in("stuck", 100).unwrap() {
                Poll::Truncated { .. } => {}
                other => panic!("expected a real consumer truncation, got {other:?}"),
            }
            truncated_before = e.counters().truncated_records;
            assert!(
                truncated_before > 0 && e.counters().truncations == 1,
                "the force-reap path produced a non-zero consumer-truncation count"
            );
            // Flush the snapshot durably, then a CLEAN shutdown (no torn tail): the log stays intact.
            e.checkpoint_all_groups().unwrap();
        }

        // Reopen the same data dir. The log is clean (no recovery loss), so the recovery-loss
        // reconciliation is a no-op and the consumer-truncation count is preserved by the #306
        // snapshot lower bound alone, NOT reconciled or raised from any loss report.
        let reopened = Engine::open(
            fs,
            ManualClock::new(),
            config_disk_full(4 * one, DiskFullPolicy::DropOldest),
        )
        .unwrap();
        let after = reopened.counters();
        assert!(
            reopened.loss_report().is_empty(),
            "a clean reopen has no recovery loss to reconcile against"
        );
        assert_eq!(
            after.truncated_records, truncated_before,
            "the snapshot lower bound preserves the consumer-truncation count across a clean reopen"
        );
        assert_eq!(
            after.truncations, 1,
            "the truncation EVENT count keeps the same snapshot-only lower bound"
        );
        // The recovery-loss family stayed at zero and no repair fired: the consumer-truncation count
        // is deliberately outside the reconciliation.
        assert_eq!(after.records_skipped, 0, "no recovery loss to reconcile");
        assert_eq!(after.counter_checkpoint_repairs, 0);
    }

    #[test]
    fn maybe_checkpoint_bounds_replay_and_reopen_resumes() {
        // interval = 2: a single ack does not reach the threshold (reopen would redeliver),
        // but the second ack does and persists the cursor, so reopen resumes past both. This
        // is the bounded-replay-window contract.
        let mut c = config(10, 5);
        c.checkpoint_interval = 2;
        let mut e = open(c);
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token);
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert!(
            !e.maybe_checkpoint().unwrap(),
            "1 < interval 2: no checkpoint yet"
        );

        let d1 = message(e.poll(0).unwrap());
        e.ack(&d1.token);
        assert_eq!(e.committed_offset(), Offset::new(2));
        assert!(
            e.maybe_checkpoint().unwrap(),
            "2 >= interval 2: checkpoints"
        );

        let fs = e.into_filesystem();
        let mut c2 = config(10, 5);
        c2.checkpoint_interval = 2;
        let mut e = Engine::open(fs, ManualClock::new(), c2).unwrap();
        // The checkpoint persisted committed = 2, so only the uncommitted tail (c) redelivers.
        assert_eq!(e.committed_offset(), Offset::new(2));
        let mut delivered = Vec::new();
        while let Poll::Message(d) = e.poll(0).unwrap() {
            delivered.push(d.offset.get());
        }
        assert_eq!(
            delivered,
            vec![2],
            "only the uncheckpointed tail redelivers"
        );
    }

    #[test]
    fn a_freezing_produce_is_fatal_and_marks_the_engine_unhealthy() {
        use ironbus_storage::fault::FaultFs;
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        let msg = |payload: &'static [u8]| Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        };
        // A first produce is durable (its fsync succeeds) and the engine is healthy.
        assert_eq!(e.produce(&msg(b"a")).unwrap(), Offset::new(0));
        assert!(e.is_healthy());

        // Arm a fatal fsync: the next produce appends, but its sync freezes the writer, so
        // produce returns a FATAL error. The session layer turns a fatal produce error into
        // an EngineFatal that ends the connection rather than a soft "produce failed", which
        // is exactly why the freeze must surface as fatal here and not a transient IO error.
        control.set_fail_sync(true);
        let err = e.produce(&msg(b"b")).unwrap_err();
        assert!(
            err.is_fatal(),
            "a freezing produce must be fatal so the session ends, got {err:?}"
        );
        assert!(matches!(
            err,
            EngineError::Storage(StorageError::WriterFrozen)
        ));

        // The engine now reports unhealthy (the /readyz 503 signal) and stays fatal forever.
        assert!(!e.is_healthy());
        assert!(e.produce(&msg(b"c")).unwrap_err().is_fatal());
    }

    /// An engine config with a hard durable-log byte cap (`max_total_bytes`), every other knob
    /// the default test config.
    fn config_with_total_cap(max_total_bytes: u64) -> EngineConfig {
        let mut cfg = config(10, 5);
        cfg.log = cfg.log.with_max_total_bytes(max_total_bytes);
        cfg
    }

    #[test]
    fn an_over_cap_produce_is_rejected_counts_and_advances_nothing() {
        // Size the cap to hold exactly two records: produce two (they fit), then the third is
        // rejected with the non-fatal AtCapacity, the rejection counter increments, and the
        // produce statistics and the durable head do not move.
        let payload = b"hello";
        // Measure one record's framed durable bytes on a throwaway engine, so the cap is exact.
        let one = {
            let mut probe = open(config(10, 5));
            produce(&mut probe, payload);
            probe.durable_record_bytes()
        };

        let mut e = open(config_with_total_cap(2 * one));
        assert_eq!(produce(&mut e, payload), Offset::new(0));
        assert_eq!(produce(&mut e, payload), Offset::new(1));
        let before = e.counters();
        assert_eq!(before.produced, 2);
        assert_eq!(before.produce_rejected, 0);
        let flushed_before = e.flushed_offset();
        let bytes_before = e.durable_record_bytes();

        // The third produce is at the cap: rejected, non-fatal, nothing advances.
        let err = e
            .produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            })
            .unwrap_err();
        assert!(err.is_at_capacity(), "got {err:?}");
        assert!(!err.is_fatal(), "the shed is never fatal");
        assert!(e.is_healthy(), "the writer stays live after a shed");

        let after = e.counters();
        assert_eq!(after.produce_rejected, 1, "the rejection is counted");
        assert_eq!(after.produced, before.produced, "produced did not move");
        assert_eq!(
            after.produced_bytes, before.produced_bytes,
            "produced_bytes did not move"
        );
        assert_eq!(
            e.flushed_offset(),
            flushed_before,
            "the durable head did not advance"
        );
        assert_eq!(
            e.durable_record_bytes(),
            bytes_before,
            "nothing was written"
        );

        // The writer never froze: a second over-cap produce is still a counted shed (not a
        // WriterFrozen), proving the rejection is repeatable and non-terminal.
        let err2 = e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        });
        assert!(
            matches!(err2, Err(ref e) if e.is_at_capacity()),
            "got {err2:?}"
        );
        assert_eq!(e.counters().produce_rejected, 2);
    }

    #[test]
    fn under_cap_produces_all_succeed_and_are_counted() {
        // With a generous cap every produce succeeds and is counted normally, and no rejection
        // is recorded: the cap is a backstop, not a tax on the happy path.
        let mut e = open(config_with_total_cap(1 << 20));
        for i in 0..5u8 {
            assert_eq!(produce(&mut e, &[i]), Offset::new(u64::from(i)));
        }
        let c = e.counters();
        assert_eq!(c.produced, 5);
        assert_eq!(c.produce_rejected, 0);
        assert_eq!(e.flushed_offset(), Offset::new(5));
    }

    /// An engine config with a small segment cap (so produces roll across many segments) plus a
    /// consumer-safe size-retention bound. Every other knob is the default test config.
    fn config_with_retention(max_retained_bytes: u64) -> EngineConfig {
        let mut cfg = config(64, 5);
        // A small segment cap so a handful of records roll: retention reaps whole sealed segments.
        cfg.log = LogConfig {
            max_segment_bytes: 160,
            max_total_bytes: 0,
            ..LogConfig::default()
        };
        cfg.max_retained_bytes = max_retained_bytes;
        cfg
    }

    // Produces `n` 16-byte records, interleaving a full drain-and-ack after each produce so the
    // default group's committed cursor tracks the head as the log grows. Retention runs on the
    // produce path against the MIN committed offset across groups, so the cursor must advance
    // alongside the produces (a streaming workload) for old segments to become reapable; this
    // models exactly that.
    fn produce_and_consume_all(e: &mut Engine<InMemoryFs, ManualClock>, n: usize) {
        let mut now = 0u64;
        for _ in 0..n {
            produce(e, &[0xab; 16]);
            loop {
                match e.poll(now).unwrap() {
                    Poll::Message(d) => {
                        assert_eq!(e.ack(&d.token), AckResult::Acked);
                    }
                    Poll::Parked { .. } => {}
                    Poll::Truncated { .. } => panic!("unexpected truncation"),
                    Poll::Idle => break,
                }
                now += 1;
            }
        }
    }

    #[test]
    fn default_unlimited_retention_reaps_nothing() {
        // The default config (max_retained_bytes == 0) never reaps: a fully consumed multi-segment
        // log keeps every segment, exactly the historical behavior.
        let mut e = open(config_with_retention(0));
        produce_and_consume_all(&mut e, 24);
        assert_eq!(e.committed_offset(), Offset::new(24));
        let bytes = e.durable_record_bytes();
        // Produce more (all consumed): still nothing reaped.
        produce_and_consume_all(&mut e, 8);
        assert_eq!(
            e.counters().segments_reaped,
            0,
            "retention off reaps nothing"
        );
        assert!(e.durable_record_bytes() > bytes, "the log only grows");
    }

    #[test]
    fn retention_reclaims_old_consumed_segments_as_the_log_grows() {
        // With a retention bound set and every group caught up, producing past the bound reaps old
        // fully-consumed segments: the durable record bytes drop and segments_reaped increments.
        let mut e = open(config_with_retention(0)); // measure one record's bytes first
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        // A bound of ~4 records: once the consumed log exceeds it, the reaper trims it back.
        let mut e = open(config_with_retention(4 * one));
        produce_and_consume_all(&mut e, 30);
        assert_eq!(e.committed_offset(), Offset::new(30), "all consumed");
        assert!(
            e.counters().segments_reaped >= 1,
            "producing past the bound reclaimed at least one segment"
        );
        assert!(
            e.durable_record_bytes() <= 4 * one,
            "the live durable bytes dropped to or under the bound: {} <= {}",
            e.durable_record_bytes(),
            4 * one
        );
        // The head is unchanged (reaping deletes old records, never the head) and the surviving
        // tail is still consumable from the committed offset (here, the head: all acked).
        assert_eq!(e.flushed_offset(), Offset::new(30));
    }

    #[test]
    fn a_slow_group_prevents_reaping_the_segments_it_still_needs() {
        // The protect floor is the MINIMUM committed offset across groups. A slow group stuck near
        // offset 0 pins the floor low, so no segment below its cursor is reaped even far over the
        // bound. This is the consumer-safety guarantee.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();
        let mut e = open(config_with_retention(2 * one));

        // The slow group "slow" leases offset 0 but never acks: its committed stays 0.
        produce(&mut e, &[0xab; 16]);
        assert!(matches!(e.poll_in("slow", 0).unwrap(), Poll::Message(_)));
        assert_eq!(e.committed_offset_in("slow"), Offset::new(0));

        // Now produce and fully consume many more in the DEFAULT group, far over the bound.
        produce_and_consume_all(&mut e, 30);
        assert_eq!(e.committed_offset(), Offset::new(31), "default caught up");
        // The slow group is still at 0, so the min committed across groups is 0: nothing below it
        // may be reaped, so NO segment is deleted even though the log is well over the bound.
        assert_eq!(e.committed_offset_in("slow"), Offset::new(0));
        assert_eq!(
            e.counters().segments_reaped,
            0,
            "a slow group pins the protect floor at 0, so nothing is reaped"
        );
        // Offset 0 (the slow group still needs it) is still readable: the record was not reaped.
        assert!(matches!(
            e.poll_now_in("slow"),
            Ok(Poll::Idle | Poll::Message(_))
        ));
    }

    #[test]
    fn retention_advances_once_the_slow_group_catches_up() {
        // Once the slowest group catches up, the protect floor rises and the next produce reaps
        // the now-fully-consumed old segments. This pins that the protection is dynamic, not a
        // permanent block.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();
        let mut e = open(config_with_retention(2 * one));

        // Build a slow group pinned at 0, produce/consume many in the default group: nothing reaps.
        produce(&mut e, &[0xab; 16]);
        let slow_d = match e.poll_in("slow", 0).unwrap() {
            Poll::Message(d) => d,
            other => panic!("expected a message, got {other:?}"),
        };
        produce_and_consume_all(&mut e, 24);
        assert_eq!(e.counters().segments_reaped, 0, "blocked by the slow group");

        // The slow group acks offset 0 and drains to the head: the floor rises to the head.
        assert_eq!(e.ack_in("slow", &slow_d.token), AckResult::Acked);
        let mut now = 100u64;
        while let Poll::Message(d) = e.poll_in("slow", now).unwrap() {
            assert_eq!(e.ack_in("slow", &d.token), AckResult::Acked);
            now += 1;
        }
        // One more produce now that every group is caught up: the reaper runs and frees space.
        produce_and_consume_all(&mut e, 1);
        assert!(
            e.counters().segments_reaped >= 1,
            "once the slow group caught up the old segments are reaped"
        );
    }

    // ---- Count- and age-based retention end to end (refs #13, #80) ----

    // The small-segment config but with the COUNT bound set (size and age off).
    fn config_with_count(max_messages: u64) -> EngineConfig {
        let mut cfg = config_with_retention(0);
        cfg.max_messages = max_messages;
        cfg
    }

    #[test]
    fn count_retention_reclaims_old_consumed_segments() {
        // With max_messages set and every group caught up, producing past it reaps old
        // fully-consumed segments: the durable record count drops to or under the bound and
        // segments_reaped increments.
        let mut e = open(config_with_count(8));
        produce_and_consume_all(&mut e, 40);
        assert_eq!(e.committed_offset(), Offset::new(40), "all consumed");
        assert!(
            e.counters().segments_reaped >= 1,
            "producing past the count bound reclaimed at least one segment"
        );
        assert!(
            e.durable_record_count() <= 8,
            "the live record count dropped to or under the bound: {} <= 8",
            e.durable_record_count()
        );
        // The head is unchanged: reaping deletes old records, never the head.
        assert_eq!(e.flushed_offset(), Offset::new(40));
    }

    #[test]
    fn count_retention_blocks_on_a_slow_group_then_unblocks() {
        // A slow group pinned at offset 0 blocks count-based reaping below its cursor, then once it
        // catches up the next produce reaps. This pins consumer-safety for the count bound.
        let mut e = open(config_with_count(4));
        // The slow group leases offset 0 but never acks: its committed stays 0.
        produce(&mut e, &[0xab; 16]);
        let slow_d = match e.poll_in("slow", 0).unwrap() {
            Poll::Message(d) => d,
            other => panic!("expected a message, got {other:?}"),
        };
        produce_and_consume_all(&mut e, 30);
        assert_eq!(
            e.counters().segments_reaped,
            0,
            "the slow group at 0 blocks count-based reaping"
        );

        // The slow group catches up: the floor rises and the next produce reaps.
        assert_eq!(e.ack_in("slow", &slow_d.token), AckResult::Acked);
        let mut now = 100u64;
        while let Poll::Message(d) = e.poll_in("slow", now).unwrap() {
            assert_eq!(e.ack_in("slow", &d.token), AckResult::Acked);
            now += 1;
        }
        produce_and_consume_all(&mut e, 1);
        assert!(
            e.counters().segments_reaped >= 1,
            "once the slow group caught up the count bound reaps"
        );
    }

    #[test]
    fn age_retention_reclaims_old_consumed_segments_as_the_clock_advances() {
        // End to end over the engine's clock seam: records produced at an OLD timestamp become
        // age-eligible once the engine clock advances past now - max_age, and the produce path
        // reaps them. Uses a shared ManualClock so the test drives `now`, never the host clock.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut cfg = config_with_retention(0);
        cfg.max_age_ms = 1_000;
        let mut e = open_with_clock(cfg, std::sync::Arc::clone(&clock));

        // Produce and fully consume many records stamped at timestamp 100 (old). The engine clock
        // is still 0, so now - max_age underflows to "nothing is old enough": no reap yet.
        let mut lease_now = 0u64;
        for _ in 0..40 {
            e.produce(&Append {
                timestamp_ms: 100,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[0xab; 16],
            })
            .unwrap();
            loop {
                match e.poll(lease_now).unwrap() {
                    Poll::Message(d) => assert_eq!(e.ack(&d.token), AckResult::Acked),
                    Poll::Parked { .. } => {}
                    Poll::Truncated { .. } => panic!("unexpected truncation"),
                    Poll::Idle => break,
                }
                lease_now += 1;
            }
        }
        assert_eq!(
            e.counters().segments_reaped,
            0,
            "nothing is aged out while the engine clock is at 0"
        );

        // Advance the wall clock well past the records' age, then produce once more: every
        // fully-consumed old segment is now older than now - max_age and is reaped.
        clock.set_unix_millis(1_000_000);
        e.produce(&Append {
            timestamp_ms: 1_000_000,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &[0xab; 16],
        })
        .unwrap();
        // Drain so the cursor stays caught up for the next pass and the protect floor is the head.
        while let Poll::Message(d) = e.poll(lease_now).unwrap() {
            assert_eq!(e.ack(&d.token), AckResult::Acked);
            lease_now += 1;
        }
        assert!(
            e.counters().segments_reaped >= 1,
            "advancing the engine clock past the age bound reaps the old segments"
        );
    }

    #[test]
    fn age_retention_blocks_on_a_slow_group() {
        // A slow group still blocks reaping below its cursor under the AGE bound, exactly as under
        // size: consumer-safety gates every bound.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut cfg = config_with_retention(0);
        cfg.max_age_ms = 1_000;
        let mut e = open_with_clock(cfg, std::sync::Arc::clone(&clock));

        // The slow group leases offset 0 but never acks.
        e.produce(&Append {
            timestamp_ms: 100,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &[0xab; 16],
        })
        .unwrap();
        assert!(matches!(e.poll_in("slow", 0).unwrap(), Poll::Message(_)));

        // Produce and fully consume many more in the default group, then advance the clock far past
        // the age bound. Everything is old, but the slow group pins the floor at 0.
        let mut lease_now = 0u64;
        for _ in 0..30 {
            e.produce(&Append {
                timestamp_ms: 100,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[0xab; 16],
            })
            .unwrap();
            while let Poll::Message(d) = e.poll(lease_now).unwrap() {
                assert_eq!(e.ack(&d.token), AckResult::Acked);
                lease_now += 1;
            }
        }
        clock.set_unix_millis(1_000_000);
        e.produce(&Append {
            timestamp_ms: 1_000_000,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &[0xab; 16],
        })
        .unwrap();
        assert_eq!(
            e.counters().segments_reaped,
            0,
            "a slow group blocks age-based reaping below its cursor"
        );
        assert_eq!(e.committed_offset_in("slow"), Offset::new(0));
    }

    // ---- Disk-full drop-oldest policy + below-earliest truncation tests (refs #82, #84) ----

    /// An engine config with a small segment cap (so a handful of records roll across segments), a
    /// durable-log byte cap, and an explicit disk-full overflow policy. Every other knob is the
    /// default test config.
    fn config_disk_full(max_total_bytes: u64, policy: DiskFullPolicy) -> EngineConfig {
        let mut cfg = config(64, 5);
        cfg.log = LogConfig {
            // A small segment cap so ~6 16-byte records roll: the cap then spans several segments.
            max_segment_bytes: 160,
            max_total_bytes,
            ..LogConfig::default()
        };
        cfg.disk_full_policy = policy;
        cfg
    }

    // The framed durable bytes of one 16-byte record, measured on a throwaway engine so a byte cap
    // can be sized exactly in record units.
    fn one_record_bytes() -> u64 {
        let mut probe = open(config(10, 5));
        produce(&mut probe, &[0xab; 16]);
        probe.durable_record_bytes()
    }

    #[test]
    fn drop_oldest_force_reaps_a_stuck_consumer_and_accepts_the_produce() {
        // A STUCK consumer leases offset 0 but never acks, so its committed stays 0 and the
        // consumer-safe reaper can never reclaim segment 0. Under DropOldest, producing past the
        // byte cap FORCE-reaps the stuck consumer's old segments (its earliest data is gone), the
        // force counter increments, and the produce SUCCEEDS (not rejected).
        let one = one_record_bytes();
        // A cap of ~4 records: once the log exceeds it, a further produce must reclaim space.
        let mut e = open(config_disk_full(4 * one, DiskFullPolicy::DropOldest));

        // The stuck consumer leases offset 0 and never acks.
        produce(&mut e, &[0xab; 16]);
        assert!(matches!(e.poll_in("stuck", 0).unwrap(), Poll::Message(_)));
        assert_eq!(e.committed_offset_in("stuck"), Offset::new(0));

        // A fast producer fills well past the cap. Every produce SUCCEEDS (never rejected),
        // because DropOldest force-reaps to make room rather than shedding.
        for _ in 0..20 {
            e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[0xab; 16],
            })
            .expect("drop-oldest accepts the produce");
        }
        assert_eq!(e.flushed_offset(), Offset::new(21), "every produce landed");
        assert_eq!(
            e.counters().produce_rejected,
            0,
            "drop-oldest never sheds while it can force-reap"
        );
        assert!(
            e.counters().segments_force_reaped >= 1,
            "the stuck consumer's old segments were force-reaped"
        );
        // The stuck consumer's earliest data (offset 0) is gone: the log no longer starts at 0.
        assert!(
            e.earliest_retained_offset().get() > 0,
            "the oldest retained offset rose above the stuck consumer's cursor"
        );
        // The live durable bytes are held near the cap (force-reaping kept it bounded).
        assert!(
            e.durable_record_bytes() <= 5 * one,
            "the log stays near the cap, not unbounded: {} <= {}",
            e.durable_record_bytes(),
            5 * one
        );
    }

    #[test]
    fn drop_new_rejects_the_same_scenario_and_reaps_nothing() {
        // The DEFAULT DropNew policy, same stuck-consumer scenario: producing past the cap is
        // REJECTED (the drop-new shed), nothing is force-reaped, and the stuck consumer's earliest
        // data is PRESERVED (the oldest retained offset stays 0).
        let one = one_record_bytes();
        let mut e = open(config_disk_full(4 * one, DiskFullPolicy::DropNew));

        produce(&mut e, &[0xab; 16]);
        assert!(matches!(e.poll_in("stuck", 0).unwrap(), Poll::Message(_)));

        // Produce until the first rejection.
        let mut rejected = false;
        for _ in 0..20 {
            match e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[0xab; 16],
            }) {
                Ok(_) => {}
                Err(err) => {
                    assert!(err.is_at_capacity(), "the rejection is the shed: {err:?}");
                    rejected = true;
                    break;
                }
            }
        }
        assert!(rejected, "drop-new sheds once the cap is hit");
        assert_eq!(
            e.counters().segments_force_reaped,
            0,
            "drop-new never force-reaps"
        );
        assert_eq!(
            e.earliest_retained_offset(),
            Offset::ZERO,
            "the stuck consumer's earliest data is preserved under drop-new"
        );
        // Offset 0 is still readable for the stuck consumer (its record was not reaped).
        assert!(matches!(
            e.poll_now_in("stuck"),
            Ok(Poll::Idle | Poll::Message(_))
        ));
    }

    #[test]
    fn a_truncated_consumer_gets_exactly_one_truncation_then_delivers() {
        // After DropOldest force-reaps a stuck consumer's records, its NEXT poll returns a
        // truncation (resetting its cursor to earliest_retained), then delivers from there. A
        // SECOND poll does NOT re-truncate the same gap.
        let one = one_record_bytes();
        let mut e = open(config_disk_full(4 * one, DiskFullPolicy::DropOldest));

        // The stuck consumer leases offset 0 (committed 0), then the producer races past the cap.
        produce(&mut e, &[0xab; 16]);
        assert!(matches!(e.poll_in("stuck", 0).unwrap(), Poll::Message(_)));
        for _ in 0..20 {
            e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[0xab; 16],
            })
            .unwrap();
        }
        let earliest = e.earliest_retained_offset();
        assert!(earliest.get() > 0, "the stuck consumer's data was reaped");

        // No truncation has been surfaced yet, so the skip counters are zero (#96).
        assert_eq!(e.counters().truncations, 0);
        assert_eq!(e.counters().truncated_records, 0);

        // The stuck consumer's NEXT poll is a truncation, resetting to earliest_retained.
        let now = 100;
        match e.poll_in("stuck", now).unwrap() {
            Poll::Truncated {
                earliest_retained,
                skipped,
            } => {
                assert_eq!(earliest_retained, earliest, "reset to earliest retained");
                assert_eq!(skipped, earliest.get(), "skipped the whole reaped span");
            }
            other => panic!("expected a truncation, got {other:?}"),
        }
        // The cursor is now at earliest_retained.
        assert_eq!(e.committed_offset_in("stuck"), earliest);
        // Exactly one truncation event was counted, spanning the whole reaped span (#96): the skip
        // is never silent.
        assert_eq!(e.counters().truncations, 1, "one truncation event counted");
        assert_eq!(
            e.counters().truncated_records,
            earliest.get(),
            "the records counter equals the skipped span"
        );

        // The NEXT poll delivers normally from earliest_retained, NOT another truncation.
        match e.poll_in("stuck", now).unwrap() {
            Poll::Message(d) => assert_eq!(d.offset, earliest, "resumes at the oldest record"),
            other => panic!("expected a delivery after the reset, got {other:?}"),
        }

        // Drain a few more; none re-truncates the same gap (the reset moved the cursor up to it).
        for _ in 0..3 {
            match e.poll_in("stuck", now).unwrap() {
                Poll::Message(d) => assert_eq!(e.ack_in("stuck", &d.token), AckResult::Acked),
                Poll::Idle => break,
                Poll::Truncated { .. } => panic!("must not re-truncate the same gap"),
                Poll::Parked { .. } => {}
            }
        }
        // The same gap never re-counts: the skip counter stays at one event (#96).
        assert_eq!(
            e.counters().truncations,
            1,
            "the same gap is not re-counted"
        );
    }

    #[test]
    fn a_caught_up_consumer_never_sees_a_truncation() {
        // A consumer that stays caught up (acking as it goes) keeps its committed at the head, which
        // never falls below the oldest retained offset, so force-reaping never truncates it.
        let one = one_record_bytes();
        let mut e = open(config_disk_full(4 * one, DiskFullPolicy::DropOldest));

        let mut now = 0u64;
        for _ in 0..30 {
            e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[0xab; 16],
            })
            .unwrap();
            // Drain and ack everything available: the consumer stays caught up to the head.
            loop {
                match e.poll(now).unwrap() {
                    Poll::Message(d) => {
                        assert_eq!(e.ack(&d.token), AckResult::Acked);
                    }
                    Poll::Truncated { .. } => panic!("a caught-up consumer is never truncated"),
                    Poll::Parked { .. } => {}
                    Poll::Idle => break,
                }
                now += 1;
            }
        }
        assert_eq!(
            e.committed_offset(),
            e.flushed_offset(),
            "the caught-up consumer is at the head"
        );
    }

    #[test]
    fn drop_oldest_with_only_the_active_segment_falls_back_to_drop_new() {
        // The wedge guard: if a single in-flight set fills the log so only the ACTIVE segment is
        // over cap (nothing sealed to force out), DropOldest falls back to the drop-new rejection
        // rather than wedging the log empty. A tiny cap with a large segment cap (no rolling) hits
        // this: the first record is on an empty log (always written), the second is over the cap
        // with only the active segment present, so it sheds.
        let one = one_record_bytes();
        let mut cfg = config(10, 5);
        // A large segment cap so NOTHING rolls: there is only ever the single active segment.
        cfg.log = LogConfig::default().with_max_total_bytes(one); // cap = one record
        cfg.disk_full_policy = DiskFullPolicy::DropOldest;
        let mut e = open(cfg);

        // First record on the empty log is always written (the empty-log carve-out).
        assert_eq!(produce(&mut e, &[0xab; 16]), Offset::new(0));
        // The log is now at the cap with only the active segment: the next produce cannot
        // force-reap (no sealed predecessor), so DropOldest falls back to the drop-new shed.
        let err = e
            .produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[0xab; 16],
            })
            .unwrap_err();
        assert!(
            err.is_at_capacity(),
            "wedge guard falls back to drop-new: {err:?}"
        );
        assert_eq!(
            e.counters().produce_rejected,
            1,
            "the fall-back shed is counted"
        );
        assert_eq!(
            e.counters().segments_force_reaped,
            0,
            "nothing could be force-reaped"
        );
        assert!(
            e.is_healthy(),
            "the writer stays live (the shed is non-fatal)"
        );
    }

    // ----- The durable dead-letter (DLQ) sink and the crash-atomic, exactly-once move (#63) -----

    use ironbus_storage::dlq::{read_dlq_entries, DlqEntry, DLQ_SUBDIR};

    /// Produces one poison message, drives it past `max_deliver` (1) so the next poll dead-letters
    /// it, and returns the engine (the poison is now parked). Uses an `Arc<ManualClock>` the caller
    /// drives so a redelivery's visibility window can expire deterministically.
    fn poison_once<F: Filesystem>(
        e: &mut Engine<F, std::sync::Arc<ManualClock>>,
        clock: &std::sync::Arc<ManualClock>,
        payload: &[u8],
    ) -> Offset {
        let off = e
            .produce(&Append {
                timestamp_ms: 42,
                flags: RecordFlags::EMPTY,
                key: b"poison-key",
                headers: b"poison-hdr",
                payload,
            })
            .unwrap();
        // First delivery (attempt 1, within max_deliver = 1).
        let _ = message(e.poll_now().unwrap());
        // Expire the lease, then re-poll: attempt 2 exceeds max_deliver and is dead-lettered.
        clock.advance_monotonic_nanos(40);
        match e.poll_now().unwrap() {
            Poll::Parked { offset, .. } => assert_eq!(offset, off),
            other => panic!("expected Parked, got {other:?}"),
        }
        off
    }

    #[test]
    fn a_poisoned_message_is_durably_written_to_the_dlq_and_committed_past() {
        let clock = std::sync::Arc::new(ManualClock::new());
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 1)).unwrap();
        let off = poison_once(&mut e, &clock, b"the-poison-payload");

        // The source group committed PAST the poison (it never redelivers).
        assert_eq!(e.committed_offset(), Offset::new(off.get() + 1));
        assert!(matches!(e.poll_now().unwrap(), Poll::Idle));
        assert_eq!(e.counters().dead_lettered, 1);
        assert_eq!(e.dlq_records(), 1, "one record in the DLQ depth");
        drop(e);

        // Reopen the data directory: the DLQ sink holds the poison record with the ORIGINAL
        // timestamp, the source group, the source offset, and the attempt it was poisoned at.
        let entries = read_dlq_entries(&probe).unwrap();
        assert_eq!(entries.len(), 1);
        let DlqEntry {
            group,
            source_offset,
            attempt,
            timestamp_ms,
            key,
            headers,
            payload,
            ..
        } = &entries[0];
        assert_eq!(group, "", "the default group");
        assert_eq!(*source_offset, off.get());
        assert_eq!(
            *attempt, 2,
            "poisoned on the 2nd attempt (over max_deliver 1)"
        );
        assert_eq!(
            *timestamp_ms, 42,
            "the original enqueue timestamp is preserved"
        );
        assert_eq!(key, b"poison-key");
        assert_eq!(headers, b"poison-hdr");
        assert_eq!(payload, b"the-poison-payload");
    }

    #[test]
    fn the_no_poison_path_never_creates_or_touches_the_dlq() {
        // A normal produce / poll / ack lifecycle must never materialize the dlq/ subdirectory.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        for _ in 0..3 {
            let d = message(e.poll(0).unwrap());
            e.ack(&d.token);
        }
        assert_eq!(e.dlq_records(), 0, "no DLQ records without poison");
        let fs = e.into_filesystem();
        // The subdir was never created, and an offline DLQ read shows nothing.
        assert!(
            !fs.subdir_exists(DLQ_SUBDIR).unwrap(),
            "the dlq/ subdir must not exist on the no-poison path"
        );
        assert!(read_dlq_entries(&fs).unwrap().is_empty());
    }

    #[test]
    fn re_poisoning_the_same_offset_does_not_double_write() {
        // Idempotency at the API level: dead-lettering the SAME (group, offset) twice (e.g. a
        // forced re-evaluation) writes exactly one DLQ record. We drive a second dead-letter of an
        // offset already at the group's high-water mark by re-invoking the internal move directly.
        let clock = std::sync::Arc::new(ManualClock::new());
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 1)).unwrap();
        let off = poison_once(&mut e, &clock, b"p");
        assert_eq!(e.dlq_records(), 1);

        // Read the source record back and re-run the dead-letter move for the SAME (group, offset,
        // attempt). The high-water mark already covers `off`, so no second DLQ write happens.
        let record = e.log.read_from(off, 1).unwrap().into_iter().next().unwrap();
        let poll = e.dead_letter_in("", off, 2, record).unwrap();
        assert!(matches!(poll, Poll::Parked { .. }));
        assert_eq!(
            e.dlq_records(),
            1,
            "re-poison is idempotent: still one record"
        );
        drop(e);
        assert_eq!(read_dlq_entries(&probe).unwrap().len(), 1);
    }

    #[test]
    fn a_crash_between_the_dlq_append_and_the_source_commit_yields_exactly_one_dlq_entry() {
        use ironbus_storage::fault::FaultFs;
        // The crash window: the DLQ append+fsync is durable, but the source-cursor commit's
        // durability has NOT yet landed (it is only in memory, the checkpoint interval is high).
        // A power loss reverts the un-checkpointed source cursor (the poison redelivers) while the
        // fsynced DLQ record survives. On reopen the per-group high-water mark, rebuilt from the
        // durable DLQ, suppresses the duplicate append: EXACTLY ONE DLQ entry, and no loss.
        let clock = std::sync::Arc::new(ManualClock::new());
        let (faultfs, _control) = FaultFs::new(InMemoryFs::new());
        // Keep a probe to the underlying in-memory disk to drive the power loss and read the DLQ.
        let probe = faultfs.inner().clone();
        // checkpoint_interval high so the dead-letter park's cursor advance is NOT checkpointed,
        // modeling the crash landing before the source commit becomes durable.
        let mut cfg = config(10, 1);
        cfg.checkpoint_interval = 1_000_000;
        let mut e = Engine::open(faultfs, std::sync::Arc::clone(&clock), cfg.clone()).unwrap();
        let off = poison_once(&mut e, &clock, b"poison");
        assert_eq!(
            e.dlq_records(),
            1,
            "the poison is in the DLQ before the crash"
        );
        // In memory the source committed past, but that advance was never checkpointed.
        assert_eq!(e.committed_offset(), Offset::new(off.get() + 1));
        drop(e);

        // CRASH: power loss reverts everything not yet durable. The DLQ record was fsynced (durable);
        // the source cursor checkpoint still reflects the pre-poison committed offset.
        probe.simulate_power_loss();

        // RECOVER: reopen over the surviving disk. The source poison redelivers (its commit was
        // lost), is re-poisoned, and is committed-past WITHOUT a duplicate DLQ write.
        let clock2 = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(probe.clone(), std::sync::Arc::clone(&clock2), cfg).unwrap();
        // The DLQ depth recovered from the durable sink is one (it survived the crash).
        assert_eq!(e.dlq_records(), 1, "the DLQ entry survived the crash");
        // The source cursor lost its un-checkpointed advance, so the poison is uncommitted again.
        assert_eq!(
            e.committed_offset(),
            Offset::ZERO,
            "the source commit was lost"
        );
        // Re-poison it: first delivery, expire, then dead-letter again. This time the move must be
        // a no-op append (already in the DLQ) and only commit past.
        let _ = message(e.poll_now().unwrap());
        clock2.advance_monotonic_nanos(40);
        assert!(matches!(e.poll_now().unwrap(), Poll::Parked { .. }));
        // EXACTLY ONCE: still one DLQ record (no duplicate), and the source is now committed-past.
        assert_eq!(
            e.dlq_records(),
            1,
            "no duplicate DLQ write after the crash-redelivery"
        );
        assert_eq!(e.committed_offset(), Offset::new(off.get() + 1));
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "no loss, no re-loop"
        );
        drop(e);

        // The durable sink, read offline, has EXACTLY ONE entry for (group "", offset, attempt).
        let entries = read_dlq_entries(&probe).unwrap();
        assert_eq!(entries.len(), 1, "exactly one DLQ entry across the crash");
        assert_eq!(entries[0].source_offset, off.get());
        assert_eq!(entries[0].group, "");
    }

    #[test]
    fn a_second_crash_redelivery_still_adds_no_duplicate() {
        use ironbus_storage::fault::FaultFs;
        // Two successive crash-then-redeliver cycles must still leave exactly one DLQ entry: the
        // idempotency key holds across repeated re-poisoning, not just the first.
        let clock = std::sync::Arc::new(ManualClock::new());
        let (faultfs, _control) = FaultFs::new(InMemoryFs::new());
        let probe = faultfs.inner().clone();
        let mut cfg = config(10, 1);
        cfg.checkpoint_interval = 1_000_000;
        let mut e = Engine::open(faultfs, std::sync::Arc::clone(&clock), cfg.clone()).unwrap();
        let _off = poison_once(&mut e, &clock, b"poison");
        drop(e);

        for round in 0..2 {
            probe.simulate_power_loss();
            let clk = std::sync::Arc::new(ManualClock::new());
            let mut e =
                Engine::open(probe.clone(), std::sync::Arc::clone(&clk), cfg.clone()).unwrap();
            assert_eq!(
                e.committed_offset(),
                Offset::ZERO,
                "round {round}: poison uncommitted"
            );
            let _ = message(e.poll_now().unwrap());
            clk.advance_monotonic_nanos(40);
            assert!(matches!(e.poll_now().unwrap(), Poll::Parked { .. }));
            assert_eq!(e.dlq_records(), 1, "round {round}: still one DLQ record");
            drop(e);
        }
        assert_eq!(
            read_dlq_entries(&probe).unwrap().len(),
            1,
            "exactly one across two crashes"
        );
    }

    // ---- key_shared routing (#64) ----

    /// Produces a record with an explicit key, for the `key_shared` tests.
    fn produce_keyed(
        e: &mut Engine<InMemoryFs, ManualClock>,
        key: &[u8],
        payload: &[u8],
    ) -> Offset {
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key,
            headers: b"",
            payload,
        })
        .unwrap()
    }

    /// Finds two distinct keys that route to two DIFFERENT members under the given membership, so a
    /// test can assert per-key affinity is non-vacuous. Panics if none found in a generous search.
    fn two_keys_to_two_members(
        e: &Engine<InMemoryFs, ManualClock>,
        group: &str,
        a: MemberId,
        b: MemberId,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut for_a = None;
        let mut for_b = None;
        for n in 0..2000u32 {
            let key = format!("k{n}").into_bytes();
            // Probe via decide: a free key returns Deliver only for its owner.
            let owns_a = matches!(
                e.route_decision_in(group, a, &key, Offset::ZERO),
                Some(RouteDecision::Deliver)
            );
            let owns_b = matches!(
                e.route_decision_in(group, b, &key, Offset::ZERO),
                Some(RouteDecision::Deliver)
            );
            if owns_a && for_a.is_none() {
                for_a = Some(key.clone());
            } else if owns_b && for_b.is_none() {
                for_b = Some(key);
            }
            if for_a.is_some() && for_b.is_some() {
                break;
            }
        }
        (
            for_a.expect("a key for member a"),
            for_b.expect("a key for member b"),
        )
    }

    #[test]
    fn key_ordering_defaults_to_none_and_is_unchanged() {
        // The default mode is None: no router, plain competing distribution, and a plain poll is
        // byte-for-byte the existing behavior. poll_in_member on a None group equals poll_in.
        let mut e = open(config(10, 5));
        assert_eq!(e.key_ordering_in("g"), KeyOrdering::None);
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        // A member-aware poll on a non-key_shared group delivers in plain competing order.
        let d = message(e.poll_in_member("g", MemberId::new(0), 0).unwrap());
        assert_eq!(d.offset, Offset::new(0));
        assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
        // Still None; member id is irrelevant.
        assert_eq!(e.key_ordering_in("g"), KeyOrdering::None);
        assert_eq!(e.busy_keys_in("g"), 0);
    }

    #[test]
    fn setting_key_shared_attaches_a_router_and_reverting_drops_it() {
        let mut e = open(config(10, 5));
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        assert_eq!(e.key_ordering_in("g"), KeyOrdering::KeyShared);
        // Re-applying does not wipe membership.
        assert!(e.join_member_in("g", MemberId::new(1)));
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        assert!(
            !e.join_member_in("g", MemberId::new(1)),
            "member 1 is still joined after re-applying the mode"
        );
        // Reverting to None drops the router.
        e.set_key_ordering_in("g", KeyOrdering::None).unwrap();
        assert_eq!(e.key_ordering_in("g"), KeyOrdering::None);
        assert!(
            !e.join_member_in("g", MemberId::new(1)),
            "a None group has no member set to join"
        );
    }

    #[test]
    fn same_key_always_routes_to_the_same_live_member() {
        // Acceptance: same-key records always route to the same live member.
        let (a, b) = (MemberId::new(10), MemberId::new(20));
        let mut e = open(config(20, 5));
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        e.join_member_in("g", a);
        e.join_member_in("g", b);
        let (key_a, _key_b) = two_keys_to_two_members(&e, "g", a, b);
        // Produce three records all with key_a, interleaved with other keys.
        let o0 = produce_keyed(&mut e, &key_a, b"a0");
        let _ = produce_keyed(&mut e, b"other", b"x");
        let o1 = produce_keyed(&mut e, &key_a, b"a1");
        let o2 = produce_keyed(&mut e, &key_a, b"a2");
        // The owner of key_a takes o0; the other member never gets a key_a record.
        let owner = if matches!(
            e.route_decision_in("g", a, &key_a, Offset::ZERO),
            Some(RouteDecision::Deliver)
        ) {
            a
        } else {
            b
        };
        let other = if owner == a { b } else { a };
        // The non-owner polling never receives a key_a record (it may get "other").
        // Drain the owner one key_a record at a time, acking, and assert offset order is preserved.
        for (expected_off, _payload) in [(o0, &b"a0"[..]), (o1, b"a1"), (o2, b"a2")] {
            // The other member must NOT be able to take this key_a offset.
            assert_eq!(
                e.route_decision_in("g", other, &key_a, expected_off),
                Some(RouteDecision::NotOwner),
                "key_a never routes to the non-owner"
            );
            // Poll as the owner until we get this key_a record (it may first serve "other").
            loop {
                match e.poll_in_member("g", owner, 0).unwrap() {
                    Poll::Message(d) if d.record.key == key_a => {
                        assert_eq!(d.offset, expected_off, "per-key offset order preserved");
                        assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
                        break;
                    }
                    Poll::Message(d) => {
                        // An "other"-keyed record the owner also owns: ack and keep going.
                        assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
                    }
                    Poll::Idle => panic!("the owner should eventually get its key_a record"),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
    }

    #[test]
    fn a_busy_key_is_not_redelivered_to_a_new_owner_until_it_drains() {
        // Acceptance: a key with an in-flight record is not delivered to a NEW owner until the
        // prior record drains or its lease expires (the drain-or-expire guard across a rebalance).
        let mut e = open(config(20, 5));
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        let m1 = MemberId::new(1);
        let m2 = MemberId::new(2);
        let m3 = MemberId::new(3);
        let m4 = MemberId::new(4);
        for m in [m1, m2, m3, m4] {
            e.join_member_in("g", m);
        }
        // Find a key owned by m2 whose owner CHANGES when m2 leaves.
        let key = (0..2000u32)
            .map(|n| format!("k{n}").into_bytes())
            .find(|k| {
                matches!(
                    e.route_decision_in("g", m2, k, Offset::ZERO),
                    Some(RouteDecision::Deliver)
                )
            })
            .expect("a key owned by m2");
        // Produce two records on this key.
        let o0 = produce_keyed(&mut e, &key, b"first");
        let o1 = produce_keyed(&mut e, &key, b"second");
        // m2 takes the first record; the key is now busy at o0.
        let d0 = message(e.poll_in_member("g", m2, 0).unwrap());
        assert_eq!(d0.offset, o0);
        assert_eq!(e.busy_keys_in("g"), 1);
        // m2 leaves: the key's owner changes.
        assert!(e.leave_member_in("g", m2));
        let new_owner = [m1, m3, m4]
            .into_iter()
            .find(|&m| {
                matches!(
                    e.route_decision_in("g", m, &key, o1),
                    Some(RouteDecision::KeyBusy | RouteDecision::Deliver)
                )
            })
            .expect("a new owner among the survivors");
        // The NEW owner cannot take o1 while o0 is in flight: the key is busy.
        assert_eq!(
            e.route_decision_in("g", new_owner, &key, o1),
            Some(RouteDecision::KeyBusy),
            "the next record waits for the in-flight one to drain"
        );
        // No survivor can poll o1 yet.
        for m in [m1, m3, m4] {
            match e.poll_in_member("g", m, 0).unwrap() {
                Poll::Idle => {}
                Poll::Message(d) => {
                    assert_ne!(d.offset, o1, "o1 must not deliver while o0 is busy");
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        // o0's lease expires (advance past the 30 ns visibility): it is now reclaimable, but per-key
        // order still requires o0 to be redelivered BEFORE o1. The new owner gets o0 first.
        let d0b = message(e.poll_in_member("g", new_owner, 40).unwrap());
        assert_eq!(
            d0b.offset, o0,
            "the expired in-flight record redelivers first"
        );
        assert_eq!(e.ack_in("g", &d0b.token), AckResult::Acked);
        // Now o1 is deliverable to the new owner.
        let d1 = message(e.poll_in_member("g", new_owner, 40).unwrap());
        assert_eq!(
            d1.offset, o1,
            "the next record delivers only after the prior drains"
        );
    }

    #[test]
    fn per_key_order_survives_a_mid_stream_join_that_moves_the_owner() {
        // Acceptance: per-key order survives a mid-stream member join, INCLUDING the case where the
        // join actually MOVES the key's owner. The in-flight record must drain before the NEW owner
        // gets the next one, so an old in-flight record and a newly routed one never interleave.
        let mut e = open(config(20, 5));
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        let m1 = MemberId::new(1);
        let m2 = MemberId::new(2);
        // Find a key that, in the {m1, m2} member set, is owned by m2, so the join below provably
        // moves it from m1 (sole owner when alone) to m2. MemberId is stable across leave/rejoin,
        // so the rendezvous owner is the same m2 after it rejoins.
        e.join_member_in("g", m1);
        e.join_member_in("g", m2);
        let (_for_m1, key) = two_keys_to_two_members(&e, "g", m1, m2);
        e.leave_member_in("g", m2);
        assert!(
            matches!(
                e.route_decision_in("g", m1, &key, Offset::ZERO),
                Some(RouteDecision::Deliver)
            ),
            "with m1 alone it owns every key, including this one"
        );
        let o0 = produce_keyed(&mut e, &key, b"0");
        let o1 = produce_keyed(&mut e, &key, b"1");
        // m1 takes o0 while it is the sole owner.
        let d0 = message(e.poll_in_member("g", m1, 0).unwrap());
        assert_eq!(d0.offset, o0);
        // m2 joins mid-stream: the key's owner MOVES to m2.
        e.join_member_in("g", m2);
        // o1 is not deliverable to ANYONE while o0 is in flight (the drain guard across the remap).
        for m in [m1, m2] {
            match e.poll_in_member("g", m, 0).unwrap() {
                Poll::Idle => {}
                Poll::Message(d) => assert_ne!(d.offset, o1, "o1 waits for o0"),
                other => panic!("unexpected {other:?}"),
            }
        }
        // Ack o0: the key frees and o1 delivers to the NEW owner m2 (not the old owner m1), in order.
        assert_eq!(e.ack_in("g", &d0.token), AckResult::Acked);
        assert_eq!(
            e.route_decision_in("g", m2, &key, o1),
            Some(RouteDecision::Deliver),
            "the key moved to m2, so m2 is now its owner"
        );
        assert_eq!(
            e.route_decision_in("g", m1, &key, o1),
            Some(RouteDecision::NotOwner),
            "m1 no longer owns the moved key"
        );
        let d1 = message(e.poll_in_member("g", m2, 0).unwrap());
        assert_eq!(
            d1.offset, o1,
            "o1 delivers after o0 to the new owner, preserving per-key order across the remap"
        );
    }

    #[test]
    fn an_empty_key_keeps_plain_competing_distribution() {
        // Records with no key have no affinity and no per-key order (#64): any member may take them
        // and they drain IN PARALLEL, not one record at a time. The load-bearing property (#64
        // review S1) is that two empty-keyed records can be in flight at two DIFFERENT members
        // SIMULTANEOUSLY; under a (wrong) empty-key serialization gate the second poll below would
        // be Idle. Then the whole batch drains exactly once across the members (the competing
        // property, no double delivery).
        let mut e = open(config(20, 5));
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        let m1 = MemberId::new(1);
        let m2 = MemberId::new(2);
        e.join_member_in("g", m1);
        e.join_member_in("g", m2);
        for p in [&b"a"[..], b"b", b"c", b"d"] {
            produce_keyed(&mut e, b"", p);
        }
        // Two empty-keyed records in flight at the same time across two members, with NO ack in
        // between: plain competing must allow this (the serialization fix). Both must deliver and
        // they must be DISTINCT offsets (no double delivery of the same record).
        let first = message(e.poll_in_member("g", m1, 0).unwrap());
        let second = message(e.poll_in_member("g", m2, 0).unwrap());
        assert_ne!(
            first.offset, second.offset,
            "two empty-keyed records drain in parallel to two members, not serialized"
        );
        let mut delivered = vec![first.offset.get(), second.offset.get()];
        assert_eq!(e.ack_in("g", &first.token), AckResult::Acked);
        assert_eq!(e.ack_in("g", &second.token), AckResult::Acked);
        // Drain the remaining two across both members.
        for m in [m1, m2, m1, m2] {
            if let Poll::Message(d) = e.poll_in_member("g", m, 0).unwrap() {
                delivered.push(d.offset.get());
                assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
            }
        }
        delivered.sort_unstable();
        assert_eq!(
            delivered,
            vec![0, 1, 2, 3],
            "every empty-keyed record delivered exactly once across the members"
        );
    }

    #[test]
    fn a_non_owner_never_takes_a_key_even_when_polling() {
        // A member that does not own a key gets Idle (or another key's record), never the foreign
        // key's record, so the affinity holds at the poll level, not just the decide level.
        let (a, b) = (MemberId::new(7), MemberId::new(8));
        let mut e = open(config(20, 5));
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        e.join_member_in("g", a);
        e.join_member_in("g", b);
        let (key_a, _key_b) = two_keys_to_two_members(&e, "g", a, b);
        let oa = produce_keyed(&mut e, &key_a, b"only-a");
        // b polls: it must NOT receive key_a's record (only Idle, since that is the only record).
        match e.poll_in_member("g", b, 0).unwrap() {
            Poll::Idle => {}
            other => panic!("the non-owner must not get key_a's record, got {other:?}"),
        }
        // a polls: it gets the record.
        let d = message(e.poll_in_member("g", a, 0).unwrap());
        assert_eq!(d.offset, oa);
    }

    #[test]
    fn busy_keys_tracks_in_flight_and_clears_on_ack() {
        let mut e = open(config(20, 5));
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        let m = MemberId::new(1);
        e.join_member_in("g", m);
        produce_keyed(&mut e, b"k1", b"a");
        produce_keyed(&mut e, b"k2", b"b");
        assert_eq!(e.busy_keys_in("g"), 0);
        let d0 = message(e.poll_in_member("g", m, 0).unwrap());
        let d1 = message(e.poll_in_member("g", m, 0).unwrap());
        assert_eq!(e.busy_keys_in("g"), 2, "two distinct keys in flight");
        e.ack_in("g", &d0.token);
        assert_eq!(e.busy_keys_in("g"), 1, "acking one frees its key");
        e.ack_in("g", &d1.token);
        assert_eq!(e.busy_keys_in("g"), 0);
    }

    // ----- Per-consumer BYTE budget passthrough (refs #65, #275) -----

    #[test]
    fn consumer_credit_bytes_passes_through_unfloored() {
        // The engine advertises the configured byte budget verbatim: unlike the message credit (which
        // is floored to 1), the byte budget is NOT floored, so `0` survives as the unlimited sentinel.
        let mut cfg = config(10, 5);
        cfg.consumer_credit_bytes = 4096;
        let e = open(cfg);
        assert_eq!(e.consumer_credit_bytes(), 4096);
    }

    #[test]
    fn a_zero_consumer_credit_bytes_means_unlimited() {
        // `0` = unlimited (the byte budget is off), matching the other byte bounds. The engine keeps
        // it as `0` rather than flooring it; the session reads `0` and never lets the byte budget bind.
        let mut cfg = config(10, 5);
        cfg.consumer_credit_bytes = 0;
        let e = open(cfg);
        assert_eq!(e.consumer_credit_bytes(), 0, "0 is preserved as unlimited");
    }

    #[test]
    fn the_default_consumer_credit_bytes_is_eight_mib() {
        // The test `config` helper uses the production default, so the default 8 MiB byte budget
        // flows through unchanged.
        let e = open(config(10, 5));
        assert_eq!(e.consumer_credit_bytes(), DEFAULT_CONSUMER_CREDIT_BYTES);
        assert_eq!(DEFAULT_CONSUMER_CREDIT_BYTES, 8 * 1024 * 1024);
    }

    // ---- Idle named-group eviction (#277) -------------------------------------------------------
    //
    // These tests drive the idle window through the explicit-`now` argument to `poll_in` (which
    // updates the group's last-activity to that `now` and runs the sweep against it), so they are
    // fully deterministic without touching the wall clock. The engine's own `now_monotonic` stays
    // at 0 (the test `ManualClock` is never advanced), so the produce-seam sweep is a no-op in
    // these tests and only the poll-seam sweep with the explicit `now` evicts.

    // A config with an explicit non-zero idle-eviction window (#277), in milliseconds, but the test
    // poll path passes `now` in the SAME units as the window (the sweep compares `now -
    // last_activity` to the configured window converted to nanoseconds). To keep the test
    // arithmetic in plain integers, the window is given in milliseconds and the test advances `now`
    // by the nanosecond equivalent.
    fn config_with_idle_evict_ms(group_idle_evict_ms: u64) -> EngineConfig {
        EngineConfig {
            group_idle_evict_ms,
            ..config(10, 5)
        }
    }

    // One millisecond in nanoseconds, the unit `now` is expressed in for these tests (the engine
    // converts the millisecond window to nanoseconds, and the poll `now` is on the same ns clock).
    const MS: u64 = 1_000_000;

    #[test]
    fn an_idle_caught_up_named_group_is_evicted_after_the_window() {
        // The headline policy: a NAMED group that is fully caught up (committed == head), holds no
        // lease, and has been idle past the window IS evicted, freeing its slot. Re-creating it
        // resumes at the head and redelivers nothing it had acked.
        let mut e = open(config_with_idle_evict_ms(10)); // 10 ms idle window
        produce(&mut e, b"a");
        // "g" consumes and acks the only message at now=0, so it is fully caught up with no lease.
        let d = message(e.poll_in("g", 0).unwrap());
        assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in("g"), e.flushed_offset(), "caught up");
        assert!(e.has_group("g"), "g is live before the window elapses");
        // A poll of the DEFAULT group well past the window runs the sweep; "g" has been idle since
        // now=0, so at now = 11 ms it is evicted (10 ms window). The default group is never evicted.
        let _ = e.poll(11 * MS).unwrap();
        assert!(!e.has_group("g"), "the idle caught-up group was evicted");
        assert!(e.has_group(""), "the default group is never evicted");
        // Re-subscribing (a fresh poll) re-creates the group; it resumes at the head and is idle.
        assert!(matches!(e.poll_in("g", 12 * MS).unwrap(), Poll::Idle));
        assert_eq!(
            e.committed_offset_in("g"),
            e.flushed_offset(),
            "the re-created group is at the head, so it redelivers nothing it had acked"
        );
    }

    #[test]
    fn a_group_with_an_in_flight_lease_is_not_evicted() {
        // A group holding an in-flight lease is mid-work: it is NEVER evicted, even long past the
        // window, so its in-flight bookkeeping is never dropped under a holder.
        let mut e = open(config_with_idle_evict_ms(10));
        produce(&mut e, b"a");
        // "g" polls offset 0 but does NOT ack it: the lease is in flight and committed < head.
        let d = message(e.poll_in("g", 0).unwrap());
        assert_eq!(e.in_flight(), 1);
        // Sweep far past the window via a default-group poll: "g" is not evicted (it has a lease,
        // and it is also behind the head).
        let _ = e.poll(100 * MS).unwrap();
        assert!(e.has_group("g"), "a group with an in-flight lease is kept");
        // Acking it later still works (the lease was never dropped by an eviction).
        assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
    }

    #[test]
    fn a_group_behind_the_head_is_not_evicted() {
        // A group whose committed cursor is BELOW the head has unconsumed work: it is NEVER evicted
        // (evicting then re-creating it could only lose its position or redeliver), even when it
        // holds no lease and is idle past the window.
        let mut e = open(config_with_idle_evict_ms(10));
        produce(&mut e, b"a");
        produce(&mut e, b"b");
        // "g" consumes and acks ONLY offset 0, leaving offset 1 unconsumed: committed (1) < head (2).
        let d = message(e.poll_in("g", 0).unwrap());
        assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
        assert!(
            e.committed_offset_in("g") < e.flushed_offset(),
            "g is behind the head"
        );
        assert_eq!(e.in_flight(), 0, "no lease, yet still behind");
        // Sweep far past the window: a behind group is kept regardless of idleness.
        let _ = e.poll(100 * MS).unwrap();
        assert!(e.has_group("g"), "a behind group is never evicted");
    }

    #[test]
    fn the_default_group_is_never_evicted_even_when_idle_and_caught_up() {
        // The default group `""` is the durable wire group: it is exempt from eviction even when it
        // is fully caught up, lease-free, and idle far past the window.
        let mut e = open(config_with_idle_evict_ms(10));
        produce(&mut e, b"a");
        let d = message(e.poll(0).unwrap());
        assert_eq!(e.ack(&d.token), AckResult::Acked);
        assert_eq!(
            e.committed_offset(),
            e.flushed_offset(),
            "default caught up"
        );
        // Many sweeps far past the window never remove the default group.
        for now in [50 * MS, 100 * MS, 1_000 * MS] {
            let _ = e.poll(now).unwrap();
            assert!(e.has_group(""), "the default group is never evicted");
        }
    }

    #[test]
    fn eviction_frees_a_slot_so_a_new_group_can_be_created_at_a_full_cap() {
        // Eviction reclaims a slot against the `max_groups` cap: with the cap full of idle
        // caught-up named groups, a sweep evicts one and a NEW group can then be created where the
        // cap previously rejected it.
        let mut e = open(EngineConfig {
            max_groups: 3, // default + 2 named groups fill the cap
            group_idle_evict_ms: 10,
            ..config(10, 5)
        });
        produce(&mut e, b"a");
        // Create two named groups, each caught up (acked the one message) and idle since now=0.
        for name in ["g0", "g1"] {
            let d = message(e.poll_in(name, 0).unwrap());
            assert_eq!(e.ack_in(name, &d.token), AckResult::Acked);
        }
        assert_eq!(e.group_count(), 3, "default + g0 + g1 fill the cap");
        // A brand-new named group is rejected at the full cap BEFORE any idle window has elapsed
        // (now = MS, i.e. 1 ms, is well under the 10 ms window, so the sweep evicts nothing yet).
        assert!(matches!(
            e.poll_in("g2", MS).unwrap_err(),
            EngineError::TooManyGroups { max: 3 }
        ));
        // Past the window, the SAME poll that wants to create "g2" first sweeps out the idle g0/g1,
        // freeing slots, then creates g2 successfully (it delivers the one message at offset 0).
        let d = message(e.poll_in("g2", 20 * MS).unwrap());
        assert_eq!(d.offset, Offset::new(0));
        assert!(
            e.has_group("g2"),
            "g2 was created after eviction freed a slot"
        );
        assert!(!e.has_group("g0"), "g0 was evicted to free the slot");
        assert!(!e.has_group("g1"), "g1 was evicted to free the slot");
    }

    #[test]
    fn a_re_subscribed_evicted_group_resumes_at_head_and_redelivers_nothing_acked() {
        // The never-lose-committed-position invariant end to end: a caught-up group is evicted, then
        // a re-subscribe (re-poll) resumes at the head and redelivers NOTHING it had already acked,
        // even across more produces.
        let mut e = open(config_with_idle_evict_ms(10));
        for p in [&b"a"[..], b"b"] {
            produce(&mut e, p);
        }
        // "g" consumes and acks both messages: caught up at offset 2.
        for _ in 0..2 {
            let d = message(e.poll_in("g", 0).unwrap());
            assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
        }
        assert_eq!(e.committed_offset_in("g"), Offset::new(2));
        // Evict it via a sweep past the window.
        let _ = e.poll(20 * MS).unwrap();
        assert!(!e.has_group("g"), "g evicted while caught up");
        // Produce one more, then re-subscribe: the re-created group resumes at the head (offset 2,
        // where it had committed), so it delivers ONLY the new message, never the acked a/b.
        produce(&mut e, b"c");
        let d = message(e.poll_in("g", 30 * MS).unwrap());
        assert_eq!(
            d.offset,
            Offset::new(2),
            "resumes at head; redelivers only the new record, nothing it had acked"
        );
        assert_eq!(d.record.payload, b"c");
    }

    #[test]
    fn a_zero_idle_window_disables_eviction() {
        // `0` = disabled: no group is ever evicted regardless of idleness, matching the `0` = off
        // convention of the other bounds.
        let mut e = open(config_with_idle_evict_ms(0));
        produce(&mut e, b"a");
        let d = message(e.poll_in("g", 0).unwrap());
        assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in("g"), e.flushed_offset(), "caught up");
        // Sweep absurdly far past any window: with eviction disabled, the group is kept.
        let _ = e.poll(u64::MAX / 2).unwrap();
        assert!(e.has_group("g"), "a zero window never evicts");
    }

    #[test]
    fn polling_an_idle_group_keeps_it_alive_and_does_not_evict_itself() {
        // A poll IS activity: polling a group that is itself idle past the window refreshes its
        // last-activity BEFORE the sweep, so the poll keeps it alive rather than evicting and
        // re-creating it. A consumer that keeps polling its own caught-up group is never reclaimed.
        let mut e = open(config_with_idle_evict_ms(10));
        produce(&mut e, b"a");
        let d = message(e.poll_in("g", 0).unwrap());
        assert_eq!(e.ack_in("g", &d.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in("g"), e.flushed_offset(), "caught up");
        // Keep polling "g" far past the window each time: it is the polled group, so the sweep at
        // the start of each poll refreshes it first and never evicts it. The committed cursor stays
        // put (no offset 0 reset), proving it was not evicted-and-recreated-fresh.
        for now in [20 * MS, 40 * MS, 1_000 * MS] {
            assert!(matches!(e.poll_in("g", now).unwrap(), Poll::Idle));
            assert!(e.has_group("g"), "polling g keeps it alive");
            assert_eq!(
                e.committed_offset_in("g"),
                e.flushed_offset(),
                "g stays caught up; it was never reset"
            );
        }
    }

    #[test]
    fn explicit_unsub_eviction_reclaims_a_caught_up_lease_free_group_immediately() {
        // `evict_group_if_idle` is the explicit-Unsub reclaim: a caught-up, lease-free named group
        // is reclaimed RIGHT NOW (no idle-window wait), but every position-safety clause still
        // holds, so it never evicts a behind, leased, default, or unknown group.
        let mut e = open(config_with_idle_evict_ms(10));
        produce(&mut e, b"a");
        produce(&mut e, b"b");
        // "caught" acks both: caught up, lease-free -> immediately evictable on unsub.
        for _ in 0..2 {
            let d = message(e.poll_in("caught", 0).unwrap());
            e.ack_in("caught", &d.token);
        }
        // "behind" acks only one: still behind -> NOT evictable even on an explicit unsub.
        let d = message(e.poll_in("behind", 0).unwrap());
        e.ack_in("behind", &d.token);
        // "leased" holds an in-flight lease -> NOT evictable on an explicit unsub.
        let _held = message(e.poll_in("leased", 0).unwrap());

        assert!(
            e.evict_group_if_idle("caught"),
            "caught up + lease-free -> evicted now"
        );
        assert!(!e.has_group("caught"));
        assert!(
            !e.evict_group_if_idle("behind"),
            "a behind group is never evicted"
        );
        assert!(e.has_group("behind"));
        assert!(
            !e.evict_group_if_idle("leased"),
            "a leased group is never evicted"
        );
        assert!(e.has_group("leased"));
        assert!(
            !e.evict_group_if_idle(""),
            "the default group is never evicted"
        );
        assert!(e.has_group(""));
        assert!(
            !e.evict_group_if_idle("ghost"),
            "an unknown group is a no-op"
        );
    }

    #[test]
    fn explicit_unsub_eviction_is_a_no_op_when_disabled() {
        // With the window disabled (`0`), even an explicit unsub of a caught-up, lease-free group
        // does NOT evict: the lifecycle policy is off entirely.
        let mut e = open(config_with_idle_evict_ms(0));
        produce(&mut e, b"a");
        let d = message(e.poll_in("g", 0).unwrap());
        e.ack_in("g", &d.token);
        assert!(!e.evict_group_if_idle("g"), "disabled: no reclaim on unsub");
        assert!(e.has_group("g"));
    }

    #[test]
    fn an_out_of_order_acked_ahead_group_is_not_evicted() {
        // "Fully caught up" requires committed == head AND no acked-ahead set. A group that acked
        // ahead of a gap (committed below the head, ahead set non-empty) is behind in the meaningful
        // sense and is NEVER evicted, so the gap's redelivery is never lost. The `is_evictable`
        // predicate rejects it on BOTH the committed-below-head clause and the non-empty-ahead-set
        // clause; this proves the group is kept regardless of how the sweep is driven.
        let mut e = open(config_with_idle_evict_ms(10));
        for p in [&b"a"[..], b"b"] {
            produce(&mut e, p);
        }
        // Poll both, ack only offset 1 (leaving the gap at 0): committed stays 0, ahead = [1, 2).
        let _t0 = message(e.poll_in("g", 0).unwrap()).token;
        let t1 = message(e.poll_in("g", 0).unwrap()).token;
        assert_eq!(e.ack_in("g", &t1), AckResult::Acked);
        assert!(
            e.committed_offset_in("g") < e.flushed_offset(),
            "behind via the gap at offset 0"
        );
        // Drive the sweep far past the window via a default-group poll: the acked-ahead group is
        // kept (it is behind). An explicit unsub also refuses to reclaim it.
        let _ = e.poll(100 * MS).unwrap();
        assert!(
            e.has_group("g"),
            "an acked-ahead (behind) group is never evicted by the sweep"
        );
        assert!(
            !e.evict_group_if_idle("g"),
            "an acked-ahead (behind) group is never evicted on unsub either"
        );
        assert!(e.has_group("g"));
    }
}
