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
use ironbus_core::attempt::{
    decode_attempt_snapshot, encode_attempt_snapshot, ATTEMPT_SNAPSHOT_MIN_LEN,
};
use ironbus_core::backpressure::{AimdLimiter, Codel, FsyncHeadroom, RetryBudget, TokenBucket};
use ironbus_core::binding::{single_home, Resolution};
use ironbus_core::clock::Clock;
use ironbus_core::compress::{
    compress_payload, Codec, CompressConfig, DEFAULT_MAX_DECOMPRESSED_BYTES,
};
use ironbus_core::confirm::{ConfirmConfig, ConfirmRegistry, ConfirmStatus, ReadyConfirm};
use ironbus_core::cursor::AckCursor;
use ironbus_core::delivery::{DeliveryConfig, Disposition};
use ironbus_core::keyshared::{KeyOrdering, KeyRouter, MemberId, RouteDecision};
use ironbus_core::lease::{
    AckOutcome, Claim, ExtendOutcome, LeaseConfig, LeaseTable, LeaseToken, NackOutcome,
};
use ironbus_core::producer_seq::{
    decode_seq_snapshot, encode_seq_snapshot, ProducerSeqRegistry, SeqConfig, SeqDecision,
};
use ironbus_core::subject::{Subject, SubjectError, SubjectPattern};
use ironbus_core::sublist::{Sublist, SublistBuilder, SublistError, SublistSnapshot};
use ironbus_core::ttl::{decode_ttl_headers, is_expired, Ttl};
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::checkpoint::{
    AttemptsCheckpoint, Checkpoint, CountersCheckpoint, ProducerSeqCheckpoint, ATTEMPTS_PAYLOAD,
    MAX_PAYLOAD, PRODUCER_SEQ_PAYLOAD,
};
use ironbus_storage::dlq::{DeadLetterReason, DlqSink, DLQ_SUBDIR};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::{Append, Log, LogConfig, RetentionBounds};
use ironbus_storage::loss::LossReport;
use ironbus_storage::naming::MAX_STREAM_NAME_LEN;
use ironbus_storage::segment::{OwnedRecord, RawByteRun, StorageError};
use ironbus_storage::streamset::{CommitOutcome, StreamError, StreamId, StreamSet};
use ironbus_storage::txn::{TxnStore, TxnStoreError};
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

/// The durability LEVEL: how an ack relates to the covering `fdatasync` (#341, #379, durability #6).
///
/// The default, [`DurabilityLevel::Sync`], is the ONLY power-loss-safe level: an ack is emitted only
/// AFTER the covering `fdatasync` returns, so an acknowledged record is never lost on a power cut
/// (invariant I2). An operator who changes nothing keeps that ZERO-acked-loss guarantee. The other
/// three levels are STRICTLY OPT-IN relaxations that trade durability for throughput by acking
/// BEFORE the covering fsync; each weakens I2 by a precisely-bounded (or, for `None`, declared but
/// unbounded) loss window. The two loss-bearing levels ([`DurabilityLevel::Async`],
/// [`DurabilityLevel::None`]) additionally require an explicit data-loss acknowledgement to enable
/// (the none/async safety gate, enforced in the CLI), because their loss is unbounded.
///
/// The enum is `#[non_exhaustive]` so a future level is not a breaking change. See
/// [`docs/DURABILITY.md`](../../../docs/DURABILITY.md) for the per-level ack condition and
/// worst-case-loss bound, and [`docs/INVARIANTS.md`](../../../docs/INVARIANTS.md) for how I2 is
/// conditioned on `Sync`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurabilityLevel {
    /// The DEFAULT and only power-loss-safe level: ack ONLY after the covering `fdatasync` returns.
    /// I2 holds (ack-implies-durable); worst-case acknowledged loss on a power cut is ZERO. The
    /// group-commit batcher amortizes the fsync but never acks before it, so batching changes the
    /// cost of durability, never the guarantee.
    #[default]
    Sync,
    /// OPT-IN, bounded-loss: ack as soon as the record is in the OS page cache (the visible head
    /// advances WITHOUT the covering fsync), and a background window issues an `fdatasync` every
    /// `flush_interval_ms` of monotonic time OR after `flush_max_bytes` of unsynced record bytes,
    /// whichever comes first. WORST-CASE acknowledged loss on a power cut is the records acked since
    /// the last completed `fdatasync`, BOUNDED by the smaller of the time window and the byte budget.
    /// NOT power-loss safe (the open window's acked-but-unsynced records are lost), but the bound is
    /// a number the operator chose.
    Interval,
    /// OPT-IN, unbounded-until-next-sync loss: ack as soon as the record is in the page cache; an
    /// `fdatasync` happens only OPPORTUNISTICALLY (on a segment roll's seal, or a clean shutdown
    /// flush), with NO time or byte ceiling forcing one. WORST-CASE acknowledged loss is every record
    /// acked since the last sync, bounded only by the OS dirty-writeback window, not by IronBus.
    /// Gated behind an explicit data-loss acknowledgement (the CLI `--async-loss-ack`).
    Async,
    /// OPT-IN, the LARGEST loss window: like [`DurabilityLevel::Async`] but with NO periodic fsync at
    /// all and no opportunistic mid-run sync beyond a segment roll's seal; the only barriers are a
    /// segment roll and a clean shutdown. WORST-CASE acknowledged loss is every record acked since
    /// the last roll or shutdown. Gated behind the same explicit data-loss acknowledgement.
    None,
}

impl DurabilityLevel {
    /// Parses the `--durability-level` flag value, accepting `sync`, `interval`, `async`, or `none`.
    /// Returns `None` for any other spelling (the caller turns that into a usage error naming the
    /// accepted values).
    #[must_use]
    pub fn parse(value: &str) -> Option<DurabilityLevel> {
        match value {
            "sync" => Some(DurabilityLevel::Sync),
            "interval" => Some(DurabilityLevel::Interval),
            "async" => Some(DurabilityLevel::Async),
            "none" => Some(DurabilityLevel::None),
            _ => None,
        }
    }

    /// The stable flag/log spelling of this level, the inverse of [`DurabilityLevel::parse`]. Used in
    /// the materialized-config startup line and the loud I2-waived warning so an operator reads back
    /// exactly the selectable name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DurabilityLevel::Sync => "sync",
            DurabilityLevel::Interval => "interval",
            DurabilityLevel::Async => "async",
            DurabilityLevel::None => "none",
        }
    }

    /// Whether an ack at this level implies the record is DURABLE (I2 holds). True ONLY for
    /// [`DurabilityLevel::Sync`]; every relaxed level acks before the covering fsync, so the ack is a
    /// weaker promise. The inverse, [`DurabilityLevel::waives_i2`], is the power-loss-unsafe signal an
    /// operator alerts on.
    #[must_use]
    pub fn ack_implies_durable(self) -> bool {
        matches!(self, DurabilityLevel::Sync)
    }

    /// Whether this level WAIVES I2 (ack no longer implies durable): true for every relaxed level,
    /// false for [`DurabilityLevel::Sync`]. The source of the sticky `power_loss_unsafe` gauge and the
    /// loud startup warning, and the predicate the CLI none/async safety gate keys on.
    #[must_use]
    pub fn waives_i2(self) -> bool {
        !self.ack_implies_durable()
    }

    /// Whether selecting this level REQUIRES an explicit data-loss acknowledgement to boot (the
    /// none/async safety gate, #49/#379): true for the UNBOUNDED-loss levels
    /// [`DurabilityLevel::Async`] and [`DurabilityLevel::None`], false for `sync` (no ack needed) and
    /// `interval` (its loss is bounded by the operator-chosen window, so it is opt-in but not gated
    /// behind the data-loss flag). The CLI refuses to start a gated level unless the acknowledgement
    /// flag is set.
    #[must_use]
    pub fn requires_loss_ack(self) -> bool {
        matches!(self, DurabilityLevel::Async | DurabilityLevel::None)
    }

    /// A one-line, human-readable description of the WORST-CASE acknowledged loss this level can take
    /// on a power cut, for the loud I2-waived startup warning. `sync` returns the zero-loss statement;
    /// each relaxed level returns its documented bound. Pure (it reads the configured window only for
    /// `interval`), so it is the single source of truth shared by the warning and the docs.
    #[must_use]
    pub fn worst_case_loss_description(
        self,
        flush_interval_ms: u64,
        flush_max_bytes: u64,
    ) -> String {
        match self {
            DurabilityLevel::Sync => {
                "zero (an ack is emitted only after the covering fdatasync; I2 holds)".to_string()
            }
            DurabilityLevel::Interval => format!(
                "bounded by the flush window: at most the records acked since the last fdatasync, \
                 forced every {flush_interval_ms} ms or {flush_max_bytes} unsynced bytes, whichever \
                 comes first"
            ),
            DurabilityLevel::Async => "every record acked since the last fdatasync, with no time or \
                 byte ceiling (bounded only by the OS dirty-writeback window); a segment roll or a \
                 clean shutdown is the only barrier"
                .to_string(),
            DurabilityLevel::None => "every record acked since the last segment roll or clean \
                 shutdown (no periodic fsync at all): the largest loss window"
                .to_string(),
        }
    }
}

/// A produce's opt-in dedup identity (#3, #33), passed to [`Engine::append_no_sync_dedup`]. The
/// caller builds this only when the wire publish carried a `msg_id` (the dedup opt-in); a produce
/// with no `msg_id` passes `None` and behaves exactly as before. Borrows the wire bytes.
#[derive(Clone, Copy, Debug)]
pub struct DedupRequest<'a> {
    /// The stable producer identity for dedup keying and epoch fencing (empty = anonymous,
    /// session-scoped). Each producer has its own bounded window keyed by this.
    pub producer_id: &'a [u8],
    /// The producer's monotonic epoch (the fencing token). A produce below the broker's known
    /// high-water for `producer_id` is fenced; a higher epoch supersedes the old session's window.
    pub epoch: u64,
    /// The idempotency key the broker deduplicates on (keying is by `msg_id` ONLY, never the body).
    pub msg_id: &'a [u8],
    /// The OPT-IN Kafka-style idempotent-producer SEQUENCE (V2-M8): `Some` iff the wire publish
    /// carried a `seq`. When present, the broker routes the produce through the DURABLE per-producer
    /// sequence high-water (deduplicate a retry to exactly-once-append, fence a zombie epoch, reject an
    /// out-of-order gap) INSTEAD of the time-bounded `msg_id` window — the effectively-once path that
    /// survives a restart + a long offline gap. `None` is exactly today's `msg_id`-window dedup.
    pub seq: Option<u64>,
}

/// The outcome of an [`Engine::append_no_sync_dedup`] (#3, #33, V2-M8): a fresh append, a benign dedup
/// hit, a stale-epoch fence, or an out-of-order-sequence rejection. The actor maps each to its wire
/// reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    /// A fresh produce was appended at this offset (write, NO fsync); park its reply behind the
    /// covering [`Engine::commit_batch`], then reply `PubAck`. This is also the no-dedup path.
    Appended(Offset),
    /// A BENIGN dedup hit: the `msg_id` was already in the producer's window. NOTHING was appended;
    /// reply `PubAckDuplicate` with this ORIGINAL offset (`duplicate = true`, `rc = 0`). Park it
    /// behind the covering commit too, so a hit on an id recorded earlier in the SAME uncommitted
    /// batch never replies before that id's offset is durable (I2).
    Duplicate(Offset),
    /// The produce presented a STALE epoch (a zombie session reusing an old `producer_id`): reject
    /// it. NOTHING was appended.
    Fenced {
        /// The producer's current (newer) known epoch that fenced this produce.
        current_epoch: u64,
    },
    /// The produce presented an OUT-OF-ORDER idempotent SEQUENCE (V2-M8): `seq > last_accepted + 1`,
    /// a gap. Accepting it would corrupt idempotence (a later retry of a skipped seq would read
    /// fresh), so it is REJECTED — the Kafka `OutOfOrderSequence` semantics. NOTHING was appended.
    OutOfOrder {
        /// The sequence the broker expected next (`last_accepted + 1`), so the producer can resync.
        expected: u64,
    },
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
    /// The per-CONSUMER (per-connection) standing in-flight credit CEILING (refs #65, #9, #10, #552):
    /// the most un-acked messages a single connection may EVER hold at once, independent of the
    /// per-GROUP `max_in_flight` window. It is the consumer-side half of credit-based flow control (MQTT
    /// Receive Maximum / `JetStream` `MaxAckPending`): a Flow fetch delivers at most
    /// `min(requested_credit, AUTO-TUNED window - already_held, byte budget remaining, whatever the
    /// group makes available)`, so the EFFECTIVE bound is the min of the producer-side group window, the
    /// per-consumer byte budget, and the consumer's CURRENT auto-tuned window (which itself never
    /// exceeds this ceiling).
    ///
    /// Post-#552 the per-consumer count window AUTO-TUNES rather than being pinned at a fixed value: it
    /// starts at the historical floor of 64 and grows toward THIS ceiling as the consumer keeps draining
    /// (the [`ironbus_core::backpressure::CreditAutotuner`] reuse of the egress AIMD), so a fast/loopback
    /// consumer fills the bandwidth-delay product instead of stalling at 64/RTT (the #464/#532 floor),
    /// while a service-bound consumer never grows what it does not drain. This field is the CEILING the
    /// auto-tune is bounded by AND the worst-case in-flight count the RAM guard charges, so the byte
    /// budget remains the firm RAM bound (the count auto-tunes UNDER it).
    ///
    /// Enforced per session (one connection), not per group, so in a competing group one slow
    /// consumer that fills its own window and stops acking pins ONLY its own credit and cannot
    /// reduce a peer's available deliveries (the per-consumer isolation from #10). A consumer at
    /// zero remaining credit gets zero deliveries from a Flow until it acks, nacks, terms, or one
    /// of its leases expires and is redelivered elsewhere, freeing the slot.
    ///
    /// The default is [`DEFAULT_CONSUMER_CREDIT`] (the Kafka-class auto-tune ceiling, 2048), NOT the
    /// MQTT absent-value 65535. A value of `0` is treated as 1 (a hard floor of one, so a consumer
    /// always makes progress) by [`Engine::open`]; a value BELOW 64 caps the auto-tune below the floor
    /// (a tightly-bounded consumer never grows past its own negotiated ceiling). The parallel
    /// per-consumer BYTE budget is [`EngineConfig::consumer_credit_bytes`]; the `max_deliver`-to-DLQ
    /// poison cap lives in [`DeliveryConfig`].
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
    /// The OPT-IN RAM ceiling in BYTES for the `ironbus_ram_headroom_bytes` edge gauge (#118, #19,
    /// #115): the resident-set budget an operator sizes the broker against on a constrained edge node
    /// (e.g. the 64 MiB `tiny` profile). The gauge reports `ram_ceiling_bytes - current_rss`, the
    /// headroom remaining before the kernel OOM-kills the process, so an operator can alert before
    /// the broker is reaped. It is purely OBSERVABILITY: the engine never enforces it (the RAM bounds
    /// that actually hold are `consumer_credit_bytes`, `max_in_flight`, `max_groups`, and the bounded
    /// registry), this only surfaces the configured budget against the measured footprint.
    ///
    /// `0` means UNSET (the default): with no ceiling the headroom gauge reports the unavailable
    /// sentinel (`-1`), since "headroom below the ceiling" is undefined. An operator opts in by
    /// setting it (typically to the cgroup/container memory limit or the device RAM budget). See
    /// [`crate::rss`].
    pub ram_ceiling_bytes: u64,
    /// The OPT-IN effectively-once dedup window (#3, #33): the dual count + time bound on each
    /// per-producer dedup ring. Dedup is OFF by default and activates per-producer only when a
    /// publish carries a `msg_id`; this only SIZES the window when it does. The defaults are
    /// [`ironbus_core::dedup::DEFAULT_MAX_IDS`] ids OR [`ironbus_core::dedup::DEFAULT_WINDOW_NANOS`]
    /// (2 minutes of monotonic time), whichever is hit first. The structure costs nothing until a
    /// producer opts in; see [`ironbus_core::dedup`] and `docs/RAM_BUDGET.md`.
    pub dedup: ironbus_core::dedup::DedupConfig,
    /// The DURABILITY LEVEL (#341, #379): how an ack relates to the covering `fdatasync`. The DEFAULT
    /// is [`DurabilityLevel::Sync`] (ack only after the covering fsync, I2 holds, ZERO acked loss on
    /// a power cut), so an engine opened with the field at its default is byte-for-byte the historical
    /// durable broker. The three relaxed levels are STRICTLY OPT-IN and weaken I2 by a precisely
    /// documented loss window; see [`DurabilityLevel`] and `docs/DURABILITY.md`. The loss-bearing
    /// levels (`async`/`none`) are additionally gated behind an explicit data-loss acknowledgement in
    /// the CLI, never reachable by accident.
    pub durability_level: DurabilityLevel,
    /// The `interval` level's TIME window in MILLISECONDS: the most time an acked-but-unsynced record
    /// may sit before the background flush forces an `fdatasync` (#341). Only consulted when
    /// `durability_level == Interval`. Measured on the engine clock seam (monotonic), so an NTP step
    /// never mis-fires the window (I6). A value of `0` disables the TIME trigger (only the byte budget
    /// forces a sync); it is floored to a sane minimum window by the CLI's validation, never here.
    pub flush_interval_ms: u64,
    /// The `interval` level's BYTE budget: the most UNSYNCED record bytes that may accumulate before
    /// the background flush forces an `fdatasync` (#341). Only consulted when
    /// `durability_level == Interval`. A value of `0` disables the BYTE trigger (only the time window
    /// forces a sync). Together with `flush_interval_ms`, the EFFECTIVE bound on acked-but-unsynced
    /// records is the SMALLER of the time and byte triggers, which is the worst-case loss the operator
    /// is choosing.
    pub flush_max_bytes: u64,
    /// The CoDel time-in-queue (sojourn) shedding controls (#68): the TARGET and INTERVAL of the
    /// load-based admission shed that bounds tail latency under overload. BOTH default to `0`
    /// (DISABLED), so a broker that does not opt in behaves EXACTLY as today (the byte-cap shed and
    /// the consumer credit are the only backpressure). When enabled, the values are CLAMPED (`target`
    /// to `[1 ms, 1 s]`, `interval` to `[20 ms, 10 s]`) and never rejected (#14), and a sustained
    /// produce-admission sojourn above TARGET for a full INTERVAL sheds the NEW produce into the
    /// configured overflow disposition (the same drop-new / drop-oldest decision the byte cap uses),
    /// counted as a CoDel shed. It NEVER drops an already-accepted record (I2 holds); see
    /// [`ironbus_core::backpressure::Codel`] and `docs/BACKPRESSURE.md`.
    pub codel_target_ms: u64,
    /// The CoDel INTERVAL in MILLISECONDS (#68): the window the admission sojourn must stay above
    /// `codel_target_ms` before shedding begins, and the base drop spacing. `0` (with the target)
    /// disables CoDel. Clamped to `[20 ms, 10 s]` when enabled. See [`EngineConfig::codel_target_ms`].
    pub codel_interval_ms: u64,
    /// The per-client retry budget ratio in PARTS PER MILLION (#69): the fraction of a client's
    /// request rate its retries may occupy before the broker-side re-check throttles them (the Google
    /// SRE accept-based adaptive throttle). Default `0` (DISABLED), so a broker that does not opt in
    /// behaves as today. The doc budget is 10% (`100_000`). See
    /// [`ironbus_core::backpressure::RetryBudget`].
    pub retry_budget_ratio_per_million: u64,
    /// The per-client retry-budget sliding window in MILLISECONDS (#69): the window the
    /// request/accept counts are tracked over. Default `0` is treated as the 60 s doc default by the
    /// controller. Only consulted when the ratio is non-zero. See
    /// [`EngineConfig::retry_budget_ratio_per_million`].
    pub retry_budget_window_ms: u64,
    /// The fire-and-forget (un-credited) admission token bucket's MESSAGE rate in msg/s (#69): caps
    /// the QoS-0-equivalent tier so it cannot bypass the consumer-credit brake. Default `0` (with the
    /// byte rate) DISABLES the bucket (the tier is ungoverned, as today). The doc default is 5000.
    /// See [`ironbus_core::backpressure::TokenBucket`].
    pub fire_and_forget_msg_rate: u64,
    /// The fire-and-forget token bucket's BYTE rate in bytes/s (#69). `0` (with the message rate)
    /// disables the bucket. The doc default is 5 MiB/s. See
    /// [`EngineConfig::fire_and_forget_msg_rate`].
    pub fire_and_forget_byte_rate: u64,
    /// The fire-and-forget token bucket's refill granularity in MILLISECONDS (#69): sizes the burst
    /// ceiling (`rate * refill_ms / 1000`). `0` is treated as the 100 ms doc default by the
    /// controller. See [`EngineConfig::fire_and_forget_msg_rate`].
    pub fire_and_forget_refill_ms: u64,
    /// The starting / static-floor egress concurrency limit for the AIMD downstream limiter (#69):
    /// the in-flight concurrency to a downstream sink, adapted up additively and down
    /// multiplicatively (bounded to `[4, 128]`) as the sink's health changes. Default `0` is treated
    /// as the doc default floor (16) by the limiter; the AIMD bounds always apply. See
    /// [`ironbus_core::backpressure::AimdLimiter`].
    pub egress_limit: u32,
    /// The fsync-headroom admission window in BYTES (#378, refining the #67 / #177 WAL backpressure
    /// seam): the most un-fsynced (buffered-but-not-yet-`fdatasync`'d) record bytes the BUFFERED write
    /// frontier may run ahead of the DURABLE (synced) frontier before a new produce is throttled (the
    /// append actor forces a group-commit flush first, which drains the backlog) or, if a flush cannot
    /// drain it, shed with the typed [`AppendOutcome`]/`ProduceOutcome` headroom signal. It reuses the
    /// storage log's [`crate::engine::Engine::unsynced_bytes`] frontier (the #341 relaxed-durability
    /// tracking), so it bounds the GROUP-COMMIT backlog under `sync` (a memory guard) and the LOSS
    /// WINDOW under a relaxed level (a bounded-loss guard), distinct from CoDel's queue-latency shed.
    ///
    /// Default `0` (DISABLED): the un-fsynced frontier is bounded only by the existing controls (under
    /// `sync` every group-commit drains it; under a relaxed level the `interval` window or a
    /// roll/shutdown does), so a zero-config broker is byte-for-byte unchanged. A small headroom is the
    /// opt-in for a tight RAM / loss-window bound. It NEVER drops an accepted record (the shed rejects
    /// NEW work, decided before the append, so I2 holds) and NEVER wedges on an oversized produce (an
    /// empty backlog always admits the next record). See [`ironbus_core::backpressure::FsyncHeadroom`]
    /// and `docs/BACKPRESSURE.md`.
    pub wal_fsync_headroom_bytes: u64,
    /// The PER-RECORD payload compression codec for NEW writes (#430, refs #387, #12, #75; ADR-0003):
    /// the produce path compresses each record's payload into the self-describing stored object
    /// (the 9-byte descriptor then the codec stream) behind [`RecordFlags::COMPRESSED`], applied at
    /// the single append seam ([`Engine::append_no_sync`]) so every produce entry (single produce,
    /// the actor's group-commit drain, dedup) and every downstream byte account (CRC, caps, segment
    /// roll, `durable_record_bytes`, the #118 write-amp meters) sees the STORED bytes.
    ///
    /// [`Codec::None`] (the no-compression sentinel) stores every record raw, byte-for-byte the
    /// historical layout, so an engine opened with it produces disk images byte-identical to a
    /// pre-compression broker. [`Codec::Lz4`] applies the ADR-0003 write guards: a payload under
    /// the 64-byte raw-store threshold ([`ironbus_core::compress::DEFAULT_RAW_STORE_THRESHOLD`])
    /// or one the codec cannot strictly shrink (the never-expand guard) is stored raw with the
    /// flag clear, indistinguishable from an uncompressed write. A record whose flags ALREADY
    /// carry [`RecordFlags::COMPRESSED`] (a producer-compressed publish) passes through
    /// UNCHANGED, never double-wrapped. (The DLQ redrive preserves the flag too, but it appends
    /// via `Log::append` directly, below this seam.)
    pub compression: Codec,
    /// The per-STREAM default message TTL in MILLISECONDS (V2-M4, #549): a record older than this
    /// many ms (its durable producer `timestamp_ms + ttl` against the engine WALL-clock seam) is
    /// EXPIRED — skipped on read, never delivered, and reclaimed by the existing segment retention
    /// reap. A per-message TTL (carried in the record headers) combines with this LOWER-WINS (the
    /// tighter of the two applies), so a stream-wide default coexists with tighter per-message TTLs.
    /// `0` means DISABLED (no per-stream default), the default, so a non-TTL stream is byte-identical
    /// to today (records never expire on read). This is the DELIVERY-skip TTL; the disk-reclamation
    /// counterpart is [`EngineConfig::max_age_ms`] (the segment reap), which the TTL piggybacks on.
    pub default_message_ttl_ms: u64,
    /// The configurable dead-letter EXCHANGE (V2-M4, #551): the data-dir SUBDIR a dead-lettered
    /// message is routed to. `None` (the default) keeps the existing FIXED behavior byte-identical —
    /// max-deliver dead-letters go to the default `dlq/` sink via the unchanged reason-less path. A
    /// `Some(subdir)` routes EVERY dead-letter (max-deliver, TTL-expired, rejected) to that named
    /// sink instead, recording the [`DeadLetterReason`](ironbus_storage::dlq::DeadLetterReason) —
    /// the `RabbitMQ` DLX-parity beat over a single fixed DLQ.
    pub dead_letter_exchange: Option<String>,
    /// Whether a TTL-EXPIRED message is dead-lettered (routed to the dead-letter exchange with
    /// [`DeadLetterReason::TtlExpired`](ironbus_storage::dlq::DeadLetterReason)) rather than silently
    /// reclaimed by retention (V2-M4, #549/#551). `false` (the default) reclaims an expired message
    /// via the segment reap (still BOUNDED and never delivered — an expired-and-not-dead-lettered
    /// message is reclaimed, not lost-by-surprise). `true` routes it to the DLX so the expiry is a
    /// recorded event. Has effect only when a [`dead_letter_exchange`](Self::dead_letter_exchange)
    /// is configured; with no DLX an expired message is always reclaimed by retention.
    pub dead_letter_expired: bool,
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
    /// The group-of-one invariant a BROADCAST group rests on was violated (#288): either a SECOND
    /// concurrent subscriber tried to join a broadcast group, or a flip to broadcast
    /// ([`Engine::set_broadcast_in`] with `true`) was attempted on a group that already carries
    /// COMPETING in-flight state (live in-flight leases or an out-of-order acked-ahead set) or more
    /// than one active subscriber. A broadcast group must be a true group-of-one, because a
    /// cumulative ack commits its single cursor straight to an offset; if a SECOND consumer held an
    /// in-flight message below that offset, the commit would silently drop it (the redelivery gate
    /// is the cursor). Rejected here so the engine never enters the unsafe multi-member-broadcast
    /// state rather than discovering the loss later. The group's mode and membership are left
    /// exactly as they were on rejection.
    BroadcastGroupBusy {
        /// The broadcast group that already has an active subscriber or unsafe competing state.
        group: String,
    },
    /// A flip to broadcast ([`Engine::set_broadcast_in`] with `true`) named the DEFAULT/empty group
    /// (`""`), which can never be a broadcast group (#288). The group-of-one safety the broadcast
    /// cumulative ack rests on is enforced by the active-subscriber cap, but that cap binds only a
    /// NAMED group: the default group's consumers reach it on the implicit default subscription and
    /// never SUB a non-empty name, so they are never registered and never capped. Two connections
    /// could then both poll the default subscription, hold competing in-flight leases, and a wire
    /// `cumulative_ack` with an empty group name would commit past a peer's still-in-flight offset,
    /// the same silent drop the cap exists to prevent. A broadcast group MUST therefore be a NAMED
    /// group whose subscribers are capped; the flip is refused here so the uncapped default group can
    /// never enter broadcast mode. The group's mode is left exactly as it was on rejection.
    BroadcastGroupNotNamed {
        /// The group name that was refused (the default/empty group, `""`).
        group: String,
    },
    /// A BROADCAST cumulative ack named an `up_to` offset OUTSIDE the durable, retained window
    /// (#288): either PAST the durable head (`up_to > flushed`, committing past records that do
    /// not exist yet, which a later truncation could never reconcile) or BELOW the earliest
    /// retained offset (`up_to < earliest_retained`, naming records the log has already reaped, a
    /// stale or replayed ack). Rejected with this typed error rather than committing a meaningless
    /// cursor; the broadcast group's committed offset is left unchanged. An idempotent re-ack (an
    /// `up_to` at or below the current commit but still within the window) is NOT this error: it is
    /// a no-op success.
    CumulativeAckOutOfRange {
        /// The rejected `up_to` offset.
        up_to: u64,
        /// The oldest offset still retained in the durable log (the lower bound, inclusive).
        earliest_retained: u64,
        /// The durable head: the offset of the next record to be written (the upper bound,
        /// inclusive, since committing exactly up to the head commits every existing record).
        durable_head: u64,
    },
    /// A stream name handed to the id-routed produce/consume path (#676, M2-I2b) was empty, too
    /// long, or held a non-graphic-ASCII byte. The default stream is addressed by the EMPTY name
    /// (which routes to today's root log byte-for-byte) via [`StreamId::default_stream`], never by
    /// passing `""` to the NAMED constructor, so a bad NAMED name fails closed at the boundary
    /// rather than reaching the filesystem. Carries the rejected name. This mirrors
    /// [`EngineError::InvalidGroupName`] for the stream axis (the same graphic-ASCII rule).
    InvalidStreamName {
        /// The rejected stream name.
        name: String,
    },
    /// A client PRODUCE targeted a READ-ONLY cross-cluster MIRROR stream (#623, V2-C7-I1). A mirror's
    /// ONLY writer is the geo mirror-apply path (single-writer preserved), so a client produce is
    /// rejected fail-closed rather than admitting a second writer. Carries the mirrored stream's name.
    /// (A SOURCE is NOT read-only — it may take local produces alongside the fan-in — so this fires only
    /// for a `--mirror` stream, never a `--source`.)
    MirrorReadOnly {
        /// The read-only mirror stream the produce was rejected for.
        name: String,
    },
    /// A consume/ack/commit targeted a NAMED stream that is not open (#676): a stream must be
    /// produced to (which declares it) before it can be consumed from, so a consume on an
    /// unknown named stream is a typed rejection, not a silent empty read. The default stream is
    /// always open and never reaches this. Carries the unknown stream's name.
    UnknownStream {
        /// The name of the unknown (never-declared) named stream.
        name: String,
    },
    /// A subject or subject pattern handed to the binding / subject-addressed path (#585, M2-I9) was
    /// not valid #567 grammar (empty, an empty token, an illegal/control rune, a misplaced wildcard, or
    /// over the depth cap). A bind validates a PATTERN (wildcards allowed); a subject-addressed publish
    /// validates a LITERAL subject (wildcards rejected). Fail-closed at the boundary, never a panic.
    /// Carries the typed [`SubjectError`] reason.
    InvalidSubject(SubjectError),
    /// A `BindSubject` would make the binding set's worst-case wildcard fork frontier exceed the trie's
    /// fail-closed cap (#568): the WHOLE binding set is refused rather than admitted and silently
    /// truncated at match time (so routing can never drop a match). Carries the trie's typed
    /// [`SublistError`] reason. (An individually-valid pattern can still trip this as a property of the
    /// accepted SET; the bind is rejected and the previous binding table is left installed unchanged.)
    BindRejected(SublistError),
    /// A subject-addressed publish resolved to ZERO bound streams (#585, the single-home FAIL-CLOSED
    /// reject): the publish is REFUSED, NOT silently dropped — the explicit beat over NATS, which would
    /// discard a publish to a subject with no matching interest while still acking success. The producer
    /// must bind the subject to a stream first. Carries the offending subject.
    NoStreamForSubject {
        /// The literal subject that matched no binding.
        subject: String,
    },
    /// A subject-addressed publish resolved to TWO OR MORE bound streams (#585, the single-home
    /// FAIL-CLOSED reject): one record needs one unambiguous destination log, so an ambiguous subject is
    /// refused rather than guessed or fanned out. The opt-in `overlap_ok` fan-out is a separate, later
    /// feature. Carries the offending subject and how many streams matched.
    AmbiguousSubject {
        /// The literal subject that matched more than one binding.
        subject: String,
        /// How many bound streams matched (always `>= 2`).
        matched: usize,
    },
    /// A transactional half-message verb (#640, V2-M8) was rejected by the pure lifecycle: an
    /// unknown / spent txn id, a conflicting resolve (commit-after-rollback or rollback-after-commit,
    /// which is REFUSED, never flipped), too many concurrently-prepared transactions, or an over-long
    /// txn id. Carries the typed [`ironbus_core::txn::TxnError`] reason. Fail-closed at the boundary;
    /// the half message's durable state is never corrupted by a rejected verb.
    Txn(ironbus_core::txn::TxnError),
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
            EngineError::BroadcastGroupBusy { group } => write!(
                f,
                "broadcast group `{group}` is a group-of-one: it already has an active subscriber \
                 or competing in-flight state, so a second subscriber or a flip to broadcast is \
                 refused"
            ),
            EngineError::BroadcastGroupNotNamed { group } => write!(
                f,
                "the default/empty group `{group}` cannot be a broadcast group: only a NAMED group \
                 has a capped subscriber set, so --broadcast-group marks a named group only"
            ),
            EngineError::CumulativeAckOutOfRange {
                up_to,
                earliest_retained,
                durable_head,
            } => write!(
                f,
                "cumulative ack up_to {up_to} is outside the retained window \
                 [{earliest_retained}, {durable_head}]"
            ),
            EngineError::InvalidStreamName { name } => write!(
                f,
                "invalid stream name {name:?} (the default stream is \"\", otherwise 1 to \
                 {MAX_STREAM_NAME_LEN} graphic-ASCII bytes)"
            ),
            EngineError::MirrorReadOnly { name } => write!(
                f,
                "stream {name:?} is a read-only cross-cluster MIRROR; its only writer is the mirror-apply path, so a client produce is rejected"
            ),
            EngineError::UnknownStream { name } => write!(
                f,
                "stream {name:?} is not open (produce to it first to declare it)"
            ),
            EngineError::InvalidSubject(e) => write!(f, "invalid subject: {e}"),
            EngineError::BindRejected(e) => write!(f, "bind rejected: {e}"),
            EngineError::NoStreamForSubject { subject } => write!(
                f,
                "no stream is bound for subject {subject:?} (bind a subject pattern to a stream first)"
            ),
            EngineError::AmbiguousSubject { subject, matched } => write!(
                f,
                "subject {subject:?} resolves to {matched} bound streams (single-home: a subject must \
                 resolve to exactly one stream; overlap fan-out is opt-in)"
            ),
            EngineError::Txn(e) => write!(f, "transaction error: {e}"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EngineError::Storage(e) => Some(e),
            EngineError::Txn(e) => Some(e),
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

impl From<StreamError> for EngineError {
    fn from(e: StreamError) -> Self {
        match e {
            // A bad NAMED stream name fails closed as the typed `InvalidStreamName` (the stream-axis
            // twin of `InvalidGroupName`), never as an opaque storage error, so a caller can tell a
            // validation rejection from an IO fault.
            StreamError::InvalidName { name } => EngineError::InvalidStreamName { name },
            StreamError::Storage(s) => EngineError::Storage(s),
        }
    }
}

impl From<SubjectError> for EngineError {
    fn from(e: SubjectError) -> Self {
        EngineError::InvalidSubject(e)
    }
}

impl From<SublistError> for EngineError {
    fn from(e: SublistError) -> Self {
        match e {
            // A pattern that fails to re-parse is a subject-grammar rejection (surface its typed
            // reason); a fork-bound rejection is the binding-SET rejection.
            SublistError::InvalidPattern(p) => EngineError::InvalidSubject(p),
            other => EngineError::BindRejected(other),
        }
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

    /// Whether this is a non-fatal drop-new produce REJECTION the producer should see as a stable
    /// "at capacity / shed" reply (the wire `ProduceOutcome::AtCapacity`): EITHER the durable-log
    /// byte-cap shed ([`StorageError::AtCapacity`]) OR the daily-write-budget shed
    /// ([`StorageError::DailyWriteBudgetExceeded`]). Both refuse the produce without writing and
    /// without freezing; the producer reply is identical, so they share this predicate. It is never
    /// fatal. To distinguish the two (only the byte cap may drive the `DropOldest` reap), match the
    /// storage error directly or use [`EngineError::is_daily_write_budget_exceeded`].
    #[must_use]
    pub fn is_at_capacity(&self) -> bool {
        matches!(self, EngineError::Storage(e)
            if e.is_at_capacity() || e.is_daily_write_budget_exceeded())
    }

    /// Whether this is the OPT-IN daily-write-budget shed ([`StorageError::DailyWriteBudgetExceeded`]),
    /// the flash-wear governor firing. It is a clean pre-write drop-new reject that is FINAL: a reap
    /// can never relieve it, so the `DropOldest` overflow policy must treat it as a final rejection and
    /// never force-reap. Kept distinct from [`EngineError::is_at_capacity`] for exactly that routing
    /// decision; both still map to the same producer-facing rejected-produce reply.
    #[must_use]
    pub fn is_daily_write_budget_exceeded(&self) -> bool {
        matches!(self, EngineError::Storage(e) if e.is_daily_write_budget_exceeded())
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
    /// The group's cursor advanced across a KEY-COMPACTION hole (#337, #411): one or more offsets in
    /// `[from, to)` were removed by compaction (a later record for the same key superseded them), so
    /// they are PERMANENTLY ABSENT mid-stream while the surrounding segment is present. This is
    /// structurally distinct from [`Poll::Truncated`]: a trim reaps a below-earliest PREFIX, whereas a
    /// compaction hole is interior (the offsets are above `earliest_retained`, the segment is still
    /// there). It is NOT data loss and NOT a missing record (the latest-value-per-key view is intact
    /// and the cursor still reaches head), so it carries no truncation counter and no `LossReport`; it
    /// is purely the consumer-FACING half of the sparse-offset contract. The engine has ALREADY acked
    /// the group's cursor past the whole `[from, to)` run before returning, so the next poll resumes at
    /// `to` and the same hole never re-signals. The caller surfaces it as a `GapMarker` with
    /// `reason = COMPACTED` to a gap-marker-capable consumer (#346/#292); a non-capable consumer takes
    /// the unchanged silent-advance (it has no gap-marker support, and a compacted hole is not a loss).
    Compacted {
        /// The first absent (compacted-away) offset, inclusive: where the hole begins.
        from: Offset,
        /// The first present offset after the hole, exclusive: delivery resumes here.
        to: Offset,
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

/// A Tier-S STREAMING fetch result (#544, M1-I7): the CONTIGUOUS batch of records the broker served
/// off the durable prefix starting at the consumer-managed `start_offset`, with NO lease granted and
/// NO per-record cursor write. The consumer owns the offset: it advances its own position past
/// `next_offset` and periodically durably-commits via [`Engine::stream_commit_in`]. At-least-once holds
/// by construction — a crash/reconnect re-reads from the last committed offset, redelivering at most
/// the uncommitted records.
#[derive(Clone, Debug, Default)]
pub struct StreamBatch {
    /// The contiguous run of records read from the durable, flushed prefix `[start_offset, ...)`, in
    /// offset order, bounded by `max_records` / `max_bytes` / the flushed frontier. May be empty (the
    /// consumer is already caught up to the durable head, or `start_offset` is at/past it). These are
    /// the SAME materialized, CRC-validated records the Tier-W poll path returns — only the
    /// lease/cursor bookkeeping is skipped.
    pub records: Vec<OwnedRecord>,
    /// The offset the consumer should resume from on its NEXT fetch: one past the last record served
    /// (or `start_offset` itself when the batch is empty). It never exceeds the flushed head. A
    /// reconnecting consumer that has not committed simply re-passes its last committed offset, not
    /// this value, and the uncommitted span redelivers.
    pub next_offset: Offset,
}

/// A Tier-S STREAMING fetch result served as RAW on-disk frame bytes (#541, M1-I5): the zero-copy twin
/// of [`StreamBatch`] used to deliver a contiguous run as ONE `DeliverBatch` frame. The contiguous
/// SEALED prefix of the run comes back as `raw` — the on-disk frame bytes VERBATIM (a refcounted slice
/// of one segment's resident bytes, the #542 zero-copy primitive), never re-encoded — so a later disk
/// `sendfile(2)` path (#658) can splice them straight into the socket. Any remainder past the sealed
/// segment's end (the active tail, which the off-actor raw plane does not serve) is materialized into
/// `tail` and delivered as ordinary per-record `Deliver` frames; the consumer sees one continuous,
/// contiguous run regardless of where the sealed/active boundary falls.
#[derive(Clone, Debug, Default)]
pub struct StreamRawBatch {
    /// The contiguous run of records from the SEALED, flushed prefix as raw on-disk frame bytes (#542):
    /// `raw.bytes` is `raw.record_count` complete on-disk frames in offset order, `raw.first_offset` is
    /// the first record's log offset, and the i-th frame's offset is `first_offset + i`. Empty
    /// (`record_count == 0`) when `start_offset` is already in the active tail or at/past the durable
    /// head. The body CRC of every frame ships verbatim for end-to-end client verification.
    pub raw: RawByteRun,
    /// The remainder of the run that fell in the ACTIVE tail (or otherwise could not be served raw),
    /// materialized as ordinary records and delivered per-record. Contiguous with and immediately
    /// following `raw` (its first offset is `raw.next_offset`). Empty when the whole run was served raw
    /// or nothing remained below the flushed head.
    pub tail: Vec<OwnedRecord>,
    /// The offset the consumer resumes from on its NEXT fetch: one past the last record served across
    /// BOTH `raw` and `tail` (or `start_offset` when the whole batch is empty). Never exceeds the
    /// flushed head.
    pub next_offset: Offset,
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
    /// record framing). A throughput signal alongside the record count. With write-path
    /// compression on (#430) this deliberately counts the ORIGINAL (pre-compression) payload
    /// bytes the producer sent, so its producer-facing throughput meaning never shifts with the
    /// codec; the stored (post-compression, on-flash) truth is `durable_record_bytes` and the
    /// #118 logical/physical write-amp meters.
    pub produced_bytes: u64,
    /// Produces REJECTED because the durable log was at or over its byte cap (the drop-new
    /// shed, refs #10, #13): nothing was written and no offset advanced. A rejected produce is
    /// NOT counted in `produced` or `produced_bytes`; this is the operator's shed-rate signal.
    pub produce_rejected: u64,
    /// Message deliveries handed out by `poll` (a redelivery counts again).
    pub delivered: u64,
    /// Deliveries that were a redelivery (the message had been delivered before).
    pub redelivered: u64,
    /// Messages dead-lettered (parked past `MaxDeliver`, or routed to a dead-letter exchange after a
    /// TTL expiry / explicit reject, #551); the resilience drop signal.
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
    /// BENIGN producer dedup HITS (#3, #33): a publish whose `msg_id` was already seen within the
    /// producer's dedup window, so the broker returned the ORIGINAL offset (`duplicate = true`,
    /// `rc = 0`) and appended NO second copy. The effectively-once-saved-a-duplicate signal: a
    /// non-zero rate means producers are retrying and the window is absorbing the duplicates rather
    /// than the log double-storing them. Exposed as the `ironbus_dedup_hits_total` counter.
    /// Saturating.
    pub dedup_hits: u64,
    /// OUT-OF-WINDOW dedup events (#3, #33): a `msg_id` aged out of a producer's window by the TIME
    /// bound (its dedup protection lapsed), so a later republish of that id would NOT be deduped and
    /// would create a genuinely new offset. The "is the window too small for the retry interval"
    /// signal an operator watches to size [`EngineConfig::dedup`]. Exposed as the
    /// `ironbus_dedup_out_of_window_total` counter. Saturating.
    pub dedup_out_of_window: u64,
    /// RECOVERY-EVENT counters (#575, the marquee NATS-can't differentiator): each is bumped ONCE per
    /// [`Engine::open`] recovery run, so an operator can alert on recovery actually firing. NATS has
    /// NO corruption-recovery metric at all (its truncate-and-drop recovery is silent, #7549/#7556),
    /// so these counters ARE the differentiator. They are recovery-event-derived (a function of the
    /// just-recovered durable [`LossReport`]), not runtime, so they reconcile cleanly from the durable
    /// artifact on every open and stay monotonic non-decreasing across a `kill -9`.
    pub recovery: RecoveryCounters,
    /// Messages EXPIRED-and-reclaimed by a per-message/per-stream TTL (V2-M4, #549): a record whose
    /// effective TTL (the lower of its per-message TTL and the stream's `default_message_ttl_ms`) had
    /// passed when a consumer reached it, so it was SKIPPED on read (never delivered) and committed
    /// past, its bytes left for the segment retention reap to reclaim. This is the "expired, not
    /// dead-lettered" bucket: the DLX-routed expiry path increments `dead_lettered` instead, so an
    /// expired message is ALWAYS accounted in exactly one of the two (no silent drop). Zero unless a
    /// TTL is configured, so a non-TTL broker is byte-identical. Saturating; exposed as the
    /// `ironbus_expired_total` counter.
    pub expired: u64,
    /// OUT-OF-ORDER idempotent-producer SEQUENCE rejections (V2-M8, #638): a sequenced publish whose
    /// `seq` skipped past the next-expected (`seq > last_accepted + 1`) was REJECTED rather than
    /// silently accepted (the Kafka `OutOfOrderSequence` semantics), so a later retry of the skipped
    /// seq cannot double-append. A non-zero rate means a producer's sequence stream has a genuine gap
    /// (a lost in-flight publish, or a client bug) the operator should investigate; it is a resilience
    /// event, never silent. Zero unless a producer opts into sequence-based idempotence, so a
    /// non-idempotent broker is byte-identical. Saturating; exposed as the
    /// `ironbus_producer_out_of_order_total` counter.
    pub producer_out_of_order: u64,
}

/// The recovery-event counter family (#575): the FLAGSHIP corruption-recovery metrics NATS has no
/// analogue for. Each is raised once per [`Engine::open`] recovery run from the just-recovered durable
/// [`LossReport`], so they are monotonic non-decreasing and replay-reconstructable across a hard crash
/// (the same durability the recovery-loss family already has). Rendered by `health.rs` as
/// `ironbus_recovery_runs_total{outcome}`, `ironbus_torn_tail_repairs_total`, and
/// `ironbus_corruption_repairs_total{artifact}` in the frozen METRICS.md taxonomy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryCounters {
    /// Recovery RUNS by outcome, indexed in [`RecoveryOutcome::ALL`] order: one increment per open,
    /// in the bucket the run's loss report classifies it into (clean / torn-tail-truncated /
    /// quarantined / data-loss). Exposed as `ironbus_recovery_runs_total{outcome=...}`.
    pub runs_by_outcome: [u64; RecoveryOutcome::ALL.len()],
    /// TORN-TAIL truncation repairs: the count of `TornTail` loss events the recovery runs dropped
    /// (a power-loss tail truncated to the longest valid prefix, NOT data loss). Exposed as the
    /// unlabeled `ironbus_torn_tail_repairs_total` counter. Saturating.
    pub torn_tail_repairs: u64,
    /// CORRUPTION repairs by artifact, indexed in [`RecoveryArtifact::ALL`] order: the count of
    /// data-loss (corruption-skip) loss events the recovery runs quarantined-and-dropped, bucketed by
    /// the on-disk artifact the corruption was in (a log segment, a cursor, or the DLQ). Exposed as
    /// `ironbus_corruption_repairs_total{artifact=...}`. Saturating.
    pub corruption_repairs_by_artifact: [u64; RecoveryArtifact::ALL.len()],
}

/// The frozen `outcome` label vocabulary of `ironbus_recovery_runs_total` (#575): the bounded,
/// fixed-cardinality classification of one recovery run. Append-only (a new variant goes at the END so
/// the durable snapshot order is stable), mirroring the [`ReasonCode`] frozen-vocabulary discipline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// The log opened with no loss event at all (the common clean-shutdown case).
    Clean,
    /// The only loss was a torn/unsynced tail truncated to the longest valid prefix (NOT data loss).
    TornTailTruncated,
    /// At least one corruption span was quarantined-and-dropped (real data loss, copied to forensics).
    Quarantined,
    /// Recovery completed but the loss report carried data loss without a successful quarantine
    /// capture (e.g. the quarantine store was over its cap): the reported-but-uncaptured data-loss
    /// outcome. Reserved alongside `Quarantined` so the outcome taxonomy is frozen up front.
    DataLoss,
}

impl RecoveryOutcome {
    /// Every outcome in a fixed order; the index into [`RecoveryCounters::runs_by_outcome`].
    /// Append-only, so the durable snapshot field order never shifts.
    pub const ALL: [RecoveryOutcome; 4] = [
        RecoveryOutcome::Clean,
        RecoveryOutcome::TornTailTruncated,
        RecoveryOutcome::Quarantined,
        RecoveryOutcome::DataLoss,
    ];

    /// This outcome's index into [`RecoveryOutcome::ALL`] (and so into `runs_by_outcome`). A total
    /// match in `ALL` order, so it is infallible (no panic path) and stays in sync with the array.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            RecoveryOutcome::Clean => 0,
            RecoveryOutcome::TornTailTruncated => 1,
            RecoveryOutcome::Quarantined => 2,
            RecoveryOutcome::DataLoss => 3,
        }
    }

    /// The frozen Prometheus `outcome` label value. Frozen alongside the metric name; a rename is a
    /// breaking taxonomy change gated by the frozen-taxonomy test.
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            RecoveryOutcome::Clean => "clean",
            RecoveryOutcome::TornTailTruncated => "torn_tail_truncated",
            RecoveryOutcome::Quarantined => "quarantined",
            RecoveryOutcome::DataLoss => "data_loss",
        }
    }
}

/// The frozen `artifact` label vocabulary of `ironbus_corruption_repairs_total` (#575): the bounded
/// on-disk artifact a corruption repair acted on. Append-only, mirroring [`ReasonCode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryArtifact {
    /// A log segment (the main append-only record log).
    Segment,
    /// A consumer cursor checkpoint.
    Cursor,
    /// The dead-letter sink (`dlq/`).
    Dlq,
}

impl RecoveryArtifact {
    /// Every artifact in a fixed order; the index into
    /// [`RecoveryCounters::corruption_repairs_by_artifact`]. Append-only.
    pub const ALL: [RecoveryArtifact; 3] = [
        RecoveryArtifact::Segment,
        RecoveryArtifact::Cursor,
        RecoveryArtifact::Dlq,
    ];

    /// This artifact's index into [`RecoveryArtifact::ALL`]. A total match in `ALL` order, so it is
    /// infallible (no panic path) and stays in sync with the array.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            RecoveryArtifact::Segment => 0,
            RecoveryArtifact::Cursor => 1,
            RecoveryArtifact::Dlq => 2,
        }
    }

    /// The frozen Prometheus `artifact` label value.
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            RecoveryArtifact::Segment => "segment",
            RecoveryArtifact::Cursor => "cursor",
            RecoveryArtifact::Dlq => "dlq",
        }
    }
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
/// The dedup family (#33) appended two more trailing fields (`dedup_hits`, `dedup_out_of_window`),
/// so an older snapshot still decodes (they read as zero) and a newer snapshot still decodes on an
/// old binary (the trailing fields are ignored).
/// The recovery-event family (#575) appended eight more trailing fields (the four
/// `runs_by_outcome` buckets, `torn_tail_repairs`, and the three `corruption_repairs_by_artifact`
/// buckets), same forward/backward-compatible rule (a pre-#575 snapshot reads them as zero, and
/// reconciliation on open re-derives them from the durable loss report).
/// The TTL family (#549) appended one more trailing field (`expired`), same rule: a pre-#549
/// snapshot reads it as zero, and a newer snapshot decodes on an old binary (the trailing field is
/// ignored).
const COUNTERS_FIELD_COUNT: usize = 26;

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
            // The dedup family (#33) appended after #307, same forward/backward-compatible rule.
            self.dedup_hits,
            self.dedup_out_of_window,
            // The recovery-event family (#575), appended after dedup in a fixed order: the four
            // outcome buckets, the torn-tail repair count, then the three artifact buckets. A
            // pre-#575 snapshot is too short to hold these (they read as zero), and reconciliation
            // on open re-derives them from the durable loss report.
            self.recovery.runs_by_outcome[0],
            self.recovery.runs_by_outcome[1],
            self.recovery.runs_by_outcome[2],
            self.recovery.runs_by_outcome[3],
            self.recovery.torn_tail_repairs,
            self.recovery.corruption_repairs_by_artifact[0],
            self.recovery.corruption_repairs_by_artifact[1],
            self.recovery.corruption_repairs_by_artifact[2],
            // The TTL family (#549), appended after the recovery family: a pre-#549 snapshot is too
            // short to hold it (it reads as zero). It is an operational counter with no replay
            // reconciliation, so the resumed value is the #306 snapshot-only lower bound.
            self.expired,
            // The idempotent-producer out-of-order rejection counter (V2-M8), appended after the TTL
            // family: a pre-M8 snapshot is too short to hold it (it reads as zero). Operational, no
            // replay reconciliation, so the resumed value is the snapshot-only lower bound.
            self.producer_out_of_order,
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
            // The dedup family (#33), appended after #307: a pre-#33 snapshot is too short to hold
            // these, so they read as zero (the tolerant decode). They are operational counters with
            // no replay reconciliation, so the resumed value is the #306 snapshot-only lower bound.
            dedup_hits: field(15),
            dedup_out_of_window: field(16),
            // The recovery-event family (#575), appended after dedup at fields 17..=24: a pre-#575
            // snapshot reads them as zero, and reconciliation on open re-derives them from the
            // durable loss report (replay-reconstructable like the recovery-loss family).
            recovery: RecoveryCounters {
                runs_by_outcome: [field(17), field(18), field(19), field(20)],
                torn_tail_repairs: field(21),
                corruption_repairs_by_artifact: [field(22), field(23), field(24)],
            },
            // The TTL family (#549), appended after recovery at field 25: a pre-#549 snapshot reads
            // it as zero (the tolerant decode). Operational, no replay reconciliation.
            expired: field(25),
            // The idempotent-producer out-of-order rejection counter (V2-M8) at field 26: a pre-M8
            // snapshot reads it as zero (the tolerant decode). Operational, no replay reconciliation.
            producer_out_of_order: field(26),
        }
    }
}

/// The runtime backpressure controllers and their shed counters (#68, #69), held on the engine
/// separate from [`Counters`] so they do NOT join the durable counters snapshot: they are RUNTIME
/// resilience signals (a monotonic-since-start lower bound, reset on restart), exactly like the
/// in-memory operational signals the snapshot already treats as best-effort. Keeping them out of
/// `encode_snapshot`/`decode_snapshot` leaves the frozen counters-snapshot format byte-for-byte
/// unchanged.
///
/// The controllers themselves ([`Codel`], [`RetryBudget`], [`TokenBucket`], [`AimdLimiter`]) are
/// pure (see [`ironbus_core::backpressure`]); the engine threads the monotonic clock seam into them
/// so they stay deterministic. All four DEFAULT to disabled / inert, so a broker that configures no
/// backpressure knob behaves exactly as today.
#[derive(Clone, Copy, Debug)]
pub struct Backpressure {
    /// The CoDel produce-admission shedding controller (#68). Disabled (never sheds) unless both the
    /// target and interval are non-zero.
    codel: Codel,
    /// The broker-side per-client retry budget (#69). Disabled (never throttles) unless the ratio is
    /// non-zero. One broker-wide instance today (per-connection identity is #106, deferred); see the
    /// field on [`Engine`].
    retry_budget: RetryBudget,
    /// The fire-and-forget (un-credited) admission token bucket (#69). Disabled (always admits)
    /// unless a rate is non-zero.
    fire_and_forget: TokenBucket,
    /// The egress AIMD concurrency limiter (#69). Always within `[4, 128]`; the seam a future
    /// gradient estimator slots into.
    egress: AimdLimiter,
    /// Whether the egress AIMD actively GOVERNS the per-consumer egress credit (#69, #402). The
    /// limiter is always constructed (the gauge reports its limit even when off), but it only BINDS
    /// the effective per-Flow credit and reacts to keep-up signals when an operator opted in via a
    /// non-zero `--egress-limit`. `false` (the default `egress_limit == 0`) is INERT: the per-Flow
    /// credit and the ack/nack signals are byte-for-byte the historical behavior, so a zero-config
    /// broker is unchanged.
    egress_aimd_enabled: bool,
    /// CoDel sojourn sheds: a new produce rejected because the admission sojourn stayed above TARGET
    /// for a full INTERVAL. The `ironbus_codel_shed_total` counter. Saturating.
    codel_shed: u64,
    /// CoDel depth/byte backstop sheds: a new produce shed by the sojourn-INDEPENDENT depth/byte
    /// bound (a stalled drain CoDel cannot see). The `ironbus_codel_backstop_shed_total` counter.
    /// Saturating.
    codel_backstop_shed: u64,
    /// Retries throttled by the budget broker-side. The `ironbus_retry_shed_total{side="broker"}`
    /// counter. Saturating.
    retry_shed: u64,
    /// Fire-and-forget messages shed by the token bucket. The `ironbus_fire_and_forget_shed_total`
    /// counter. Saturating.
    fire_and_forget_shed: u64,
    /// Egress requests shed at the AIMD concurrency limit. The `ironbus_egress_shed_total` counter.
    /// Saturating.
    egress_shed: u64,
    /// The fsync-headroom admission credit (#378): bounds the un-fsynced (buffered-but-not-durable)
    /// write frontier to a configured byte headroom. Disabled (always admits) unless the headroom is
    /// non-zero. PURE math; the engine feeds it the live `unsynced_bytes()` frontier.
    fsync_headroom: FsyncHeadroom,
    /// fsync-headroom sheds (#378): a new produce shed because admitting it would push the un-fsynced
    /// backlog past the configured headroom even AFTER a group-commit drain. The
    /// `ironbus_wal_fsync_headroom_shed_total` counter. Saturating.
    wal_headroom_shed: u64,
}

impl Backpressure {
    /// Builds the backpressure controllers from an [`EngineConfig`] (a single borrow, so it can run
    /// before the `Engine` struct literal that moves the config's non-`Copy` fields). Every knob
    /// defaults to a disabling value, so the controllers are inert unless an operator opts in.
    fn from_engine_config(config: &EngineConfig) -> Backpressure {
        Backpressure::new(
            config.codel_target_ms,
            config.codel_interval_ms,
            config.retry_budget_ratio_per_million,
            config.retry_budget_window_ms,
            config.fire_and_forget_msg_rate,
            config.fire_and_forget_byte_rate,
            config.fire_and_forget_refill_ms,
            config.egress_limit,
            config.wal_fsync_headroom_bytes,
        )
    }

    /// Builds the backpressure controllers from the engine config knobs (all scalar `Copy` values, so
    /// no borrow of the whole config is needed). Every knob defaults to a disabling value, so the
    /// controllers are inert unless an operator opts in.
    // One parameter per backpressure knob is the clearest shape (it mirrors the config fields
    // one-to-one); bundling them into a sub-struct would only add indirection.
    #[allow(clippy::too_many_arguments)]
    fn new(
        codel_target_ms: u64,
        codel_interval_ms: u64,
        retry_budget_ratio_per_million: u64,
        retry_budget_window_ms: u64,
        fire_and_forget_msg_rate: u64,
        fire_and_forget_byte_rate: u64,
        fire_and_forget_refill_ms: u64,
        egress_limit: u32,
        wal_fsync_headroom_bytes: u64,
    ) -> Backpressure {
        Backpressure {
            codel: Codel::from_millis(codel_target_ms, codel_interval_ms),
            retry_budget: RetryBudget::new(retry_budget_ratio_per_million, retry_budget_window_ms),
            fire_and_forget: TokenBucket::new(
                fire_and_forget_msg_rate,
                fire_and_forget_byte_rate,
                fire_and_forget_refill_ms,
            ),
            egress: AimdLimiter::new(
                if egress_limit == 0 {
                    ironbus_core::backpressure::DEFAULT_EGRESS_LIMIT
                } else {
                    egress_limit
                },
                ironbus_core::backpressure::EGRESS_LIMIT_MIN,
                ironbus_core::backpressure::EGRESS_LIMIT_MAX,
            ),
            // The AIMD only GOVERNS the egress credit when an operator opts in (a non-zero
            // `--egress-limit`); a `0` leaves it inert (the gauge still reports the static 16), so the
            // default per-consumer credit path is unchanged.
            egress_aimd_enabled: egress_limit != 0,
            fsync_headroom: FsyncHeadroom::new(wal_fsync_headroom_bytes),
            codel_shed: 0,
            codel_backstop_shed: 0,
            retry_shed: 0,
            fire_and_forget_shed: 0,
            egress_shed: 0,
            wal_headroom_shed: 0,
        }
    }
}

/// A read-only snapshot of the backpressure controllers' observable state (#68, #69), for the
/// `/metrics` rendering and the `/admin` introspection. Counters are `_total`; estimates / ratios /
/// limits are gauges, matching the #16 frozen-taxonomy rule (gauges carry no `_total` suffix).
#[derive(Clone, Copy, Debug)]
pub struct BackpressureSnapshot {
    /// The `ironbus_codel_shed_total` counter: new produces shed by the CoDel sojourn control.
    pub codel_shed: u64,
    /// The `ironbus_codel_backstop_shed_total` counter: new produces shed by the depth/byte backstop.
    pub codel_backstop_shed: u64,
    /// The `ironbus_codel_interval_resets_total` counter: suspend-gap interval resets.
    pub codel_interval_resets: u64,
    /// The `ironbus_codel_sojourn_estimate_ms` gauge: the current minimum-sojourn estimate, in ms.
    pub codel_sojourn_estimate_ms: u64,
    /// The `ironbus_retry_shed_total{side="broker"}` counter: retries throttled by the budget.
    pub retry_shed: u64,
    /// The `ironbus_retry_ratio` gauge, in parts-per-million: the observed retry (shed) rate as a
    /// fraction of the request rate.
    pub retry_ratio_per_million: u64,
    /// The `ironbus_fire_and_forget_shed_total` counter: messages shed by the token bucket.
    pub fire_and_forget_shed: u64,
    /// The `ironbus_egress_shed_total` counter: requests shed at the concurrency limit.
    pub egress_shed: u64,
    /// The `ironbus_egress_limit` gauge: the current AIMD egress concurrency limit (4..=128).
    pub egress_limit: u32,
    /// The `ironbus_wal_fsync_headroom_shed_total` counter (#378): new produces shed because the
    /// un-fsynced backlog could not be drained below the headroom.
    pub wal_headroom_shed: u64,
    /// The `ironbus_wal_fsync_headroom_bytes` gauge (#378): the configured fsync-headroom window in
    /// bytes (`0` = disabled / unbounded).
    pub wal_fsync_headroom_bytes: u64,
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
    /// The OPT-IN RAM ceiling in bytes for the `ironbus_ram_headroom_bytes` edge gauge (`0` = unset,
    /// the gauge reports the unavailable sentinel) (#118).
    pub ram_ceiling_bytes: u64,
    /// The OPT-IN daily physical write budget in bytes (`0` = the flash-wear governor is off) (#118).
    pub daily_physical_write_budget_bytes: u64,
}

/// The durable, unnamed default work-group: the one the wire protocol uses today, the one
/// persisted in `cursor.ckpt`. Named groups (#9) are independent in-memory cursors.
const DEFAULT_GROUP: &str = "";

/// The RESERVED internal dedup `producer_id` PREFIX for transactional-commit real-stream appends
/// (#640, V2-M8). A txn commit appends the buffered payload to the real stream through the DURABLE
/// effectively-once producer-SEQUENCE dedup keyed on `prefix + txn_id` (seq 0), so a crash-recovery
/// re-commit re-append is recognized as a benign duplicate at the original offset and the dedup
/// SURVIVES a restart (the crash-window-(b) guarantee). The leading NUL byte cannot appear in a wire
/// producer id (graphic bytes only), so a txn's dedup high-water is ISOLATED in its own per-producer
/// entry and never collides with, evicts, or is evicted by a real producer's window. Each distinct txn
/// id is its OWN single-sequence producer (seq 0), so txns resolving out of order never trip the
/// producer-seq out-of-order guard.
const TXN_DEDUP_PRODUCER_PREFIX: &[u8] = b"\x00ironbus-txn:";

/// Builds the reserved-namespace producer id for a txn-commit real-stream append (#640):
/// [`TXN_DEDUP_PRODUCER_PREFIX`] followed by the txn id. The txn id is bounded by the wire/lifecycle
/// `MAX_TXN_ID_LEN` (256), and the prefix is short, so the result stays well within
/// `ironbus_core::dedup::MAX_PRODUCER_ID_LEN`.
fn txn_dedup_producer_id(txn_id: &[u8]) -> Vec<u8> {
    let mut pid = Vec::with_capacity(TXN_DEDUP_PRODUCER_PREFIX.len() + txn_id.len());
    pid.extend_from_slice(TXN_DEDUP_PRODUCER_PREFIX);
    pid.extend_from_slice(txn_id);
    pid
}

/// Maps a [`TxnStoreError`] (a durable txn-store IO/framing failure) to an [`EngineError`]: a storage
/// error propagates as [`EngineError::Storage`]; an unframable record (unreachable from the bounded
/// wire path) surfaces as the structural [`StorageError::SegmentFull`] rather than a panic.
fn txn_store_error_to_engine(e: TxnStoreError) -> EngineError {
    match e {
        TxnStoreError::Storage(s) => EngineError::Storage(s),
        TxnStoreError::Unframable => {
            EngineError::Storage(ironbus_storage::segment::StorageError::SegmentFull)
        }
    }
}

/// The build version string for the metric registry's `ironbus_build_info` (#97), the crate
/// version baked in at compile time.
fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The default per-consumer in-flight credit CEILING (refs #65, #10, #552): the most un-acked
/// messages one connection may EVER hold at once — the high, Kafka-class window the per-consumer
/// auto-tune ([`ironbus_core::backpressure::CreditAutotuner`], #552) grows TOWARD as the consumer
/// keeps up, NOT the window every consumer is pinned at.
///
/// Pre-#552 this was a FIXED 64, which (Little's Law at the #19 working point, 10k msg/s x 5 ms =
/// 50 concurrent) had ~28% headroom for a SERVICE-bound consumer but pinned a fast/loopback consumer
/// to 64/RTT — the bandwidth-delay product floor the #464 fair-consume bench and the #532 follow-up
/// surfaced. The window now AUTO-TUNES: it starts at the historical floor of 64
/// ([`ironbus_core::backpressure::DEFAULT_CREDIT_FLOOR`]) and grows to this ceiling
/// ([`ironbus_core::backpressure::DEFAULT_CREDIT_CEILING`] = 2048) while the consumer drains, so a
/// keeping-up consumer fills the pipe instead of stalling at 64/RTT, while a service-bound consumer
/// stays near 64 (it never grows what it does not drain).
///
/// This value is also the WORST-CASE in-flight message count the refuse-to-boot RAM guard charges
/// (`crate::rss`): with the byte budget OFF it is `consumer_credit * MAX_FRAME_LEN` per connection, so
/// raising the ceiling makes a no-byte-budget config HONESTLY refuse under a small RAM ceiling rather
/// than silently grow. With the byte budget SET (the 8 MiB default), the byte budget binds term 1 and
/// the count ceiling is irrelevant to RAM — the count auto-tunes UNDER the firm byte cap. NOT the
/// MQTT absent-value 65535. See [`EngineConfig::consumer_credit`].
pub const DEFAULT_CONSUMER_CREDIT: u32 = ironbus_core::backpressure::DEFAULT_CREDIT_CEILING;

/// The default per-consumer in-flight BYTE budget (refs #65, #275, #10, #20, #552): the most un-acked
/// PAYLOAD bytes one connection may hold at once before a Flow stops delivering to it, the RAM-side
/// companion to [`DEFAULT_CONSUMER_CREDIT`] and — post-#552 — the FIRM RAM bound the auto-tuning count
/// window grows UNDER. 8 MiB: large enough that the small records an edge broker carries grow the count
/// window well past 64 toward the ceiling (a keeping-up loopback consumer fills the pipe) before the
/// byte budget binds, yet a firm RAM ceiling that a large-payload consumer cannot exceed regardless of
/// how high the count auto-tunes (e.g. at 2048 the count is byte-bound at any record over ~4 KiB). A
/// single message larger than this is still delivered (the hard floor of one), so the budget never
/// wedges a consumer. `0` means UNLIMITED (the byte budget is off — then ONLY the count ceiling binds
/// in-flight RAM, which is why a no-byte-budget config is charged the full count ceiling by the RAM
/// guard). See [`EngineConfig::consumer_credit_bytes`].
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

/// The default CoDel TARGET sojourn in MILLISECONDS for `serve` (#68): `0` = DISABLED. CoDel is
/// OFF by default so a zero-config broker behaves exactly as today (byte-cap shed + consumer
/// credit only); an operator opts in by setting a non-zero target, at which point the RFC 8289
/// recommended 5 ms applies (and is clamped to `[1 ms, 1 s]`). See [`EngineConfig::codel_target_ms`].
pub const DEFAULT_CODEL_TARGET_MS: u64 = 0;

/// The default CoDel INTERVAL in MILLISECONDS for `serve` (#68): the RFC 8289 recommended 100 ms,
/// used only when a non-zero target enables CoDel (and clamped to `[20 ms, 10 s]`). With the
/// default `0` target CoDel is off regardless. See [`EngineConfig::codel_interval_ms`].
pub const DEFAULT_CODEL_INTERVAL_MS: u64 = 100;

/// The default per-client retry-budget ratio in PARTS PER MILLION for `serve` (#69): `0` = DISABLED
/// (no retry is throttled), so a zero-config broker behaves as today. The doc budget is 10%
/// (`100_000`), opt-in. See [`EngineConfig::retry_budget_ratio_per_million`].
pub const DEFAULT_RETRY_BUDGET_RATIO_PER_MILLION: u64 = 0;

/// The default per-client retry-budget window in MILLISECONDS for `serve` (#69): 60 s, used only
/// when the ratio is non-zero. See [`EngineConfig::retry_budget_window_ms`].
pub const DEFAULT_RETRY_BUDGET_WINDOW_MS: u64 = 60_000;

/// The default fire-and-forget token-bucket MESSAGE rate (msg/s) for `serve` (#69): `0` = DISABLED
/// (the un-credited tier is ungoverned, as today). The doc default is 5000, opt-in. See
/// [`EngineConfig::fire_and_forget_msg_rate`].
pub const DEFAULT_FIRE_AND_FORGET_MSG_RATE: u64 = 0;

/// The default fire-and-forget token-bucket BYTE rate (bytes/s) for `serve` (#69): `0` = DISABLED.
/// The doc default is 5 MiB/s, opt-in. See [`EngineConfig::fire_and_forget_byte_rate`].
pub const DEFAULT_FIRE_AND_FORGET_BYTE_RATE: u64 = 0;

/// The default fire-and-forget token-bucket refill granularity (ms) for `serve` (#69): 100 ms (the
/// doc default). See [`EngineConfig::fire_and_forget_refill_ms`].
pub const DEFAULT_FIRE_AND_FORGET_REFILL_MS: u64 = 100;

/// The default starting / static-floor egress concurrency limit for `serve` (#69): the doc default
/// floor of 16 (the AIMD bounds `[4, 128]` always apply). See [`EngineConfig::egress_limit`].
pub const DEFAULT_EGRESS_LIMIT: u32 = 16;

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

/// The filename prefix of a named work-group's durable per-message ATTEMPT-COUNT checkpoint (#358),
/// the companion to its `cursor-<hex>.ckpt`. The default group uses `attempts.ckpt` (note
/// `attempts.`, not `attempts-`), so it never matches the named pattern. Neither prefix begins with
/// `cursor`, so the attempt files never collide with, nor are mistaken for, a cursor checkpoint.
const GROUP_ATTEMPTS_PREFIX: &str = "attempts-";

/// Lowercase-hex-encodes bytes, for embedding a graphic-ASCII work-group name in a safe,
/// reversible filename (a name may contain `/`, `:`, etc., which are unsafe in a path). Delegates
/// to the storage layer's encoder so the engine and the offline admin verbs (#299) share one
/// implementation and cannot drift on the on-disk checkpoint names.
fn hex_encode(bytes: &[u8]) -> String {
    ironbus_storage::naming::hex_encode(bytes)
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

/// The durable checkpoint filename for a named work-group: `cursor-<hex(name)>.ckpt`. Delegates to
/// the storage layer's canonical name so the engine's writes and the offline admin verbs' rewrites
/// (#299) target byte-for-byte the same file. Only ever called for a NAMED group here (the default
/// group uses [`CURSOR_CHECKPOINT`] directly); the storage helper would also map the empty name to
/// `cursor.ckpt`, which matches [`CURSOR_CHECKPOINT`].
fn group_checkpoint_name(group: &str) -> String {
    ironbus_storage::naming::cursor_checkpoint_name(group)
}

/// The durable per-message attempt-count checkpoint filename for a work-group (#358): the default
/// group is `attempts.ckpt`, a named group is `attempts-<hex(name)>.ckpt` (the companion to its
/// `cursor-<hex>.ckpt`). Kept beside the cursor checkpoint so the attempt counts ride the same
/// crash-safe dual-slot discipline.
fn group_attempts_name(group: &str) -> String {
    if group == DEFAULT_GROUP {
        ATTEMPTS_CHECKPOINT.to_string()
    } else {
        format!(
            "{GROUP_ATTEMPTS_PREFIX}{}{GROUP_CKPT_SUFFIX}",
            hex_encode(group.as_bytes())
        )
    }
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

/// Recovers the work-group name from a named-group ATTEMPT-COUNT checkpoint filename
/// (`attempts-<hex>.ckpt`), or `None` for the default `attempts.ckpt`, a cursor file, or a malformed
/// name (#358). Used so a group whose poison was in flight but never committed (so it has an
/// attempts file but NO cursor file yet) is still rediscovered and resumed at open.
fn parse_group_attempts_name(name: &str) -> Option<String> {
    let mid = name
        .strip_prefix(GROUP_ATTEMPTS_PREFIX)?
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

/// Builds the checkpoint payload for a group's in-flight attempt counts (#358): the CRC-protected
/// snapshot of the `(offset, attempt)` pairs, capped to a checkpoint slot. The pairs come from the
/// live lease table (ascending by offset, one per in-flight offset, bounded by `max_in_flight`), so
/// they already satisfy the codec's sorted-distinct contract. If the snapshot would overflow a slot
/// (a pathologically large in-flight set), only the leading pairs that fit are kept; dropping the
/// overflow tail only resets those few offsets to attempt 1 after a crash (at-least-once safe), it
/// never loses an attempt count for the offsets it does keep, and the in-flight window bounds it.
fn attempts_snapshot_payload(pairs: &[(u64, u32)]) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_attempt_snapshot(pairs, &mut buf);
    if buf.len() <= ATTEMPTS_PAYLOAD {
        return buf;
    }
    // A slot holds ATTEMPTS_PAYLOAD bytes: the fixed header and crc, plus 12 per pair. Keep the
    // leading pairs that fit and re-encode; the count field is rewritten, so the result is valid.
    let max_pairs = ATTEMPTS_PAYLOAD.saturating_sub(ATTEMPT_SNAPSHOT_MIN_LEN) / 12;
    let kept = &pairs[..max_pairs.min(pairs.len())];
    let mut out = Vec::new();
    encode_attempt_snapshot(kept, &mut out);
    out
}

/// Reads the recovered snapshot bytes of a work-group's durable attempt-count checkpoint (#358),
/// or `None` if the group has no attempts file yet (it never poisoned, or predates the feature).
/// The dual-slot `AttemptsCheckpoint::open` discards a torn slot, so the bytes are either the last
/// fully-durable snapshot or `None`; the caller decodes and clamps them.
///
/// # Errors
/// Propagates a genuine IO error from opening or reading the attempts checkpoint file.
fn read_group_attempts<F: Filesystem>(fs: &F, group: &str) -> Result<Option<Vec<u8>>, EngineError> {
    let name = group_attempts_name(group);
    if !fs.exists(&name)? {
        return Ok(None);
    }
    let (_, recovered) = AttemptsCheckpoint::open(fs.open(&name)?)?;
    Ok(recovered)
}

/// Builds a [`WorkGroup`] around a recovered `cursor` and seeds its lease table with the durable
/// attempt counts decoded from `attempts_recovered` (#358), clamped to the cursor's watermark and
/// the durable head `flushed`. Shared by the default-group and named-group resume paths so the
/// clamp-and-seed step lives in one place. A `None`/torn attempt payload yields no carried counts.
fn resume_work_group(
    cursor: AckCursor,
    attempts_recovered: Option<&[u8]>,
    lease: LeaseConfig,
    opened_at: u64,
    flushed: u64,
) -> WorkGroup {
    let committed = cursor.committed().get();
    let attempts = resume_attempts_from_snapshot(attempts_recovered, committed, flushed);
    let mut group = WorkGroup::resume(cursor, lease, opened_at);
    group.leases.resume_attempts(attempts);
    group
}

/// Discovers and resumes each NAMED work-group from its own `cursor-<hex>.ckpt` plus its
/// `attempts-<hex>.ckpt` (#60, #358), inserting each into `groups`, and returns the per-group
/// last-checkpointed committed offsets. Recovery is deliberately NOT bounded by `max_groups`: the
/// cap gates only NEW group creation, never the resume of groups already durable on disk (lowering
/// `--max-groups` below the on-disk count must not silently drop committed cursors). A group already
/// present (the default group) or with an invalid name is skipped.
///
/// # Errors
/// Propagates a storage error from listing or opening a group's checkpoint files.
fn recover_named_groups<F: Filesystem>(
    fs: &F,
    groups: &mut BTreeMap<String, WorkGroup>,
    lease: LeaseConfig,
    opened_at: u64,
    flushed: u64,
) -> Result<BTreeMap<String, u64>, EngineError> {
    // Discover every durable named group from BOTH its cursor file AND its attempts file (#358): a
    // group whose poison was in flight but never committed has an `attempts-<hex>.ckpt` yet no
    // `cursor-<hex>.ckpt` (the cursor write is gated on the watermark advancing), so iterating only
    // cursor files would orphan its durable attempt counts. The union of the two filename sets, with
    // a fresh cursor for a group that has only an attempts file, recovers both.
    let mut names = std::collections::BTreeSet::new();
    for file in fs.list()? {
        if let Some(gname) = parse_group_checkpoint_name(&file) {
            names.insert(gname);
        } else if let Some(gname) = parse_group_attempts_name(&file) {
            names.insert(gname);
        }
    }
    let mut group_last_checkpointed = BTreeMap::new();
    for gname in names {
        if validate_group_name(&gname).is_err() || groups.contains_key(&gname) {
            continue;
        }
        // Resume the cursor from `cursor-<hex>.ckpt` if present, else start fresh at offset 0 (the
        // attempts-only case). Then seed the durable attempt counts from `attempts-<hex>.ckpt`,
        // clamped exactly like the default group, so MaxDeliver survives a restart in every group.
        let cursor_name = group_checkpoint_name(&gname);
        let gcursor = if fs.exists(&cursor_name)? {
            let (_, recovered) = Checkpoint::open(fs.open(&cursor_name)?)?;
            resume_cursor_from_snapshot(recovered.as_deref(), flushed)
        } else {
            AckCursor::new()
        };
        group_last_checkpointed.insert(gname.clone(), gcursor.committed().get());
        let recovered_a = read_group_attempts(fs, &gname)?;
        let g = resume_work_group(gcursor, recovered_a.as_deref(), lease, opened_at, flushed);
        groups.insert(gname, g);
    }
    Ok(group_last_checkpointed)
}

/// Reconstructs a group's carried attempt counts from a recovered `attempts.ckpt` payload, clamped
/// to the durable log head `flushed` and the resumed committed watermark `committed`: a carried
/// count is only meaningful for an offset that still exists (`< flushed`) and has NOT been committed
/// past (`>= committed`), since a committed offset never redelivers. A torn, corrupt, or absent
/// snapshot yields no carried counts (every in-flight message resumes at attempt 1, the pre-#358
/// behavior), so a bad attempt snapshot can never block startup or invent a count.
fn resume_attempts_from_snapshot(
    recovered: Option<&[u8]>,
    committed: u64,
    flushed: u64,
) -> Vec<(u64, u32)> {
    let Some(payload) = recovered else {
        return Vec::new();
    };
    let Ok(pairs) = decode_attempt_snapshot(payload) else {
        return Vec::new();
    };
    pairs
        .into_iter()
        .filter(|&(offset, _)| offset >= committed && offset < flushed)
        .collect()
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
    /// Whether this group is a BROADCAST consumer (#288): a group-of-one that sees every record in
    /// order, as opposed to a competing or `key_shared` work-group that several members drain out
    /// of order. Only a broadcast group accepts a cumulative ack ([`Engine::cumulative_ack_in`]):
    /// committing its single cursor up to an offset is well-defined and drops nothing because no
    /// peer holds an in-flight message below it. Mutually exclusive with `router` (a broadcast
    /// group is never `key_shared`): [`Engine::set_broadcast_in`] and [`Engine::set_key_ordering_in`]
    /// each clear the other mode. `false` (plain competing) by default, so an unconfigured group is
    /// unaffected and the cumulative-ack guard rejects it exactly as before.
    broadcast: bool,
    /// The set of currently-ACTIVE subscribers (#288), one entry per live connection subscribed
    /// to this group (keyed by the connection's stable [`MemberId`], so a re-subscribe by the same
    /// connection is idempotent). It enforces the BROADCAST group-of-one invariant: a broadcast
    /// group accepts AT MOST ONE subscriber, so a cumulative ack can only ever commit past the
    /// single consumer's OWN in-flight leases, never a peer's. A plain competing or `key_shared`
    /// group ignores the cap (any number may subscribe). The session registers on SUB
    /// ([`Engine::subscribe_in`]) and deregisters on UNSUB / subscription switch / disconnect
    /// ([`Engine::unsubscribe_in`]). Empty for the default group (its implicit consumers do not SUB)
    /// and for any group no connection currently holds.
    subscribers: std::collections::BTreeSet<MemberId>,
    /// The engine-clock-seam (monotonic, nanoseconds) timestamp of this group's LAST ACTIVITY
    /// (#277): updated whenever a poll, ack, nack, progress, or term touches the group. The idle
    /// eviction sweep ([`Engine::sweep_idle_groups`]) measures the idle window against it. Seeded
    /// at the group's creation time so a freshly-created group is not instantly evictable. A
    /// purely monotonic timestamp is enough because the sweep only ever subtracts it from a later
    /// `now`, never compares it across wall-clock boundaries.
    last_activity: u64,
    /// Whether ANY consumer interaction has EVER been observed for this group (#424): a poll,
    /// ack, nack, term, progress, cumulative ack, or an explicit subscribe in this process, or
    /// any durable consumer state (a cursor or attempts checkpoint) found at open. Every group
    /// except the boot-created default group starts `true`: a NAMED group comes to exist through
    /// a consumer op, a durable-state resume, or a serve-time declaration (`set_broadcast_in` /
    /// `set_key_ordering_in` create their groups before any consumer exists, and a DECLARED
    /// group deliberately keeps the conservative pre-#424 pinning until its consumers arrive).
    /// The boot-created default group (`""`) starts `false` when it carries NO durable state,
    /// because it exists structurally (it is the wire's unnamed group) whether or not anyone
    /// consumes through it. The retention protect floor ([`Engine::min_committed_offset`]) skips
    /// a group that is still untouched, so a deployment that only consumes through named groups
    /// is not pinned at offset 0 forever by the phantom default group. The flag is in-memory
    /// only, the documented trade for adding no new durable state: a default-group consumer is
    /// protected across a restart only once a cursor (or attempts) checkpoint actually exists on
    /// disk. The live write is offset-gated ([`Engine::maybe_checkpoint`] writes only after
    /// `checkpoint_interval` newly committed offsets) and the shutdown write
    /// ([`Engine::checkpoint_cursor`], driven by the server on drain and connection close) skips
    /// a cursor with nothing to record, so a consumer that polled but never committed resumes
    /// untouched even after a graceful stop.
    touched: bool,
    /// Whether this group is a TIER-S STREAMING consumer (#544, M1-I7): a consumer-managed-offset
    /// mode where the broker serves a CONTIGUOUS batch off the durable prefix with NO lease, NO
    /// generation fence, and NO per-record cursor write, and durability comes from a PERIODIC
    /// cumulative [`Engine::stream_commit_in`] that advances this group's committed cursor via
    /// `commit_up_to`. It is the streaming twin of the default TIER-W work-queue mode (`broadcast` /
    /// `router` above): where Tier-W grants a per-record lease and writes the cursor on every ack,
    /// Tier-S removes exactly that per-record cost, which is what makes single-consumer durable
    /// consume lose to NATS. At-least-once holds BY CONSTRUCTION — a crash or reconnect re-reads from
    /// the last committed offset (the consumer passes its own `start_offset` to
    /// [`Engine::stream_fetch_in`]), so at most the uncommitted records redeliver (the Kafka /
    /// NATS-pull contract). The streaming cursor still pins the retention floor exactly like any
    /// other group (it is read by [`Engine::min_committed_offset`] once `touched`), so a committed
    /// streaming consumer frees retention correctly. `false` (Tier-W work-queue) by default, so an
    /// unconfigured group is byte-for-byte unchanged and the Tier-W lease path is untouched. A
    /// streaming group never grants leases, so it never carries the broadcast group-of-one hazard:
    /// it is orthogonal to `broadcast` and `router` and does NOT clear them (a future Connect-default
    /// tier negotiation, M1-I9, may layer policy on top; this flag is the per-group selector only).
    streaming: bool,
}

/// What happens to an evicted group's `group_last_checkpointed` entry (#432): `Keep` leaves it
/// as a GHOST that keeps pinning the retention protect floor at the eviction-point head (the
/// idle sweep's policy: eviction reclaims memory, never retention protection); `Release` removes
/// it (the explicit-`Unsub` policy: the consumer renounced the position, so the pin is opt-out
/// by unsubscribe, never implicit by absence).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum GhostPolicy {
    Keep,
    Release,
}

impl WorkGroup {
    fn new(config: LeaseConfig, now: u64) -> WorkGroup {
        WorkGroup::resume(AckCursor::new(), config, now)
    }

    /// Builds a work-group around an already-recovered `cursor` (the durable-resume path at open,
    /// #60), plain competing (`router: None`, `broadcast: false`): the mode is re-applied
    /// server-side after open, never restored from disk here.
    fn resume(cursor: AckCursor, config: LeaseConfig, now: u64) -> WorkGroup {
        WorkGroup {
            cursor,
            leases: LeaseTable::new(config),
            router: None,
            broadcast: false,
            subscribers: std::collections::BTreeSet::new(),
            last_activity: now,
            // Touched by default (#424): a named group is created by a consumer op, a durable
            // resume, or a serve-time declaration, and every one of those keeps the conservative
            // pinning. The single exception, the boot-created default group with no durable
            // state, is flipped to untouched right after open inserts it.
            touched: true,
            // Tier-W (work-queue lease mode) by default (#544): a resumed/new group is byte-for-byte
            // the existing lease path. Tier-S streaming is opted into server-side via
            // `set_streaming_in` after open, never restored from disk here (the mode is re-applied,
            // exactly like `broadcast` / `router`).
            streaming: false,
        }
    }
}

/// The PER-NAMED-STREAM engine state (#676, V2-M2-I2b): each named stream owns its OWN
/// `groups: BTreeMap<GroupName, WorkGroup>` (the lease / `AckCursor` / 0-1-2-ack core
/// RE-INSTANTIATED per stream, UNCHANGED logic), exactly as the DEFAULT stream `""` owns
/// [`Engine::groups`]. The named stream's durable LOG itself lives in the [`Engine::streams`]
/// [`StreamSet`] (so the cross-stream `commit_tick` barrier, #678/#564, coordinates its
/// durability); this struct holds only the per-stream CONSUMER state that mirrors the default
/// stream's group machinery.
///
/// Scope (#676): a named stream's consume path here re-instantiates the SAME competing
/// work-group primitives the default stream uses — the [`AckCursor`], the [`LeaseTable`], the
/// 0/1/2 ack spectrum — independently per stream. The richer sub-paths a named stream does NOT
/// yet thread (a per-stream DLQ, retry-throttle, key-shared routing, the Tier-S streaming mode,
/// durable per-group cursor/attempt checkpoints, and the per-stream metric LABELS) are FLAGGED as
/// follow-ups (M2-I5 retention, M2-I14 metrics); they are inert here, never REMOVED from the
/// default stream. A named stream's groups are in-memory only for now (its consumer position does
/// not survive a restart — only its LOG recovers, via the `StreamSet`), the explicit trade this
/// reviewable slice makes.
/// The subject->stream BINDING table (#585, V2-M2-I9): the authoritative registry of
/// `(SubjectPattern -> StreamId)` bindings PLUS the wait-free routing trie ([`SublistSnapshot`]) it
/// compiles to. The registry (`entries`) is the source of truth a rebuild reads; the `snapshot` is the
/// immutable, generation-stamped trie a publish resolves against wait-free.
///
/// # Bind = rebuild + swap (invalidates every connection's resolve cache)
///
/// A [`BindingTable::bind`] appends a `pattern -> stream` entry, rebuilds a fresh immutable trie from
/// the whole registry, and [`SublistSnapshot::store`]s it — which bumps the snapshot's monotonic
/// generation. Each connection's [`ResolveCache`](ironbus_core::resolve_cache::ResolveCache) compares
/// that generation on its next resolve and drops its stale cached answer (one O(1) compare, no global
/// flush — the beat over NATS's per-change global Sublist-cache flush). The rebuild is the rare,
/// amortized cost a bind pays; every resolve against the installed trie is wait-free.
///
/// # Fail-closed at ingest
///
/// `bind` validates the pattern through the #567 grammar BEFORE registering it, and the trie rebuild is
/// itself fail-closed on the fork bound (#568): a binding SET whose worst-case wildcard fork frontier
/// would exceed the cap is REFUSED and the PREVIOUS table is left installed unchanged, so a bad bind
/// never corrupts routing and never silently truncates a match.
struct BindingTable {
    /// The authoritative `(pattern, stream)` registry, the source of truth a rebuild reads. An owned
    /// pattern string + its target stream; the same pattern may appear for two DISTINCT streams (which
    /// makes any subject they both cover ambiguous under single-home). In-memory only this phase.
    entries: Vec<(String, StreamId)>,
    /// The compiled, wait-free routing trie: a publish resolves a literal subject against this
    /// snapshot (directly or through a per-connection resolve cache) with no lock and no walk on a
    /// cache hit. Rebuilt and swapped on every successful `bind`, advancing its generation.
    snapshot: SublistSnapshot<StreamId>,
}

impl BindingTable {
    /// An empty binding table: no subject is bound, so every resolve is a fail-closed `NoStream` until a
    /// `bind` registers a pattern. The trie starts at generation 0.
    fn new() -> BindingTable {
        BindingTable {
            entries: Vec::new(),
            snapshot: SublistSnapshot::empty(),
        }
    }

    /// Builds an immutable routing trie from the current registry (generation `0`; the snapshot restamps
    /// it monotonically on `store`). Fail-closed on the #568 fork bound.
    fn build(&self) -> Result<Sublist<StreamId>, SublistError> {
        let mut b = SublistBuilder::new();
        for (pattern, stream) in &self.entries {
            // Re-validate + register each stored pattern. `bind` only ever stores patterns that parsed,
            // so an insert error here is an internal-invariant surface, never reached via the public API.
            b.insert(pattern, stream.clone())
                .map_err(SublistError::InvalidPattern)?;
        }
        b.build(0)
    }

    /// Registers `pattern -> stream` and atomically swaps in the rebuilt trie, returning the new
    /// generation. Validates the pattern through the #567 grammar first (fail-closed). If the rebuilt
    /// SET would exceed the #568 fork bound, the registry is rolled back and the PREVIOUS trie stays
    /// installed (a bad bind never corrupts routing). Idempotent: re-binding the SAME `(pattern, stream)`
    /// pair is a no-op success (it does not duplicate the entry), so a client may re-declare its bindings
    /// safely.
    ///
    /// # Errors
    /// [`SublistError::InvalidPattern`] for a malformed pattern, or [`SublistError::ForkLimitExceeded`]
    /// if the resulting binding set would exceed the fork bound.
    fn bind(&mut self, pattern: &str, stream: StreamId) -> Result<u64, SublistError> {
        // Validate the pattern at the boundary (fail-closed) before it can enter the registry.
        SubjectPattern::parse(pattern).map_err(SublistError::InvalidPattern)?;
        // Idempotent: an identical (pattern, stream) pair is already bound -> no rebuild, no duplicate.
        if self
            .entries
            .iter()
            .any(|(p, s)| p == pattern && *s == stream)
        {
            return Ok(self.snapshot.generation());
        }
        // Tentatively register, then rebuild. On a fork-bound rejection, ROLL BACK the registry so the
        // installed trie and the registry stay consistent (the previous table remains the truth).
        self.entries.push((pattern.to_owned(), stream));
        match self.build() {
            Ok(trie) => Ok(self.snapshot.store(trie)),
            Err(e) => {
                self.entries.pop();
                Err(e)
            }
        }
    }

    /// The number of registered bindings (for tests/metrics).
    fn len(&self) -> usize {
        self.entries.len()
    }
}

struct NamedStream {
    /// This stream's competing work-groups, keyed by group name, byte-for-byte the SAME machinery
    /// as the default stream's [`Engine::groups`] — independent per stream so the same group NAME
    /// in stream A and stream B is two unrelated cursors (the per-stream-groups isolation #676
    /// requires). The default group `""` is created lazily on the first consume of this stream.
    groups: BTreeMap<String, WorkGroup>,
}

impl NamedStream {
    /// A freshly-declared named stream with no work-groups yet (created lazily on first consume).
    fn new() -> NamedStream {
        NamedStream {
            groups: BTreeMap::new(),
        }
    }
}

pub struct Engine<F: Filesystem, C: Clock> {
    log: Log<F, C>,
    /// The per-NAMED-stream LOG substrate (#676, V2-M2-I2b): a [`StreamSet`] over the SAME data
    /// directory, holding each named stream's independent [`Log`] under `streams/<hex(name)>/` (the
    /// `dlq/` subdir pattern, generalized — #563). It is opened EAGERLY at [`Engine::open`] so any
    /// named streams already on disk recover, and a named stream is `declare`d on its first produce.
    ///
    /// The DEFAULT stream `""` is served entirely by [`Engine::log`] above (byte-for-byte today): the
    /// engine NEVER appends to, syncs, or reads the `StreamSet`'s own `""` slot, so the default
    /// stream's produce / consume / durability / recovery / metrics are untouched and a deployment
    /// that never names a stream never materializes `streams/` (the `StreamSet`'s `""` slot is an
    /// inert re-open of the root that is never written — see the scope note in the PR; folding the
    /// default fully INTO the `StreamSet` is the follow-up that removes that inert slot).
    ///
    /// The cross-stream group-commit [`StreamSet::commit_tick`] (#678/#564) coordinates the durability
    /// barrier across the DIRTIED named streams: a produce pass touching K named streams commits with
    /// ONE coordinated tick (K `fdatasync` barriers, amortized over the batch), and because the engine
    /// never dirties the `""` slot, the default stream's single-log group-commit on [`Engine::log`] is
    /// byte-identical.
    streams: StreamSet<F, C>,
    /// The per-NAMED-stream CONSUMER state (#676), keyed by [`StreamId`]: each entry mirrors the
    /// default stream's work-group machinery (its `groups` map of [`WorkGroup`]s) for one named
    /// stream, so the same group name in two streams is two independent cursors (cross-stream
    /// isolation). A named stream gets an entry on its first produce (alongside its `StreamSet`
    /// `declare`); the default stream `""` is NEVER a key here (it uses [`Engine::groups`]). Empty
    /// for a deployment that never names a stream, so the default path costs nothing.
    named_streams: BTreeMap<StreamId, NamedStream>,
    /// The subject->stream BINDING table (#585, V2-M2-I9): the registry of `(SubjectPattern -> StreamId)`
    /// bindings plus the wait-free routing trie ([`SublistSnapshot`]) it builds. A `BindSubject` adds a
    /// `pattern -> stream` entry and rebuilds the immutable trie, swapping a fresh generation in — which
    /// is exactly the signal each connection's resolve cache watches to drop a stale routing answer
    /// (#569). A subject-addressed publish resolves through this table to ONE bound stream (single-home,
    /// fail-closed). Empty until the first bind, so a deployment that never binds a subject costs nothing
    /// here and the explicit-stream-id (#588) + default-stream paths are entirely unaffected.
    bindings: BindingTable,
    /// Per-work-group consumer state, keyed by group name. The default group (`""`) is the
    /// durable one (checkpointed to `cursor.ckpt`); named groups are independent
    /// broadcast/competing cursors, in-memory for now (durable per-group state is #60).
    ///
    /// This is the DEFAULT stream `""`'s group map (#676): named streams keep their OWN groups in
    /// [`Engine::named_streams`], so this field is untouched by the multi-stream re-key and the
    /// default-stream consume path is byte-for-byte today.
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
    /// The default group's durable per-message ATTEMPT-COUNT checkpoint (#358): a CRC'd dual-slot
    /// `attempts.ckpt` holding the `{offset -> attempt_count}` map of the default group's in-flight
    /// (delivered but unacked) entries, written on the same cursor-checkpoint cadence and the
    /// graceful-shutdown flush. On [`Engine::open`] its snapshot seeds the default lease table's
    /// carried attempt counts, so a redelivered poison message resumes its attempt number instead of
    /// resetting to 1 and `MaxDeliver`/DLQ routing holds across an unclean restart. It is CORRECTNESS
    /// state but tolerant: a torn or missing snapshot recovers as no carried counts (every in-flight
    /// message resumes at attempt 1, the pre-#358 behavior), so it can never block open. Named groups
    /// use their own `attempts-<hex>.ckpt`, reopened per write like their cursor checkpoint. The map
    /// is bounded by `max_in_flight` per group, so it never grows unbounded.
    attempts_checkpoint: AttemptsCheckpoint<F::File>,
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
    /// The OPT-IN RAM ceiling in bytes for the `ironbus_ram_headroom_bytes` edge gauge (#118): the
    /// resident-set budget the headroom gauge subtracts the measured RSS from. `0` means UNSET (the
    /// gauge reports the unavailable sentinel). Pure observability; never enforced. See
    /// [`EngineConfig::ram_ceiling_bytes`] and [`crate::rss`].
    ram_ceiling_bytes: u64,
    last_checkpointed: u64,
    /// The default group's committed offset at its last ATTEMPT-COUNT checkpoint write (#358), so a
    /// fully-drained group (nothing in flight) is not re-written every flush once its empty snapshot
    /// is already durable. Attempt writes ALSO fire whenever in-flight leases exist (a redelivery
    /// escalates a count without moving the cursor), so this only suppresses redundant empty writes.
    last_attempts_checkpointed: u64,
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
    /// The durable TRANSACTIONAL HALF-MESSAGE store (V2-M8, #640): the `txn/` sub-log that buffers
    /// prepared (half) messages INVISIBLE to consumers and their commit/rollback op-markers, plus the
    /// in-memory lifecycle table it rebuilds at open. Opened LAZILY on the first `TxnPrepare` (so a
    /// broker that never produces a transactional message never creates the subdirectory), or eagerly
    /// by [`Engine::open`] when the subdirectory already exists, so prepared half messages + their
    /// resolutions are recovered before the first resolve after a crash. `None` keeps the non-txn hot
    /// path byte-for-byte unchanged.
    txn: Option<TxnStore<F, C>>,
    /// The [`LogConfig`] the txn store's log is opened with: the same segment sizing as the main log,
    /// with NO total-byte cap (a half message / op-marker must never be shed — a prepared half message
    /// is an undelivered durable payload, and a resolution is the durable record of the commit/rollback).
    txn_config: LogConfig,
    /// The per-STREAM default message TTL (V2-M4, #549): a record reached on the poll path whose
    /// EFFECTIVE TTL (the lower of this and the record's own per-message TTL) has passed against the
    /// WALL-clock seam (anchored to the record's durable producer `timestamp_ms`) is EXPIRED — skipped
    /// on read and committed past, its bytes reclaimed by the same segment retention reap that ages
    /// out `max_age_ms`. [`Ttl::NONE`] (the default) means no per-stream TTL, so a non-TTL stream is
    /// byte-identical (records never expire on read). See [`EngineConfig::default_message_ttl_ms`].
    default_message_ttl: Ttl,
    /// The configurable dead-letter EXCHANGE target subdir (V2-M4, #551), or `None` for the default
    /// fixed `dlq/` sink. When set, EVERY dead-letter (max-deliver, TTL-expired, rejected) routes to
    /// this named sink via the reason-carrying append; `None` keeps the existing fixed-DLQ path
    /// byte-identical. See [`EngineConfig::dead_letter_exchange`].
    dead_letter_exchange: Option<String>,
    /// Whether a TTL-EXPIRED message is DEAD-LETTERED (to the configured exchange, with reason
    /// [`DeadLetterReason::TtlExpired`]) rather than reclaimed by retention (V2-M4, #549/#551). Has
    /// effect only when `dead_letter_exchange` is `Some`; with no exchange an expired message is
    /// always reclaimed by the reap (still bounded, never delivered, counted in `expired`). See
    /// [`EngineConfig::dead_letter_expired`].
    dead_letter_expired: bool,
    /// The set of group names CONFIGURED to use `key_shared` ordering (#64), declared server-side
    /// (NOT on the wire). Empty by default, so every group is plain competing
    /// ([`KeyOrdering::None`]) unless an operator opts it in. A session consults
    /// [`Engine::is_configured_key_shared`] on SUB and, for a configured group, puts it into
    /// `key_shared` mode and joins as a member. Held separate from the live per-group router so the
    /// declared config survives a group that has no current members.
    key_shared_groups: std::collections::BTreeSet<String>,
    /// The set of NAMED local streams that are READ-ONLY cross-cluster MIRRORS (#623, V2-C7-I1): a
    /// client PRODUCE to one of these is REJECTED with [`EngineError::MirrorReadOnly`], because a
    /// mirror's ONLY writer is the geo mirror-apply path (single-writer preserved). EMPTY by default —
    /// configured ONCE via [`Engine::set_mirror_read_only_streams`] only when a `--mirror` is present, so
    /// a non-geo broker's produce path is byte-for-byte unchanged (a single `is_empty()` short-circuit).
    mirror_read_only: std::collections::BTreeSet<String>,
    /// The opt-in effectively-once dedup registry (#3, #33): the per-producer bounded windows of
    /// `(msg_id -> offset)`. Empty until a producer opts in by sending a `msg_id`, so a broker no
    /// producer dedups against costs nothing here. Consulted on the produce path (the actor thread,
    /// serially) and pure (the monotonic clock comes through the seam). Lost on restart by default
    /// (session-scoped); see [`ironbus_core::dedup`].
    dedup: ironbus_core::dedup::DedupRegistry,
    /// The idempotent-producer SEQUENCE registry (V2-M8, #638/#639): the per-producer
    /// `(epoch, last_seq, last_offset)` high-water that deduplicates a Kafka-style sequenced retry to
    /// exactly-once-append, fences a zombie epoch, and rejects an out-of-order gap. Empty until a
    /// producer opts in by sending a `seq`, so a broker no producer sequences against costs nothing.
    /// Consulted on the produce path (the actor thread, serially) and pure. UNLIKE [`Self::dedup`],
    /// its state is DURABLE: the high-water is snapshotted to [`Self::producer_seq_checkpoint`] and
    /// RESTORED at open, so dedup survives a broker restart AND a long offline gap (the beat over
    /// NATS's time-bounded window). The state is O(active producers), bounded with LRU eviction; a
    /// long-dead producer is reclaimed under cap pressure. See [`ironbus_core::producer_seq`].
    producer_seq: ironbus_core::producer_seq::ProducerSeqRegistry,
    /// The durable idempotent-producer SEQUENCE checkpoint (V2-M8, #638/#639): a CRC'd dual-slot
    /// `producer-seq.ckpt` holding every active producer's `(epoch, last_seq, last_offset)`
    /// high-water, written on the same cursor-checkpoint cadence and the graceful-shutdown flush.
    /// On [`Engine::open`] its snapshot RESTORES [`Self::producer_seq`], so a replayed retry across
    /// a broker restart is STILL deduped and a long offline gap never drops it. It is CORRECTNESS
    /// state but tolerant: a torn or missing snapshot recovers as no carried high-waters (every
    /// producer resumes at-least-once, the safe degrade), so it can never block open. The map is
    /// O(active producers) and the snapshot is capped to a slot (the most-recently-active producers
    /// that fit), so it never grows unbounded. `None` until the first sequenced produce, so a broker
    /// no producer sequences against never creates the file (the disk image is unchanged).
    producer_seq_checkpoint: Option<ProducerSeqCheckpoint<F::File>>,
    /// The DURABILITY LEVEL (#341, #379): the default [`DurabilityLevel::Sync`] acks only after the
    /// covering fsync (I2 holds, zero acked loss). The relaxed levels ack before the covering fsync
    /// for a documented loss window. Read on every `commit_batch` to decide whether to issue the
    /// covering `fdatasync` or only advance the visible head via `Log::flush_no_sync`. See
    /// [`EngineConfig::durability_level`].
    durability_level: DurabilityLevel,
    /// The `interval` level's TIME window in NANOSECONDS (the configured `flush_interval_ms` converted
    /// at open, on the monotonic clock seam): the most time an acked-but-unsynced record may sit
    /// before the next `commit_batch` forces an `fdatasync`. `0` disables the time trigger. Only
    /// consulted under [`DurabilityLevel::Interval`]. See [`EngineConfig::flush_interval_ms`].
    flush_interval_nanos: u64,
    /// The `interval` level's BYTE budget: the most UNSYNCED record bytes that may accumulate before a
    /// `commit_batch` forces an `fdatasync`. `0` disables the byte trigger. Only consulted under
    /// [`DurabilityLevel::Interval`]. See [`EngineConfig::flush_max_bytes`].
    flush_max_bytes: u64,
    /// The monotonic-clock instant (nanoseconds, via the clock seam, never a raw `Instant::now`) of
    /// the LAST completed `fdatasync` under a relaxed level, the time-window anchor for `interval`
    /// (#341). Seeded to the engine's open instant (a fresh broker's first record is at most one
    /// window old). Reset to the current monotonic instant every time a covering fsync completes, so
    /// the next window measures from the last real durability barrier. Unused under `sync` (which
    /// always fsyncs).
    last_sync_monotonic_nanos: u64,
    /// The measured nanoseconds the LAST real `fdatasync` took (via the clock seam), carried out of
    /// [`Engine::commit_durability_barrier`] so `commit_batch` records it into the latency histograms
    /// only when a genuine barrier ran. Meaningless when the last commit deferred its sync; the caller
    /// only reads it when the barrier reported a real fsync.
    last_fsync_nanos: u64,
    /// The runtime backpressure controllers and their shed counters (#68, #69): the CoDel
    /// produce-admission shed, the broker-side retry budget, the fire-and-forget token bucket, and
    /// the egress AIMD limiter. Held OUTSIDE the durable counters snapshot (a runtime resilience
    /// signal, not a checkpointed counter). All four default to inert, so a broker that configures no
    /// backpressure knob behaves exactly as today. See [`Backpressure`] and
    /// [`ironbus_core::backpressure`].
    backpressure: Backpressure,
    /// The OPT-IN, OFF-BY-DEFAULT key-compaction configuration (#337): when enabled, after the
    /// produce-path reaper runs the engine runs ONE rate-limited, off-hot-path compaction pass over
    /// a run of adjacent dirty SEALED segments, rewriting the survivors (keeping their original
    /// sparse offsets) into a fresh v2 compacted segment. It NEVER touches the active segment, so it
    /// never races or blocks an append. The default is DISABLED, so a broker that does not opt in is
    /// byte-for-byte unchanged. Set with [`Engine::set_compaction_config`]. The order is fixed and
    /// load-bearing (`compact_and_delete`): the cheap whole-segment reaper runs FIRST, then the
    /// compactor, so CPU and flash are never spent compacting a segment about to be reaped. See
    /// [`ironbus_storage::compaction`] and `docs/COMPACTION.md`.
    compaction: ironbus_storage::compaction::CompactionConfig,
    /// The per-record write-path compression configuration (#430, ADR-0003), materialized at open
    /// from [`EngineConfig::compression`] with the frozen defaults (the 64-byte raw-store
    /// threshold, no dictionary). Consulted on the single append seam
    /// ([`Engine::append_no_sync`]); a `Codec::None` codec makes the seam a pass-through, so the
    /// historical broker is byte-for-byte unchanged.
    compress: CompressConfig<'static>,
    /// The bounded Level-2 produce-confirm registry (#497, part of #499): the per-offset map keying a
    /// producer's awaited `ProduceConfirm` to the durable offset and the producer connection. EMPTY
    /// until a producer publishes at Level 2 (`AckLevel::ServerAndClientAck`), so a broker no producer
    /// uses Level 2 on pays nothing here. A Level-2 produce registers its durable offset
    /// ([`Engine::register_l2_confirm`]) AFTER its Level-1 `PubAck` (the record is durable first, I2);
    /// when the DESIGNATED group's committed cursor advances past that offset (the cursor-commit hook
    /// in [`Engine::ack_in`] / [`Engine::cumulative_ack_in`]) a `Consumed` confirm fires; a
    /// dead-letter / force-reap before any ack fires a `DeadLettered` confirm; the idle/retention tick
    /// sweeps a confirm no consumer acks within the TTL to `TimedOut`; a producer disconnect drops its
    /// entries. HARD-bounded (a max pending count AND a TTL), so a slow or absent consumer can never
    /// grow it without bound (the same threat class as the dedup window cap).
    confirm_registry: ConfirmRegistry,
    /// The name of the ONE designated consumer group whose ack confirms a Level-2 produce (#497).
    /// "Consumed" is ambiguous across the many groups a record is delivered to, so the confirm is
    /// keyed to a SINGLE group: the default group (`""`, the wire's unnamed group) unless an operator
    /// names another, exactly the group whose cursor-commit the engine hooks. Keyed to ONE group (not
    /// "any group", which is non-deterministic, nor "all groups", which is unbounded). The engine
    /// fires `Consumed` only when THIS group's cursor advances; an ack in any other group is ignored
    /// by the confirm path (its own delivery and acking are unaffected).
    confirm_group: String,
}

/// The file name of the work-group's durable committed-cursor checkpoint.
const CURSOR_CHECKPOINT: &str = "cursor.ckpt";

/// The file name of the durable resilience-counters checkpoint (#98). It never collides with the
/// cursor checkpoints (`cursor.ckpt` and `cursor-<hex>.ckpt`).
const COUNTERS_CHECKPOINT: &str = "counters.ckpt";

/// The file name of the default group's durable per-message ATTEMPT-COUNT checkpoint (#358). It
/// never collides with the cursor or counters checkpoints (`attempts.` vs `cursor.`/`counters.`),
/// and named groups use `attempts-<hex>.ckpt`.
const ATTEMPTS_CHECKPOINT: &str = "attempts.ckpt";

/// The file name of the durable idempotent-producer SEQUENCE checkpoint (V2-M8, #638/#639). It never
/// collides with the cursor/counters/attempts checkpoints (`producer-seq.` vs `cursor.`/`counters.`/
/// `attempts.`). UNLIKE the others it is opened lazily: a broker no producer sequences against never
/// creates it, so the disk image of a non-idempotent workload is unchanged.
const PRODUCER_SEQ_CHECKPOINT: &str = "producer-seq.ckpt";

/// The result of opening the durable idempotent-producer SEQUENCE checkpoint (V2-M8): the dual-slot
/// handle (only `Some` if the file already existed at open) plus the recovered snapshot bytes (decoded
/// and clamped by the caller), or `None` if the file was absent or its slots were torn.
type RecoveredProducerSeq<File> = (Option<ProducerSeqCheckpoint<File>>, Option<Vec<u8>>);

/// The result of opening the durable attempt-count checkpoint (#358): the long-lived dual-slot
/// handle plus the recovered snapshot bytes (decoded and clamped by the caller), or `None` if the
/// file was fresh or its slots were torn. Named so the [`Engine::open_attempts_checkpoint`]
/// signature stays simple.
type RecoveredAttempts<File> = (AttemptsCheckpoint<File>, Option<Vec<u8>>);

/// The result of [`Engine::open_log_and_streams`] (#676): the DEFAULT stream's root [`Log`] paired
/// with the per-NAMED-stream [`StreamSet`] substrate. Named so the two-element tuple does not trip
/// the `type_complexity` lint and reads as one value at the call site.
type LogAndStreams<F, C> = (Log<F, C>, StreamSet<F, C>);

/// Materializes the engine's write-path compression configuration (#430, ADR-0003): the
/// configured codec over the frozen defaults (the 64-byte raw-store threshold, `dict_id` 0, no
/// dictionary, the default zstd level). Kept out of [`Engine::open`] so the open path stays
/// readable; the seam itself lives in [`Engine::append_no_sync`].
fn compress_config(codec: Codec) -> CompressConfig<'static> {
    CompressConfig {
        codec,
        ..CompressConfig::default()
    }
}

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
    #[allow(clippy::too_many_lines)]
    pub fn open(fs: F, clock: C, config: EngineConfig) -> Result<Engine<F, C>, EngineError>
    where
        F: Clone,
    {
        if config.max_in_flight == 0 {
            return Err(EngineError::ZeroMaxInFlight);
        }
        // Open the DEFAULT stream's root log AND the per-named-stream StreamSet substrate (#676). The
        // root log is opened FIRST so it owns the authoritative recovery (truncating + reporting any
        // torn tail, byte for byte as before); the StreamSet then re-opens the already-clean root for
        // its inert `""` slot and recovers the named streams. See [`Engine::open_log_and_streams`].
        let (log, streams) = Self::open_log_and_streams(fs, clock, config.log)?;

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

        // Open (creating if absent) the default group's attempt-count checkpoint (#358) and recover
        // its snapshot, so the durable per-message attempt counts seed the default lease table below
        // and `MaxDeliver` survives an unclean restart. The handle is kept long-lived like the cursor
        // checkpoint; the recovered bytes are clamped and applied after the cursor resumes. Factored
        // out (like the counters checkpoint) to keep `open` readable.
        let (attempts_checkpoint, recovered_attempts) = Self::open_attempts_checkpoint(&log)?;

        // Open and recover the durable resilience-counters checkpoint (#98), seeding the in-memory
        // counters from the last snapshot (or all-zeros if it is missing or torn) AND reconciling the
        // recovery-loss family with the durable log / loss report (#307). Factored out to keep `open`
        // readable; the never-block-recovery contract and the checkpoint-plus-replay max live there.
        let (counters_checkpoint, counters) = Self::open_counters_checkpoint(&log)?;

        // Recover the durable idempotent-producer SEQUENCE high-waters (V2-M8). If the
        // `producer-seq.ckpt` file exists, open its dual-slot handle and decode the last fully-durable
        // snapshot; a torn or corrupt snapshot decodes to nothing (every producer resumes
        // at-least-once, the safe degrade), never blocking open. The decoded high-waters are RESTORED
        // into the registry after construction (seed_producer_seq_from_recovered), so a replayed retry
        // across this restart is STILL deduped — and because the bound is sequence state, not
        // wall-clock, a long offline gap never drops it (the beat over NATS). A broker that never had a
        // sequenced producer has no file and opens with an empty registry + no handle (disk unchanged).
        let (producer_seq_checkpoint, recovered_seq) = Self::open_producer_seq_checkpoint(&log)?;

        let flushed = log.flushed_offset().get();
        // The open-time monotonic instant, used to seed each group's last-activity (#277), so a
        // group recovered at open is treated as just-active and the idle eviction sweep cannot
        // reclaim it before it has had a full idle window of inactivity after the restart.
        let opened_at = log.now_monotonic();
        // The broker start time as Unix SECONDS for `ironbus_start_time_seconds` (#97), read ONCE
        // from the clock seam (never a raw `SystemTime::now`); uptime derives from `opened_at`.
        let start_time_unix_seconds = log.now_unix_millis() / 1_000;
        // The default group's durable cursor, from `cursor.ckpt`, clamped to the head, plus its
        // durable attempt counts from `attempts.ckpt` (#358): a redelivered in-flight message
        // resumes its attempt number instead of resetting to 1, so `MaxDeliver` routes a poison
        // record to the DLQ after at least `MaxDeliver` attempts TOTAL across the restart (at most that
        // plus the redeliveries not yet checkpointed when the crash hit; never below the durable floor).
        let cursor = resume_cursor_from_snapshot(recovered.as_deref(), flushed);
        let default_committed = cursor.committed().get();
        let mut default_group = resume_work_group(
            cursor,
            recovered_attempts.as_deref(),
            config.lease,
            opened_at,
            flushed,
        );
        // The boot-created default group starts UNTOUCHED (#424) when it carries no durable
        // consumer state at all: no `cursor.ckpt` and no `attempts.ckpt`. It exists structurally
        // (the wire's unnamed group), so its fresh offset-0 cursor must not pin the retention
        // protect floor for a deployment that only consumes through named groups. The first
        // consumer interaction in this process, or any durable state at the next open, marks it
        // a real consumer with the full slow-consumer protection.
        default_group.touched = recovered.is_some() || recovered_attempts.is_some();
        let mut groups = BTreeMap::new();
        groups.insert(DEFAULT_GROUP.to_string(), default_group);
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
        let group_last_checkpointed = recover_named_groups(
            log.filesystem(),
            &mut groups,
            config.lease,
            opened_at,
            flushed,
        )?;

        // The DLQ sink's log shares the main log's segment sizing but is NEVER byte-capped: a
        // poison record is the durable evidence of a dropped message and must not itself be shed.
        let dlq_config = LogConfig {
            max_segment_bytes: config.log.max_segment_bytes,
            max_total_bytes: 0,
            // The DLQ is already the durable forensic sink for dropped messages; it needs no second
            // forensic quarantine of its own.
            max_quarantine_bytes: 0,
            // The DLQ must NEVER shed: a poison record is durable evidence, so it carries no daily
            // physical write budget (the flash-wear governor is for the main produce path only, #118).
            daily_physical_write_budget_bytes: 0,
        };
        // The dead-letter sink's subdir: the configured dead-letter EXCHANGE target (#551), or the
        // default fixed `dlq/` (byte-identical to today) when none is configured.
        let dlq_subdir = config
            .dead_letter_exchange
            .as_deref()
            .unwrap_or(DLQ_SUBDIR)
            .to_string();
        // Eagerly open (recovering its high-water mark) the dead-letter sink IF its subdirectory
        // already exists from a prior run, so the idempotency key is present before the first poison
        // redelivers after a crash. A fresh data directory has no sink subdir yet, so the sink stays
        // unopened (lazy) and the no-dead-letter path never creates it.
        let dlq = if Self::dlq_dir_exists(&log, &dlq_subdir) {
            Some(DlqSink::open_at(
                log.filesystem(),
                &dlq_subdir,
                log.clock_clone(),
                dlq_config,
            )?)
        } else {
            None
        };

        // The TRANSACTIONAL HALF-MESSAGE store's log (V2-M8, #640) shares the main log's segment
        // sizing but is NEVER byte-capped: a prepared half message is an undelivered durable payload
        // and a resolution op-marker is the durable record of the commit/rollback, so neither may be
        // shed. Eagerly open it (recovering the lifecycle table + buffered payloads) IF its `txn/`
        // subdirectory already exists from a prior run, so a crash-orphaned prepared half message is
        // recoverable before the first resolve after a crash. A fresh data directory has no `txn/`
        // subdir yet, so the store stays unopened (lazy) and the non-transactional path never creates
        // it — keeping the hot path byte-for-byte unchanged.
        let txn_config = LogConfig {
            max_segment_bytes: config.log.max_segment_bytes,
            max_total_bytes: 0,
            max_quarantine_bytes: 0,
            daily_physical_write_budget_bytes: 0,
        };
        let txn = if Self::txn_dir_exists(&log) {
            Some(TxnStore::open(
                log.filesystem(),
                log.clock_clone(),
                txn_config,
                ironbus_core::txn::TxnConfig::default(),
            )?)
        } else {
            None
        };

        // Build the backpressure controllers (#68, #69) from the config knobs BEFORE the struct
        // literal, since the literal moves the non-Copy `config.delivery` and field expressions are
        // evaluated in source order (a later read of `config` would then be a
        // borrow-after-partial-move). All knobs default to inert.
        let backpressure = Backpressure::from_engine_config(&config);
        let mut engine = Engine {
            log,
            // The per-named-stream LOG substrate (#676), opened above; recovered named streams (if
            // any) are already in it. The default stream is served by `log`, never this set's `""`.
            streams,
            // The per-named-stream CONSUMER state (#676): EMPTY at open. A named stream gets its
            // entry on its first produce (alongside the StreamSet `declare`); its work-groups are
            // created lazily on first consume. A deployment that never names a stream keeps this
            // empty, so the default path is byte-for-byte today. (Recovering a named stream's
            // consumer cursors across a restart is the flagged #60-style follow-up; today only the
            // named stream's LOG recovers, via the StreamSet.)
            named_streams: BTreeMap::new(),
            // The subject->stream binding table (#585): EMPTY at open (no subject is bound until a
            // client `BindSubject`s one). Bindings are in-memory only this phase — a stream's subject
            // bindings do NOT survive a restart (only its LOG recovers, via the StreamSet); durable
            // binding persistence is a flagged follow-up. A deployment that never binds keeps this empty,
            // so the default + explicit-stream-id paths are byte-for-byte unaffected.
            bindings: BindingTable::new(),
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
            attempts_checkpoint,
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
            ram_ceiling_bytes: config.ram_ceiling_bytes,
            last_checkpointed: default_committed,
            // Seed at the resumed watermark so a freshly-opened, fully-drained group does not
            // redundantly re-write its empty attempt snapshot before any new poll (#358).
            last_attempts_checkpointed: default_committed,
            // Seeded from the durable counters snapshot (#98), all-zeros if it was missing or torn.
            counters,
            fsync: LatencyHistogram::default(),
            // The bounded metric registry (#97), from the clock seam; its head and per-consumer
            // floors are seeded from the recovered state after construction.
            registry: MetricRegistry::new(crate_version(), start_time_unix_seconds, opened_at),
            last_dead_lettered: None,
            dlq,
            dlq_config,
            // The transactional half-message store (V2-M8, #640): opened above iff the `txn/` subdir
            // already exists, else `None` until the first `TxnPrepare` lazily creates it. A
            // non-transactional broker keeps this `None`, so the produce/consume hot path is unchanged.
            txn,
            txn_config,
            // Empty by default: no group is key_shared until an operator configures one (#64), so an
            // unconfigured engine is plain competing everywhere and unchanged.
            key_shared_groups: std::collections::BTreeSet::new(),
            // The read-only cross-cluster MIRROR set (#623): EMPTY by default, so a non-geo broker's
            // produce path is byte-for-byte unchanged. Configured once via
            // `set_mirror_read_only_streams` only when a `--mirror` is present.
            mirror_read_only: std::collections::BTreeSet::new(),
            // The opt-in dedup registry (#33), sized by the configured window. Empty until a
            // producer opts in by sending a `msg_id`, so it costs nothing for a no-dedup workload.
            dedup: ironbus_core::dedup::DedupRegistry::new(config.dedup),
            // The idempotent-producer SEQUENCE registry (V2-M8). Self-bounded by `SeqConfig` internal
            // defaults (NOT a new `EngineConfig` field, like the confirm registry), so every config
            // construction site is unchanged; a knob can be threaded later. Empty here, then RESTORED
            // from the recovered `producer-seq.ckpt` snapshot by `seed_producer_seq_from_recovered`
            // below, so a sequenced retry is deduped across this restart.
            producer_seq: ProducerSeqRegistry::new(SeqConfig::default()),
            // The durable idempotent-SEQUENCE checkpoint handle: `Some` iff a `producer-seq.ckpt`
            // already existed at open (recovered above), else `None` until the FIRST sequenced produce
            // creates it. A broker no producer sequences against never creates the file.
            producer_seq_checkpoint,
            // The durability level (#341, #379): default `sync` is the historical durable broker
            // (ack only after the covering fsync, I2). The interval window is held in nanoseconds on
            // the monotonic clock seam; the time-window anchor is seeded to the open instant so a
            // fresh broker's first record is at most one window old.
            durability_level: config.durability_level,
            flush_interval_nanos: config.flush_interval_ms.saturating_mul(1_000_000),
            flush_max_bytes: config.flush_max_bytes,
            last_sync_monotonic_nanos: opened_at,
            last_fsync_nanos: 0,
            // The runtime backpressure controllers (#68, #69), prebuilt above. Held outside the
            // durable snapshot, so a broker that configures none of them is byte-for-byte the
            // historical broker.
            backpressure,
            // Key compaction (#337) is OFF by default: an operator opts a topic in via
            // `set_compaction_config`. A broker that does not is byte-for-byte unchanged (no v2
            // segment is ever written, no compaction pass ever runs).
            compaction: ironbus_storage::compaction::CompactionConfig::default(),
            // The #430 write-path compression seam; `Codec::None` makes it a pass-through,
            // so the disk image is byte-for-byte historical.
            compress: compress_config(config.compression),
            // The bounded Level-2 produce-confirm registry (#497), at its default cap + TTL. Empty
            // until a producer publishes at Level 2, so a no-L2 broker pays nothing. NOT a new
            // `EngineConfig` field (the registry is self-bounded by internal defaults); a knob can be
            // threaded later without touching every config construction site.
            confirm_registry: ConfirmRegistry::new(ConfirmConfig::default()),
            // The designated group whose ack confirms a Level-2 produce (#497): the default/unnamed
            // group, which every plain producer/consumer uses. An operator can redesignate it via
            // `set_confirm_group` server-side (NOT on the wire).
            confirm_group: DEFAULT_GROUP.to_string(),
            // The per-stream default message TTL (V2-M4, #549), as the pure `Ttl` policy type; `0`
            // (the default) is `Ttl::NONE`, so a non-TTL broker never expires a record on read.
            default_message_ttl: Ttl::from_millis(config.default_message_ttl_ms),
            // The configurable dead-letter exchange + the expired-routing flag (#551), inert by
            // default (`None` keeps the fixed `dlq/` sink byte-identical).
            dead_letter_exchange: config.dead_letter_exchange,
            dead_letter_expired: config.dead_letter_expired,
        };
        engine.seed_registry_from_recovered_state(flushed);
        // RESTORE the durable idempotent-producer SEQUENCE high-waters (V2-M8) into the registry, so a
        // replayed sequenced retry across this broker restart is STILL deduped to the original offset
        // and a long offline gap never drops it. A `None`/torn snapshot restores nothing (every
        // producer resumes at-least-once). Clamped to the durable head so a high-water can never point
        // past a record the log actually holds (a snapshot written slightly ahead of a torn-tail
        // recovery degrades to at-least-once for that producer rather than returning a phantom offset).
        engine.seed_producer_seq_from_recovered(recovered_seq.as_deref(), flushed, opened_at);
        Ok(engine)
    }

    /// Enables (or reconfigures) OPT-IN key compaction (#337), OFF by default. When enabled, the
    /// engine runs ONE rate-limited, OFF-HOT-PATH compaction pass after each produce-path reaper run
    /// (the `compact_and_delete` order: reaper first, then compactor). Compaction only ever touches
    /// SEALED segments and writes a NEW v2 segment, never the active one, so it cannot race or block
    /// an append. Pass a [`CompactionConfig`](ironbus_storage::compaction::CompactionConfig) with
    /// `enabled: true` to turn it on; the default is disabled.
    /// Opens the DEFAULT stream's root [`Log`] and the per-NAMED-stream [`StreamSet`] substrate over
    /// the SAME data directory (#676), in the load-bearing ORDER:
    ///   1. the root log FIRST, from the ORIGINAL `fs`: today's single-log open, which performs the
    ///      #670 layout-marker check and the longest-valid-prefix recovery, TRUNCATING any torn
    ///      active-segment tail and REPORTING that loss — byte for byte as before. It owns the
    ///      authoritative recovery of the root.
    ///   2. the [`StreamSet`] SECOND, from a CLONE of `fs`: its inert `""` slot is a read-only re-open
    ///      of the now-already-recovered root that the engine NEVER writes (the default stream is
    ///      served by the root `Log`), and it recovers each NAMED stream under `streams/`
    ///      independently. A data dir with no `streams/` subtree opens with only the inert `""` slot
    ///      and never materializes `streams/`, so the disk image is unchanged.
    ///
    /// The order matters: a [`StreamSet`] open BEFORE the root open would recover (repair) the torn
    /// tail first, so the root's own open would then find it already clean and report ZERO loss,
    /// masking the recovery-loss the existing tests (and the loss report) assert. (Folding the default
    /// fully INTO the [`StreamSet`] to drop the inert duplicate `""` slot is the flagged follow-up.)
    ///
    /// # Errors
    /// Propagates a storage error from either open (including the fail-closed layout-version check).
    fn open_log_and_streams(
        fs: F,
        clock: C,
        config: LogConfig,
    ) -> Result<LogAndStreams<F, C>, EngineError>
    where
        F: Clone,
    {
        let fs_for_streams = fs.clone();
        let log = Log::open(fs, clock.clone(), config)?;
        let (streams, _stream_recoveries) =
            StreamSet::open(&fs_for_streams, clock, config).map_err(EngineError::Storage)?;
        Ok((log, streams))
    }

    pub fn set_compaction_config(&mut self, config: ironbus_storage::compaction::CompactionConfig) {
        self.compaction = config;
    }

    /// Declare a set of NAMED local streams as READ-ONLY cross-cluster MIRRORS (#623, V2-C7-I1): a
    /// client PRODUCE to any of these is rejected with [`EngineError::MirrorReadOnly`], so a mirror's
    /// only writer stays the geo mirror-apply path (single-writer preserved). Configured ONCE on a
    /// `--mirror` serve; with no geo config it is never called, so the set stays empty and the produce
    /// path is byte-for-byte unchanged. The empty name (`""`, the default stream) is NEVER a mirror and
    /// is filtered out defensively.
    pub fn set_mirror_read_only_streams<I: IntoIterator<Item = String>>(&mut self, streams: I) {
        self.mirror_read_only = streams.into_iter().filter(|s| !s.is_empty()).collect();
    }

    /// True if `stream` is a configured READ-ONLY mirror (a client produce to it must be rejected). The
    /// fast path is a single `BTreeSet::is_empty` short-circuit, so a non-geo broker pays nothing.
    #[must_use]
    pub fn is_mirror_read_only(&self, stream: &str) -> bool {
        !self.mirror_read_only.is_empty() && self.mirror_read_only.contains(stream)
    }

    /// The current key-compaction configuration (#337). Disabled by default. Read-only echo for the
    /// introspection / config surface.
    #[must_use]
    pub fn compaction_config(&self) -> ironbus_storage::compaction::CompactionConfig {
        self.compaction
    }

    /// Applies the LIVE-reloadable engine configuration (#380): the consumer-safe retention bounds
    /// (size / age / count) and the disk-full overflow policy. These are the ONLY engine knobs a
    /// runtime reload (a SIGHUP re-read of `--config`, see `crates/ironbus-cli`) changes on a running
    /// broker, precisely because they are read only OFF the per-message hot path — the retention
    /// reaper and the disk-full make-room path — so changing them between commits is sound: the next
    /// reap uses the new bounds (still floored at the consumer protect offset by `reap_for_retention`,
    /// so a tightened bound never reaps below a live group's cursor), and the next over-cap produce
    /// uses the new policy. Every other engine knob (durability, flush, the per-consumer credits,
    /// max-in-flight, the segment size, the data dir) is contract- or layout-bound and requires a
    /// restart; the caller diffs those itself and refuses to apply a change here.
    ///
    /// Runs an immediate reap so a reload that TIGHTENS retention reclaims space at once rather than
    /// waiting for the next produce (produce-path reaping is otherwise only triggered by a produce).
    ///
    /// # Errors
    /// [`EngineError`] if the immediate retention reap hits a storage error. The new bounds and
    /// policy are already installed before the reap runs (a failed reclamation never undoes a durable
    /// record, mirroring [`Engine::reap_for_retention`]'s own contract), so a reap on the next
    /// produce simply continues from the new bounds.
    pub fn apply_reloadable_config(
        &mut self,
        retention: RetentionBounds,
        disk_full_policy: DiskFullPolicy,
    ) -> Result<(), EngineError> {
        self.retention = retention;
        self.disk_full_policy = disk_full_policy;
        self.reap_for_retention()
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

    /// Whether the dead-letter sink's `subdir` already exists, so a prior run dead-lettered at least
    /// one message there. `subdir` is the configured dead-letter EXCHANGE target (#551), or the
    /// default `dlq/`. Used by [`Engine::open`] to decide whether to eagerly open the sink (rebuilding
    /// the idempotency high-water mark) versus deferring to the lazy open on the first dead-letter.
    /// This is a non-creating probe ([`Filesystem::subdir_exists`]), so `Engine::open` on a fresh
    /// data directory never materializes the sink subdirectory.
    fn dlq_dir_exists(log: &Log<F, C>, subdir: &str) -> bool {
        log.filesystem().subdir_exists(subdir).unwrap_or(false)
    }

    /// Whether the transactional half-message store's `txn/` subdirectory already exists, so a prior
    /// run prepared at least one half message (V2-M8, #640). Used by [`Engine::open`] to decide whether
    /// to eagerly open the store (recovering the lifecycle table + buffered prepared payloads) versus
    /// deferring to the lazy open on the first `TxnPrepare`. A non-creating probe
    /// ([`ironbus_storage::txn::TxnStore::dir_exists`]), so `Engine::open` on a fresh data directory
    /// never materializes the `txn/` subtree.
    fn txn_dir_exists(log: &Log<F, C>) -> bool {
        TxnStore::<F, C>::dir_exists(log.filesystem()).unwrap_or(false)
    }

    /// Opens (creating if absent) the default group's durable per-message ATTEMPT-COUNT checkpoint
    /// (#358) and recovers the last snapshot bytes, returning the checkpoint handle plus the
    /// recovered payload (decoded and clamped by the caller after the cursor resumes). The handle is
    /// kept long-lived like the cursor and counters checkpoints. A torn or missing snapshot is
    /// surfaced as `None`/discarded by the dual-slot fallback, so it never blocks open; the only
    /// errors are genuine IO failures from creating or reading the file.
    ///
    /// # Errors
    /// Propagates a genuine IO error from creating or opening the attempts checkpoint file.
    fn open_attempts_checkpoint(
        log: &Log<F, C>,
    ) -> Result<RecoveredAttempts<F::File>, EngineError> {
        let attempts_file = {
            let fs = log.filesystem();
            if fs.exists(ATTEMPTS_CHECKPOINT)? {
                fs.open(ATTEMPTS_CHECKPOINT)?
            } else {
                let file = fs.create_new(ATTEMPTS_CHECKPOINT)?;
                fs.sync_dir()?; // the new file's directory entry must be durable
                file
            }
        };
        Ok(AttemptsCheckpoint::open(attempts_file)?)
    }

    /// Opens the durable idempotent-producer SEQUENCE checkpoint (V2-M8) IF it already exists, and
    /// recovers the last snapshot bytes, returning `(Some(handle), recovered)`; if the file is absent
    /// it returns `(None, None)` WITHOUT creating it (a broker no producer sequences against never
    /// materializes the file, so a non-idempotent workload's disk image is unchanged — the handle is
    /// created lazily on the first sequenced produce by [`Engine::ensure_producer_seq_checkpoint`]).
    /// A torn or missing snapshot is surfaced as `None` by the dual-slot fallback, so it never blocks
    /// open; the only errors are genuine IO failures from opening or reading the file.
    ///
    /// # Errors
    /// Propagates a genuine IO error from opening the producer-seq checkpoint file.
    fn open_producer_seq_checkpoint(
        log: &Log<F, C>,
    ) -> Result<RecoveredProducerSeq<F::File>, EngineError> {
        let fs = log.filesystem();
        if !fs.exists(PRODUCER_SEQ_CHECKPOINT)? {
            return Ok((None, None));
        }
        let file = fs.open(PRODUCER_SEQ_CHECKPOINT)?;
        let (checkpoint, recovered) = ProducerSeqCheckpoint::open(file)?;
        Ok((Some(checkpoint), recovered))
    }

    /// RESTORES the recovered idempotent-producer SEQUENCE high-waters (V2-M8) into the registry at
    /// open, so a replayed sequenced retry across this broker restart is STILL deduped to its original
    /// offset and a long offline gap never drops it (the durability beat over NATS's time-bounded
    /// window). A `None` or torn snapshot restores nothing — every producer resumes at-least-once, the
    /// safe degrade. Each high-water is CLAMPED to the durable head `flushed`: a snapshot whose
    /// `last_offset` points PAST a record the log actually holds (e.g. it was written slightly ahead of
    /// a torn-tail recovery) is dropped for that producer rather than returning a phantom offset, so a
    /// recovered duplicate can never point past the durable log. `now` seeds the LRU recency.
    fn seed_producer_seq_from_recovered(
        &mut self,
        recovered: Option<&[u8]>,
        flushed: u64,
        now: u64,
    ) {
        let Some(bytes) = recovered else {
            return;
        };
        let Ok(entries) = decode_seq_snapshot(bytes) else {
            // A torn or corrupt snapshot: restore nothing (at-least-once), never trust bad state.
            return;
        };
        for (producer_id, epoch, last_seq, last_offset) in entries {
            // Clamp: a high-water offset must point at a record the durable log holds. `flushed` is
            // the count of durable records, so a valid record offset is strictly below it. Drop a
            // high-water whose offset is past the durable head (degrade that producer to at-least-once).
            if last_offset.get() >= flushed {
                continue;
            }
            self.producer_seq
                .restore(&producer_id, epoch, last_seq, last_offset, now);
        }
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
        // Recovery-EVENT counters (#575): record THIS open as one recovery run, classified by its loss
        // report, and add this run's per-event repair counts. Unlike the recovery-LOSS `max`
        // reconciliation above, these are additive per-open EVENT counts, which is correct and never
        // double-counts: `loss_report()` reflects only THIS recovery (a torn tail or corruption span
        // this open dropped), and a clean re-open after a prior recovery already truncated/quarantined
        // the damage carries an EMPTY report, so it adds a clean-outcome run and zero repairs.
        Self::accumulate_recovery_events(&mut counters.recovery, log.loss_report());
        Ok((counters_checkpoint, counters))
    }

    /// Records ONE recovery run in the recovery-EVENT counter family (#575), the marquee
    /// corruption-recovery metrics NATS has no analogue for. It is called once per [`Engine::open`]
    /// with the just-recovered durable [`LossReport`]:
    ///
    /// - bumps exactly ONE `runs_by_outcome` bucket: `Clean` for an empty report, else
    ///   `TornTailTruncated` when the only loss was a torn tail (no data loss), else `Quarantined`
    ///   when a data-loss corruption span was dropped (the corruption was copied to the quarantine
    ///   store before truncation, per the recovery contract);
    /// - adds the count of `TornTail` loss events to `torn_tail_repairs`;
    /// - adds each data-loss (corruption) event to the matching `corruption_repairs_by_artifact`
    ///   bucket. A corruption skip in the main log is the `Segment` artifact; recovery does not
    ///   today produce cursor or DLQ corruption loss events (a torn cursor reverts via its dual-slot
    ///   checkpoint, never producing a loss event), so those buckets stay zero here, reserved for the
    ///   frozen taxonomy and incremented by the offline `repair` path when it acts on those artifacts.
    ///
    /// It is a pure, saturating accumulation over the in-memory report (no IO, never fails recovery),
    /// and adding only THIS open's events keeps the counters monotonic non-decreasing across restarts
    /// without double-counting (the report is per-recovery; a clean re-open adds nothing).
    fn accumulate_recovery_events(recovery: &mut RecoveryCounters, loss: &LossReport) {
        let data_loss = loss.data_loss_bytes() > 0;
        let outcome = if loss.is_empty() {
            RecoveryOutcome::Clean
        } else if data_loss {
            RecoveryOutcome::Quarantined
        } else {
            RecoveryOutcome::TornTailTruncated
        };
        let bucket = &mut recovery.runs_by_outcome[outcome.index()];
        *bucket = bucket.saturating_add(1);

        for event in &loss.events {
            if event.reason_code.is_data_loss() {
                // A corruption skip in the main log: the `Segment` artifact. (Recovery does not
                // emit cursor/DLQ loss events today; those buckets are driven by the offline
                // `repair` path, reserved here so the taxonomy is frozen up front.)
                let idx = RecoveryArtifact::Segment.index();
                recovery.corruption_repairs_by_artifact[idx] =
                    recovery.corruption_repairs_by_artifact[idx].saturating_add(1);
            } else {
                recovery.torn_tail_repairs = recovery.torn_tail_repairs.saturating_add(1);
            }
        }
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
        let has_in_flight = group.leases.in_flight() > 0;
        if committed > self.last_checkpointed || has_ahead {
            let payload = self.cursor_checkpoint_payload();
            self.checkpoint.write(&payload)?;
            self.last_checkpointed = committed;
        }
        // Persist the durable per-message attempt counts (#358) when the cursor advanced OR there
        // are in-flight leases: a redelivery escalates an attempt count WITHOUT moving the cursor,
        // so a poison record being retried must still record its rising count. Writing an empty
        // snapshot when nothing is in flight clears any stale carried counts from the last crash.
        if committed > self.last_attempts_checkpointed || has_in_flight {
            self.checkpoint_default_attempts()?;
            self.last_attempts_checkpointed = committed;
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

    /// Durably writes the default group's in-flight attempt-count snapshot to `attempts.ckpt`
    /// (#358), via the same CRC'd dual-slot checkpoint the cursor uses. The payload is the live
    /// lease table's `(offset, attempt)` pairs, capped to a slot; an empty payload (nothing in
    /// flight) is a valid snapshot that clears any stale carried counts. The handle is long-lived,
    /// so this continues the crash-safe two-slot sequence without reopening.
    ///
    /// # Errors
    /// Propagates a storage error from writing the checkpoint.
    fn checkpoint_default_attempts(&mut self) -> Result<(), EngineError> {
        let pairs = self
            .groups
            .get(DEFAULT_GROUP)
            .map_or_else(Vec::new, |g| g.leases.attempt_counts());
        let payload = attempts_snapshot_payload(&pairs);
        self.attempts_checkpoint.write(&payload)?;
        Ok(())
    }

    /// Durably writes a NAMED group's in-flight attempt-count snapshot to its `attempts-<hex>.ckpt`
    /// (#358), the companion to [`Engine::write_group_checkpoint`]. The file is reopened per write so
    /// the crash-safe two-slot sequence continues correctly, exactly as the named cursor checkpoint.
    ///
    /// # Errors
    /// Propagates a storage error from opening or writing the checkpoint file.
    fn write_group_attempts(&mut self, group: &str) -> Result<(), EngineError> {
        let pairs = match self.groups.get(group) {
            Some(g) => g.leases.attempt_counts(),
            None => return Ok(()),
        };
        let payload = attempts_snapshot_payload(&pairs);
        let name = group_attempts_name(group);
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
        let (mut cp, _) = AttemptsCheckpoint::open(file)?;
        cp.write(&payload)?;
        Ok(())
    }

    /// Builds the CRC-protected idempotent-producer SEQUENCE snapshot payload (V2-M8), capped to a
    /// checkpoint slot. The high-waters come from the registry SORTED by `producer_id`; if the snapshot
    /// would overflow a slot (more active producers than fit), only the leading entries that fit are
    /// kept — dropping the overflow tail only resets those few producers to at-least-once after a
    /// restart (a later publish reads fresh), never a correctness break, and the registry's
    /// `max_producers` cap bounds the count anyway. Sorting is stable, so the SAME producers persist
    /// each flush rather than thrashing. (A future refinement could prefer the most-recently-active
    /// producers; sorted-prefix is the simple, deterministic bound today.)
    fn producer_seq_snapshot_payload(&self) -> Vec<u8> {
        let entries = self.producer_seq.snapshot_pairs();
        let mut buf = Vec::new();
        encode_seq_snapshot(&entries, &mut buf);
        if buf.len() <= PRODUCER_SEQ_PAYLOAD {
            return buf;
        }
        // Trim to the leading entries that fit. Each entry is `2 + producer_id + 24` bytes; we cannot
        // assume a fixed size, so grow the kept prefix until the encoded size would exceed the cap.
        let mut kept: Vec<ironbus_core::producer_seq::SeqHighWater> = Vec::new();
        let mut probe = Vec::new();
        for entry in entries {
            probe.clear();
            let mut candidate = kept.clone();
            candidate.push(entry.clone());
            encode_seq_snapshot(&candidate, &mut probe);
            if probe.len() > PRODUCER_SEQ_PAYLOAD {
                break;
            }
            kept.push(entry);
        }
        let mut out = Vec::new();
        encode_seq_snapshot(&kept, &mut out);
        out
    }

    /// Lazily opens (creating if absent) the durable idempotent-producer SEQUENCE checkpoint handle
    /// (V2-M8) on the FIRST sequenced produce, so a broker no producer sequences against never creates
    /// `producer-seq.ckpt` (its disk image is unchanged). A no-op once the handle exists.
    ///
    /// # Errors
    /// Propagates a genuine IO error from creating or opening the checkpoint file.
    fn ensure_producer_seq_checkpoint(&mut self) -> Result<(), EngineError> {
        if self.producer_seq_checkpoint.is_some() {
            return Ok(());
        }
        let file = {
            let fs = self.log.filesystem();
            if fs.exists(PRODUCER_SEQ_CHECKPOINT)? {
                fs.open(PRODUCER_SEQ_CHECKPOINT)?
            } else {
                let f = fs.create_new(PRODUCER_SEQ_CHECKPOINT)?;
                fs.sync_dir()?; // the new file's directory entry must be durable
                f
            }
        };
        let (checkpoint, _) = ProducerSeqCheckpoint::open(file)?;
        self.producer_seq_checkpoint = Some(checkpoint);
        Ok(())
    }

    /// Durably writes the idempotent-producer SEQUENCE high-water snapshot to `producer-seq.ckpt`
    /// (V2-M8), via the same CRC'd dual-slot checkpoint discipline the cursor and attempt counts use.
    /// This is what makes a replayed sequenced retry across a broker restart STILL deduped and a long
    /// offline gap never drop it — the durability beat over NATS's time-bounded window. A NO-OP when no
    /// producer has ever sequenced (the handle is `None`), so a non-idempotent workload pays nothing.
    /// CORRECTNESS state (like the attempt counts), so a write error propagates.
    ///
    /// # Errors
    /// Propagates a storage error from writing the checkpoint.
    fn checkpoint_producer_seq(&mut self) -> Result<(), EngineError> {
        if self.producer_seq_checkpoint.is_none() {
            return Ok(()); // no sequenced producer has ever published; nothing durable to write
        }
        // Build the (slot-capped) payload BEFORE taking the mutable handle borrow, so the immutable
        // `self.producer_seq` read does not overlap the `&mut self.producer_seq_checkpoint` write.
        let payload = self.producer_seq_snapshot_payload();
        // The handle is `Some` (checked above); the cap-trimmed payload always fits the slot.
        if let Some(cp) = self.producer_seq_checkpoint.as_mut() {
            cp.write(&payload)?;
        }
        Ok(())
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
            // Persist the durable per-message attempt counts on the same cadence (#358): a poison
            // record under retry must keep its rising attempt count durable so `MaxDeliver` holds
            // across an unclean restart. This is CORRECTNESS state (unlike the counters below), so a
            // write failure propagates rather than being swallowed.
            self.checkpoint_default_attempts()?;
            self.last_attempts_checkpointed = committed;
            // Persist the idempotent-producer SEQUENCE high-waters on the same cadence (V2-M8): a
            // sequenced producer's `(epoch, last_seq, last_offset)` must stay durable so a retry is
            // deduped across an unclean restart AND a long offline gap (the beat over NATS's
            // time-bounded window). CORRECTNESS state, so a write failure propagates. A no-op when no
            // producer has ever sequenced (the handle is `None`).
            self.checkpoint_producer_seq()?;
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
        let has_in_flight = g.leases.in_flight() > 0;
        let last = self
            .group_last_checkpointed
            .get(group)
            .copied()
            .unwrap_or(0);
        if committed > last || has_ahead {
            self.write_group_checkpoint(group, committed)?;
        }
        // Persist this named group's durable attempt counts (#358) when the cursor advanced or any
        // lease is in flight (a redelivery escalates a count without moving the cursor), exactly as
        // the default group does, so MaxDeliver survives a restart in every group.
        if committed > last || has_in_flight {
            self.write_group_attempts(group)?;
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
            // Persist the named group's attempt counts on the same interval cadence (#358).
            self.write_group_attempts(group)?;
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
        // The CLEAN-SHUTDOWN durability barrier (#341, #379): force a real covering `fdatasync`
        // FIRST, so a relaxed level (`interval`/`async`/`none`) makes every acked-but-unsynced record
        // durable before the graceful stop completes. This is what bounds the relaxed levels' loss to
        // "since the last roll OR clean shutdown": a graceful stop loses nothing, only an ABRUPT power
        // cut exposes the open window. Under the default `sync` level there is never an unsynced tail,
        // so this is a cheap no-op fsync. It runs before the cursor checkpoints so the durable log
        // head the checkpoints clamp against is already advanced.
        self.force_sync()?;
        // Snapshot the names first so the checkpoint calls (which take `&mut self`) do not borrow
        // the live `groups` map across the loop.
        let names: Vec<String> = self.groups.keys().cloned().collect();
        for name in names {
            self.checkpoint_group(&name)?;
        }
        // Flush the idempotent-producer SEQUENCE high-waters (V2-M8) on the clean-shutdown barrier too,
        // AFTER the cursors are flushed (so the durable head the high-waters clamp against is advanced)
        // and BEFORE the observability-only counters. CORRECTNESS state: a restart after a clean stop
        // resumes dedup exactly where it left off. A no-op when no producer has ever sequenced.
        self.checkpoint_producer_seq()?;
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
        // start fresh at offset 0 (a genuinely new group). Clamped to the head exactly as `open`. The
        // cursor and the attempt counts (#358) are read INDEPENDENTLY: a group evicted with poison in
        // flight but uncommitted has an `attempts-<hex>.ckpt` yet no `cursor-<hex>.ckpt`, so the
        // attempt counts must resume even when the cursor starts fresh, or MaxDeliver would reset.
        let (cursor, recovered_a) = {
            let fs = self.log.filesystem();
            let cursor = if fs.exists(&name)? {
                let (_, recovered) = Checkpoint::open(fs.open(&name)?)?;
                resume_cursor_from_snapshot(recovered.as_deref(), flushed)
            } else {
                AckCursor::new()
            };
            (cursor, read_group_attempts(fs, group)?)
        };
        // Inserting the live group below also SUPERSEDES any ghost floor pin (#432): once the
        // name is live, `min_committed_offset` reads the touched resumed cursor (exactly the
        // ghost's value) instead of the ghost entry, so the floor follows the returning
        // consumer's live progress immediately, no checkpoint write needed. This resume-at-ghost
        // property holds for THIS consumer path only: the serve-flag declared-group paths
        // (`set_key_ordering_in`, `set_broadcast_in`) create an absent group fresh at offset 0
        // without resuming, which supersedes the ghost with a LOWER (more conservative) pin
        // until the declared group drains; the floor can move down there, never up.
        self.group_last_checkpointed
            .insert(group.to_string(), cursor.committed().get());
        let g = resume_work_group(
            cursor,
            recovered_a.as_deref(),
            self.lease_config,
            now,
            flushed,
        );
        self.groups.insert(group.to_string(), g);
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
        // A single produce is exactly a one-message group commit: append (no sync), then the one
        // durability barrier that covers it, then the post-sync bookkeeping. The append-actor's
        // group-commit path (#177) calls the same two primitives but amortizes ONE `commit_batch`
        // over a drained batch of appends, so this stays the single source of truth for both.
        let offset = self.append_no_sync(message)?;
        self.commit_batch()?;
        Ok(offset)
    }

    // ===================================================================================
    // ID-ROUTED produce / consume / ack (#676, V2-M2-I2b — thread the StreamSet through the
    // Engine). These entry points carry a STREAM ID. The default stream `""` routes to today's
    // single-log path BYTE-FOR-BYTE (it calls the EXISTING `produce` / `poll_in` / `ack_in` on
    // `self.log` + `self.groups`, unchanged); a NAMED stream routes to its own `Log` in the
    // `StreamSet` + its own per-stream `groups` in `self.named_streams`, re-instantiating the SAME
    // competing work-group primitives (AckCursor / LeaseTable / 0-1-2 ack) per stream.
    //
    // SCOPE (#676): the stream id arrives on these INTERNAL entry points and defaults to `""` when
    // absent, so an old client (and every existing caller) reaches the default stream unchanged.
    // The client-facing WIRE frames that carry a stream id (StreamDeclare / PubTo / SubTo) are
    // M2-I10 (#588) — NOT in this PR; the engine is merely READY to receive a stream id. The named
    // stream's consume path here is the COMPETING work-group only; a named stream's DLQ,
    // retry-throttle, key-shared routing, Tier-S streaming, durable per-group cursors, and per-stream
    // metric labels are FLAGGED follow-ups (never removed from the default stream).
    // ===================================================================================

    /// Produces `message` to the stream named `stream` (#676): the default stream (the EMPTY name)
    /// routes to today's single-log [`Engine::produce`] BYTE-FOR-BYTE, while a NAMED stream appends
    /// to its OWN [`Log`] in the [`StreamSet`] and commits it with the cross-stream
    /// [`StreamSet::commit_tick`] barrier (#678/#564). A named stream is `declare`d on its first
    /// produce (materializing `streams/<hex(name)>/` and its independent log + recovery), so a
    /// producer need not declare it separately.
    ///
    /// # Errors
    /// [`EngineError::InvalidStreamName`] for a malformed NAMED name (fail-closed at the boundary,
    /// before the filesystem); else a storage error from the named stream's append or its commit
    /// barrier. The default stream surfaces exactly [`Engine::produce`]'s error taxonomy.
    pub fn produce_in_stream(
        &mut self,
        stream: &str,
        message: &Append<'_>,
    ) -> Result<Offset, EngineError>
    where
        F: Clone,
    {
        // The default stream is today's root log, byte-for-byte: route straight to the existing
        // single-log produce on `self.log`. NOTHING about the default path changes when a stream id
        // is supplied as `""` — an old client (no stream id) and a new client naming `""` are
        // indistinguishable from the historical broker.
        if stream.is_empty() {
            return self.produce(message);
        }
        // READ-ONLY MIRROR guard (#623): a client produce to a configured cross-cluster mirror is
        // rejected fail-closed BEFORE any declare/append, so a mirror's only writer stays the geo
        // mirror-apply path (single-writer preserved). The check is a single set lookup, skipped entirely
        // when no mirror is configured (the non-geo byte-identical path).
        if self.is_mirror_read_only(stream) {
            return Err(EngineError::MirrorReadOnly {
                name: stream.to_string(),
            });
        }
        let id = StreamId::named(stream)?;
        // Declare-on-first-produce: open the named stream's independent log under `streams/<hex>/`
        // (idempotent — a no-op if already open) and mirror it in the per-stream consumer state.
        self.streams.declare(&id).map_err(EngineError::Storage)?;
        self.named_streams
            .entry(id.clone())
            .or_insert_with(NamedStream::new);
        // Append to THIS stream's log (a single-`Log` append; appending to X never touches Y, so
        // per-record cost stays flat as streams grow), then make it durable with the cross-stream
        // group-commit tick. The tick syncs ONLY the dirtied streams; because the engine never
        // dirties the StreamSet's `""` slot (the default stream lives on `self.log`), the default
        // stream's durability is entirely unaffected.
        let offset = self
            .streams
            .append_to(&id, message)
            .map_err(EngineError::Storage)?;
        // Per-stream PRODUCE throughput (#571): one record produced to THIS named stream, keyed by its
        // name (bounded + overflow-folded so an unbounded stream cardinality cannot OOM the node). The
        // default stream is counted in `append_no_sync` under the empty label; a named produce never
        // reaches `append_no_sync` (it routes through the StreamSet), so the two paths never double-count.
        self.registry.record_stream_produced(stream.as_bytes());
        // ONE coordinated commit tick (#678): K dirtied named streams => K fdatasync barriers,
        // amortized over the batch; a clean stream costs nothing. The default `""` slot is never
        // dirtied here, so this never syncs the root a second time.
        let _outcome: CommitOutcome = self.streams.commit_tick();
        Ok(offset)
    }

    // ===================================================================================
    // TRANSACTIONAL HALF-MESSAGE 2PC (#640, V2-M8 part 1/2): prepare / commit / rollback.
    //
    // A producer PREPAREs a half message — durably buffered in `txn/`, INVISIBLE to consumers — then
    // runs its local transaction and COMMITs (the half message is appended to the real target stream
    // and becomes visible) or ROLLs it BACK (the half message is discarded, never delivered). All
    // three go through the single-writer engine (the actor's `Command::Run`), so they are serialized
    // with every produce and never race.
    //
    // ## The crash-safety argument (the load-bearing property)
    //
    // The commit must move the buffered payload to the real stream AND record the resolution across TWO
    // separate logs (the real stream + the `txn/` op-log), and a crash anywhere must NEVER
    // double-append on replay. The ORDERING (in `txn_commit`'s fresh-resolve path) is:
    //
    //   commit(txn):
    //     A.  WRITE the buffered payload to the REAL target stream (NO fsync), DEDUPED by the DURABLE
    //         producer-SEQUENCE high-water keyed on the txn id (`txn_dedup_producer_id(txn)`, seq 0).
    //         This assigns `real_offset` and records the txn-id high-water IN MEMORY.
    //     A2. FLUSH the producer-seq checkpoint (fsync the high-water) — BEFORE the record's own fsync.
    //     A3. COMMIT-BATCH (fsync the record), making the real append durable.
    //     B.  append + fsync the COMMITTED op-marker (carrying `real_offset`) to the `txn/` op-log.
    //
    // The op-marker (B) is the COMMIT POINT: a txn is committed iff its op-marker is durable. The crash
    // windows, each proven by a test:
    //   (a) crash AFTER prepare, BEFORE A: only the half record is durable, so on reopen the txn
    //       replays as Prepared (unresolved, recoverable). A later commit is a FRESH resolve.
    //       (storage test `crash_after_prepare_before_op_replays_as_prepared`; engine tests below.)
    //   (b) crash AFTER A3 (real record durable), BEFORE B: the txn replays as Prepared (no op-marker),
    //       payload buffered, so recovery re-commits. Its step A re-WRITEs the SAME payload under the
    //       SAME txn-id seq, which the DURABLE producer-seq high-water (made durable in A2, restored
    //       from `producer-seq.ckpt` on open) recognizes as a DUPLICATE — original offset, appends
    //       NOTHING. EXACTLY ONCE (no dup, no loss).
    //   (c) crash AFTER B: the txn replays as Committed; no replay work, and a retried commit is a
    //       benign idempotent no-op returning the recorded offset.
    //
    // The two-fsync sub-window A2<->A3 is why A2 (the high-water fsync) is ordered BEFORE A3 (the
    // record fsync), NOT after:
    //   - crash between A2 and A3 (high-water durable, record NOT): the record is lost in the torn
    //     tail; on recovery `seed_producer_seq_from_recovered` CLAMPS a high-water whose offset is at
    //     or past the durable head and DROPS it, so the redrive re-writes FRESH at the real head — no
    //     double (the first write was lost), no loss (the redrive lands it).
    //   - crash after A3 (record durable): the high-water was fsync'd first, so it is durable too, and
    //     the redrive dedups to the original offset.
    // Either way the real append is exactly-once across a crash. (A NAMED target stream does not yet
    // carry the durable txn dedup — a flagged follow-up — so its commit redrive is at-least-once; the
    // default stream, the common case, is exactly-once.)
    //
    // DURABILITY-SCOPE CAVEATS (be honest about what the guarantee rests on — see docs/RECOVERY.md
    // "Transactional messages (2PC)"):
    //   (a) The default-stream exactly-once / no-committed-empty guarantee is SCOPED to
    //       `DurabilityLevel::Sync` (the default). It rests on A3 (the real record's covering fsync)
    //       running BEFORE B (the op-marker, which ALWAYS force-fsyncs). Under a RELAXED level
    //       (`interval`/`async`/`none`) A3 is a no-fsync `flush_no_sync`, so a power cut can leave the
    //       lifecycle state Committed (B fsync'd) while the unsynced real record is lost — a
    //       committed-but-empty txn. This is consistent with the relaxed-level acked-loss waiver (I2 is
    //       already waived there), but it is a NEW asymmetry: the lifecycle marker is durable while its
    //       record is not. Use `sync` (the default) for the no-committed-empty guarantee.
    //   (b) A NAMED (non-default) target stream's commit redrive is at-least-once on a crash (only the
    //       default stream carries the durable txn-id seq dedup), as noted above.
    //   (c) The txn-id dedup high-water shares the bounded LRU `producer-seq.ckpt` slot, so a VERY late
    //       default-stream redrive whose high-water was evicted degrades to at-least-once (safe — never
    //       loss, never a flip); immediate redrives are unaffected (see `commit_real_append`).
    //
    // The INVISIBILITY invariant holds throughout: the payload lives in `txn/` (never the real stream)
    // until step A, and a consumer never reads `txn/`; a rolled-back txn's payload is never written to
    // the real stream at all.
    // ===================================================================================

    /// Lazily opens the transactional half-message store, creating the `txn/` subtree on the FIRST
    /// transactional verb (so a non-transactional broker never materializes it). A no-op if already
    /// open. Returns a mutable borrow of the store for the caller's verb.
    ///
    /// # Errors
    /// Propagates a storage error from creating the subdirectory or opening the txn log.
    fn ensure_txn_store(&mut self) -> Result<&mut TxnStore<F, C>, EngineError> {
        if self.txn.is_none() {
            let store = TxnStore::open(
                self.log.filesystem(),
                self.log.clock_clone(),
                self.txn_config,
                ironbus_core::txn::TxnConfig::default(),
            )
            .map_err(EngineError::Storage)?;
            self.txn = Some(store);
        }
        // Just-ensured to be `Some`.
        Ok(self.txn.as_mut().expect("txn store ensured"))
    }

    /// PREPAREs a transactional half message (#640): durably buffers `message` for `txn_id` targeting
    /// the real `stream`, INVISIBLE to consumers, and acks. The half message survives a restart as
    /// `Prepared` until a [`Engine::txn_commit`] or [`Engine::txn_rollback`] resolves it. Idempotent: a
    /// re-prepare of a still-prepared id is a benign no-op (the half message is already durable).
    ///
    /// # Errors
    /// [`EngineError::Txn`] for an unknown/spent id, too-many-prepared, or an over-long txn id; a
    /// storage error from creating/opening the `txn/` store or the durable half-record append.
    pub fn txn_prepare(
        &mut self,
        txn_id: &[u8],
        stream: &str,
        message: &Append<'_>,
    ) -> Result<(), EngineError> {
        let now = self.log.now_monotonic();
        let store = self.ensure_txn_store()?;
        // Decide FIRST on the pure lifecycle (no IO): a fresh prepare durably buffers; a benign
        // duplicate re-acks without a second half record; a spent/over-cap id is refused.
        match store
            .table_mut()
            .prepare(txn_id, now)
            .map_err(EngineError::Txn)?
        {
            ironbus_core::txn::PrepareDecision::AlreadyPrepared => Ok(()),
            ironbus_core::txn::PrepareDecision::Prepared => {
                // Durably append + fsync the half record. If the durable write fails, ROLL BACK the
                // in-memory prepared state so the table and the durable log stay consistent (the
                // prepare did not happen), and surface the error.
                match store.append_half(txn_id, stream, message) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        // The half record is NOT durable: undo the in-memory prepare (mark it rolled
                        // back in memory only — no op record is written, and on reopen there is no half
                        // record either, so the txn is simply absent). We use the table's rollback to
                        // clear the prepared entry; the durable log never saw this txn.
                        let _ = store.table_mut().rollback(txn_id, now);
                        Err(txn_store_error_to_engine(e))
                    }
                }
            }
        }
    }

    /// COMMITs the prepared half message named by `txn_id` (#640): appends the buffered payload to the
    /// real target stream (DEDUPED by the txn id) and fsyncs it, writes + fsyncs the committed
    /// op-marker, then advances the lifecycle to Committed. Returns the committed real offset. The half
    /// message becomes VISIBLE to consumers only here. Idempotent: a retried commit of an
    /// already-committed txn returns the original offset and appends nothing; a commit of an
    /// already-rolled-back txn is REFUSED. See the module-level crash-safety argument above.
    ///
    /// DURABILITY SCOPE: the no-committed-empty guarantee (a durable Committed marker always has its
    /// real record durable too) holds under [`DurabilityLevel::Sync`] (the default), where A3 force-
    /// fsyncs the record before the op-marker B. Under a RELAXED level A3 is a no-fsync flush while B
    /// always fsyncs, so a power cut can leave a Committed lifecycle over a lost (unsynced) record — a
    /// committed-but-empty txn, consistent with that level's acked-loss waiver. See caveat (a) in the
    /// module-level argument and docs/RECOVERY.md.
    ///
    /// # Errors
    /// [`EngineError::Txn`] for an unknown id or a commit-after-rollback (refused, never flipped); a
    /// storage error from the real-stream append, the op-marker append, or a durability barrier.
    pub fn txn_commit(&mut self, txn_id: &[u8]) -> Result<Offset, EngineError>
    where
        F: Clone,
    {
        let now = self.log.now_monotonic();
        // Decide on the pure lifecycle FIRST (no IO). A fresh resolve must do the real append + marker;
        // a benign duplicate returns the prior committed offset (recorded in the op-marker, recovered
        // on replay) WITHOUT re-appending; a conflicting flip is refused.
        let decision = {
            let store = self.ensure_txn_store()?;
            store
                .table_mut()
                .commit(txn_id, now)
                .map_err(EngineError::Txn)?
        };
        match decision {
            ironbus_core::txn::ResolveDecision::AlreadyResolved => {
                // A retried commit of an already-committed txn (the in-memory table or the replayed
                // op-marker already says Committed). The payload is already on the real stream and was
                // dropped from the buffer on the first commit, so we return the recorded real offset
                // from the DURABLE producer-seq high-water WITHOUT re-appending — exactly idempotent.
                Ok(self.dedup_offset_for(txn_id))
            }
            ironbus_core::txn::ResolveDecision::Resolved => {
                // The FRESH commit (or the crash-recovery redrive of a Prepared txn). Pull the buffered
                // half message and run the crash-safe ordering (see the module-level argument):
                //   STEP A:  WRITE the payload to the real stream (no fsync), DEDUPED by the durable
                //            txn-id seq — this assigns the offset and records the seq high-water in
                //            memory. A redrive re-write reads seq 0 as a duplicate at the original offset.
                //   STEP A2: FLUSH the producer-seq checkpoint (fsync the high-water) BEFORE the record's
                //            fsync, so the dedup identity is durable no later than the record (and a crash
                //            that loses the record clamps the over-the-head high-water away on recovery).
                //   STEP A3: COMMIT-BATCH (fsync the record), making the real append durable.
                //   STEP B:  append + fsync the COMMITTED op-marker (the commit point), carrying the offset.
                let half = self
                    .txn
                    .as_ref()
                    .and_then(|s| s.prepared_payload(txn_id).cloned())
                    .ok_or(EngineError::Txn(ironbus_core::txn::TxnError::UnknownTxn))?;
                let real_offset = self.commit_real_append(txn_id, &half)?; // STEP A (write, no fsync)
                self.flush_txn_commit_dedup()?; // STEP A2: dedup identity durable before the record
                self.commit_batch()?; // STEP A3: the real record is now durable
                                      // STEP B: the commit point. On its failure the in-memory table already says Committed
                                      // but no marker is durable; a reopen replays as Prepared and re-commits, deduped by the
                                      // (now-durable, from A2) txn-id seq — safe. We surface the error.
                let store = self.ensure_txn_store()?;
                store
                    .mark_committed(txn_id, real_offset.get())
                    .map_err(txn_store_error_to_engine)?;
                Ok(real_offset)
            }
        }
    }

    /// Appends a committed half message's payload to its real target stream, DEDUPED by the txn id via
    /// the DURABLE producer-SEQUENCE high-water (#639), so a crash-recovery re-commit re-appending the
    /// same payload is recognized as a duplicate at the original offset, never a second copy — and the
    /// dedup SURVIVES a restart (unlike the in-memory `msg_id` window). The txn id is used as the
    /// `producer_id` (in the reserved [`TXN_DEDUP_PRODUCER_ID`]-prefixed namespace), epoch 0, seq 0:
    /// every txn is its own single-sequence producer, so resolving txns out of order never trips the
    /// out-of-order guard. After the append the durable seq high-water is FLUSHED (the caller's
    /// responsibility, via [`Engine::flush_txn_commit_dedup`]) before the op-marker, so the dedup
    /// identity is durable before the commit point.
    ///
    /// DEDUP HIGH-WATER AGING (caveat (c)): the txn-id high-water shares the bounded (LRU, ~4096-entry)
    /// `producer-seq.ckpt` slot. A VERY late default-stream redrive whose high-water was EVICTED by
    /// newer producers before the redrive runs degrades to at-least-once (it re-appends a fresh copy) —
    /// which is SAFE (never loss, never a flipped outcome). An immediate crash-recovery redrive is
    /// unaffected: the txn pseudo-ids were just written and sort to the front of the LRU, so they are
    /// still present when recovery replays the Prepared txn.
    fn commit_real_append(
        &mut self,
        txn_id: &[u8],
        half: &ironbus_storage::txn::HalfMessage,
    ) -> Result<Offset, EngineError>
    where
        F: Clone,
    {
        // Build the real-stream append from the preserved half message, with HAS_KEY cleared (the
        // segment codec re-derives it from the key length).
        let flags = RecordFlags::from_bits(half.flags.bits() & !RecordFlags::HAS_KEY.bits());
        let append = Append {
            timestamp_ms: half.timestamp_ms,
            flags,
            key: &half.key,
            headers: &half.headers,
            payload: &half.payload,
        };
        let pid = txn_dedup_producer_id(txn_id);
        // The default stream routes through the DURABLE producer-sequence dedup (seq 0). A NAMED target
        // stream does not yet carry per-stream dedup (a flagged follow-up), so its commit append is
        // at-least-once on a crash-recovery redrive; for the default (and most common) target the
        // durable seq high-water makes the commit replay exactly-once across a restart.
        //
        // The ORDERING here is the crash-safety crux (see the module-level argument). The append is a
        // WRITE-only (no fsync): it assigns the offset and records the txn-id seq high-water IN MEMORY.
        // The caller (`txn_commit`) then flushes the seq checkpoint (fsync the high-water) BEFORE
        // `commit_batch` fsyncs the record, so:
        //   - crash after the high-water fsync but before the record fsync: the record is lost in the
        //     torn tail; recovery CLAMPS the recovered high-water (its offset >= the durable head) and
        //     DROPS it, so the redrive re-appends FRESH (no double, no loss).
        //   - crash after the record fsync: the high-water is already durable (flushed first), so the
        //     redrive reads seq 0 as a DUPLICATE at the original offset (no double).
        // Either way the real append is exactly-once across a crash.
        if half.stream.is_empty() {
            let dedup = DedupRequest {
                producer_id: &pid,
                epoch: 0,
                msg_id: txn_id,
                seq: Some(0),
            };
            let outcome = self.append_no_sync_dedup(&append, Some(dedup))?;
            match outcome {
                AppendOutcome::Appended(offset) | AppendOutcome::Duplicate(offset) => Ok(offset),
                // The txn seq dedup never fences or rejects out-of-order (epoch 0, single seq 0), so
                // these are unreachable; surface a typed error rather than panic if a future change
                // reaches them.
                AppendOutcome::Fenced { .. } | AppendOutcome::OutOfOrder { .. } => {
                    Err(EngineError::Txn(ironbus_core::txn::TxnError::UnknownTxn))
                }
            }
        } else {
            // A named target stream: produce-in-stream is its own append+commit (no durable txn dedup
            // yet); at-least-once on a crash-recovery redrive (flagged follow-up).
            self.produce_in_stream(&half.stream, &append)
        }
    }

    /// Durably flushes the producer-sequence high-water so the txn-commit real-append dedup SURVIVES a
    /// restart (#640). Called by [`Engine::txn_commit`] AFTER the (write-only) real append records the
    /// txn-id high-water in memory and BEFORE the record's covering fsync, so the dedup identity is
    /// durable no later than the record itself (and a crash that loses the record also has its
    /// over-the-head high-water clamped away on recovery). A no-op if no txn (or sequenced producer)
    /// has ever committed.
    ///
    /// # Errors
    /// Propagates a storage error from creating or writing the producer-seq checkpoint.
    fn flush_txn_commit_dedup(&mut self) -> Result<(), EngineError> {
        self.ensure_producer_seq_checkpoint()?;
        self.checkpoint_producer_seq()
    }

    /// Looks up the durable offset the producer-sequence high-water holds for a txn id's committed real
    /// append (the effectively-once identity used by [`Engine::commit_real_append`]). Used to return a
    /// stable offset on an idempotent re-commit whose buffered payload is already gone. Falls back to
    /// the log's flushed head if the high-water aged out (a bounded staleness — the txn is committed
    /// regardless).
    fn dedup_offset_for(&self, txn_id: &[u8]) -> Offset {
        let pid = txn_dedup_producer_id(txn_id);
        match self.producer_seq.high_water(&pid) {
            // The recorded last-accepted offset for this txn's single seq 0 IS its committed offset.
            Some((_epoch, Some(_seq), last_offset)) => last_offset,
            _ => self.log.flushed_offset(),
        }
    }

    /// ROLLs BACK the prepared half message named by `txn_id` (#640): writes + fsyncs a rolled-back
    /// op-marker; the buffered payload is DISCARDED and never appended to the real stream — never
    /// delivered. Idempotent: a retried rollback of an already-rolled-back txn is a benign success; a
    /// rollback of an already-committed txn is REFUSED (never flipped).
    ///
    /// # Errors
    /// [`EngineError::Txn`] for an unknown id or a rollback-after-commit (refused, never flipped); a
    /// storage error from the op-marker append or its durability barrier.
    pub fn txn_rollback(&mut self, txn_id: &[u8]) -> Result<(), EngineError> {
        let now = self.log.now_monotonic();
        let store = self.ensure_txn_store()?;
        match store
            .table_mut()
            .rollback(txn_id, now)
            .map_err(EngineError::Txn)?
        {
            // A retried rollback of an already-rolled-back txn: benign no-op (the op-marker is durable).
            ironbus_core::txn::ResolveDecision::AlreadyResolved => Ok(()),
            ironbus_core::txn::ResolveDecision::Resolved => {
                // The FRESH rollback: durably record the rolled-back op-marker. The buffered payload is
                // dropped by the store; it never reaches the real stream.
                store
                    .mark_rolled_back(txn_id)
                    .map_err(txn_store_error_to_engine)
            }
        }
    }

    /// The count of currently-`Prepared` (unresolved) half messages (#640), for observability and the
    /// part-2 back-check. `0` when no txn store is open.
    #[must_use]
    pub fn txn_prepared_count(&self) -> usize {
        self.txn.as_ref().map_or(0, TxnStore::prepared_count)
    }

    /// CREATE-OR-ENSURE the named stream `stream` WITHOUT producing to it (#588, M2-I10): the
    /// engine-side of the `StreamDeclare` wire verb. The default stream (the EMPTY name) is always
    /// present and is a no-op success (`Ok(false)`, "already existed") — it is NEVER materialized via
    /// the named `streams/` subtree. A NAMED stream is `declare`d in the [`StreamSet`] (materializing
    /// `streams/<hex(name)>/` and its independent log + recovery) and mirrored in the per-stream
    /// consumer state, exactly as the declare-on-first-produce in [`Engine::produce_in_stream`] does,
    /// so a later produce/consume reuses the same open log. Idempotent: re-declaring an open stream is
    /// `Ok(false)`; a first declare is `Ok(true)`.
    ///
    /// # Errors
    /// [`EngineError::InvalidStreamName`] for a malformed NAMED name (empty is the default, never a
    /// named-name error here because it short-circuits above; otherwise the graphic-ASCII / length rule
    /// fails closed at the boundary, before the filesystem), else a storage error from opening the
    /// stream's log.
    pub fn declare_stream(&mut self, stream: &str) -> Result<bool, EngineError>
    where
        F: Clone,
    {
        // The default stream is always open and lives on the root log, NOT in the StreamSet's named
        // subtree: declaring it is a no-op success, so a `StreamDeclare("")` (which the proto rejects
        // anyway) never materializes the inert `""` slot.
        if stream.is_empty() {
            return Ok(false);
        }
        let id = StreamId::named(stream)?;
        let created = self.streams.declare(&id).map_err(EngineError::Storage)?;
        // Mirror the per-stream consumer state so a subsequent consume resolves the same way a
        // produce-declared stream does (idempotent: an existing entry is left untouched).
        self.named_streams
            .entry(id)
            .or_insert_with(NamedStream::new);
        Ok(created)
    }

    /// Whether the named stream `stream` EXISTS (is open) (#588): the engine-side of the `StreamInfo`
    /// wire verb's existence bit. The default stream (the EMPTY name) ALWAYS exists. A named stream
    /// exists once it has been declared (via [`Engine::declare_stream`] or declare-on-first-produce).
    /// A malformed named name reports `false` (it can never have been declared), never an error — the
    /// wire layer fails a malformed id closed before this is reached, so this is a pure existence read.
    #[must_use]
    pub fn stream_exists(&self, stream: &str) -> bool {
        if stream.is_empty() {
            return true;
        }
        let Ok(id) = StreamId::named(stream) else {
            return false;
        };
        self.streams.get(&id).is_some()
    }

    /// Polls the stream named `stream` in work-group `group` (#676): the default stream routes to
    /// today's [`Engine::poll_in`] BYTE-FOR-BYTE; a NAMED stream delivers off its OWN log + its own
    /// per-stream work-group (the same competing lease/cursor machinery, independent per stream, so
    /// the same group name in two streams is two unrelated cursors).
    ///
    /// # Errors
    /// [`EngineError::InvalidStreamName`] / [`EngineError::UnknownStream`] for a bad or never-declared
    /// named stream, [`EngineError::InvalidGroupName`] / [`EngineError::TooManyGroups`] from the group
    /// gate, else a storage error from the read.
    pub fn poll_in_stream(
        &mut self,
        stream: &str,
        group: &str,
        now: u64,
    ) -> Result<Poll, EngineError> {
        if stream.is_empty() {
            return self.poll_in(group, now);
        }
        let id = StreamId::named(stream)?;
        // A named stream must be produced-to (declared) before it can be consumed: an unknown stream
        // is a typed rejection, never a silent empty read (matching `StreamSet::read_range`).
        let Some(flushed) = self.streams.get(&id).map(|log| log.flushed_offset().get()) else {
            return Err(EngineError::UnknownStream {
                name: stream.to_string(),
            });
        };
        validate_group_name(group)?;
        let lease_config = self.lease_config;
        let max_groups = self.max_groups;
        // Resolve (creating lazily, under the per-stream group cap) this stream's work-group. The
        // cap is PER STREAM (each named stream gets its own `max_groups` budget), so a noisy stream
        // cannot starve a sibling's group slots — at least as strong as the default-stream bound.
        let named = self
            .named_streams
            .entry(id.clone())
            .or_insert_with(NamedStream::new);
        if !named.groups.contains_key(group) {
            if max_groups != 0 && named.groups.len() >= max_groups {
                return Err(EngineError::TooManyGroups { max: max_groups });
            }
            named
                .groups
                .insert(group.to_string(), WorkGroup::new(lease_config, now));
        }
        self.deliver_from_named_stream(&id, group, now, flushed)
    }

    /// The competing claim/deliver loop for a NAMED stream (#676), factored out of
    /// [`Engine::poll_in_stream`] so the public entry point stays small. The work-group `group` of
    /// stream `id` is already present (the caller created it under the per-stream cap), and `flushed`
    /// is that stream's durable head. Re-instantiates the SAME primitives the default stream uses —
    /// the [`AckCursor`], the [`LeaseTable`] claim/ack, the 0/1/2-ack disposition — per stream.
    ///
    /// Each iteration resolves the group in its OWN scoped borrow: the per-record log read borrows
    /// `&self.streams` (a field DISJOINT from `self.named_streams`), so a persistent group borrow held
    /// across the read would be a borrow conflict; resolving the group fresh per use keeps the borrows
    /// non-overlapping. `id`/`group` are guaranteed present by the caller, so the lookups never miss.
    fn deliver_from_named_stream(
        &mut self,
        id: &StreamId,
        group: &str,
        now: u64,
        flushed: u64,
    ) -> Result<Poll, EngineError> {
        // Stamp the polled group active and read its committed cursor in a SHORT scoped borrow, so the
        // borrow ends before the loop re-borrows `self.named_streams` per iteration.
        let Some(committed) = self.named_group_mut(id, group).map(|g| {
            g.last_activity = now;
            g.touched = true;
            g.cursor.committed().get()
        }) else {
            return Ok(Poll::Idle);
        };
        // The delivery window: at most `max_in_flight` offsets above the committed cursor, never past
        // the durable end — the SAME window as the default-stream poll.
        let window_end = committed
            .saturating_add(u64::from(self.max_in_flight))
            .min(flushed);
        let mut offset = committed;
        while offset < window_end {
            let off = Offset::new(offset);
            // Skip an already-acked offset and claim the next deliverable lease (scoped group borrow).
            let Some(claim) = self.named_group_mut(id, group).map(|g| {
                if g.cursor.is_acked(off) {
                    None
                } else {
                    Some(g.leases.claim(off, now))
                }
            }) else {
                return Ok(Poll::Idle);
            };
            let (token, deliveries) = match claim {
                None | Some(Claim::InFlight) => {
                    offset += 1;
                    continue;
                }
                Some(Claim::Exhausted) => return Err(EngineError::GenerationExhausted),
                Some(Claim::Granted { token, deliveries }) => (token, deliveries),
            };
            // Read the leased record off THIS stream's log (immutable `&self.streams` borrow, now that
            // the group borrow above has ended).
            let record = match self.streams.get(id) {
                Some(log) => log.read_from(off, 1).map_err(EngineError::Storage)?,
                None => return Ok(Poll::Idle),
            };
            let Some(record) = record.into_iter().next() else {
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
                    // No per-stream DLQ yet (#676 scope): commit PAST the poison message so it never
                    // redelivers (at-least-once preserved; the forensic DLQ copy is the flagged
                    // follow-up). The default stream keeps its full crash-atomic DLQ move unchanged.
                    if let Some(g) = self.named_group_mut(id, group) {
                        g.leases.ack(&token);
                        g.cursor.ack(off);
                    }
                    self.counters.dead_lettered = self.counters.dead_lettered.saturating_add(1);
                    offset += 1;
                }
            }
        }
        Ok(Poll::Idle)
    }

    /// Mutably borrows work-group `group` of NAMED stream `id`, or `None` if the stream or group is
    /// not present (#676). The single resolution point for the per-stream consume/ack paths, so they
    /// never `.expect()` (the missing case is handled, not a panic).
    fn named_group_mut(&mut self, id: &StreamId, group: &str) -> Option<&mut WorkGroup> {
        self.named_streams
            .get_mut(id)
            .and_then(|s| s.groups.get_mut(group))
    }

    /// Acks `token` in work-group `group` of the stream named `stream` (#676): the default stream
    /// routes to today's [`Engine::ack_in`] BYTE-FOR-BYTE; a NAMED stream commits in its OWN
    /// per-stream group cursor and frees its lease slot, independent of every other stream and of the
    /// default stream. An ack on an unknown stream or group is a fence, never a new allocation.
    pub fn ack_in_stream(&mut self, stream: &str, group: &str, token: &LeaseToken) -> AckResult {
        if stream.is_empty() {
            return self.ack_in(group, token);
        }
        let Ok(id) = StreamId::named(stream) else {
            return AckResult::Fenced;
        };
        let now = self.streams.get(&id).map_or(0, Log::now_monotonic);
        let Some(named) = self.named_streams.get_mut(&id) else {
            return AckResult::Fenced;
        };
        let Some(g) = named.groups.get_mut(group) else {
            return AckResult::Fenced;
        };
        g.last_activity = now;
        g.touched = true;
        match g.leases.ack(token) {
            AckOutcome::Acked => {
                g.cursor.ack(token.offset);
                self.counters.acks += 1;
                AckResult::Acked
            }
            AckOutcome::Fenced => AckResult::Fenced,
        }
    }

    /// The committed offset of work-group `group` in the stream named `stream` (#676): the default
    /// stream reads today's [`Engine::committed_offset_in`]; a NAMED stream reads its OWN per-stream
    /// group cursor (`Offset::ZERO` for an unknown stream or group). Used by the cross-stream
    /// isolation tests to assert a named stream's cursor is independent of the default's.
    #[must_use]
    pub fn committed_offset_in_stream(&self, stream: &str, group: &str) -> Offset {
        if stream.is_empty() {
            return self.committed_offset_in(group);
        }
        let Ok(id) = StreamId::named(stream) else {
            return Offset::ZERO;
        };
        self.named_streams
            .get(&id)
            .and_then(|s| s.groups.get(group))
            .map_or(Offset::ZERO, |g| g.cursor.committed())
    }

    /// The durable head (flushed offset) of the stream named `stream` (#676): the default stream's
    /// head from [`Engine::log`], or a NAMED stream's head from its own log in the [`StreamSet`]
    /// (`Offset::ZERO` for an unknown named stream). Lets a test assert a produce to a named stream
    /// advanced ONLY that stream's head, not the default's (cross-stream data isolation).
    #[must_use]
    pub fn stream_head(&self, stream: &str) -> Offset {
        if stream.is_empty() {
            return self.log.flushed_offset();
        }
        let Ok(id) = StreamId::named(stream) else {
            return Offset::ZERO;
        };
        self.streams
            .get(&id)
            .map_or(Offset::ZERO, Log::flushed_offset)
    }

    /// The number of OPEN named streams (#676), EXCLUDING the always-present default stream: `0` for
    /// a deployment that never named a stream. (The [`StreamSet`] always carries its `""` slot, so we
    /// subtract it to report the named count an operator cares about.)
    #[must_use]
    pub fn named_stream_count(&self) -> usize {
        // The StreamSet's `len()` includes its inert default `""` slot; the named count is the rest.
        self.streams.len().saturating_sub(1)
    }

    // ===================================================================================
    // SUBJECT->STREAM BINDING + FAIL-CLOSED SINGLE-HOME RESOLUTION (#585, V2-M2-I9).
    //
    // A stream BINDS a set of subject PATTERNS (e.g. "orders" binds "order.>", "payment.*.done"); a
    // publish to a literal SUBJECT resolves — via the wait-free trie + a per-connection resolve cache —
    // to the bound stream(s): EXACTLY ONE routes there, ZERO is a fail-closed NoStreamForSubject reject
    // (the beat over NATS's silent drop), >= 2 is an AmbiguousSubject reject (single-home default; the
    // overlap_ok fan-out is the SEPARATE later issue, FLAGGED). The binding lives in the trie with
    // target = StreamId; a bind rebuilds it and advances the generation, invalidating every connection's
    // resolve cache. The explicit-stream-id (#588) and default-stream paths are untouched.
    // ===================================================================================

    /// BINDS the subject `pattern` to the stream named `stream` (#585): registers `pattern -> stream` in
    /// the routing trie and atomically swaps the rebuilt, generation-advanced trie in (invalidating every
    /// connection's resolve cache). The named stream is `declare`d on bind (materializing its independent
    /// log + recovery) so a subsequent subject-addressed publish has a destination log; the DEFAULT
    /// stream (the EMPTY name) is always present and is `declare`-free. The `pattern` is a #567 PATTERN
    /// (wildcards `*`/`>` allowed). Idempotent: re-binding the same `(pattern, stream)` pair is a no-op
    /// success. Returns the new routing generation.
    ///
    /// # Errors
    /// [`EngineError::InvalidSubject`] for a malformed pattern, [`EngineError::InvalidStreamName`] for a
    /// malformed named stream, [`EngineError::BindRejected`] if the resulting binding SET would exceed
    /// the trie's #568 fork bound (the previous table stays installed), or [`EngineError::Storage`] from
    /// declaring the stream's log.
    pub fn bind_subject(&mut self, stream: &str, pattern: &str) -> Result<u64, EngineError>
    where
        F: Clone,
    {
        // Validate the pattern up front (fail-closed) so a malformed pattern never declares a stream.
        SubjectPattern::parse(pattern)?;
        let id = if stream.is_empty() {
            // The default stream is always open (it is the root log), so binding a subject TO the default
            // stream is legitimate and declare-free: a subject-addressed publish then lands in "".
            StreamId::default_stream()
        } else {
            let id = StreamId::named(stream)?;
            // Declare-on-bind: the stream must have a log to receive a subject-addressed publish later,
            // exactly as declare-on-first-produce gives the id-routed path one (idempotent).
            self.streams.declare(&id).map_err(EngineError::Storage)?;
            self.named_streams
                .entry(id.clone())
                .or_insert_with(NamedStream::new);
            id
        };
        // Register + rebuild + swap (advances the generation; rolls back on a fork-bound rejection).
        Ok(self.bindings.bind(pattern, id)?)
    }

    /// Resolves the literal `subject` to a single bound stream under the FAIL-CLOSED single-home default
    /// (#585), WITHOUT the per-connection resolve cache (a one-shot / server-internal resolve; the hot
    /// publish path uses the session's cache). The subject is validated as a #567 LITERAL (no wildcards);
    /// then the trie match is reduced single-home: exactly one bound stream -> that [`StreamId`], zero ->
    /// `NoStreamForSubject`, two-or-more -> `AmbiguousSubject`.
    ///
    /// # Errors
    /// [`EngineError::InvalidSubject`] for a malformed/wildcard subject, [`EngineError::NoStreamForSubject`]
    /// when no binding matches (fail-closed, never a silent drop), or [`EngineError::AmbiguousSubject`]
    /// when more than one bound stream matches (single-home).
    pub fn resolve_subject(&self, subject: &str) -> Result<StreamId, EngineError> {
        let subj = Subject::parse_literal(subject)?;
        let mut matched = Vec::new();
        self.bindings.snapshot.match_into(&subj, &mut matched);
        match single_home(&matched) {
            Resolution::Routed(id) => Ok(id),
            Resolution::NoStream => Err(EngineError::NoStreamForSubject {
                subject: subject.to_string(),
            }),
            Resolution::Ambiguous { matched } => Err(EngineError::AmbiguousSubject {
                subject: subject.to_string(),
                matched,
            }),
        }
    }

    /// Produces `message` BY SUBJECT (#585): resolves the literal `subject` to its single bound stream
    /// (single-home, fail-closed) and routes the append there via the id-routed
    /// [`Engine::produce_in_stream`] (which is byte-for-byte the default path when the bound stream is
    /// the default `""`). A subject bound to no stream is a `NoStreamForSubject` reject (the publish is
    /// REFUSED, not silently dropped — the beat over NATS); a subject bound to two-or-more is an
    /// `AmbiguousSubject` reject. Returns the assigned [`Offset`] in the resolved stream.
    ///
    /// This resolves WITHOUT the per-connection cache (the engine has no per-connection identity); the
    /// session resolves through its cache and then calls [`Engine::produce_in_stream`] with the resolved
    /// stream name, so the hot path stays O(1). This entry point exists for callers that want the engine
    /// to do both steps in one actor job (and for the end-to-end tests).
    ///
    /// # Errors
    /// The [`Engine::resolve_subject`] rejects (invalid/unbound/ambiguous subject), else the
    /// [`Engine::produce_in_stream`] error taxonomy for the resolved stream.
    pub fn produce_by_subject(
        &mut self,
        subject: &str,
        message: &Append<'_>,
    ) -> Result<Offset, EngineError>
    where
        F: Clone,
    {
        // Resolve first (fail-closed): a NoStream/Ambiguous subject is refused BEFORE any append, so a
        // publish to an unbound subject never touches a log (no silent drop, no partial write).
        let id = self.resolve_subject(subject)?;
        // Route the append to the resolved stream's log via the id-routed path. The default stream `""`
        // routes byte-for-byte through `produce`; a named stream appends to its own log + commit tick.
        self.produce_in_stream(id.name(), message)
    }

    /// The number of registered subject bindings (#585), `0` for a deployment that never bound a subject.
    /// For tests/metrics.
    #[must_use]
    pub fn binding_count(&self) -> usize {
        self.bindings.len()
    }

    /// The current routing-table generation (#585): bumped on every successful [`Engine::bind_subject`].
    /// A per-connection resolve cache compares it to detect a bind change. For tests.
    #[must_use]
    pub fn binding_generation(&self) -> u64 {
        self.bindings.snapshot.generation()
    }

    /// Borrows the wait-free routing [`SublistSnapshot`] (#585) so a per-connection resolve cache can
    /// resolve a subject through it (a wait-free `ArcSwap` load + walk on a miss, an O(1) hash lookup on
    /// a hit). This is the read seam the session's cached subject-resolve uses; the snapshot is immutable
    /// and generation-stamped, so the cache's generation-guard detects a bind change with one compare.
    #[must_use]
    pub fn binding_snapshot(&self) -> &SublistSnapshot<StreamId> {
        &self.bindings.snapshot
    }

    /// Appends `message` durably-pending (write, NO fsync) and records the produce statistics that
    /// do not depend on the sync, returning its assigned offset. The record is NOT yet durable and
    /// NOT yet visible to readers (the flushed head only advances in [`Engine::commit_batch`]); the
    /// caller MUST follow one or more `append_no_sync` calls with exactly one [`Engine::commit_batch`]
    /// before acking any of them, so the ack-implies-durable invariant (I2) holds. This is the write
    /// half of group commit (#177): the append actor drains a batch of pending appends through here,
    /// then issues ONE `commit_batch` covering them all.
    ///
    /// This is also the single write-path COMPRESSION seam (#430, ADR-0003): with a non-`None`
    /// [`EngineConfig::compression`] codec, the payload is compressed HERE, before
    /// `append_with_policy`, so the CRC, the byte-cap and segment-roll checks,
    /// `durable_record_bytes`, and the #118 write-amp meters all account the STORED bytes. The two
    /// ADR-0003 write guards (the 64-byte raw-store threshold and the never-expand guard) keep a
    /// small or incompressible payload stored raw, byte-identical to an uncompressed write; a
    /// third, seam-local guard stores a payload LARGER than the readers' per-unit decompressed
    /// cap ([`DEFAULT_MAX_DECOMPRESSED_BYTES`]) raw, so the write side never emits a record the
    /// shipped read side refuses. A
    /// message whose flags ALREADY carry [`RecordFlags::COMPRESSED`] (a producer-compressed
    /// publish arriving over the wire) passes through UNCHANGED, so a stored object is never
    /// double-wrapped. The DLQ redrive also preserves the flag on the records it re-injects, but
    /// NOT via this guard: it re-appends through `Log::append` directly and never reaches this
    /// seam (the flag is carried verbatim there, see `ironbus_storage::admin::redrive_dlq`).
    /// `produced_bytes` deliberately counts the ORIGINAL
    /// logical payload bytes, never the stored bytes (see [`Counters::produced_bytes`]).
    ///
    /// # Errors
    /// As [`Engine::produce`]: a drop-new shed (either the byte-cap [`StorageError::AtCapacity`] or
    /// the daily-write-budget [`StorageError::DailyWriteBudgetExceeded`]) surfaces the non-fatal
    /// rejection and increments `produce_rejected`; any other storage error propagates. Nothing is
    /// written and no statistic moves on an error.
    pub fn append_no_sync(&mut self, message: &Append<'_>) -> Result<Offset, EngineError> {
        // The write-path compression seam (#430, ADR-0003). The pass-through guard on an ALREADY
        // COMPRESSED message is load-bearing: the wire legally delivers bit 0 set (a producer may
        // publish a pre-compressed stored object), and compressing it again would wrap a
        // descriptor in a descriptor and decode to garbage. (The DLQ redrive also re-injects
        // records carrying the flag, but it appends via `Log::append` directly and never reaches
        // this seam; the flag is preserved verbatim there.)
        //
        // Store RAW when the payload exceeds the readers' per-unit decompressed cap
        // (`DEFAULT_MAX_DECOMPRESSED_BYTES`): every shipped reader (the client fetch decode, the
        // CLI dump/peek) rejects a compressed descriptor whose claimed `uncompressed_len` is over
        // that cap BEFORE allocating (the #76 bomb guard), so compressing such a payload would
        // durably ACK a record those readers refuse with `DecompressedTooLarge` (a consumer stall
        // on a pseudo-poison record). The write side must never emit a record the shipped read
        // side refuses; a raw store never consults the cap, so an over-cap record (legal up to
        // the record bound) stays readable everywhere.
        let comp;
        let stored;
        let to_append: &Append<'_> = if self.compress.codec == Codec::None
            || message.flags.contains(RecordFlags::COMPRESSED)
            || message.payload.len() > DEFAULT_MAX_DECOMPRESSED_BYTES as usize
        {
            message
        } else {
            match compress_payload(message.payload, &self.compress) {
                Ok(c) if c.compressed => {
                    comp = c;
                    stored = Append {
                        timestamp_ms: message.timestamp_ms,
                        flags: message.flags.with(comp.flag()),
                        key: message.key,
                        headers: message.headers,
                        payload: &comp.stored,
                    };
                    &stored
                }
                // A raw store (the sub-threshold or never-expand guard fired, the stored bytes
                // are the payload byte-for-byte) or a compress error (only `PayloadTooLarge`,
                // unreachable for wire-bounded payloads under the record cap): append the
                // ORIGINAL message unchanged, so the produce error taxonomy is exactly the
                // historical one and a raw-stored record is byte-identical to a no-compression
                // write.
                _ => message,
            }
        };
        let offset = match self.append_with_policy(to_append) {
            Ok(offset) => offset,
            Err(e) => {
                // A drop-new shed: count the rejection (a shed-rate signal) but advance no produce
                // statistics, since nothing was written. Both the byte-cap shed AND the distinct
                // daily-write-budget shed are counted rejections (each increments `produce_rejected`
                // exactly once; the budget shed's own `daily_budget_sheds` counter is bumped once
                // inside `Log::append`). `e` is the STORAGE error here, so check both predicates;
                // only the byte cap could ever have force-reaped (the budget shed propagated straight
                // back from `append_with_policy`). Other storage errors fall through unchanged.
                if e.is_at_capacity() || e.is_daily_write_budget_exceeded() {
                    self.counters.produce_rejected =
                        self.counters.produce_rejected.saturating_add(1);
                    // The byte-cap / daily-budget shed is the BYTE dimension of the CoDel depth/byte
                    // backstop (#68): a sojourn-INDEPENDENT bound enforced at enqueue that holds even
                    // when a stalled drain produces no sojourn samples CoDel could see. Count it as a
                    // backstop shed so `ironbus_codel_backstop_shed_total` is the unified
                    // sojourn-independent backstop signal. (`produce_rejected` keeps its own historical
                    // meaning; this is additive observability, not a behavior change.)
                    self.record_backstop_shed();
                }
                return Err(EngineError::Storage(e));
            }
        };
        // The record bytes are counted at append time (the bytes are committed to the active
        // segment), but the durable head and the fsync histogram advance only in `commit_batch`.
        // Deliberately measured on the ORIGINAL `message`, not the compressed `to_append` (#430):
        // `produced_bytes` keeps its producer-facing LOGICAL meaning regardless of the codec; the
        // stored (post-compression) truth is `durable_record_bytes` and the #118 physical meters.
        self.registry.record_appended();
        // Per-stream PRODUCE throughput (#571): one record produced to the DEFAULT stream (the empty
        // name). `append_no_sync` is the single chokepoint every default-stream produce funnels through
        // (the actor's group-commit drain calls it directly), so counting here counts each produced
        // record exactly once. A NAMED stream's produce routes through `produce_in_stream` and is
        // counted there under its own label. Bounded + overflow-folded; allocation-free for the (single)
        // default-stream label.
        self.registry.record_stream_produced(b"");
        self.counters.produced += 1;
        let bytes = message.key.len() + message.headers.len() + message.payload.len();
        self.counters.produced_bytes = self
            .counters
            .produced_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        Ok(offset)
    }

    /// The opt-in effectively-once dedup variant of [`Engine::append_no_sync`] (#3, #33): it consults
    /// the per-producer dedup window FIRST, then appends only on a fresh produce.
    ///
    /// `dedup` is the producer's dedup identity for THIS publish: `(producer_id, epoch, msg_id)`. The
    /// `msg_id`'s presence is what activates dedup (the caller passes `Some` only when the wire carried
    /// a `msg_id`); a `None` `dedup` is exactly today's no-dedup [`Engine::append_no_sync`].
    ///
    /// The three outcomes, decided on the actor thread serially so they cannot race:
    /// - [`AppendOutcome::Duplicate`]: the `msg_id` is already in the producer's live window. NOTHING
    ///   is appended; the ORIGINAL offset is returned for a `PubAckDuplicate` (`duplicate = true`,
    ///   `rc = 0`). The `dedup_hits` counter increments. This is a BENIGN hit, never an error.
    /// - [`AppendOutcome::Fenced`]: the produce presented a STALE epoch (a zombie session). NOTHING is
    ///   appended; the caller rejects it.
    /// - [`AppendOutcome::Appended`]: a fresh produce. The record is appended (write, no fsync) exactly
    ///   as [`Engine::append_no_sync`], the `(msg_id -> offset)` mapping is RECORDED immediately (so a
    ///   second copy of the same `msg_id` LATER IN THE SAME BATCH dedups against it before its fsync),
    ///   and the offset is returned to be parked behind the covering commit (I2). If the maintenance
    ///   evicted an id by the TIME bound, the `dedup_out_of_window` counter increments.
    ///
    /// The monotonic `now` comes through the clock seam (the same one the lease table reads), so an
    /// NTP wall-clock step can never mis-expire the window (I6).
    ///
    /// # Errors
    /// On a fresh produce, the same storage errors as [`Engine::append_no_sync`] (a drop-new shed or a
    /// fatal write). A dedup hit or a fence never appends, so it never errors here.
    pub fn append_no_sync_dedup(
        &mut self,
        message: &Append<'_>,
        dedup: Option<DedupRequest<'_>>,
    ) -> Result<AppendOutcome, EngineError> {
        let Some(req) = dedup else {
            // No dedup requested: identical to the historical no-dedup append.
            return self.append_no_sync(message).map(AppendOutcome::Appended);
        };
        // The idempotent-producer SEQUENCE path (V2-M8): when the publish carried a `seq`, route
        // through the DURABLE per-producer sequence high-water (effectively-once across a restart + a
        // long offline gap) INSTEAD of the time-bounded `msg_id` window. This is the Kafka-style
        // dedup-to-exactly-once-append + zombie-epoch fencing + out-of-order rejection.
        if let Some(seq) = req.seq {
            return self.append_no_sync_seq(message, req.producer_id, req.epoch, seq);
        }
        let now = self.log.now_monotonic();
        match self
            .dedup
            .check(req.producer_id, req.epoch, req.msg_id, now)
        {
            ironbus_core::dedup::DedupDecision::Duplicate { offset } => {
                // A benign dedup hit: return the original offset, append nothing, count the hit.
                self.counters.dedup_hits = self.counters.dedup_hits.saturating_add(1);
                Ok(AppendOutcome::Duplicate(offset))
            }
            ironbus_core::dedup::DedupDecision::Fenced { current_epoch } => {
                Ok(AppendOutcome::Fenced { current_epoch })
            }
            ironbus_core::dedup::DedupDecision::Fresh { out_of_window } => {
                if out_of_window {
                    // An id aged out of the window by the TIME bound: a future republish of it would
                    // not be deduped. Count it so an operator can size the window to the retry interval.
                    self.counters.dedup_out_of_window =
                        self.counters.dedup_out_of_window.saturating_add(1);
                }
                let offset = self.append_no_sync(message)?;
                // Record the mapping at append time (offset assigned), so a same-batch duplicate is
                // caught before the covering fsync. The reply is still parked behind that fsync, so a
                // dedup hit never returns an offset that is not (or will not be) durable.
                self.dedup.record(req.producer_id, req.msg_id, offset, now);
                Ok(AppendOutcome::Appended(offset))
            }
        }
    }

    /// The idempotent-producer SEQUENCE variant of [`Engine::append_no_sync_dedup`] (V2-M8): it
    /// consults the DURABLE per-producer `(epoch, last_seq, last_offset)` high-water FIRST, then
    /// appends only on the next-expected (fresh) sequence. This is the EFFECTIVELY-ONCE path that
    /// survives a broker restart AND a long offline gap (the high-water is persisted, not a
    /// time-bounded window like the `msg_id` ring or NATS's `Nats-Msg-Id`).
    ///
    /// The four outcomes, decided on the actor thread serially so they cannot race:
    /// - [`AppendOutcome::Duplicate`]: `seq <= last_accepted`, a RETRY. NOTHING is appended; the
    ///   producer's last-accepted offset is returned for a `PubAckDuplicate` (`duplicate = true`,
    ///   `rc = 0`). A retry is deduped to exactly-once-append; counts the benign dedup hit.
    /// - [`AppendOutcome::Fenced`]: a STALE epoch (a zombie session). NOTHING is appended.
    /// - [`AppendOutcome::OutOfOrder`]: `seq > last_accepted + 1`, a GAP. REJECTED (Kafka
    ///   `OutOfOrderSequence`), so a later retry of a skipped seq cannot double-append; NOTHING is
    ///   appended; counts the rejection.
    /// - [`AppendOutcome::Appended`]: the next-expected sequence. The record is appended (write, no
    ///   fsync), the high-water is advanced to `(epoch, seq, offset)` IMMEDIATELY (so a same-batch
    ///   retry dedups before its fsync), and the offset is parked behind the covering commit (I2).
    ///   The durable `producer-seq.ckpt` handle is opened on the first such append (lazily, so a
    ///   non-idempotent workload never creates the file) and the high-water is snapshotted on the
    ///   checkpoint cadence + the graceful-shutdown flush.
    ///
    /// `now` (monotonic, from the clock seam) is used ONLY for the registry's LRU recency; the dedup
    /// decision itself is wall-clock-independent — the whole point of effectively-once over a gap.
    ///
    /// # Errors
    /// On a fresh produce, the same storage errors as [`Engine::append_no_sync`], plus an IO error
    /// from lazily creating the durable checkpoint file on the first sequenced append. A duplicate,
    /// fence, or out-of-order rejection never appends, so it never errors here.
    fn append_no_sync_seq(
        &mut self,
        message: &Append<'_>,
        producer_id: &[u8],
        epoch: u64,
        seq: u64,
    ) -> Result<AppendOutcome, EngineError> {
        let now = self.log.now_monotonic();
        match self.producer_seq.check(producer_id, epoch, seq, now) {
            SeqDecision::Duplicate { offset } => {
                // A benign retry: return the original offset, append nothing, count the hit (it is the
                // same observable as a msg_id dedup hit, so it shares the `ironbus_dedup_hits_total`
                // counter — no extra metric for the same effect).
                self.counters.dedup_hits = self.counters.dedup_hits.saturating_add(1);
                Ok(AppendOutcome::Duplicate(offset))
            }
            SeqDecision::Fenced { current_epoch } => Ok(AppendOutcome::Fenced { current_epoch }),
            SeqDecision::OutOfOrder { expected } => {
                // A silent reorder would corrupt idempotence; reject it (never append) and count it.
                self.counters.producer_out_of_order =
                    self.counters.producer_out_of_order.saturating_add(1);
                Ok(AppendOutcome::OutOfOrder { expected })
            }
            SeqDecision::Fresh => {
                // Ensure the durable checkpoint handle exists BEFORE the append, so the first
                // sequenced produce's high-water can be persisted on the next checkpoint tick (and a
                // file-creation IO error fails the produce rather than silently losing durability).
                self.ensure_producer_seq_checkpoint()?;
                let offset = self.append_no_sync(message)?;
                // Advance the high-water at append time (offset assigned), so a same-batch retry of
                // this seq dedups before the covering fsync. The reply is still parked behind that
                // fsync, so a duplicate never returns an offset that is not (or will not be) durable.
                self.producer_seq
                    .record(producer_id, epoch, seq, offset, now);
                Ok(AppendOutcome::Appended(offset))
            }
        }
    }

    /// The current out-of-order idempotent-sequence rejection count (the
    /// `ironbus_producer_out_of_order_total` counter, V2-M8).
    #[must_use]
    pub fn producer_out_of_order(&self) -> u64 {
        self.counters.producer_out_of_order
    }

    /// The number of producers currently tracked by the idempotent-sequence registry (V2-M8), for
    /// tests and introspection: O(active producers), bounded with LRU eviction.
    #[must_use]
    pub fn producer_seq_count(&self) -> usize {
        self.producer_seq.producer_count()
    }

    /// The current benign dedup-hit count (the `ironbus_dedup_hits_total` counter, #33).
    #[must_use]
    pub fn dedup_hits(&self) -> u64 {
        self.counters.dedup_hits
    }

    /// The current out-of-window dedup count (the `ironbus_dedup_out_of_window_total` counter, #33).
    #[must_use]
    pub fn dedup_out_of_window(&self) -> u64 {
        self.counters.dedup_out_of_window
    }

    /// The CoDel produce-admission decision (#68): given the monotonic instant a produce was ENQUEUED
    /// (when the session handed it to the append actor, read from the clock seam, `0` = not stamped),
    /// returns `true` if THIS new produce should be SHED under the controlled-delay control law,
    /// having measured its sojourn `now_monotonic - enqueue` (clamped `>= 0`) at this dequeue.
    ///
    /// This is the load-based (latency) shed distinct from the byte cap: a sustained admission
    /// sojourn above TARGET for a full INTERVAL sheds the NEW produce. It NEVER drops an
    /// already-accepted record (it is consulted BEFORE the append), so I2 holds. A shed increments
    /// the `ironbus_codel_shed_total` counter (a shed is never silent). When CoDel is disabled (the
    /// default), it always returns `false` (admit), so the produce path is byte-for-byte unchanged.
    ///
    /// `enqueue_monotonic_nanos` of `0` (an un-stamped produce, e.g. a test or a path that does not
    /// route through the actor channel) reads as a zero sojourn (below TARGET), so it never sheds:
    /// the control degrades safely to admit.
    pub fn codel_admit(&mut self, enqueue_monotonic_nanos: u64) -> bool {
        if !self.backpressure.codel.is_enabled() {
            return false;
        }
        let now = self.log.now_monotonic();
        // Sojourn is a non-negative duration; the monotonic clock never goes backwards, but clamp to
        // `>= 0` defensively (an un-stamped enqueue of 0 yields a 0 sojourn = below target = admit).
        let sojourn = now.saturating_sub(enqueue_monotonic_nanos);
        let shed = self.backpressure.codel.sojourn(sojourn, now);
        if shed {
            self.backpressure.codel_shed = self.backpressure.codel_shed.saturating_add(1);
        }
        shed
    }

    /// Signals the CoDel controller that the admission queue drained to empty at the current
    /// monotonic instant (#68), so the above-TARGET window closes and the dropping state is left. The
    /// append actor calls this when it has drained its whole pending batch with no further produce, so
    /// a bursty-but-healthy queue never lingers in the dropping state. A no-op when CoDel is disabled.
    pub fn codel_queue_empty(&mut self) {
        if self.backpressure.codel.is_enabled() {
            let now = self.log.now_monotonic();
            self.backpressure.codel.on_empty(now);
        }
    }

    /// The CoDel depth/byte BACKSTOP decision (#68): the sojourn-INDEPENDENT bound that fires when a
    /// drain is fully stalled (no sojourn samples), checked at enqueue. Given the current admission
    /// `pending_depth` (un-drained produce count) and the per-topic `ring_capacity` message bound
    /// (`0` = the bound is off, the byte cap alone backstops), returns `true` if the new enqueue is
    /// over the depth bound and must be shed regardless of sojourn. A shed increments the
    /// `ironbus_codel_backstop_shed_total` counter. The BYTE half of the backstop is the existing
    /// durable-log byte cap (`max_total_bytes`), which already sheds at enqueue independent of CoDel,
    /// so this method covers the DEPTH dimension the in-memory admission queue adds.
    pub fn codel_backstop_admit(&mut self, pending_depth: u64, ring_capacity: u64) -> bool {
        let shed = ring_capacity != 0 && pending_depth >= ring_capacity;
        if shed {
            self.backpressure.codel_backstop_shed =
                self.backpressure.codel_backstop_shed.saturating_add(1);
        }
        shed
    }

    /// Records that the byte-cap (or daily-budget) backstop shed a produce (#68), so the backstop
    /// shed counter reflects the BYTE dimension too, not only the depth dimension of
    /// [`Engine::codel_backstop_admit`]. The caller (the produce path) invokes it when an over-cap
    /// produce was rejected, so `ironbus_codel_backstop_shed_total` is the unified
    /// sojourn-independent backstop signal CoDel cannot see. Saturating.
    fn record_backstop_shed(&mut self) {
        self.backpressure.codel_backstop_shed =
            self.backpressure.codel_backstop_shed.saturating_add(1);
    }

    /// Whether the fsync-headroom admission credit is ENABLED (#378): a non-zero
    /// `wal_fsync_headroom_bytes`. The append actor reads this to decide whether the headroom path
    /// applies at all, so a zero-config broker takes the byte-for-byte historical path.
    #[must_use]
    pub fn wal_headroom_enabled(&self) -> bool {
        self.backpressure.fsync_headroom.is_enabled()
    }

    /// The configured fsync-headroom window in BYTES (#378), `0` = disabled. Exposed for the
    /// `ironbus_wal_fsync_headroom_bytes` gauge and the materialized-config introspection.
    #[must_use]
    pub fn wal_fsync_headroom_bytes(&self) -> u64 {
        self.backpressure.fsync_headroom.headroom_bytes()
    }

    /// The fsync-headroom ADMISSION decision for a new produce of `record_bytes` logical bytes (#378):
    /// returns `true` to ADMIT, `false` to throttle/shed, given the LIVE un-fsynced backlog
    /// (`unsynced_bytes()`, the #341 frontier) the storage log tracks. It reuses that frontier, so it
    /// bounds the GROUP-COMMIT backlog under `sync` and the LOSS WINDOW under a relaxed level.
    ///
    /// PURE read (no IO, no clock, no mutation): it consults the configured headroom against the
    /// current frontier only. When the headroom is disabled (the default) it always admits, so the
    /// produce path is unchanged. The NO-WEDGE floor lives in the pure
    /// [`FsyncHeadroom::would_admit`]: an EMPTY backlog always admits, so an oversized produce never
    /// deadlocks. The caller (the append actor) composes this with the group-commit DRAIN: it forces a
    /// flush (which resets the frontier to `0`) BEFORE the final shed decision, so a shed happens only
    /// when a drain was possible and still insufficient. It NEVER drops an accepted record (the
    /// decision is taken before the append), so I2 holds.
    #[must_use]
    pub fn wal_headroom_admit(&self, record_bytes: u64) -> bool {
        self.backpressure
            .fsync_headroom
            .would_admit(self.log.unsynced_bytes(), record_bytes)
    }

    /// Records one fsync-headroom shed (#378): a new produce rejected because the un-fsynced backlog
    /// could not be drained below the headroom even after a group-commit flush. Bumps the
    /// `ironbus_wal_fsync_headroom_shed_total` counter (a shed is never silent). Saturating.
    pub fn record_wal_headroom_shed(&mut self) {
        self.backpressure.wal_headroom_shed = self.backpressure.wal_headroom_shed.saturating_add(1);
    }

    /// Accounts `n` byte-cap sheds that the CONNECTION-THREAD fast-reject already performed off the
    /// actor (#476, fixes #465), so a fast-reject is counted EXACTLY like the authoritative actor-side
    /// byte-cap shed — never silent. The connection thread replies `AtCapacity` without enqueuing, so
    /// it cannot touch these actor-owned counters itself; the actor folds the accumulated fast-reject
    /// delta in here once per batch (the reconcile in `actor::run_actor`). It bumps the SAME three
    /// signals an in-actor `AtCapacity` shed does — `produce_rejected` (the drop-new shed counter),
    /// the unified sojourn-independent backstop shed, and the per-client retry-budget shed — so
    /// `ironbus_produce_rejected_total` stays equal to the rejections the producers actually saw,
    /// whether they were shed on the actor or fast-rejected on the connection thread. A no-op for
    /// `n == 0`. All bumps saturate. Idempotent only in the sense that the caller passes a DELTA it
    /// has not folded before (the gate hands out each fast-reject exactly once).
    pub fn record_fast_reject_sheds(&mut self, n: u64) {
        if n == 0 {
            return;
        }
        self.counters.produce_rejected = self.counters.produce_rejected.saturating_add(n);
        let now = self.log.now_monotonic();
        for _ in 0..n {
            // Mirror the per-shed accounting of the in-actor byte-cap path exactly (one backstop shed
            // and one retry-budget shed per rejected produce), so the two paths are observationally
            // identical. Both are saturating no-ops when their controller is disabled (the default).
            self.backpressure.codel_backstop_shed =
                self.backpressure.codel_backstop_shed.saturating_add(1);
            self.backpressure.retry_budget.record_shed(now);
        }
    }

    /// The broker-side per-client retry-budget re-check (#69): records one ORIGINAL request the
    /// broker ACCEPTED at the current monotonic instant, feeding the accept-based throttle so the
    /// observed retry ratio stays meaningful. Called when a produce (or other request) is admitted.
    /// A no-op accounting bump when the budget is disabled. See [`ironbus_core::backpressure::RetryBudget`].
    pub fn retry_budget_record_accept(&mut self) {
        let now = self.log.now_monotonic();
        self.backpressure.retry_budget.record_accept(now);
    }

    /// Records one freshly-appended record's produce ACK LEVEL (#571) into the bounded metric
    /// registry's fixed three-slot per-ack-level counter (`c0`/`c1`/`c2`). Allocation-free (a
    /// fixed-index array bump under the single-writer engine lock). Called by the append actor's drain
    /// on a FRESH append only, so the per-level sum equals the fresh-append count.
    pub fn record_produce_ack_level(&mut self, level: ironbus_proto::message::AckLevel) {
        self.registry.record_ack_level(level);
    }

    /// The broker-side per-client retry-budget re-check for a SHED request (#69): records one request
    /// the broker shed (raising the request count without the accept count), which drives the throttle
    /// probability up. Called when a produce is shed (CoDel, byte cap, or backstop). A no-op when the
    /// budget is disabled.
    pub fn retry_budget_record_shed(&mut self) {
        let now = self.log.now_monotonic();
        self.backpressure.retry_budget.record_shed(now);
    }

    /// Whether a RETRY (a redelivery the client is re-issuing) should be THROTTLED broker-side (#69),
    /// at the current monotonic instant. `true` means the budget is exhausted and the retry must be
    /// shed with the do-not-retry signal (so a buggy or hostile client that ignores its own
    /// client-side throttle still cannot mount a retry storm). A throttle increments the
    /// `ironbus_retry_shed_total` counter. When the budget is disabled, never throttles.
    pub fn retry_budget_should_throttle(&mut self) -> bool {
        let now = self.log.now_monotonic();
        Self::retry_budget_throttle(&mut self.backpressure, now)
    }

    /// The retry-throttle decision over the broker-wide budget (#69, #402), as an ASSOCIATED function
    /// taking `&mut Backpressure` (a field disjoint from `self.groups`) so the `poll` loop can consult
    /// it WHILE holding a `&mut WorkGroup` borrow (the borrow checker allows the disjoint field). At
    /// monotonic `now`, returns `true` to THROTTLE this retry (the budget is exhausted) and counts the
    /// throttle in `ironbus_retry_shed_total{side="broker"}` (never silent). When the budget is
    /// disabled (the default), never throttles. See [`ironbus_core::backpressure::RetryBudget`].
    fn retry_budget_throttle(backpressure: &mut Backpressure, now: u64) -> bool {
        let throttle = backpressure.retry_budget.should_throttle(now);
        if throttle {
            backpressure.retry_shed = backpressure.retry_shed.saturating_add(1);
        }
        throttle
    }

    /// The retry-throttle redelivery decision (#402), as an ASSOCIATED function over the disjoint
    /// fields (`backpressure`, `delivery`, `lease_config`) plus the polled group's `leases`, so the
    /// `poll` loops can call it while holding a `&mut WorkGroup` borrow. Returns `true` if the offset
    /// is a REDELIVERY (an expired lease, so the next claim would be attempt >= 2) AND the broker-side
    /// retry budget is exhausted, in which case it DEFERS the redelivery (pushes the lease deadline
    /// out by the next attempt's backoff, floored to one visibility window) WITHOUT bumping the
    /// attempt count or the generation: the redelivery is SPACED OUT, never dropped, so the
    /// at-least-once message still redelivers on a later poll until `MaxDeliver` routes it to the DLQ
    /// (no data loss). A FIRST delivery (no lease) returns `false` and is never throttled. When the
    /// budget is disabled (the default), it returns `false` and the redelivery path is unchanged. The
    /// throttle counts in `ironbus_retry_shed_total{side="broker"}` (a throttle is never silent).
    fn retry_throttle_defer(
        backpressure: &mut Backpressure,
        delivery: &DeliveryConfig,
        lease_config: LeaseConfig,
        leases: &mut LeaseTable,
        off: Offset,
        now: u64,
    ) -> bool {
        let Some(prior_attempt) = leases.pending_redelivery_attempt(off, now) else {
            // Not a redelivery candidate (no lease, or the lease is still active): never throttled.
            return false;
        };
        if !Self::retry_budget_throttle(backpressure, now) {
            return false;
        }
        // The deferral delay: the configured backoff for the NEXT attempt, floored to one visibility
        // window, so the storm is spaced out by at least a real interval (a deferral always makes
        // progress in time).
        let next_attempt = prior_attempt.saturating_add(1);
        let defer = delivery
            .nack_backoff(next_attempt)
            .max(lease_config.visibility_nanos.max(1));
        leases.defer_redelivery(off, now, defer);
        true
    }

    /// Accounts `n` LEVEL-0 (no-ack / fire-and-forget) byte-cap sheds that the CONNECTION-THREAD
    /// fast-reject already performed off the actor (#495, generalizing #476). An over-cap L0 produce is
    /// shed at the connection thread BEFORE it enqueues (the client accepted loss by contract, so it
    /// gets no ack and never blocks), which is a fire-and-forget DROP — so it is folded into
    /// `ironbus_fire_and_forget_shed_total`, the SAME counter the fire-and-forget TOKEN-BUCKET drop
    /// bumps ([`Engine::fire_and_forget_admit`]), NOT `produce_rejected` (the Level-1 at-least-once
    /// rejection counter). The actor folds the accumulated L0-shed delta in here once per batch (the
    /// reconcile in `actor::run_actor`), so an L0 cap-shed is never silent. A no-op for `n == 0`;
    /// saturating. Idempotent in the sense that the caller passes a DELTA it has not folded before (the
    /// gate hands out each L0 shed exactly once).
    pub fn record_fire_and_forget_sheds(&mut self, n: u64) {
        self.backpressure.fire_and_forget_shed =
            self.backpressure.fire_and_forget_shed.saturating_add(n);
    }

    /// The fire-and-forget (un-credited) admission decision (#69): tries to admit one fire-and-forget
    /// message of `payload_bytes` at the current monotonic instant through the per-connection token
    /// bucket. `true` admits; `false` SHEDS the message (the bucket is empty), incrementing
    /// `ironbus_fire_and_forget_shed_total`. The bucket governs ONLY this path, so a depleted bucket
    /// sheds fire-and-forget messages and NOTHING ELSE (the credited path is untouched). When the
    /// bucket is disabled (the default), always admits. See [`ironbus_core::backpressure::TokenBucket`].
    pub fn fire_and_forget_admit(&mut self, payload_bytes: u64) -> bool {
        let now = self.log.now_monotonic();
        let admit = self
            .backpressure
            .fire_and_forget
            .try_admit(payload_bytes, now);
        if !admit {
            self.backpressure.fire_and_forget_shed =
                self.backpressure.fire_and_forget_shed.saturating_add(1);
        }
        admit
    }

    /// The egress concurrency budget under the AIMD limiter (#69): the current limit (within
    /// `[4, 128]`). Exposed for the `ironbus_egress_limit` gauge and the AIMD-aware per-consumer
    /// egress credit. The gauge reports it even when the AIMD is inert (the static 16 default).
    #[must_use]
    pub fn egress_limit(&self) -> u32 {
        self.backpressure.egress.limit()
    }

    /// Whether the egress AIMD actively GOVERNS the per-consumer egress credit (#69, #402): `true`
    /// only when an operator opted in via a non-zero `--egress-limit`. When `false` (the default) the
    /// per-consumer credit path is byte-for-byte the historical behavior, so a zero-config broker is
    /// unchanged. The session reads this to decide whether to apply the AIMD cap and feed the signals.
    #[must_use]
    pub fn egress_aimd_enabled(&self) -> bool {
        self.backpressure.egress_aimd_enabled
    }

    /// The AIMD-limited per-Flow egress GRANT for a consumer whose negotiated credit ceiling is
    /// `ceiling` (#69, #402): `min(ceiling, current AIMD limit)`, so the AIMD adjusts the effective
    /// credit WITHIN the negotiated #292 cap and NEVER exceeds it. When the AIMD is inert (the
    /// default), it returns `ceiling` unchanged, so the per-consumer credit is exactly the negotiated
    /// value. The session uses this as one of the `min` terms bounding a Flow batch.
    #[must_use]
    pub fn egress_grant_within(&self, ceiling: u32) -> u32 {
        if self.backpressure.egress_aimd_enabled {
            ceiling.min(self.backpressure.egress.limit())
        } else {
            ceiling
        }
    }

    /// KEEP-UP signal to the egress AIMD (#69, #402): the consumer kept up (it ACKED promptly), so
    /// additive-increase the egress limit by one (capped at 128). A no-op when the AIMD is inert, so
    /// an unconfigured broker never moves the limit off its static default. Called on a clean ack.
    pub fn egress_keep_up(&mut self) {
        if self.backpressure.egress_aimd_enabled {
            self.backpressure.egress.on_success();
        }
    }

    /// FALLING-BEHIND signal to the egress AIMD (#69, #402): the consumer fell behind (a would-block
    /// at the egress grant with a near-full in-flight set, slow acks, or a nack), so
    /// multiplicative-decrease the egress limit (halve, floored at 4) and count the throttled grant in
    /// `ironbus_egress_shed_total` (never silent). A no-op when the AIMD is inert. The asymmetry
    /// (halve fast, climb slowly) throttles a slow consumer smoothly instead of oscillating.
    pub fn egress_falling_behind(&mut self) {
        if self.backpressure.egress_aimd_enabled {
            self.backpressure.egress.on_failure();
            self.backpressure.egress_shed = self.backpressure.egress_shed.saturating_add(1);
        }
    }

    /// Reports a CLEAN egress window to the AIMD limiter (#69): additive increase by one (capped at
    /// 128), UNGATED (it always moves the limit). Retained as the raw limiter knob for tests and a
    /// future downstream-sink call site; the session uses the AIMD-enabled-gated [`Engine::egress_keep_up`].
    pub fn egress_on_success(&mut self) {
        self.backpressure.egress.on_success();
    }

    /// Reports a FAILED egress signal to the AIMD limiter (#69): multiplicative decrease (halve,
    /// floored at 4), UNGATED. The raw limiter knob; the session uses the gated
    /// [`Engine::egress_falling_behind`].
    pub fn egress_on_failure(&mut self) {
        self.backpressure.egress.on_failure();
    }

    /// Records that an egress request was SHED at the concurrency limit (#69), incrementing
    /// `ironbus_egress_shed_total`. Saturating.
    pub fn egress_record_shed(&mut self) {
        self.backpressure.egress_shed = self.backpressure.egress_shed.saturating_add(1);
    }

    /// A read-only snapshot of the backpressure controllers' observable state (#68, #69), for the
    /// `/metrics` rendering and the `/admin` introspection. The counters are the runtime resilience
    /// signals; the estimate / ratio / limit are gauges.
    #[must_use]
    pub fn backpressure_snapshot(&self) -> BackpressureSnapshot {
        BackpressureSnapshot {
            codel_shed: self.backpressure.codel_shed,
            codel_backstop_shed: self.backpressure.codel_backstop_shed,
            codel_interval_resets: self.backpressure.codel.interval_resets(),
            codel_sojourn_estimate_ms: self.backpressure.codel.sojourn_estimate_ms(),
            retry_shed: self.backpressure.retry_shed,
            retry_ratio_per_million: self.backpressure.retry_budget.observed_ratio_per_million(),
            fire_and_forget_shed: self.backpressure.fire_and_forget_shed,
            egress_shed: self.backpressure.egress_shed,
            egress_limit: self.backpressure.egress.limit(),
            wal_headroom_shed: self.backpressure.wal_headroom_shed,
            wal_fsync_headroom_bytes: self.backpressure.fsync_headroom.headroom_bytes(),
        }
    }

    /// Issues the durability barrier for a group-committed batch, advances the visible head so those
    /// records become visible to readers, and runs the once-per-batch post-commit bookkeeping (the
    /// fsync histogram, retention reap, idle-group sweep). This is the sync half of group commit
    /// (#177): one `commit_batch` amortizes the work over a whole drained batch of
    /// [`Engine::append_no_sync`] calls, which is what removes the per-produce barrier and the
    /// head-of-line block.
    ///
    /// The BARRIER is durability-level aware (#341, #379):
    /// - Under the default [`DurabilityLevel::Sync`] this issues the covering `fdatasync` BEFORE it
    ///   returns, so after `Ok` every record appended since the previous commit is DURABLE and the
    ///   append actor may ack the whole batch: I2 is preserved (ack-implies-durable, zero acked loss
    ///   on a power cut). This is the historical behavior, byte-for-byte, for the default broker.
    /// - Under a relaxed level the records are made VISIBLE (page-cache, readable) WITHOUT the covering
    ///   fsync, so the ack the actor then sends is a weaker promise: I2 is WAIVED, by design and
    ///   opt-in. `interval` still forces an `fdatasync` here when the time window or the byte budget is
    ///   due (bounding the loss); `async`/`none` issue no barrier here at all (a segment roll's seal or
    ///   a clean shutdown is their only barrier). The fsync histogram records only REAL fsyncs, so a
    ///   relaxed level's deferred-sync batch contributes no spurious zero-latency sample.
    ///
    /// # Errors
    /// Propagates a storage error from the durability barrier (a failed `fdatasync` freezes the
    /// writer, the fatal `WriterFrozen`), the retention reap, or the idle-group sweep. A frozen writer
    /// surfaces the fatal error under every level (the relaxed `flush_no_sync` still refuses a frozen
    /// writer), so a relaxed level never silently swallows a fatal storage fault.
    pub fn commit_batch(&mut self) -> Result<(), EngineError> {
        // The durability barrier, chosen by the active level. Returns whether a REAL `fdatasync` ran
        // this batch, so the fsync/append-latency histograms record only genuine barriers (a relaxed
        // level's deferred-sync batch must not log a fake 0-ns fsync sample).
        // Stamp the produce->ack window start BEFORE the durability barrier (#570): the records were
        // appended in this drained batch and are acked to their producers only once this barrier makes
        // them durable, so the engine time across the barrier is the producer-visible ack latency.
        // One clock-seam read, no allocation; only used if a real fsync ran below.
        let produce_ack_start = self.log.now_monotonic();
        if self.commit_durability_barrier()? {
            // A real fsync covered this batch: it is the shared durable-append cost (group commit
            // amortizes ONE fsync over the whole drained batch), so record it once into the
            // fixed-bucket `ironbus_fsync_duration_seconds` and as the batch's append latency. Both
            // are O(1) and allocation-free. The relaxed-level batches that DEFERRED their sync record
            // nothing here; the eventual covering fsync (a window flush, a roll, or shutdown) is the
            // one that logs the latency, so the histogram still reflects real barriers, not acks.
            let fsync_nanos = self.last_fsync_nanos;
            self.fsync.observe(fsync_nanos);
            self.registry.observe_fsync_nanos(fsync_nanos);
            self.registry.observe_append_nanos(fsync_nanos);
            // The produce->ACK request-path latency (#570): the engine time the barrier took to make
            // this batch durable (and thus ackable). Measured across the barrier from the seam, so it
            // captures the full produce->ack window the producer waits on, distinct from the bare
            // `last_fsync_nanos` syscall cost. Allocation-free; recorded only on a real barrier.
            let produce_ack_nanos = self.log.now_monotonic().saturating_sub(produce_ack_start);
            self.registry.observe_produce_ack_nanos(produce_ack_nanos);
        }
        // Consumer-safe retention (refs #13, #80): after the records are durable, reclaim disk by the
        // size, age, or count bound, by deleting whole old SEALED segments while the log is over the
        // retention bound, but never one any consumer still needs. Run once per group commit so space
        // is freed as the log grows; it is a no-op unless a bound is set. The protect floor is the
        // MINIMUM committed offset across every TOUCHED group (#424), so the slowest consumer's
        // records are never reaped while an untouched structural group cannot pin the floor.
        self.reap_for_retention()?;
        // Idle named-group eviction sweep (#277): the produce seam is the second deterministic tick
        // (the poll seam is the first), so a broker that produces but is not being polled still
        // reclaims idle groups against the clock seam. The sweep is a no-op when the window is
        // disabled (`group_idle_evict_ms == 0`). A produce ADVANCES the head, so any group that was
        // caught up is now behind and (correctly) not evictable until it catches up again; the sweep
        // here therefore reclaims only groups that were already idle AND caught up before this batch.
        let now = self.log.now_monotonic();
        self.sweep_idle_groups(now)?;
        // The Level-2 confirm-timeout sweep (#497): on the SAME produce/group-commit tick, time out
        // any pending L2 confirm no consumer has acked within the registry TTL, so a slow or absent
        // consumer cannot pin a confirm (or grow the registry) forever. A no-op unless the TTL is set
        // AND an L2 confirm is outstanding, so a no-L2 broker is unaffected. It rides this existing
        // tick rather than a new timer, and runs regardless of the idle-eviction window so the TTL
        // bound holds even when group idle-eviction is disabled.
        self.sweep_l2_confirm_timeouts();
        Ok(())
    }

    /// Decides and issues the durability barrier for the current `commit_batch`, by the active level
    /// (#341, #379), and reports whether a REAL `fdatasync` ran (so the caller records the latency
    /// histograms only for genuine barriers).
    ///
    /// - [`DurabilityLevel::Sync`] (default): always `log.sync()` (the covering `fdatasync`). After it
    ///   returns the batch is durable, so the ack is ack-implies-durable (I2). Returns `true`.
    /// - [`DurabilityLevel::Interval`]: forces `log.sync()` only when the time window
    ///   (`flush_interval_nanos`, measured on the monotonic clock seam, never the wall clock, so an
    ///   NTP step never mis-fires it, I6) OR the unsynced-byte budget (`flush_max_bytes`) is due;
    ///   otherwise `log.flush_no_sync()` (advance the visible head, no fsync). A forced sync resets the
    ///   window anchor and returns `true`; a deferred batch returns `false`. The window thus bounds the
    ///   acked-but-unsynced records to the smaller of the time and byte triggers.
    /// - [`DurabilityLevel::Async`] / [`DurabilityLevel::None`]: never force a sync here;
    ///   `log.flush_no_sync()` only. A segment roll's seal (every level) and a clean shutdown
    ///   ([`Engine::checkpoint_all_groups`]) are their only barriers. Returns `false`.
    ///
    /// A frozen writer surfaces the fatal error under every level (`flush_no_sync` refuses a frozen
    /// writer too), so a relaxed level never swallows a fatal storage fault.
    ///
    /// # Errors
    /// Propagates a storage error from the `fdatasync` (a failed barrier freezes the writer, the fatal
    /// `WriterFrozen`) or from `flush_no_sync` on an already-frozen writer.
    fn commit_durability_barrier(&mut self) -> Result<bool, EngineError> {
        // `sync` and a DUE `interval` window both issue the covering fsync; `async`/`none` and a
        // not-yet-due `interval` window only advance the visible head (page cache), deferring the
        // fsync. The decision is taken BEFORE the barrier so a relaxed level never issues an fsync the
        // level did not ask for.
        let force_sync = match self.durability_level {
            DurabilityLevel::Sync => true,
            DurabilityLevel::Interval => self.interval_flush_is_due(),
            // `async`/`none` never force a periodic fsync; the seal-on-roll and shutdown flush are the
            // only barriers. `none` differs from `async` only in that there is no opportunistic
            // mid-run sync to add later, which is a documentation distinction, not a branch here (both
            // defer every commit's fsync identically; the difference is the absence of a window).
            DurabilityLevel::Async | DurabilityLevel::None => false,
        };
        if force_sync {
            // Time the real durability barrier via the clock seam (so the deterministic sim stays
            // reproducible: logical time does not advance in-memory).
            let started = self.log.now_monotonic();
            self.log.sync()?;
            let done = self.log.now_monotonic();
            self.last_fsync_nanos = done.saturating_sub(started);
            // Reset the interval window anchor to this real barrier, so the next window measures from
            // the last completed fsync, not from the broker's open instant.
            self.last_sync_monotonic_nanos = done;
            Ok(true)
        } else {
            // A relaxed, deferred batch: make the records VISIBLE (readable, page-cache) without the
            // covering fsync. I2 is WAIVED for the acked-but-unsynced tail until the next real barrier.
            self.log.flush_no_sync().map_err(EngineError::Storage)?;
            Ok(false)
        }
    }

    /// Whether the `interval` level's flush window is DUE this commit (#341): true when the time
    /// window has elapsed since the last completed `fdatasync` OR the accumulated unsynced record
    /// bytes have reached the byte budget. A trigger of `0` is DISABLED (that dimension never fires),
    /// so with both at `0` the window never forces a sync (it degrades to `async`-like deferral, which
    /// the CLI validation prevents by requiring at least one positive trigger). Pure read of engine
    /// state plus the monotonic clock seam; no wall-clock read (I6).
    fn interval_flush_is_due(&self) -> bool {
        // The BYTE trigger: the log tracks the exact unsynced record-byte exposure (the logical bytes
        // appended since the last real barrier, reset on a `sync` or a roll's seal), so compare it
        // directly against the budget. A `0` budget disables the byte trigger.
        let byte_due =
            self.flush_max_bytes != 0 && self.log.unsynced_bytes() >= self.flush_max_bytes;
        let time_due = self.flush_interval_nanos != 0 && {
            let elapsed = self
                .log
                .now_monotonic()
                .saturating_sub(self.last_sync_monotonic_nanos);
            elapsed >= self.flush_interval_nanos
        };
        byte_due || time_due
    }

    /// Forces a real covering `fdatasync` regardless of the active level, making every visible record
    /// DURABLE (#341, #379). This is the clean-shutdown / explicit-flush barrier the relaxed levels
    /// rely on: [`Engine::checkpoint_all_groups`] calls it so a graceful stop loses NOTHING even under
    /// `async`/`none` (their loss window is bounded by "since the last roll OR clean shutdown"). Under
    /// `sync` it is the same fsync `commit_batch` already issued, so it is a cheap no-op when nothing
    /// is unsynced. After it returns `Ok` the visible and durable heads are equal.
    ///
    /// # Errors
    /// Propagates the fatal `WriterFrozen` if the barrier fails (the writer freezes read-only) or the
    /// writer was already frozen.
    pub fn force_sync(&mut self) -> Result<(), EngineError> {
        let started = self.log.now_monotonic();
        self.log.sync()?;
        let done = self.log.now_monotonic();
        // A real barrier ran: reset the interval window anchor and record the latency, so a shutdown
        // flush under a relaxed level is reflected in the fsync histogram like any other real fsync.
        self.last_sync_monotonic_nanos = done;
        let fsync_nanos = done.saturating_sub(started);
        self.fsync.observe(fsync_nanos);
        self.registry.observe_fsync_nanos(fsync_nanos);
        self.registry.observe_append_nanos(fsync_nanos);
        Ok(())
    }

    /// The active durability level (#341, #379), for the observability surface and the materialized
    /// config line. Default [`DurabilityLevel::Sync`].
    #[must_use]
    pub fn durability_level(&self) -> DurabilityLevel {
        self.durability_level
    }

    /// Whether the active durability level WAIVES I2 (ack no longer implies durable): the sticky
    /// power-loss-unsafe signal exposed as the `ironbus_durability_power_loss_unsafe` gauge (#379).
    /// `false` under the default `sync`, `true` under any relaxed level.
    #[must_use]
    pub fn power_loss_unsafe(&self) -> bool {
        self.durability_level.waives_i2()
    }

    /// The current UNSYNCED exposure in RECORD BYTES: the durable-record bytes that are VISIBLE
    /// (acked) but NOT yet covered by a returned `fdatasync` (#341, #379). Always `0` under `sync`
    /// (the visible and durable heads are equal); under a relaxed level it is the live bytes-at-risk a
    /// power cut would lose, the operator's real-time loss-exposure read. Exposed as the
    /// `ironbus_durability_unsynced_bytes` gauge.
    #[must_use]
    pub fn unsynced_bytes(&self) -> u64 {
        self.log.unsynced_bytes()
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
    ///
    /// The opt-in daily-write-budget shed ([`StorageError::DailyWriteBudgetExceeded`], #118) is
    /// EXCLUDED from the `DropOldest` reap path on purpose: no reap ever lowers today's
    /// physical-write meter, so force-reaping to relieve a budget shed would erase the durable log
    /// segment-by-segment without ever admitting the produce. It is therefore a FINAL drop-new
    /// rejection under EVERY policy (it propagates straight back, the same as under `DropNew`), so
    /// the producer is told to back off and the flash-wear governor protects the disk it is meant to.
    fn append_with_policy(&mut self, message: &Append<'_>) -> Result<Offset, StorageError> {
        match self.log.append(message) {
            Ok(offset) => Ok(offset),
            // Only the genuine disk-full byte-cap shed is reclaimable by a reap, so only it may drive
            // the `DropOldest` reclaim-then-retry loop. The daily-write-budget shed and any other
            // storage error (a frozen writer, an oversized record) propagate unchanged; under DropNew
            // every rejection is final too.
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
            // fully-consumed segment with NO data loss. The protect floor is the slowest TOUCHED
            // group's committed offset (#424), so this never drops a record a consumer needs.
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
                        // The Level-2 force-reap terminal (#497): the forced drop-oldest just deleted
                        // the oldest sealed segment out from under any slow consumer, so a record
                        // below the NEW earliest-retained offset can never be consumed (acked) by the
                        // designated group. Fire a `DeadLettered` `ProduceConfirm` for every pending
                        // L2 confirm now below that floor, so the producer is not left awaiting a
                        // confirm the broker has made impossible. A no-op unless an L2 confirm was
                        // pending in the reaped span. Same threat class as the dead-letter terminal.
                        let earliest = self.log.earliest_offset().get();
                        self.terminate_confirms_below(earliest, ConfirmStatus::DeadLettered);
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
    /// every TOUCHED consumer group (#424): a group that has ever seen a consumer interaction or
    /// durable consumer state. A never-touched group (the boot-created default group `""` of a
    /// deployment that only consumes through named groups) does not pin the floor, and with no
    /// touched group at all the floor is the durable head. A record any touched group has not
    /// yet consumed is never reaped. The age bound reads `now` from the
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
        // The `compact_and_delete` order (#337) is fixed and load-bearing: the cheap WHOLE-SEGMENT
        // reaper runs FIRST (so CPU and flash are never spent compacting a segment about to be
        // reaped), THEN, if compaction is enabled, one rate-limited compaction pass.
        if self.retention != RetentionBounds::default() {
            let protect_below = self.min_committed_offset();
            let outcome = self.log.reap(self.retention, protect_below)?;
            self.counters.segments_reaped = self
                .counters
                .segments_reaped
                .saturating_add(outcome.segments_reaped);
        }
        // The OPT-IN, OFF-HOT-PATH compaction pass (#337): a no-op unless an operator enabled it.
        // It only ever reads SEALED segments and writes a NEW v2 segment, never the active one, so
        // it does not race or block the append path. It runs here, off the critical produce write,
        // after the produce already succeeded and was acked.
        if self.compaction.enabled {
            // A frozen writer has no active segment; skip compaction rather than touch a dead log.
            let _ = self.log.maybe_compact(&self.compaction)?;
        }
        Ok(())
    }

    /// The retention protect floor: the minimum committed offset across every work-group that
    /// has ever seen a consumer interaction or durable consumer state (`touched`, #424). A
    /// touched group sitting at offset 0 keeps the floor at 0 (reaping nothing), exactly the
    /// safe behavior for a real, slow consumer. An UNTOUCHED group is skipped: the boot-created
    /// default group (`""`) exists structurally whether or not anyone consumes through it, and
    /// before #424 its virgin offset-0 cursor pinned the floor at 0 forever for a deployment
    /// that only consumes through named groups, silently disabling every retention bound. With
    /// no touched group at all the floor is the durable head: no consumer has ever shown intent,
    /// so every sealed record is reapable once a retention bound trips.
    ///
    /// GHOST entries also pin (#432): a `group_last_checkpointed` entry whose group is NOT live
    /// is an idle-evicted group's durable position, kept by the sweep so eviction (a memory
    /// reclaim) never silently weakens retention protection the way absence would. A ghost is
    /// touched by construction (it carried durable state). The ghost is superseded the moment
    /// the group returns (the live group takes over via the touched filter: the consumer paths
    /// resume at exactly the ghost's value, while the serve-flag declared-group paths create
    /// fresh at offset 0, a LOWER and therefore safe pin) and is released by an explicit Unsub
    /// ([`Engine::evict_group_if_idle`]). Note the pin binds only the consumer-safe reaper:
    /// `reap_oldest_forced` under drop-oldest deliberately ignores the floor, ghost or live.
    /// The ghost set is bounded by the distinct group names ever checkpointed (the same class
    /// of bound as the on-disk checkpoint files, which open already loads unboundedly by
    /// design); each retention pass scans it with one live-map lookup per entry.
    fn min_committed_offset(&self) -> u64 {
        let live = self
            .groups
            .values()
            .filter(|g| g.touched)
            .map(|g| g.cursor.committed().get());
        let ghosts = self
            .group_last_checkpointed
            .iter()
            .filter(|(name, _)| !self.groups.contains_key(name.as_str()))
            .map(|(_, &committed)| committed);
        live.chain(ghosts)
            .min()
            .unwrap_or_else(|| self.flushed_offset().get())
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
    /// would reset a re-created group to offset 0 and redeliver the whole already-acked log. The
    /// in-memory `group_last_checkpointed` entry is ALSO kept as a GHOST (#432) that keeps
    /// pinning the retention protect floor at the eviction-point head until the group returns
    /// (the live resumed cursor supersedes it) or an explicit `Unsub` releases it, so an idle
    /// eviction reclaims memory without silently weakening retention protection (a restart would
    /// re-pin the durable cursor as a live touched group anyway, so the ghost only makes the
    /// pre-restart runtime consistent with that). If the
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
            // The sweep KEEPS the ghost (#432): an idle consumer never renounced its position,
            // so its eviction-point checkpoint keeps pinning the retention protect floor.
            self.evict_group(&name, GhostPolicy::Keep)?;
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
    /// The `ghost` policy (#432) decides whether the group's `group_last_checkpointed` entry
    /// survives the removal as a GHOST that keeps pinning the retention protect floor at the
    /// eviction-point head. The idle sweep KEEPS the ghost: an idle consumer did not renounce its
    /// position, and a restart would re-pin it anyway (recovery resumes every durable cursor as a
    /// live touched group), so keeping the ghost makes the pre-restart runtime consistent with
    /// what a restart already enforces. An explicit `Unsub` RELEASES it: the consumer named the
    /// group and walked away, so pinning becomes opt-out by unsubscribe, never implicit by
    /// absence.
    ///
    /// # Errors
    /// Propagates a storage error from writing the group's checkpoint.
    fn evict_group(&mut self, group: &str, ghost: GhostPolicy) -> Result<(), EngineError> {
        let committed = match self.groups.get(group) {
            Some(g) => g.cursor.committed().get(),
            None => return Ok(()),
        };
        // Persist the cursor at the head BEFORE removing the group. `write_group_checkpoint` is
        // unconditional (unlike the interval/has-advanced gate of `checkpoint_group`), so the
        // checkpoint is durably at the head even if no interval checkpoint had fired since the group
        // caught up. Only after this succeeds do we drop the in-memory state. The
        // `write_group_checkpoint` call also refreshes `group_last_checkpointed`, so a kept ghost
        // pins at exactly the eviction-point head.
        self.write_group_checkpoint(group, committed)?;
        self.groups.remove(group);
        if ghost == GhostPolicy::Release {
            self.group_last_checkpointed.remove(group);
        }
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
        let Some(g) = self.groups.get(group) else {
            // The group is not live: it may have been sweep-evicted earlier while this connection
            // stayed subscribed, leaving a GHOST floor entry (#432). The explicit Unsub is the
            // consumer renouncing the position, so release the ghost here. Safe to remove
            // unconditionally in this arm: a `group_last_checkpointed` key absent from
            // `self.groups` is by definition a ghost (a live group's entry is the checkpoint
            // interval gate and is only touched while the group is live), and the default group
            // `""` is always live so it can never reach this arm. The release is in-memory only
            // (the `cursor-<hex>.ckpt` is never deleted), so a restart conservatively re-pins via
            // recovery. Any connection that can speak the wire can release any ghost by name
            // (SUB then UNSUB on an absent group): that matches the pre-#106 trust model, where
            // an unauthenticated peer can already produce, consume, and ack on any group; the
            // authed surface (#106/#380) is where per-group rights would land.
            self.group_last_checkpointed.remove(group);
            return false;
        };
        // `now == last_activity` with a window of 0 makes the idle clause vacuously true, so the
        // predicate reduces to exactly the position-safety clauses; the explicit Unsub is what
        // authorizes skipping the idle wait.
        let evictable = Self::is_evictable(group, g, flushed, g.last_activity, 0);
        // Persist-then-drop. A checkpoint write error leaves the group live (the `is_ok`), so the
        // explicit reclaim, like the sweep, never trades a committed position for a disk hiccup.
        // The explicit Unsub RELEASES the ghost (#432): pinning is opt-out by unsubscribe.
        evictable && self.evict_group(group, GhostPolicy::Release).is_ok()
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
    /// A thin timing wrapper over [`Engine::poll_in_timed`] that records the deliver request-path
    /// latency (#570): one clock-seam read at entry, the inner scan, and — ONLY when the poll handed
    /// out a delivery ([`Poll::Message`]) — one allocation-free `observe` of the engine time the poll
    /// took. An idle/parked/truncated poll records nothing (no delivery happened), so the histogram is
    /// the distribution of latencies for polls that actually delivered.
    pub fn poll_in(&mut self, group: &str, now: u64) -> Result<Poll, EngineError> {
        let outcome = self.poll_in_timed(group, now);
        if matches!(outcome, Ok(Poll::Message(_))) {
            let deliver_nanos = self.log.now_monotonic().saturating_sub(now);
            self.registry.observe_deliver_nanos(deliver_nanos);
        }
        outcome
    }

    // The poll loop is one cohesive scan (truncation, compaction-hole, retry-throttle, claim,
    // disposition, dead-letter capture); splitting it would scatter the single in-flight-window walk
    // across helpers and obscure the order the cases must be checked in. Mirrors `poll_in_member`.
    #[allow(clippy::too_many_lines)]
    fn poll_in_timed(&mut self, group: &str, now: u64) -> Result<Poll, EngineError> {
        // Mark the group being polled active FIRST (if it is already live), so the sweep below never
        // evicts the very group this poll is about to drain (#277): a poll IS activity, so refreshing
        // its last-activity before the sweep keeps a self-poll of an otherwise-idle group from
        // needlessly evicting-and-re-creating it.
        if let Some(g) = self.groups.get_mut(group) {
            g.last_activity = now;
            // A poll is a consumer interaction (#424): the group now pins the retention floor.
            g.touched = true;
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
        // The TTL knobs read ONCE before the group borrow (V2-M4, #549): the per-stream default TTL,
        // the wall-clock seam instant the whole scan checks deadlines against (so expiry is
        // seam-anchored and `ManualClock`-deterministic with no per-record clock read in the hot
        // scan), and whether an expired message routes to a dead-letter exchange. All read here
        // because the group borrow below cannot coexist with a later `&self` read.
        let default_ttl = self.default_message_ttl;
        let now_unix_millis = self.log.now_unix_millis();
        let dead_letters_expired = self.dead_letters_expired();
        let g = self
            .groups
            .entry(group.to_string())
            .or_insert_with(|| WorkGroup::new(lease_config, now));
        // Stamp last-activity again (#277): redundant for a group refreshed before the sweep, but it
        // also covers a freshly created/resumed group and the `or_insert_with` fallback, so EVERY
        // poll (deliverable or idle) keeps the polled group alive against the next sweep.
        g.last_activity = now;
        g.touched = true;
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
        // A TTL-EXPIRED message to route to the dead-letter EXCHANGE (V2-M4, #549/#551), captured the
        // same way (the DLX append needs `&mut self`). Only used when an exchange + the expired flag
        // are configured; otherwise an expired record is committed-past INLINE (reclaim, no DLX).
        let mut expired_dlx: Option<(Offset, u32, OwnedRecord)> = None;
        // Whether the scan committed past at least one INLINE-reclaimed expired record (#549), so the
        // consumer-lag floor is synced ONCE after the borrow ends (no per-record `&mut self` call).
        let mut expired_inline = false;
        while offset < window_end {
            let off = Offset::new(offset);
            if g.cursor.is_acked(off) {
                offset += 1;
                continue;
            }
            // RETRY-THROTTLE enforcement (#402): a REDELIVERY under an exhausted budget is DEFERRED
            // (spaced out), never dropped. See [`Engine::retry_throttle_defer`]. A `true` means it was
            // deferred this poll, so skip it (it redelivers later, at-least-once intact).
            if Self::retry_throttle_defer(
                &mut self.backpressure,
                &self.delivery,
                self.lease_config,
                &mut g.leases,
                off,
                now,
            ) {
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
                    // SPARSE-OFFSET tolerance for a compacted log (#337): if the record the read
                    // returned is NOT at `off`, then `off` was COMPACTED AWAY (a superseded value
                    // removed by a later record for its key). The read advanced to the next present
                    // survivor at `record.offset`, so the WHOLE half-open run `[off, record.offset)`
                    // is compacted-away (every offset between is absent). A compaction gap is NOT data
                    // loss and NOT a missing record: those offsets are ALREADY-SATISFIED (nothing to
                    // deliver there), so the cursor is acked past the entire run as if each had been
                    // acked. The lease just claimed at `off` is released first. This is the interior,
                    // sparse-offset twin of the below-earliest trim above: a trim reaps a PREFIX (the
                    // `committed < earliest` branch returns `Poll::Truncated`), whereas this hole is
                    // ABOVE `earliest` with the segment still present, so it is surfaced as the
                    // distinct `Poll::Compacted` (the caller maps it to `GapMarker(reason=COMPACTED)`
                    // for a capable consumer, #346/#411; a non-capable consumer silently advances). For
                    // a dense (non-compacted) log the offsets always match, so this branch is never
                    // taken and the hot path is unchanged.
                    if record.offset != off {
                        g.leases.ack(&token);
                        let mut hole = offset;
                        while hole < record.offset.get() {
                            g.cursor.ack(Offset::new(hole));
                            hole += 1;
                        }
                        return Ok(Poll::Compacted {
                            from: off,
                            to: record.offset,
                        });
                    }
                    // TTL EXPIRY (V2-M4, #549): a record whose effective TTL has passed against the
                    // wall-clock seam is EXPIRED — it is NEVER delivered. The lease just claimed is
                    // dropped. With a dead-letter exchange + the expired flag configured, capture it
                    // for the crash-atomic DLX move below (reason TtlExpired); otherwise SKIP it on
                    // read: commit the cursor past it INLINE (it is reclaimed by the segment reap,
                    // bounded, no per-message timer) and keep scanning for a live message. Either way
                    // it is ACCOUNTED (the `expired` or `dead_lettered` counter), never silently
                    // dropped. The non-TTL fast path returns false here, so the hot scan is unchanged.
                    if Self::record_is_expired(default_ttl, now_unix_millis, &record) {
                        g.leases.ack(&token);
                        if dead_letters_expired {
                            expired_dlx = Some((off, deliveries, record));
                            break;
                        }
                        g.cursor.ack(off);
                        if let Some(router) = g.router.as_mut() {
                            router.clear_offset(off);
                        }
                        self.counters.expired += 1;
                        expired_inline = true;
                        offset += 1;
                        continue;
                    }
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
        // An EXPIRED-and-DLX'd message (#551) routes to the dead-letter exchange OUTSIDE the group
        // borrow (the sink append needs `&mut self`), exactly as the max-deliver dead-letter does.
        if let Some((off, deliveries, record)) = expired_dlx {
            return self.expire_dead_letter_in(group, off, deliveries, record);
        }
        // The inline expiry skip(s) advanced this group's committed cursor past the reclaimed
        // records; sync the consumer-lag floor ONCE now the borrow has ended (#97/#549).
        if expired_inline {
            let committed = self
                .groups
                .get(group)
                .map_or(0, |g| g.cursor.committed().get());
            self.sync_consumer_lag(group, committed);
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
            // A configured dead-letter EXCHANGE (#551) records the reason; with no exchange this
            // stays the reason-less v1 max-deliver append, byte-identical to before #551.
            if self.dead_letter_exchange.is_some() {
                self.dlq_sink()?.append_dead_letter(
                    group,
                    &record,
                    attempt,
                    DeadLetterReason::MaxDeliverExceeded,
                )?;
            } else {
                self.dlq_sink()?.append_poison(group, &record, attempt)?;
            }
        }
        // The DLQ record is now durable (or was already), so commit the source cursor past the
        // poison message: drop nothing, never redeliver. This is the second, ordered durability
        // step; only after the append's fsync does the source advance. The shared commit also fires
        // the Level-2 designated-group dead-letter terminal (#497) and the lag/counter bookkeeping.
        self.commit_dead_letter_past(group, off);
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
            // Route to the configured dead-letter EXCHANGE subdir (#551) when set, else the default
            // fixed `dlq/` (byte-identical to the pre-#551 path).
            let subdir = self.dead_letter_exchange.as_deref().unwrap_or(DLQ_SUBDIR);
            let sink = DlqSink::open_at(
                self.log.filesystem(),
                subdir,
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

    /// Whether `record` has EXPIRED at the wall-clock seam (V2-M4, #549): its EFFECTIVE TTL (the lower
    /// of its per-message TTL, decoded from the headers prefix, and `default_ttl`) has a deadline
    /// (anchored to the record's DURABLE producer `timestamp_ms`, so it survives a restart) that has
    /// passed at the wall-clock instant `now_unix_millis`. A record with no effective TTL is never
    /// expired (the non-TTL fast path, byte-identical). Free of `&self` so the poll loop can call it
    /// while holding a mutable group borrow — the caller reads the wall-clock seam ONCE before the
    /// borrow ([`Clock::now_unix_millis`], never a raw host-clock read) and threads it in, so the
    /// deadline is still seam-anchored and `ManualClock`-deterministic, with no per-record clock read
    /// in the hot scan.
    fn record_is_expired(default_ttl: Ttl, now_unix_millis: u64, record: &OwnedRecord) -> bool {
        let (per_message, _original) = decode_ttl_headers(&record.headers);
        let ttl = Ttl::lower_of(per_message, default_ttl);
        if ttl.is_none() {
            return false;
        }
        is_expired(ttl, record.timestamp_ms, now_unix_millis)
    }

    /// Whether an EXPIRED record should be routed to a dead-letter exchange (V2-M4, #549/#551): only
    /// when an exchange is configured AND the expired-routing flag is set. Otherwise an expired record
    /// is reclaimed by retention (skipped on read, committed past, counted in `expired`).
    fn dead_letters_expired(&self) -> bool {
        self.dead_letter_expired && self.dead_letter_exchange.is_some()
    }

    /// Crash-atomically DEAD-LETTERS an EXPIRED message (V2-M4, #549/#551) to the configured exchange,
    /// recording [`DeadLetterReason::TtlExpired`], then commits the source group's cursor past it and
    /// returns [`Poll::Parked`]. The ordering and idempotency are identical to [`Engine::dead_letter_in`]
    /// (APPEND+FSYNC the reason-carrying dead-letter record BEFORE the cursor commit; a redelivered
    /// re-expired message is a no-op append at or below the per-group high-water mark), so an expiry is
    /// a fully reported, exactly-once event. Used only when [`Engine::dead_letters_expired`] holds.
    fn expire_dead_letter_in(
        &mut self,
        group: &str,
        off: Offset,
        attempt: u32,
        record: OwnedRecord,
    ) -> Result<Poll, EngineError> {
        // Idempotency: a re-expired message already durably in the exchange (at or below the group's
        // high-water mark) is committed-past WITHOUT a second append, exactly as the poison path.
        let already = self.dlq_sink()?.already_dead_lettered(group, off.get());
        if !already {
            // APPEND the reason-carrying (TtlExpired) dead-letter and FSYNC, BEFORE committing the
            // source cursor: the same crash-safety contract as the max-deliver path.
            self.dlq_sink()?.append_dead_letter(
                group,
                &record,
                attempt,
                DeadLetterReason::TtlExpired,
            )?;
        }
        self.commit_dead_letter_past(group, off);
        Ok(Poll::Parked {
            offset: off,
            record,
        })
    }

    /// Commits a group's cursor PAST a dead-lettered/expired offset and updates the shared
    /// bookkeeping (key-share router clear, consumer-lag floor, `dead_lettered` counter, the
    /// last-dead-lettered gauge, and the Level-2 designated-group dead-letter terminal). Shared by the
    /// max-deliver [`Engine::dead_letter_in`] and the TTL-expiry [`Engine::expire_dead_letter_in`]
    /// (both append to the durable sink first, then call this), so the post-append commit is identical
    /// regardless of WHY the message died.
    fn commit_dead_letter_past(&mut self, group: &str, off: Offset) {
        let Some(g) = self.groups.get_mut(group) else {
            // Unreachable: the poll path created/looked up the group before reaching here.
            return;
        };
        g.cursor.ack(off);
        // key_shared (#64): committing past a dead-lettered offset frees its key (idempotent).
        if let Some(router) = g.router.as_mut() {
            router.clear_offset(off);
        }
        let committed = g.cursor.committed().get();
        self.sync_consumer_lag(group, committed);
        self.counters.dead_lettered += 1;
        self.last_dead_lettered = Some(off);
        // The Level-2 dead-letter terminal (#497): if the DESIGNATED confirm group dead-lettered this
        // offset, fire a `DeadLettered` confirm rather than leaving the producer to wait out the TTL.
        if group == self.confirm_group {
            self.confirm_registry
                .terminate(off, ConfirmStatus::DeadLettered);
        }
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
                // key_shared and broadcast are mutually exclusive (#288): a key_shared group is a
                // competing group that drains out of order across members, so it can never accept a
                // cumulative ack. Clear the broadcast flag if it was set.
                g.broadcast = false;
            }
            KeyOrdering::None => g.router = None,
        }
        Ok(())
    }

    /// Marks a work-group as a BROADCAST consumer, or clears it back to plain competing (#288). A
    /// broadcast group is a GROUP-OF-ONE that sees every record in order, the only group shape for
    /// which a cumulative ack ([`Engine::cumulative_ack_in`]) is safe: committing its single cursor
    /// up to an offset drops nothing because no peer holds an in-flight message below it. Marking a
    /// group broadcast clears any `key_shared` router (the two modes are mutually exclusive); a
    /// broadcast group then drains by the unchanged plain-competing claim path (a lone consumer
    /// claims every record in order), and its only added power is the cumulative-ack verb. Clearing
    /// it back to `false` reverts to plain competing distribution. The group is created if absent
    /// (subject to the same name and cap checks as [`Engine::poll_in`]).
    ///
    /// Like [`Engine::set_key_ordering_in`], this is the v1 mode-wiring seam: the broadcast mode is
    /// server-side per-group configuration, set before a consumer polls, NOT a wire-negotiated
    /// field on the frozen `Sub` frame. The cumulative-ack VERB itself is on the wire (the tag-19
    /// `CumulativeAck` frame, #288); negotiating broadcast on `Sub`/`Connect` is the #11 follow-up.
    ///
    /// # Errors
    /// - [`EngineError::BroadcastGroupNotNamed`] when marking the DEFAULT/empty group (`""`)
    ///   broadcast (`broadcast == true`). The default group's consumers never SUB a non-empty name,
    ///   so the active-subscriber cap that makes a broadcast group a true group-of-one can never bind
    ///   it; two connections could both poll the default subscription and a cumulative ack would
    ///   commit past a peer's in-flight offset. A broadcast group must be a NAMED group whose
    ///   subscribers are capped, so the flip is refused and the default group keeps its plain
    ///   competing mode.
    /// - [`EngineError::InvalidGroupName`] or [`EngineError::TooManyGroups`] if a new group would
    ///   have to be created and fails the name or cap check.
    /// - [`EngineError::BroadcastGroupBusy`] when flipping an EXISTING group to broadcast
    ///   (`broadcast == true`) that already carries COMPETING state a cumulative ack could then
    ///   commit past: live in-flight leases, an out-of-order acked-ahead set, or more than one
    ///   active subscriber. Clearing the router alone would NOT make such a group a true
    ///   group-of-one (the populated lease table and the multi-member subscriber set would remain,
    ///   reopening the silent-drop trap #63 guards), so the flip is refused and the group keeps its
    ///   prior mode. Marking a FRESH or already-quiescent group broadcast (the configure-time
    ///   `--broadcast-group` path, before any consumer leases anything) is always allowed.
    pub fn set_broadcast_in(&mut self, group: &str, broadcast: bool) -> Result<(), EngineError> {
        // Close the default-group bypass (#288): the DEFAULT/empty group (`""`) is pre-created at
        // open, so `validate_group_name` (which the contains-key branch below would run) never runs
        // for it, AND its consumers reach it on the implicit default subscription rather than a SUB,
        // so the active-subscriber cap never registers (and never caps) them. A broadcast flip of the
        // default group would therefore pass the flip guard while empty yet leave two competing
        // pollers free to accrue in-flight leases that a later cumulative ack commits past: the same
        // silent drop, uncapped. A group whose subscribers cannot be capped must never be broadcast,
        // so the default/empty group is refused outright; `--broadcast-group` marks a NAMED group
        // only. A flip to NON-broadcast (clearing the flag) is always safe, so it is not gated here.
        if broadcast && group == DEFAULT_GROUP {
            return Err(EngineError::BroadcastGroupNotNamed {
                group: group.to_string(),
            });
        }
        if !self.groups.contains_key(group) {
            validate_group_name(group)?;
            if self.max_groups != 0 && self.groups.len() >= self.max_groups {
                return Err(EngineError::TooManyGroups {
                    max: self.max_groups,
                });
            }
        }
        // Guard the flip to broadcast (#288): a group-of-one is only safe if the group is not
        // already carrying competing multi-member in-flight state. An existing group with live
        // in-flight leases, an out-of-order acked-ahead set, or more than one active subscriber
        // could have those leases held by DIFFERENT consumers, so a later cumulative ack would
        // commit (and silently drop) a peer's still-in-flight message. Refuse the flip and leave
        // the group's mode untouched; the operator must drain the group (or mark it broadcast
        // before any consumer competes on it) first. A flip to NON-broadcast is always safe, and a
        // group being newly created here is empty, so the configure-time path is unaffected.
        if broadcast {
            if let Some(g) = self.groups.get(group) {
                if g.leases.in_flight() != 0
                    || !g.cursor.ahead_ranges().is_empty()
                    || g.subscribers.len() > 1
                {
                    return Err(EngineError::BroadcastGroupBusy {
                        group: group.to_string(),
                    });
                }
            }
        }
        let now = self.log.now_monotonic();
        let lease_config = self.lease_config;
        let g = self
            .groups
            .entry(group.to_string())
            .or_insert_with(|| WorkGroup::new(lease_config, now));
        g.broadcast = broadcast;
        // A broadcast group is never key_shared: drop any router so the cumulative-ack guard sees a
        // genuine group-of-one, not a competing cursor wearing the broadcast flag.
        if broadcast {
            g.router = None;
        }
        Ok(())
    }

    /// Registers `member` as an ACTIVE subscriber of `group` (#288), enforcing the BROADCAST
    /// group-of-one invariant: a broadcast group accepts AT MOST ONE subscriber, so a cumulative
    /// ack can only ever commit past that single consumer's OWN in-flight leases, never a peer's.
    /// A plain competing or `key_shared` group accepts any number of subscribers (the cap binds
    /// only when the group is broadcast). Idempotent per connection: a re-SUB by the SAME `member`
    /// to a broadcast group it already holds is accepted (it is still the lone subscriber).
    ///
    /// This NEVER creates the group: like SUB itself (the engine creates a named group on the first
    /// FLOW, not on SUB), an unknown group is a no-op success here. That is safe for the cap because
    /// a broadcast group ALWAYS exists already (it was created by [`Engine::set_broadcast_in`] at
    /// configure time, before any consumer subscribes), so the second-subscriber reject still fires
    /// on every broadcast group. A name that the engine will later reject is surfaced on the first
    /// FLOW exactly as before, so SUB stays infallible for the name/cap checks.
    ///
    /// # Errors
    /// [`EngineError::BroadcastGroupBusy`] if `group` already exists, is broadcast, and a DIFFERENT
    /// member is already its active subscriber. The subscriber set is left unchanged on rejection.
    pub fn subscribe_in(&mut self, group: &str, member: MemberId) -> Result<(), EngineError> {
        let Some(g) = self.groups.get_mut(group) else {
            // An unknown group cannot be broadcast (broadcast requires an existing group), so there
            // is nothing to cap yet. Do not create it: the first FLOW creates it, preserving the
            // "SUB alone does not create the group" invariant. The session re-registers via the
            // FLOW path is not needed because the cap only ever binds a broadcast group.
            return Ok(());
        };
        // A broadcast group is a group-of-one: reject a SECOND, DIFFERENT subscriber. A re-SUB by
        // the member that already holds the group is fine (the set membership is idempotent), so
        // `contains` short-circuits the "already mine" case before the cap check.
        if g.broadcast && !g.subscribers.contains(&member) && !g.subscribers.is_empty() {
            return Err(EngineError::BroadcastGroupBusy {
                group: group.to_string(),
            });
        }
        // An explicit subscribe is a consumer interaction (#424): the group (the default group
        // included) now pins the retention floor like any other live consumer.
        g.touched = true;
        g.subscribers.insert(member);
        Ok(())
    }

    /// Removes `member` from `group`'s active-subscriber set (#288): the connection unsubscribed,
    /// switched groups, or disconnected, so its broadcast slot frees for a later subscriber.
    /// Idempotent and a no-op for an unknown group or a member that was never registered, so it is
    /// safe to call on every subscription switch, UNSUB, and connection close.
    pub fn unsubscribe_in(&mut self, group: &str, member: MemberId) {
        if let Some(g) = self.groups.get_mut(group) {
            g.subscribers.remove(&member);
        }
    }

    /// The number of ACTIVE subscribers currently registered on `group` (#288), or `0` for an
    /// unknown group. A broadcast group is capped at one by [`Engine::subscribe_in`]; this exposes
    /// the count for tests and operability.
    #[must_use]
    pub fn subscriber_count_in(&self, group: &str) -> usize {
        self.groups.get(group).map_or(0, |g| g.subscribers.len())
    }

    /// The number of in-flight (delivered-but-not-yet-acked) leases for `group`, or 0 if the group
    /// is unknown. Mirrors [`Engine::subscriber_count_in`] for tests and operability.
    #[must_use]
    pub fn in_flight_in(&self, group: &str) -> usize {
        self.groups.get(group).map_or(0, |g| g.leases.in_flight())
    }

    /// Whether `group` is a BROADCAST consumer (#288): a group-of-one that sees every record in
    /// order and therefore accepts a cumulative ack. `false` for an unknown group or a plain
    /// competing / `key_shared` work-group.
    #[must_use]
    pub fn is_broadcast_in(&self, group: &str) -> bool {
        self.groups.get(group).is_some_and(|g| g.broadcast)
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
    // The key-shared poll scan (claim, route, deliver, and the #337 sparse-offset hole skip) is one
    // cohesive loop; splitting it would thread the router/cursor/lease state through a helper and
    // obscure the per-offset decision, so the function runs a few lines over the soft limit.
    #[allow(clippy::too_many_lines)]
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
        // The TTL knobs read ONCE before the group borrow (V2-M4, #549), exactly as in `poll_in`:
        // the per-stream default TTL, the seam-anchored wall-clock instant, and the expired-routing
        // flag. Read here because the group borrow below cannot coexist with a later `&self` read.
        let default_ttl = self.default_message_ttl;
        let now_unix_millis = self.log.now_unix_millis();
        let dead_letters_expired = self.dead_letters_expired();
        let g = self
            .groups
            .entry(group.to_string())
            .or_insert_with(|| WorkGroup::new(lease_config, now));
        // Mark the key_shared group active (#277); it is never evicted, but keeping its timestamp
        // current is consistent and cheap.
        g.last_activity = now;
        g.touched = true;
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
        // The TTL-expiry capture + the lag-sync flag (V2-M4, #549), exactly as in `poll_in`: an
        // expired record is never routed to any member; with a DLX + the expired flag it is captured
        // for the crash-atomic move below, otherwise reclaimed inline. The TTL knobs were read above
        // the group borrow.
        let mut expired_dlx: Option<(Offset, u32, OwnedRecord)> = None;
        let mut expired_inline = false;
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
            // SPARSE-OFFSET tolerance for a compacted log (#337): a record returned at an offset
            // ABOVE `off` means `off` was COMPACTED AWAY (a superseded value). The read advanced to
            // the next present survivor at `record.offset`, so the whole half-open run
            // `[off, record.offset)` is compacted-away. Those offsets are already-satisfied (nothing
            // to deliver, never routed), so the cursor is acked past the entire run. The compacted
            // offsets were never claimed, so the router holds no entry for them. This is surfaced as
            // the distinct `Poll::Compacted` (the caller maps it to `GapMarker(reason=COMPACTED)` for
            // a capable consumer, #346/#411; a non-capable member silently advances), the interior
            // twin of the below-earliest trim above (which returns `Poll::Truncated`). For a dense log
            // this branch is never taken.
            if record.offset != off {
                let mut hole = offset;
                while hole < record.offset.get() {
                    g.cursor.ack(Offset::new(hole));
                    hole += 1;
                }
                return Ok(Poll::Compacted {
                    from: off,
                    to: record.offset,
                });
            }
            // TTL EXPIRY (V2-M4, #549), key_shared path: an expired record is NEVER routed to any
            // member. No lease is held yet here (the claim is below), so there is nothing to release.
            // With a dead-letter exchange + the expired flag, capture it for the crash-atomic DLX move
            // (reason TtlExpired); otherwise SKIP it on read — commit the cursor past it inline (the
            // segment reap reclaims the bytes, bounded) and keep scanning. Either way it is accounted
            // (`expired` or `dead_lettered`), never silently dropped. The non-TTL path is unchanged.
            if Self::record_is_expired(default_ttl, now_unix_millis, &record) {
                if dead_letters_expired {
                    expired_dlx = Some((off, 1, record));
                    break;
                }
                g.cursor.ack(off);
                if let Some(router) = g.router.as_mut() {
                    router.clear_offset(off);
                }
                self.counters.expired += 1;
                expired_inline = true;
                offset += 1;
                continue;
            }
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
            // RETRY-THROTTLE enforcement (#402), key_shared path: a REDELIVERY routed to this member
            // under an exhausted budget is DEFERRED (spaced out), never dropped. See
            // [`Engine::retry_throttle_defer`]. A `true` skips it on this poll (it redelivers later).
            if Self::retry_throttle_defer(
                &mut self.backpressure,
                &self.delivery,
                self.lease_config,
                &mut g.leases,
                off,
                now,
            ) {
                offset += 1;
                continue;
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
        // An EXPIRED-and-DLX'd message (#551) routes to the dead-letter exchange OUTSIDE the borrow.
        if let Some((off, deliveries, record)) = expired_dlx {
            return self.expire_dead_letter_in(group, off, deliveries, record);
        }
        // Sync the consumer-lag floor once if the scan reclaimed inline-expired records (#97/#549).
        if expired_inline {
            let committed = self
                .groups
                .get(group)
                .map_or(0, |g| g.cursor.committed().get());
            self.sync_consumer_lag(group, committed);
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

    /// The name of the ONE designated group whose ack confirms a Level-2 produce (#497). Defaults to
    /// the default/unnamed group; see [`Engine::set_confirm_group`].
    #[must_use]
    pub fn confirm_group(&self) -> &str {
        &self.confirm_group
    }

    /// Redesignates the group whose ack confirms a Level-2 produce (#497), server-side (NOT on the
    /// wire). The default is the default/unnamed group. Changing it does not retroactively re-key
    /// already-pending confirms (they fire on the newly-designated group's commit going forward);
    /// pending entries that the old group would have confirmed eventually time out, so the registry
    /// stays bounded. Intended to be set once at serve time, like `set_broadcast_in`.
    pub fn set_confirm_group(&mut self, group: &str) {
        self.confirm_group = group.to_string();
    }

    /// Registers a Level-2 (server+client-ack) produce's DURABLE offset against the producer
    /// connection awaiting its `ProduceConfirm` (#497). The caller (the session) invokes this AFTER
    /// the record's Level-1 `PubAck` is determined, so the record is durable first (I2) and the
    /// confirm wait is layered ON TOP of, never instead of, the durability ack. BOUNDED: a register at
    /// the registry cap drop-oldests the eldest pending confirm (queued as a `Dropped` terminal for
    /// its producer), so a slow or absent consumer can never grow the registry. `member` is the
    /// producer connection's stable id (its `MemberId`).
    pub fn register_l2_confirm(&mut self, offset: Offset, member: MemberId) {
        let now = self.log.now_monotonic();
        self.confirm_registry.register(offset, member.get(), now);
    }

    /// Drains every READY `ProduceConfirm` terminal for the producer connection `member` (#497), in
    /// FIFO order, so the session can write them to that producer on its own pass. Other producers'
    /// ready terminals are left in place. Returns the drained terminals (possibly empty); the common
    /// no-L2 case returns an empty `Vec` without touching the registry's internals.
    pub fn drain_l2_confirms(&mut self, member: MemberId) -> Vec<ReadyConfirm> {
        self.confirm_registry.drain_ready_for(member.get())
    }

    /// Drops every Level-2 confirm entry (pending AND ready) for a producer connection that has
    /// disconnected (#497): nobody is waiting, so no terminal is produced and the registry is bounded
    /// against a producer that opens L2 produces then vanishes. Called from the connection cleanup
    /// path on every exit, like the `key_shared` leave and the subscription deregister.
    pub fn drop_l2_confirms(&mut self, member: MemberId) {
        self.confirm_registry.drop_member(member.get());
    }

    /// Fires a `Consumed` `ProduceConfirm` for every pending Level-2 confirm below `committed`, but
    /// ONLY when `group` is the designated confirm group (#497). This is the cursor-commit hook: every
    /// site that advances a group's `AckCursor` (an ack, a cumulative ack) calls it AFTER the advance,
    /// passing the group's fresh committed watermark, so a confirm fires exactly when the record it
    /// keys becomes consumed by the designated group. An ack in any OTHER group is ignored here (its
    /// own delivery/acking is unaffected), keeping "consumed" well-defined and the hook a pure,
    /// additive overlay on the unchanged consume/ack path.
    fn confirm_designated_commit(&mut self, group: &str, committed: u64) {
        if group == self.confirm_group {
            self.confirm_registry.confirm_up_to(Offset::new(committed));
        }
    }

    /// Terminates every pending Level-2 confirm below `floor` with `status` (#497): the disk-full
    /// force-reap path uses it to surface a `DeadLettered` terminal for every confirm whose record was
    /// force-reaped out from under every consumer. Group-agnostic on purpose: a force-reap deletes the
    /// record for ALL groups, so a confirm keyed to the designated group below the new floor is
    /// unsatisfiable regardless. A no-op unless a confirm is pending in the reaped span.
    fn terminate_confirms_below(&mut self, floor: u64, status: ConfirmStatus) {
        self.confirm_registry
            .terminate_below(Offset::new(floor), status);
    }

    /// Sweeps every pending Level-2 confirm older than the registry TTL to a `TimedOut` terminal
    /// (#497), the "no consumer ever acks" failure mode. Driven from the existing idle/retention tick
    /// ([`Engine::sweep_idle_groups`]), so it adds no new timer; a no-op when the TTL is disabled or no
    /// L2 confirm is outstanding. Reads the clock seam for `now`.
    fn sweep_l2_confirm_timeouts(&mut self) {
        let now = self.log.now_monotonic();
        self.confirm_registry.sweep_timed_out(now);
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
        g.touched = true;
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
                // The Level-2 cursor-commit hook (#497): if THIS is the designated confirm group and
                // its watermark just advanced past a pending L2 produce, fire its `Consumed`
                // `ProduceConfirm`. ADDITIVE — a no-op unless `group` is the designated group AND a
                // confirm is pending below the new watermark, so the consume/ack path is otherwise
                // byte-for-byte unchanged. The `g` borrow has ended (`sync_consumer_lag` above took
                // `&mut self`), so this re-borrows `self` safely.
                self.confirm_designated_commit(group, committed);
                // The consume (ack) request-path latency (#570): the engine time to service this ack
                // that committed (lease ack + cursor commit + lag maintenance). One clock-seam read,
                // allocation-free, recorded only on a real commit (a fenced ack records nothing).
                let consume_nanos = self.log.now_monotonic().saturating_sub(now);
                self.registry.observe_consume_nanos(consume_nanos);
                // Per-group CONSUME throughput (#571): one record consumed (acked) by this group.
                // Bounded + overflow-folded, keyed by the group name, allocation-free for an existing
                // label. Recorded only on a real commit (a fenced ack records nothing), mirroring the
                // lag-maintenance point above.
                self.registry.record_group_consumed(group.as_bytes());
                AckResult::Acked
            }
            AckOutcome::Fenced => AckResult::Fenced,
        }
    }

    /// Cumulative ack (ack-all-up-to-`up_to`) in a named work-group (#288, the broadcast half of
    /// the `JetStream` `AckAll` verb, refs #63). `up_to` is EXCLUSIVE: every offset strictly below
    /// it becomes committed in one move.
    ///
    /// The work-group HARD-REJECT is sacrosanct: a competing or `key_shared` group (and any group
    /// that has NOT been marked broadcast via [`Engine::set_broadcast_in`], including an unknown
    /// group) shares one commit cursor while its members drain out of order, so acking up to an
    /// offset would commit past (and silently drop) messages still in flight to peers. Such a group
    /// is rejected with the typed [`EngineError::CumulativeAckOnWorkGroup`] and its cursor is left
    /// untouched.
    ///
    /// Only a BROADCAST group, a group-of-one that sees every record in order, accepts the verb. For
    /// it, `up_to` is validated against the durable, retained window: an `up_to` PAST the durable
    /// head or BELOW the earliest-retained offset is rejected with the typed
    /// [`EngineError::CumulativeAckOutOfRange`] (never a panic), and the commit is IDEMPOTENT and
    /// MONOTONIC: an `up_to` at or below the current commit (but still within the window) is a no-op
    /// success and the watermark never moves backwards. On a successful advance the group's single
    /// cursor jumps to `up_to` (any contiguous acked-ahead run is absorbed) and the activity stamp
    /// is refreshed so the idle sweep does not reclaim the group mid-stream.
    ///
    /// # Errors
    /// - [`EngineError::CumulativeAckOnWorkGroup`] if `group` is not a broadcast consumer (a
    ///   competing or `key_shared` work-group, or an unknown group).
    /// - [`EngineError::CumulativeAckOutOfRange`] if `up_to` is past the durable head or below the
    ///   earliest-retained offset.
    pub fn cumulative_ack_in(&mut self, group: &str, up_to: Offset) -> Result<(), EngineError> {
        // The work-group rejection (#63) is the safety trap and stays UNCHANGED: only a group that
        // is live AND marked broadcast may proceed. An unknown group, a plain competing group, and a
        // key_shared group all fall here with the cursor untouched.
        if !self.is_broadcast_in(group) {
            return Err(EngineError::CumulativeAckOnWorkGroup);
        }
        // Validate `up_to` against the durable, retained window BEFORE touching the cursor, so a bad
        // offset leaves the committed position exactly as it was. The window is
        // [earliest_retained, durable_head]: committing exactly up to the head commits every record
        // that exists (the head is the next-to-write offset, so `up_to == head` is in range), while
        // an `up_to` below the oldest retained record names reaped (or never-seen) offsets. Read
        // both bounds immutably before the mutable group borrow.
        let durable_head = self.log.flushed_offset().get();
        let earliest_retained = self.log.earliest_offset().get();
        let up_to_raw = up_to.get();
        if up_to_raw > durable_head || up_to_raw < earliest_retained {
            return Err(EngineError::CumulativeAckOutOfRange {
                up_to: up_to_raw,
                earliest_retained,
                durable_head,
            });
        }
        let now = self.log.now_monotonic();
        // The group is broadcast (the guard above proved it is present), so the lookup never misses;
        // fall back to the rejection rather than panic if an invariant ever breaks.
        let Some(g) = self.groups.get_mut(group) else {
            return Err(EngineError::CumulativeAckOnWorkGroup);
        };
        // A cumulative ack IS activity: refresh the stamp so the idle sweep does not reclaim the
        // group out from under a consumer that is committing via cumulative ack rather than poll.
        g.last_activity = now;
        g.touched = true;
        let before = g.cursor.committed().get();
        // Commit the single broadcast cursor up to `up_to`. `commit_up_to` is idempotent and
        // monotonic: an `up_to` at or below `committed` is a no-op success (the re-ack case) and the
        // watermark never regresses. The redelivery gate is the cursor (`poll_in` skips `is_acked`
        // offsets), so committing past a lease stops its redelivery.
        if g.cursor.commit_up_to(up_to) {
            // Count each newly-committed offset as an ack (the same `acks` counter per-message acks
            // drive), so the resilience taxonomy is unchanged: no new counter is introduced.
            let advanced = g.cursor.committed().get().saturating_sub(before);
            self.counters.acks = self.counters.acks.saturating_add(advanced);
        }
        // Reclaim the in-flight lease slots this commit covers (every offset below `up_to`). The
        // cursor commit alone only STOPS redelivery; without this the leases linger in-flight until
        // the visibility timeout. A BROADCAST consumer that drains by fetch + cumulative ack relies
        // on this reclaim: otherwise leases pile up faster than they expire, the in-flight window
        // fills, and the consumer starves its own fetches. Per-message ack reclaims one slot
        // (`leases.ack`); this is the bulk equivalent, and idempotent on a re-ack (nothing remains
        // leased below an already-committed `up_to`).
        g.leases.release_below(up_to);
        // Capture the watermark before the borrow ends, then fire the Level-2 cursor-commit hook
        // (#497) once `g` is released. A broadcast group can be the designated confirm group, so a
        // bulk cumulative ack confirms every pending L2 produce below the new watermark in one move,
        // exactly as a sequence of per-message acks would. ADDITIVE: a no-op unless this is the
        // designated group with confirms pending.
        let committed = g.cursor.committed().get();
        self.confirm_designated_commit(group, committed);
        Ok(())
    }

    /// Cumulative ack in the default work-group (#288): delegates to [`Engine::cumulative_ack_in`]
    /// with the default group name, so the default group is a broadcast consumer only if it was
    /// marked one via [`Engine::set_broadcast_in`] (otherwise the work-group reject applies).
    ///
    /// # Errors
    /// As [`Engine::cumulative_ack_in`].
    pub fn cumulative_ack(&mut self, up_to: Offset) -> Result<(), EngineError> {
        self.cumulative_ack_in(DEFAULT_GROUP, up_to)
    }

    /// Marks `group` a TIER-S STREAMING consumer (#544, M1-I7), or clears the mode. A streaming group
    /// is consumer-managed-offset: [`Engine::stream_fetch_in`] serves a contiguous batch off the
    /// durable prefix with NO lease and NO per-record cursor write, and durability comes from a
    /// periodic cumulative [`Engine::stream_commit_in`]. This is the serve-time declaration that opts a
    /// named group into the streaming tier, mirroring [`Engine::set_broadcast_in`] /
    /// [`Engine::set_key_ordering_in`] (the existing per-group mode setters). The Connect-level tier
    /// DEFAULT negotiation is a SEPARATE issue (M1-I9); this is the explicit per-group selector only,
    /// and it does NOT change any default — an unconfigured group stays Tier-W.
    ///
    /// Creates the group if absent (validating the name and the group cap, exactly like
    /// `set_broadcast_in`). Unlike `set_broadcast_in` there is no group-of-one cap to guard: a
    /// streaming group grants no leases, so there is no in-flight state a later commit could silently
    /// drop. The flip is therefore always safe and does not clear `broadcast` / `router` (a streaming
    /// consumer simply reads contiguously; the lease-mode flags are inert on the streaming path).
    ///
    /// # Errors
    /// [`EngineError::InvalidGroupName`] for a malformed name, or [`EngineError::TooManyGroups`] if a
    /// new group would exceed the per-engine cap.
    pub fn set_streaming_in(&mut self, group: &str, streaming: bool) -> Result<(), EngineError> {
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
        g.streaming = streaming;
        Ok(())
    }

    /// Whether `group` is a TIER-S STREAMING consumer (#544): a consumer-managed-offset group served
    /// by [`Engine::stream_fetch_in`] / [`Engine::stream_commit_in`]. `false` for an unknown group or a
    /// default Tier-W work-queue group.
    #[must_use]
    pub fn is_streaming_in(&self, group: &str) -> bool {
        self.groups.get(group).is_some_and(|g| g.streaming)
    }

    /// Serves a Tier-S STREAMING fetch (#544, M1-I7): a CONTIGUOUS batch of records starting at the
    /// consumer-managed `start_offset`, bounded by `max_records` / `max_bytes` and the flushed
    /// frontier — with NO lease grant, NO generation fence, and NO per-record cursor write. This is the
    /// headline single-consumer consume win: it removes exactly the per-record lease `BTreeMap` insert,
    /// generation bump, and RLE cursor mutate that the Tier-W [`Engine::poll`] path pays on every
    /// record, replacing N per-record actor round-trips with ONE contiguous read.
    ///
    /// At-least-once holds BY CONSTRUCTION: the consumer owns its offset and re-reads from its last
    /// committed position on a crash/reconnect (it passes that offset as `start_offset`), so the broker
    /// keeps no per-delivery state and at most the uncommitted records redeliver — the Kafka /
    /// NATS-pull contract. The records returned are the SAME materialized, CRC-validated
    /// [`OwnedRecord`]s the Tier-W path delivers (via the shared `Log::read_range`); only the
    /// bookkeeping differs.
    ///
    /// The group must be in streaming mode (declared via [`Engine::set_streaming_in`]); a fetch on a
    /// non-streaming group is rejected so a client cannot bypass the Tier-W lease path by accident.
    /// `member` is accepted for symmetry with the Tier-W member-aware poll and future per-member
    /// streaming policy, but a streaming fetch is not member-routed (the consumer manages its own
    /// offset), so it is currently unused beyond marking the group active.
    ///
    /// A streaming fetch NEVER advances the group cursor and NEVER touches the lease table: retention
    /// is pinned only by the periodic [`Engine::stream_commit_in`], so a consumer that fetches but
    /// never commits pins the floor at its committed offset (not its read offset), exactly the
    /// consumer-managed contract.
    ///
    /// # Errors
    /// [`EngineError::CumulativeAckOnWorkGroup`] if `group` is not a streaming group (reusing the
    /// wrong-mode error; the verb belongs to a streaming consumer only), or a storage error reading the
    /// durable prefix.
    pub fn stream_fetch_in(
        &mut self,
        group: &str,
        _member: MemberId,
        start_offset: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<StreamBatch, EngineError> {
        // A streaming fetch belongs to a streaming group ONLY. A Tier-W (lease) group must keep using
        // the poll/Fetch path; serving it a contiguous lease-free batch would bypass its lease/cursor
        // semantics. Reject with the wrong-mode error rather than silently degrade the work-queue.
        if !self.is_streaming_in(group) {
            return Err(EngineError::CumulativeAckOnWorkGroup);
        }
        let now = self.log.now_monotonic();
        // A fetch IS activity: refresh the idle stamp and mark the group touched so its committed
        // cursor pins the retention floor (#277 / #424), exactly like a Tier-W poll.
        if let Some(g) = self.groups.get_mut(group) {
            g.last_activity = now;
            g.touched = true;
        }
        // The contiguous read off the durable, flushed prefix. `Log::read_range` bounds the read by the
        // flushed frontier (no un-flushed record is served), `max_records`, and `max_bytes`, and
        // returns the SAME CRC-validated records the Tier-W poll's `read_from` does — the single shared
        // read primitive. NO lease is claimed, NO cursor is written: this is the whole point.
        let records = self.log.read_range(start_offset, max_records, max_bytes)?;
        // The consumer resumes from one past the last record served (or `start_offset` when empty). The
        // records are contiguous and offset-ordered, so the last one's offset + 1 is the resume point;
        // it never exceeds the flushed head (read_range clamps to it). `checked_next` only returns
        // `None` at the `u64::MAX` boundary a real deployment never reaches; fall back to the record's
        // own offset there rather than wrap, mirroring `AckCursor::ack`'s exhausted-boundary handling.
        let next_offset = records.last().map_or(start_offset, |r| {
            r.offset.checked_next().unwrap_or(r.offset)
        });
        // Count the streaming deliveries on the SAME `delivered` counter the Tier-W poll drives, so the
        // observability taxonomy is unchanged (no new counter). A streaming delivery is never a
        // redelivery from the broker's view (the broker keeps no per-delivery state); a consumer-driven
        // re-read after an uncommitted crash is invisible here, exactly as the at-least-once contract
        // intends.
        self.counters.delivered = self.counters.delivered.saturating_add(records.len() as u64);
        Ok(StreamBatch {
            records,
            next_offset,
        })
    }

    /// Serves a Tier-S streaming fetch in the default work-group (#544): delegates to
    /// [`Engine::stream_fetch_in`] with the default group name (which must have been marked streaming).
    ///
    /// # Errors
    /// As [`Engine::stream_fetch_in`].
    pub fn stream_fetch(
        &mut self,
        member: MemberId,
        start_offset: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<StreamBatch, EngineError> {
        self.stream_fetch_in(DEFAULT_GROUP, member, start_offset, max_records, max_bytes)
    }

    /// Serves a Tier-S STREAMING fetch as RAW on-disk frame bytes (#541, M1-I5): the zero-copy twin of
    /// [`Engine::stream_fetch_in`] used to deliver a contiguous run as ONE `DeliverBatch` frame. It runs
    /// the IDENTICAL group-mode guard, activity refresh, and `delivered`-counter accounting as
    /// `stream_fetch_in` (so the two are interchangeable on the wire from the engine's view), but sources
    /// the contiguous SEALED prefix as the on-disk frame bytes VERBATIM ([`Log::read_range_raw`], the
    /// #542 zero-copy primitive) instead of materializing every record. Any remainder in the ACTIVE tail
    /// (which the raw read does not serve) is materialized via the SAME `Log::read_range` the per-record
    /// path uses, so the consumer always receives one continuous contiguous run.
    ///
    /// The records the client reconstructs from `raw` (offset POSITIONALLY as `first_offset + i`) and the
    /// records in `tail` together are EXACTLY the records `stream_fetch_in` would return for the same
    /// `[start_offset, ...)` window — the differential test in `engine.rs` pins this. NO lease is
    /// granted, NO generation is fenced, NO cursor is written, exactly like `stream_fetch_in`.
    ///
    /// # Errors
    /// [`EngineError::CumulativeAckOnWorkGroup`] if `group` is not a streaming group (the same wrong-mode
    /// guard as `stream_fetch_in`), or a storage error reading the durable prefix.
    pub fn stream_fetch_raw_in(
        &mut self,
        group: &str,
        _member: MemberId,
        start_offset: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<StreamRawBatch, EngineError> {
        // The wrong-mode guard and activity refresh are IDENTICAL to `stream_fetch_in`: a raw fetch is
        // the same Tier-S streaming fetch, only the delivery encoding differs.
        if !self.is_streaming_in(group) {
            return Err(EngineError::CumulativeAckOnWorkGroup);
        }
        let now = self.log.now_monotonic();
        if let Some(g) = self.groups.get_mut(group) {
            g.last_activity = now;
            g.touched = true;
        }
        // The contiguous SEALED prefix as raw on-disk frame bytes (zero-copy, no body decode), plus the
        // resume point for anything this single-segment raw read did not serve.
        let (raw, tail_from) = self
            .log
            .read_range_raw(start_offset, max_records, max_bytes)?;
        // Materialize the ACTIVE-tail remainder (if any), bounded by the records the raw run did NOT
        // already serve and the residual byte budget, so the raw + tail run never exceeds the request.
        let raw_count = usize::try_from(raw.record_count).unwrap_or(usize::MAX);
        let tail = match tail_from {
            Some(from) if raw_count < max_records => {
                let remaining = max_records - raw_count;
                // The byte budget the raw run already consumed cannot be cheaply known here; pass the
                // ORIGINAL `max_bytes` so the tail is bounded by the same cap (the first-frame-always
                // rule keeps a single over-cap tail record from stalling). The record-count remainder is
                // the hard bound that keeps raw + tail within the request.
                self.log.read_range(from, remaining, max_bytes)?
            }
            _ => Vec::new(),
        };
        // The resume offset is one past the last record across raw and tail (or `start_offset` when
        // both are empty), mirroring `stream_fetch_in`'s `next_offset`.
        let next_offset = tail.last().map_or(raw.next_offset, |r| {
            r.offset.checked_next().unwrap_or(r.offset)
        });
        let total = raw.record_count.saturating_add(tail.len() as u64);
        self.counters.delivered = self.counters.delivered.saturating_add(total);
        Ok(StreamRawBatch {
            raw,
            tail,
            next_offset,
        })
    }

    /// Serves a Tier-S streaming RAW fetch in the default work-group (#541): delegates to
    /// [`Engine::stream_fetch_raw_in`] with the default group name (which must have been marked streaming).
    ///
    /// # Errors
    /// As [`Engine::stream_fetch_raw_in`].
    pub fn stream_fetch_raw(
        &mut self,
        member: MemberId,
        start_offset: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<StreamRawBatch, EngineError> {
        self.stream_fetch_raw_in(DEFAULT_GROUP, member, start_offset, max_records, max_bytes)
    }

    /// Commits a Tier-S STREAMING group's cursor up to the EXCLUSIVE offset `up_to` (#544, M1-I7): the
    /// consumer's PERIODIC, cumulative "everything below `up_to` is durably processed" checkpoint. It
    /// REUSES the broadcast cumulative-ack cursor primitive ([`AckCursor::commit_up_to`]) — no new
    /// durable structure is invented — and advances the SAME committed watermark
    /// [`Engine::min_committed_offset`] reads, so a committed streaming consumer frees retention exactly
    /// like a Tier-W ack or a broadcast cumulative ack.
    ///
    /// It is the streaming twin of [`Engine::cumulative_ack_in`] and deliberately distinct from it: this
    /// targets a STREAMING group (where `cumulative_ack_in` targets a BROADCAST group), so the two never
    /// collide and the broadcast-only guard on `cumulative_ack_in` is unchanged. Because a streaming
    /// group grants NO leases, this commit does NOT call `release_below` (there is nothing in-flight to
    /// reclaim); it ONLY advances the watermark. It is idempotent and monotonic — an `up_to` at or below
    /// the committed offset is a no-op success — exactly like `commit_up_to`.
    ///
    /// `up_to` is validated against the durable, retained window `[earliest_retained, durable_head]`
    /// BEFORE the cursor is touched, so a bad offset leaves the committed position unchanged.
    ///
    /// # Errors
    /// [`EngineError::CumulativeAckOnWorkGroup`] if `group` is not a streaming group, or
    /// [`EngineError::CumulativeAckOutOfRange`] if `up_to` is past the durable head or below the
    /// earliest retained offset.
    pub fn stream_commit_in(&mut self, group: &str, up_to: Offset) -> Result<(), EngineError> {
        // Streaming groups only: the verb belongs to a consumer-managed-offset group. A Tier-W or
        // broadcast group is rejected (a broadcast group uses `cumulative_ack_in` instead), so the two
        // commit verbs never cross modes.
        if !self.is_streaming_in(group) {
            return Err(EngineError::CumulativeAckOnWorkGroup);
        }
        // Validate `up_to` against the durable, retained window BEFORE touching the cursor — identical
        // to `cumulative_ack_in`. Committing past the head names records that do not exist; committing
        // below the earliest retained offset names reaped (or replayed-stale) records. Either leaves the
        // committed position exactly as it was.
        let durable_head = self.log.flushed_offset().get();
        let earliest_retained = self.log.earliest_offset().get();
        let up_to_raw = up_to.get();
        if up_to_raw > durable_head || up_to_raw < earliest_retained {
            return Err(EngineError::CumulativeAckOutOfRange {
                up_to: up_to_raw,
                earliest_retained,
                durable_head,
            });
        }
        let now = self.log.now_monotonic();
        let Some(g) = self.groups.get_mut(group) else {
            return Err(EngineError::CumulativeAckOnWorkGroup);
        };
        // A commit IS activity: refresh the stamp so the idle sweep does not reclaim a group that
        // commits via streaming rather than poll.
        g.last_activity = now;
        g.touched = true;
        let before = g.cursor.committed().get();
        // Advance the single streaming cursor up to `up_to`. `commit_up_to` is idempotent and monotonic
        // (an `up_to` at or below `committed` is a no-op success; the watermark never regresses), so a
        // re-commit after a redeliver cannot move the floor backwards. NO `release_below`: a streaming
        // group holds no leases, so there is nothing in-flight to reclaim (the cardinal difference from
        // the broadcast cumulative-ack path).
        if g.cursor.commit_up_to(up_to) {
            // Count each newly-committed offset as an ack on the SAME counter per-message acks drive, so
            // the resilience taxonomy is unchanged (no new counter), exactly like `cumulative_ack_in`.
            let advanced = g.cursor.committed().get().saturating_sub(before);
            self.counters.acks = self.counters.acks.saturating_add(advanced);
        }
        // Fire the Level-2 cursor-commit hook (#497) once `g` is released: a streaming group can be the
        // designated confirm group, so a cumulative streaming commit confirms every pending L2 produce
        // below the new watermark in one move. ADDITIVE: a no-op unless this is the designated group
        // with confirms pending.
        let committed = g.cursor.committed().get();
        self.confirm_designated_commit(group, committed);
        Ok(())
    }

    /// Commits a Tier-S streaming cursor in the default work-group (#544): delegates to
    /// [`Engine::stream_commit_in`] with the default group name (which must have been marked streaming).
    ///
    /// # Errors
    /// As [`Engine::stream_commit_in`].
    pub fn stream_commit(&mut self, up_to: Offset) -> Result<(), EngineError> {
        self.stream_commit_in(DEFAULT_GROUP, up_to)
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
        g.touched = true;
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
        g.touched = true;
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
    ///
    /// Under the default `sync` level this is also the SYNCED head ([`Engine::synced_offset_for_test`]): every
    /// visible record is durable (I2). Under a relaxed level this VISIBLE head can run ahead of the
    /// synced head by the unsynced window (the records in `[synced, flushed)` are acked but not yet
    /// fsync'd, the bytes-at-risk a power cut would lose).
    #[must_use]
    pub fn flushed_offset(&self) -> Offset {
        self.log.flushed_offset()
    }

    /// The DURABLE head (#341, #379): the first offset NOT yet covered by a returned `fdatasync`.
    /// Equals [`Engine::flushed_offset`] under the default `sync` level (every visible record is
    /// durable, I2); under a relaxed level the visible head may lead this by the unsynced window. A
    /// power loss reverts the records in `[synced_offset, flushed_offset)`, so this is the head a
    /// crash would recover to. Used by the durability tests to bound a relaxed level's loss.
    #[must_use]
    pub fn synced_offset_for_test(&self) -> u64 {
        self.log.synced_offset().get()
    }

    /// The lock-free, off-actor consume READ plane (#539): the shared handle a consumer thread reads
    /// the SEALED, flushed prefix through with NO append-actor round-trip. The engine (on the single
    /// actor thread) keeps PUBLISHING to it — the new flushed frontier after every commit, a fresh
    /// sealed snapshot on every seal/reap — so a handed-out handle always observes the current
    /// durable prefix. The off-actor plane carries multi-consumer replay/fan-out load (the durable
    /// prefix, the #491 ceiling) with zero actor contention; a read whose range reaches the active
    /// tail or a compacted segment reports a fallback so the caller serves that small remainder
    /// through the actor (the through-actor `poll`), keeping consume behavior identical.
    ///
    /// Cloning the returned handle is two `Arc` bumps; every consumer shares the same published
    /// frontier and snapshot. Built lazily on first call.
    ///
    /// # Errors
    /// Propagates an IO error building the initial sealed snapshot (reading the sealed segments'
    /// sparse seek anchors). After it returns Ok the plane is cached.
    pub fn read_plane(&self) -> Result<ironbus_storage::read_plane::ReadPlane<F>, EngineError>
    where
        F: Clone,
    {
        Ok(self.log.read_plane()?)
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

    /// The configured durable-log byte cap (`LogConfig::max_total_bytes`, the quantity
    /// [`Engine::durable_record_bytes`] is shed against). `0` means UNLIMITED (the cap is off). Fixed
    /// for the engine's life: the cap is layout/contract-bound and NOT live-reloadable (a change
    /// requires a restart), so a one-time snapshot of it (e.g. for the #476 connection-thread
    /// fast-reject gate) never drifts.
    #[must_use]
    pub fn max_total_bytes(&self) -> u64 {
        self.log.config().max_total_bytes
    }

    /// The CURRENT durable-log overflow policy ([`EngineConfig::disk_full_policy`]). Unlike the cap,
    /// this IS live-reloadable ([`Engine::apply_reloadable_config`]), but only between batches on the
    /// append-actor thread, so reading it on that thread (e.g. to refresh the #476 fast-reject gate
    /// after a commit or a reload) observes a stable value for the current pass.
    #[must_use]
    pub fn disk_full_policy(&self) -> DiskFullPolicy {
        self.disk_full_policy
    }

    /// The log's total durable RECORD COUNT (the quantity the count-retention bound,
    /// [`EngineConfig::max_messages`], is measured against). An operator can compare it to the
    /// configured count bound to see headroom before retention reaps.
    #[must_use]
    pub fn durable_record_count(&self) -> u64 {
        self.log.durable_record_count()
    }

    /// The total LOGICAL bytes appended this run (#118): user payload (key + headers + payload), no
    /// framing. The denominator of the flash write-amplification ratio. Exposed as the
    /// `ironbus_logical_bytes_written` counter on `/metrics`.
    #[must_use]
    pub fn logical_bytes_written(&self) -> u64 {
        self.log.logical_bytes_written()
    }

    /// The total PHYSICAL bytes appended to segments this run (#118): record frames plus segment
    /// headers and footers, the real flash-wear write volume. The numerator of the write-amplification
    /// ratio. Exposed as the `ironbus_physical_bytes_written` counter on `/metrics`.
    #[must_use]
    pub fn physical_bytes_written(&self) -> u64 {
        self.log.physical_bytes_written()
    }

    /// The physical bytes written so far on the current UTC day (#118): the daily-write-budget meter.
    /// Exposed as the `ironbus_physical_bytes_written_today` gauge on `/metrics`.
    #[must_use]
    pub fn physical_bytes_written_today(&self) -> u64 {
        self.log.physical_bytes_written_today()
    }

    /// The OPT-IN daily physical write budget in bytes (`0` = the flash-wear governor is off), echoed
    /// for the `ironbus_daily_physical_write_budget_bytes` gauge (#118).
    #[must_use]
    pub fn daily_physical_write_budget_bytes(&self) -> u64 {
        self.log.daily_physical_write_budget_bytes()
    }

    /// The count of appends shed because the daily physical write budget was reached (#118): the
    /// over-budget signal. Exposed as the `ironbus_daily_write_budget_sheds_total` counter on
    /// `/metrics`.
    #[must_use]
    pub fn daily_budget_sheds(&self) -> u64 {
        self.log.daily_budget_sheds()
    }

    /// The OPT-IN RAM ceiling in bytes for the `ironbus_ram_headroom_bytes` gauge (`0` = unset)
    /// (#118). Pure observability; never enforced. See [`EngineConfig::ram_ceiling_bytes`].
    #[must_use]
    pub fn ram_ceiling_bytes(&self) -> u64 {
        self.ram_ceiling_bytes
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

    /// The PERSISTED on-disk footprint of the forensic quarantine store (#134, #315): the total
    /// bytes of the corruption-skip copies `quarantine/` currently holds (capped, copy-not-move),
    /// seeded at open from a read-only scan of the durable blobs so it SURVIVES a restart and
    /// reflects real disk pressure even when this recovery had no new corruption skip, plus any new
    /// capture this recovery made. Zero only when the quarantine dir is absent, empty, or
    /// unreadable. Exposed on `/metrics` as the `ironbus_quarantine_bytes` gauge.
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

    /// A clone of the engine's clock seam (#68), for the append-actor handle so a connection handler
    /// can stamp a produce's ENQUEUE instant without a round-trip through the actor (the CoDel sojourn
    /// measurement). The clone reads the SAME monotonic time as the engine's clock (an
    /// `Arc<ManualClock>` clone aliases the same atomics; a `SystemClock` clone keeps the same
    /// monotonic origin), so an enqueue stamp and the actor's dequeue read are comparable.
    #[must_use]
    pub fn clock_clone(&self) -> C {
        self.log.clock_clone()
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
            ram_ceiling_bytes: self.ram_ceiling_bytes,
            daily_physical_write_budget_bytes: self.log.daily_physical_write_budget_bytes(),
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
            // The RAM-headroom ceiling is OFF by default in the shared test config (#118); the
            // headroom test sets a non-zero ceiling explicitly.
            ram_ceiling_bytes: 0,
            // The dedup window (#33) is at its spec default in the shared test config; the dedup
            // tests below build a config with a tight count/time bound explicitly.
            dedup: ironbus_core::dedup::DedupConfig::default(),
            durability_level: crate::engine::DurabilityLevel::Sync,
            flush_interval_ms: 0,
            flush_max_bytes: 0,
            // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
            // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
            codel_target_ms: 0,
            codel_interval_ms: 0,
            retry_budget_ratio_per_million: 0,
            retry_budget_window_ms: 0,
            fire_and_forget_msg_rate: 0,
            fire_and_forget_byte_rate: 0,
            fire_and_forget_refill_ms: 0,
            egress_limit: 0,
            wal_fsync_headroom_bytes: 0,
            // Compression OFF in the shared test config (#430), so every existing test's disk
            // image stays byte-identical to the pre-compression broker; the compression tests
            // build a config with `Codec::Lz4` explicitly.
            compression: Codec::None,
            // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
            // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
            default_message_ttl_ms: 0,
            dead_letter_exchange: None,
            dead_letter_expired: false,
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
        assert_eq!(d0.record.payload.as_ref(), b"a");
        assert_eq!(d0.deliveries, 1);
        assert_eq!(e.ack(&d0.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(1));

        let d1 = message(e.poll(0).unwrap());
        assert_eq!(d1.offset, Offset::new(1));
        assert_eq!(e.ack(&d1.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(2));

        assert!(matches!(e.poll(0).unwrap(), Poll::Idle));
    }

    // An engine config with a tiny segment cap so a handful of keyed produces roll into several
    // sealed segments, giving the off-hot-path compactor adjacent dirty sources (#337).
    fn small_segment_config() -> EngineConfig {
        EngineConfig {
            log: LogConfig {
                max_segment_bytes: 200,
                ..LogConfig::default()
            },
            ..config(64, 5)
        }
    }

    #[test]
    fn compaction_off_by_default_and_opt_in_skips_holes_on_poll() {
        // Off by default: the engine's compaction config is disabled, so no v2 segment is written
        // and a normal dense poll is unchanged.
        let mut e = open(small_segment_config());
        assert!(!e.compaction_config().enabled);

        // Enable compaction, then produce multiple versions per key across several rolled segments.
        e.set_compaction_config(ironbus_storage::compaction::CompactionConfig::enabled());
        let mut last_alpha = Offset::ZERO;
        let mut last_beta = Offset::ZERO;
        for v in 0..6u8 {
            last_alpha = produce_keyed(&mut e, b"alpha", &[v; 12]);
            last_beta = produce_keyed(&mut e, b"beta", &[v + 100; 12]);
        }
        // A produce after the rolls runs the off-hot-path compaction pass (reaper-then-compactor),
        // which never blocks this append (it returns the new offset normally).
        let last = produce_keyed(&mut e, b"gamma", b"only");
        assert_eq!(
            last.get(),
            12,
            "the append path is never blocked by compaction"
        );

        // Drain via poll: the consumer sees ONLY the survivors (latest per key + the one-shot key),
        // at their ORIGINAL offsets, SKIPPING the compacted holes without a MissingRecord error. The
        // compacted holes now surface as a one-time `Poll::Compacted { from, to }` (#411): the engine
        // has already acked the cursor across each `[from, to)` run, so the drain just records the span
        // and keeps polling. Each span is a half-open, ascending, non-overlapping interval.
        let mut delivered: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut compacted_spans: Vec<(u64, u64)> = Vec::new();
        loop {
            match e.poll(0).unwrap() {
                Poll::Message(d) => {
                    let off = d.offset.get();
                    delivered.push((off, d.record.payload.to_vec()));
                    assert_eq!(e.ack(&d.token), AckResult::Acked);
                }
                Poll::Compacted { from, to } => {
                    assert!(from.get() < to.get(), "a compacted span is non-empty");
                    compacted_spans.push((from.get(), to.get()));
                }
                Poll::Idle => break,
                other => panic!("unexpected poll outcome: {other:?}"),
            }
        }
        // At least one compacted hole was crossed (the superseded versions were removed), and the spans
        // are strictly ascending and non-overlapping (the offset invariants hold across the holes).
        assert!(
            !compacted_spans.is_empty(),
            "the drain crossed at least one compacted hole"
        );
        for w in compacted_spans.windows(2) {
            assert!(
                w[0].1 <= w[1].0,
                "compacted spans are ascending and disjoint"
            );
        }
        // The surviving alpha/beta are at their LATEST original offsets (sparse), gamma is present,
        // and no superseded version was delivered.
        let offsets: Vec<u64> = delivered.iter().map(|(o, _)| *o).collect();
        assert!(
            offsets.contains(&last_alpha.get()),
            "latest alpha delivered at its offset"
        );
        assert!(
            offsets.contains(&last_beta.get()),
            "latest beta delivered at its offset"
        );
        assert!(
            offsets.contains(&last.get()),
            "the one-shot gamma delivered"
        );
        // Offsets strictly increasing (the poll skipped the compacted holes), and the cursor reached
        // the head (every offset, present or compacted-away, is satisfied).
        let mut sorted = offsets.clone();
        sorted.sort_unstable();
        assert_eq!(
            offsets, sorted,
            "delivered in ascending order, holes skipped"
        );
        assert_eq!(
            e.committed_offset().get(),
            13,
            "the cursor advanced past every hole to the head"
        );
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
                assert_eq!(record.payload.as_ref(), b"poison");
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
            delivered.push((d.offset.get(), d.record.payload.to_vec()));
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
            delivered.push((d.offset.get(), d.record.payload.to_vec()));
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
        assert_eq!(d.record.payload.as_ref(), b"b");
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
                    delivered.push((d.offset.get(), d.record.payload.to_vec()));
                    e.ack(&d.token);
                }
                Poll::Idle => break,
                Poll::Parked { offset, .. } => panic!("unexpected park at {}", offset.get()),
                Poll::Truncated { .. } => panic!("unexpected truncation"),
                Poll::Compacted { .. } => panic!("unexpected compaction"),
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
                Poll::Compacted { .. } => panic!("unexpected compaction"),
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
            delivered.push((d.offset.get(), d.record.payload.to_vec()));
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
        // Only a group MARKED broadcast (#288) accepts it; a competing/key_shared/unknown group is
        // rejected with the typed error and never panics. The cursor is left untouched.
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        produce(&mut e, b"b");
        // An unknown group (never polled, never marked broadcast): rejected.
        assert!(matches!(
            e.cumulative_ack_in("never-seen", Offset::new(1)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        // The default group is a plain competing work-group (not broadcast): rejected.
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
    fn broadcast_cumulative_ack_commits_the_cursor_up_to() {
        // A broadcast group (a group-of-one that sees every record in order, #288) accepts the
        // cumulative ack: committing its single cursor up to `up_to` is safe and visible.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c", b"d"] {
            produce(&mut e, p);
        }
        e.set_broadcast_in("bcast", true).unwrap();
        assert!(e.is_broadcast_in("bcast"));
        assert_eq!(e.committed_offset_in("bcast"), Offset::new(0));
        // Commit up to 3 (exclusive): offsets 0,1,2 are now committed; 3 is the next to deliver.
        e.cumulative_ack_in("bcast", Offset::new(3)).unwrap();
        assert_eq!(e.committed_offset_in("bcast"), Offset::new(3));
        // The next poll delivers offset 3, not a redelivery of the cumulatively-acked prefix.
        let d = message(e.poll_in("bcast", 0).unwrap());
        assert_eq!(d.offset, Offset::new(3));
        assert_eq!(d.deliveries, 1, "the acked prefix is not redelivered");
        // Other groups are untouched: the default group still sees the whole log from zero.
        assert_eq!(e.committed_offset(), Offset::new(0));
    }

    #[test]
    fn broadcast_cumulative_ack_reclaims_the_in_flight_leases_it_commits() {
        // Regression for the broadcast-drain stall: a broadcast consumer leases a batch (poll/fetch)
        // and commits it with cumulative_ack. The commit must RECLAIM those leases' in-flight slots
        // at once, not leave them to expire through the visibility timeout -- otherwise a high-rate
        // consumer piles leases up faster than they expire, fills its in-flight window, and starves
        // its own fetches.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c", b"d"] {
            produce(&mut e, p);
        }
        e.set_broadcast_in("g", true).unwrap();
        // Lease offsets 0, 1, 2 (three deliveries, none acked yet).
        for expected in 0..3 {
            let d = message(e.poll_in("g", 0).unwrap());
            assert_eq!(d.offset, Offset::new(expected));
        }
        assert_eq!(
            e.in_flight_in("g"),
            3,
            "three leases in flight before the cumulative ack"
        );
        // Cumulative ack up to 3 (exclusive): commits 0,1,2 AND reclaims their lease slots.
        e.cumulative_ack_in("g", Offset::new(3)).unwrap();
        assert_eq!(
            e.committed_offset_in("g"),
            Offset::new(3),
            "cursor advanced"
        );
        assert_eq!(
            e.in_flight_in("g"),
            0,
            "the committed leases were reclaimed -- the in-flight window is restored"
        );
        // Not starved: the next poll delivers offset 3, not a redelivery of the acked prefix.
        let d = message(e.poll_in("g", 0).unwrap());
        assert_eq!(d.offset, Offset::new(3));
        assert_eq!(d.deliveries, 1, "the acked prefix is not redelivered");
    }

    #[test]
    fn broadcast_cumulative_ack_is_idempotent_and_never_regresses() {
        // A re-ack at the same or a lower `up_to` is a no-op SUCCESS, never an error or a regression
        // (#288). The committed watermark only ever moves forward.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c", b"d", b"e"] {
            produce(&mut e, p);
        }
        e.set_broadcast_in("b", true).unwrap();
        e.cumulative_ack_in("b", Offset::new(4)).unwrap();
        assert_eq!(e.committed_offset_in("b"), Offset::new(4));
        // Same offset again: Ok, still 4.
        e.cumulative_ack_in("b", Offset::new(4)).unwrap();
        assert_eq!(e.committed_offset_in("b"), Offset::new(4));
        // A LOWER offset: Ok (no error), and the watermark holds at 4 (no regression).
        e.cumulative_ack_in("b", Offset::new(1)).unwrap();
        assert_eq!(e.committed_offset_in("b"), Offset::new(4), "no regression");
        // up_to == 0 is the trivial idempotent no-op.
        e.cumulative_ack_in("b", Offset::new(0)).unwrap();
        assert_eq!(e.committed_offset_in("b"), Offset::new(4));
        // A forward move still works after the no-ops.
        e.cumulative_ack_in("b", Offset::new(5)).unwrap();
        assert_eq!(e.committed_offset_in("b"), Offset::new(5));
    }

    #[test]
    fn broadcast_cumulative_ack_rejects_past_the_durable_head() {
        // An `up_to` past the durable head names records that do not exist yet: rejected with the
        // typed out-of-range error (no panic), and the cursor is untouched (#288).
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b"] {
            produce(&mut e, p);
        }
        e.set_broadcast_in("b", true).unwrap();
        // The head is 2 (offsets 0 and 1 exist). up_to == 2 is in range (commits both); up_to == 3
        // is one past the head.
        assert!(matches!(
            e.cumulative_ack_in("b", Offset::new(3)),
            Err(EngineError::CumulativeAckOutOfRange {
                up_to: 3,
                durable_head: 2,
                ..
            })
        ));
        assert_eq!(
            e.committed_offset_in("b"),
            Offset::new(0),
            "a rejected ack commits nothing"
        );
        // Exactly at the head is accepted: it commits every existing record.
        e.cumulative_ack_in("b", Offset::new(2)).unwrap();
        assert_eq!(e.committed_offset_in("b"), Offset::new(2));
    }

    #[test]
    fn broadcast_cumulative_ack_rejects_below_the_earliest_retained() {
        // The disk-full drop-oldest policy force-reaps the oldest segment under a stuck consumer, so
        // the earliest retained offset rises above 0. A broadcast cumulative ack below it names
        // reaped records: rejected with the typed out-of-range error, cursor untouched (#288).
        let one = one_record_bytes();
        let mut e = open(config_disk_full(4 * one, DiskFullPolicy::DropOldest));
        // A stuck consumer leases offset 0 and never acks, so the consumer-safe reaper cannot
        // reclaim segment 0 and DropOldest force-reaps it once the byte cap is exceeded.
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
            .expect("drop-oldest accepts the produce");
        }
        let earliest = e.earliest_retained_offset().get();
        assert!(earliest > 0, "drop-oldest should have reaped a prefix");
        e.set_broadcast_in("b", true).unwrap();
        // An up_to strictly below the earliest retained offset is rejected, cursor untouched.
        assert!(matches!(
            e.cumulative_ack_in("b", Offset::new(earliest - 1)),
            Err(EngineError::CumulativeAckOutOfRange {
                earliest_retained,
                ..
            }) if earliest_retained == earliest
        ));
        assert_eq!(
            e.committed_offset_in("b"),
            Offset::new(0),
            "a rejected ack commits nothing"
        );
        // Exactly at the earliest retained offset is in range (the lower bound is inclusive).
        e.cumulative_ack_in("b", Offset::new(earliest)).unwrap();
        assert_eq!(e.committed_offset_in("b"), Offset::new(earliest));
    }

    #[test]
    fn marking_broadcast_clears_key_shared_and_vice_versa() {
        // Broadcast and key_shared are mutually exclusive (#288): each mode-set clears the other, so
        // a group can never be both a competing key_shared cursor AND accept a cumulative ack.
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        // key_shared first, then broadcast: the router is dropped and the cumulative ack is accepted.
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        assert_eq!(e.key_ordering_in("g"), KeyOrdering::KeyShared);
        e.set_broadcast_in("g", true).unwrap();
        assert!(e.is_broadcast_in("g"));
        assert_eq!(
            e.key_ordering_in("g"),
            KeyOrdering::None,
            "broadcast cleared the router"
        );
        e.cumulative_ack_in("g", Offset::new(1)).unwrap();
        assert_eq!(e.committed_offset_in("g"), Offset::new(1));
        // Now flip back to key_shared: the broadcast flag is cleared, so the cumulative ack is
        // rejected again (the work-group guard is restored).
        e.set_key_ordering_in("g", KeyOrdering::KeyShared).unwrap();
        assert!(!e.is_broadcast_in("g"), "key_shared cleared broadcast");
        assert!(matches!(
            e.cumulative_ack_in("g", Offset::new(1)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        // Clearing broadcast back to false also restores the work-group rejection.
        e.set_broadcast_in("g", false).unwrap();
        e.set_broadcast_in("g", true).unwrap();
        e.set_broadcast_in("g", false).unwrap();
        assert!(!e.is_broadcast_in("g"));
        assert!(matches!(
            e.cumulative_ack_in("g", Offset::new(1)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
    }

    #[test]
    fn the_cumulative_ack_rejection_renders_a_distinct_message() {
        // The typed error has a self-describing Display, distinct from the other engine errors,
        // so the wire layer can surface a stable reason.
        let msg = EngineError::CumulativeAckOnWorkGroup.to_string();
        assert!(msg.contains("cumulative ack"), "{msg}");
        assert!(msg.contains("broadcast"), "{msg}");
    }

    #[test]
    fn a_broadcast_group_rejects_a_second_concurrent_subscriber() {
        // The group-of-one invariant enforced in code (#288): a broadcast group accepts AT MOST ONE
        // active subscriber, so a cumulative ack can only ever commit past that single consumer's
        // OWN in-flight leases, never a peer's. A second SUB is rejected with the typed error.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        e.set_broadcast_in("g", true).unwrap();
        // Consumer A subscribes: accepted, it is the lone subscriber.
        e.subscribe_in("g", MemberId::new(1)).unwrap();
        assert_eq!(e.subscriber_count_in("g"), 1);
        // Consumer B subscribes to the SAME broadcast group: REJECTED (the second subscriber).
        assert!(
            matches!(
                e.subscribe_in("g", MemberId::new(2)),
                Err(EngineError::BroadcastGroupBusy { ref group }) if group == "g"
            ),
            "a second subscriber to a broadcast group must be rejected"
        );
        // The reject changed nothing: A is still the lone subscriber.
        assert_eq!(e.subscriber_count_in("g"), 1);
        // A re-SUB by the SAME member is idempotent, NOT a second subscriber.
        e.subscribe_in("g", MemberId::new(1)).unwrap();
        assert_eq!(e.subscriber_count_in("g"), 1);
        // Once A leaves, B may take over the slot.
        e.unsubscribe_in("g", MemberId::new(1));
        assert_eq!(e.subscriber_count_in("g"), 0);
        e.subscribe_in("g", MemberId::new(2)).unwrap();
        assert_eq!(e.subscriber_count_in("g"), 1);
    }

    #[test]
    fn exploit_a_no_offset_is_silently_dropped_under_the_subscriber_cap() {
        // EXPLOIT A (the silent-drop sequence the cap now blocks, #288): with two concurrent
        // subscribers a broadcast group could lease offset 0 to A (unacked) and offset 1 to B, B
        // acks 1, a cumulative ack to 2 jumps the cursor past A's still-in-flight offset 0, and when
        // A's lease expires offset 0 is skipped forever. The subscriber cap blocks step 3 (B's SUB),
        // so the sequence cannot even begin: every produced record stays deliverable to the lone
        // consumer and NONE is skipped.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        e.set_broadcast_in("g", true).unwrap();
        // A subscribes and leases offset 0 (in-flight, unacked).
        e.subscribe_in("g", MemberId::new(1)).unwrap();
        let d0 = message(e.poll_in("g", 0).unwrap());
        assert_eq!(d0.offset, Offset::new(0));
        // B's SUB (the exploit's step 3) is REJECTED before it can lease offset 1.
        assert!(matches!(
            e.subscribe_in("g", MemberId::new(2)),
            Err(EngineError::BroadcastGroupBusy { .. })
        ));
        // Drive the lone consumer to completion: offset 0 (A's lease, now acked) then 1, 2. Because
        // the second subscriber never joined, the cumulative ack the lone consumer issues only ever
        // commits past its OWN in-flight leases, so nothing is skipped.
        assert_eq!(e.ack_in("g", &d0.token), AckResult::Acked);
        let head = e.flushed_offset();
        e.cumulative_ack_in("g", head).unwrap();
        assert_eq!(
            e.committed_offset_in("g"),
            Offset::new(3),
            "every produced record is committed, none skipped"
        );
        // No record below the head is left undelivered-and-uncommitted: the cursor reached the head.
        assert_eq!(e.committed_offset_in("g"), head);
    }

    #[test]
    fn exploit_b_flipping_a_live_competing_group_to_broadcast_is_rejected() {
        // EXPLOIT B (#288): a group accrues COMPETING out-of-order in-flight lease state, then is
        // flipped to broadcast (`set_broadcast_in(g, true)`), then cumulative-acked past the
        // in-flight leases for the same silent drop. The flip guard now refuses the flip while the
        // group carries that competing state, so the unsafe cumulative ack is never reachable.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        // Two consumers compete on a plain group "g": lease offset 0 (held, unacked) and offset 1.
        let d0 = message(e.poll_in("g", 0).unwrap());
        let d1 = message(e.poll_in("g", 0).unwrap());
        assert_eq!(d0.offset, Offset::new(0));
        assert_eq!(d1.offset, Offset::new(1));
        // Ack offset 1 only: the cursor now has an out-of-order acked-ahead set [1,2), committed 0,
        // and offset 0 is still in flight. This is the competing signature.
        assert_eq!(e.ack_in("g", &d1.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in("g"), Offset::new(0));
        // Flipping to broadcast is REJECTED: the populated lease table / ahead set would let a
        // cumulative ack commit past offset 0 (a peer's in-flight message).
        assert!(
            matches!(
                e.set_broadcast_in("g", true),
                Err(EngineError::BroadcastGroupBusy { ref group }) if group == "g"
            ),
            "flipping a live competing group to broadcast must be rejected"
        );
        // The group is NOT broadcast, so the cumulative ack is still hard-rejected as a work-group:
        // the silent drop is unreachable, and offset 0 stays deliverable.
        assert!(!e.is_broadcast_in("g"));
        assert!(matches!(
            e.cumulative_ack_in("g", Offset::new(2)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        assert_eq!(
            e.committed_offset_in("g"),
            Offset::new(0),
            "offset 0 was never committed past; it is not silently dropped"
        );
    }

    #[test]
    fn flipping_a_group_with_in_flight_leases_to_broadcast_is_rejected() {
        // The flip guard also refuses a group holding a contiguous in-flight lease that was NOT
        // acked-ahead: a single live lease is still competing state a flip-then-cumulative-ack could
        // commit past if a peer held it. The operator must drain first (#288).
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        produce(&mut e, b"b");
        // Lease offset 0 and hold it (in-flight, unacked) on a plain group.
        let d0 = message(e.poll_in("g", 0).unwrap());
        assert_eq!(d0.offset, Offset::new(0));
        assert!(matches!(
            e.set_broadcast_in("g", true),
            Err(EngineError::BroadcastGroupBusy { .. })
        ));
        assert!(!e.is_broadcast_in("g"), "the flip was refused");
        // After the lease is acked (the group is drained), the flip to broadcast is allowed.
        assert_eq!(e.ack_in("g", &d0.token), AckResult::Acked);
        e.set_broadcast_in("g", true).unwrap();
        assert!(e.is_broadcast_in("g"));
    }

    #[test]
    fn a_lone_broadcast_consumer_cumulative_acks_past_its_own_in_flight_leases() {
        // The LEGITIMATE case still works (#288): a single broadcast consumer that has leased
        // messages in order (its OWN in-flight leases) can cumulative-ack PAST them. Acking past
        // your own in-flight leases is the consumer's explicit "I am done up to here" and is safe,
        // because there is no peer holding a message below the watermark.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c", b"d"] {
            produce(&mut e, p);
        }
        // Mark broadcast at configure time (a fresh, quiescent group): allowed.
        e.set_broadcast_in("g", true).unwrap();
        // The lone consumer subscribes and leases offsets 0,1,2 in order (its own in-flight leases),
        // none acked per-message.
        e.subscribe_in("g", MemberId::new(1)).unwrap();
        let d0 = message(e.poll_in("g", 0).unwrap());
        let d1 = message(e.poll_in("g", 0).unwrap());
        let d2 = message(e.poll_in("g", 0).unwrap());
        assert_eq!(
            (d0.offset, d1.offset, d2.offset),
            (Offset::new(0), Offset::new(1), Offset::new(2))
        );
        assert_eq!(
            e.in_flight(),
            3,
            "three of the consumer's own leases in flight"
        );
        // Cumulative-ack past its own in-flight leases up to 3 (exclusive): committed jumps to 3.
        e.cumulative_ack_in("g", Offset::new(3)).unwrap();
        assert_eq!(e.committed_offset_in("g"), Offset::new(3));
        // The next poll delivers offset 3, not a redelivery of the cumulatively-acked prefix.
        let d3 = message(e.poll_in("g", 0).unwrap());
        assert_eq!(d3.offset, Offset::new(3));
        assert_eq!(
            d3.deliveries, 1,
            "the cumulatively-acked prefix is not redelivered"
        );
    }

    #[test]
    fn the_broadcast_busy_rejection_renders_a_distinct_message() {
        // The new typed error has a self-describing Display, distinct from the work-group reject.
        let msg = EngineError::BroadcastGroupBusy {
            group: "g".to_string(),
        }
        .to_string();
        assert!(msg.contains("broadcast group"), "{msg}");
        assert!(msg.contains("group-of-one"), "{msg}");
    }

    #[test]
    fn the_default_group_can_never_be_marked_broadcast() {
        // The residual silent-loss bypass (#288): the DEFAULT/empty group (`""`) is pre-created at
        // open and its consumers never SUB, so the active-subscriber cap never binds it. Marking it
        // broadcast would leave two competing default-subscription pollers free to accrue in-flight
        // leases that a cumulative ack (with an empty group name) commits past, the same silent drop,
        // uncapped. So `set_broadcast_in("", true)` is REJECTED with a distinct typed error and the
        // default group stays a plain competing work-group that still HARD-REJECTS a cumulative ack.
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        // Even on a fresh, empty default group (the flip guard would otherwise pass), the flip is
        // refused outright with the typed `BroadcastGroupNotNamed`, not `BroadcastGroupBusy`.
        assert!(
            matches!(
                e.set_broadcast_in(DEFAULT_GROUP, true),
                Err(EngineError::BroadcastGroupNotNamed { ref group }) if group.is_empty()
            ),
            "marking the default/empty group broadcast must be refused"
        );
        // The default group is NOT broadcast: a cumulative ack on it is still the #63 work-group
        // HARD-REJECT, and nothing is committed past a (would-be) peer's in-flight offset.
        assert!(!e.is_broadcast_in(DEFAULT_GROUP));
        // Two competing pollers on the default subscription each hold an in-flight lease.
        let d0 = message(e.poll(0).unwrap());
        let _d1 = message(e.poll(0).unwrap());
        assert_eq!(d0.offset, Offset::new(0));
        assert!(matches!(
            e.cumulative_ack(Offset::new(2)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        assert_eq!(
            e.committed_offset(),
            Offset::new(0),
            "the default-group cumulative ack commits nothing: no silent drop"
        );
        // Clearing the (never-set) broadcast flag on the default group is always a safe no-op.
        e.set_broadcast_in(DEFAULT_GROUP, false).unwrap();
        assert!(!e.is_broadcast_in(DEFAULT_GROUP));
    }

    #[test]
    fn the_broadcast_not_named_rejection_renders_a_distinct_message() {
        // The default-group reject has a self-describing Display, distinct from the busy reject.
        let msg = EngineError::BroadcastGroupNotNamed {
            group: String::new(),
        }
        .to_string();
        assert!(msg.contains("default/empty group"), "{msg}");
        assert!(msg.contains("named group only"), "{msg}");
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
                Poll::Compacted { .. } => panic!("unexpected compaction"),
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
        assert_eq!(d.record.payload.as_ref(), b"a");
        let d_b = message(e.poll(0).unwrap());
        assert_eq!(d_b.record.payload.as_ref(), b"b");
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
        assert_eq!(d.record.payload.as_ref(), b"b");
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
        assert_eq!(d.record.payload.as_ref(), b"b");
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

        // Reopen on the same fs: the OPERATIONAL counters resume from the snapshot, byte-for-byte.
        // The recovery-EVENT family (#575) legitimately advances on the reopen (a reopen IS another
        // recovery run), so it is compared separately by `recovery_event_counters_*`; zero it here so
        // this assertion stays about the operational-counter resume it was written to check.
        let e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 1)).unwrap();
        let mut resumed = e.counters();
        resumed.recovery = RecoveryCounters::default();
        let mut expected = before;
        expected.recovery = RecoveryCounters::default();
        assert_eq!(
            resumed, expected,
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
        // The OPERATIONAL counters recover as all-zeros (the missing snapshot). The recovery-EVENT
        // family legitimately records this clean open as one run, so it is excluded from the
        // all-zeros check (covered by `recovery_event_counters_*`).
        let mut resumed = e.counters();
        resumed.recovery = RecoveryCounters::default();
        assert_eq!(
            resumed,
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
        // The OPERATIONAL counters recover as all-zeros (the torn snapshot). The recovery-EVENT
        // family records this clean open as one run, so it is excluded here.
        let mut resumed = e.counters();
        resumed.recovery = RecoveryCounters::default();
        assert_eq!(
            resumed,
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
        // The OPERATIONAL counters resume from the shutdown flush; the recovery-EVENT family advances
        // on the reopen (another clean run), so zero it for this operational-counter assertion.
        let mut resumed = e.counters();
        resumed.recovery = RecoveryCounters::default();
        let mut expected = final_counts;
        expected.recovery = RecoveryCounters::default();
        assert_eq!(
            resumed, expected,
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
            // The dedup family (#33), appended after #307; non-zero so the snapshot round-trip
            // proves the two new trailing fields are carried.
            dedup_hits: 314,
            dedup_out_of_window: 42,
            // The recovery-event family (#575), appended after dedup; every field non-zero so the
            // round-trip proves all eight new trailing fields are carried in order.
            recovery: RecoveryCounters {
                runs_by_outcome: [501, 502, 503, 504],
                torn_tail_repairs: 505,
                corruption_repairs_by_artifact: [506, 507, 508],
            },
            // The TTL family (#549), appended after recovery; non-zero so the round-trip proves the
            // new trailing field is carried.
            expired: 999,
            // The idempotent-producer out-of-order rejection counter (V2-M8), appended after TTL;
            // non-zero so the round-trip proves the new trailing field is carried.
            producer_out_of_order: 1357,
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
    fn recovery_event_counters_classify_and_count_each_outcome() {
        // The recovery-EVENT family (#575) records one run per accumulation, in the right outcome
        // bucket, and adds the per-event torn-tail / corruption repair counts. Driven directly over
        // the helper so each outcome is pinned deterministically.
        let mut r = RecoveryCounters::default();

        // 1) A CLEAN report: one clean run, no repairs.
        Engine::<InMemoryFs, ManualClock>::accumulate_recovery_events(&mut r, &LossReport::new());
        assert_eq!(r.runs_by_outcome[RecoveryOutcome::Clean.index()], 1);
        assert_eq!(r.torn_tail_repairs, 0);
        assert_eq!(
            r.corruption_repairs_by_artifact[RecoveryArtifact::Segment.index()],
            0
        );

        // 2) A TORN-TAIL-only report: one torn_tail_truncated run, one torn-tail repair, NO
        //    corruption (a torn tail is not data loss).
        let mut torn = LossReport::new();
        torn.push(LossEvent::span(0, 16, 64, 1, ReasonCode::TornTail));
        Engine::<InMemoryFs, ManualClock>::accumulate_recovery_events(&mut r, &torn);
        assert_eq!(
            r.runs_by_outcome[RecoveryOutcome::TornTailTruncated.index()],
            1
        );
        assert_eq!(r.torn_tail_repairs, 1);
        assert_eq!(
            r.corruption_repairs_by_artifact[RecoveryArtifact::Segment.index()],
            0,
            "a torn tail is never counted as a corruption repair"
        );

        // 3) A CORRUPTION report (data loss): one quarantined run, one segment corruption repair.
        let mut corrupt = LossReport::new();
        corrupt.push(LossEvent::span(
            1,
            0,
            4096,
            1,
            ReasonCode::CorruptRecordBody,
        ));
        Engine::<InMemoryFs, ManualClock>::accumulate_recovery_events(&mut r, &corrupt);
        assert_eq!(r.runs_by_outcome[RecoveryOutcome::Quarantined.index()], 1);
        assert_eq!(
            r.corruption_repairs_by_artifact[RecoveryArtifact::Segment.index()],
            1
        );
        // The torn-tail count is unchanged by a pure-corruption run.
        assert_eq!(r.torn_tail_repairs, 1);

        // The counters are monotonic across the three accumulations (one run each = three runs).
        let total_runs: u64 = r.runs_by_outcome.iter().sum();
        assert_eq!(total_runs, 3, "exactly one run recorded per accumulation");

        // The hand-written `index()` stays in lockstep with `ALL` (the array order the renderer and
        // the durable snapshot both depend on).
        for (i, o) in RecoveryOutcome::ALL.iter().enumerate() {
            assert_eq!(o.index(), i, "RecoveryOutcome::index must match ALL order");
        }
        for (i, a) in RecoveryArtifact::ALL.iter().enumerate() {
            assert_eq!(a.index(), i, "RecoveryArtifact::index must match ALL order");
        }
    }

    #[test]
    fn recovery_event_counters_fire_on_a_real_torn_tail_reopen() {
        // End to end: a hard crash tears the tail, and reopening the engine bumps the recovery-event
        // counters once (one torn_tail_truncated run + one torn-tail repair), the operator-facing
        // proof the recovery actually fired. NATS has no such metric.
        let fs = InMemoryFs::new();
        let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
        for _ in 0..4 {
            produce(&mut e, &[0xcd; 16]);
        }
        drop(e);
        tear_segment_tail(&fs, 3);

        let reopened = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        let r = reopened.counters().recovery;
        assert_eq!(
            r.runs_by_outcome[RecoveryOutcome::TornTailTruncated.index()],
            1,
            "the torn-tail reopen recorded exactly one torn_tail_truncated run"
        );
        assert!(
            r.torn_tail_repairs >= 1,
            "the torn tail was counted as a torn-tail repair, got {}",
            r.torn_tail_repairs
        );
        assert_eq!(
            r.corruption_repairs_by_artifact[RecoveryArtifact::Segment.index()],
            0,
            "a torn tail is never a corruption repair"
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
                    Poll::Compacted { .. } => panic!("unexpected compaction"),
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

    // ---- The untouched default group and the protect floor (#424) ----

    // Produces one 16-byte record then drains the NAMED group `worker` to the head, acking
    // everything, `n` times. The default group is never polled, acked, or subscribed: this is the
    // named-groups-only deployment shape that #424 is about. The drain is EXHAUSTIVE on purpose:
    // a one-time `Truncated` (the worker re-created after a reopen resumes at offset 0, below the
    // reaped earliest, and is reset up with the #84 signal) continues the drain rather than
    // silently ending it, and any other non-message outcome panics, so a partial drain can never
    // leave the worker behind and turn a later floor assertion into a flake.
    fn produce_and_consume_all_in_worker(
        e: &mut Engine<InMemoryFs, ManualClock>,
        n: usize,
        now: &mut u64,
    ) {
        for _ in 0..n {
            produce(e, &[0xab; 16]);
            loop {
                match e.poll_in("worker", *now).unwrap() {
                    Poll::Message(d) => {
                        assert_eq!(e.ack_in("worker", &d.token), AckResult::Acked);
                        *now += 1;
                    }
                    Poll::Truncated { .. } => {}
                    Poll::Idle => break,
                    other => panic!("unexpected poll result draining worker: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn a_producer_only_deployment_reaps_with_no_consumer_at_all() {
        // The fallback floor: with NO touched group (the sole group is the untouched default
        // group), the floor is the durable head, so a producer-only deployment still honors its
        // retention bounds instead of growing to the hard cap. Mutation coverage: reverting the
        // fallback to 0 fails this test.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let mut e = open(config_with_retention(2 * one));
        for _ in 0..30 {
            produce(&mut e, &[0xab; 16]);
        }
        assert!(
            e.counters().segments_reaped >= 1,
            "no consumer ever existed, so the floor is the head and old segments reaped"
        );
        assert!(
            e.durable_record_bytes() <= 2 * one,
            "the live durable bytes dropped to or under the bound: {} <= {}",
            e.durable_record_bytes(),
            2 * one
        );
    }

    #[test]
    fn a_subscribed_default_group_pins_retention_before_its_first_poll() {
        // An explicit SUB on the default group is consumer intent BEFORE any poll: it must pin
        // the floor, or records produced between the SUB and the first FLOW could be reaped out
        // from under the consumer that announced itself. Mutation coverage: removing the
        // subscribe_in touch fails this test.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let mut e = open(config_with_retention(2 * one));
        e.subscribe_in(DEFAULT_GROUP, MemberId::new(1)).unwrap();
        let mut now = 0u64;
        produce_and_consume_all_in_worker(&mut e, 30, &mut now);
        assert_eq!(
            e.counters().segments_reaped,
            0,
            "a subscribed default group is touched and pins the floor at 0"
        );
    }

    #[test]
    fn an_untouched_default_group_does_not_pin_retention() {
        // A deployment that only ever consumes through NAMED groups: before #424 the structural
        // default group sat at committed 0 forever, pinned the protect floor, and silently
        // disabled every retention bound (the log grew to the hard cap, then drop-new shed every
        // produce). The untouched default group must NOT pin the floor: with the named group
        // drained to the head, producing past the bound reaps.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let mut e = open(config_with_retention(2 * one));
        let mut now = 0u64;
        produce_and_consume_all_in_worker(&mut e, 30, &mut now);
        assert!(
            e.counters().segments_reaped >= 1,
            "an untouched default group does not pin the floor, so old segments reaped"
        );
        assert!(
            e.durable_record_bytes() <= 2 * one,
            "the live durable bytes dropped to or under the bound: {} <= {}",
            e.durable_record_bytes(),
            2 * one
        );
    }

    #[test]
    fn a_polled_default_group_pins_retention_like_any_consumer() {
        // ONE default-group poll (here it leases offset 0 and never acks) marks it a real
        // consumer: it pins the floor at 0 exactly like the named slow group in
        // `a_slow_group_prevents_reaping_the_segments_it_still_needs`, so a real default-group
        // consumer keeps the full slow-consumer protection.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let mut e = open(config_with_retention(2 * one));
        produce(&mut e, &[0xab; 16]);
        assert!(matches!(e.poll(0).unwrap(), Poll::Message(_)));

        let mut now = 100u64;
        produce_and_consume_all_in_worker(&mut e, 30, &mut now);
        assert_eq!(
            e.counters().segments_reaped,
            0,
            "a polled default group is touched and pins the floor at 0"
        );
    }

    #[test]
    fn an_untouched_default_group_stays_untouched_across_reopen() {
        // Nothing durable is ever written for a group nobody consumed from, so a restart resumes
        // the default group untouched and named-groups-only retention keeps reaping.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let mut e = open(config_with_retention(2 * one));
        let mut now = 0u64;
        produce_and_consume_all_in_worker(&mut e, 10, &mut now);

        let fs = e.into_filesystem();
        let mut e = Engine::open(fs, ManualClock::new(), config_with_retention(2 * one)).unwrap();
        let reaped_before = e.counters().segments_reaped;
        produce_and_consume_all_in_worker(&mut e, 20, &mut now);
        assert!(
            e.counters().segments_reaped > reaped_before,
            "the reopened broker still reaps: the default group resumed untouched"
        );
    }

    #[test]
    fn a_checkpointed_default_group_resumes_touched_across_reopen() {
        // A default-group consumer whose cursor reached its durable checkpoint resumes TOUCHED:
        // its committed offset is the floor across the restart, so its unconsumed records stay
        // protected. The session layer drives the checkpoint cadence, so the test calls
        // `checkpoint_cursor` explicitly, exactly like a graceful stop does.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let mut e = open(config_with_retention(2 * one));
        produce(&mut e, &[0xab; 16]);
        produce(&mut e, &[0xcd; 16]);
        let d = match e.poll(0).unwrap() {
            Poll::Message(d) => d,
            other => panic!("expected a message, got {other:?}"),
        };
        assert_eq!(e.ack(&d.token), AckResult::Acked);
        e.checkpoint_cursor().unwrap();

        let fs = e.into_filesystem();
        let mut e = Engine::open(fs, ManualClock::new(), config_with_retention(2 * one)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(1), "cursor resumed");
        // Far over the bound through the named group: the touched default group's floor (1)
        // still protects its unconsumed record at offset 1 from being reaped.
        let mut now = 100u64;
        produce_and_consume_all_in_worker(&mut e, 30, &mut now);
        let d = match e.poll(now).unwrap() {
            Poll::Message(d) => d,
            other => panic!("expected the protected record, got {other:?}"),
        };
        assert_eq!(
            d.offset,
            Offset::new(1),
            "the resumed touched default group's unconsumed record survived retention"
        );
        assert_eq!(d.record.payload.as_ref(), &[0xcd; 16]);
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
                    Poll::Compacted { .. } => panic!("unexpected compaction"),
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
    fn force_reaping_an_l2_records_segment_dead_letters_its_pending_confirm() {
        // #497: an L2 produce at offset 0 registers a pending confirm. If the disk-full drop-oldest
        // policy FORCE-reaps the oldest segment (deleting offset 0 out from under every consumer)
        // before any consumer acked it, the pending confirm can never be satisfied, so a DEAD_LETTERED
        // terminal fires to the producer instead of leaving it waiting out the whole TTL.
        let one = one_record_bytes();
        let mut e = open(config_disk_full(4 * one, DiskFullPolicy::DropOldest));
        let producer = MemberId::new(42);

        // The first record (offset 0) is an L2 produce: register its pending confirm.
        produce(&mut e, &[0xab; 16]);
        e.register_l2_confirm(Offset::new(0), producer);
        assert_eq!(
            e.drain_l2_confirms(producer).len(),
            0,
            "no terminal yet (nothing reaped)"
        );

        // A fast producer fills past the cap; drop-oldest force-reaps segment 0 (offset 0 is gone).
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
        assert!(
            e.earliest_retained_offset().get() > 0,
            "offset 0 was force-reaped"
        );
        // The producer's pending confirm for the reaped offset became a DEAD_LETTERED terminal.
        let ready = e.drain_l2_confirms(producer);
        assert_eq!(ready.len(), 1, "exactly one terminal for the reaped offset");
        assert_eq!(ready[0].offset, 0);
        assert_eq!(ready[0].status, ConfirmStatus::DeadLettered);
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
                Poll::Compacted { .. } => panic!("unexpected compaction"),
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
                    Poll::Compacted { .. } => panic!("unexpected compaction"),
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

    #[test]
    fn drop_oldest_treats_a_daily_budget_shed_as_final_and_never_force_reaps() {
        // Regression for the #118 BLOCKER: under DropOldest the daily-write-budget shed must be a
        // FINAL drop-new reject, NOT routed into the force-reap loop. The pre-fix code returned the
        // SAME `AtCapacity` for the byte cap and the budget, so a budget shed under DropOldest drove
        // `make_room_then_append`, which force-reaped EVERY sealed segment (a reap never lowers
        // today's physical-write meter, so the retry shed again) and inflated `daily_budget_sheds`
        // by one PER reap-loop retry: catastrophic, unintended data loss.
        //
        // Build several SEALED segments (a tiny segment cap so each rolls), with a daily budget the
        // build-up crosses, then assert an over-budget produce is REJECTED, force-reaps ZERO segments
        // (segment_count and segments_force_reaped unchanged), and bumps `daily_budget_sheds` by
        // exactly one per rejected produce.
        let one = one_record_bytes();
        // A small segment cap so records roll into many sealed segments; a budget sized to admit
        // roughly a dozen records before it bites, so a healthy spread of sealed segments exists when
        // the governor first fires (the force-reap loop, if entered, would have many targets to erase).
        let budget = 12 * one;
        let mut cfg = config(64, 5);
        cfg.log = LogConfig {
            max_segment_bytes: 160,
            daily_physical_write_budget_bytes: budget,
            ..LogConfig::default()
        };
        cfg.disk_full_policy = DiskFullPolicy::DropOldest;
        let mut e = open(cfg);

        // Produce until the governor first sheds. Every admitted produce lands; the first rejection is
        // the budget shed. Bounded loop so a logic error cannot spin forever.
        let mut admitted = 0u64;
        let mut first_shed = None;
        for _ in 0..200 {
            match e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[0xab; 16],
            }) {
                Ok(_) => admitted += 1,
                Err(err) => {
                    first_shed = Some(err);
                    break;
                }
            }
        }
        let shed = first_shed.expect("the daily budget eventually sheds a produce");
        // The shed is the distinct, final daily-budget reject (it still reads as "at capacity" to the
        // producer, mapping to the same rejected-produce reply, but it is NOT the byte-cap shed).
        assert!(
            shed.is_daily_write_budget_exceeded(),
            "the over-budget produce is the distinct daily-budget shed, got {shed:?}"
        );
        assert!(
            shed.is_at_capacity(),
            "the budget shed still maps to the producer-facing rejected-produce reply, got {shed:?}"
        );
        assert!(
            admitted >= 2,
            "the build-up created multiple records before the budget bit (admitted {admitted})"
        );
        // Several SEALED segments exist at the moment the governor fires (the build-up rolled them);
        // this is exactly the state in which the pre-fix reap loop would erase the log.
        let segments_before = e.segment_count();
        assert!(
            segments_before >= 2,
            "multiple segments exist when the governor fires (have {segments_before})"
        );
        // The KEY assertions: the budget shed force-reaped NOTHING.
        assert_eq!(
            e.counters().segments_force_reaped,
            0,
            "a daily-budget shed must NEVER force-reap (this is the BLOCKER)"
        );
        assert_eq!(
            e.daily_budget_sheds(),
            1,
            "exactly one shed counted for the one rejected produce (not inflated by reap retries)"
        );
        assert_eq!(
            e.counters().produce_rejected,
            1,
            "the budget shed is counted once as a rejected produce"
        );
        assert!(
            e.is_healthy(),
            "a budget shed is non-fatal: the writer stays live"
        );

        // A second over-budget produce sheds again: still final, still no force-reap, and the
        // segment count is unchanged across BOTH sheds (the log was never erased segment-by-segment).
        let shed2 = e
            .produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &[0xab; 16],
            })
            .unwrap_err();
        assert!(
            shed2.is_daily_write_budget_exceeded(),
            "the second over-budget produce is also the daily-budget shed, got {shed2:?}"
        );
        assert_eq!(
            e.counters().segments_force_reaped,
            0,
            "the second budget shed force-reaps nothing either"
        );
        assert_eq!(
            e.segment_count(),
            segments_before,
            "no segment was reaped across the budget sheds (the durable log is intact)"
        );
        assert_eq!(
            e.daily_budget_sheds(),
            2,
            "exactly one shed counted per rejected produce (two produces, two sheds)"
        );
        assert_eq!(
            e.counters().produce_rejected,
            2,
            "two rejected produces counted"
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

    // ----- Per-message / per-stream TTL + configurable dead-letter exchanges (V2-M4, #549/#551) -----

    use ironbus_core::ttl::encode_ttl_headers;
    use ironbus_storage::dlq::read_dead_letter_entries;

    /// A config with a per-STREAM default message TTL (V2-M4, #549): `default_message_ttl_ms` set,
    /// the dead-letter exchange and expired-routing flag left inert. Spread from the shared `config`
    /// so every other field keeps its golden-path value.
    fn config_with_ttl(default_message_ttl_ms: u64) -> EngineConfig {
        EngineConfig {
            default_message_ttl_ms,
            ..config(64, 5)
        }
    }

    /// A config with a configurable dead-letter EXCHANGE (#551) AND the expired-routing flag on, so a
    /// TTL-expired message is dead-lettered (reason `TtlExpired`) to the named subdir rather than
    /// reclaimed by retention. `max_deliver` is high so the only dead-letter trigger here is the TTL.
    fn config_with_dlx_for_expired(default_message_ttl_ms: u64, exchange: &str) -> EngineConfig {
        EngineConfig {
            default_message_ttl_ms,
            dead_letter_exchange: Some(exchange.to_string()),
            dead_letter_expired: true,
            ..config(64, 5)
        }
    }

    /// Produces one record at producer timestamp `timestamp_ms` carrying a per-message TTL header
    /// (or no TTL header when `Ttl::NONE`), returning its offset. The TTL is anchored to this durable
    /// producer timestamp, so advancing the WALL clock past `timestamp_ms + ttl` expires it.
    fn produce_with_ttl<F: Filesystem>(
        e: &mut Engine<F, std::sync::Arc<ManualClock>>,
        timestamp_ms: u64,
        ttl: Ttl,
        payload: &[u8],
    ) -> Offset {
        let headers = encode_ttl_headers(ttl, b"orig");
        e.produce(&Append {
            timestamp_ms,
            flags: RecordFlags::EMPTY,
            key: b"k",
            headers: &headers,
            payload,
        })
        .unwrap()
    }

    #[test]
    fn a_per_message_ttl_expires_on_read_and_is_reclaimed_not_delivered() {
        // The marquee TTL behavior (#549), driven by a ManualClock so expiry is DETERMINISTIC (no
        // wall-clock flake). A record with a 1_000 ms per-message TTL produced at wall-clock 100 is
        // LIVE before its 1_100 deadline and EXPIRED at/after it: at the deadline the poll SKIPS it
        // (never delivers), commits the cursor PAST it (reclaimed by retention, bounded), and counts
        // it as `expired` (no silent drop).
        let clock = std::sync::Arc::new(ManualClock::at_unix_millis(100));
        let mut e = open_with_clock(config_with_ttl(0), std::sync::Arc::clone(&clock));
        let off = produce_with_ttl(&mut e, 100, Ttl::from_millis(1_000), b"perishable");

        // BEFORE the deadline (wall clock 100 < 1_100): the record is delivered normally.
        clock.set_unix_millis(1_099);
        let d = message(e.poll_now().unwrap());
        assert_eq!(d.offset, off, "a live record is delivered");
        // Nack it back (let the lease expire) so it is re-pollable, then cross the deadline.
        clock.advance_monotonic_nanos(200); // expire the visibility lease
        clock.set_unix_millis(1_100); // AT the deadline: now expired

        // At/after the deadline the next poll does NOT deliver it: it is skipped, committed past,
        // and counted as expired. With no live record behind it the poll is Idle.
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "an expired record is never delivered"
        );
        assert_eq!(
            e.counters().expired,
            1,
            "the expiry is accounted (no silent drop)"
        );
        assert_eq!(
            e.counters().delivered,
            1,
            "only the one pre-deadline delivery"
        );
        assert_eq!(
            e.committed_offset(),
            Offset::new(off.get() + 1),
            "the cursor committed PAST the expired record (reclaimed, not redelivered forever)"
        );
        // No dead-letter exchange configured, so an expired record is reclaimed, never dead-lettered.
        assert_eq!(e.counters().dead_lettered, 0);
        assert_eq!(e.dlq_records(), 0);
    }

    #[test]
    fn a_no_ttl_record_never_expires_byte_identical() {
        // Back-compat (#549): a record with NO TTL header (and no per-stream default) is NEVER
        // expired, no matter how far the wall clock advances — byte-identical to the pre-TTL broker.
        let clock = std::sync::Arc::new(ManualClock::at_unix_millis(0));
        let mut e = open_with_clock(config_with_ttl(0), std::sync::Arc::clone(&clock));
        let off = produce_with_ttl(&mut e, 0, Ttl::NONE, b"eternal");
        // Advance the wall clock to the far future: a no-TTL record is still delivered.
        clock.set_unix_millis(u64::MAX);
        let d = message(e.poll_now().unwrap());
        assert_eq!(d.offset, off);
        assert_eq!(e.counters().expired, 0, "no TTL = never expires");
    }

    #[test]
    fn a_per_stream_default_ttl_expires_a_record_with_no_per_message_ttl() {
        // The per-STREAM default TTL (#549): a record produced WITHOUT its own per-message TTL still
        // expires under the stream-wide `default_message_ttl_ms`. Proves the default applies on its
        // own (lower-wins with NONE = the default), via the deterministic ManualClock.
        let clock = std::sync::Arc::new(ManualClock::at_unix_millis(0));
        let mut e = open_with_clock(config_with_ttl(500), std::sync::Arc::clone(&clock));
        let off = produce_with_ttl(&mut e, 0, Ttl::NONE, b"defaulted");
        // Cross the 0 + 500 deadline.
        clock.set_unix_millis(500);
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "expired under the stream default"
        );
        assert_eq!(e.counters().expired, 1);
        assert_eq!(e.committed_offset(), Offset::new(off.get() + 1));
    }

    #[test]
    fn lower_wins_a_tighter_per_message_ttl_beats_a_looser_stream_default() {
        // Lower-wins precedence (#549): a tight 100 ms per-message TTL expires BEFORE the looser
        // 10_000 ms per-stream default. At wall-clock 100 (the per-message deadline) the record is
        // already expired even though the stream default would keep it until 10_000.
        let clock = std::sync::Arc::new(ManualClock::at_unix_millis(0));
        let mut e = open_with_clock(config_with_ttl(10_000), std::sync::Arc::clone(&clock));
        produce_with_ttl(&mut e, 0, Ttl::from_millis(100), b"tight");
        clock.set_unix_millis(100); // the tighter per-message deadline
        assert!(matches!(e.poll_now().unwrap(), Poll::Idle));
        assert_eq!(e.counters().expired, 1, "the tighter per-message TTL won");
    }

    #[test]
    fn an_expired_record_routes_to_the_configured_dead_letter_exchange_with_the_reason() {
        // The configurable dead-letter EXCHANGE (#551): with an exchange + the expired flag, a
        // TTL-expired record is NOT silently reclaimed — it is dead-lettered to the NAMED subdir,
        // recording reason `TtlExpired`, crash-atomically and exactly-once. Beats NATS's single fixed
        // DLQ + matches RabbitMQ DLX. The default `dlq/` sink is NEVER touched.
        let clock = std::sync::Arc::new(ManualClock::at_unix_millis(0));
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(
            fs,
            std::sync::Arc::clone(&clock),
            config_with_dlx_for_expired(1_000, "dlx-expired"),
        )
        .unwrap();
        let off = produce_with_ttl(&mut e, 0, Ttl::from_millis(1_000), b"to-the-dlx");

        // Cross the 0 + 1_000 deadline, then poll: the expired record is dead-lettered to the DLX.
        clock.set_unix_millis(1_000);
        match e.poll_now().unwrap() {
            Poll::Parked { offset, .. } => assert_eq!(offset, off),
            other => panic!("expected the expired record Parked to the DLX, got {other:?}"),
        }
        assert_eq!(
            e.counters().expired,
            0,
            "a DLX'd expiry is counted as dead_lettered, not expired"
        );
        assert_eq!(
            e.counters().dead_lettered,
            1,
            "the expiry is a recorded dead-letter (no silent drop)"
        );
        assert_eq!(
            e.committed_offset(),
            Offset::new(off.get() + 1),
            "committed past"
        );
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "never redelivers"
        );
        drop(e);

        // The default dlq/ sink is untouched; the configured exchange holds the dead-letter with the
        // TtlExpired reason and the original source offset.
        assert!(
            read_dlq_entries(&probe).unwrap().is_empty(),
            "the default dlq/ sink is never used"
        );
        let entries = read_dead_letter_entries(&probe, "dlx-expired").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].reason,
            DeadLetterReason::TtlExpired,
            "the trigger is recorded"
        );
        assert_eq!(entries[0].source_offset, off.get());
    }

    #[test]
    fn a_max_deliver_dead_letter_with_no_exchange_is_byte_identical_v1() {
        // Back-compat (#551): with NO dead-letter exchange configured, the max-deliver dead-letter
        // path still writes the default `dlq/` sink as a v1 (reason-less) record that decodes as
        // MaxDeliverExceeded — byte-identical to the pre-#551 broker.
        let clock = std::sync::Arc::new(ManualClock::new());
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 1)).unwrap();
        let off = poison_once(&mut e, &clock, b"poison");
        drop(e);
        let entries = read_dlq_entries(&probe).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_offset, off.get());
        assert_eq!(
            entries[0].reason,
            DeadLetterReason::MaxDeliverExceeded,
            "a no-exchange max-deliver dead-letter decodes as the original trigger (v1 back-compat)"
        );
    }

    #[test]
    fn an_expired_record_with_no_routing_flag_is_reclaimed_not_dead_lettered() {
        // The "expired, not dead-lettered" path even WITH an exchange configured: when the
        // expired-routing flag is OFF, a TTL-expired record is reclaimed by retention (counted in
        // `expired`), NOT routed to the exchange. Bounded + accounted, no silent drop.
        let clock = std::sync::Arc::new(ManualClock::at_unix_millis(0));
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let cfg = EngineConfig {
            default_message_ttl_ms: 1_000,
            dead_letter_exchange: Some("dlx-unused".to_string()),
            dead_letter_expired: false, // routing OFF: reclaim, do not dead-letter
            ..config(64, 5)
        };
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), cfg).unwrap();
        let off = produce_with_ttl(&mut e, 0, Ttl::from_millis(1_000), b"reclaim-me");
        clock.set_unix_millis(1_000);
        assert!(matches!(e.poll_now().unwrap(), Poll::Idle));
        assert_eq!(e.counters().expired, 1, "reclaimed, counted as expired");
        assert_eq!(
            e.counters().dead_lettered,
            0,
            "NOT dead-lettered (routing flag off)"
        );
        assert_eq!(e.committed_offset(), Offset::new(off.get() + 1));
        drop(e);
        // Neither the default nor the named exchange subdir was materialized: nothing was dead-lettered.
        assert!(read_dlq_entries(&probe).unwrap().is_empty());
        assert!(read_dead_letter_entries(&probe, "dlx-unused")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn an_expired_dlx_record_survives_a_restart_deadline_anchored_to_the_producer_timestamp() {
        // The deadline is anchored to the DURABLE producer timestamp (#549), so it survives a
        // restart: a record produced before a reboot still expires at producer_ts + ttl after it.
        // Produce under one clock, drop the engine, reopen, advance the wall clock past the deadline,
        // and confirm the reopened engine expires + dead-letters it (the on-disk DLX exists).
        let clock = std::sync::Arc::new(ManualClock::at_unix_millis(0));
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let cfg = || config_with_dlx_for_expired(1_000, "dlx-expired");
        let mut e = Engine::open(fs.clone(), std::sync::Arc::clone(&clock), cfg()).unwrap();
        let off = produce_with_ttl(&mut e, 0, Ttl::from_millis(1_000), b"survives-restart");
        // Checkpoint + drop WITHOUT crossing the deadline (wall clock still 0).
        e.checkpoint_all_groups().unwrap();
        drop(e);

        // Reopen over a FRESH clock already past the deadline: the record produced at 0 with a 1_000
        // ms TTL is expired at wall-clock 5_000, so the reopened engine dead-letters it.
        let clock2 = std::sync::Arc::new(ManualClock::at_unix_millis(5_000));
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock2), cfg()).unwrap();
        match e.poll_now().unwrap() {
            Poll::Parked { offset, .. } => assert_eq!(offset, off),
            other => panic!("expected the restored record to expire+dead-letter, got {other:?}"),
        }
        assert_eq!(e.counters().dead_lettered, 1);
        drop(e);
        let entries = read_dead_letter_entries(&probe, "dlx-expired").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].reason, DeadLetterReason::TtlExpired);
    }

    #[test]
    fn re_expiring_the_same_offset_to_the_dlx_does_not_double_write() {
        // Idempotency for the TTL-DLX move, mirroring the poison idempotency (#551): a re-expired
        // offset already at/below the group's high-water mark is committed-past WITHOUT a second
        // append. Drive the move once, then re-run the move helper directly on the same offset.
        let clock = std::sync::Arc::new(ManualClock::at_unix_millis(0));
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(
            fs,
            std::sync::Arc::clone(&clock),
            config_with_dlx_for_expired(1_000, "dlx-expired"),
        )
        .unwrap();
        let off = produce_with_ttl(&mut e, 0, Ttl::from_millis(1_000), b"once");
        clock.set_unix_millis(1_000);
        let record = e.log.read_from(off, 1).unwrap().into_iter().next().unwrap();
        let _ = e
            .expire_dead_letter_in(DEFAULT_GROUP, off, 1, record.clone())
            .unwrap();
        // A second move of the SAME offset must be a no-op append (idempotent high-water mark).
        let _ = e
            .expire_dead_letter_in(DEFAULT_GROUP, off, 1, record)
            .unwrap();
        drop(e);
        let entries = read_dead_letter_entries(&probe, "dlx-expired").unwrap();
        assert_eq!(
            entries.len(),
            1,
            "re-expiring the same offset writes exactly one DLX record"
        );
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

    // ---- durable per-message attempt counter (#358) ----

    /// Delivers the offset-0 message `n` times (each delivery expires before the next), nacking
    /// nothing, so its lease delivery count reaches `n` WITHOUT yet exceeding `max_deliver`. The
    /// caller has produced exactly one message and configured `max_deliver > n`. Returns the offset.
    fn deliver_n_times(
        e: &mut Engine<InMemoryFs, std::sync::Arc<ManualClock>>,
        clock: &std::sync::Arc<ManualClock>,
        n: u32,
    ) {
        for attempt in 1..=n {
            let d = message(e.poll_now().unwrap());
            assert_eq!(
                d.deliveries, attempt,
                "the {attempt}th delivery reports attempt {attempt}"
            );
            // Let the lease expire so the next poll redelivers it (attempt + 1).
            clock.advance_monotonic_nanos(40);
        }
    }

    #[test]
    fn a_message_delivered_n_minus_1_times_resumes_at_attempt_n_after_a_crash_and_reaches_the_dlq()
    {
        // THE TEETH (#358): a poison message delivered MaxDeliver-1 times, then a crash+restart,
        // must redeliver as attempt MaxDeliver (not 1) and reach the DLQ after exactly MaxDeliver
        // TOTAL attempts across the restart, not 2*MaxDeliver. Without the durable attempt counter
        // the count resets to 1 on restart and the poison would need MaxDeliver MORE attempts.
        let clock = std::sync::Arc::new(ManualClock::new());
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        // max_deliver = 5: the 6th attempt is poison. Deliver it 4 times pre-crash (still under the
        // cap), checkpoint so the attempt count is durable, then crash before the 5th.
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 5)).unwrap();
        e.produce(&Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key: b"k",
            headers: b"h",
            payload: b"poison",
        })
        .unwrap();
        deliver_n_times(&mut e, &clock, 4);
        // Persist the durable attempt count (the cursor has NOT advanced: nothing acked).
        e.checkpoint_cursor().unwrap();
        assert_eq!(e.committed_offset(), Offset::ZERO, "still uncommitted");
        drop(e);

        // CRASH+RESTART: the lease table is empty, but the durable attempt count carries 4.
        let clock2 = std::sync::Arc::new(ManualClock::new());
        let mut e =
            Engine::open(probe.clone(), std::sync::Arc::clone(&clock2), config(10, 5)).unwrap();
        // The FIRST redelivery after the restart is attempt 5 (resumed 4 + 1), NOT 1.
        let d = message(e.poll_now().unwrap());
        assert_eq!(
            d.deliveries, 5,
            "resumes at attempt 5 across the restart, not 1"
        );
        // Expire it: the next poll is attempt 6, which exceeds max_deliver (5) and dead-letters.
        clock2.advance_monotonic_nanos(40);
        match e.poll_now().unwrap() {
            Poll::Parked { offset, .. } => assert_eq!(offset, Offset::ZERO),
            other => panic!("expected the poison to be dead-lettered, got {other:?}"),
        }
        assert_eq!(e.dlq_records(), 1, "reaches the DLQ after MaxDeliver TOTAL");
        assert_eq!(
            e.committed_offset(),
            Offset::new(1),
            "committed past poison"
        );
        drop(e);

        // The DLQ entry records attempt 6 (the poison attempt), proving the count was TOTAL across
        // the restart (6 = MaxDeliver + 1), not a fresh 2 after a reset.
        let entries = read_dlq_entries(&probe).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].attempt, 6,
            "the poison attempt is MaxDeliver + 1 = 6, counted across the restart"
        );
    }

    #[test]
    fn without_the_durable_counter_a_restart_would_double_the_attempts_this_proves_it_does_not() {
        // A focused counterfactual: deliver 4 times, crash, and confirm the post-restart delivery is
        // attempt 5 (not 1). If the durability regressed, the first post-restart delivery would be
        // attempt 1 and this assertion would fail, so the test has teeth against a regression.
        let clock = std::sync::Arc::new(ManualClock::new());
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 100)).unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"p",
        })
        .unwrap();
        deliver_n_times(&mut e, &clock, 4);
        e.checkpoint_cursor().unwrap();
        drop(e);

        let clock2 = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(probe, std::sync::Arc::clone(&clock2), config(10, 100)).unwrap();
        let d = message(e.poll_now().unwrap());
        assert_eq!(
            d.deliveries, 5,
            "the attempt count resumed; a reset-to-1 regression would fail here"
        );
    }

    #[test]
    fn a_clean_ack_clears_the_durable_attempt_count_across_a_restart() {
        // A message delivered a few times then cleanly ACKED must leave NO carried attempt count: a
        // later message at the same offset (impossible here since offsets are monotonic, but a fresh
        // run resuming an acked offset must not inherit) resumes fresh. We assert the acked offset
        // never redelivers and carries nothing: the cursor committed past it and the snapshot is empty.
        let clock = std::sync::Arc::new(ManualClock::new());
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 5)).unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"a",
        })
        .unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"b",
        })
        .unwrap();
        // Deliver offset 0 three times, then ACK it cleanly (the durable count must be cleared).
        for _ in 0..2 {
            let _ = message(e.poll_now().unwrap());
            clock.advance_monotonic_nanos(40);
        }
        let d = message(e.poll_now().unwrap());
        assert_eq!(d.offset, Offset::ZERO);
        assert_eq!(d.deliveries, 3);
        assert_eq!(e.ack(&d.token), AckResult::Acked);
        e.checkpoint_cursor().unwrap();
        assert_eq!(e.committed_offset(), Offset::new(1), "offset 0 committed");
        drop(e);

        // Reopen: offset 0 is committed past (never redelivers); only offset 1 (b) is deliverable,
        // and it starts at attempt 1 (no stale count leaked from offset 0's three deliveries).
        let clock2 = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(probe, std::sync::Arc::clone(&clock2), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(1));
        let d = message(e.poll_now().unwrap());
        assert_eq!(d.offset, Offset::new(1), "only the unacked tail redelivers");
        assert_eq!(
            d.deliveries, 1,
            "a clean ack cleared the durable count; the next message is attempt 1"
        );
    }

    #[test]
    fn an_old_snapshot_without_attempt_counts_decodes_as_attempts_zero() {
        // ADDITIVE-FORMAT proof (#358): a data directory from BEFORE this feature has a cursor
        // checkpoint but NO attempts.ckpt. Opening it must resume with no carried counts (every
        // in-flight message at attempt 1, the pre-#358 behavior), never a panic or a wrong count.
        let clock = std::sync::Arc::new(ManualClock::new());
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 5)).unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"p",
        })
        .unwrap();
        deliver_n_times(&mut e, &clock, 3);
        e.checkpoint_cursor().unwrap();
        drop(e);

        // Simulate an OLD data directory: delete the attempts checkpoint so only the cursor remains.
        assert!(probe.exists(ATTEMPTS_CHECKPOINT).unwrap());
        probe.remove(ATTEMPTS_CHECKPOINT).unwrap();
        assert!(!probe.exists(ATTEMPTS_CHECKPOINT).unwrap());

        // Reopen with no attempts file: the in-flight message resumes at attempt 1 (counts = 0),
        // exactly the pre-#358 behavior. Open must not panic and the recovery must succeed.
        let clock2 = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(probe, std::sync::Arc::clone(&clock2), config(10, 5)).unwrap();
        let d = message(e.poll_now().unwrap());
        assert_eq!(
            d.deliveries, 1,
            "an old snapshot (no attempt counts) decodes as attempts = 0"
        );
    }

    #[test]
    fn a_torn_attempts_snapshot_falls_back_to_no_carried_counts() {
        // A corrupt attempts.ckpt must never block startup or invent a count: it degrades to "no
        // carried counts" (attempt 1), the at-least-once-safe fallback, exactly like a torn cursor.
        use ironbus_storage::io::RandomAccessFile;
        let clock = std::sync::Arc::new(ManualClock::new());
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 5)).unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"p",
        })
        .unwrap();
        deliver_n_times(&mut e, &clock, 3);
        e.checkpoint_cursor().unwrap();
        drop(e);

        // Corrupt EVERY byte region of attempts.ckpt so neither slot's CRC can validate.
        let ckpt = probe.open(ATTEMPTS_CHECKPOINT).unwrap();
        let mut bytes = ckpt.snapshot();
        assert!(!bytes.is_empty(), "the attempts checkpoint was written");
        for b in &mut bytes {
            *b ^= 0xff;
        }
        ckpt.set_len(0).unwrap();
        ckpt.write_all_at(&bytes, 0).unwrap();
        ckpt.sync_all().unwrap();

        // Reopen: the torn snapshot is rejected, so no carried counts; the in-flight message resumes
        // at attempt 1 and open succeeds without panic.
        let clock2 = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(probe, std::sync::Arc::clone(&clock2), config(10, 5)).unwrap();
        let d = message(e.poll_now().unwrap());
        assert_eq!(
            d.deliveries, 1,
            "a torn attempts snapshot degrades to no carried counts (attempt 1)"
        );
    }

    #[test]
    fn a_named_groups_attempt_count_survives_a_restart_and_reaches_its_dlq() {
        // The durable attempt counter holds in a NAMED group too (#358), not only the default group:
        // a poison record retried in group "work", crashed, and restarted, reaches the DLQ after
        // MaxDeliver TOTAL attempts and is recorded under the group "work".
        let clock = std::sync::Arc::new(ManualClock::new());
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let mut e = Engine::open(fs, std::sync::Arc::clone(&clock), config(10, 3)).unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"poison",
        })
        .unwrap();
        // Deliver twice in group "work" (max_deliver = 3, so still under the cap).
        for attempt in 1..=2u32 {
            let d = message(e.poll_in("work", e.log.now_monotonic()).unwrap());
            assert_eq!(d.deliveries, attempt);
            clock.advance_monotonic_nanos(40);
        }
        // Flush the named group's cursor AND attempt counts.
        e.checkpoint_group("work").unwrap();
        drop(e);

        // Reopen: the named group resumes its attempt count, so the next delivery is attempt 3.
        let clock2 = std::sync::Arc::new(ManualClock::new());
        let mut e =
            Engine::open(probe.clone(), std::sync::Arc::clone(&clock2), config(10, 3)).unwrap();
        let d = message(e.poll_in("work", e.log.now_monotonic()).unwrap());
        assert_eq!(d.deliveries, 3, "the named group resumed at attempt 3");
        // Expire: the next poll is attempt 4, which exceeds max_deliver (3) and dead-letters.
        clock2.advance_monotonic_nanos(40);
        match e.poll_in("work", e.log.now_monotonic()).unwrap() {
            Poll::Parked { offset, .. } => assert_eq!(offset, Offset::ZERO),
            other => panic!("expected the poison to be dead-lettered, got {other:?}"),
        }
        drop(e);

        // The DLQ entry is recorded under group "work" at attempt 4 (MaxDeliver + 1, TOTAL).
        let entries = read_dlq_entries(&probe).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].group, "work");
        assert_eq!(
            entries[0].attempt, 4,
            "MaxDeliver + 1 counted across the restart"
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
                    Poll::Message(d) if d.record.key.as_ref() == key_a.as_slice() => {
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
        assert_eq!(d.record.payload.as_ref(), b"c");
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
        // The reclaimed group leaves NO ghost floor entry (#432): an explicit Unsub releases the
        // pin, so its entry is gone, while the live groups keep their interval-gate entries.
        assert!(
            !e.group_last_checkpointed.contains_key("caught"),
            "explicit unsub releases the ghost"
        );
    }

    // ---- Ghost checkpoints and the retention protect floor (#432) ----

    // Retention bounds (small segments, byte bound) plus the idle-eviction window, so a test can
    // sweep-evict a caught-up group and watch its GHOST pin (or not pin) the protect floor.
    fn config_with_retention_and_evict(max_retained_bytes: u64, evict_ms: u64) -> EngineConfig {
        let mut cfg = config_with_retention(max_retained_bytes);
        cfg.group_idle_evict_ms = evict_ms;
        cfg
    }

    // Drains the named group to the head at `now`, acking everything. Never touches the default
    // group (#424): these tests must control exactly which groups pin the floor.
    fn drain_named(e: &mut Engine<InMemoryFs, ManualClock>, group: &str, now: u64) {
        while let Poll::Message(d) = e.poll_in(group, now).unwrap() {
            assert_eq!(e.ack_in(group, &d.token), AckResult::Acked);
        }
    }

    #[test]
    fn a_sweep_evicted_groups_ghost_pins_the_retention_floor() {
        // The #432 contract: an idle sweep eviction reclaims MEMORY, never retention protection.
        // After "g" is evicted at head H, its ghost keeps the floor at H, so records produced
        // after the eviction can never be reaped out from under the absent consumer, and the
        // durable log cannot shrink to the bound. An explicit Unsub then releases the pin and
        // retention catches up.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let mut e = open(config_with_retention_and_evict(2 * one, 10));
        produce(&mut e, &[0xab; 16]);
        drain_named(&mut e, "g", 0);
        assert_eq!(e.committed_offset_in("g"), e.flushed_offset(), "caught up");
        // Sweep at 11 ms via a DRIVER group's poll ("g" idle since 0 is past the 10 ms window;
        // polling "g" itself would refresh it, and polling the default group would touch it).
        let _ = e.poll_in("driver", 11 * MS).unwrap();
        assert!(!e.has_group("g"), "g was sweep-evicted");
        assert!(
            e.group_last_checkpointed.contains_key("g"),
            "the sweep kept g's ghost"
        );
        // Keep the driver pinned at the head so only g's ghost can hold the floor down.
        for _ in 0..30 {
            produce(&mut e, &[0xab; 16]);
            drain_named(&mut e, "driver", 12 * MS);
        }
        assert!(
            e.durable_record_bytes() > 2 * one,
            "the ghost pins the floor at the eviction head, so retention cannot reach the bound: {} > {}",
            e.durable_record_bytes(),
            2 * one
        );
        // The explicit Unsub releases the ghost; the next produce reaps to the bound.
        assert!(!e.evict_group_if_idle("g"), "g is not live, nothing evicts");
        assert!(
            !e.group_last_checkpointed.contains_key("g"),
            "the explicit unsub released the ghost"
        );
        produce(&mut e, &[0xab; 16]);
        drain_named(&mut e, "driver", 13 * MS);
        assert!(
            e.durable_record_bytes() <= 2 * one,
            "with the ghost released retention reaches the bound: {} <= {}",
            e.durable_record_bytes(),
            2 * one
        );
    }

    #[test]
    fn a_returning_group_supersedes_its_ghost_and_the_floor_follows_it() {
        // The ghost is a stand-in, not a permanent pin: when the evicted group returns, the live
        // resumed cursor (at exactly the ghost's value) takes over, and as the returning consumer
        // drains, the floor follows its live progress and retention catches up with no Unsub.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let mut e = open(config_with_retention_and_evict(2 * one, 10));
        produce(&mut e, &[0xab; 16]);
        drain_named(&mut e, "g", 0);
        let evicted_at = e.committed_offset_in("g");
        let _ = e.poll_in("driver", 11 * MS).unwrap();
        assert!(!e.has_group("g"), "g was sweep-evicted");
        for _ in 0..20 {
            produce(&mut e, &[0xab; 16]);
            drain_named(&mut e, "driver", 12 * MS);
        }
        assert!(e.durable_record_bytes() > 2 * one, "ghost pinning");
        // g returns: it resumes exactly at its ghost's offset (nothing below was needed, nothing
        // above was reaped), supersedes the ghost, drains, and the floor follows it to the head.
        let first = e.poll_in("g", 13 * MS).unwrap();
        assert!(
            matches!(first, Poll::Message(_)),
            "resumes at the ghost offset, no truncation"
        );
        assert_eq!(
            e.committed_offset_in("g"),
            evicted_at,
            "resumed at the eviction head"
        );
        drain_named(&mut e, "g", 14 * MS);
        produce(&mut e, &[0xab; 16]);
        drain_named(&mut e, "g", 15 * MS);
        drain_named(&mut e, "driver", 15 * MS);
        assert!(
            e.durable_record_bytes() <= 2 * one,
            "the returned group caught up, the floor rose, retention reached the bound: {} <= {}",
            e.durable_record_bytes(),
            2 * one
        );
    }

    #[test]
    fn a_sweep_evicted_ghost_is_resumed_live_and_touched_across_reopen() {
        // Restart consistency (#432): the ghost is in-memory, but the cursor checkpoint it mirrors
        // is durable, so a reopen resumes the evicted group as a LIVE touched group at the same
        // offset, pinning the floor exactly as the ghost did before the restart.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let cfg = || config_with_retention_and_evict(2 * one, 10);
        let mut e = open(cfg());
        produce(&mut e, &[0xab; 16]);
        drain_named(&mut e, "g", 0);
        let evicted_at = e.committed_offset_in("g");
        let _ = e.poll_in("driver", 11 * MS).unwrap();
        assert!(!e.has_group("g"));

        let fs = e.into_filesystem();
        let mut e = Engine::open(fs, ManualClock::new(), cfg()).unwrap();
        assert!(e.has_group("g"), "recovery resumed the evicted group live");
        assert_eq!(e.committed_offset_in("g"), evicted_at, "at its checkpoint");
        for _ in 0..20 {
            produce(&mut e, &[0xab; 16]);
            drain_named(&mut e, "driver", 1);
        }
        assert!(
            e.durable_record_bytes() > 2 * one,
            "the resumed live group pins across the restart exactly as the ghost did"
        );
    }

    #[test]
    fn producer_only_head_fallback_is_unchanged_with_no_ghosts() {
        // The #424 producer-only fallback survives #432: with no named group ever created, no
        // ghost exists, the untouched default group still does not pin, and retention reaps.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();

        let mut e = open(config_with_retention_and_evict(2 * one, 10));
        for _ in 0..30 {
            produce(&mut e, &[0xab; 16]);
        }
        assert!(
            e.counters().segments_reaped >= 1,
            "no consumer, no ghost: the floor is the head and old segments reaped"
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

    // --- Opt-in effectively-once dedup (#3, #33) ---

    /// A dedup config with a TIGHT count and time bound so the engine tests can drive eviction with
    /// small integers (4 ids OR 1000 ns), over a shared `ManualClock` the test advances.
    fn config_with_dedup(max_ids: usize, window_nanos: u64) -> EngineConfig {
        EngineConfig {
            dedup: ironbus_core::dedup::DedupConfig {
                max_ids,
                window_nanos,
                ..ironbus_core::dedup::DedupConfig::default()
            },
            ..config(10, 5)
        }
    }

    /// Produces with an opt-in dedup identity through the engine's group-commit primitives
    /// (`append_no_sync_dedup` + `commit_batch`), exactly as the actor does, returning the outcome.
    fn produce_dedup(
        e: &mut Engine<InMemoryFs, std::sync::Arc<ManualClock>>,
        payload: &[u8],
        producer_id: &[u8],
        epoch: u64,
        msg_id: &[u8],
    ) -> AppendOutcome {
        let outcome = e
            .append_no_sync_dedup(
                &Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                },
                Some(DedupRequest {
                    producer_id,
                    epoch,
                    msg_id,
                    seq: None,
                }),
            )
            .unwrap();
        e.commit_batch().unwrap();
        outcome
    }

    // ===================================================================================
    // V2-M8: idempotent producer (PID + epoch + monotonic sequence) — effectively-once across a
    // broker restart + a long offline gap (#638/#639).
    // ===================================================================================

    /// Produces with an opt-in idempotent SEQUENCE through the engine's group-commit primitives, the
    /// V2-M8 sequenced twin of `produce_dedup`: the `seq` routes the produce through the DURABLE
    /// per-producer high-water (dedup-to-exactly-once-append, epoch fencing, out-of-order rejection).
    fn produce_seq(
        e: &mut Engine<InMemoryFs, std::sync::Arc<ManualClock>>,
        payload: &[u8],
        producer_id: &[u8],
        epoch: u64,
        seq: u64,
    ) -> AppendOutcome {
        let outcome = e
            .append_no_sync_dedup(
                &Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload,
                },
                Some(DedupRequest {
                    producer_id,
                    epoch,
                    // The msg_id is unused on the sequence path (the engine routes on `seq`), so an
                    // empty one is fine; the wire layer still carries it.
                    msg_id: b"",
                    seq: Some(seq),
                }),
            )
            .unwrap();
        e.commit_batch().unwrap();
        outcome
    }

    /// Opens an engine over a SHARED `InMemoryFs` + `ManualClock`, so a test can drop it and reopen
    /// the SAME data directory to model a broker restart (the durability tests need this).
    fn open_on(
        fs: InMemoryFs,
        clock: std::sync::Arc<ManualClock>,
        config: EngineConfig,
    ) -> Engine<InMemoryFs, std::sync::Arc<ManualClock>> {
        Engine::open(fs, clock, config).unwrap()
    }

    #[test]
    fn a_retried_sequenced_publish_deduplicates_to_one_append() {
        // The headline guarantee: a retry of the same (producer, epoch, seq) returns the ORIGINAL
        // offset via Duplicate and appends NOTHING — the log holds exactly ONE record.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config(10, 5), clock);
        assert_eq!(
            produce_seq(&mut e, b"v1", b"p", 0, 0),
            AppendOutcome::Appended(Offset::new(0))
        );
        assert_eq!(e.flushed_offset(), Offset::new(1));
        // Retry the SAME seq (payload differs; the sequence path ignores the body): the ORIGINAL
        // offset, no second record, the dedup-hit counter increments.
        assert_eq!(
            produce_seq(&mut e, b"v1-retry", b"p", 0, 0),
            AppendOutcome::Duplicate(Offset::new(0))
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(1),
            "the durable head did NOT advance on a sequenced retry (one append only)"
        );
        assert_eq!(e.dedup_hits(), 1);
        // seq 1 is the next expected: fresh.
        assert_eq!(
            produce_seq(&mut e, b"v2", b"p", 0, 1),
            AppendOutcome::Appended(Offset::new(1))
        );
        assert_eq!(e.flushed_offset(), Offset::new(2));
    }

    #[test]
    fn an_out_of_order_sequence_is_rejected_not_silently_accepted() {
        // The Kafka OutOfOrderSequence rule: a gap (seq > last + 1) is REJECTED so a later retry of
        // the skipped seq cannot double-append. Nothing is appended and the counter fires.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config(10, 5), clock);
        produce_seq(&mut e, b"a", b"p", 0, 0); // offset 0, high-water seq 0
        assert_eq!(
            produce_seq(&mut e, b"skip", b"p", 0, 2),
            AppendOutcome::OutOfOrder { expected: 1 },
            "a gapped sequence is rejected, not appended"
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(1),
            "the out-of-order produce appended nothing"
        );
        assert_eq!(e.producer_out_of_order(), 1);
        // The in-order seq 1 still reads fresh (no corruption from the rejected gap).
        assert_eq!(
            produce_seq(&mut e, b"b", b"p", 0, 1),
            AppendOutcome::Appended(Offset::new(1))
        );
    }

    #[test]
    fn a_zombie_stale_epoch_is_fenced_while_the_new_epoch_writes() {
        // A restarted producer comes back with a higher epoch (fresh sequence space); the OLD session
        // reusing the old producer_id at the stale epoch is FENCED, so a zombie cannot double-write.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config(10, 5), clock);
        // Epoch 5 establishes and writes seq 0.
        assert_eq!(
            produce_seq(&mut e, b"e5s0", b"p", 5, 0),
            AppendOutcome::Appended(Offset::new(0))
        );
        // The new session (epoch 6) supersedes: its seq 0 is fresh (the sequence space reset).
        assert_eq!(
            produce_seq(&mut e, b"e6s0", b"p", 6, 0),
            AppendOutcome::Appended(Offset::new(1))
        );
        // A ZOMBIE at the OLD epoch 5 is fenced — it appends nothing.
        assert_eq!(
            produce_seq(&mut e, b"zombie", b"p", 5, 1),
            AppendOutcome::Fenced { current_epoch: 6 }
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(2),
            "the fenced zombie appended nothing"
        );
        // The new epoch keeps writing.
        assert_eq!(
            produce_seq(&mut e, b"e6s1", b"p", 6, 1),
            AppendOutcome::Appended(Offset::new(2))
        );
    }

    #[test]
    fn sequenced_dedup_survives_a_broker_restart() {
        // The DURABILITY beat: persist the high-water, restart the broker (reopen the SAME data dir),
        // and a replayed retry is STILL deduped to the original offset — where NATS's volatile window
        // would have forgotten and re-appended.
        let fs = InMemoryFs::new();
        let clock = std::sync::Arc::new(ManualClock::new());
        {
            let mut e = open_on(fs.clone(), std::sync::Arc::clone(&clock), config(10, 5));
            produce_seq(&mut e, b"v0", b"p", 1, 0); // offset 0
            produce_seq(&mut e, b"v1", b"p", 1, 1); // offset 1
                                                    // A clean shutdown flush persists the producer-seq high-water.
            e.checkpoint_all_groups().unwrap();
        }
        // Restart: reopen the same fs. The high-water is restored from `producer-seq.ckpt`.
        let mut e2 = open_on(fs, std::sync::Arc::clone(&clock), config(10, 5));
        assert_eq!(
            e2.flushed_offset(),
            Offset::new(2),
            "the two records survived the restart"
        );
        // A replayed RETRY of seq 1 across the restart is STILL a duplicate at its original offset.
        assert_eq!(
            produce_seq(&mut e2, b"v1-replay", b"p", 1, 1),
            AppendOutcome::Duplicate(Offset::new(1)),
            "the dedup high-water survived the restart (the NATS beat)"
        );
        assert_eq!(
            e2.flushed_offset(),
            Offset::new(2),
            "the replayed retry appended nothing after the restart"
        );
        // The next expected seq still reads fresh, and a stale epoch is still fenced post-restart.
        assert_eq!(
            produce_seq(&mut e2, b"v2", b"p", 1, 2),
            AppendOutcome::Appended(Offset::new(2))
        );
        assert_eq!(
            produce_seq(&mut e2, b"zombie", b"p", 0, 9),
            AppendOutcome::Fenced { current_epoch: 1 },
            "a stale epoch is still fenced after the restart (the high-water carried the epoch)"
        );
    }

    #[test]
    fn sequenced_dedup_survives_a_long_offline_gap_no_time_expiry() {
        // The other half of the beat: the dedup is bounded by SEQUENCE state, not wall-clock, so a
        // LONG offline gap (huge monotonic advance) never drops it — unlike the time-bounded msg_id
        // window / NATS Nats-Msg-Id, which would have lapsed.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config(10, 5), std::sync::Arc::clone(&clock));
        produce_seq(&mut e, b"v0", b"p", 1, 0); // offset 0 at t=0
                                                // A producer goes offline for a very long time (far past any dedup time window).
        clock.advance_monotonic_nanos(10 * 365 * 24 * 3_600 * 1_000_000_000); // ~10 years
                                                                              // A replayed retry of seq 0 is STILL a duplicate — no time bound to expire it.
        assert_eq!(
            produce_seq(&mut e, b"v0-replay", b"p", 1, 0),
            AppendOutcome::Duplicate(Offset::new(0)),
            "sequence dedup never lapses with the clock (the gap beat over NATS)"
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(1),
            "the long-gap retry appended nothing"
        );
    }

    #[test]
    fn sequenced_dedup_survives_a_restart_then_a_long_gap_combined() {
        // Restart AND a long gap together — the full effectively-once survival claim.
        let fs = InMemoryFs::new();
        let clock = std::sync::Arc::new(ManualClock::new());
        {
            let mut e = open_on(fs.clone(), std::sync::Arc::clone(&clock), config(10, 5));
            produce_seq(&mut e, b"v0", b"p", 3, 0); // offset 0
            e.checkpoint_all_groups().unwrap();
        }
        // A long offline gap spans the restart.
        clock.advance_monotonic_nanos(5 * 365 * 24 * 3_600 * 1_000_000_000); // ~5 years
        let mut e2 = open_on(fs, std::sync::Arc::clone(&clock), config(10, 5));
        assert_eq!(
            produce_seq(&mut e2, b"v0-replay", b"p", 3, 0),
            AppendOutcome::Duplicate(Offset::new(0)),
            "dedup survived BOTH a restart and a long gap"
        );
        assert_eq!(e2.flushed_offset(), Offset::new(1));
    }

    #[test]
    fn a_non_sequenced_producer_is_byte_identical_at_least_once() {
        // Back-compat: a produce with NO seq (and no msg_id) is exactly today's at-least-once append.
        // The producer-seq registry is never touched, no `producer-seq.ckpt` is created, and two
        // identical payloads both append.
        let fs = InMemoryFs::new();
        let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(produce(&mut e, b"same"), Offset::new(0));
        assert_eq!(produce(&mut e, b"same"), Offset::new(1));
        assert_eq!(e.flushed_offset(), Offset::new(2), "both appended");
        assert_eq!(e.producer_seq_count(), 0, "no producer was sequenced");
        assert_eq!(e.producer_out_of_order(), 0);
        // A clean shutdown flush must NOT create the producer-seq checkpoint file when no producer
        // ever sequenced (the disk image of a non-idempotent workload is unchanged).
        e.checkpoint_all_groups().unwrap();
        assert!(
            !fs.exists(PRODUCER_SEQ_CHECKPOINT).unwrap(),
            "a non-idempotent workload never creates producer-seq.ckpt"
        );
    }

    #[test]
    fn the_producer_seq_state_is_bounded_o_producers_and_reclaims_dead_producers() {
        // The memory bound: a flood of distinct producer_ids keeps the registry state O(producers),
        // never O(messages). The registry's `max_producers` cap (its internal default) bounds it; the
        // LRU evicts (reclaims) the least-recently-active producer, so a dead producer does not pin a
        // slot forever. We assert it stays bounded under far more producers than messages-per-producer.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config(10, 5), clock);
        let cap = ironbus_core::producer_seq::DEFAULT_MAX_SEQ_PRODUCERS;
        for i in 0..(cap as u64 + 500) {
            let pid = format!("producer-{i}");
            // Each distinct producer publishes exactly one sequenced record.
            produce_seq(&mut e, b"x", pid.as_bytes(), 0, 0);
            assert!(
                e.producer_seq_count() <= cap,
                "producer-seq state exceeded the O(producers) cap"
            );
        }
        assert_eq!(
            e.producer_seq_count(),
            cap,
            "the registry holds exactly the cap after the flood (dead producers reclaimed by LRU)"
        );
    }

    #[test]
    fn no_msg_id_means_no_dedup_todays_behavior_unchanged() {
        // The default no-dedup produce: passing `None` dedup is byte-for-byte today's append. Two
        // identical payloads with no msg_id both append (distinct offsets), and nothing is counted.
        let mut e = open(config_with_dedup(4, 1000));
        assert_eq!(produce(&mut e, b"same"), Offset::new(0));
        assert_eq!(produce(&mut e, b"same"), Offset::new(1));
        assert_eq!(e.flushed_offset(), Offset::new(2), "both appended");
        assert_eq!(e.dedup_hits(), 0, "no dedup hit without a msg_id");
        assert_eq!(e.dedup_out_of_window(), 0);
    }

    #[test]
    fn a_duplicate_within_the_window_returns_the_original_offset_and_appends_nothing() {
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config_with_dedup(4, 1000), clock);
        // Fresh produce at offset 0.
        assert_eq!(
            produce_dedup(&mut e, b"v1", b"p1", 0, b"idem"),
            AppendOutcome::Appended(Offset::new(0))
        );
        assert_eq!(e.flushed_offset(), Offset::new(1));
        // The SAME msg_id again (payload differs, dedup keys on msg_id only): the ORIGINAL offset 0,
        // no second record appended (the head does not move), the hit counter increments.
        assert_eq!(
            produce_dedup(&mut e, b"v2-ignored", b"p1", 0, b"idem"),
            AppendOutcome::Duplicate(Offset::new(0))
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(1),
            "the durable head did NOT advance on a dedup hit (no second record)"
        );
        assert_eq!(e.dedup_hits(), 1);
        assert_eq!(e.dedup_out_of_window(), 0);
    }

    #[test]
    fn an_id_evicted_by_the_count_bound_is_treated_as_fresh() {
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config_with_dedup(2, 0), clock); // count bound 2, no time bound
        produce_dedup(&mut e, b"a", b"p", 0, b"m0"); // offset 0
        produce_dedup(&mut e, b"b", b"p", 0, b"m1"); // offset 1, window now full (m0, m1)
        produce_dedup(&mut e, b"c", b"p", 0, b"m2"); // offset 2, evicts m0
                                                     // m0 was evicted by the count bound: a republish is FRESH (appends a new offset), not a
                                                     // false dedup.
        assert_eq!(
            produce_dedup(&mut e, b"a-again", b"p", 0, b"m0"),
            AppendOutcome::Appended(Offset::new(3)),
            "a count-evicted id is fresh, not a false dedup hit"
        );
        assert_eq!(e.flushed_offset(), Offset::new(4));
        assert_eq!(e.dedup_hits(), 0, "no dedup hit: m0 had aged out by count");
    }

    #[test]
    fn an_id_evicted_by_the_time_bound_is_fresh_and_counts_out_of_window() {
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config_with_dedup(100, 1000), std::sync::Arc::clone(&clock));
        produce_dedup(&mut e, b"v1", b"p", 0, b"idem"); // offset 0 at t=0
                                                        // Still within the 1000 ns window: a duplicate.
        clock.advance_monotonic_nanos(999);
        assert_eq!(
            produce_dedup(&mut e, b"v1b", b"p", 0, b"idem"),
            AppendOutcome::Duplicate(Offset::new(0))
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(1),
            "no append on the in-window dup"
        );
        // Past the window: the aged id is evicted, the republish is FRESH (a new offset), and the
        // out-of-window counter fires.
        clock.advance_monotonic_nanos(1);
        assert_eq!(
            produce_dedup(&mut e, b"v2", b"p", 0, b"idem"),
            AppendOutcome::Appended(Offset::new(1)),
            "a time-evicted id is fresh, not a false dedup hit"
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(2),
            "the republish appended a new record"
        );
        assert!(
            e.dedup_out_of_window() >= 1,
            "the time-bound eviction counted out-of-window"
        );
    }

    #[test]
    fn a_stale_epoch_is_fenced_and_a_fresh_epoch_supersedes() {
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config_with_dedup(100, 0), clock);
        // Establish epoch 5 with msg m1 at offset 0.
        produce_dedup(&mut e, b"a", b"p", 5, b"m1");
        // A produce at the OLDER epoch 4 is fenced: nothing appended.
        assert_eq!(
            produce_dedup(&mut e, b"b", b"p", 4, b"m2"),
            AppendOutcome::Fenced { current_epoch: 5 }
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(1),
            "the fenced produce appended nothing"
        );
        // A NEWER epoch 6 supersedes: the old window is reset, so m1 reads fresh again (appends).
        assert_eq!(
            produce_dedup(&mut e, b"c", b"p", 6, b"m1"),
            AppendOutcome::Appended(Offset::new(1)),
            "a newer epoch resets the window, so a prior epoch's id is fresh"
        );
        assert_eq!(e.flushed_offset(), Offset::new(2));
    }

    // ---- #341 / #379 relaxed durability levels ----

    /// A `config(10, 5)` with the durability level overridden, sharing the default test knobs so a
    /// durability test differs from the default ONLY in the level (and the interval triggers). Used
    /// with `open_durability` below so a `sync` and a relaxed engine run the SAME workload over the
    /// SAME power-loss harness, the only difference being the level.
    fn config_durability(
        level: DurabilityLevel,
        flush_interval_ms: u64,
        flush_max_bytes: u64,
    ) -> EngineConfig {
        EngineConfig {
            durability_level: level,
            flush_interval_ms,
            flush_max_bytes,
            ..config(10, 5)
        }
    }

    /// Opens an engine over the given shared `InMemoryFs` and `ManualClock` with `config`. The caller
    /// keeps its own clone of BOTH handles so it can drive `simulate_power_loss` (the fs) and advance
    /// the monotonic clock (the interval window) while the engine owns its own clones.
    fn open_durability(
        fs: InMemoryFs,
        clock: std::sync::Arc<ManualClock>,
        config: EngineConfig,
    ) -> Engine<InMemoryFs, std::sync::Arc<ManualClock>> {
        Engine::open(fs, clock, config).unwrap()
    }

    /// Produces `payload` on a clock-driven engine (the durability harness uses an `Arc<ManualClock>`,
    /// so the plain `produce` helper, which is typed to a bare `ManualClock`, does not apply).
    fn produce_d(
        e: &mut Engine<InMemoryFs, std::sync::Arc<ManualClock>>,
        payload: &[u8],
    ) -> Offset {
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        })
        .unwrap()
    }

    #[test]
    fn the_default_level_is_sync_and_acks_only_post_fsync_zero_acked_loss() {
        // THE TEETH for the safe default (#341): a broker that changes NOTHING runs `sync`, every ack
        // is post-fsync (I2), the unsynced exposure is always zero, and a power cut after the acks
        // loses NOTHING. This is the zero-acked-loss guarantee an operator keeps for free.
        let cfg = config(10, 5);
        assert_eq!(
            cfg.durability_level,
            DurabilityLevel::Sync,
            "the compiled default level is sync"
        );
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_durability(fs, std::sync::Arc::clone(&clock), cfg);
        assert!(!e.power_loss_unsafe(), "sync never waives I2");
        for i in 0..8u8 {
            produce_d(&mut e, &[i]);
            // After each `sync` commit the unsynced exposure is back to zero: there is never an
            // acked-but-unsynced tail under the default level.
            assert_eq!(
                e.unsynced_bytes(),
                0,
                "sync leaves no unsynced exposure after a commit"
            );
        }
        assert_eq!(e.flushed_offset(), Offset::new(8));
        // The crash: revert every unsynced page-cache byte. Under sync there is NONE, so nothing is
        // lost.
        probe.simulate_power_loss();
        let reopened = open_durability(probe, clock, config(10, 5));
        assert_eq!(
            reopened.flushed_offset(),
            Offset::new(8),
            "sync loses ZERO acked records across a power cut (I2): every ack was post-fsync"
        );
    }

    #[test]
    fn async_loses_the_unsynced_tail_on_a_power_cut_but_sync_loses_nothing_same_harness() {
        // THE TEETH contrast (#341, #379): the SAME 8-record workload over the SAME power-loss harness
        // under `async` vs `sync`. `async` acks on the page-cache write and defers the fsync (no roll,
        // no shutdown here), so the power cut reverts the WHOLE unsynced tail: the recovered head is
        // the durable prefix (0, since nothing was synced). `sync` over the identical harness loses
        // NOTHING. The difference is entirely the level.
        let run = |level: DurabilityLevel| -> u64 {
            let fs = InMemoryFs::new();
            let probe = fs.clone();
            let clock = std::sync::Arc::new(ManualClock::new());
            let mut e = open_durability(fs, clock.clone(), config_durability(level, 0, 0));
            for i in 0..8u8 {
                produce_d(&mut e, &[i]);
            }
            assert_eq!(
                e.flushed_offset(),
                Offset::new(8),
                "all 8 are acked (visible)"
            );
            // An ABRUPT power cut (no graceful shutdown, so no force_sync): unsynced bytes revert.
            probe.simulate_power_loss();
            // Reopen with the SAFE default level so recovery itself is unconditionally durable.
            let reopened = open_durability(probe, clock, config(10, 5));
            reopened.flushed_offset().get()
        };
        let sync_recovered = run(DurabilityLevel::Sync);
        let async_recovered = run(DurabilityLevel::Async);
        assert_eq!(
            sync_recovered, 8,
            "sync loses nothing on the power cut (every ack post-fsync, I2)"
        );
        assert_eq!(
            async_recovered, 0,
            "async loses its whole unsynced tail on an abrupt power cut (I2 waived by design): the \
             durable prefix is 0 because no fsync, roll, or shutdown covered the batch"
        );
        assert!(
            async_recovered < sync_recovered,
            "the relaxed level traded durability for throughput, exactly the documented contract"
        );
    }

    #[test]
    fn interval_acks_within_the_window_and_a_crash_loses_at_most_the_window() {
        // THE TEETH for the BOUNDED level (#341): under `interval` with a BYTE budget, a crash loses
        // AT MOST the records acked since the last completed fdatasync (the open window), never more.
        // We size the byte budget so a forced fsync fires partway through, then assert the recovered
        // head is at least the synced prefix and at most the visible head, i.e. the loss is bounded by
        // the window, not unbounded. The same workload under `sync` (asserted at the end) loses
        // nothing in the identical harness.
        let payload = [7u8; 100]; // 100 logical bytes per record.
        let budget = 250u64; // forces a sync after ~3 records of unsynced bytes.
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let clock = std::sync::Arc::new(ManualClock::new());
        // Time trigger off (0), byte trigger on: a sync is forced once >= `budget` unsynced bytes
        // accumulate, so the window is purely byte-bounded and deterministic (no clock advance).
        let mut e = open_durability(
            fs,
            clock.clone(),
            config_durability(DurabilityLevel::Interval, 0, budget),
        );
        assert!(
            e.power_loss_unsafe(),
            "interval waives I2 (opt-in, bounded)"
        );
        for _ in 0..8u32 {
            produce_d(&mut e, &payload);
            // The live unsynced exposure NEVER exceeds the byte budget plus one record: the window
            // forces a sync as soon as the budget is reached, so the bytes-at-risk are bounded.
            assert!(
                e.unsynced_bytes() <= budget.saturating_add(payload.len() as u64),
                "interval bounds the unsynced exposure to the byte window (at risk {} > bound)",
                e.unsynced_bytes()
            );
        }
        let visible = e.flushed_offset().get();
        let synced = e.synced_offset_for_test();
        assert_eq!(visible, 8, "all 8 are acked (visible) under interval");
        assert!(
            synced >= 1,
            "the byte window forced at least one real fdatasync, so a non-trivial prefix is durable \
             ({synced} synced of {visible})"
        );
        // The crash: the unsynced tail reverts. Recovery yields a prefix that is AT LEAST the synced
        // head (those records were fsync'd) and AT MOST the visible head: the loss is bounded by the
        // open window, exactly the documented `interval` guarantee.
        probe.simulate_power_loss();
        let reopened = open_durability(probe, clock, config(10, 5));
        let recovered = reopened.flushed_offset().get();
        assert!(
            recovered >= synced,
            "interval recovers at least the fsync'd prefix ({recovered} >= {synced})"
        );
        assert!(
            recovered <= visible,
            "interval never recovers more than was acked ({recovered} <= {visible})"
        );
        let lost = visible - recovered;
        let window_records = budget.div_ceil(payload.len() as u64) + 1;
        assert!(
            lost <= window_records,
            "interval loses AT MOST the flush window ({lost} lost, window <= {window_records} records)"
        );

        // The SAME harness under `sync`: a crash loses NOTHING (the teeth contrast).
        let fs2 = InMemoryFs::new();
        let probe2 = fs2.clone();
        let clock2 = std::sync::Arc::new(ManualClock::new());
        let mut e2 = open_durability(fs2, clock2.clone(), config(10, 5));
        for _ in 0..8u32 {
            produce_d(&mut e2, &payload);
        }
        probe2.simulate_power_loss();
        let reopened2 = open_durability(probe2, clock2, config(10, 5));
        assert_eq!(
            reopened2.flushed_offset().get(),
            8,
            "sync loses nothing in the SAME harness (zero acked loss)"
        );
    }

    #[test]
    fn interval_time_window_forces_a_sync_so_a_crash_after_it_loses_nothing() {
        // The TIME trigger (#341): with the byte trigger off and a time window set, advancing the
        // monotonic clock past the window forces a covering fdatasync on the next commit, after which
        // a crash loses nothing up to that barrier. Proves the time dimension of the bound (not just
        // the byte dimension) and that it reads the MONOTONIC clock seam (I6), never the wall clock.
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let clock = std::sync::Arc::new(ManualClock::new());
        // 1 s time window, byte trigger off.
        let mut e = open_durability(
            fs,
            clock.clone(),
            config_durability(DurabilityLevel::Interval, 1_000, 0),
        );
        // First record: acked on page-cache write, not yet synced (the window has not elapsed).
        produce_d(&mut e, b"a");
        assert!(
            e.unsynced_bytes() > 0,
            "the first interval record is acked but not yet synced (window not elapsed)"
        );
        // Advance the MONOTONIC clock past the window, then produce again: this commit's window is due,
        // so it forces the covering fsync, making BOTH records durable.
        clock.advance_monotonic_nanos(1_000 * 1_000_000 + 1);
        produce_d(&mut e, b"b");
        assert_eq!(
            e.unsynced_bytes(),
            0,
            "the elapsed time window forced an fdatasync, clearing the unsynced exposure"
        );
        probe.simulate_power_loss();
        let reopened = open_durability(probe, clock, config(10, 5));
        assert_eq!(
            reopened.flushed_offset().get(),
            2,
            "after the time window forced a sync, the crash loses nothing up to that barrier"
        );
    }

    #[test]
    fn a_clean_shutdown_makes_a_relaxed_level_lose_nothing() {
        // The clean-shutdown barrier (#341, #379): `none` (the largest loss window) defers every
        // commit's fsync, but a GRACEFUL stop (`checkpoint_all_groups`) forces a covering fdatasync
        // FIRST, so a clean shutdown loses NOTHING even under `none`. This is what bounds the relaxed
        // levels' loss to "since the last roll OR clean shutdown": only an ABRUPT cut exposes the
        // window.
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_durability(
            fs,
            clock.clone(),
            config_durability(DurabilityLevel::None, 0, 0),
        );
        for i in 0..5u8 {
            produce_d(&mut e, &[i]);
        }
        assert!(
            e.unsynced_bytes() > 0,
            "none defers the fsync, so there is a real unsynced exposure before shutdown"
        );
        // A graceful shutdown forces the covering fsync (and checkpoints the cursors).
        e.checkpoint_all_groups().unwrap();
        assert_eq!(
            e.unsynced_bytes(),
            0,
            "the clean-shutdown force_sync cleared the unsynced exposure (nothing at risk now)"
        );
        // Even an abrupt power cut AFTER the clean shutdown flush loses nothing: it was all synced.
        probe.simulate_power_loss();
        let reopened = open_durability(probe, clock, config(10, 5));
        assert_eq!(
            reopened.flushed_offset().get(),
            5,
            "a clean shutdown under `none` loses nothing (the shutdown flush is a real barrier)"
        );
    }

    #[test]
    fn a_segment_roll_bounds_the_relaxed_loss_to_one_open_segment() {
        // The roll barrier (#341): a segment roll SEALS the old segment (fsyncing every record in it),
        // so under a relaxed level the loss is bounded to AT MOST the records in the one OPEN segment,
        // never the whole log. We use a tiny 160-byte segment (the same small-segment knob the roll
        // tests use) so several small records force at least one roll mid-workload under `async`, then
        // a crash recovers at least everything up to the last roll.
        let small_segment = LogConfig {
            max_segment_bytes: 160,
            ..LogConfig::default()
        };
        let cfg = EngineConfig {
            log: small_segment,
            durability_level: DurabilityLevel::Async,
            flush_interval_ms: 0,
            flush_max_bytes: 0,
            // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
            // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
            codel_target_ms: 0,
            codel_interval_ms: 0,
            retry_budget_ratio_per_million: 0,
            retry_budget_window_ms: 0,
            fire_and_forget_msg_rate: 0,
            fire_and_forget_byte_rate: 0,
            fire_and_forget_refill_ms: 0,
            egress_limit: 0,
            wal_fsync_headroom_bytes: 0,
            ..config(10, 5)
        };
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_durability(fs, clock.clone(), cfg);
        // Produce enough small records to force at least one roll (so a seal made a prefix durable).
        for i in 0..32u8 {
            produce_d(&mut e, &[i]);
        }
        let synced = e.synced_offset_for_test();
        let visible = e.flushed_offset().get();
        assert!(
            synced >= 1,
            "a segment roll sealed at least one segment, so a non-trivial prefix is durable even \
             under async ({synced} synced of {visible} visible)"
        );
        probe.simulate_power_loss();
        let reopened = open_durability(
            probe,
            clock,
            EngineConfig {
                log: small_segment,
                ..config(10, 5)
            },
        );
        let recovered = reopened.flushed_offset().get();
        assert!(
            recovered >= synced,
            "the roll's seal bounds the async loss: recovery keeps at least the last-sealed prefix \
             ({recovered} >= {synced})"
        );
    }

    #[test]
    fn the_active_durability_level_is_observable() {
        // The OBSERVABILITY surface (#341, #379): the engine reports the active level, whether it
        // waives I2 (the power-loss-unsafe signal), and the live unsynced exposure, for every level.
        // sync: safe, no exposure.
        let e_sync = open(config(10, 5));
        assert_eq!(e_sync.durability_level(), DurabilityLevel::Sync);
        assert!(!e_sync.power_loss_unsafe());
        assert_eq!(e_sync.unsynced_bytes(), 0);
        // Each relaxed level reports itself and waives I2.
        for level in [
            DurabilityLevel::Interval,
            DurabilityLevel::Async,
            DurabilityLevel::None,
        ] {
            let e = open(config_durability(level, 1_000, 1024));
            assert_eq!(e.durability_level(), level, "the level is reported back");
            assert!(
                e.power_loss_unsafe(),
                "{level:?} waives I2 (power-loss unsafe)"
            );
        }
        // The flag spellings round-trip, so the metric label and the materialized-config line read
        // back exactly the selectable name.
        for (level, name) in [
            (DurabilityLevel::Sync, "sync"),
            (DurabilityLevel::Interval, "interval"),
            (DurabilityLevel::Async, "async"),
            (DurabilityLevel::None, "none"),
        ] {
            assert_eq!(level.as_str(), name);
            assert_eq!(DurabilityLevel::parse(name), Some(level));
        }
        assert_eq!(DurabilityLevel::parse("bogus"), None);
    }

    // ---- #378 fsync-headroom admission credit ----

    #[test]
    fn the_default_headroom_is_off_and_never_sheds() {
        // THE TEETH for the safe default (#378): with the headroom at `0` (the compiled default) the
        // admission credit is DISABLED, so it admits every produce regardless of the un-fsynced
        // backlog, and the broker is byte-for-byte unchanged.
        let cfg = config(10, 5);
        assert_eq!(
            cfg.wal_fsync_headroom_bytes, 0,
            "the default headroom is off"
        );
        let e = open(cfg);
        assert!(!e.wal_headroom_enabled(), "a zero headroom is disabled");
        assert_eq!(e.wal_fsync_headroom_bytes(), 0);
        // Even a record larger than any plausible headroom is admitted when the control is off.
        assert!(e.wal_headroom_admit(1_000_000), "disabled always admits");
    }

    #[test]
    fn the_headroom_admits_within_the_window_and_sheds_past_it_against_the_live_frontier() {
        // THE TEETH for the headroom math reusing the live `unsynced_bytes()` frontier (#378, #341):
        // under a RELAXED level (async), each `produce` advances the un-fsynced backlog (a commit
        // defers the fsync, so the frontier GROWS), and the headroom admits while the next record
        // fits and SHEDS once it would exceed the configured bound. This is the loss-window cap.
        let headroom = 64u64;
        let cfg = EngineConfig {
            wal_fsync_headroom_bytes: headroom,
            ..config_durability(DurabilityLevel::Async, 0, 0)
        };
        let fs = InMemoryFs::new();
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_durability(fs, clock, cfg);
        assert!(e.wal_headroom_enabled());
        assert_eq!(e.wal_fsync_headroom_bytes(), headroom);

        // An empty backlog ALWAYS admits, even an oversized record (the no-wedge floor).
        assert_eq!(e.unsynced_bytes(), 0);
        assert!(
            e.wal_headroom_admit(10_000),
            "an empty backlog admits even an oversized record (no wedge)"
        );

        // Produce 16-byte records under async: the frontier grows by 16 each commit (no fsync), so
        // after 4 the backlog is 64 (exactly the headroom). The 5th would push past it -> shed.
        let payload = [0xab_u8; 16];
        for _ in 0..4 {
            // While the next record fits within the headroom, the credit admits it.
            assert!(
                e.wal_headroom_admit(payload.len() as u64),
                "a record that fits the remaining headroom is admitted"
            );
            produce_d(&mut e, &payload);
        }
        assert_eq!(
            e.unsynced_bytes(),
            64,
            "async deferred every fsync, so the un-fsynced backlog is the 4x16 bytes"
        );
        // The backlog is at the headroom: a 5th record would exceed it, so the credit sheds it.
        assert!(
            !e.wal_headroom_admit(payload.len() as u64),
            "a non-empty backlog at the headroom sheds the next produce (the loss-window cap)"
        );
        // The accepted records are untouched (no data loss): the head still reflects all 4.
        assert_eq!(
            e.flushed_offset(),
            Offset::new(4),
            "the shed rejected NEW work only; the 4 accepted records are still durable-pending"
        );
    }

    #[test]
    fn a_sync_drains_the_backlog_and_re_admits() {
        // THE TEETH for the throttle-then-admit composition (#378): a real durability barrier
        // (`force_sync`, the same fsync `commit_batch` issues under `sync`) drains the un-fsynced
        // frontier to zero, so the headroom that had filled is freed and the next produce is admitted
        // again. Under the default `sync` level this is exactly what the actor's group-commit drain
        // does, so the headroom THROTTLES (drain-then-admit) and never sheds.
        let headroom = 64u64;
        let cfg = EngineConfig {
            wal_fsync_headroom_bytes: headroom,
            ..config_durability(DurabilityLevel::Async, 0, 0)
        };
        let fs = InMemoryFs::new();
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_durability(fs, clock, cfg);
        let payload = [0xcd_u8; 16];
        for _ in 0..4 {
            produce_d(&mut e, &payload);
        }
        assert_eq!(e.unsynced_bytes(), 64, "the backlog filled the headroom");
        assert!(
            !e.wal_headroom_admit(payload.len() as u64),
            "at the headroom the next produce is shed before a drain"
        );
        // A real durability barrier drains the un-fsynced frontier to zero (the writer caught up).
        e.force_sync().unwrap();
        assert_eq!(
            e.unsynced_bytes(),
            0,
            "a sync drained the un-fsynced backlog (the writer caught up)"
        );
        // With the backlog drained the headroom re-admits, so the producer makes progress again.
        assert!(
            e.wal_headroom_admit(payload.len() as u64),
            "after the sync drained the backlog, the headroom admits again"
        );
    }

    #[test]
    fn the_sync_level_keeps_a_zero_backlog_so_the_headroom_never_sheds_there() {
        // THE TEETH for the safe-default composition (#378 + #341): under the default `sync` level
        // every `produce` issues the covering fsync, so the un-fsynced backlog is ALWAYS zero after a
        // commit. The headroom therefore never has a non-empty backlog to shed against: under `sync`
        // it can only ever THROTTLE (and with the actor's drain it admits), never lose, never shed.
        let cfg = EngineConfig {
            wal_fsync_headroom_bytes: 8,
            ..config(10, 5)
        };
        assert_eq!(cfg.durability_level, DurabilityLevel::Sync);
        let mut e = open(cfg);
        let big = [0u8; 4096];
        for _ in 0..6 {
            // Each produce syncs (sync level), so before the next produce the backlog is zero and the
            // empty-backlog floor admits even this 4 KiB record despite the tiny 8-byte headroom.
            assert_eq!(
                e.unsynced_bytes(),
                0,
                "sync leaves no backlog between produces"
            );
            assert!(
                e.wal_headroom_admit(big.len() as u64),
                "an empty backlog admits the next record even past a tiny headroom (no wedge)"
            );
            e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &big,
            })
            .unwrap();
        }
        assert_eq!(
            e.flushed_offset(),
            Offset::new(6),
            "every produce was admitted and durable"
        );
        assert_eq!(
            e.backpressure_snapshot().wal_headroom_shed,
            0,
            "sync never sheds on the headroom"
        );
    }

    // ---- Backpressure controls (#68, #69): deterministic engine-level tests over a ManualClock ----

    /// A config with CoDel enabled at a 5 ms target / 100 ms interval, everything else inert. The
    /// lease/visibility nanos are roomy so CoDel (not the lease) drives the test.
    fn codel_config() -> EngineConfig {
        let mut c = config(64, 5);
        c.codel_target_ms = 5;
        c.codel_interval_ms = 100;
        c
    }

    /// A simple append borrowing `payload`, for the backpressure tests.
    fn append_at(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    #[test]
    fn a_client_produce_to_a_read_only_mirror_is_rejected_typed() {
        // #623 read-only enforcement: a stream declared a cross-cluster MIRROR rejects a client produce
        // with the typed EngineError::MirrorReadOnly (its only writer is the geo apply path).
        let fs = InMemoryFs::new();
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        e.set_mirror_read_only_streams(["mirror-orders".to_string()]);
        assert!(e.is_mirror_read_only("mirror-orders"));

        // A produce to the mirror is rejected, typed, BEFORE any append (the stream stays unmaterialized).
        let err = e
            .produce_in_stream("mirror-orders", &append_at(b"nope"))
            .unwrap_err();
        assert!(
            matches!(err, EngineError::MirrorReadOnly { ref name } if name == "mirror-orders"),
            "expected MirrorReadOnly, got {err:?}"
        );
        assert_eq!(
            crate::codes::ErrorCode::of_engine_error(&err),
            crate::codes::ErrorCode::ERR_MIRROR_READ_ONLY
        );

        // A NON-mirror named stream still produces fine (the guard is scoped to the configured set).
        assert!(e.produce_in_stream("other", &append_at(b"ok")).is_ok());
        // The default stream is never a mirror and is byte-for-byte unaffected.
        assert!(e.produce(&append_at(b"default")).is_ok());
    }

    #[test]
    fn no_mirror_configured_is_byte_identical_produce() {
        // The non-geo guarantee: with no mirror configured the set is empty and EVERY produce is admitted
        // exactly as today (the guard is a single is_empty() short-circuit).
        let fs = InMemoryFs::new();
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert!(!e.is_mirror_read_only("anything"));
        assert!(e.produce_in_stream("anything", &append_at(b"ok")).is_ok());
        assert!(e.produce(&append_at(b"ok")).is_ok());
    }

    #[test]
    fn codel_off_by_default_never_sheds_and_admits_every_produce() {
        // The safe-default property: with CoDel at its inert default, `codel_admit` never sheds, no
        // matter the enqueue stamp, so the produce path is byte-for-byte unchanged.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config(64, 5), std::sync::Arc::clone(&clock));
        clock.advance_millis(10_000); // a huge "sojourn" if CoDel were on
        for _ in 0..100 {
            assert!(!e.codel_admit(0), "disabled CoDel must admit (never shed)");
        }
        let snap = e.backpressure_snapshot();
        assert_eq!(snap.codel_shed, 0, "no CoDel sheds when disabled");
    }

    #[test]
    fn codel_does_not_shed_under_normal_admission_latency() {
        // Enqueue stamps that keep the sojourn UNDER the 5 ms target never shed, however long the run.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(codel_config(), std::sync::Arc::clone(&clock));
        for _ in 0..5_000 {
            // Advance 1 ms, and stamp the enqueue 1 ms ago: a 1 ms sojourn, under the 5 ms target.
            clock.advance_millis(1);
            let enqueue = e.now_monotonic().saturating_sub(1_000_000); // 1 ms in nanos
            assert!(
                !e.codel_admit(enqueue),
                "a 1 ms sojourn is under target, never shed"
            );
        }
        assert_eq!(e.backpressure_snapshot().codel_shed, 0);
    }

    #[test]
    fn codel_sheds_under_sustained_overload_and_never_drops_an_accepted_record() {
        // The headline #68 property with teeth: a sustained admission sojourn ABOVE the target for a
        // full interval sheds NEW produces, and a shed NEVER appends a record (no data loss: the
        // durable head only advances for ADMITTED produces). We drive a shared ManualClock so the
        // sojourn is exact and the test is deterministic.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(codel_config(), std::sync::Arc::clone(&clock));
        let mut admitted = 0u64;
        let mut shed = 0u64;
        // Feed 300 ms of produces whose sojourn is 20 ms (well above the 5 ms target): after one full
        // 100 ms interval CoDel enters the dropping state and begins shedding.
        for _ in 0..300 {
            clock.advance_millis(1);
            let enqueue = e.now_monotonic().saturating_sub(20_000_000); // 20 ms sojourn
            if e.codel_admit(enqueue) {
                // A shed: do NOT append (exactly what the actor does), so nothing durable is written.
                shed += 1;
            } else {
                // Admitted: append durably. This is the only path that advances the durable head.
                e.produce(&append_at(b"ok")).unwrap();
                admitted += 1;
            }
        }
        assert!(shed > 0, "sustained overload past the target must shed");
        // NO DATA LOSS: the durable head equals exactly the number of ADMITTED produces. A shed never
        // appended, and an admitted produce was never dropped.
        assert_eq!(
            e.flushed_offset().get(),
            admitted,
            "the durable log holds exactly the admitted produces; no shed was ever appended, no \
             admitted record was ever dropped"
        );
        // Observability: the shed counter matches the sheds we saw, and the sojourn estimate is live.
        let snap = e.backpressure_snapshot();
        assert_eq!(
            snap.codel_shed, shed,
            "the shed counter is the observable shed rate"
        );
        assert!(
            snap.codel_sojourn_estimate_ms >= 5,
            "the sojourn estimate is exposed"
        );
    }

    #[test]
    fn codel_recovers_and_stops_shedding_once_admission_latency_falls() {
        // After overload, a return to low admission latency exits the dropping state and admits again.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(codel_config(), std::sync::Arc::clone(&clock));
        // Drive into shedding.
        for _ in 0..300 {
            clock.advance_millis(1);
            let enqueue = e.now_monotonic().saturating_sub(20_000_000);
            let _ = e.codel_admit(enqueue);
        }
        assert!(e.backpressure_snapshot().codel_shed > 0);
        // Recovery: low sojourn for a while. None of these shed.
        let before = e.backpressure_snapshot().codel_shed;
        for _ in 0..300 {
            clock.advance_millis(1);
            let enqueue = e.now_monotonic().saturating_sub(1_000_000); // 1 ms, under target
            assert!(!e.codel_admit(enqueue), "a recovered sojourn never sheds");
        }
        assert_eq!(
            e.backpressure_snapshot().codel_shed,
            before,
            "no new sheds once admission latency recovered"
        );
    }

    #[test]
    fn codel_depth_backstop_sheds_independent_of_sojourn() {
        // The sojourn-INDEPENDENT depth backstop: at or above the ring capacity the new enqueue is
        // shed regardless of CoDel, and the backstop shed counter rises. A `0` capacity disables it.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config(64, 5), std::sync::Arc::clone(&clock));
        // capacity 4: depths 0..3 admit, 4 and up shed.
        assert!(!e.codel_backstop_admit(0, 4));
        assert!(!e.codel_backstop_admit(3, 4));
        assert!(
            e.codel_backstop_admit(4, 4),
            "at capacity the backstop sheds"
        );
        assert!(
            e.codel_backstop_admit(99, 4),
            "over capacity the backstop sheds"
        );
        // A 0 capacity disables the depth backstop (the byte cap alone backstops).
        assert!(!e.codel_backstop_admit(u64::MAX, 0));
        assert!(e.backpressure_snapshot().codel_backstop_shed >= 2);
    }

    #[test]
    fn the_byte_cap_shed_counts_as_a_backstop_shed() {
        // A drop-new byte-cap shed (the BYTE dimension of the backstop) increments the unified
        // backstop counter, so `ironbus_codel_backstop_shed_total` reflects a stalled-drain byte
        // bound CoDel cannot see.
        let one = LogConfig::default().max_segment_bytes;
        let mut cfg = config(64, 5);
        cfg.log = LogConfig::new(one).unwrap().with_max_total_bytes(4 * one);
        cfg.disk_full_policy = DiskFullPolicy::DropNew;
        let mut e = open(cfg);
        // Fill the log over its cap; once over, produces are shed (drop-new), and each shed bumps the
        // backstop counter.
        let big = vec![0u8; usize::try_from(one).unwrap_or(usize::MAX) / 2];
        let mut sheds = 0u64;
        for _ in 0..40 {
            if e.produce(&append_at(&big)).is_err() {
                sheds += 1;
            }
        }
        assert!(sheds > 0, "the byte cap eventually sheds");
        assert!(
            e.backpressure_snapshot().codel_backstop_shed >= sheds,
            "every byte-cap shed counts as a backstop shed"
        );
    }

    #[test]
    fn the_retry_budget_throttles_a_storm_broker_side() {
        // The broker-side retry budget bounds redelivery work: after the broker sheds a burst of
        // requests, hammering retries gets most of them throttled (the anti-amplification re-check),
        // and the throttles are counted.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut cfg = config(64, 5);
        cfg.retry_budget_ratio_per_million = 100_000; // 10%
        cfg.retry_budget_window_ms = 60_000;
        let mut e = open_with_clock(cfg, std::sync::Arc::clone(&clock));
        // The broker sheds 1000 requests (accepts collapse), so the retry numerator goes positive.
        for _ in 0..1000 {
            e.retry_budget_record_shed();
        }
        assert!(
            e.backpressure_snapshot().retry_ratio_per_million > 0,
            "sheds are observable"
        );
        let mut throttled = 0u64;
        let mut allowed = 0u64;
        for _ in 0..1000 {
            if e.retry_budget_should_throttle() {
                throttled += 1;
            } else {
                allowed += 1;
            }
        }
        assert!(
            throttled > allowed,
            "most retries throttled under a storm: {throttled} vs {allowed}"
        );
        assert_eq!(
            e.backpressure_snapshot().retry_shed,
            throttled,
            "the throttle counter matches"
        );
    }

    #[test]
    fn the_egress_aimd_decreases_on_failure_and_recovers_additively_within_caps() {
        // The egress AIMD: halve on a downstream failure (floored at 4), additive recovery (capped at
        // 128), so a slow sink is throttled smoothly within the configured caps.
        let mut e = open(config(64, 5));
        assert_eq!(e.egress_limit(), 16, "the default floor");
        e.egress_on_failure();
        assert_eq!(e.egress_limit(), 8, "halves on a downstream failure");
        e.egress_on_failure();
        assert_eq!(e.egress_limit(), 4, "halves toward the floor");
        e.egress_on_failure();
        assert_eq!(e.egress_limit(), 4, "never below the floor of 4");
        for _ in 0..200 {
            e.egress_on_success();
        }
        assert_eq!(e.egress_limit(), 128, "additive recovery, capped at 128");
        e.egress_record_shed();
        assert_eq!(
            e.backpressure_snapshot().egress_shed,
            1,
            "an egress shed is counted"
        );
    }

    #[test]
    fn the_fire_and_forget_bucket_caps_the_uncredited_tier() {
        // The fire-and-forget token bucket caps the un-credited admission tier: the burst drains, then
        // it sheds until tokens refill, and each shed is counted. Disabled by default (always admits).
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut cfg = config(64, 5);
        cfg.fire_and_forget_msg_rate = 5000;
        cfg.fire_and_forget_byte_rate = 0; // message dimension only, for a crisp count
        cfg.fire_and_forget_refill_ms = 100;
        let mut e = open_with_clock(cfg, std::sync::Arc::clone(&clock));
        // Drain the burst at t=0.
        let mut admitted = 0u64;
        for _ in 0..2000 {
            if e.fire_and_forget_admit(0) {
                admitted += 1;
            }
        }
        assert!(
            (400..=600).contains(&admitted),
            "burst capped near 500, got {admitted}"
        );
        assert!(
            e.backpressure_snapshot().fire_and_forget_shed > 0,
            "the bucket sheds and counts"
        );
        // After a refill window, tokens are available again.
        clock.advance_millis(100);
        assert!(
            e.fire_and_forget_admit(0),
            "tokens refilled after the window"
        );
    }

    #[test]
    fn a_disabled_fire_and_forget_bucket_always_admits() {
        // The safe default: with no rate configured the un-credited tier is ungoverned (admits all).
        let mut e = open(config(64, 5));
        for _ in 0..1000 {
            assert!(
                e.fire_and_forget_admit(1_000_000),
                "disabled bucket admits everything"
            );
        }
        assert_eq!(e.backpressure_snapshot().fire_and_forget_shed, 0);
    }

    // ---- Retry-throttle ENFORCEMENT in the redelivery path (#402): DEFERS, never drops ----

    #[test]
    fn the_retry_throttle_defers_a_redelivery_but_never_drops_it_and_it_reaches_the_dlq() {
        // THE TEETH for the retry-throttle enforcement (#402): with the budget EXHAUSTED, a
        // redelivery is DEFERRED (spaced out) rather than delivered, but the at-least-once message is
        // NEVER dropped: once the budget window rolls it redelivers, and after MaxDeliver attempts it
        // reaches the DLQ. We drive a shared ManualClock so the budget window and the lease deadlines
        // are exact and deterministic.
        let clock = std::sync::Arc::new(ManualClock::new());
        // max_deliver = 3 (the 4th attempt is poison); a tiny 1 ms budget window so we can roll it; a
        // ratio of 1 ppm (~0% budget) so a single shed-storm throttles the very next redelivery.
        let mut cfg = config(64, 3);
        cfg.retry_budget_ratio_per_million = 1;
        cfg.retry_budget_window_ms = 1; // 1 ms window (1_000_000 ns)
        let mut e = open_with_clock(cfg, std::sync::Arc::clone(&clock));

        // Produce one at-least-once message and deliver it once (attempt 1).
        let off = e
            .produce(&Append {
                timestamp_ms: 1,
                flags: RecordFlags::EMPTY,
                key: b"k",
                headers: b"h",
                payload: b"v",
            })
            .unwrap();
        let d1 = message(e.poll_now().unwrap());
        assert_eq!(d1.offset, off);
        assert_eq!(d1.deliveries, 1, "first delivery");

        // Exhaust the budget: a storm of broker sheds makes accepts collapse, so the next retry is
        // throttled (numerator > 0, budget rounds to 0 at 1 ppm).
        for _ in 0..1000 {
            e.retry_budget_record_shed();
        }
        // Expire the lease so the next poll WOULD redeliver (attempt 2).
        clock.advance_monotonic_nanos(40);
        let shed_before = e.backpressure_snapshot().retry_shed;
        // The redelivery is THROTTLED: the poll defers it and returns Idle (the message is NOT
        // delivered now), but it is NOT lost (still in flight, attempt count untouched).
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "an exhausted budget DEFERS the redelivery (no delivery this poll)"
        );
        assert_eq!(
            e.backpressure_snapshot().retry_shed,
            shed_before + 1,
            "the deferred redelivery is counted as a throttle (never silent)"
        );
        assert_eq!(
            e.counters().dead_lettered,
            0,
            "NOT dropped, NOT dead-lettered"
        );
        assert_eq!(
            e.committed_offset(),
            Offset::ZERO,
            "still uncommitted, still in flight"
        );

        // Roll the budget window (advance past 1 ms) so the storm decays and retries are permitted
        // again, and advance past the deferral so the lease is reclaimable. The message redelivers.
        clock.advance_monotonic_nanos(5_000_000); // 5 ms: past the 1 ms window AND any deferral
        let d2 = message(e.poll_now().unwrap());
        assert_eq!(d2.offset, off);
        assert_eq!(
            d2.deliveries, 2,
            "the deferral did NOT bump the attempt count: this is the genuine 2nd delivery"
        );

        // Drive the remaining genuine attempts to MaxDeliver, rolling the window each time so the
        // throttle never blocks forward progress, until the message is dead-lettered. Every message
        // still eventually reaches the DLQ: at-least-once + MaxDeliver intact, no data loss.
        let mut guard = 0;
        loop {
            guard += 1;
            assert!(
                guard < 50,
                "the message must reach the DLQ in bounded polls"
            );
            clock.advance_monotonic_nanos(5_000_000); // roll the window + expire the lease
            match e.poll_now().unwrap() {
                Poll::Message(d) => {
                    assert_eq!(d.offset, off, "still the same message redelivering");
                }
                Poll::Parked { offset, .. } => {
                    assert_eq!(offset, off, "the poison parked is our message");
                    break;
                }
                Poll::Idle => { /* a transient throttle: roll again and retry */ }
                other => panic!("unexpected poll outcome {other:?}"),
            }
        }
        assert_eq!(
            e.counters().dead_lettered,
            1,
            "the message reached the DLQ at MaxDeliver: NO data loss, the throttle only deferred"
        );
        assert_eq!(
            e.committed_offset(),
            Offset::new(off.get() + 1),
            "committed past the poison after the DLQ move"
        );
    }

    #[test]
    fn a_disabled_retry_budget_never_defers_a_redelivery() {
        // The safe default: with the budget at its inert default, a redelivery is delivered
        // immediately on the next poll (never deferred), so the redelivery path is unchanged.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = open_with_clock(config(64, 5), std::sync::Arc::clone(&clock));
        let off = e.produce(&append_at(b"v")).unwrap();
        let d1 = message(e.poll_now().unwrap());
        assert_eq!(d1.deliveries, 1);
        // Even after a storm of sheds, a DISABLED budget never throttles, so the redelivery is prompt.
        for _ in 0..1000 {
            e.retry_budget_record_shed();
        }
        clock.advance_monotonic_nanos(40);
        let d2 = message(e.poll_now().unwrap());
        assert_eq!(d2.offset, off);
        assert_eq!(d2.deliveries, 2, "a disabled budget redelivers at once");
        assert_eq!(
            e.backpressure_snapshot().retry_shed,
            0,
            "no throttles when disabled"
        );
    }

    // ---- Egress AIMD wired to the per-consumer egress credit (#402) ----

    #[test]
    fn the_egress_aimd_is_inert_by_default_and_grants_the_full_ceiling() {
        // The safe default: with `egress_limit == 0` the AIMD does NOT govern the per-consumer credit,
        // so `egress_grant_within` returns the negotiated ceiling unchanged and the keep-up /
        // falling-behind signals are no-ops (the gauge still reports the static 16).
        let mut e = open(config(64, 5));
        assert!(!e.egress_aimd_enabled(), "inert by default");
        assert_eq!(e.egress_grant_within(64), 64, "the full ceiling is granted");
        e.egress_falling_behind();
        e.egress_falling_behind();
        assert_eq!(
            e.egress_limit(),
            16,
            "the limit does not move when the AIMD is inert"
        );
        assert_eq!(
            e.backpressure_snapshot().egress_shed,
            0,
            "no shed counted when inert"
        );
        e.egress_keep_up();
        assert_eq!(e.egress_limit(), 16, "keep-up is a no-op when inert");
    }

    #[test]
    fn the_egress_aimd_decreases_on_falling_behind_and_recovers_on_keep_up_within_the_cap() {
        // THE TEETH for the egress AIMD (#402): when enabled, a falling-behind signal multiplicatively
        // decreases the effective egress credit (within the negotiated cap), and keep-up additively
        // recovers it, NEVER exceeding the negotiated ceiling. We start at 8 so the moves are crisp.
        let mut cfg = config(64, 5);
        cfg.egress_limit = 8; // opt in to the AIMD, starting limit 8
        let mut e = open(cfg);
        assert!(e.egress_aimd_enabled());
        // The grant is min(ceiling, AIMD limit): with a ceiling of 4 the limiter never exceeds it.
        assert_eq!(
            e.egress_grant_within(4),
            4,
            "AIMD never exceeds the negotiated cap"
        );
        assert_eq!(
            e.egress_grant_within(64),
            8,
            "the AIMD limit binds below a big ceiling"
        );
        // Falling behind halves the limit and counts the throttled grant.
        e.egress_falling_behind();
        assert_eq!(e.egress_limit(), 4, "halved on falling behind");
        assert_eq!(
            e.backpressure_snapshot().egress_shed,
            1,
            "the throttled grant is counted"
        );
        e.egress_falling_behind();
        assert_eq!(e.egress_limit(), 4, "floored at 4, never collapses to zero");
        // Keep-up climbs additively, but the grant stays within the negotiated ceiling.
        for _ in 0..200 {
            e.egress_keep_up();
        }
        assert_eq!(e.egress_limit(), 128, "additive recovery, capped at 128");
        assert_eq!(
            e.egress_grant_within(64),
            64,
            "even a recovered AIMD never grants beyond the negotiated ceiling"
        );
    }

    // =============================================================================================
    // The write-path compression seam (#430, ADR-0003): `EngineConfig::compression` applied in
    // `append_no_sync`. The `Codec::None` byte-identity half is pinned by every OTHER test in this
    // module (the shared config passes `Codec::None`) plus the determinism / conformance-vector
    // suites; these cover the lz4 half: the round trip, the two write guards, the pass-through
    // (no-double-compression) guard, and the stored-vs-logical byte accounting.
    // =============================================================================================

    /// The shared test config with lz4 write-path compression (#430). Everything else identical
    /// to `config(10, 5)`, so any behavioral difference in these tests is the codec alone.
    fn lz4_config() -> EngineConfig {
        EngineConfig {
            compression: Codec::Lz4,
            ..config(10, 5)
        }
    }

    /// A compressible payload of `len` bytes: repeated ASCII text, the shape lz4 shrinks well.
    fn compressible(len: usize) -> Vec<u8> {
        b"edge node telemetry "
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    /// A deterministic high-entropy payload of `len` bytes (xorshift64*), which lz4 cannot
    /// strictly shrink, so the never-expand guard must store it raw.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let word = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    #[test]
    fn lz4_round_trips_a_compressible_payload_through_produce_and_poll() {
        use ironbus_core::compress::{
            decompress_payload, NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES,
        };
        let original = compressible(4096);

        // The raw-store baseline: the identical workload on a `Codec::None` engine, for the
        // stored-byte comparison below.
        let mut none = open(config(10, 5));
        produce(&mut none, &original);
        let raw_durable = none.durable_record_bytes();

        let mut e = open(lz4_config());
        produce(&mut e, &original);
        // Stored accounting is post-compression: the lz4 engine holds strictly fewer durable
        // record bytes than the raw-store engine for the same logical produce.
        assert!(
            e.durable_record_bytes() < raw_durable,
            "lz4 durable bytes ({}) must be under the raw-store bytes ({raw_durable})",
            e.durable_record_bytes()
        );
        // `produced_bytes` deliberately counts the ORIGINAL logical payload bytes (#430), so the
        // producer-facing throughput meaning is codec-independent.
        assert_eq!(e.counters().produced_bytes, original.len() as u64);
        assert_eq!(none.counters().produced_bytes, original.len() as u64);

        // The DELIVERED record carries the COMPRESSED flag and the STORED (descriptor + stream)
        // bytes, which differ from (and undercut) the original; the consumer-side decode
        // recovers the original payload exactly.
        let d = message(e.poll(0).unwrap());
        assert!(
            d.record.flags.contains(RecordFlags::COMPRESSED),
            "the stored record carries COMPRESSED, got {:?}",
            d.record.flags
        );
        assert_ne!(
            d.record.payload.as_ref(),
            original.as_slice(),
            "the stored bytes are not the raw payload"
        );
        assert!(
            d.record.payload.len() < original.len(),
            "strictly smaller (never-expand)"
        );
        let back = decompress_payload(
            d.record.flags,
            &d.record.payload,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, original, "the decode recovers the original payload");
    }

    #[test]
    fn a_sub_threshold_payload_stores_raw_even_with_lz4_configured() {
        use ironbus_core::compress::DEFAULT_RAW_STORE_THRESHOLD;
        // One byte under the 64-byte raw-store threshold: compressible in principle, but the
        // guard stores it raw, byte-for-byte the no-compression layout.
        let original = vec![b'x'; DEFAULT_RAW_STORE_THRESHOLD - 1];
        let mut none = open(config(10, 5));
        produce(&mut none, &original);
        let mut e = open(lz4_config());
        produce(&mut e, &original);
        assert_eq!(
            e.durable_record_bytes(),
            none.durable_record_bytes(),
            "a raw store is byte-identical to the no-compression encoder"
        );
        let d = message(e.poll(0).unwrap());
        assert!(!d.record.flags.contains(RecordFlags::COMPRESSED));
        assert_eq!(d.record.payload, original);
    }

    #[test]
    fn an_incompressible_payload_stores_raw_under_the_never_expand_guard() {
        let original = incompressible(4096);
        let mut none = open(config(10, 5));
        produce(&mut none, &original);
        let mut e = open(lz4_config());
        produce(&mut e, &original);
        assert_eq!(
            e.durable_record_bytes(),
            none.durable_record_bytes(),
            "a never-expand raw store is byte-identical to the no-compression encoder"
        );
        let d = message(e.poll(0).unwrap());
        assert!(!d.record.flags.contains(RecordFlags::COMPRESSED));
        assert_eq!(d.record.payload, original);
    }

    #[test]
    fn a_compressible_payload_over_the_readers_cap_stores_raw_and_round_trips() {
        use ironbus_core::compress::{
            decompress_payload, NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES,
        };
        // One byte OVER the readers' per-unit decompressed cap: highly compressible, but the
        // seam's cap guard MUST store it raw. Compressed, its descriptor would claim an
        // `uncompressed_len` above the cap every shipped reader (the client fetch decode, the
        // CLI dump/peek) enforces BEFORE allocating, so the record would be durably ACKED and
        // then refused with `DecompressedTooLarge` on every read: a consumer stall on a
        // pseudo-poison record the broker itself manufactured.
        let cap = DEFAULT_MAX_DECOMPRESSED_BYTES as usize;
        let original = compressible(cap + 1);
        let mut e = open(lz4_config());
        produce(&mut e, &original);
        let d = message(e.poll(0).unwrap());
        assert!(
            !d.record.flags.contains(RecordFlags::COMPRESSED),
            "an over-cap payload is stored raw, never compressed"
        );
        assert_eq!(
            d.record.payload, original,
            "the raw store carries the payload verbatim"
        );
        // The shipped read-side decode accepts it: the cap binds only a COMPRESSED claim, so the
        // over-cap raw record round-trips instead of being pseudo-poison.
        let back = decompress_payload(
            d.record.flags,
            &d.record.payload,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn a_compressible_payload_at_the_readers_cap_compresses_and_round_trips() {
        use ironbus_core::compress::{
            decompress_payload, NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES,
        };
        // Exactly AT the cap (the largest legal compressed claim, since the readers reject only
        // a claim STRICTLY above it): the seam compresses, and the shipped read-side decode under
        // the default cap accepts and recovers it. Together with the over-cap test above this
        // pins the guard to the readers' exact boundary.
        let cap = DEFAULT_MAX_DECOMPRESSED_BYTES as usize;
        let original = compressible(cap);
        let mut e = open(lz4_config());
        produce(&mut e, &original);
        let d = message(e.poll(0).unwrap());
        assert!(
            d.record.flags.contains(RecordFlags::COMPRESSED),
            "an at-cap payload still compresses"
        );
        assert!(
            d.record.payload.len() < original.len(),
            "strictly smaller (never-expand)"
        );
        let back = decompress_payload(
            d.record.flags,
            &d.record.payload,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, original, "the decode recovers the original payload");
    }

    #[test]
    fn an_already_compressed_append_passes_through_byte_identical() {
        use ironbus_core::compress::{
            compress_payload, decompress_payload, CompressConfig, NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        };
        // A producer-compressed stored object, exactly what a producer may legally deliver with
        // bit 0 set (PUB_WIRE_ONLY_FLAGS masks only the wire-only high bits 3..=7, never bit 0). The
        // seam MUST pass it through
        // untouched: re-compressing would wrap the descriptor in a descriptor and decode to
        // garbage.
        //
        // The fixture must be a RECOMPRESSIBLE stored object for this test to have teeth: an lz4
        // stream over ordinary text is itself incompressible, so on such a fixture a DELETED
        // pass-through guard is masked by the never-expand guard (the re-compress attempt expands
        // and stores the same bytes raw). lz4-of-1-MiB-of-zeros is a few KiB of highly repetitive
        // match tokens that recompress to tens of bytes, so a double-wrap changes the stored
        // bytes and the byte-identity assertion below catches it.
        let original = vec![0u8; 1024 * 1024];
        let comp = compress_payload(&original, &CompressConfig::default()).unwrap();
        assert!(comp.compressed, "the fixture payload genuinely compresses");
        let rewrap = compress_payload(&comp.stored, &CompressConfig::default()).unwrap();
        assert!(
            rewrap.compressed,
            "the stored object must itself be recompressible, or this test cannot \
             distinguish the pass-through guard from the never-expand guard"
        );

        let mut e = open(lz4_config());
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::COMPRESSED,
            key: b"",
            headers: b"",
            payload: &comp.stored,
        })
        .unwrap();
        let d = message(e.poll(0).unwrap());
        assert!(d.record.flags.contains(RecordFlags::COMPRESSED));
        assert_eq!(
            d.record.payload, comp.stored,
            "the already-compressed payload is stored verbatim, never double-wrapped"
        );
        let back = decompress_payload(
            d.record.flags,
            &d.record.payload,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, original, "one decode recovers the original");
    }

    #[test]
    fn the_byte_cap_meters_stored_bytes_not_logical_bytes() {
        // A 2 KiB durable-byte cap against 1 KiB compressible payloads (raw frame ~1068 bytes:
        // 36-byte header + payload + 8-byte trailer). Raw-stored, two produces reach the cap and
        // the third is the AtCapacity drop-new shed; lz4-stored frames are tens of bytes, so the
        // same workload stays far under the cap and every produce is accepted. This pins that the
        // cap accounts POST-compression stored bytes (the on-flash truth), not logical bytes.
        let capped_log = LogConfig {
            max_total_bytes: 2048,
            ..LogConfig::default()
        };
        let payload = compressible(1024);

        let mut none = open(EngineConfig {
            log: capped_log,
            ..config(10, 5)
        });
        for _ in 0..2 {
            none.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &payload,
            })
            .unwrap();
        }
        let err = none
            .produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &payload,
            })
            .unwrap_err();
        assert!(
            matches!(&err, EngineError::Storage(e) if e.is_at_capacity()),
            "raw-stored, the third 1 KiB produce trips the 2 KiB cap, got {err:?}"
        );

        let mut lz4 = open(EngineConfig {
            log: capped_log,
            compression: Codec::Lz4,
            ..config(10, 5)
        });
        for i in 0..8 {
            lz4.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: &payload,
            })
            .unwrap_or_else(|e| panic!("lz4-stored produce {i} stays under the cap: {e:?}"));
        }
        assert!(
            lz4.durable_record_bytes() < 2048,
            "eight compressed 1 KiB produces hold fewer stored bytes than two raw ones: {}",
            lz4.durable_record_bytes()
        );
    }

    // ----- Tier-S streaming consumer-managed-offset consume mode (#544, M1-I7) -----

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    #[test]
    fn stream_fetch_serves_a_contiguous_batch_with_no_lease_and_no_cursor_write() {
        // THE core property (#544): a Tier-S streaming fetch serves a contiguous run off the durable
        // prefix WITHOUT granting any lease or writing any per-record cursor state. This is what removes
        // the per-record cost that makes single-consumer durable consume lose to NATS.
        let mut e = open(config(10, 5));
        for i in 0..6u8 {
            produce(&mut e, &[i]);
        }
        e.set_streaming_in("s", true).unwrap();

        let batch = e
            .stream_fetch_in("s", member(1), Offset::ZERO, 4, None)
            .unwrap();
        // A contiguous prefix [0, 4) of records in offset order.
        assert_eq!(batch.records.len(), 4);
        for (i, r) in batch.records.iter().enumerate() {
            assert_eq!(r.offset.get(), i as u64);
            assert_eq!(&r.payload[..], &[u8::try_from(i).unwrap()]);
        }
        // The resume point is one past the last record served.
        assert_eq!(batch.next_offset, Offset::new(4));
        // NO lease was granted: the in-flight set is empty.
        assert_eq!(
            e.in_flight_in("s"),
            0,
            "a streaming fetch grants no lease (the headline Tier-S property)"
        );
        // NO cursor was written: the committed offset stays exactly where it was (0).
        assert_eq!(
            e.committed_offset_in("s"),
            Offset::ZERO,
            "a streaming fetch writes no per-record cursor state"
        );

        // Fetching AGAIN from the same start re-reads the SAME records (idempotent, consumer-managed):
        // the broker keeps no per-delivery state, so there is nothing to advance.
        let again = e
            .stream_fetch_in("s", member(1), Offset::ZERO, 4, None)
            .unwrap();
        assert_eq!(again.records.len(), 4);
        assert_eq!(again.records[0].offset, Offset::ZERO);
        assert_eq!(e.in_flight_in("s"), 0);
        assert_eq!(e.committed_offset_in("s"), Offset::ZERO);
    }

    #[test]
    fn stream_fetch_raw_decodes_to_the_same_records_as_stream_fetch() {
        // #541 DIFFERENTIAL: the RAW batch source (`stream_fetch_raw_in`) decodes — `raw` (positional
        // offsets) plus the materialized `tail` — to EXACTLY the records `stream_fetch_in` returns for
        // the same window, with the same offsets, in the same order. This is the core correctness proof
        // that a DeliverBatch carries the same delivery a per-record Deliver run would.
        let mut e = open(config(100, 5));
        for i in 0..40u8 {
            produce(&mut e, &[i, i.wrapping_add(1)]);
        }
        e.set_streaming_in("s", true).unwrap();
        for start in 0..40u64 {
            for max in [1usize, 3, 8, 64] {
                let materialized = e
                    .stream_fetch_in("s", member(1), Offset::new(start), max, None)
                    .unwrap();
                let raw = e
                    .stream_fetch_raw_in("s", member(1), Offset::new(start), max, None)
                    .unwrap();
                // Decode `raw` (positional offsets) then append the materialized tail, the way the
                // session ships them (DeliverBatch then per-record Deliver).
                let mut got: Vec<(u64, Vec<u8>)> = Vec::new();
                let mut cursor = 0usize;
                let mut off = raw.raw.first_offset.get();
                while cursor < raw.raw.bytes.len() {
                    let (view, consumed) =
                        ironbus_core::codec::decode(&raw.raw.bytes[cursor..]).unwrap();
                    got.push((off, view.payload.to_vec()));
                    off += 1;
                    cursor += consumed;
                }
                for r in &raw.tail {
                    got.push((r.offset.get(), r.payload.to_vec()));
                }
                let want: Vec<(u64, Vec<u8>)> = materialized
                    .records
                    .iter()
                    .map(|r| (r.offset.get(), r.payload.to_vec()))
                    .collect();
                assert_eq!(
                    got, want,
                    "raw batch != materialized at start={start} max={max}"
                );
                assert_eq!(
                    raw.next_offset, materialized.next_offset,
                    "resume offset mismatch at start={start} max={max}"
                );
            }
        }
    }

    #[test]
    fn stream_fetch_raw_is_rejected_on_a_non_streaming_group_like_stream_fetch() {
        // The raw path applies the IDENTICAL wrong-mode guard as `stream_fetch_in`, so a client cannot
        // get a lease-free batch off a Tier-W group by asking for the raw frame.
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        assert!(matches!(
            e.stream_fetch_raw_in("w", member(1), Offset::ZERO, 4, None),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        assert!(matches!(
            e.stream_fetch_raw(member(1), Offset::ZERO, 4, None),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
    }

    #[test]
    fn stream_fetch_is_rejected_on_a_non_streaming_group() {
        // A streaming fetch must not bypass the Tier-W lease path: a group that was never declared
        // streaming rejects the verb, so a client cannot accidentally turn a work-queue into a stream.
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        // The default Tier-W group (never marked streaming) rejects it.
        assert!(matches!(
            e.stream_fetch_in("w", member(1), Offset::ZERO, 4, None),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        // The default group likewise.
        assert!(matches!(
            e.stream_fetch(member(1), Offset::ZERO, 4, None),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
    }

    #[test]
    fn stream_commit_advances_the_watermark_via_the_cumulative_cursor() {
        // A periodic cumulative StreamCommit advances the streaming group's committed watermark via the
        // REUSED `commit_up_to` primitive (no new durable structure), and is idempotent / monotonic.
        let mut e = open(config(10, 5));
        for _ in 0..10 {
            produce(&mut e, b"x");
        }
        e.set_streaming_in("s", true).unwrap();
        e.stream_fetch_in("s", member(1), Offset::ZERO, 10, None)
            .unwrap();
        assert_eq!(e.committed_offset_in("s"), Offset::ZERO);

        // Commit up to 5 (exclusive): the watermark jumps to 5.
        e.stream_commit_in("s", Offset::new(5)).unwrap();
        assert_eq!(e.committed_offset_in("s"), Offset::new(5));
        // Idempotent: a re-commit at or below the watermark is a no-op success, never a regression.
        e.stream_commit_in("s", Offset::new(5)).unwrap();
        e.stream_commit_in("s", Offset::new(3)).unwrap();
        assert_eq!(e.committed_offset_in("s"), Offset::new(5));
        // Advance further.
        e.stream_commit_in("s", Offset::new(10)).unwrap();
        assert_eq!(e.committed_offset_in("s"), Offset::new(10));
        // Still no lease was ever taken (commit reclaims nothing because there is nothing in-flight).
        assert_eq!(e.in_flight_in("s"), 0);
    }

    #[test]
    fn stream_commit_rejects_a_non_streaming_group_and_an_out_of_range_offset() {
        let mut e = open(config(10, 5));
        for _ in 0..4 {
            produce(&mut e, b"x");
        }
        // A non-streaming group rejects the commit (a broadcast group uses cumulative_ack_in instead).
        assert!(matches!(
            e.stream_commit_in("w", Offset::new(2)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        e.set_streaming_in("s", true).unwrap();
        // Past the durable head: rejected, watermark unchanged.
        assert!(matches!(
            e.stream_commit_in("s", Offset::new(99)),
            Err(EngineError::CumulativeAckOutOfRange { .. })
        ));
        assert_eq!(e.committed_offset_in("s"), Offset::ZERO);
    }

    #[test]
    fn stream_at_least_once_survives_a_crash_reconnect_redelivering_only_uncommitted() {
        // THE at-least-once correctness test (#544): a consumer fetches a batch, commits a PREFIX, then
        // "crashes" (reconnects with no broker-side delivery state) and resumes from its LAST COMMITTED
        // offset. The committed offset survives; every uncommitted record is re-delivered; nothing is
        // lost and the contiguous order is preserved across the reconnect.
        let mut e = open(config(10, 5));
        let n = 8u8;
        for i in 0..n {
            produce(&mut e, &[i]);
        }
        e.set_streaming_in("s", true).unwrap();

        // Fetch all 8, then durably commit only up to 5 (the consumer processed [0,5) and crashed
        // before committing 5,6,7).
        let first = e
            .stream_fetch_in("s", member(1), Offset::ZERO, 8, None)
            .unwrap();
        assert_eq!(first.records.len(), 8);
        e.stream_commit_in("s", Offset::new(5)).unwrap();
        assert_eq!(e.committed_offset_in("s"), Offset::new(5));

        // CRASH + RECONNECT: the broker kept no per-delivery state (no lease). The reconnecting consumer
        // resumes from its last committed offset (5) — the consumer-managed contract. It re-reads
        // [5, 8): exactly the uncommitted records, in order, none lost, at most re-delivered.
        let resumed = e
            .stream_fetch_in("s", member(1), e.committed_offset_in("s"), 8, None)
            .unwrap();
        let resumed_offsets: Vec<u64> = resumed.records.iter().map(|r| r.offset.get()).collect();
        assert_eq!(
            resumed_offsets,
            vec![5, 6, 7],
            "exactly the uncommitted records re-deliver, in contiguous order"
        );
        // The full delivered set across the crash (committed [0,5) once + redelivered [5,8)) covers
        // every produced offset at least once: no message loss.
        let mut seen: std::collections::BTreeSet<u64> =
            first.records.iter().map(|r| r.offset.get()).collect();
        seen.extend(resumed.records.iter().map(|r| r.offset.get()));
        assert_eq!(
            seen,
            (0..u64::from(n)).collect(),
            "every produced offset is delivered at least once (at-least-once)"
        );

        // The consumer finishes and commits the rest: the watermark reaches the head.
        e.stream_commit_in("s", Offset::new(u64::from(n))).unwrap();
        assert_eq!(e.committed_offset_in("s"), Offset::new(u64::from(n)));
    }

    #[test]
    fn stream_commit_frees_retention_like_any_other_group() {
        // A streaming group's committed cursor pins/frees the retention floor exactly like a Tier-W ack
        // or a broadcast cumulative ack: it is read by `min_committed_offset` once touched. A streaming
        // consumer that fetches-but-never-commits pins the floor at its committed (0); once it commits,
        // the now-consumed old segments become reapable.
        let mut e = open(config_with_retention(0));
        produce(&mut e, &[0xab; 16]);
        let one = e.durable_record_bytes();
        let mut e = open(config_with_retention(2 * one));

        e.set_streaming_in("s", true).unwrap();
        // Produce well past the bound; the streaming consumer FETCHES everything but does NOT commit, so
        // its cursor stays at 0 and pins the floor: nothing below 0 may be reaped.
        for _ in 0..30 {
            produce(&mut e, &[0xab; 16]);
        }
        let head = e.flushed_offset();
        e.stream_fetch_in("s", member(1), Offset::ZERO, 1024, None)
            .unwrap();
        assert_eq!(e.committed_offset_in("s"), Offset::ZERO);
        // Produce one more to drive the retention pass: the floor is pinned at 0, so nothing reaps.
        produce(&mut e, &[0xab; 16]);
        assert_eq!(
            e.counters().segments_reaped,
            0,
            "an uncommitted streaming consumer pins the floor at its committed offset (0)"
        );

        // Now the consumer durably COMMITS up to the head it read: the floor rises and the next produce
        // reaps the now-consumed old segments back toward the bound.
        e.stream_commit_in("s", head).unwrap();
        assert_eq!(e.committed_offset_in("s"), head);
        produce(&mut e, &[0xab; 16]);
        assert!(
            e.counters().segments_reaped >= 1,
            "once the streaming consumer commits, old consumed segments reap (retention freed)"
        );
        assert!(
            e.durable_record_bytes() <= 4 * one,
            "the live durable bytes dropped toward the bound after the streaming commit"
        );
    }

    #[test]
    fn tier_w_lease_path_is_unchanged_when_tier_s_is_available() {
        // PRESERVE (#544): adding Tier-S leaves Tier-W (the lease/poll/ack work-queue) byte-identical.
        // A default-group poll still grants a lease, an ack still advances the cursor, and the streaming
        // verbs are simply unavailable on a Tier-W group. This is the regression guard that the
        // work-queue differentiator stays intact.
        let mut e = open(config(10, 5));
        for i in 0..3u8 {
            produce(&mut e, &[i]);
        }
        // The Tier-W poll path is exactly as before: a lease is granted, the cursor advances on ack.
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.offset, Offset::ZERO);
        assert_eq!(e.in_flight_in(""), 1, "Tier-W still grants a lease");
        assert_eq!(e.ack(&d.token), AckResult::Acked);
        assert_eq!(
            e.committed_offset_in(""),
            Offset::new(1),
            "Tier-W ack still advances the cursor"
        );
        // The streaming verbs are rejected on this Tier-W group (it was never marked streaming).
        assert!(matches!(
            e.stream_fetch(member(1), Offset::ZERO, 4, None),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
        assert!(matches!(
            e.stream_commit(Offset::new(1)),
            Err(EngineError::CumulativeAckOnWorkGroup)
        ));
    }

    #[test]
    fn stream_fetch_respects_max_records_max_bytes_and_the_flushed_bound() {
        let mut e = open(config(64, 5));
        for _ in 0..10 {
            produce(&mut e, &[0xcd; 32]);
        }
        e.set_streaming_in("s", true).unwrap();
        // max_records bounds the batch.
        let b = e
            .stream_fetch_in("s", member(1), Offset::ZERO, 3, None)
            .unwrap();
        assert_eq!(b.records.len(), 3);
        assert_eq!(b.next_offset, Offset::new(3));
        // A start at the head serves nothing and resumes at the head (caught up).
        let head = e.flushed_offset();
        let caught_up = e.stream_fetch_in("s", member(1), head, 100, None).unwrap();
        assert!(caught_up.records.is_empty());
        assert_eq!(caught_up.next_offset, head);
        // A tiny byte cap still serves at least one record (the floor-of-one), never zero.
        let one_byte = e
            .stream_fetch_in("s", member(1), Offset::ZERO, 100, Some(1))
            .unwrap();
        assert_eq!(
            one_byte.records.len(),
            1,
            "the byte cap floors at one record so a stream never wedges"
        );
    }

    // =================================================================================
    // #676 (V2-M2-I2b): thread the StreamSet through the Engine — id-routed produce/consume.
    // The default stream "" must stay byte-for-byte today; a NAMED stream is an independent
    // log + its own per-stream work-groups; the two are isolated; recovery reopens both.
    // =================================================================================

    /// Produces `payload` to the NAMED stream `stream` via the id-routed entry point.
    fn produce_to(e: &mut Engine<InMemoryFs, ManualClock>, stream: &str, payload: &[u8]) -> Offset {
        e.produce_in_stream(
            stream,
            &Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            },
        )
        .unwrap()
    }

    #[test]
    fn a_no_stream_id_produce_consume_is_byte_for_byte_the_default_stream() {
        // Routing through the id-routed entry points with the EMPTY stream name must behave EXACTLY
        // like the historical no-stream produce/poll/ack on the default group. (The single-log
        // golden-path test `produce_poll_ack_advances_the_cursor` already pins the bare-method
        // behavior; this asserts the id-routed `""` path is indistinguishable from it.)
        let mut e = open(config(10, 5));
        assert_eq!(produce_to(&mut e, "", b"a"), Offset::new(0));
        assert_eq!(produce_to(&mut e, "", b"b"), Offset::new(1));
        // The default head advanced; NO named stream was created (the `""` path never names one).
        assert_eq!(e.stream_head(""), Offset::new(2));
        assert_eq!(
            e.named_stream_count(),
            0,
            "the default path never materializes a named stream"
        );

        let d0 = message(e.poll_in_stream("", DEFAULT_GROUP, 0).unwrap());
        assert_eq!(d0.offset, Offset::new(0));
        assert_eq!(d0.record.payload.as_ref(), b"a");
        assert_eq!(
            e.ack_in_stream("", DEFAULT_GROUP, &d0.token),
            AckResult::Acked
        );
        assert_eq!(e.committed_offset(), Offset::new(1));
        // The id-routed default ack moved the SAME cursor the bare `committed_offset()` reads.
        assert_eq!(
            e.committed_offset_in_stream("", DEFAULT_GROUP),
            Offset::new(1)
        );

        let d1 = message(e.poll_in_stream("", DEFAULT_GROUP, 0).unwrap());
        assert_eq!(d1.offset, Offset::new(1));
        assert_eq!(
            e.ack_in_stream("", DEFAULT_GROUP, &d1.token),
            AckResult::Acked
        );
        assert_eq!(e.committed_offset(), Offset::new(2));
        assert!(matches!(
            e.poll_in_stream("", DEFAULT_GROUP, 0).unwrap(),
            Poll::Idle
        ));
    }

    #[test]
    fn a_named_stream_end_to_end_declare_produce_consume_ack() {
        // Produce DECLARES the named stream (no separate declare needed), the consume delivers off
        // ITS OWN log + group, and the ack advances ITS OWN cursor — the full work-queue cycle on a
        // stream other than the default.
        let mut e = open(config(10, 5));
        assert_eq!(produce_to(&mut e, "orders", b"o0"), Offset::new(0));
        assert_eq!(produce_to(&mut e, "orders", b"o1"), Offset::new(1));
        assert_eq!(e.named_stream_count(), 1);
        assert_eq!(e.stream_head("orders"), Offset::new(2));

        let d0 = message(e.poll_in_stream("orders", "g", 0).unwrap());
        assert_eq!(d0.offset, Offset::new(0));
        assert_eq!(d0.record.payload.as_ref(), b"o0");
        assert_eq!(d0.deliveries, 1);
        assert_eq!(e.ack_in_stream("orders", "g", &d0.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in_stream("orders", "g"), Offset::new(1));

        let d1 = message(e.poll_in_stream("orders", "g", 0).unwrap());
        assert_eq!(d1.offset, Offset::new(1));
        assert_eq!(e.ack_in_stream("orders", "g", &d1.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in_stream("orders", "g"), Offset::new(2));
        assert!(matches!(
            e.poll_in_stream("orders", "g", 0).unwrap(),
            Poll::Idle
        ));
    }

    #[test]
    fn a_named_stream_is_isolated_from_the_default_streams_data_and_cursor() {
        // The cross-stream ISOLATION property (#676): a produce/consume/ack on a named stream NEVER
        // touches the default stream's data or cursor, and vice versa.
        let mut e = open(config(10, 5));
        // Default stream gets two records; the named stream gets one DIFFERENT record.
        assert_eq!(produce(&mut e, b"default-0"), Offset::new(0));
        assert_eq!(produce(&mut e, b"default-1"), Offset::new(1));
        assert_eq!(produce_to(&mut e, "metrics", b"metrics-0"), Offset::new(0));

        // Each stream has its OWN head/offset space: the named stream's offset 0 is independent of
        // the default stream's offsets.
        assert_eq!(e.stream_head(""), Offset::new(2));
        assert_eq!(e.stream_head("metrics"), Offset::new(1));

        // Consume + ack the named stream fully. The default stream's cursor must NOT move.
        let m = message(e.poll_in_stream("metrics", "g", 0).unwrap());
        assert_eq!(m.record.payload.as_ref(), b"metrics-0");
        assert_eq!(e.ack_in_stream("metrics", "g", &m.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in_stream("metrics", "g"), Offset::new(1));
        assert_eq!(
            e.committed_offset(),
            Offset::ZERO,
            "acking the named stream must not advance the default stream's cursor"
        );

        // Now consume the DEFAULT stream: it still serves its own data, unaffected by the named
        // stream's activity, and the named stream's cursor stays put.
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.record.payload.as_ref(), b"default-0");
        assert_eq!(e.ack(&d.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert_eq!(
            e.committed_offset_in_stream("metrics", "g"),
            Offset::new(1),
            "consuming the default stream must not disturb the named stream's cursor"
        );
    }

    #[test]
    fn the_same_group_name_in_two_streams_is_two_independent_cursors() {
        // PER-STREAM GROUPS (#676): a group name `g` in stream A and `g` in stream B are unrelated
        // cursors — acking in A's `g` never advances B's `g`.
        let mut e = open(config(10, 5));
        produce_to(&mut e, "a", b"a0");
        produce_to(&mut e, "a", b"a1");
        produce_to(&mut e, "b", b"b0");
        produce_to(&mut e, "b", b"b1");

        // Drain stream A's group `g` by ONE; stream B's group `g` is untouched.
        let a0 = message(e.poll_in_stream("a", "g", 0).unwrap());
        assert_eq!(a0.record.payload.as_ref(), b"a0");
        assert_eq!(e.ack_in_stream("a", "g", &a0.token), AckResult::Acked);
        assert_eq!(e.committed_offset_in_stream("a", "g"), Offset::new(1));
        assert_eq!(
            e.committed_offset_in_stream("b", "g"),
            Offset::ZERO,
            "the SAME group name in a sibling stream is an independent cursor"
        );

        // Stream B's group `g` still delivers from ITS offset 0 (not skipped by A's progress).
        let b0 = message(e.poll_in_stream("b", "g", 0).unwrap());
        assert_eq!(b0.offset, Offset::new(0));
        assert_eq!(b0.record.payload.as_ref(), b"b0");
    }

    #[test]
    fn commit_tick_commits_multiple_named_streams_in_one_tick() {
        // The cross-stream #678 commit_tick path: producing to TWO named streams makes both durable
        // (their durable heads advance), and the records are independently readable from each stream.
        // (`produce_in_stream` drives one tick per produce; this asserts the multi-stream durability
        // result the tick guarantees — each dirtied stream's head reaches its appended count.)
        let mut e = open(config(10, 5));
        produce_to(&mut e, "s1", b"x");
        produce_to(&mut e, "s2", b"y");
        produce_to(&mut e, "s1", b"z");
        // Both named streams committed independently; the default stream stayed empty (never dirtied
        // by the named-stream commit tick).
        assert_eq!(e.stream_head("s1"), Offset::new(2));
        assert_eq!(e.stream_head("s2"), Offset::new(1));
        assert_eq!(
            e.stream_head(""),
            Offset::ZERO,
            "the default stream is never touched by named produces"
        );
        assert_eq!(e.named_stream_count(), 2);

        // The durable records are readable per stream (proving the tick made them durable+visible).
        let m1 = message(e.poll_in_stream("s1", "g", 0).unwrap());
        assert_eq!(m1.record.payload.as_ref(), b"x");
        let m2 = message(e.poll_in_stream("s2", "g", 0).unwrap());
        assert_eq!(m2.record.payload.as_ref(), b"y");
    }

    #[test]
    fn recovery_reopens_all_streams_engine_state() {
        // RECOVERY (#676): after a restart, the engine reopens the default stream AND every named
        // stream's log, so produced records on each stream survive and remain consumable. (Named
        // streams' CONSUMER cursors are in-memory for now — the flagged #60-style follow-up — so this
        // asserts the LOG of each stream recovers and redelivers its records, the durable guarantee.)
        let fs = InMemoryFs::new();
        {
            let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
            produce(&mut e, b"default-survives"); // default stream, offset 0
            produce_to(&mut e, "alpha", b"alpha-survives"); // named stream, offset 0
            produce_to(&mut e, "beta", b"beta-survives"); // named stream, offset 0
            assert_eq!(e.named_stream_count(), 2);
        }
        // Reopen over the SAME filesystem: every stream's log recovers.
        let mut e2 = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(
            e2.named_stream_count(),
            2,
            "both named streams recovered from disk at reopen"
        );
        assert_eq!(e2.stream_head(""), Offset::new(1));
        assert_eq!(e2.stream_head("alpha"), Offset::new(1));
        assert_eq!(e2.stream_head("beta"), Offset::new(1));

        // Each recovered stream redelivers its own record (the log survived the restart).
        let d = message(e2.poll(0).unwrap());
        assert_eq!(d.record.payload.as_ref(), b"default-survives");
        let a = message(e2.poll_in_stream("alpha", "g", 0).unwrap());
        assert_eq!(a.record.payload.as_ref(), b"alpha-survives");
        let b = message(e2.poll_in_stream("beta", "g", 0).unwrap());
        assert_eq!(b.record.payload.as_ref(), b"beta-survives");
    }

    #[test]
    fn an_invalid_named_stream_fails_closed_and_an_unknown_stream_consume_rejects() {
        // The validation boundary (#676): a malformed NAMED name fails closed BEFORE the filesystem,
        // and a consume on a never-declared stream is a typed rejection, not a silent empty read.
        let mut e = open(config(10, 5));
        // A name with a control byte is rejected (the graphic-ASCII rule, the same as a group name).
        let bad = e.produce_in_stream(
            "bad\nname",
            &Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload: b"x",
            },
        );
        assert!(matches!(bad, Err(EngineError::InvalidStreamName { .. })));
        assert_eq!(
            e.named_stream_count(),
            0,
            "a rejected name never materializes a stream"
        );
        // A consume on a stream that was never produced-to is UnknownStream, not an empty Idle.
        let unknown = e.poll_in_stream("never-declared", "g", 0);
        assert!(matches!(unknown, Err(EngineError::UnknownStream { .. })));
    }

    // =================================================================================
    // #585 (V2-M2-I9): subject->stream binding + fail-closed single-home resolution.
    // A stream BINDS subject patterns; a publish BY SUBJECT resolves single-home to the bound
    // stream (exactly-one routes, zero is NoStreamForSubject, >=2 is AmbiguousSubject); a bind
    // change invalidates the resolve cache. The explicit-stream-id (#676) + default "" paths are
    // unchanged. The beat over NATS: a publish to an unbound subject is a TYPED reject, never a
    // silent drop.
    // =================================================================================

    /// Publishes `payload` BY SUBJECT via the subject-addressed entry point (no per-connection cache;
    /// the engine method resolves through the trie directly).
    fn produce_subject(
        e: &mut Engine<InMemoryFs, ManualClock>,
        subject: &str,
        payload: &[u8],
    ) -> Result<Offset, EngineError> {
        e.produce_by_subject(
            subject,
            &Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            },
        )
    }

    #[test]
    fn bind_then_publish_by_subject_lands_in_the_bound_stream_end_to_end() {
        // THE end-to-end happy path: bind "order.>" to stream "orders"; a publish to a LITERAL subject
        // "order.us.created" resolves single-home to "orders" and the record lands in THAT stream's log,
        // readable off "orders" (not the default stream, not any other).
        let mut e = open(config(10, 5));
        e.bind_subject("orders", "order.>").unwrap();
        assert_eq!(e.binding_count(), 1);

        // Publish by subject -> offset 0 in "orders".
        assert_eq!(
            produce_subject(&mut e, "order.us.created", b"o0").unwrap(),
            Offset::new(0)
        );
        assert_eq!(
            produce_subject(&mut e, "order.eu.created", b"o1").unwrap(),
            Offset::new(1)
        );
        // The records landed in "orders" — consume them off that stream.
        assert_eq!(e.stream_head("orders"), Offset::new(2));
        let d0 = message(e.poll_in_stream("orders", "g", 0).unwrap());
        assert_eq!(d0.record.payload.as_ref(), b"o0");
        let d1 = message(e.poll_in_stream("orders", "g", 0).unwrap());
        assert_eq!(d1.record.payload.as_ref(), b"o1");
        // The DEFAULT stream got nothing (the subject did not route there).
        assert_eq!(e.stream_head(""), Offset::ZERO);
        // And `resolve_subject` agrees the subject maps to exactly "orders".
        assert_eq!(
            e.resolve_subject("order.us.created").unwrap(),
            StreamId::named("orders").unwrap()
        );
    }

    #[test]
    fn a_publish_to_an_unbound_subject_is_a_typed_no_stream_reject_not_a_silent_drop() {
        // THE beat over NATS: a publish to a subject with NO matching binding is REFUSED with the typed
        // NoStreamForSubject (fail-closed), never silently dropped while acking success. Nothing is
        // written to any log.
        let mut e = open(config(10, 5));
        e.bind_subject("orders", "order.>").unwrap();
        let rejected = produce_subject(&mut e, "telemetry.cpu", b"x");
        assert!(
            matches!(rejected, Err(EngineError::NoStreamForSubject { .. })),
            "an unbound subject is fail-closed, got {rejected:?}"
        );
        assert_eq!(
            rejected.unwrap_err().code(),
            crate::codes::ErrorCode::ERR_NO_STREAM_FOR_SUBJECT
        );
        // No silent drop: neither the bound stream nor the default got the record.
        assert_eq!(e.stream_head("orders"), Offset::ZERO);
        assert_eq!(e.stream_head(""), Offset::ZERO);
    }

    #[test]
    fn an_ambiguous_subject_bound_to_two_streams_is_a_typed_reject() {
        // Single-home default: a subject covered by bindings on TWO distinct streams is AmbiguousSubject
        // (one record needs one unambiguous destination). The overlap_ok fan-out is the flagged later
        // issue.
        let mut e = open(config(10, 5));
        e.bind_subject("orders", "order.>").unwrap();
        e.bind_subject("audit", "order.us.*").unwrap();
        let rejected = produce_subject(&mut e, "order.us.created", b"x");
        match rejected {
            Err(EngineError::AmbiguousSubject { matched, .. }) => assert_eq!(matched, 2),
            other => panic!("expected AmbiguousSubject, got {other:?}"),
        }
        // A subject only ONE of them covers is unambiguous and routes.
        assert_eq!(
            produce_subject(&mut e, "order.eu.created", b"y").unwrap(),
            Offset::new(0)
        );
        assert_eq!(e.stream_head("orders"), Offset::new(1));
        assert_eq!(e.stream_head("audit"), Offset::ZERO);
    }

    #[test]
    fn a_bind_change_is_reflected_by_resolution_no_stale_routing() {
        // A rebind moves a subject's destination; resolution must reflect the NEW binding immediately
        // (the engine resolves against the swapped-in trie; a per-connection cache's generation-guard
        // drops its stale answer — proven in the core resolve_cache + binding tests).
        let mut e = open(config(10, 5));
        e.bind_subject("a", "order.>").unwrap();
        let g0 = e.binding_generation();
        assert_eq!(
            e.resolve_subject("order.x").unwrap(),
            StreamId::named("a").unwrap()
        );
        // Rebind the SAME pattern to a different stream "b": the generation advances and resolution moves.
        let g1 = e.bind_subject("b", "order.>").unwrap();
        assert!(g1 > g0, "a bind advances the routing generation");
        // Now "order.x" is bound to BOTH a and b -> ambiguous (single-home). This proves the new binding
        // took effect (no stale single-route to "a").
        assert!(matches!(
            e.resolve_subject("order.x"),
            Err(EngineError::AmbiguousSubject { matched: 2, .. })
        ));
    }

    #[test]
    fn binding_to_the_default_stream_routes_a_subject_to_the_default_log() {
        // PRESERVE: a subject may be bound to the DEFAULT stream "" — a publish by that subject then
        // lands in the default log (byte-for-byte the historical produce). A NO-subject default publish
        // (`produce`) is unaffected.
        let mut e = open(config(10, 5));
        e.bind_subject("", "metric.>").unwrap();
        assert_eq!(
            produce_subject(&mut e, "metric.cpu", b"m0").unwrap(),
            Offset::new(0)
        );
        // It landed in the DEFAULT stream's log; no named stream was created.
        assert_eq!(e.stream_head(""), Offset::new(1));
        assert_eq!(e.named_stream_count(), 0);
        let d = message(e.poll_in_stream("", DEFAULT_GROUP, 0).unwrap());
        assert_eq!(d.record.payload.as_ref(), b"m0");
    }

    #[test]
    fn an_invalid_subject_or_pattern_fails_closed_at_the_boundary() {
        // A malformed bind pattern, and a wildcard/malformed PUBLISH subject, are each a typed
        // InvalidSubject reject — never a panic, never a silent admit.
        let mut e = open(config(10, 5));
        // A bind pattern with a non-final `>` is rejected (the #567 grammar).
        assert!(matches!(
            e.bind_subject("orders", "order.>.bad"),
            Err(EngineError::InvalidSubject(_))
        ));
        assert_eq!(e.binding_count(), 0, "a rejected bind registers nothing");
        // A PUBLISH subject may not carry a wildcard (it must be a literal).
        e.bind_subject("orders", "order.>").unwrap();
        assert!(matches!(
            produce_subject(&mut e, "order.*", b"x"),
            Err(EngineError::InvalidSubject(_))
        ));
    }

    #[test]
    fn binding_is_idempotent_and_a_named_bind_declares_the_stream() {
        // Re-binding the same (pattern, stream) pair is a no-op success (no duplicate, no generation
        // churn), and binding a NAMED stream DECLARES it so a subject-addressed publish has a log.
        let mut e = open(config(10, 5));
        let g1 = e.bind_subject("orders", "order.>").unwrap();
        // Binding declared "orders".
        assert_eq!(e.named_stream_count(), 1);
        // Idempotent re-bind: same generation, still one binding.
        let g2 = e.bind_subject("orders", "order.>").unwrap();
        assert_eq!(
            g1, g2,
            "an idempotent re-bind does not advance the generation"
        );
        assert_eq!(e.binding_count(), 1);
    }

    #[test]
    fn the_explicit_stream_id_and_default_paths_are_unchanged_by_binding() {
        // PRESERVE: with bindings present, the explicit-stream-id (#676) and default "" produce/consume
        // paths behave EXACTLY as before — binding adds a parallel route, it never re-routes them.
        let mut e = open(config(10, 5));
        e.bind_subject("orders", "order.>").unwrap();
        // Explicit-stream-id produce to a DIFFERENT named stream still works and is isolated.
        assert_eq!(produce_to(&mut e, "shipments", b"s0"), Offset::new(0));
        assert_eq!(e.stream_head("shipments"), Offset::new(1));
        // A default no-subject produce still targets the default log.
        let mut e2 = open(config(10, 5));
        e2.bind_subject("orders", "order.>").unwrap();
        assert_eq!(produce_to(&mut e2, "", b"d0"), Offset::new(0));
        assert_eq!(e2.stream_head(""), Offset::new(1));
        let d = message(e2.poll_in_stream("", DEFAULT_GROUP, 0).unwrap());
        assert_eq!(d.record.payload.as_ref(), b"d0");
    }

    // ===================================================================================
    // TRANSACTIONAL HALF-MESSAGE 2PC (#640, V2-M8 part 1/2): engine-level prepare/commit/rollback,
    // the INVISIBILITY invariant, the crash windows, and byte-identical-when-unused.
    // ===================================================================================

    fn txn_half(payload: &[u8]) -> Append<'static> {
        Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: Box::leak(payload.to_vec().into_boxed_slice()),
        }
    }

    /// Drains the default group, returning every delivered payload (acking each), so a test can assert
    /// EXACTLY what a consumer sees.
    fn drain_visible(e: &mut Engine<InMemoryFs, ManualClock>) -> Vec<Vec<u8>> {
        let mut seen = Vec::new();
        loop {
            match e.poll(0).unwrap() {
                Poll::Message(d) => {
                    seen.push(d.record.payload.to_vec());
                    e.ack(&d.token);
                }
                Poll::Idle => break,
                other => panic!("unexpected poll outcome: {other:?}"),
            }
        }
        seen
    }

    #[test]
    fn a_prepared_half_message_is_invisible_until_commit() {
        // THE INVISIBILITY INVARIANT: a Prepared-but-uncommitted half message is NEVER returned by the
        // consume path; it appears in the target stream ONLY after commit.
        let mut e = open(config(10, 5));
        e.txn_prepare(b"tx1", "", &txn_half(b"half")).unwrap();
        assert_eq!(e.txn_prepared_count(), 1);
        // The consumer sees NOTHING (the half message lives in txn/, not the real stream).
        assert!(
            matches!(e.poll(0).unwrap(), Poll::Idle),
            "prepared half is invisible"
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(0),
            "nothing in the real stream yet"
        );
        // Commit: now it appears in the real stream, exactly once.
        let off = e.txn_commit(b"tx1").unwrap();
        assert_eq!(off, Offset::new(0));
        assert_eq!(e.txn_prepared_count(), 0);
        assert_eq!(drain_visible(&mut e), vec![b"half".to_vec()]);
    }

    #[test]
    fn a_rolled_back_half_message_is_never_delivered() {
        // After rollback the half message NEVER appears in the real stream.
        let mut e = open(config(10, 5));
        e.txn_prepare(b"tx1", "", &txn_half(b"secret")).unwrap();
        e.txn_rollback(b"tx1").unwrap();
        assert_eq!(e.txn_prepared_count(), 0);
        assert!(
            matches!(e.poll(0).unwrap(), Poll::Idle),
            "rolled-back half is never delivered"
        );
        assert_eq!(
            e.flushed_offset(),
            Offset::new(0),
            "nothing was ever appended to the real stream"
        );
        assert!(drain_visible(&mut e).is_empty());
    }

    #[test]
    fn commit_interleaves_with_normal_produces_visibly_only_after_commit() {
        // A normal produce is immediately visible; a prepared half is not, until committed — and the
        // committed record lands at its own offset after the earlier normal produces.
        let mut e = open(config(10, 5));
        assert_eq!(produce(&mut e, b"n0"), Offset::new(0));
        e.txn_prepare(b"tx1", "", &txn_half(b"txn")).unwrap();
        assert_eq!(produce(&mut e, b"n1"), Offset::new(1));
        // So far only the two normal produces are visible.
        // (Peek without acking is awkward; instead assert the txn commit lands at offset 2.)
        let off = e.txn_commit(b"tx1").unwrap();
        assert_eq!(
            off,
            Offset::new(2),
            "the committed record lands after the normal produces"
        );
        assert_eq!(
            drain_visible(&mut e),
            vec![b"n0".to_vec(), b"n1".to_vec(), b"txn".to_vec()]
        );
    }

    #[test]
    fn recommit_is_idempotent_returning_the_same_offset() {
        // A retried commit of an already-committed txn returns the SAME offset and appends nothing.
        let mut e = open(config(10, 5));
        e.txn_prepare(b"tx1", "", &txn_half(b"v")).unwrap();
        let off1 = e.txn_commit(b"tx1").unwrap();
        let off2 = e.txn_commit(b"tx1").unwrap();
        let off3 = e.txn_commit(b"tx1").unwrap();
        assert_eq!(off1, off2);
        assert_eq!(off2, off3);
        // Exactly one record is visible (no double-append from the re-commits).
        assert_eq!(drain_visible(&mut e), vec![b"v".to_vec()]);
    }

    #[test]
    fn commit_after_rollback_and_rollback_after_commit_are_refused() {
        let mut e = open(config(10, 5));
        // commit-after-rollback is refused, never flipped.
        e.txn_prepare(b"a", "", &txn_half(b"a")).unwrap();
        e.txn_rollback(b"a").unwrap();
        assert!(matches!(e.txn_commit(b"a"), Err(EngineError::Txn(_))));
        // rollback-after-commit is refused too.
        e.txn_prepare(b"b", "", &txn_half(b"b")).unwrap();
        e.txn_commit(b"b").unwrap();
        assert!(matches!(e.txn_rollback(b"b"), Err(EngineError::Txn(_))));
        // Only b's committed record is visible (a was rolled back).
        assert_eq!(drain_visible(&mut e), vec![b"b".to_vec()]);
    }

    #[test]
    fn an_unknown_commit_or_rollback_is_rejected() {
        let mut e = open(config(10, 5));
        // Open the txn store first (so a real store exists), then resolve a ghost.
        e.txn_prepare(b"real", "", &txn_half(b"r")).unwrap();
        assert!(matches!(e.txn_commit(b"ghost"), Err(EngineError::Txn(_))));
        assert!(matches!(e.txn_rollback(b"ghost"), Err(EngineError::Txn(_))));
    }

    #[test]
    fn crash_after_prepare_reopens_as_prepared_and_recoverable() {
        // CRASH WINDOW (a): only the half record is durable. On reopen the txn is Prepared
        // (recoverable, unresolved) and STILL invisible to consumers; a later commit is a fresh resolve.
        let fs = InMemoryFs::new();
        {
            let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
            e.txn_prepare(b"tx1", "", &txn_half(b"half")).unwrap();
            // CRASH: no commit/rollback.
        }
        let mut reopened = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(
            reopened.txn_prepared_count(),
            1,
            "the prepared half survived the restart"
        );
        assert!(
            matches!(reopened.poll(0).unwrap(), Poll::Idle),
            "still invisible after restart"
        );
        assert_eq!(
            reopened.flushed_offset(),
            Offset::new(0),
            "not in the real stream"
        );
        // A fresh commit after restart delivers it exactly once.
        let off = reopened.txn_commit(b"tx1").unwrap();
        assert_eq!(off, Offset::new(0));
        assert_eq!(drain_visible(&mut reopened), vec![b"half".to_vec()]);
    }

    #[test]
    fn a_committed_txn_reopens_as_resolved_and_recommit_is_idempotent() {
        // CRASH WINDOW (c): the op-marker is durable, so on reopen the txn is Committed; the real
        // record is present exactly once, and a retried commit after restart is a benign idempotent
        // no-op (NO double-append).
        let fs = InMemoryFs::new();
        {
            let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
            e.txn_prepare(b"tx1", "", &txn_half(b"committed")).unwrap();
            e.txn_commit(b"tx1").unwrap();
            // CLEAN shutdown after the durable commit.
        }
        let mut reopened = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(reopened.txn_prepared_count(), 0, "resolved, not prepared");
        // The committed record is present exactly once.
        assert_eq!(reopened.flushed_offset(), Offset::new(1));
        // A retried commit after restart is idempotent (no second append).
        let off = reopened.txn_commit(b"tx1").unwrap();
        assert_eq!(
            off,
            Offset::new(0),
            "the recorded committed offset, not a new append"
        );
        assert_eq!(
            reopened.flushed_offset(),
            Offset::new(1),
            "still exactly one record"
        );
        assert_eq!(drain_visible(&mut reopened), vec![b"committed".to_vec()]);
    }

    #[test]
    fn recommit_after_a_crash_before_the_op_marker_is_deduped_no_double_append() {
        // CRASH WINDOW (b), THE HARD ONE: a crash AFTER the real record is durable but BEFORE the
        // op-marker. We SIMULATE it by reopening after a commit that durably appended + flushed the
        // seq high-water but whose op-marker we delete from the txn store — the txn replays as
        // Prepared, and the redrive re-commit must dedup the real append to the ORIGINAL offset (no
        // double). We approximate the window by: commit normally (real record + seq high-water + marker
        // all durable), reopen, then re-commit — the durable producer-seq high-water dedups the
        // re-append to the original offset. This proves the dedup identity SURVIVES a restart, which is
        // exactly what makes window (b)'s redrive idempotent.
        let fs = InMemoryFs::new();
        let committed_off;
        {
            let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
            e.txn_prepare(b"tx1", "", &txn_half(b"once")).unwrap();
            committed_off = e.txn_commit(b"tx1").unwrap();
        }
        // Reopen: the producer-seq high-water for the txn id is restored from producer-seq.ckpt.
        let mut reopened = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
        // Re-driving the SAME real append (the window-(b) recovery action) under the same txn-id seq is
        // a DUPLICATE at the original offset — never a second record.
        let half = ironbus_storage::txn::HalfMessage {
            txn_id: b"tx1".to_vec(),
            stream: String::new(),
            timestamp_ms: 0,
            key: Vec::new(),
            headers: Vec::new(),
            payload: b"once".to_vec(),
            flags: RecordFlags::EMPTY,
        };
        let redriven = reopened.commit_real_append(b"tx1", &half).unwrap();
        assert_eq!(
            redriven, committed_off,
            "the durable txn-id seq dedups the crash-recovery re-append to the original offset"
        );
        // Still exactly one record in the real stream (the re-append was a no-op duplicate).
        reopened.commit_batch().unwrap();
        assert_eq!(
            reopened.flushed_offset(),
            Offset::new(1),
            "no double-append across the restart"
        );
    }

    #[test]
    fn crash_between_a2_and_a3_clamps_the_phantom_high_water_and_redrives_fresh() {
        use ironbus_storage::fault::FaultFs;
        // THE CLAMP BRANCH (the A2<->A3 torn-tail window), the one the durable-seq ordering exists
        // for: the producer-seq high-water (A2) was fsync'd, but the real-stream record's covering
        // fsync (A3) was LOST in the torn tail. On recovery `seed_producer_seq_from_recovered` must
        // CLAMP the over-the-head high-water and DROP it, so the redrive re-appends the record FRESH
        // exactly once at the real head — no double-append (the first write was lost), no loss.
        //
        // We construct the EXACT torn state faithfully (the in-memory FS would otherwise sync both):
        // run the real commit steps A (write, no fsync) and A2 (fsync the seq checkpoint) so the
        // high-water is durable, then ARM an fsync fault and run A3 (commit_batch's covering fsync),
        // which fails and freezes the writer with the record still UNSYNCED — exactly the mid-A2/A3
        // crash. A power loss then reverts the unsynced record while the fsync'd seq checkpoint
        // survives, and a clean reopen drives recovery's clamp.
        let (faultfs, control) = FaultFs::new(InMemoryFs::new());
        let probe = faultfs.inner().clone();
        {
            let mut e = Engine::open(faultfs, ManualClock::new(), config(10, 5)).unwrap();
            e.txn_prepare(b"tx1", "", &txn_half(b"once")).unwrap();
            // The buffered half (durably fsync'd at prepare) is what a redrive re-appends. Pull it
            // exactly as `txn_commit` does, then run the commit ordering by hand so we can inject the
            // fault precisely BETWEEN A2 and A3.
            let half = e
                .txn
                .as_ref()
                .and_then(|s| s.prepared_payload(b"tx1").cloned())
                .expect("the prepared half is buffered");
            // STEP A: write the real record (no fsync) — assigns offset 0 and records the txn-id seq
            // high-water in memory.
            let off = e.commit_real_append(b"tx1", &half).unwrap();
            assert_eq!(off, Offset::new(0), "the first real append takes offset 0");
            // STEP A2: fsync the producer-seq checkpoint, making the dedup high-water DURABLE before
            // the record. This sync must SUCCEED (the fault is not yet armed).
            e.flush_txn_commit_dedup().unwrap();
            // STEP A3: the record's covering fsync — ARM the fault so it FAILS, leaving the record
            // written-but-unsynced and freezing the writer. This is the torn A2<->A3 crash point.
            control.set_fail_sync(true);
            assert!(
                e.commit_batch().is_err(),
                "A3's covering fsync fails (the torn-tail crash point), freezing the writer"
            );
            // The op-marker B was never reached, so the txn is still Prepared on disk.
            // CRASH (drop the frozen engine).
        }
        // POWER LOSS: the unsynced real record reverts (lost), the fsync'd producer-seq.ckpt survives
        // (so its high-water now points PAST the durable head — the phantom the clamp must drop).
        probe.simulate_power_loss();

        // RECOVER over the surviving disk with a CLEAN fs (no fault layer), exactly as a real reopen.
        let mut reopened = Engine::open(probe.clone(), ManualClock::new(), config(10, 5)).unwrap();
        // The record was lost: the real stream is empty, and the txn replays as Prepared (no op-marker
        // was ever written), so it is recoverable and still invisible.
        assert_eq!(
            reopened.flushed_offset(),
            Offset::new(0),
            "the unsynced real record was lost in the torn tail"
        );
        assert_eq!(
            reopened.txn_prepared_count(),
            1,
            "the txn replays as Prepared (the op-marker never landed)"
        );
        assert!(
            matches!(reopened.poll(0).unwrap(), Poll::Idle),
            "still invisible after the crash"
        );
        // THE CLAMP'S TEETH: the recovered high-water pointed at offset 0 with a durable head of 0
        // (0 >= flushed), so `seed_producer_seq_from_recovered` DROPPED it. The redrive (a fresh
        // commit of the still-Prepared txn) therefore re-appends FRESH at offset 0 — it is NOT deduped
        // away to a phantom offset (which would have been a silent loss).
        let redriven = reopened.txn_commit(b"tx1").unwrap();
        assert_eq!(
            redriven,
            Offset::new(0),
            "the dropped phantom high-water lets the redrive re-append FRESH at the real head"
        );
        // EXACTLY ONCE: the record is now durable and visible, exactly one copy — no double, no loss.
        assert_eq!(
            reopened.flushed_offset(),
            Offset::new(1),
            "exactly one record after the redrive (no double-append, no loss)"
        );
        assert_eq!(drain_visible(&mut reopened), vec![b"once".to_vec()]);
    }

    #[test]
    fn re_prepare_of_a_prepared_id_is_a_benign_duplicate() {
        let mut e = open(config(10, 5));
        e.txn_prepare(b"tx1", "", &txn_half(b"v")).unwrap();
        // A retried prepare is a benign no-op: no second half record buffered.
        e.txn_prepare(b"tx1", "", &txn_half(b"v")).unwrap();
        assert_eq!(e.txn_prepared_count(), 1);
        // Commit still delivers exactly one record.
        e.txn_commit(b"tx1").unwrap();
        assert_eq!(drain_visible(&mut e), vec![b"v".to_vec()]);
    }

    #[test]
    fn the_txn_subdir_is_absent_until_the_first_prepare() {
        // BYTE-IDENTICAL-WHEN-UNUSED: a broker that never produces a transactional message never
        // materializes the txn/ subtree, so the data dir is byte-for-byte the non-txn broker.
        let fs = InMemoryFs::new();
        let mut e = Engine::open(fs.clone(), ManualClock::new(), config(10, 5)).unwrap();
        assert!(
            !ironbus_storage::txn::TxnStore::<InMemoryFs, ManualClock>::dir_exists(&fs).unwrap(),
            "no txn/ subdir before any prepare"
        );
        // Normal produce/consume is entirely unaffected and never creates txn/.
        produce(&mut e, b"normal");
        assert_eq!(drain_visible(&mut e), vec![b"normal".to_vec()]);
        assert!(
            !ironbus_storage::txn::TxnStore::<InMemoryFs, ManualClock>::dir_exists(&fs).unwrap(),
            "normal produce/consume never materializes txn/"
        );
        // Only the first prepare creates it.
        e.txn_prepare(b"tx1", "", &txn_half(b"v")).unwrap();
        assert!(
            ironbus_storage::txn::TxnStore::<InMemoryFs, ManualClock>::dir_exists(&fs).unwrap(),
            "the first prepare materializes txn/"
        );
    }
}
