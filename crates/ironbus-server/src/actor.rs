// SPDX-License-Identifier: MIT OR Apache-2.0
//! The append actor: a single thread that owns the [`Engine`] and group-commits produces (#177).
//!
//! The pre-#177 server shared the engine behind a `Mutex` and held it across `Session::process`,
//! so a `Pub`'s `fdatasync` ran under the lock: a single stalled disk head-of-line-blocked EVERY
//! connection, pings and acks included, and each producer serialized behind every other producer's
//! flush. This replaces that with the actor model the issue asks for:
//!
//! - ONE actor thread owns the [`Engine`] (the offsets and the active segment), so the single-writer
//!   rule the storage layer requires is kept by construction, with no lock held across an fsync.
//! - Connection handlers fan in over a BOUNDED [`std::sync::mpsc::sync_channel`], each command
//!   carrying a reply channel; a handler SENDS a command and AWAITS its reply instead of locking the
//!   engine. The bound provides backpressure (a producer blocks when the channel is full) without a
//!   custom lock-free structure.
//! - GROUP COMMIT: the actor drains a batch of pending [`Command::Produce`]s, appends each with
//!   [`Engine::append_no_sync`] (no fsync), issues ONE [`Engine::commit_batch`] (`fdatasync`) that
//!   covers the whole batch, and only THEN acks the batch. This amortizes the fsync and removes the
//!   head-of-line block.
//!
//! Pings (and anything that needs no engine state) are answered by the connection handler WITHOUT
//! touching the actor, so a stalled produce `sync_data` on one producer's group never blocks another
//! connection's ping. Acks/flow/sub run as a [`Command::Run`] job that the actor executes against the
//! owned engine. On the non-fsync tiers the actor flushes any pending produce batch (one fsync)
//! BEFORE a job runs, so a job observes a consistent durable head and the total durable order is
//! unchanged. On the PIPELINED sync tier (#1040) a job does NOT quiesce the in-flight barrier: it
//! observes a consistent, MONOTONE durable head that may trail the appended head by the in-flight
//! window (reads are bounded by the flushed frontier, which only advances at durability), and an
//! in-job inline barrier (a txn `commit_batch`, a `force_sync`, a named-stream `commit_tick`)
//! composes safely — the overtaken flight's late completion is a FULL no-op and the in-job-covered
//! waiters release at the post-job reconcile.
//!
//! ## The pipelined sync tier (#1040)
//!
//! Exactly where an ack waits on a REAL pre-ack fsync barrier ([`Engine::commit_syncs_before_ack`],
//! #1026 — durability `sync` on a real-barrier backend), `run_actor` branches ONCE at entry into a
//! pipelined loop: appends stay on the actor, but the covering `fdatasync` runs on a dedicated
//! flusher thread ([`crate::flusher`]) with AT MOST ONE barrier in flight. Each parked reply is
//! stamped with the appended head at park and released ONLY once the durable head reaches it
//! (INV-1, I2). Everything appended while a barrier is in flight merges into the NEXT ticket,
//! dispatched the instant the previous completes — the in-flight fsync IS the batching window
//! (self-clocking group commit; the #454 wall-clock gather is retired). Every other tier runs the
//! legacy loop byte-for-byte.
//!
//! ## Invariants
//!
//! - I2 (ack-implies-durable): a [`Command::Produce`] reply is sent only AFTER the covering
//!   `commit_batch` returns, so a `PubAck` never precedes the fsync that made the record durable.
//! - Single total durable order: the actor assigns offsets and appends serially in arrival order.
//! - No lost replies / no deadlock: every command gets exactly one reply; a closed channel is a typed
//!   [`ActorGone`], never a panic, so neither side hangs forever if the other dies.

use crate::commit_notify::{CommitNotify, StreamCell};
use crate::engine::{AsyncCommit, DiskFullPolicy, Engine, EngineError};
use crate::flusher::{spawn_flusher, FlushJob, SyncDone};
use crate::liveness::ActorWatchdog;
use crate::produce_gate::ProduceCapGate;
use bytes::Bytes;
use ironbus_core::clock::Clock;
use ironbus_core::types::Offset;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Append;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::cluster::client_ack::{ClientAckGate, ClusterProduceRouting};
use crate::cluster::dataplane::{AckDisposition, FollowerReadOutcome};
use crate::cluster::read_consistency::ReadTier;
use ironbus_core::keyshared::MemberId;

/// The default bound on the actor command channel: the most produce/engine commands that may be
/// in flight before a sender blocks (backpressure). Sized for the edge box's bounded connection
/// count: large enough that a healthy burst does not stall, small enough that a wedged actor bounds
/// the queued work rather than buffering without limit. It does not cap the GROUP size (the actor
/// drains everything available each pass); it caps the un-drained backlog.
pub const DEFAULT_CHANNEL_BOUND: usize = 1024;

/// How long [`ProduceSubmission::wait`] parks per `recv_timeout` slice before it re-checks the shared
/// `actor_alive` flag (#949). It bounds ONLY the latency to detect a departed actor on the residual
/// shutdown race (a produce whose reply the exiting actor never sent, whose co-located `channel.tx`
/// keeps the reply channel open so a plain `recv` would block FOREVER); it does NOT add latency to a
/// normal produce, because `recv_timeout` returns the instant the actor sends the outcome (the fast
/// path is unchanged — a value always wakes the wait immediately). A produce that legitimately blocks
/// longer than this (a slow covering fsync) simply re-loops after a cheap flag load; the interval is
/// long enough that such spurious wakeups are negligible on the hot path, short enough that a wedged
/// producer learns [`ActorGone`] promptly at shutdown.
const WAIT_ACTOR_ALIVE_POLL: Duration = Duration::from_millis(250);

/// One recycled produce reply channel: a paired bounded `sync_channel(1)` (#475). The pool keeps the
/// pair together so the SAME channel can carry one publish's outcome after another WITHOUT a fresh
/// per-publish allocation. The `tx` half stays in the pool and is CLONED into each `Command::Produce`
/// (a cheap `Arc` refcount bump, never a heap channel alloc); the `rx` half rides with the in-flight
/// submission and recv's exactly one outcome before the pair returns to the pool. A capacity-1 channel
/// keeps the I2 group-commit semantics byte-for-byte: the actor's send still cannot precede its
/// covering `commit_batch`, and a `recv` still yields exactly one outcome.
///
/// `pub` only so it can ride inside the public [`ProduceSubmission::Pending`] variant; its fields stay
/// private, so a caller can neither construct one nor reach into the channel — it is an opaque,
/// pool-managed handle.
#[derive(Debug)]
pub struct ReplyChannel {
    tx: SyncSender<ProduceOutcome>,
    rx: Receiver<ProduceOutcome>,
}

/// A per-CONNECTION free-list of reusable produce reply channels (#475), so the produce hot path
/// amortizes the `sync_channel(1)` allocation it used to pay PER publish. Each cloned [`EngineHandle`]
/// (one per connection, see `server.rs`) gets its OWN fresh pool, so a recycled channel NEVER crosses
/// between connections (no cross-delivery) and every in-flight publish on a connection still holds a
/// DISTINCT channel for its whole lifetime — exactly the per-publish receiver identity the FIFO reply
/// order and I2 already rely on. Only the owning connection thread ever locks this `Mutex` (it pops on
/// submit and pushes back on `wait`; the actor thread only ever uses a CLONED `tx`, never the pool), so
/// the lock is always uncontended — far cheaper than the heap channel alloc+drop it replaces. The
/// `Arc` lets an in-flight [`ProduceSubmission`] hold a back-reference to return its pair on `wait`
/// while keeping [`EngineHandle`] `Send` (an `Rc` would not cross the move into the connection thread).
///
/// `pub` only because the public [`ProduceSubmission::Pending`] variant holds one; it carries no
/// reachable API surface of its own (the element type's fields are private).
pub type ReplyPool = Arc<Mutex<Vec<ReplyChannel>>>;

/// Pops a reusable reply channel from the pool, or makes a fresh one if the pool is empty (#475). The
/// pool warms to the connection's in-flight window once, then recycles; the steady state pays no
/// channel allocation. The lock is uncontended (only the connection thread touches the pool).
fn pool_take(pool: &ReplyPool) -> ReplyChannel {
    pool.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .pop()
        .unwrap_or_else(|| {
            let (tx, rx) = sync_channel(1);
            ReplyChannel { tx, rx }
        })
}

/// Returns a drained reply channel to the pool for the next publish to reuse (#475). Called only after
/// its single outcome has been `recv`'d, so the channel is empty and ready. A poisoned lock is
/// recovered (the pool is plain data; a panic elsewhere never corrupts it), so recycling never panics.
fn pool_return(pool: &ReplyPool, channel: ReplyChannel) {
    pool.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(channel);
}

/// A produce request's payload, OWNED so it can cross the channel to the actor (the wire [`Append`]
/// borrows the connection's input buffer, which the actor cannot hold). The actor borrows it back as
/// an [`Append`] to append it. Fields mirror [`Append`], plus the opt-in dedup identity (#33).
///
/// The byte fields are [`bytes::Bytes`] (refcounted) rather than `Vec<u8>` (#474): moving an
/// `OwnedAppend` across the append-actor channel is already a move, but carrying the bytes as `Bytes`
/// makes a CLONE (the `#[derive(Clone)]` used by the test/replay paths) and any future slice-of-the-
/// read-buffer handoff a refcount bump instead of a deep copy. The storage encode still copies the
/// payload into the segment buffer when it appends (the `Bytes` is consumed by the borrow there,
/// exactly as the `Vec` was), so durability and the on-disk image are byte-identical.
#[derive(Clone, Debug)]
pub struct OwnedAppend {
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Record flags as raw bits (the codec normalizes `HAS_KEY`; unknown bits are preserved). The
    /// wire-only dedup bit is masked OFF by the session before this crosses the channel.
    pub flags: u8,
    /// The routing or ordering key (empty if none).
    pub key: Bytes,
    /// The record headers blob (empty if none).
    pub headers: Bytes,
    /// The record payload.
    pub payload: Bytes,
    /// The record's body checksums (CRC32C, plus xxh3-64 for a large body), PRE-COMPUTED off the
    /// single-writer append actor on the producing connection thread that built this `OwnedAppend`
    /// (issue #830). `Some` carries the offloaded value so the actor stores it without re-hashing the
    /// body; `None` (the default for test/replay/re-injection constructors) makes the actor compute
    /// the checksum on the append path exactly as before. The value describes the producer-supplied
    /// body (`key ++ headers ++ payload`); the engine trusts it only when the record is stored with
    /// that exact body (it is dropped when the write-path compression seam rewrites the body).
    pub body_checksums: Option<ironbus_core::codec::BodyChecksums>,
    /// The OPT-IN dedup identity (#3, #33): `Some` iff the publish carried a `msg_id` (the dedup
    /// opt-in), owned so it can cross the channel. `None` is the default no-dedup produce.
    pub dedup: Option<OwnedDedup>,
    /// The monotonic instant (nanoseconds, from the clock seam) the session ENQUEUED this produce to
    /// the actor (#68), so the engine can measure the admission SOJOURN (`now - enqueue`) at dequeue
    /// for the CoDel controlled-delay shed. `0` means UN-STAMPED (a test or a path that does not
    /// route through the actor channel), which reads as a zero sojourn (below TARGET, never sheds), so
    /// the field is backward-compatible and CoDel-off behavior is unchanged.
    pub enqueue_monotonic_nanos: u64,
    /// Whether the producer marked this publish FIRE-AND-FORGET (QoS-0, #11, #402): the client did
    /// NOT wait for a `PubAck` and accepts loss by contract. When `true`, the broker gates the
    /// produce on the fire-and-forget token bucket (#336) and DROPS it (without acking) if the bucket
    /// is exhausted; when admitted it appends the record durably as usual but sends NO `PubAck`.
    /// `false` (the default) is the historical at-least-once path with the unchanged `PubAck`, so an
    /// old client is byte-for-byte unchanged. Derived from the wire `PUB_FLAG_FIRE_AND_FORGET` bit by
    /// the session.
    pub fire_and_forget: bool,
    /// The produce ACK LEVEL (#494/#571), derived by the session from the wire PUB flags via
    /// [`ironbus_proto::message::pub_ack_level`] BEFORE the wire-only level bits are masked out of
    /// `flags`. Carried here so the actor can attribute each accepted record to its level
    /// (`c0`/`c1`/`c2`) for the per-ack-level produce counters, without re-reading the (now-masked)
    /// flags. Defaults to [`AckLevel::ServerAck`] (Level 1), the old-client / no-level-bit encoding,
    /// so every existing constructor and an old client are unchanged.
    pub ack_level: ironbus_proto::message::AckLevel,
}

/// An owned copy of a produce's dedup identity (#33), so it can cross the actor channel (the wire
/// [`ironbus_proto::message::PubDedup`] borrows the connection buffer). Mirrors
/// [`crate::engine::DedupRequest`].
#[derive(Clone, Debug)]
pub struct OwnedDedup {
    /// The stable producer identity for dedup keying and epoch fencing (empty = anonymous).
    pub producer_id: Bytes,
    /// The producer's monotonic epoch (the fencing token).
    pub epoch: u64,
    /// The idempotency key the broker deduplicates on (never the body).
    pub msg_id: Bytes,
    /// The OPT-IN Kafka-style idempotent-producer SEQUENCE (V2-M8): `Some` iff the wire publish
    /// carried a `seq`. When present, the broker routes the produce through the DURABLE per-producer
    /// sequence high-water (dedup a retry to exactly-once-append, fence a zombie epoch, reject an
    /// out-of-order gap) instead of the time-bounded `msg_id` window. `None` is today's dedup.
    pub seq: Option<u64>,
}

/// The outcome of a produce, mapped to the wire reply by the session. It carries enough to
/// reproduce the pre-actor `handle_pub` behavior exactly: a success with the assigned offset, the
/// non-fatal drop-new shed, a fatal storage error (which ends the session), or a transient failure,
/// plus the two opt-in dedup outcomes (#33).
#[derive(Debug)]
pub enum ProduceOutcome {
    /// The record is durable (the covering `commit_batch` completed); reply `PubAck` with this offset.
    Appended(Offset),
    /// A BENIGN dedup hit (#33): the `msg_id` was already in the producer's window, so nothing was
    /// appended and this is the ORIGINAL offset. Reply `PubAckDuplicate` (`duplicate = true`,
    /// `rc = 0`), keep the session. Released only after the covering `commit_batch` (I2), so a hit on
    /// an id recorded earlier in the SAME uncommitted batch never replies before that id is durable.
    AppendedDuplicate(Offset),
    /// A stale-epoch FENCE (#33, V2-M8): a zombie session reusing an old `producer_id` presented an
    /// epoch below the broker's known high-water. Reply an error, keep the session (the producer can
    /// re-handshake with a fresh epoch).
    Fenced,
    /// An OUT-OF-ORDER idempotent SEQUENCE rejection (V2-M8): a sequenced publish whose `seq` skipped
    /// past the next-expected (`seq > last_accepted + 1`) was REJECTED rather than silently accepted
    /// (the Kafka `OutOfOrderSequence` semantics), so a later retry of a skipped seq cannot
    /// double-append. Reply a stable error, keep the session (the producer can resync from the
    /// expected sequence). NOTHING was appended.
    OutOfOrder,
    /// The durable-log byte cap shed (drop-new): reply a stable "at capacity" error, keep the session.
    AtCapacity,
    /// A CoDel load-shed (#68): the broker is overloaded past the controlled-delay target, so this
    /// NEW produce was shed (rejected) to protect tail latency. Distinct from `AtCapacity` (a byte-cap
    /// shed) so a producer can tell a latency-load shed from a disk-full shed. It NEVER drops an
    /// already-accepted record (the shed is decided BEFORE the append, so I2 holds). Reply a stable
    /// "shed under load" error, keep the session (a later produce succeeds once the standing delay
    /// clears).
    Shed,
    /// An fsync-HEADROOM shed (#378): the un-fsynced (buffered-but-not-durable) write frontier is at
    /// its configured headroom and a group-commit drain could NOT reduce it (it persists only under a
    /// relaxed durability level, where a commit defers the fsync; under `sync` the drain always frees
    /// the headroom, so this is never reached). The NEW produce is shed to keep the un-fsynced backlog
    /// (the loss window / RAM bound) within the headroom. Distinct from [`ProduceOutcome::Shed`] (a
    /// CoDel latency shed) and [`ProduceOutcome::AtCapacity`] (a disk-full byte-cap shed), so a
    /// producer can tell a headroom shed from the others. It NEVER drops an already-accepted record
    /// (the buffered records stay and are made durable by their level's barrier; only this NEW produce
    /// is rejected, decided before its append), so I2 / no-data-loss hold. Reply a stable typed error,
    /// keep the session (a later produce succeeds once the writer catches up).
    WalHeadroomShed,
    /// A FIRE-AND-FORGET (QoS-0, #11, #402) produce that was APPENDED durably but gets NO `PubAck`:
    /// the producer fired and forgot, so the broker appends the record (covering group-commit fsync,
    /// exactly like a normal produce) but the session sends nothing back. Carries the assigned offset
    /// for the actor's accounting / tests; the session ignores it and replies no frame. This is NOT
    /// an at-least-once promise (the client did not wait for it), so the no-ack is by contract.
    FireAndForgetAppended(Offset),
    /// A FIRE-AND-FORGET (QoS-0, #11, #402) produce DROPPED by the fire-and-forget token bucket
    /// (#336) under load: the broker did NOT append it and sends NO frame, because the QoS-0 producer
    /// accepts loss by contract. Counted by `ironbus_fire_and_forget_shed_total` (a shed is never
    /// silent). It NEVER touches the at-least-once path (the bucket governs only this tier), so a
    /// depleted bucket sheds fire-and-forget messages and NOTHING ELSE.
    FireAndForgetDropped,
    /// A fatal storage error (a frozen writer): reply an error AND end the session.
    Fatal(EngineError),
    /// A transient produce failure: reply a generic error, keep the session.
    Failed(EngineError),
}

/// A produce that has been SUBMITTED but whose outcome has not necessarily been awaited yet: the
/// decoupled half of the pipelined-publish path (#450). The session submits every `Pub` in a pass
/// through [`EngineAccess::produce_submit`] and parks the submission, so the actor sees the whole
/// in-flight window in one drain and covers it with ONE group-commit fsync; the parked submissions
/// are then awaited in FIFO submission order, which is exactly the per-connection reply order the
/// wire contract promises. I2 is untouched: the actor still releases no produce reply before the
/// covering `commit_batch`, so `wait` cannot observe an ack that precedes its fsync.
#[derive(Debug)]
pub enum ProduceSubmission {
    /// The outcome is already known: a direct (same-thread) engine performed the produce
    /// synchronously, so there is nothing to await. The test-only [`EngineAccess`] impls and the
    /// trait's default `produce_submit` use this arm; it keeps the pipelined session logic exercised
    /// against a synchronous engine without a thread.
    Ready(ProduceOutcome),
    /// The produce is in flight to the append actor; the channel yields the outcome only after the
    /// covering group-commit fsync (I2), exactly like [`EngineHandle::produce`]'s awaited reply. The
    /// channel is a RECYCLED pair from the connection's reply pool (#475): it is held intact for this
    /// publish's whole lifetime (so its receiver identity, the FIFO reply order and I2 already depend
    /// on, is unchanged) and returned to `pool` for the next publish to reuse once its single outcome
    /// has been awaited.
    Pending {
        /// The recycled reply channel carrying THIS publish's outcome (its `tx` was cloned into the
        /// `Command::Produce`; this `rx` recv's the one outcome the actor sends after the fsync).
        channel: ReplyChannel,
        /// The connection's reply-channel pool to return the drained channel to on `wait` (#475).
        pool: ReplyPool,
        /// SPIN-ASSISTED reply handoff (#1032): when set, `wait` busy-polls the reply channel for a
        /// bounded window ([`REPLY_SPIN_MICROS`]) before parking in the blocking `recv`, shaving the
        /// cross-thread wake-up (measured ~10us hot, with a 100us+ jitter tail under macOS
        /// scheduling) off the actor->session reply hop. Snapshotted from `!commit_syncs_before_ack()` at `spawn_actor` time (#1026): it is set
        /// ONLY where the ack waits on no pre-ack fsync barrier (the ephemeral memory backend, or a
        /// relaxed `interval`/`async`/`none` durability level), where the reply arrives within tens of
        /// microseconds and the spin converts a scheduler wake into a near-immediate observation. On
        /// durability `sync` over a real-barrier backend the reply is fsync-dominated (milliseconds),
        /// so spinning would burn CPU for nothing — the flag stays `false` and `wait` parks exactly as
        /// before, BY CONSTRUCTION leaving the I2 sync path's wait mechanics untouched. The spin
        /// changes only WHEN the session OBSERVES the outcome, never when the actor SENDS it (still
        /// strictly after the covering commit), and each recycled channel carries exactly one outcome,
        /// so FIFO ack order (#917) and ack-implies-durable (I2) are unaffected by construction.
        spin: bool,
        /// The shared actor-liveness flag (#949): `true` while the append actor runs, flipped to
        /// `false` by the actor thread's drop guard when [`run_actor`] returns (or unwinds). This is
        /// the ONLY way `wait` can detect actor departure on the produce path — the recycled channel's
        /// co-located `tx` (still held right here in `channel`) keeps the reply channel OPEN, so a
        /// plain `recv` never observes a disconnect and would wedge forever on a produce the exiting
        /// actor abandoned reply-less (the residual shutdown race #802's review surfaced). The `Arc` is
        /// SHARED across every connection's [`EngineHandle`] clone (one flag per actor).
        actor_alive: Arc<AtomicBool>,
    },
}

/// The result of a NON-BLOCKING poll of a submitted produce ([`ProduceSubmission::try_take`], #1045):
/// either the covering commit has released the outcome (`Ready`), or it has not yet, in which case the
/// UNCONSUMED submission is handed back (`NotReady`) so the caller can re-park it and poll again on a
/// later pass. This is the primitive the session's persistent parked-window ring uses to release only
/// the READY front prefix of its pipelined produces without ever block-awaiting an un-fsync'd one — so
/// one connection keeps reading and submitting the NEXT batch while the actor fsyncs the current one
/// (the single-connection group-commit overlap #1045 closes), instead of stalling the pass on the
/// fdatasync of the batch it just parked.
#[derive(Debug)]
pub enum TryTake {
    /// The outcome is available (the actor released it after its covering `commit_batch`, I2): the
    /// caller writes its wire reply and drops the entry.
    Ready(ProduceOutcome),
    /// The outcome is not yet available: the submission is returned intact (its channel un-touched, so
    /// a later `try_take` or a blocking `wait` still yields the one outcome) for the caller to re-park.
    NotReady(ProduceSubmission),
}

/// The bounded busy-poll window for a spin-assisted produce-reply wait (#1032), in microseconds.
/// Sized to cover the whole session->actor->session round trip on the no-pre-ack-fsync tiers — one
/// cross-thread wake (measured ~10us hot, but with a scheduler-jitter tail well past 100us) plus the
/// in-memory append (a few us) — so the reply is observed DURING the spin in the common case and the
/// second wake is eliminated (measured: closed-loop single-in-flight wire ack p99 81us -> 35us, p50
/// 23.6us -> 22.0us, and +3-14% throughput on the memory produce paths; the quiet-machine probes on
/// #1032). Small
/// enough that the fallback park (a reply slower than the window: a deep pipelined batch mid-drain, a
/// preempted actor) wastes at most this much CPU before blocking exactly as the historical path did.
const REPLY_SPIN_MICROS: u64 = 100;

/// Receives the one produce outcome with a bounded spin BEFORE parking (#1032): busy-poll `try_recv`
/// for up to [`REPLY_SPIN_MICROS`], then fall back to the blocking `recv`. Semantically identical to a
/// plain `recv` — the channel carries exactly ONE outcome, sent by the actor only after the covering
/// commit (I2), so polling cannot reorder, duplicate, or early-observe anything; only the WAKE
/// mechanics differ (a poll hit skips the scheduler wake a park would need).
fn recv_spin_then_park(
    rx: &Receiver<ProduceOutcome>,
    actor_alive: &AtomicBool,
) -> Result<ProduceOutcome, ActorGone> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_micros(REPLY_SPIN_MICROS);
    loop {
        match rx.try_recv() {
            Ok(outcome) => return Ok(outcome),
            // Unreachable in practice (the submission retains a co-located `tx`, so the channel cannot
            // disconnect while it waits — the #802 invariant), but map it exactly like `wait`'s recv.
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Err(ActorGone),
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if std::time::Instant::now() >= deadline {
            // Window exhausted (the reply is slower than a wake is worth spinning for): park in the
            // SLICED recv (#949) — the same wait as the non-spin tier, so a departed actor is
            // detected here too instead of wedging forever on the open co-located channel.
            return recv_sliced(rx, actor_alive);
        }
        std::hint::spin_loop();
    }
}

/// Parks on the produce reply channel in bounded [`WAIT_ACTOR_ALIVE_POLL`] slices, consulting the
/// shared `actor_alive` flag between slices (#949). A delivered outcome ALWAYS wins (the recv is
/// checked first, and re-checked once after a dead-flag observation), so a real ack released just
/// before the actor exited is never lost to a spurious [`ActorGone`] (I2). Detecting departure needs
/// this flag, not a channel disconnect: the recycled channel's co-located `tx` (#475) keeps the
/// channel open even when the exiting actor drops its cloned `tx` un-sent.
fn recv_sliced(
    rx: &Receiver<ProduceOutcome>,
    actor_alive: &AtomicBool,
) -> Result<ProduceOutcome, ActorGone> {
    loop {
        match rx.recv_timeout(WAIT_ACTOR_ALIVE_POLL) {
            Ok(outcome) => return Ok(outcome),
            // A real disconnect (a non-recycled reply channel, e.g. the direct/test path) is still
            // `ActorGone`, exactly as before.
            Err(RecvTimeoutError::Disconnected) => return Err(ActorGone),
            Err(RecvTimeoutError::Timeout) => {
                // The actor is still running: the outcome is merely not ready yet (a slow covering
                // fsync). Re-loop and keep waiting — no latency is added to a normal produce, only a
                // cheap flag load per slice on a genuinely slow one.
                if actor_alive.load(Ordering::Acquire) {
                    continue;
                }
                // The actor has exited. Re-check the channel ONCE: it may have released the outcome
                // and THEN flipped the flag between our timeout and this load, so a real ack still
                // wins over `ActorGone` (I2 — never lose a durable ack).
                match rx.try_recv() {
                    Ok(outcome) => return Ok(outcome),
                    Err(_) => return Err(ActorGone),
                }
            }
        }
    }
}

impl ProduceSubmission {
    /// Awaits the produce outcome. For a [`ProduceSubmission::Pending`] submission this blocks until
    /// the actor has issued the covering `commit_batch` and released the reply (I2); for a
    /// [`ProduceSubmission::Ready`] one it returns immediately.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the actor exited before replying. Detecting that on the produce path
    /// needs the shared `actor_alive` flag, NOT a channel disconnect: the recycled reply channel's
    /// co-located `tx` (#475) still lives in this submission's `channel`, so the `rx` never observes a
    /// disconnect even when the actor drops its cloned `tx` un-sent. So this recv's in bounded slices
    /// and, on a slice that times out with no outcome, consults `actor_alive` — flipped `false` by the
    /// actor's drop guard on exit — to return [`ActorGone`] instead of wedging forever (#949, closing
    /// the residual #802 race). A delivered outcome ALWAYS wins the flag (recv is checked first), so a
    /// real ack released just before the actor exited is never lost to a spurious `ActorGone` (I2).
    pub fn wait(self) -> Result<ProduceOutcome, ActorGone> {
        match self {
            ProduceSubmission::Ready(outcome) => Ok(outcome),
            ProduceSubmission::Pending {
                channel,
                pool,
                spin,
                actor_alive,
            } => {
                // Recv the ONE outcome the actor sends after the covering fsync (I2). A plain `recv`
                // cannot detect actor departure here — the co-located `tx` in `channel` keeps the
                // channel OPEN, so it would block forever on a produce the exiting actor abandoned
                // reply-less. BOTH tiers therefore park in bounded slices with an actor-liveness
                // check ([`recv_sliced`], #949): the no-pre-ack-fsync tiers (`spin`, #1032) first
                // busy-poll the reply for the bounded spin window — the same hot fast path as before
                // — and fall back to the identical sliced park when the window expires.
                let outcome = if spin {
                    recv_spin_then_park(&channel.rx, &actor_alive)?
                } else {
                    recv_sliced(&channel.rx, &actor_alive)?
                };
                // The channel is now drained and ready: return the intact pair to the pool so the next
                // publish reuses it instead of allocating a fresh one (#475).
                pool_return(&pool, channel);
                Ok(outcome)
            }
        }
    }

    /// NON-BLOCKING poll of the produce outcome (#1045): the decoupled companion to [`wait`]. A
    /// [`ProduceSubmission::Ready`] (a direct/same-thread engine, or a fast-reject) is ALWAYS ready. A
    /// [`ProduceSubmission::Pending`] one is polled with a single `try_recv`: if the actor has already
    /// released the outcome (after its covering `commit_batch`, I2) it is returned [`TryTake::Ready`]
    /// and the recycled channel goes back to the pool (#475); otherwise the submission is handed back
    /// intact as [`TryTake::NotReady`] for the caller to re-park (its channel is untouched, so the one
    /// outcome is still there for a later `try_take` or a blocking `wait`).
    ///
    /// Semantically it can only ever observe what `wait` would: the channel carries exactly ONE
    /// outcome, SENT by the actor strictly after the covering commit, so polling cannot reorder,
    /// duplicate, or early-observe an ack ahead of its fsync — only the WAKE differs (a poll that comes
    /// up empty parks nothing and returns immediately, where `wait` would block).
    ///
    /// # Errors
    /// Returns [`ActorGone`] only if the actor dropped its cloned `tx` UN-sent (it exited before
    /// replying), which disconnects the channel — exactly the condition `wait` maps to `ActorGone`. An
    /// empty (not-yet-ready) channel is NOT an error; it is [`TryTake::NotReady`].
    ///
    /// [`wait`]: ProduceSubmission::wait
    pub fn try_take(self) -> Result<TryTake, ActorGone> {
        match self {
            ProduceSubmission::Ready(outcome) => Ok(TryTake::Ready(outcome)),
            ProduceSubmission::Pending {
                channel,
                pool,
                spin,
                actor_alive,
            } => match channel.rx.try_recv() {
                // The outcome is here: recycle the drained channel (#475) and hand it back.
                Ok(outcome) => {
                    pool_return(&pool, channel);
                    Ok(TryTake::Ready(outcome))
                }
                // Not yet released: return the submission INTACT (channel un-drained) to re-park. The
                // co-located `tx` guarantees the channel cannot be disconnected here (the #802
                // invariant), so `Empty` truly means "the actor has not committed this batch yet".
                Err(TryRecvError::Empty) => Ok(TryTake::NotReady(ProduceSubmission::Pending {
                    channel,
                    pool,
                    spin,
                    actor_alive,
                })),
                // The actor exited before replying (it dropped its cloned `tx` un-sent): map it exactly
                // like `wait`'s recv error so the session ends the connection cleanly.
                Err(TryRecvError::Disconnected) => Err(ActorGone),
            },
        }
    }
}

#[cfg(test)]
impl ProduceSubmission {
    /// Test-only constructor for a PENDING submission over a raw channel the test drives (#1045), so a
    /// session test can control DETERMINISTICALLY when each parked produce's outcome becomes ready (the
    /// ready-prefix release path) without a real actor thread or a real fsync. The returned
    /// [`SyncSender`] is a SECOND handle on the reply channel: send a [`ProduceOutcome`] on it to make
    /// this submission observe as [`TryTake::Ready`] (or unblock its `wait`); hold it un-sent to keep
    /// the submission [`TryTake::NotReady`]. The submission retains its OWN co-located `tx`, so dropping
    /// the returned sender never disconnects the channel (it stays `NotReady`, never `ActorGone`),
    /// matching the production #802 invariant.
    pub(crate) fn pending_for_test() -> (Self, SyncSender<ProduceOutcome>) {
        let (tx, rx) = sync_channel(1);
        let submission = ProduceSubmission::Pending {
            channel: ReplyChannel { tx: tx.clone(), rx },
            // A throwaway per-submission pool: the recycled channel returns here on release and is
            // simply dropped with the test, never crossing to another connection.
            pool: Arc::new(Mutex::new(Vec::new())),
            // No spin: the test drives readiness explicitly, so the wait mechanics are irrelevant.
            spin: false,
            // A standing-alive flag: these deterministic tests have no real actor whose departure
            // the sliced wait (#949) would need to detect.
            actor_alive: Arc::new(AtomicBool::new(true)),
        };
        (submission, tx)
    }
}

/// The error a handler sees when the actor is gone (it exited or panicked, so the command channel or
/// the reply channel is closed). It is a TYPED error, never a panic, so a connection winds down
/// cleanly instead of hanging forever on a dead actor (invariant: no lost replies / no deadlock).
#[derive(Debug)]
pub struct ActorGone;

impl core::fmt::Display for ActorGone {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the append actor is no longer running")
    }
}

impl std::error::Error for ActorGone {}

/// A unit of engine work the actor runs on the owned engine: it captures its inputs by value and
/// sends its own result over the reply channel it closed over. Used for every engine operation that
/// is not a group-committed produce (acks, flow/poll, subscribe, checkpoint). Boxed so one channel
/// carries heterogeneous jobs; `Send` so it can cross to the actor thread.
type Job<F, C> = Box<dyn FnOnce(&mut Engine<F, C>) + Send>;

/// A command the actor processes. `Produce` is batched and group-committed; `Run` is any other engine
/// operation, run between batches (after the pending batch is flushed). `Shutdown` asks the actor to
/// flush its pending batch, checkpoint every group, and exit, preserving the graceful-shutdown drain
/// (#195) even though the engine now lives behind the actor rather than a shared `Mutex`.
enum Command<F: Filesystem, C: Clock> {
    /// A produce to batch into the next group commit, with the channel to reply on once durable.
    Produce {
        /// The owned produce payload.
        append: OwnedAppend,
        /// The one-shot reply channel for the produce outcome (sent only after the covering fsync).
        reply: SyncSender<ProduceOutcome>,
    },
    /// A LEVEL-0 (no-ack / fire-and-forget) produce to batch into the next group commit with NO reply
    /// channel (#495, design option (b)). The actor still does the append on its single-writer storage
    /// (so the single total order and I2 for OTHER records hold) and covers it in the SAME
    /// `commit_batch` as the rest of the batch, but it NEVER parks a reply and sends NOTHING back: the
    /// L0 producer fired and forgot, so it allocated no reply channel and does not wait for the fsync.
    /// This GENERALIZES the historical `PUB_FLAG_FIRE_AND_FORGET` path (an old faf publish IS a Level-0
    /// publish): the append's `fire_and_forget` marker still gates it on the fire-and-forget token
    /// bucket (#336) and a bucket/CoDel/headroom shed simply drops it with no frame, exactly as the
    /// reply-bearing faf path did — only now without the wasted reply-channel allocation, park, and
    /// fsync-wait. The connection-thread byte-cap pre-check (#476) sheds an over-cap L0 BEFORE this is
    /// ever sent (counted in `fire_and_forget_shed`), so this command is only ever reached for an L0
    /// produce the gate did not fast-reject.
    ProduceNoReply {
        /// The owned Level-0 produce payload (its `fire_and_forget` marker is set, so the actor's
        /// fire-and-forget admission and the no-ack disposition apply).
        append: OwnedAppend,
    },
    /// A BATCH of LEVEL-0 (no-ack / fire-and-forget) produces submitted as ONE channel send (#11 fast
    /// path): the session accumulates the Level-0 produces decoded from one socket read and hands them
    /// over in a single `Command` instead of one send per message, cutting the per-message
    /// session->actor channel-send + waker-notify cost that caps the QoS-0 ingest rate. The actor
    /// appends each IN ORDER with the SAME admission + no-reply disposition as [`Command::ProduceNoReply`]
    /// (every append joins the pending batch and is covered by the one `commit_batch`); the per-append
    /// byte-cap shed (#476) already ran at the connection thread (counted in `fire_and_forget_shed`)
    /// when the batch was built, so each append here is one the gate did not fast-reject. Order is
    /// preserved because the session flushes this batch BEFORE any later Level-1 produce or non-produce
    /// job, so the actor still observes the connection's single total order.
    ProduceNoReplyBatch {
        /// The owned Level-0 produce payloads, in connection order.
        appends: Vec<OwnedAppend>,
    },
    /// Run an engine job (an ack, a flow/poll batch, a subscribe, a checkpoint), then it replies itself.
    Run(Job<F, C>),
    /// Graceful shutdown: flush the pending batch, checkpoint every group, then exit the actor loop.
    /// Carries a reply so the caller can await the drain's result (so `cmd_serve` exits 0 only after
    /// the final fsync + checkpoints completed, with no acked-but-not-durable loss).
    Shutdown(SyncSender<Result<(), EngineError>>),
}

/// A cloneable handle a connection handler uses to talk to the actor: it sends commands and awaits
/// replies on the bounded channel instead of locking the engine. Cloning hands each connection its
/// own sender into the same actor; the actor stops when the last handle is dropped (or on an explicit
/// [`EngineHandle::shutdown`]).
pub struct EngineHandle<F: Filesystem, C: Clock> {
    tx: SyncSender<Command<F, C>>,
    /// A clone of the engine's clock seam (#68), so a connection handler can read the monotonic
    /// instant it ENQUEUES a produce at WITHOUT a round-trip through the actor. The session stamps
    /// this onto the produce so the engine can measure the admission SOJOURN (`dequeue - enqueue`)
    /// for the CoDel controlled-delay shed. It is the SAME clock the actor's engine reads at dequeue
    /// (a `ManualClock` clone aliases via `Arc`, a `SystemClock` clone keeps the same monotonic
    /// origin), so the two readings are comparable.
    clock: C,
    /// The static per-consumer credit caps (#65, #275, #292), snapshotted from the engine config at
    /// `spawn_actor` time so the `Connect` handshake can NEGOTIATE the per-consumer credit WITHOUT a
    /// round-trip through the actor. They are fixed for the life of the engine (a `serve` flag sets
    /// them once for every connection), so a cheap copy in the handle is exact and never drifts. Reading
    /// them off the actor is what keeps `Connect` (like `Ping`) off the actor's checkpoint/fsync path, so
    /// a stalled produce on one connection cannot head-of-line-block another connection's handshake
    /// (invariant 4, #177). `.0` is the message-count cap (`consumer_credit`, floored to >= 1), `.1` is
    /// the byte-budget cap (`consumer_credit_bytes`, `0` = unlimited).
    consumer_credit_caps: (u32, u64),
    /// The per-CONNECTION free-list of reusable produce reply channels (#475): `produce_submit` pops a
    /// recycled `sync_channel(1)` from here instead of allocating one PER publish, removing the
    /// per-publish channel alloc+drop from the produce hot path. [`Clone`] gives each new connection a
    /// FRESH empty pool (a recycled channel never crosses connections, so no cross-delivery), and the
    /// pool is only ever locked by the owning connection thread (uncontended). It carries no produce
    /// state: it is purely an allocation cache, so it never affects reply ORDER or I2.
    reply_pool: ReplyPool,
    /// The connection-thread byte-cap fast-reject gate (#476, fixes #465): a relaxed-atomic snapshot
    /// of the durable-log byte-cap shed state the connection thread reads BEFORE the blocking
    /// `tx.send`, so an at-or-over-cap produce is replied `AtCapacity` immediately WITHOUT enqueuing
    /// onto a possibly-full (blocking) actor channel. SHARED across every connection (one gate per
    /// actor), so a `clone` keeps the SAME `Arc` (unlike `reply_pool`): the actor publishes the one
    /// authoritative byte total here and every connection reads it. The gate is a fast-reject FILTER
    /// only; the actor's own byte-cap check stays authoritative (I2 / ordering), and the gate is
    /// engineered to NEVER false-reject (see [`crate::produce_gate`]).
    cap_gate: Arc<ProduceCapGate>,
    /// Whether a produce reply wait should SPIN before parking (#1032): the negation of
    /// [`crate::engine::Engine::commit_syncs_before_ack`] (#1026), snapshotted at `spawn_actor` time
    /// exactly like `consumer_credit_caps` (both inputs — the durability level and the backend type —
    /// are fixed for the engine's life, so the snapshot never drifts). `true` on the ephemeral memory
    /// backend and the relaxed `interval`/`async`/`none` levels, where an ack waits on no fsync
    /// barrier and the reply round trip is tens of microseconds — there a bounded busy-poll in
    /// [`ProduceSubmission::wait`] observes the reply without the second scheduler wake. `false` on
    /// durability `sync` over a real-barrier backend: the reply is fsync-dominated, so the wait parks
    /// immediately, byte-for-byte the historical path (the I2 sync tier is untouched by construction).
    reply_spin: bool,
    /// The CLUSTER produce-ack gate slot (#719, V2-C2): `None` on a SINGLE-NODE / no-cluster broker
    /// (the slot is never even created, so the produce-ack hot path never consults it and is
    /// byte-for-byte today's — the single-node guarantee, owned by this `Option`). On a clustered serve
    /// it is `Some(Arc<OnceLock<..>>)`: a shared, set-once slot created at serve start and POPULATED by
    /// the data-plane bootstrap thread once the committed placement builds the
    /// [`ClientAckGate`](crate::cluster::client_ack::ClientAckGate). The `Arc` is SHARED on clone (like
    /// `cap_gate`): every connection reads the one slot the bootstrap fills. Until it is filled (the
    /// brief bootstrap window) the produce path acks immediately exactly as the non-cluster path does.
    client_ack: Option<ClientAckSlot<F, C>>,
    /// The actor-progress watchdog (#862): the SAME `Arc` the actor thread stamps `busy`/`idle` on
    /// around each command batch (including its covering fsync). The health server reads it (via
    /// [`EngineAccess::actor_watchdog_overran`]) WITHOUT going through the actor, so a HUNG fsync that
    /// blocks the actor forever flips `/healthz` and `/readyz` to 503 instead of leaving liveness green.
    /// Shared on clone (like `cap_gate`): one watchdog per actor. Disabled (`bound == 0`) until the
    /// serve path sets the bound via [`set_actor_watchdog_bound`](Self::set_actor_watchdog_bound).
    actor_watchdog: Arc<ActorWatchdog>,
    /// The shared actor-liveness flag (#949): `true` while the append actor runs, flipped `false` by
    /// the actor thread's drop guard when [`run_actor`] returns or unwinds. A [`ProduceSubmission::Pending`]
    /// captures a clone so [`ProduceSubmission::wait`] can detect actor departure DESPITE the recycled
    /// reply channel's co-located `tx` keeping the channel open — the fix for the residual shutdown race
    /// where a produce whose reply the exiting actor never sent would otherwise wedge forever. Shared on
    /// clone (like `cap_gate`): one flag per actor.
    actor_alive: Arc<AtomicBool>,
    /// The event-driven consume long-poll budget in MILLISECONDS (push delivery), snapshotted from
    /// [`crate::engine::EngineConfig::consume_longpoll_ms`] at `spawn_actor` time exactly like
    /// `consumer_credit_caps` — a fixed-for-life value the `Connect` path reads LOCALLY (no actor
    /// round-trip) to set `Session::consume_longpoll_ms`. `0` (the default) is OFF: an idle Flow/Fetch
    /// returns empty immediately, byte-for-byte today's behavior.
    consume_longpoll_ms: u64,
    /// The engine-wide commit-notify wakeup seam (push delivery): the SAME `Arc` the append actor
    /// [`CommitNotify::bump`]s whenever the durable poll frontier advances, so an idle consumer that
    /// long-polls can wake the instant a record commits instead of returning empty. SHARED across every
    /// connection (one per actor), so a `clone` keeps the SAME `Arc` (like `cap_gate`). Consulted only
    /// when `consume_longpoll_ms > 0`; the default-off path never touches it.
    commit_notify: Arc<CommitNotify>,
}

/// The shared, set-once slot holding the clustered [`ClientAckGate`] (#719). Created empty at serve
/// start and filled by the data-plane bootstrap once the placement commits, so every per-connection
/// [`EngineHandle`] clone (which captured the slot at serve start) reaches the SAME gate.
pub type ClientAckSlot<F, C> = Arc<OnceLock<Arc<ClientAckGate<F, C>>>>;

// Derived `Clone` would demand `F: Clone`; the handle clones the `SyncSender` and the clock (`C` is
// already `Clock + Clone` everywhere a handle is built), so spell it out for any `F`.
impl<F: Filesystem, C: Clock + Clone> Clone for EngineHandle<F, C> {
    fn clone(&self) -> Self {
        EngineHandle {
            tx: self.tx.clone(),
            clock: self.clock.clone(),
            consumer_credit_caps: self.consumer_credit_caps,
            // A FRESH pool per clone (#475): each connection gets its own handle (see `server.rs`), so
            // recycled reply channels stay strictly per-connection and never cross-deliver. The pool
            // warms lazily on that connection's first produces.
            reply_pool: Arc::new(Mutex::new(Vec::new())),
            // The SAME shared gate (#476): every connection reads the one byte-cap snapshot the actor
            // publishes, so the `Arc` is shared on clone (NOT freshened like `reply_pool`).
            cap_gate: Arc::clone(&self.cap_gate),
            // The same fixed-for-the-engine's-life spin discriminant (#1032): a plain copy.
            reply_spin: self.reply_spin,
            // The SAME shared cluster produce-ack slot (#719): every connection reads the one slot the
            // data-plane bootstrap fills, so the `Arc<OnceLock>` is shared on clone. `None` off-cluster.
            client_ack: self.client_ack.clone(),
            // The SAME shared actor-progress watchdog (#862): one per actor, read by the health server.
            actor_watchdog: Arc::clone(&self.actor_watchdog),
            // The SAME shared actor-liveness flag (#949): one per actor, observed by a pending wait.
            actor_alive: Arc::clone(&self.actor_alive),
            // The fixed-for-life long-poll budget (push delivery): a plain copy, like `reply_spin`.
            consume_longpoll_ms: self.consume_longpoll_ms,
            // The SAME shared commit-notify seam (push delivery): one per actor, bumped by the actor
            // and waited on by every idle long-polling consumer, so the `Arc` is shared on clone.
            commit_notify: Arc::clone(&self.commit_notify),
        }
    }
}

impl<F: Filesystem + 'static, C: Clock + 'static> EngineHandle<F, C> {
    /// Install the SHARED cluster produce-ack slot (#719) on this base handle, returning the handle.
    /// Called ONCE on a clustered serve, RIGHT AFTER [`spawn_actor_with_gather`] and BEFORE any
    /// per-connection clone, so every connection's handle captures the same slot. The slot is filled
    /// later by the data-plane bootstrap once the placement commits. A single-node / no-cluster serve
    /// never calls this, so its handles carry `None` and the produce-ack path stays byte-for-byte
    /// today's (the single-node guarantee).
    #[must_use]
    pub fn with_client_ack_slot(mut self, slot: ClientAckSlot<F, C>) -> Self {
        self.client_ack = Some(slot);
        self
    }

    /// Arm the append-actor wedge watchdog (#862) with an overrun bound in NANOSECONDS; `0` DISABLES it
    /// (the default). Called ONCE at serve start from the configured bound, BEFORE any produce can wedge,
    /// so a hung durability fsync that blocks the actor longer than `bound_nanos` flips `/healthz` and
    /// `/readyz` to 503 (via [`EngineAccess::actor_watchdog_overran`]) instead of leaving liveness green.
    /// The bound is shared across every connection's handle clone (one watchdog per actor).
    pub fn set_actor_watchdog_bound(&self, bound_nanos: u64) {
        self.actor_watchdog.set_bound_nanos(bound_nanos);
    }

    /// The shared cluster produce-ack gate (#719), once the data-plane bootstrap has filled the slot;
    /// `None` on a single-node / no-cluster serve (no slot) or during the brief bootstrap window before
    /// the placement commits (the slot exists but is empty). The produce path consults it ONLY when it
    /// is `Some` — the single-node path never reaches here.
    #[must_use]
    fn client_ack_gate(&self) -> Option<&Arc<ClientAckGate<F, C>>> {
        self.client_ack.as_ref().and_then(|slot| slot.get())
    }

    /// Drop any released-but-undrained cluster produce-acks for a DISCONNECTED producer connection
    /// (#719), so the gate's outbox does not leak. An inherent forwarder (the connection-cleanup path in
    /// `server.rs` holds a concrete [`EngineHandle`], not an `EngineAccess` bound). A no-op on a
    /// single-node / no-cluster broker (no gate), so the disconnect path is byte-for-byte unchanged.
    pub fn drop_client_acks(&self, member: MemberId) {
        if let Some(gate) = self.client_ack_gate() {
            gate.drop_connection(member);
        }
    }

    /// The static per-consumer credit caps (#292): `(consumer_credit, consumer_credit_bytes)`,
    /// snapshotted from the engine config at `spawn_actor`. Read by the `Connect` handshake to
    /// negotiate the per-consumer credit WITHOUT a round-trip through the actor (so a stalled produce
    /// cannot head-of-line-block a handshake, #177). `.0` is floored to >= 1; `.1` of `0` is unlimited.
    #[must_use]
    pub fn consumer_credit_caps(&self) -> (u32, u64) {
        self.consumer_credit_caps
    }

    /// The event-driven consume long-poll budget in MILLISECONDS (push delivery), snapshotted from the
    /// engine config at `spawn_actor`. Read by the connection setup to seed `Session::consume_longpoll_ms`
    /// WITHOUT an actor round-trip (like [`EngineHandle::consumer_credit_caps`]). `0` = OFF (the default).
    #[must_use]
    pub fn consume_longpoll_ms(&self) -> u64 {
        self.consume_longpoll_ms
    }

    /// The engine-wide commit-notify wakeup seam (push delivery): the shared `Arc` an idle
    /// long-polling consumer waits on and the append actor bumps on every durable-frontier advance.
    #[must_use]
    pub fn commit_notify(&self) -> &Arc<CommitNotify> {
        &self.commit_notify
    }

    /// Submits a produce for the next group commit and AWAITS its outcome. The reply arrives only
    /// after the covering `commit_batch` fsync completes (I2), so a `PubAck` derived from
    /// [`ProduceOutcome::Appended`] is always ack-implies-durable. Blocks while the bounded channel is
    /// full (backpressure) or while the actor is mid-fsync, but never deadlocks: the actor always
    /// drains and replies.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the actor exited before the produce could be enqueued or replied,
    /// so the handler ends the connection cleanly rather than hanging.
    pub fn produce(&self, append: OwnedAppend) -> Result<ProduceOutcome, ActorGone> {
        self.produce_submit(append)?.wait()
    }

    /// Submits a produce for the next group commit WITHOUT awaiting its outcome, returning the
    /// pending [`ProduceSubmission`] (#450): the pipelined-publish primitive. The send into the
    /// bounded channel still blocks when the channel is full (backpressure), but the caller does not
    /// wait for the covering fsync, so a session can put a whole window of produces in front of the
    /// actor before awaiting the first reply; the actor drains them as ONE batch and covers the batch
    /// with one `commit_batch`. The reply itself is still released only after that fsync (I2), so
    /// awaiting the submission later yields exactly what [`EngineHandle::produce`] would have.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the actor exited before the produce could be enqueued.
    pub fn produce_submit(&self, append: OwnedAppend) -> Result<ProduceSubmission, ActorGone> {
        // CONNECTION-THREAD FAST-REJECT (#476, fixes #465): an O(1) relaxed-atomic read of the
        // byte-cap shed state BEFORE the blocking `tx.send`. When the gate is SURE the actor would
        // shed this produce with `AtCapacity` (the log is at or over its drop-new byte cap), reply
        // `AtCapacity` IMMEDIATELY without enqueuing — so a saturated channel can no longer make a
        // client BLOCK on `send` ahead of a shed it was always going to get (the #465 symptom).
        //
        // It is a fast-reject FILTER, never the source of truth: the actor's own byte-cap check
        // (`Engine::append_no_sync` -> `Log::append`) is UNCHANGED and still authoritative for I2 and
        // the single total order. The gate is engineered to NEVER false-reject (it only fires when the
        // snapshot is provably still over cap at the actor, and disengages under drop-oldest); when it
        // is not sure it returns `false` and the produce takes the normal, fully-authoritative path.
        // The `Ready` arm short-circuits the whole channel round-trip, exactly like the direct-engine
        // submission, so the session maps it through the identical `AtCapacity` reply seam.
        if self.cap_gate.would_shed() {
            // Count the fast-reject so it is NOT a silent shed (#476): the actor folds this into the
            // engine's authoritative `produce_rejected` on its next batch, so a fast-reject is counted
            // exactly like an in-actor `AtCapacity` shed. Then reply `AtCapacity` immediately.
            self.cap_gate.record_fast_reject();
            return Ok(ProduceSubmission::Ready(ProduceOutcome::AtCapacity));
        }
        // Take a RECYCLED reply channel from this connection's pool (#475) instead of allocating a
        // fresh `sync_channel(1)` per publish. Clone its `tx` into the command (a cheap `Arc` bump);
        // the pair's `rx` rides with the submission and recycles on `wait`.
        let channel = pool_take(&self.reply_pool);
        let reply = channel.tx.clone();
        if self
            .tx
            .send(Command::Produce { append, reply })
            .map_err(|_| ActorGone)
            .is_err()
        {
            // The actor is gone: return the unused channel to the pool (the cloned `tx` we just made is
            // dropped with the failed command) so a later handle op can still reuse it, and report it.
            pool_return(&self.reply_pool, channel);
            return Err(ActorGone);
        }
        Ok(ProduceSubmission::Pending {
            channel,
            pool: Arc::clone(&self.reply_pool),
            // The no-pre-ack-fsync tiers get the spin-assisted wait (#1032); the sync tier parks
            // exactly as before (fixed at spawn time, see the field's doc).
            spin: self.reply_spin,
            // Capture the shared liveness flag so `wait` can detect actor departure despite the
            // recycled channel's co-located `tx` keeping the reply channel open (#949).
            actor_alive: Arc::clone(&self.actor_alive),
        })
    }

    /// Submits a LEVEL-0 (no-ack / fire-and-forget) produce with NO reply channel (#495): the
    /// NATS-Core-speed path. Unlike [`EngineHandle::produce_submit`] it allocates NO reply channel,
    /// parks NOTHING, and does not wait for the covering fsync — the L0 producer fired and forgot. The
    /// actor still does the append on its single-writer storage (the single total order and I2 for
    /// OTHER records are untouched; this is NOT the phase-5 actor bypass), but sends nothing back.
    ///
    /// It generalizes the historical fire-and-forget path: `append.fire_and_forget` must be set, so the
    /// actor gates the produce on the fire-and-forget token bucket (#336) and a bucket/CoDel/headroom
    /// shed simply drops it with no frame — exactly the old faf disposition, only without the wasted
    /// reply-channel allocation + park + fsync-wait.
    ///
    /// The connection-thread byte-cap fast-reject (#476) runs FIRST, identically to `produce_submit`,
    /// so an at-or-over-cap L0 produce is shed at the connection thread WITHOUT enqueuing (droppable
    /// under overload; the QoS-0 producer accepts loss). That shed is COUNTED — but on the L0 counter,
    /// which the actor folds into `ironbus_fire_and_forget_shed_total` (a fire-and-forget drop, not a
    /// Level-1 `produce_rejected`), so it is never a silent drop.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the actor exited before the produce could be enqueued. (A SHED — the
    /// cap pre-check firing — is NOT an error: the L0 produce is simply dropped, counted, and `Ok`.)
    pub fn produce_no_reply(&self, append: OwnedAppend) -> Result<(), ActorGone> {
        // CONNECTION-THREAD FAST-REJECT (#476, generalized for L0 by #495): the SAME O(1) relaxed read
        // of the byte-cap shed state `produce_submit` does, BEFORE the blocking `tx.send`. When the
        // gate is SURE the actor would shed this produce, DROP it here without enqueuing — the L0
        // producer accepts loss by contract, so there is no ack to send and no client to block. Count
        // it on the L0 shed counter (the actor folds it into `fire_and_forget_shed`, NOT
        // `produce_rejected`), so a dropped L0 is never silent. The gate never false-rejects (see
        // [`crate::produce_gate`]), so a produce it lets through is one the actor would have accepted.
        if self.cap_gate.would_shed() {
            self.cap_gate.record_l0_shed();
            return Ok(());
        }
        // Send the no-reply produce: NO reply channel allocated, NOTHING parked. The send still blocks
        // on a FULL actor channel (backpressure is shared with the at-least-once tier), but the caller
        // does not wait for the reply — there is none.
        self.tx
            .send(Command::ProduceNoReply { append })
            .map_err(|_| ActorGone)
    }

    /// Submits a BATCH of LEVEL-0 (no-ack) produces as ONE channel send (#11 fast path): the coalesced
    /// twin of [`EngineHandle::produce_no_reply`]. Each append runs the SAME O(1) connection-thread
    /// byte-cap fast-reject (#476) the per-message path does — an at-or-over-cap append is dropped here
    /// and counted on the L0 shed counter (never silent) — and only the admitted appends are sent, IN
    /// ORDER, in one `Command::ProduceNoReplyBatch`. If every append sheds, NOTHING is sent (no empty
    /// command). The actor appends each exactly as it would a per-message `ProduceNoReply`, so the
    /// single total order and the no-ack disposition are unchanged; the only difference is one channel
    /// send + one waker notify for the whole batch instead of one per message.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the actor exited before the batch could be enqueued. (A per-append SHED
    /// is NOT an error: the L0 produce is dropped, counted, and the rest of the batch still sends.)
    pub fn produce_no_reply_batch(&self, mut appends: Vec<OwnedAppend>) -> Result<(), ActorGone> {
        if appends.is_empty() {
            return Ok(());
        }
        // FAST PATH — no cap configured (the default): the gate can NEVER shed (`would_shed` is `false`
        // by construction when `cap == 0`), so EVERY append is admitted. Move the whole batch straight
        // into the one command WITHOUT the per-append pre-check and WITHOUT a second `admitted`
        // allocation + element-by-element move. The session already owns exactly this connection's
        // socket-read worth of Level-0 appends, so on the common uncapped QoS-0 hot path this batch
        // submit allocates and copies nothing extra (the very allocation this #11 fast path exists to
        // avoid per message must not be re-introduced per batch).
        if self.cap_gate.cap() == 0 {
            return self
                .tx
                .send(Command::ProduceNoReplyBatch { appends })
                .map_err(|_| ActorGone);
        }
        // CAPPED PATH: per-append fast-reject, SAME as `produce_no_reply`. The byte-cap snapshot can
        // advance as the actor drains, so re-sample it per append (a `would_shed` that fires is SURE the
        // actor would shed; it never false-rejects). Drop at-or-over-cap appends here, count each on the
        // L0 shed counter (folded into `fire_and_forget_shed`, not `produce_rejected`, never silent), and
        // send only the admitted ones, IN ORDER, in one command. If every append sheds, send nothing.
        // Filter at-or-over-cap appends IN PLACE (no second allocation): `retain` calls the predicate
        // once per append in order, so the per-append shed-sampling and the IN-ORDER admission are
        // identical to the per-message path; only the extra `admitted` Vec is gone. If every append
        // sheds, send nothing.
        appends.retain(|_| {
            if self.cap_gate.would_shed() {
                self.cap_gate.record_l0_shed();
                false
            } else {
                true
            }
        });
        if appends.is_empty() {
            return Ok(());
        }
        self.tx
            .send(Command::ProduceNoReplyBatch { appends })
            .map_err(|_| ActorGone)
    }

    /// Runs `job` on the owned engine and AWAITS its result. Used for every engine operation that is
    /// not a group-committed produce: acks, the flow/poll fetch, subscribe/unsubscribe, the
    /// interval/close-path checkpoint. The actor flushes any pending produce batch (one fsync) BEFORE
    /// running the job, so the job observes a consistent durable head and the total durable order is
    /// unchanged. The job captures its inputs by value and returns its output via the reply channel.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the actor exited before the job could run or reply.
    pub fn with<R, J>(&self, job: J) -> Result<R, ActorGone>
    where
        R: Send + 'static,
        J: FnOnce(&mut Engine<F, C>) -> R + Send + 'static,
    {
        let (reply_tx, reply_rx) = sync_channel(1);
        let boxed: Job<F, C> = Box::new(move |engine| {
            let result = job(engine);
            // A closed reply channel means the handler gave up (its connection died); dropping the
            // result is correct, never a panic, so the actor keeps serving other connections.
            let _ = reply_tx.send(result);
        });
        self.tx.send(Command::Run(boxed)).map_err(|_| ActorGone)?;
        reply_rx.recv().map_err(|_| ActorGone)
    }

    /// Asks the actor to gracefully drain: flush the pending produce batch (one fsync), checkpoint
    /// EVERY work-group's cursor, then exit. Returns the drain's result so the caller can exit 0 only
    /// after the final fsync and checkpoints completed (no acked-but-not-durable loss on shutdown,
    /// #195). Idempotent in effect: a second call after the actor has exited returns [`ActorGone`].
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the actor already exited; otherwise the inner result carries any
    /// storage error from the final flush or the checkpoints.
    pub fn shutdown(&self) -> Result<Result<(), EngineError>, ActorGone> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(Command::Shutdown(reply_tx))
            .map_err(|_| ActorGone)?;
        reply_rx.recv().map_err(|_| ActorGone)
    }

    /// Submits a produce and returns its reply receiver WITHOUT awaiting (a blocking send into the
    /// bounded channel, so backpressure still applies). Used only by tests that must enqueue several
    /// produces while the actor is stalled mid-fsync, then collect their outcomes later. Not on the
    /// hot path; the production handler uses [`EngineHandle::produce`], which awaits.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the actor already exited.
    #[cfg(test)]
    pub fn produce_async(
        &self,
        append: OwnedAppend,
    ) -> Result<Receiver<ProduceOutcome>, ActorGone> {
        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(Command::Produce {
                append,
                reply: reply_tx,
            })
            .map_err(|_| ActorGone)?;
        Ok(reply_rx)
    }
}

/// The APPEND SHARD a produce to `stream` routes to (#811), in `0..shards`. The DEFAULT stream `""` is
/// PINNED to shard 0 (mirroring `StreamId::is_default`), preserving its byte-identical single-log path; a
/// named stream hashes its validated name bytes (a stable `DefaultHasher` — never persisted, so the hash
/// algorithm can change freely) modulo `shards`. With `shards == 1` (the unsharded broker today) this
/// always returns 0, so the routing seam is byte-for-byte until a later phase spawns K shard actors.
#[must_use]
pub fn shard_of(stream: &str, shards: usize) -> usize {
    use core::hash::{Hash, Hasher};
    if shards <= 1 || stream.is_empty() {
        return 0;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    stream.as_bytes().hash(&mut hasher);
    usize::try_from(hasher.finish() % shards as u64).unwrap_or(0)
}

/// The engine access a [`Session`](crate::session::Session) needs: a group-committed produce and a
/// generic "run this on the engine" call. Production wires [`EngineHandle`] (the channel to the
/// append actor); session UNIT tests wire [`DirectEngine`] (a same-thread `&mut Engine`), so the
/// dispatch logic is written once and exercised both over the real actor and synchronously without a
/// thread. The `Send + 'static` bounds on `with` are what the channel impl requires; the direct impl
/// satisfies them trivially (it never crosses a thread).
pub trait EngineAccess<F: Filesystem, C: Clock> {
    /// Submits a produce and awaits its [`ProduceOutcome`] (durable, via the covering group-commit
    /// fsync, for [`EngineHandle`]; immediate for [`DirectEngine`]).
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the engine is no longer reachable (the actor exited).
    fn produce(&self, append: OwnedAppend) -> Result<ProduceOutcome, ActorGone>;

    /// Submits a produce WITHOUT awaiting its outcome (#450), so a session can keep a window of
    /// produces in flight and let the actor group-commit them under ONE fsync. The default
    /// implementation performs the produce synchronously and returns it already
    /// [`ProduceSubmission::Ready`], which is exact for the direct (same-thread) engines: there is
    /// no actor to pipeline into, so the awaited and submitted paths are the same one-message group
    /// commit. [`EngineHandle`] overrides this with the real non-awaiting channel send.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the engine is no longer reachable.
    fn produce_submit(&self, append: OwnedAppend) -> Result<ProduceSubmission, ActorGone> {
        Ok(ProduceSubmission::Ready(self.produce(append)?))
    }

    /// Submits a LEVEL-0 (no-ack / fire-and-forget) produce with NO reply channel (#495): the session
    /// routes a Level-0 publish here instead of [`EngineAccess::produce_submit`], so no reply channel
    /// is allocated, nothing is parked, and the connection does not wait for the covering fsync. The
    /// default implementation performs the produce synchronously and DISCARDS the outcome, which is
    /// exact for the direct (same-thread) test engines: there is no actor to bypass the reply for, the
    /// append still happens on the one engine, and an L0 produce never gets a wire frame anyway, so
    /// dropping the outcome reproduces the no-ack contract. [`EngineHandle`] overrides this with the
    /// real no-reply channel send (the cap pre-check + `Command::ProduceNoReply`).
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the engine is no longer reachable. A cap-shed of the L0 produce is NOT
    /// an error (it is a counted fire-and-forget drop), so a shed still returns `Ok`.
    fn produce_no_reply(&self, append: OwnedAppend) -> Result<(), ActorGone> {
        let _ = self.produce(append)?;
        Ok(())
    }

    /// Submits a BATCH of LEVEL-0 (no-ack) produces as ONE handoff (#11 fast path): the coalesced twin
    /// of [`EngineAccess::produce_no_reply`], so the session hands the actor a whole socket-read's worth
    /// of Level-0 produces with one channel send instead of one per message. The default produces each
    /// in order via [`EngineAccess::produce_no_reply`], which is exact for the direct (same-thread) test
    /// engines (no channel to coalesce). [`EngineHandle`] overrides it with the real single
    /// `Command::ProduceNoReplyBatch` send.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the engine is no longer reachable. A per-append cap-shed is NOT an error.
    fn produce_no_reply_batch(&self, appends: Vec<OwnedAppend>) -> Result<(), ActorGone> {
        for append in appends {
            self.produce_no_reply(append)?;
        }
        Ok(())
    }

    /// Runs `job` on the engine and returns its result.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the engine is no longer reachable.
    fn with<R, J>(&self, job: J) -> Result<R, ActorGone>
    where
        R: Send + 'static,
        J: FnOnce(&mut Engine<F, C>) -> R + Send + 'static;

    /// The number of APPEND SHARDS this engine is fanned across (#811). `1` for the single-actor engine
    /// (the default, and every test fixture); a sharded engine returns its shard count. The caller picks a
    /// produce's shard with [`shard_of`]`(stream, self.shard_count())` and dispatches via
    /// [`with_on_shard`](EngineAccess::with_on_shard), so a hot stream's appends never head-of-line-block
    /// a cold stream's on the same core once `K > 1` lands.
    fn shard_count(&self) -> usize {
        1
    }

    /// Run `job` on the append SHARD `shard` owns (#811) — the shard-routed twin of
    /// [`with`](EngineAccess::with). The DEFAULT (single-actor) impl IGNORES `shard` and runs on the one
    /// engine, so it is BYTE-FOR-BYTE identical to `with` while the broker is unsharded (`shard_count() ==
    /// 1`, so the only `shard` a caller ever passes is `0`). A future K-shard engine overrides this to send
    /// the job to shard `shard`'s actor. Landing this seam now (the `StreamId` routing flows through the
    /// dispatch layer) is what later phases flip to spawn K shard actors — the default stream `""` always
    /// resolves to shard 0 ([`shard_of`]), preserving its byte-identical single-log path.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the shard's engine is no longer reachable.
    fn with_on_shard<R, J>(&self, shard: usize, job: J) -> Result<R, ActorGone>
    where
        R: Send + 'static,
        J: FnOnce(&mut Engine<F, C>) -> R + Send + 'static,
    {
        // Single-actor engine: there is one shard (0); route every job to it. A sharded engine overrides.
        debug_assert!(
            shard < self.shard_count(),
            "shard index {shard} out of range for {} shards",
            self.shard_count()
        );
        let _ = shard;
        self.with(job)
    }

    /// The current MONOTONIC time (nanoseconds) from the engine's clock seam, read LOCALLY (no actor
    /// round-trip), so a connection handler can stamp a produce's ENQUEUE instant for the CoDel
    /// admission sojourn (#68). It is the same clock the engine reads at dequeue, so the two readings
    /// are comparable.
    fn now_monotonic_nanos(&self) -> u64;

    /// The static per-consumer credit caps `(consumer_credit, consumer_credit_bytes)` (#292), read
    /// LOCALLY (no actor round-trip), so the `Connect` handshake negotiates the per-consumer credit
    /// off the actor's hot path and a stalled produce cannot head-of-line-block a handshake (#177).
    /// `.0` is the message-count cap (floored to >= 1); `.1` of `0` is unlimited.
    fn consumer_credit_caps(&self) -> (u32, u64);

    /// Whether this engine carries a CLUSTER produce-ack gate (#719): `false` on a SINGLE-NODE /
    /// no-cluster broker (the DEFAULT), so the produce-ack hot path can skip building the gate's bytes
    /// and write the immediate ack directly — the zero-cost byte-identical fast path. A cheap LOCAL read
    /// (no actor round-trip, no lock). [`EngineHandle`] overrides it to report whether its cluster slot
    /// is filled.
    fn has_client_ack_gate(&self) -> bool {
        false
    }

    /// Whether the append actor's IN-FLIGHT command batch has overrun the watchdog bound at
    /// `now_monotonic_nanos` — i.e. a HUNG durability fsync has wedged the actor thread (#862). A cheap
    /// LOCAL, non-blocking atomic read (it does NOT go through the actor, so it answers even while the
    /// actor is wedged). The DEFAULT impl returns `false` (no actor / no watchdog — every non-handle
    /// `EngineAccess`, e.g. an in-process test fixture, is never "wedged"). [`EngineHandle`] overrides it
    /// to consult its shared [`ActorWatchdog`]. The health server uses this to flip `/healthz` and
    /// `/readyz` to 503 on a wedge instead of leaving liveness green or hanging `/readyz` behind the
    /// wedged fsync.
    fn actor_watchdog_overran(&self, _now_monotonic_nanos: u64) -> bool {
        false
    }

    /// Whether the durable-log writer APPEARS healthy (not frozen), read from a PUBLISHED flag WITHOUT
    /// going through the actor (#862), so `/readyz` can answer on a hung writer instead of queuing a job
    /// behind the wedged fsync and HANGING. The DEFAULT returns `true` (no actor / an in-process test
    /// fixture is assumed live); [`EngineHandle`] overrides it to read the actor's last-published
    /// `is_healthy()`. This is an ADVISORY read: it reflects the state as of the last completed batch, so
    /// a freeze becomes visible after the batch that froze the writer commits — exactly when the old
    /// `engine.with(|e| e.is_healthy())` would have observed it, but without the blocking round-trip.
    fn writer_appears_healthy(&self) -> bool {
        true
    }

    /// Whether the append actor is still RUNNING (#922): a cheap LOCAL, non-blocking atomic read of the
    /// shared `actor_alive` flag (#949) — `true` while [`run_actor`] runs, flipped `false` by its drop
    /// guard on return OR unwind (a PANIC also clears it). The DEFAULT impl returns `true` (no actor /
    /// an in-process test fixture is assumed live), mirroring [`EngineAccess::writer_appears_healthy`];
    /// [`EngineHandle`] overrides it to read the shared flag. The health server uses this to flip
    /// `/readyz` (and, outside a drain, `/healthz`) to 503 on an UNEXPECTED actor death — the case the
    /// watchdog cannot see when the actor died IDLE (`processing_since == 0`) or the watchdog is
    /// disabled, and the frozen-writer flag cannot see either (a dead actor publishes nothing).
    fn actor_alive(&self) -> bool {
        true
    }

    /// The engine-wide commit-notify wakeup seam (push delivery), or `None` for an engine that has no
    /// append actor to bump it. The DEFAULT impl returns `None` (every non-handle `EngineAccess` — the
    /// in-process test fixtures — has no separate actor to signal a commit), so a session over such an
    /// engine takes the byte-for-byte-unchanged empty-and-return consume path even when long-poll is
    /// configured (there is nothing to wake it). [`EngineHandle`] overrides it to hand back its shared
    /// [`CommitNotify`], which the actor bumps on every durable-frontier advance. Consulted ONLY when
    /// `Session::consume_longpoll_ms > 0`; the default-off consume path never calls it.
    fn commit_notify(&self) -> Option<&Arc<CommitNotify>> {
        None
    }

    /// Whether an idle consume long-poll should SPIN briefly before parking on the commit-notify
    /// condvar (#1100). The SAME discriminant the produce path spins on (`reply_spin` =
    /// `!Engine::commit_syncs_before_ack()`, #1032/#1026): `true` on the no-pre-ack-fsync tiers (memory
    /// backend or a relaxed `interval`/`async`/`none` level) where a commit is poll-visible within
    /// microseconds, so a bounded busy-poll catches the wake without the park/unpark round-trip whose
    /// jitter tail is the p999 delivery regression; `false` on the fsync-barrier `sync` tier where a
    /// commit is milliseconds away and spinning would only burn a core. The DEFAULT impl returns
    /// `false` (the in-process test fixtures have no actor to bump the seam, so their long-poll never
    /// waits anyway); [`EngineHandle`] overrides it with the snapshotted `reply_spin`. Consulted ONLY
    /// alongside a live [`EngineAccess::commit_notify`] seam when `Session::consume_longpoll_ms > 0`.
    fn consume_wait_spin(&self) -> bool {
        false
    }

    /// The CLUSTER produce-ack decision (#719) for one durable produce on connection `member`: called
    /// AFTER the local group-commit fsync returned `Appended(offset)`, with the `offset`, and the EXACT
    /// wire-`PubAck` frame bytes the session would otherwise write now.
    ///
    /// Returns `None` on a SINGLE-NODE / no-cluster broker (the DEFAULT impl): there is no gate, so the
    /// session writes the immediate ack-after-local-fsync reply exactly as today — byte-for-byte, with
    /// ZERO added work (no lock, no allocation). [`EngineHandle`] overrides it to consult the shared
    /// [`ClientAckGate`](crate::cluster::client_ack::ClientAckGate) ONLY when the cluster slot is filled
    /// (a clustered serve past bootstrap); even then it returns `None` unless the gate is present, so the
    /// non-cluster and pre-bootstrap paths stay the immediate ack. A `Some(AckDisposition)` tells the
    /// session whether to WRITE the reply now or WITHHOLD it (the gate parked it; the data plane releases
    /// it on quorum-fsync, drained later via [`EngineAccess::drain_client_acks`]).
    ///
    /// The DEFAULT-partition scoping (#693 is multi-partition routing) is the gate's concern; the session
    /// passes the default partition. `reply_bytes` is returned verbatim inside `WriteNow` so the caller
    /// can move them back out without a clone on the common immediate-ack path.
    fn client_ack_disposition(
        &self,
        _member: MemberId,
        _offset: u64,
        _reply_bytes: Vec<u8>,
    ) -> Option<AckDisposition> {
        None
    }

    /// Drain (and remove) every cluster produce-ack the data plane RELEASED for connection `member`
    /// since its last pass (#719), in release/offset order, for the session to flush on its OWN pass —
    /// the cross-thread hand-off (the data plane releases on a peer-I/O thread; only the owning
    /// connection's thread may write its socket), exactly like the #497 `ProduceConfirm` drain. The
    /// DEFAULT impl returns empty (single-node / no-cluster: nothing is ever parked, so nothing
    /// releases) WITHOUT any work. [`EngineHandle`] overrides it to drain the gate's outbox when the
    /// cluster slot is filled.
    fn drain_client_acks(&self, _member: MemberId) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// Drop any released-but-undrained cluster produce-acks for a producer connection that DISCONNECTED
    /// (#719), so the gate's outbox does not leak. The DEFAULT impl is a no-op (no gate). [`EngineHandle`]
    /// overrides it to clear the gate's outbox entry when the cluster slot is filled. Called from the
    /// connection-cleanup path, like #497's `drop_l2_confirms`.
    fn drop_client_acks(&self, _member: MemberId) {}

    /// The cluster PRODUCE-ROUTING decision (#735, the `NOT_LEADER` redirect): called by the produce path
    /// BEFORE any local append/ack. The DEFAULT impl returns [`ClusterProduceRouting::Local`] (a
    /// SINGLE-NODE / no-cluster broker — proceed exactly as today, with ZERO work: no lock, no allocation,
    /// the byte-identical hot path). [`EngineHandle`] overrides it to consult the shared
    /// [`ClientAckGate`](crate::cluster::client_ack::ClientAckGate) ONLY when the cluster slot is filled (a
    /// clustered serve past bootstrap); even then it returns `Local` unless this node provably holds a
    /// clustered replica role for the partition it does NOT lead, in which case it returns
    /// [`ClusterProduceRouting::Redirect`] with the current leader's CLIENT-address hint. NEVER a false
    /// `NOT_LEADER` on the leader or on a non-clustered partition.
    fn cluster_produce_routing(&self, _partition: u64) -> ClusterProduceRouting {
        ClusterProduceRouting::Local
    }

    /// Serve a CLUSTER FOLLOWER-READ consume (#735, half B) from this node's follower read plane via the
    /// #723 read-consistency tiers, fail-closed by the SAFE committed watermark. The DEFAULT impl returns
    /// `None` (SINGLE-NODE / no-cluster: there is no follower role — serve the consume the normal way,
    /// with ZERO work). [`EngineHandle`] overrides it to consult the gate ONLY when the cluster slot is
    /// filled; it returns `None` unless this node FOLLOWS the partition (the leader / no-role case uses the
    /// normal path), else `Some(outcome)` — the served zero-copy bytes or a confirm-with-leader signal.
    /// The committed-HW safe-watermark bar is sourced internally by the gate from the metadata status, so
    /// the caller need not know it.
    fn cluster_follower_consume(
        &self,
        _partition: u64,
        _tier: ReadTier,
        _from: Offset,
        _max_records: usize,
        _max_bytes: Option<usize>,
    ) -> Option<FollowerReadOutcome> {
        None
    }
}

// `F: Clone` is required by the follower-read consume override (#735, half B): the gate's
// `serve_follower_consume` builds a read plane over the follower's owned replica log (the #621
// `serve_follower_read` lives in the `F: Filesystem + Clone` impl). Every PRODUCTION path that uses an
// `EngineHandle` as an `EngineAccess` already carries `F: Clone` (the serve loop in `server.rs` requires
// it for `session.process`), and the shipped filesystems (`InMemoryFs`/`StdFs`) are all `Clone`, so this
// adds no real constraint; the CLI/bench helpers that hold a non-`Clone` `EngineHandle` use only its
// inherent methods, not this trait impl.
impl<F: Filesystem + Clone + 'static, C: Clock + Clone + 'static> EngineAccess<F, C>
    for EngineHandle<F, C>
{
    fn produce(&self, append: OwnedAppend) -> Result<ProduceOutcome, ActorGone> {
        EngineHandle::produce(self, append)
    }

    fn produce_submit(&self, append: OwnedAppend) -> Result<ProduceSubmission, ActorGone> {
        // The REAL non-awaiting submit (#450): the produce crosses to the actor now, the covering
        // fsync is awaited later, so a session window group-commits under one `commit_batch`.
        EngineHandle::produce_submit(self, append)
    }

    fn produce_no_reply(&self, append: OwnedAppend) -> Result<(), ActorGone> {
        // The REAL no-reply L0 submit (#495): the cap pre-check, then a `Command::ProduceNoReply` send
        // with NO reply channel, NO park, NO fsync-wait — the NATS-Core-speed path.
        EngineHandle::produce_no_reply(self, append)
    }

    fn produce_no_reply_batch(&self, appends: Vec<OwnedAppend>) -> Result<(), ActorGone> {
        // The REAL batched no-reply submit (#11 fast path): per-append cap pre-check, then ONE
        // `Command::ProduceNoReplyBatch` send — one channel send + one waker notify for the whole
        // socket-read's worth of Level-0 produces instead of one per message.
        EngineHandle::produce_no_reply_batch(self, appends)
    }

    fn with<R, J>(&self, job: J) -> Result<R, ActorGone>
    where
        R: Send + 'static,
        J: FnOnce(&mut Engine<F, C>) -> R + Send + 'static,
    {
        EngineHandle::with(self, job)
    }

    fn now_monotonic_nanos(&self) -> u64 {
        // A LOCAL clock read, no actor round-trip: the handle holds a clone of the engine's clock.
        self.clock.now_monotonic_nanos()
    }

    fn consumer_credit_caps(&self) -> (u32, u64) {
        // A LOCAL read of the snapshotted caps, no actor round-trip (the #177 head-of-line guard).
        EngineHandle::consumer_credit_caps(self)
    }

    fn has_client_ack_gate(&self) -> bool {
        // A cheap local read: the slot exists AND is filled (a clustered serve past bootstrap).
        self.client_ack_gate().is_some()
    }

    fn actor_watchdog_overran(&self, now_monotonic_nanos: u64) -> bool {
        // A non-blocking atomic read of the shared watchdog (#862): does NOT go through the actor, so
        // it answers even while the actor is wedged on a hung fsync. `false` until the serve path arms
        // the bound (`bound == 0` is disabled), so single-node and unconfigured brokers are unaffected.
        self.actor_watchdog.overran(now_monotonic_nanos)
    }

    fn writer_appears_healthy(&self) -> bool {
        // A non-blocking atomic read of the writer-frozen flag the actor publishes after each batch
        // (#862): `/readyz` reads this instead of `engine.with(|e| e.is_healthy())`, so a hung writer
        // can never block the health server. `true` for a fresh broker that has run no batch yet.
        self.actor_watchdog.writer_healthy()
    }

    fn actor_alive(&self) -> bool {
        // A non-blocking atomic read of the shared liveness flag (#949): `true` while `run_actor`
        // runs, flipped `false` by its drop guard on return OR unwind. `/readyz` (and `/healthz`
        // outside a drain) read this to catch an UNEXPECTED actor death the watchdog misses when the
        // actor died idle or the bound is disabled (#922). Never goes through the actor.
        self.actor_alive.load(Ordering::Acquire)
    }

    fn commit_notify(&self) -> Option<&Arc<CommitNotify>> {
        // The shared seam the append actor bumps on every durable-frontier advance (push delivery): an
        // idle long-polling consumer waits on this and wakes the instant a record commits.
        Some(EngineHandle::commit_notify(self))
    }

    fn consume_wait_spin(&self) -> bool {
        // The SAME fixed-for-life discriminant the produce reply wait spins on (#1032): `reply_spin` =
        // `!commit_syncs_before_ack()`, snapshotted at `spawn_actor`. On the no-pre-ack-fsync tiers a
        // commit is poll-visible within microseconds, so an idle long-poll spins briefly to catch the
        // commit-notify wake without the park round-trip (#1100); the fsync `sync` tier stays parked.
        self.reply_spin
    }

    fn client_ack_disposition(
        &self,
        member: MemberId,
        offset: u64,
        reply_bytes: Vec<u8>,
    ) -> Option<AckDisposition> {
        // SINGLE-NODE / no-cluster / pre-bootstrap: `client_ack_gate` is `None`, so this returns `None`
        // with ZERO work (no lock, no alloc) and the session writes the immediate ack exactly as today.
        // Only a clustered serve past bootstrap reaches the gate, which itself NO-OPs (writes now) for
        // every non-C2-fsync configured level or non-led partition.
        let gate = self.client_ack_gate()?;
        Some(gate.on_local_fsynced_ack(
            member,
            crate::cluster::client_ack::DEFAULT_PARTITION,
            offset,
            reply_bytes,
        ))
    }

    fn drain_client_acks(&self, member: MemberId) -> Vec<Vec<u8>> {
        // No gate (single-node / pre-bootstrap): nothing was ever parked, so nothing releases — empty,
        // no work. With a gate, drain this connection's released wire PubAcks (the common case is empty).
        match self.client_ack_gate() {
            Some(gate) => gate.drain_released(member),
            None => Vec::new(),
        }
    }

    fn drop_client_acks(&self, member: MemberId) {
        EngineHandle::drop_client_acks(self, member);
    }

    fn cluster_produce_routing(&self, partition: u64) -> ClusterProduceRouting {
        // SINGLE-NODE / no-cluster / pre-bootstrap: `client_ack_gate` is `None`, so this returns `Local`
        // with ZERO work (no lock, no alloc) and the produce path proceeds exactly as today — the
        // byte-identical hot path. Only a clustered serve past bootstrap reaches the gate, which itself
        // returns `Local` for a led / no-role partition and `Redirect` only for a non-led replica role.
        match self.client_ack_gate() {
            Some(gate) => gate.produce_routing(partition),
            None => ClusterProduceRouting::Local,
        }
    }

    fn cluster_follower_consume(
        &self,
        partition: u64,
        tier: ReadTier,
        from: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Option<FollowerReadOutcome> {
        // SINGLE-NODE / no-cluster / pre-bootstrap: no gate, so this returns `None` with ZERO work and the
        // consume serves through the normal (local-engine) path — byte-identical. Only a clustered serve
        // past bootstrap reaches the gate, which returns `None` unless this node FOLLOWS the partition.
        self.client_ack_gate()?.serve_follower_consume(
            partition,
            tier,
            from,
            max_records,
            max_bytes,
        )
    }
}

/// A test-only [`EngineAccess`] that drives an engine DIRECTLY on the calling thread (no actor, no
/// channel), so the session unit tests can interleave `Session::process` with direct engine reads and
/// mutations exactly as they did before the actor existed. A produce here is a one-message group
/// commit (`append_no_sync` + `commit_batch`), so it still exercises the group-commit primitives and
/// preserves I2 (the outcome reflects the covering fsync).
#[cfg(test)]
pub struct DirectEngine<F: Filesystem, C: Clock> {
    engine: std::cell::RefCell<Engine<F, C>>,
}

#[cfg(test)]
impl<F: Filesystem, C: Clock + Clone> DirectEngine<F, C> {
    /// Wraps an owned engine for direct same-thread access.
    pub fn new(engine: Engine<F, C>) -> Self {
        DirectEngine {
            engine: std::cell::RefCell::new(engine),
        }
    }

    /// Borrows the engine mutably for a direct read or mutation the test does outside a session.
    pub fn engine_mut(&self) -> std::cell::RefMut<'_, Engine<F, C>> {
        self.engine.borrow_mut()
    }
}

#[cfg(test)]
impl<F: Filesystem, C: Clock + Clone> EngineAccess<F, C> for DirectEngine<F, C> {
    fn produce(&self, append: OwnedAppend) -> Result<ProduceOutcome, ActorGone> {
        Ok(produce_once(&mut self.engine.borrow_mut(), &append))
    }

    fn with<R, J>(&self, job: J) -> Result<R, ActorGone>
    where
        R: Send + 'static,
        J: FnOnce(&mut Engine<F, C>) -> R + Send + 'static,
    {
        Ok(job(&mut self.engine.borrow_mut()))
    }

    fn now_monotonic_nanos(&self) -> u64 {
        self.engine.borrow().now_monotonic()
    }

    fn consumer_credit_caps(&self) -> (u32, u64) {
        let e = self.engine.borrow();
        (e.consumer_credit(), e.consumer_credit_bytes())
    }
}

/// A test-only [`EngineAccess`] over a `Mutex`-guarded engine, so a test that drives the health
/// server on its own thread (which needs a `Sync` engine source) can keep inspecting the engine
/// directly through the same `Arc<Mutex<Engine>>`. A produce is a one-message group commit, like
/// [`DirectEngine`]'s. Cloning the `Arc` shares the same engine.
#[cfg(test)]
pub type SharedEngine<F, C> = std::sync::Arc<std::sync::Mutex<Engine<F, C>>>;

#[cfg(test)]
impl<F: Filesystem, C: Clock + Clone> EngineAccess<F, C> for SharedEngine<F, C> {
    fn produce(&self, append: OwnedAppend) -> Result<ProduceOutcome, ActorGone> {
        let mut engine = self
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(produce_once(&mut engine, &append))
    }

    fn with<R, J>(&self, job: J) -> Result<R, ActorGone>
    where
        R: Send + 'static,
        J: FnOnce(&mut Engine<F, C>) -> R + Send + 'static,
    {
        let mut engine = self
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(job(&mut engine))
    }

    fn now_monotonic_nanos(&self) -> u64 {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .now_monotonic()
    }

    fn consumer_credit_caps(&self) -> (u32, u64) {
        let e = self
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (e.consumer_credit(), e.consumer_credit_bytes())
    }

    fn writer_appears_healthy(&self) -> bool {
        // The shared-engine test fixture (a `Mutex<Engine>`, no separate actor): read the REAL writer
        // state under the lock, so a frozen engine reports unhealthy to `/readyz` exactly as the old
        // `engine.with(|e| e.is_healthy())` did. The lock is uncontended in a health test (no real
        // actor holds it across an fsync), so this never blocks — unlike the production `EngineHandle`,
        // whose override reads the actor's PUBLISHED flag so a HUNG actor can never block the read.
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_healthy()
    }
}

/// Borrows an [`OwnedAppend`]'s dedup identity (#33) as an engine [`DedupRequest`], or `None` for a
/// no-dedup produce. The borrow is valid for the duration of the engine call (the owned bytes outlive
/// it), so the engine sees the `producer_id` / `epoch` / `msg_id` without copying again.
fn dedup_request(append: &OwnedAppend) -> Option<crate::engine::DedupRequest<'_>> {
    append.dedup.as_ref().map(|d| crate::engine::DedupRequest {
        producer_id: &d.producer_id,
        epoch: d.epoch,
        msg_id: &d.msg_id,
        seq: d.seq,
    })
}

/// Performs ONE one-message group commit (`append_no_sync_dedup` + `commit_batch`) on `engine`,
/// mapping the result to a [`ProduceOutcome`] exactly as the actor does, so the test-only direct
/// access paths preserve I2 (the outcome reflects the covering fsync), the shed/freeze taxonomy, and
/// the opt-in dedup outcomes (#33).
#[cfg(test)]
fn produce_once<F: Filesystem, C: Clock + Clone>(
    engine: &mut Engine<F, C>,
    append: &OwnedAppend,
) -> ProduceOutcome {
    // FIRE-AND-FORGET (QoS-0, #11) admission, decided FIRST and only for a fire-and-forget produce,
    // exactly as the real actor does, so the direct path preserves the QoS-0 drop-no-ack contract.
    // An exhausted bucket DROPS it (no append, no ack); the bucket governs only this tier.
    if append.fire_and_forget {
        let payload_bytes = u64::try_from(append.payload.len()).unwrap_or(u64::MAX);
        if !engine.fire_and_forget_admit(payload_bytes) {
            return ProduceOutcome::FireAndForgetDropped;
        }
    }
    // The CoDel admission shed (#68), decided before the append exactly as the real actor does, so
    // the direct path preserves the load-shed taxonomy and the no-data-loss property (it never
    // appends a record it shed). A no-op when CoDel is disabled.
    if engine.codel_admit(append.enqueue_monotonic_nanos) {
        engine.retry_budget_record_shed();
        return ProduceOutcome::Shed;
    }
    // The fsync-headroom admission (#378), decided before the append exactly as the real actor does,
    // so the direct path preserves the headroom-shed taxonomy and the no-data-loss property. A no-op
    // when the headroom is disabled (the default). `produce_once` is a one-message group commit, so
    // under `sync` the frontier is drained before each call and this never sheds; under a relaxed
    // level the un-fsynced backlog can accumulate across calls, and once it fills the headroom this
    // sheds the NEW produce (a drain cannot reduce a deferred-sync backlog).
    if engine.wal_headroom_enabled() {
        let record_bytes =
            u64::try_from(append.key.len() + append.headers.len() + append.payload.len())
                .unwrap_or(u64::MAX);
        if !engine.wal_headroom_admit(record_bytes) {
            engine.record_wal_headroom_shed();
            engine.retry_budget_record_shed();
            return ProduceOutcome::WalHeadroomShed;
        }
    }
    let view = Append {
        timestamp_ms: append.timestamp_ms,
        flags: ironbus_core::types::RecordFlags::from_bits(append.flags),
        key: &append.key,
        headers: &append.headers,
        payload: &append.payload,
    };
    match engine.append_no_sync_dedup_checked(&view, dedup_request(append), append.body_checksums) {
        // A fresh append: the covering fsync decides durability (I2). A fire-and-forget produce is
        // made durable identically but maps to the no-ack outcome (#11), so the direct path matches
        // the real actor's QoS-0 contract.
        Ok(crate::engine::AppendOutcome::Appended(offset)) => {
            engine.retry_budget_record_accept();
            match engine.commit_batch() {
                Ok(()) if append.fire_and_forget => ProduceOutcome::FireAndForgetAppended(offset),
                Ok(()) => ProduceOutcome::Appended(offset),
                Err(e) => ProduceOutcome::Fatal(e),
            }
        }
        // A dedup hit: nothing appended, but still commit (a no-op fsync) so a hit on an id recorded
        // earlier in this same one-message batch is durable before the reply (I2 uniformity).
        Ok(crate::engine::AppendOutcome::Duplicate(offset)) => match engine.commit_batch() {
            Ok(()) => ProduceOutcome::AppendedDuplicate(offset),
            Err(e) => ProduceOutcome::Fatal(e),
        },
        // A stale-epoch fence: nothing appended, reject (no fsync needed; nothing changed).
        Ok(crate::engine::AppendOutcome::Fenced { .. }) => ProduceOutcome::Fenced,
        // An out-of-order idempotent sequence (V2-M8): nothing appended, reject (no fsync needed).
        Ok(crate::engine::AppendOutcome::OutOfOrder { .. }) => ProduceOutcome::OutOfOrder,
        Err(e) if e.is_at_capacity() => ProduceOutcome::AtCapacity,
        Err(e) if e.is_fatal() => ProduceOutcome::Fatal(e),
        Err(e) => ProduceOutcome::Failed(e),
    }
}

/// Spawns the append actor on its own thread, returning a handle to talk to it and the thread's join
/// handle. The actor OWNS `engine` for its whole life; callers reach it only through commands. The
/// channel is bounded by `channel_bound` (backpressure). The join handle yields the engine back on a
/// clean exit so a caller (a test, or a shutdown path that needs the filesystem) can recover it.
///
/// The actor exits when it receives [`Command::Shutdown`] OR when the last [`EngineHandle`] is dropped
/// (the command channel disconnects); both paths perform the same graceful drain (flush the pending
/// batch, checkpoint every group) before returning the engine, so a drop-driven shutdown is as safe
/// as an explicit one.
///
/// # Panics
/// Panics if the OS refuses to spawn the actor thread. This is a STARTUP step (the single actor is
/// spawned once when the broker boots), not a request path, so a spawn failure at boot is surfaced as
/// a panic rather than threaded through every later call; the no-panic bar is for the library hot
/// paths, which never spawn.
pub fn spawn_actor<F, C>(
    engine: Engine<F, C>,
    channel_bound: usize,
) -> (EngineHandle<F, C>, std::thread::JoinHandle<Engine<F, C>>)
where
    F: Filesystem + 'static,
    F::File: 'static,
    C: Clock + Clone + 'static,
{
    spawn_actor_with_gather(engine, channel_bound, 0)
}

/// Like [`spawn_actor`]; the historical GROUP-COMMIT GATHER window parameter (#454, #472) is now
/// INERT (#1040). The gather only ever engaged on the fsync-before-ack tier
/// ([`crate::engine::Engine::commit_syncs_before_ack`]; every other tier resolved the window to
/// 0), and that tier now runs the PIPELINED sync branch of [`run_actor`], whose self-clocking
/// group commit strictly dominates a wall-clock window: the in-flight `fdatasync` IS the batching
/// window — everything appended while one barrier is in flight merges into the next ticket,
/// dispatched the instant the previous completes — with zero idle-start latency and unbounded
/// amortization (the 200 us window was both a latency floor and a coalescing ceiling, and it
/// slept to its wall-clock deadline). `gather_micros` is therefore accepted for call-site
/// compatibility (the CLI keeps `--commit-gather-us` parsed, validated, and warned-deprecated)
/// and IGNORED here.
///
/// # Panics
/// Panics if the OS refuses to spawn the actor thread, exactly as [`spawn_actor`]: a STARTUP step,
/// not a request path, so the no-panic bar for the library hot paths is untouched.
pub fn spawn_actor_with_gather<F, C>(
    engine: Engine<F, C>,
    channel_bound: usize,
    _gather_micros: u64,
) -> (EngineHandle<F, C>, std::thread::JoinHandle<Engine<F, C>>)
where
    F: Filesystem + 'static,
    F::File: 'static,
    C: Clock + Clone + 'static,
{
    let (tx, rx) = sync_channel::<Command<F, C>>(channel_bound.max(1));
    // Clone the engine's clock seam BEFORE the engine moves into the actor thread, so the handle can
    // stamp a produce's enqueue instant (the CoDel sojourn measurement, #68) with the SAME clock the
    // actor reads at dequeue.
    let clock = engine.clock_clone();
    // Snapshot the static per-consumer credit caps (#292) BEFORE the engine moves into the actor, so
    // the Connect handshake can negotiate them off the actor's hot path (no round-trip, #177).
    let consumer_credit_caps = (engine.consumer_credit(), engine.consumer_credit_bytes());
    // Snapshot the consume long-poll budget (push delivery) BEFORE the engine moves, exactly like the
    // credit caps above: it is fixed for the engine's life (a `serve` flag sets it once), so the
    // `Connect` path reads it off the handle to seed `Session::consume_longpoll_ms` with no round-trip.
    let consume_longpoll_ms = engine.consume_longpoll_ms();
    // The engine-wide commit-notify wakeup seam (push delivery): ONE per actor, cloned into BOTH the
    // handle template (so every connection shares it) AND the actor thread (which bumps it on every
    // durable-frontier advance). Created unconditionally — it costs a `Mutex<u64>` + `Condvar` and is
    // only ever bumped/waited when a consumer long-polls, so a default-off broker never touches it.
    let commit_notify = CommitNotify::new();
    let actor_commit_notify = Arc::clone(&commit_notify);
    // Snapshot the produce-reply spin discriminant (#1032) BEFORE the engine moves: a reply wait
    // spins only where the ack waits on NO pre-ack fsync barrier (#1026) — the memory backend or a
    // relaxed durability level — where the round trip is tens of microseconds. Both inputs are fixed
    // for the engine's life (the level is not live-reloadable, the backend type is static), so the
    // snapshot is exact, mirroring the actor's own gather-window resolution.
    let reply_spin = !engine.commit_syncs_before_ack();
    // The PIPELINED sync tier (#1040): exactly where an ack waits on a real pre-ack fsync barrier
    // (#1026, the same fixed-for-life snapshot `reply_spin` negates), spawn the dedicated flusher
    // thread and hand its rig to the actor — resolved ONCE here, before the engine moves, exactly
    // like the `reply_spin` snapshot. `None` on every other tier: no flusher thread exists and the
    // legacy loop runs byte-for-byte. The deterministic sim and `produce_once` drive the `Engine`
    // directly and never reach this spawn, so they can never enter the pipelined branch.
    let pipeline = engine.commit_syncs_before_ack().then(|| {
        // Job channel bound 1: depth-1 dispatch by construction (INV-3) — the send can never
        // block because a second barrier is never dispatched while one is outstanding. Completion
        // channel UNBOUNDED: the flusher's send never blocks, so it can never wedge behind a slow
        // actor and the actor can never miss a completion (the L8 topology). The flusher never
        // holds a command-channel sender, so drop-driven shutdown (the last `EngineHandle` drop
        // disconnecting `rx`) is preserved structurally.
        let (req_tx, req_rx) = sync_channel::<FlushJob<F::File>>(1);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<SyncDone>();
        PipelineRig {
            req_tx,
            done_rx,
            flusher: spawn_flusher(req_rx, done_tx),
            max_dirty_bytes: engine.sync_max_dirty_bytes(),
        }
    });
    // Build the connection-thread byte-cap fast-reject gate (#476) BEFORE the engine moves into the
    // actor. The cap is fixed for the engine's life (not live-reloadable), so it is snapshotted once
    // here; the live byte total and the policy sentinel are published by the actor as it runs. The
    // gate is shared (one `Arc` for every connection), and the SAME `Arc` is seeded into the actor so
    // the actor's publishes and the connections' reads see one value.
    let cap_gate = Arc::new(ProduceCapGate::new(engine.max_total_bytes()));
    // Seed the gate to the engine's CURRENT durable bytes and policy, so a broker recovered ALREADY
    // over its cap (a restart on a full log) fast-rejects from the very first produce rather than
    // waiting for the first commit to publish a reading. Publish-only (no reconcile): nothing has run
    // yet, so there are no fast-rejects to fold, and `&engine` is still borrowed before the move.
    match engine.disk_full_policy() {
        DiskFullPolicy::DropNew => cap_gate.publish_drop_new(engine.durable_record_bytes()),
        _ => cap_gate.disengage(),
    }
    let actor_gate = Arc::clone(&cap_gate);
    // The actor-progress watchdog (#862), shared between the actor thread (which stamps busy/idle) and
    // every EngineHandle clone (the health server reads it). Created DISABLED (bound 0); the serve path
    // arms it via `EngineHandle::set_actor_watchdog_bound`, so existing callers/tests are inert by
    // default. The actor's clock is read for the stamp; the health server reads the SAME clock seam.
    let actor_watchdog = Arc::new(ActorWatchdog::new(0));
    let actor_watchdog_thread = Arc::clone(&actor_watchdog);
    let actor_clock = clock.clone();
    // The shared actor-liveness flag (#949): `true` now, flipped `false` by the drop guard below when
    // the actor thread's closure returns OR unwinds, so a `ProduceSubmission::wait` parked on a produce
    // the exiting actor abandoned reply-less (the residual #802 shutdown race) observes the departure and
    // returns `ActorGone` instead of blocking forever behind the recycled channel's co-located `tx`.
    let actor_alive = Arc::new(AtomicBool::new(true));
    let actor_alive_thread = Arc::clone(&actor_alive);
    let join = std::thread::Builder::new()
        .name("ironbus-append-actor".to_string())
        .spawn(move || {
            // Flip the liveness flag `false` when this closure ends by ANY path — a normal `run_actor`
            // return (drop/Shutdown drain) or a panic unwind — so a waiting producer is never wedged by
            // a departed actor (#949). Bound to a local so it outlives the `run_actor` call and drops at
            // scope end, AFTER the returned engine is computed.
            let _actor_alive_guard = ActorAliveGuard(actor_alive_thread);
            run_actor(
                engine,
                &rx,
                pipeline,
                &actor_gate,
                &actor_watchdog_thread,
                &actor_clock,
                &actor_commit_notify,
                consume_longpoll_ms,
            )
        })
        // A thread-spawn failure at startup is unrecoverable for the server, but the no-panic bar is
        // for the LIBRARY hot paths; spawning the single actor at boot is a startup step. Surface it
        // by propagating the panic only here (boot), never on a request path.
        .expect("spawning the append actor thread");
    (
        EngineHandle {
            tx,
            clock,
            consumer_credit_caps,
            // The base handle's pool (#475); each per-connection `clone` gets its own fresh pool, so
            // this one is only used if the base handle itself produces (e.g. in tests).
            reply_pool: Arc::new(Mutex::new(Vec::new())),
            // The shared fast-reject gate (#476); every connection `clone` shares this same `Arc`.
            cap_gate,
            // The spin discriminant snapshotted above (#1032); copied into every connection clone.
            reply_spin,
            // No cluster produce-ack slot by default (#719): the single-node / no-cluster broker never
            // creates one. A clustered serve installs the shared slot via
            // [`EngineHandle::with_client_ack_slot`] right after this returns, BEFORE any connection's
            // handle is cloned, so every connection sees it.
            client_ack: None,
            // The shared actor-progress watchdog (#862), disabled until the serve path arms its bound.
            actor_watchdog,
            // The shared actor-liveness flag (#949), observed by a pending produce's `wait`.
            actor_alive,
            // The consume long-poll budget snapshot + shared commit-notify seam (push delivery).
            consume_longpoll_ms,
            commit_notify,
        },
        join,
    )
}

/// Flips the shared actor-liveness flag `false` when the append actor thread's closure ends by ANY
/// path — a clean [`run_actor`] return (a `Shutdown`/drop drain) or a panic unwind (#949). Held as a
/// local in the actor closure, so its `Drop` is the single point that publishes "the actor is gone" to
/// every [`ProduceSubmission::wait`] parked on a reply the exiting actor never sent. A `Release` store
/// pairs with the `Acquire` load in `wait`, so a producer that sees the flag cleared also sees any
/// outcome the actor released before it exited (that outcome still wins — `wait` recv's first).
struct ActorAliveGuard(Arc<AtomicBool>);

impl Drop for ActorAliveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Refreshes the connection-thread fast-reject gate (#476) AND reconciles its fast-reject count into
/// the engine's authoritative shed counters. Called by the actor thread ONLY — after each
/// `commit_batch` (the one place the durable bytes change) and after a config reload that can flip the
/// policy — so it runs once per batch, amortized with the fsync, never per message.
///
/// Two jobs, both on the actor:
/// 1. RECONCILE: fold any fast-rejects the connection threads performed since the last call into the
///    engine's `produce_rejected` (and the backstop / retry-budget shed signals), so a connection-
///    thread fast-reject is counted EXACTLY like an in-actor `AtCapacity` shed (never a silent shed).
/// 2. PUBLISH the gate's next snapshot. Under [`DiskFullPolicy::DropNew`] it publishes the live
///    `durable_record_bytes` (the gate may then fast-reject an at-or-over-cap produce); under
///    [`DiskFullPolicy::DropOldest`] it DISENGAGES the gate (the under-cap sentinel), because that
///    policy ACCEPTS an over-cap produce after a force-reap, so a connection-thread fast-reject would
///    be a false reject. See [`crate::produce_gate`] for the full no-false-reject argument.
fn refresh_cap_gate<F, C>(gate: &ProduceCapGate, engine: &mut Engine<F, C>)
where
    F: Filesystem,
    C: Clock + Clone,
{
    // 1. Count the fast-rejects performed off the actor since last time (a fast-reject is never
    //    silent). The delta is exact (monotonic total minus the actor's high-water mark). The Level-1
    //    at-least-once fast-reject folds into `produce_rejected`; the Level-0 (no-ack) cap-shed folds
    //    into `fire_and_forget_shed` (#495), because an over-cap L0 drop is a fire-and-forget drop, not
    //    a Level-1 rejection. Two separate exact deltas, each reconciled to its own counter.
    engine.record_fast_reject_sheds(gate.take_unreconciled_fast_rejects());
    engine.record_fire_and_forget_sheds(gate.take_unreconciled_l0_sheds());
    // 2. Publish the gate's next snapshot from the now-current byte total and overflow policy.
    match engine.disk_full_policy() {
        DiskFullPolicy::DropNew => gate.publish_drop_new(engine.durable_record_bytes()),
        // Drop-oldest accepts over-cap produces (force-reap then append), so the gate must not fire.
        // `#[non_exhaustive]` enum: any future non-drop-new policy also disengages, which is the
        // conservative default (fall through to the authoritative actor path).
        _ => gate.disengage(),
    }
}

/// The pipelined sync tier's spawn-time rig (#1040): the dedicated flusher thread plus its two
/// channels, created in [`spawn_actor_with_gather`] BEFORE the engine moves (exactly like the
/// `reply_spin` snapshot) and handed to [`run_actor`]'s pipelined branch. `None` on every other
/// tier: no flusher thread exists and the legacy loop runs byte-for-byte.
///
/// This rig REPLACES the retired #454/#472 wall-clock gather window: the in-flight `fdatasync` is
/// the batching window now (self-clocking, zero idle-start latency, unbounded amortization),
/// where the gather was both a latency floor and a coalescing ceiling that slept to its deadline.
struct PipelineRig<File> {
    /// The depth-1 barrier-job channel's send half (INV-3): bound 1, provably empty at every
    /// dispatch because at most one barrier is ever outstanding.
    req_tx: SyncSender<FlushJob<File>>,
    /// The DEDICATED completion channel (the L8 topology): a returned barrier never rides the
    /// command queue, so it can never be starved behind a command backlog.
    done_rx: Receiver<SyncDone>,
    /// The flusher's join handle, reaped on every `run_actor` return path (after the quiesce, so
    /// the join can never hang on an in-flight barrier).
    flusher: std::thread::JoinHandle<()>,
    /// The spawn-time snapshot of [`Engine::sync_max_dirty_bytes`] (INV-9); `0` disables the
    /// dirty-byte admission throttle.
    max_dirty_bytes: u64,
}

/// One tracked stream in the actor's [`FrontierTracker`]: the last durable head it has already
/// signalled for this stream, plus a CACHED handle to that stream's [`StreamCell`] so a per-batch
/// advance bumps it WITHOUT re-locking the commit-notify registry each commit.
struct TrackedStream {
    /// The last durable poll frontier already signalled to this stream's long-polling consumers. Only
    /// a head STRICTLY GREATER than this bumps (and then advances this), so a re-observation of an
    /// unchanged head is a no-op.
    last_notified: u64,
    /// This stream's wakeup cell (get-or-created from the registry once, then cached here). Bumped
    /// directly on advance — no registry lock on the steady path.
    cell: Arc<StreamCell>,
}

/// The append actor's PER-STREAM commit-notify frontier tracker (push delivery, #1100 L2). For each
/// stream it has observed — the default `""` and every named stream (#588) — it holds the last durable
/// head it signalled and a cached [`StreamCell`] handle, so a per-batch advance scan bumps ONLY the
/// streams whose frontier actually grew (the default log AND any named-stream log that advanced),
/// waking only those streams' waiters. Built ONCE per actor when long-poll is enabled and NEVER touched
/// on a default-off broker, so the produce hot path is byte-for-byte unchanged when push delivery is
/// off. Replaces L1's single `last_notified: u64` (which only ever observed the root log).
struct FrontierTracker {
    /// stream name -> its last-signalled head + cached wakeup cell.
    per_stream: HashMap<Arc<str>, TrackedStream>,
}

impl FrontierTracker {
    /// Seed the tracker with EVERY currently-open stream's RECOVERED head, WITHOUT bumping — so a
    /// broker that recovered a non-empty log does not spuriously wake (there are no waiters at spawn
    /// anyway); only advances AFTER spawn signal. Called once at actor entry when long-poll is enabled.
    fn seed<F, C>(engine: &Engine<F, C>, commit_notify: &CommitNotify) -> FrontierTracker
    where
        F: Filesystem,
        C: Clock + Clone,
    {
        let mut per_stream: HashMap<Arc<str>, TrackedStream> = HashMap::new();
        engine.for_each_poll_frontier(|name, head| {
            let cell = commit_notify.cell(name);
            per_stream.insert(
                Arc::from(name),
                TrackedStream {
                    last_notified: head,
                    cell,
                },
            );
        });
        FrontierTracker { per_stream }
    }

    /// Signal every stream whose DURABLE poll frontier advanced since it was last signalled: scan the
    /// default log AND every named-stream log, and for each one whose head grew, record the new head
    /// and [`StreamCell::bump`] THAT stream's cell (waking only its waiters). Called STRICTLY AFTER the
    /// durability work that may have advanced any frontier, so it never reorders a commit/append/
    /// release. OVER-bumping a stream is harmless (a woken waiter that still finds nothing re-waits or
    /// times out); UNDER-bumping only costs that stream's waiters a little latency (they fall back to
    /// their long-poll timeout). Cheap on the steady state: one head read + compare per open stream,
    /// and a `bump` (a short per-cell lock + `notify_all`) only on a real advance.
    ///
    /// A stream FIRST observed here (declared + produced during the run, so it was absent from the
    /// spawn-time seed) is registered on the spot with `last_notified = 0`; because its first records
    /// jump the head to `> 0`, it BUMPS immediately, so a consumer already parked on the freshly
    /// declared stream wakes on its first commit rather than eating its full budget (over-bump is
    /// harmless if there is no waiter yet).
    fn notify_advances<F, C>(&mut self, engine: &Engine<F, C>, commit_notify: &CommitNotify)
    where
        F: Filesystem,
        C: Clock + Clone,
    {
        let per_stream = &mut self.per_stream;
        engine.for_each_poll_frontier(|name, head| {
            if let Some(tracked) = per_stream.get_mut(name) {
                if head > tracked.last_notified {
                    tracked.last_notified = head;
                    tracked.cell.bump();
                }
            } else {
                let cell = commit_notify.cell(name);
                // First observation post-seed: seed at 0 so a stream that committed its first records
                // this very batch (head > 0) still wakes any already-parked waiter. Over-bump is safe.
                if head > 0 {
                    cell.bump();
                }
                per_stream.insert(
                    Arc::from(name),
                    TrackedStream {
                        last_notified: head,
                        cell,
                    },
                );
            }
        });
    }
}

/// The actor's run loop. It blocks for one command, then DRAINS every command already queued
/// (`try_recv`) into the same pass so a burst of produces group-commits together. Produces are
/// appended (no sync) and their replies parked; a non-produce job or the end of the drain triggers
/// the ONE `commit_batch` that covers the parked produces, after which their replies are released.
/// Returns the engine on exit so a caller can recover it. Branches ONCE at entry on the spawn-time
/// tier snapshot (#1040): with a [`PipelineRig`] it runs [`run_actor_pipelined`] instead.
// The drain/group-commit loop is one cohesive unit (recv → drain → per-command append/run/shutdown →
// one covering fsync → publish); splitting it would scatter the single-writer ordering it enforces. The
// #862 watchdog stamps push it one line over the pedantic 100-line bound.
// One added arg over the pedantic 7-arg bound: the append actor's single-writer loop legitimately
// threads the engine, command channel, pipeline rig, cap gate, watchdog, clock, and (push delivery)
// commit-notify seam — bundling any subset into a struct would only obscure the ownership the loop
// relies on. Same rationale as `handle_connection`'s allow.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn run_actor<F, C>(
    mut engine: Engine<F, C>,
    rx: &Receiver<Command<F, C>>,
    pipeline: Option<PipelineRig<F::File>>,
    cap_gate: &ProduceCapGate,
    watchdog: &ActorWatchdog,
    clock: &C,
    commit_notify: &CommitNotify,
    consume_longpoll_ms: u64,
) -> Engine<F, C>
where
    F: Filesystem,
    C: Clock + Clone,
{
    // The PIPELINED sync tier (#1040), resolved at spawn: decoupled fdatasync, self-clocking group
    // commit, in-flight write merging. Exactly where an ack waits on a real pre-ack fsync barrier
    // (#1026) the pipelined loop runs; every non-fsync tier falls through to the LEGACY loop below,
    // byte-for-byte (an ack there waits on no barrier, so there is nothing to pipeline).
    if let Some(rig) = pipeline {
        return run_actor_pipelined(
            engine,
            rx,
            rig,
            cap_gate,
            watchdog,
            clock,
            commit_notify,
            consume_longpoll_ms,
        );
    }
    // Produces appended this pass but not yet durable: each parked reply is released only after the
    // single covering `commit_batch`, so a `PubAck` never precedes its fsync (I2).
    let mut pending: Vec<PendingProduce> = Vec::new();
    // Push delivery is OPT-IN and default-OFF (`consume_longpoll_ms == 0`): when off, the actor NEVER
    // touches the commit-notify seam, so the group-commit hot path is byte-for-byte the historical one
    // (no `flushed_offset` read, no lock, no `notify_all` per commit). Only a long-poll-enabled broker
    // seeds the last-signalled frontier and bumps on advance.
    let longpoll_enabled = consume_longpoll_ms != 0;
    // The PER-STREAM commit-notify frontier tracker (#1100 L2): seeded to every open stream's recovered
    // head so only real ADVANCES bump, and it bumps ONLY the cells whose stream advanced (the default
    // log AND any named-stream log). `None` (and never built) when long-poll is off, so the group-commit
    // hot path never touches it. Replaces L1's single root-log `last_notified`.
    let mut frontiers = longpoll_enabled.then(|| FrontierTracker::seed(&engine, commit_notify));
    // The per-pass command batch, hoisted and reused across drains exactly like `pending` above (#828):
    // each pass `clear()`s it and `drain(..)`s it empty, so its backing capacity is retained instead of
    // freed and regrown-from-zero every batch. This actor is the single serialization point for all
    // produce/control work, so removing the per-batch alloc + ~log2(N) regrowth reallocs is pure win.
    let mut commands: Vec<Command<F, C>> = Vec::new();
    loop {
        // Block for the next command; a disconnect (the last handle dropped) ends the loop after a
        // final drain so no acked-but-not-durable record is lost. While blocked here the actor is IDLE
        // (the watchdog was cleared at the end of the previous pass), so a quiet broker never trips it.
        let Ok(first) = rx.recv() else {
            // Shutdown drain: mark BUSY across it so a wedged final fsync is still detectable, then exit.
            watchdog.mark_busy(clock.now_monotonic_nanos());
            flush_pending(&mut engine, &mut pending);
            return engine;
        };
        // A command arrived: the actor is now BUSY processing this batch — the append AND the covering
        // durability fsync. The watchdog stamps the start instant (one relaxed store per BATCH); if the
        // fsync HANGS, this stamp stays put while the clock advances and the health server's
        // `actor_watchdog_overran` trips once the bound is exceeded (#862).
        watchdog.mark_busy(clock.now_monotonic_nanos());
        // Reuse the retained buffer: empty it (a `drain(..)` from the previous pass already left it
        // logically empty, but a `Shutdown` early-return skips that, so `clear()` is the invariant), then
        // seed it with the command that unblocked the `recv()`.
        commands.clear();
        commands.push(first);
        // Drain everything immediately available so a concurrent burst of produces forms one group.
        while let Ok(cmd) = rx.try_recv() {
            commands.push(cmd);
        }
        // An explicit `Drain` iterator (not a `for`) so the `Shutdown` arm can hand the STILL-UNPROCESSED
        // tail of this batch to the drain, replying a closing outcome to every produce queued after the
        // `Shutdown` instead of abandoning it reply-less (#802). Draining (rather than `into_iter`)
        // consumes the elements by value while leaving the buffer's capacity for the next pass (#828).
        let mut command_iter = commands.drain(..);
        while let Some(cmd) = command_iter.next() {
            match cmd {
                // An at-least-once (Level-1, or Level-2 falling back to Level-1) produce: do the
                // admission + append and PARK its reply behind the covering fsync (I2). The reply is
                // `Some`, so every disposition sends exactly the frame it always did — this arm is
                // byte-for-byte the historical produce path (the shared helper is a pure extraction).
                Command::Produce { append, reply } => {
                    process_produce(&mut engine, &mut pending, &append, Some(reply));
                }
                // A LEVEL-0 (no-ack / fire-and-forget) produce (#495): the SAME admission + append, but
                // with NO reply channel (`None`), so every disposition — a bucket/CoDel/headroom shed,
                // a dedup hit, a fence, an append, even a fatal freeze — drops silently with no frame,
                // exactly the fire-and-forget contract. An appended L0 still joins the batch and is
                // covered by the one `commit_batch` (single-writer storage / single total order), it
                // just parks `None` so `flush_pending` sends nothing for it.
                Command::ProduceNoReply { append } => {
                    process_produce(&mut engine, &mut pending, &append, None);
                }
                // A BATCH of Level-0 produces (#11 fast path): append each IN ORDER with the SAME no-reply
                // disposition as `ProduceNoReply` above (one `process_produce` per append, `None` reply),
                // all joining the same pending batch under the one covering `commit_batch`. Purely a
                // CHANNEL-SEND coalescing — the per-append append/admission work is byte-identical to the
                // per-message arm; only the session->actor handoff was batched, so the single total order
                // and I2 for other records are untouched.
                Command::ProduceNoReplyBatch { appends } => {
                    for append in &appends {
                        process_produce(&mut engine, &mut pending, append, None);
                    }
                }
                // A non-produce job must observe a consistent durable head and keep the total durable
                // order, so flush the parked produces (one fsync) BEFORE it runs.
                Command::Run(job) => {
                    flush_pending(&mut engine, &mut pending);
                    // Reconcile any off-actor fast-rejects into the engine's shed counters BEFORE the
                    // job runs (#476), so a job that READS those counters — e.g. the `/metrics`
                    // snapshot — observes the fast-rejects already folded in. Without this ordering a
                    // scrape could under-report `produce_rejected` by the fast-rejects not yet folded.
                    // The L0 (no-ack) cap-sheds fold into `fire_and_forget_shed` (#495) on the same
                    // pre-job boundary, so a scrape never under-reports either counter.
                    engine.record_fast_reject_sheds(cap_gate.take_unreconciled_fast_rejects());
                    engine.record_fire_and_forget_sheds(cap_gate.take_unreconciled_l0_sheds());
                    job(&mut engine);
                    // A `Run` job can move BOTH the byte total (a job that reaps) AND the overflow
                    // policy (the live config reload, the only mutator of `disk_full_policy`), so
                    // refresh the gate's published snapshot from the engine's now-current state (#476).
                    // Doing it AFTER the job keeps the gate's policy view in lock-step with a reload
                    // before any later produce reads it (a flip to drop-oldest never false-rejects).
                    refresh_cap_gate(cap_gate, &mut engine);
                }
                // Graceful drain (#195): flush the pending batch, checkpoint every group, reply the
                // result, and exit. The flush happens first so a produce acked-by-being-in-the-batch
                // is made durable before the checkpoints and the exit.
                Command::Shutdown(reply) => {
                    flush_pending(&mut engine, &mut pending);
                    let result = engine.checkpoint_all_groups();
                    let _ = reply.send(result);
                    // #802: with concurrent senders on the one shared channel the reachable order
                    // `[Produce, Shutdown, Produce]` puts a produce AFTER the `Shutdown` in this drained
                    // batch (and more may still be buffered). Abandoning it drops the reply, and because
                    // a produce submission RETAINS a co-located `tx`, its `wait()`/`recv()` never sees a
                    // disconnect and wedges forever. Reply a closing outcome to every such produce (the
                    // unprocessed tail plus the channel remainder) so no client is left waiting.
                    drain_shutdown_replies(command_iter, rx);
                    return engine;
                }
            }
        }
        // The drain is exhausted: commit the parked produces with the ONE covering fsync, then release
        // their replies. This is the steady-state group commit boundary.
        flush_pending(&mut engine, &mut pending);
        // Push delivery (OPT-IN): only when long-poll is enabled does the covering commit's frontier
        // advance wake an idle long-polling consumer. When off this branch is skipped entirely, so the
        // group-commit boundary stays byte-for-byte the historical path. STRICTLY AFTER the flush (pure
        // observation; a bump reads the now-current per-stream `flushed_offset`s), never reordered with
        // it. Bumps ONLY the streams that advanced this batch (#1100 L2), not every idle consumer.
        if let Some(frontiers) = frontiers.as_mut() {
            frontiers.notify_advances(&engine, commit_notify);
        }
        // The batch just changed the durable byte total (an append grows it; a post-commit retention
        // reap can shrink it), so refresh the connection-thread fast-reject gate with the now-current
        // reading (#476). This is the ONE refresh that matters for steady-state load: a produce that
        // pushed the log at/over its drop-new cap is now visible to every connection's pre-check, so
        // the NEXT saturating produce fast-rejects instead of blocking on a full channel (the #465
        // fix). It runs once per drained batch (amortized with the fsync), never per message. It also
        // reconciles any fast-rejects performed off the actor into the engine's shed counters (#476).
        refresh_cap_gate(cap_gate, &mut engine);
        // The admission queue drained to empty: tell CoDel so the controlled-delay window closes and
        // a bursty-but-healthy queue never lingers in the dropping state (#68). A no-op when CoDel is
        // disabled (the default), so the steady-state loop is unchanged for a broker that has not
        // opted in.
        engine.codel_queue_empty();
        // Publish the writer's live/frozen state for `/readyz` to read non-blockingly (#862): the
        // covering commit just ran, so `is_healthy()` now reflects a frozen writer (a fsync that RETURNED
        // an error) — and a `/readyz` probe reads this flag instead of round-tripping through the actor,
        // so it can never hang behind the writer. A cheap local read + one relaxed store, per batch.
        watchdog.publish_writer_healthy(engine.is_healthy());
        // The batch committed (its fsync returned) and the queue drained: the actor returns to IDLE
        // (it blocks in `rx.recv()` next), so clear the watchdog — an idle actor is never wedged (#862).
        // ORDER IS LOAD-BEARING: `mark_idle` is a RELEASE store that publishes the `publish_writer_healthy`
        // store just above it, so a `/readyz` reader that sees the cleared wedge (Acquire) also sees the
        // frozen flag — never a transient stale-healthy 200 on a weakly-ordered arch. Do not reorder.
        watchdog.mark_idle();
    }
}

/// The PIPELINED sync tier's run loop (#1040): the actor appends and parks replies exactly like the
/// legacy loop, but the covering `fdatasync` runs on the dedicated flusher thread with AT MOST ONE
/// barrier in flight (INV-3), so the actor keeps appending while the disk syncs and everything
/// appended during a flight merges into the NEXT ticket (self-clocking group commit).
///
/// BLOCKING TOPOLOGY (the L8 fix): the actor blocks on the completion channel ONLY when a command
/// `try_recv` came up empty AND a barrier is outstanding — i.e. when a completion is the sole event
/// that can make progress the actor can deliver. Commands arriving during that wait queue in the
/// bounded channel for at most one fsync — exactly the delay the legacy INLINE fdatasync imposes on
/// them — and under load (channel non-empty) the actor never blocks there at all. The flusher never
/// holds a command-channel sender, so `rx` disconnects exactly when the last [`EngineHandle`] drops
/// (drop-driven shutdown preserved structurally); a disconnect mid-flight is observed right after
/// the in-flight completion is processed, and the loss-free E7 drain runs.
// One cohesive state machine (recv/try_recv → per-command poll+process → pass-end
// stage/dispatch/release/reconcile); splitting it would scatter the single-writer ordering and the
// reconcile points the no-wedge lemma is proved over.
// One added arg over the pedantic 7-arg bound: the append actor's single-writer loop legitimately
// threads the engine, command channel, pipeline rig, cap gate, watchdog, clock, and (push delivery)
// commit-notify seam — bundling any subset into a struct would only obscure the ownership the loop
// relies on. Same rationale as `handle_connection`'s allow.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn run_actor_pipelined<F, C>(
    mut engine: Engine<F, C>,
    rx: &Receiver<Command<F, C>>,
    rig: PipelineRig<F::File>,
    cap_gate: &ProduceCapGate,
    watchdog: &ActorWatchdog,
    clock: &C,
    commit_notify: &CommitNotify,
    consume_longpoll_ms: u64,
) -> Engine<F, C>
where
    F: Filesystem,
    C: Clock + Clone,
{
    // Push delivery is OPT-IN and default-OFF: when off, this loop NEVER touches the commit-notify seam,
    // so the pipelined group-commit path is byte-for-byte the historical one (no `flushed_offset` probe,
    // no lock, no `notify_all`). Only a long-poll-enabled broker seeds the frontier and bumps on advance.
    let longpoll_enabled = consume_longpoll_ms != 0;
    // The PER-STREAM commit-notify frontier tracker (#1100 L2): in this (sync) tier a stream's
    // `flushed_offset` advances only at barrier completion, so a bump means a record just became
    // poll-visible on THAT stream. Seeded to every open stream's recovered head so only real advances
    // signal; `None` (never built) when off. Replaces L1's single root-log `last_notified`.
    let mut frontiers = longpoll_enabled.then(|| FrontierTracker::seed(&engine, commit_notify));
    let mut pipeline = Pipeline {
        parked: VecDeque::new(),
        in_flight: None,
        next_seq: 0,
        req_tx: Some(rig.req_tx),
        done_rx: rig.done_rx,
        flusher: Some(rig.flusher),
        max_dirty_bytes: rig.max_dirty_bytes,
        watchdog,
        clock,
        cap_gate,
    };
    // The per-pass command batch, hoisted and reused across drains (#828), exactly as in the
    // legacy loop.
    let mut commands: Vec<Command<F, C>> = Vec::new();
    // A command the PREVIOUS pass end pulled off the channel while deciding its dispatch shape
    // (H1's channel-empty probe, or a non-produce arrival ending H2's linger): it becomes the
    // next pass's first command, so channel order is preserved exactly.
    let mut carryover: Option<Command<F, C>> = None;
    loop {
        // E10 (idle wait): while a barrier is IN FLIGHT never block on the command channel — a
        // non-blocking `try_recv` keeps commands flowing, and an EMPTY channel means the one event
        // that can advance the parked acks is the completion, so block on `done_rx` instead. With
        // no flight outstanding this is the legacy `recv()`, verbatim. A pass-end carryover
        // front-runs both: it was already received.
        let first = if let Some(cmd) = carryover.take() {
            cmd
        } else if pipeline.in_flight.is_some() {
            match rx.try_recv() {
                Ok(cmd) => cmd,
                Err(TryRecvError::Empty) => {
                    pipeline.wait_one_completion(&mut engine);
                    // Push delivery (OPT-IN): waiting out the in-flight barrier is where the durable
                    // frontier advances while the command channel is idle, so wake any long-polling
                    // consumer to re-poll the moment the barrier completes. Skipped entirely when off, so
                    // the idle-wait path is unchanged. STRICTLY AFTER the completion is folded in — pure
                    // observation of the now-current per-stream `flushed_offset`s (#1100 L2).
                    if let Some(frontiers) = frontiers.as_mut() {
                        frontiers.notify_advances(&engine, commit_notify);
                    }
                    continue;
                }
                Err(TryRecvError::Disconnected) => {
                    // E7: the last handle dropped mid-flight. Mark BUSY across the final drain so
                    // a wedged final barrier is still detectable, quiesce (drain the flight via
                    // `done_rx`, inline-commit the tail), and exit loss-free.
                    watchdog.mark_busy(clock.now_monotonic_nanos());
                    pipeline.quiesce_to_durable(&mut engine);
                    pipeline.join_flusher();
                    return engine;
                }
            }
        } else {
            let Ok(cmd) = rx.recv() else {
                // E7, no flight outstanding: the legacy shutdown drain with the inline barrier.
                watchdog.mark_busy(clock.now_monotonic_nanos());
                pipeline.quiesce_to_durable(&mut engine);
                pipeline.join_flusher();
                return engine;
            };
            cmd
        };
        // BUSY for this pass (#862): the busy stamp catches a wedged INLINE barrier (quiesce,
        // in-job sync); the flusher's in-flight barrier is watched by the dedicated sync-inflight
        // stamp (INV-8), because this busy stamp is re-freshened every pass and cleared at idle.
        watchdog.mark_busy(clock.now_monotonic_nanos());
        // Pass top: fold in any completion that landed while this pass was being assembled, so a
        // returned barrier releases its acks and re-dispatches before any command work runs.
        pipeline.poll_completions(&mut engine);
        commands.clear();
        commands.push(first);
        // Drain everything immediately available so a burst forms one merged window.
        while let Ok(cmd) = rx.try_recv() {
            commands.push(cmd);
        }
        // The same explicit `Drain` as the legacy loop, for the #802 Shutdown-tail contract.
        let mut command_iter = commands.drain(..);
        while let Some(cmd) = command_iter.next() {
            // Before EACH command: a `try_recv` on an empty channel is a few nanoseconds, and this
            // is what bounds the disk's idle time to ~one command instead of one pass (L8) — the
            // instant a barrier returns, the very next command boundary dispatches the successor.
            pipeline.poll_completions(&mut engine);
            match cmd {
                // E1: the SAME admission + append as the legacy arm (`process_produce` is shared);
                // only the park sink differs — the reply is stamped with its covering target and
                // released by `release_ready` once the durable head reaches it (INV-1).
                Command::Produce { append, reply } => {
                    process_produce(&mut engine, &mut pipeline, &append, Some(reply));
                }
                Command::ProduceNoReply { append } => {
                    process_produce(&mut engine, &mut pipeline, &append, None);
                }
                Command::ProduceNoReplyBatch { appends } => {
                    for append in &appends {
                        process_produce(&mut engine, &mut pipeline, append, None);
                    }
                }
                // E5: a Run job does NOT quiesce the pipeline (L9). The job observes a consistent,
                // MONOTONE durable head that may trail the appended head by the in-flight window;
                // reads are bounded by the flushed frontier, which only advances at durability
                // (INV-2), and an in-job INLINE barrier (txn `commit_batch`, `force_sync`,
                // named-stream `commit_tick`) composes via the all-or-nothing staleness guard
                // (INV-6). The shed reconcile → job → cap-gate refresh sequence is the legacy
                // arm's, verbatim; the post-job poll/release/reconcile converts any in-job barrier
                // advance into ack releases and keeps the no-wedge lemma at this reconcile point.
                Command::Run(job) => {
                    engine.record_fast_reject_sheds(cap_gate.take_unreconciled_fast_rejects());
                    engine.record_fire_and_forget_sheds(cap_gate.take_unreconciled_l0_sheds());
                    job(&mut engine);
                    refresh_cap_gate(cap_gate, &mut engine);
                    pipeline.poll_completions(&mut engine);
                    pipeline.release_ready(&mut engine);
                    pipeline.reconcile_writer_freeze(&mut engine, None);
                }
                // E6: graceful drain (#195). Quiesce to durable FIRST (drain the flight, then the
                // legacy inline barrier for the tail — identical post-conditions to the legacy
                // `flush_pending`), so a produce acked-by-being-parked is durable before the
                // checkpoints and the exit. Completions never ride the command channel, so the
                // #802 shutdown-tail drain is unchanged.
                Command::Shutdown(reply) => {
                    pipeline.quiesce_to_durable(&mut engine);
                    let result = engine.checkpoint_all_groups();
                    let _ = reply.send(result);
                    drain_shutdown_replies(command_iter, rx);
                    pipeline.join_flusher();
                    return engine;
                }
            }
        }
        // E4 (pass end): fold completions, release anything a seal / in-job barrier made durable
        // this pass, then finish the pass — the SOLO-INLINE / adaptive-linger dispatch decision
        // plus the stage-and-dispatch of the covering barrier (or the merge into the in-flight
        // window) — and reconcile a synchronous freeze so no parked reply can ever wedge (the
        // no-wedge lemma's pass-end point). Then the legacy tail, verbatim.
        pipeline.poll_completions(&mut engine);
        pipeline.release_ready(&mut engine);
        carryover = pipeline.finish_pass(&mut engine, rx);
        pipeline.reconcile_writer_freeze(&mut engine, None);
        // Push delivery (OPT-IN): wake any idle long-polling consumer if the durable poll frontier
        // advanced this pass. Placed AFTER `finish_pass` on purpose: the pass-end dispatch may take the
        // SOLO-INLINE barrier (a single waiter's covering `fdatasync` run inline), which advances
        // `flushed_offset` right here with NO in-flight barrier to observe later — a bump before
        // `finish_pass` would miss it and strand the consumer until its timeout. An ASYNC barrier instead
        // leaves the frontier unchanged now (this is a no-op) and is caught by the `wait_one_completion`
        // bump when it completes. Skipped entirely when off, so the pass-end path is unchanged. Pure
        // observation of the now-current per-stream `flushed_offset`s; never reorders the durability
        // work above. Bumps ONLY the streams that advanced this pass (#1100 L2).
        if let Some(frontiers) = frontiers.as_mut() {
            frontiers.notify_advances(&engine, commit_notify);
        }
        refresh_cap_gate(cap_gate, &mut engine);
        engine.codel_queue_empty();
        // The same #862 publish → idle RELEASE-store pairing as the legacy loop (do not reorder);
        // wedge visibility while idle-with-flight comes from the sync-inflight stamp (INV-8), not
        // the busy stamp.
        watchdog.publish_writer_healthy(engine.is_healthy());
        watchdog.mark_idle();
    }
}

/// One produce reply parked in the pipelined branch (#1040), stamped with the appended head at park
/// so it can be released the moment the durable head covers it. The pipelined twin of
/// [`PendingProduce`], plus the covering target.
struct ParkedAck {
    /// The pre-sync outcome, exactly [`PendingProduce::outcome`]'s taxonomy.
    outcome: PendingOutcome,
    /// The reply channel, or `None` for a Level-0 (no-ack) produce (#495): released or fataled
    /// with no frame either way, exactly the legacy contract.
    reply: Option<SyncSender<ProduceOutcome>>,
    /// `log.next_offset()` AFTER this produce's append: the ack releases only once
    /// `covering_target <= durable_offset()` (INV-1, I2). Non-decreasing along the deque (INV-4:
    /// single writer, offsets monotone), so release is a FIFO prefix drain and per-connection ack
    /// order equals submission order (#917) with zero session changes.
    covering_target: Offset,
}

/// The one in-flight covering barrier (#1040): the dispatch sequence number echoed back by the
/// flusher (INV-3's depth-1 debug check) and the engine's opaque staged commit.
struct InFlight {
    /// The dispatch sequence number, echoed in [`SyncDone::seq`].
    seq: u64,
    /// The staged commit ([`Engine::begin_async_commit`]) to hand back on completion.
    commit: AsyncCommit,
}

/// The CAP on the adaptive first-dispatch linger (H2, #1040): at a pass end that is about to
/// dispatch the FIRST barrier of a window (nothing in flight, >= 2 waiters parked), the actor
/// lingers on the command channel for up to `min(this cap, last_fsync_nanos / 10)` before
/// staging, folding late arrivals of the same burst into the one covering barrier. The cap
/// bounds the tax at 200 us — the retired #454 gather's window, which field experience showed
/// is invisible against a wall-dominant barrier (macOS `F_FULLFSYNC`, ~3.8 ms) and is exactly
/// where the immediate first dispatch was measured splitting each session burst into ~2.6
/// barriers where the gather paid ~1.8. The `last_fsync_nanos / 10` term self-tunes it away on
/// fast-barrier disks (Linux fdatasync ~200-300 us => linger <= ~30 us, negligible) and to zero
/// before the first barrier ever completes (never linger blind). Under sustained load a flight
/// is outstanding at every pass end, so the linger NEVER engages there — deliberately a
/// constant, not a knob: the tier self-tunes.
const FIRST_DISPATCH_LINGER_CAP_NANOS: u64 = 200_000;

/// The pipelined branch's actor-local state machine (#1040): the parked-ack deque, the depth-1
/// in-flight record, the flusher channels, and the spawn-time snapshots. All mutation happens on
/// the actor thread (single-writer preserved); the flusher only ever executes `sync_data` on the
/// shared fd it is handed.
///
/// The NO-WEDGE LEMMA, proved over the helpers below: at every reconcile point (pass end, each
/// completion, post-job, quiesce), for every entry `p` in `parked` exactly one holds — (1)
/// `p.covering_target <= durable_offset()`, released by [`Pipeline::release_ready`]; (2) the
/// writer is frozen, fataled by [`Pipeline::reconcile_writer_freeze`]; or (3) the writer is live
/// with `p.covering_target > durable_offset()`, which implies `has_unsynced_records()`, so
/// [`Pipeline::maybe_issue`] either already holds an in-flight barrier (whose completion re-runs
/// this analysis) or dispatches one now. Progress is therefore guaranteed, a false ack is
/// impossible by INV-1, and a permanent parked wedge is impossible by cases 2-3.
struct Pipeline<'a, F: Filesystem, C: Clock + Clone> {
    /// Parked produce replies, covering targets non-decreasing (INV-4).
    parked: VecDeque<ParkedAck>,
    /// The at-most-one outstanding barrier (INV-3).
    in_flight: Option<InFlight>,
    /// The dispatch sequence counter (monotone; echoed by the flusher).
    next_seq: u64,
    /// The barrier-job channel's send half; `None` only after [`Pipeline::join_flusher`] dropped
    /// it to end the flusher (every `run_actor_pipelined` return path).
    req_tx: Option<SyncSender<FlushJob<F::File>>>,
    /// The dedicated completion channel (unbounded; the flusher's send never blocks).
    done_rx: Receiver<SyncDone>,
    /// The flusher's join handle, reaped by [`Pipeline::join_flusher`].
    flusher: Option<std::thread::JoinHandle<()>>,
    /// The INV-9 dirty-byte bound snapshot; `0` disables the throttle.
    max_dirty_bytes: u64,
    /// The shared actor watchdog (#862): this branch stamps the sync-inflight field (INV-8).
    watchdog: &'a ActorWatchdog,
    /// The engine's clock seam, for the sync-inflight stamp (the same clock `overran` reads).
    clock: &'a C,
    /// The connection-thread fast-reject gate (#476), refreshed after each completion's commit
    /// tail (durable bytes moved).
    cap_gate: &'a ProduceCapGate,
}

impl<F, C> Pipeline<'_, F, C>
where
    F: Filesystem,
    C: Clock + Clone,
{
    /// Drains every already-delivered completion without blocking (a `try_recv` on an empty
    /// channel is a few nanoseconds). Called at pass top, before EACH command in a drained pass,
    /// at pass end, and post-job (L8). A disconnected channel with a flight outstanding is the
    /// flusher's death: a dispatched barrier can never return, the failed-barrier class (E3).
    fn poll_completions(&mut self, engine: &mut Engine<F, C>) {
        loop {
            match self.done_rx.try_recv() {
                Ok(done) => self.on_completion(engine, done),
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    if self.in_flight.is_some() {
                        self.on_flusher_death(engine);
                    }
                    return;
                }
            }
        }
    }

    /// Blocks for exactly one completion (E10's idle wait, E8's throttle wait, quiesce's flight
    /// drain). Only ever called with a flight outstanding, so the flusher owes exactly one
    /// message; a disconnect instead is the flusher's death (E3).
    fn wait_one_completion(&mut self, engine: &mut Engine<F, C>) {
        debug_assert!(
            self.in_flight.is_some(),
            "wait_one_completion requires an outstanding flight (#1040)"
        );
        match self.done_rx.recv() {
            Ok(done) => self.on_completion(engine, done),
            Err(_) => self.on_flusher_death(engine),
        }
    }

    /// Applies one RETURNED barrier — E2 (Ok) / E3 (Err), in the spec's exact order.
    fn on_completion(&mut self, engine: &mut Engine<F, C>, done: SyncDone) {
        let Some(flight) = self.in_flight.take() else {
            // Unreachable by INV-3 (the flusher echoes exactly one completion per job); tolerate
            // in release builds by ignoring the orphan rather than corrupting state.
            debug_assert!(
                false,
                "a completion arrived with no in-flight barrier (INV-3)"
            );
            return;
        };
        debug_assert_eq!(
            flight.seq, done.seq,
            "the depth-1 seq echo mismatched (INV-3)"
        );
        // The flight is no longer outstanding, whatever its result: clear the wedge stamp (INV-8).
        self.watchdog.clear_sync_inflight();
        match done.result {
            Ok(()) => {
                // (2) Heads + read-plane frontier + histograms, all-or-nothing against a stale
                // ticket (INV-6, enforced inside the log — never bypassed here). The frontier is
                // published INSIDE this call, on this thread, strictly before the releases below
                // (INV-10: read-your-acked-write for actor-routed reads AND the off-actor plane).
                engine.complete_async_commit(&flight.commit, done.fsync_nanos);
                // (3) Dispatch the NEXT barrier BEFORE any bookkeeping or ack fan-out (L11): the
                // disk idles only for the length of this call, and the window appended during the
                // completed flight is already staged behind its own ticket.
                self.maybe_issue(engine);
                // (4) Release the FIFO prefix the completed barrier covered (INV-1).
                self.release_ready(engine);
                // (5) The once-per-commit tail (retention reap + sweeps), AFTER dispatch and
                // release so bookkeeping never idles the disk or the producers. An error freezes
                // (the R2 disposition): the acks already released were covered by a RETURNED
                // barrier, so I2 holds; everything still parked is fataled by the reconcile.
                match engine.commit_tail_after_async_completion() {
                    Ok(()) => {
                        // (6) The no-wedge lemma's per-completion reconcile point.
                        self.reconcile_writer_freeze(engine, None);
                    }
                    Err(e) => {
                        let _ = engine.fail_async_commit();
                        self.reconcile_writer_freeze(engine, Some(e));
                    }
                }
                // (7) The durable byte total moved: refresh the fast-reject gate (#476).
                refresh_cap_gate(self.cap_gate, engine);
            }
            Err(io_error) => {
                // E3: the covering barrier FAILED. Freeze the writer forever (INV-7; the exact
                // terminal state a failed inline `Log::sync` leaves), then fatal-fan EVERY parked
                // reply: batch N's first at-least-once member carries the real error, everything
                // else `WriterFrozen` — batch N+1 can never become durable behind a frozen writer.
                // `maybe_issue` can never re-arm (`begin_async_commit` errors on frozen), so a
                // failed barrier is never retried (fsyncgate).
                let _ = engine.fail_async_commit();
                self.reconcile_writer_freeze(
                    engine,
                    Some(EngineError::Storage(
                        ironbus_storage::segment::StorageError::Io(io_error),
                    )),
                );
            }
        }
    }

    /// The flusher died with a barrier outstanding (`done_rx` disconnected): a dispatched barrier
    /// can never return, which is the failed-barrier class — E3 with a synthesized error. Quiesce
    /// can therefore never hang on a dead flusher.
    fn on_flusher_death(&mut self, engine: &mut Engine<F, C>) {
        self.in_flight = None;
        self.watchdog.clear_sync_inflight();
        let _ = engine.fail_async_commit();
        self.reconcile_writer_freeze(
            engine,
            Some(EngineError::Storage(
                ironbus_storage::segment::StorageError::Io(std::io::Error::other(
                    "the fsync flusher thread died with a barrier in flight (#1040)",
                )),
            )),
        );
    }

    /// Releases the FIFO prefix of parked replies whose covering target the durable head has
    /// reached — the ONLY release path (INV-1): a non-Fatal reply is sent from here and nowhere
    /// else, and `durable_offset` advances only after a RETURNED successful barrier (a completed
    /// flusher fdatasync, an inline `Log::sync`, or a roll's seal). INV-4 makes the prefix drain
    /// exact: targets are non-decreasing, so the first uncovered entry ends the sweep.
    fn release_ready(&mut self, engine: &mut Engine<F, C>) {
        let durable = engine.durable_offset();
        while self
            .parked
            .front()
            .is_some_and(|p| p.covering_target <= durable)
        {
            let Some(p) = self.parked.pop_front() else {
                return;
            };
            // A Level-0 (no-ack) parked produce carries no reply channel (#495): durable now,
            // but the producer fired and forgot, so send nothing.
            let Some(reply) = p.reply else {
                continue;
            };
            let _ = reply.send(released_outcome(p.outcome));
        }
    }

    /// The L6 fix, a first-class transition: if the writer froze (a failed flusher barrier, a
    /// failed seal/stage, a failed in-job inline sync), first release every waiter an EARLIER
    /// returned barrier already covers (their acks are honest), then fatal-fan the remainder
    /// exactly per the legacy `flush_pending` Err arm — `first` (the real error) to the first
    /// at-least-once member, `WriterFrozen` to the rest, Level-0 `None` replies skipped WITHOUT
    /// consuming the real error. Publishes the unhealthy flag at freeze time so `/readyz` flips
    /// without waiting for the pass-end publish. Idempotent; a no-op on a live writer.
    fn reconcile_writer_freeze(&mut self, engine: &mut Engine<F, C>, first: Option<EngineError>) {
        if engine.log_is_writable() {
            return;
        }
        self.release_ready(engine);
        fatal_fan_replies(self.parked.drain(..).map(|p| p.reply), first);
        self.watchdog.publish_writer_healthy(false);
    }

    /// Stages and dispatches the covering barrier for everything appended-but-unsynced — or does
    /// nothing if a barrier is already in flight (this IS the in-flight write merge: the window
    /// keeps accumulating and the completion dispatches its successor). `Ok(None)` is a CLEAN log
    /// (no barrier owed — distinct from frozen by construction, the L1 fix: frozen is an `Err`).
    /// The stage (`prepare_async_sync` inside `begin_async_commit`) flushes the writer's pending
    /// bytes into the file BEFORE the job crosses the channel, so the ticket's dirty-at-sync-start
    /// snapshot is exact (INV-5).
    fn maybe_issue(&mut self, engine: &mut Engine<F, C>) {
        if self.in_flight.is_some() {
            return;
        }
        match engine.begin_async_commit() {
            Ok(None) => {}
            Ok(Some((file, commit))) => {
                self.next_seq += 1;
                let seq = self.next_seq;
                // INV-8: non-zero exactly while a barrier is in flight, stamped BEFORE the send so
                // the watchdog can never miss a wedged dispatch.
                self.watchdog
                    .mark_sync_inflight(self.clock.now_monotonic_nanos());
                self.in_flight = Some(InFlight { seq, commit });
                // The bound-1 job channel is provably empty here (depth-1): the send never blocks.
                // A send failure means the flusher is gone — a dispatched barrier can never
                // return, so treat it as the failed-barrier class immediately.
                let sent = self
                    .req_tx
                    .as_ref()
                    .is_some_and(|tx| tx.send(FlushJob { seq, file }).is_ok());
                if !sent {
                    self.on_flusher_death(engine);
                }
            }
            Err(e) => self.reconcile_writer_freeze(engine, Some(e)),
        }
    }

    /// Finishes a pass (E4's dispatch decision, #1040): stages the covering barrier for the
    /// window just appended — inline, lingered, or dispatched — by the shape of the pass.
    /// Returns a command to hand the NEXT pass when the decision pulled one off the channel.
    ///
    /// - **Flight outstanding:** nothing to decide — the window keeps merging and the completion
    ///   dispatches its successor (this IS the in-flight write merge; the completion covers
    ///   dispatch, so an inline barrier here would only serialize the actor behind the disk).
    /// - **H1 SOLO-INLINE:** exactly ONE waiter parked (by the no-wedge lemma's case analysis,
    ///   with no flight and the pass-top/pass-end releases done, everything parked was parked by
    ///   THIS pass) and the command channel verifiably empty — there is provably nothing to
    ///   overlap, so the two flusher hops (actor -> flusher -> actor) are pure added cost per
    ///   barrier. Run the LEGACY inline barrier instead (the same `commit_batch` the legacy
    ///   branch and `quiesce_to_durable` issue): identical latency to the pre-pipeline actor BY
    ///   CONSTRUCTION, zero thread hops, and the inline barrier is an ordinary intervening sync
    ///   the machinery already composes with (the durable head advances, `release_ready` covers
    ///   the waiter, no ticket exists). The emptiness probe is an actual `try_recv`: a command
    ///   already queued means more of the burst is coming, so dispatch async and carry the
    ///   command into the next pass — never inline with work waiting (that is the legacy loop's
    ///   pathology this branch exists to remove).
    /// - **H2 ADAPTIVE FIRST-DISPATCH LINGER:** >= 2 waiters parked and no flight — the FIRST
    ///   barrier of a burst window. Linger up to `min(200 us, last_fsync_nanos / 10)` draining
    ///   late arrivals of the same burst into this window before staging
    ///   ([`FIRST_DISPATCH_LINGER_CAP_NANOS`]): produces append and park; a non-produce command
    ///   ends the linger and carries over; a disconnect ends it (the next loop iteration runs
    ///   the E7 drain). Wall-clock deadline, same precedent as the flusher's measurement (the
    ///   sim never constructs the pipeline).
    fn finish_pass(
        &mut self,
        engine: &mut Engine<F, C>,
        rx: &Receiver<Command<F, C>>,
    ) -> Option<Command<F, C>> {
        if self.in_flight.is_some() {
            return None;
        }
        // H1: a solo waiter with a drained channel goes inline; a solo waiter with the burst's
        // next command already queued dispatches async and hands the command to the next pass.
        if self.parked.len() == 1 {
            return match rx.try_recv() {
                Ok(cmd) => {
                    self.maybe_issue(engine);
                    Some(cmd)
                }
                // Disconnected inlines too: no command can ever arrive to overlap with, and the
                // next loop iteration observes the disconnect and runs the loss-free E7 drain.
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => {
                    self.commit_inline(engine);
                    None
                }
            };
        }
        // H2: linger before the burst window's FIRST dispatch, scaled to the observed barrier
        // cost (zero before the first barrier ever completes — never linger blind).
        if self.parked.len() >= 2 {
            let linger_nanos = FIRST_DISPATCH_LINGER_CAP_NANOS.min(engine.last_fsync_nanos() / 10);
            if linger_nanos > 0 {
                let deadline =
                    std::time::Instant::now() + std::time::Duration::from_nanos(linger_nanos);
                while let Some(remaining) =
                    deadline.checked_duration_since(std::time::Instant::now())
                {
                    match rx.recv_timeout(remaining) {
                        Ok(Command::Produce { append, reply }) => {
                            process_produce(engine, self, &append, Some(reply));
                        }
                        Ok(Command::ProduceNoReply { append }) => {
                            process_produce(engine, self, &append, None);
                        }
                        Ok(Command::ProduceNoReplyBatch { appends }) => {
                            for append in &appends {
                                process_produce(engine, self, append, None);
                            }
                        }
                        // A non-produce command ends the linger: dispatch the window now and
                        // handle the command in the normal loop (as the next pass's head).
                        Ok(other) => {
                            self.maybe_issue(engine);
                            return Some(other);
                        }
                        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
                    }
                    // A lingered produce's admission throttle (E8) may itself have dispatched
                    // (dispatch-before-block): the window's barrier is already out, so the
                    // linger's purpose is spent — later arrivals merge behind the flight.
                    if self.in_flight.is_some() {
                        break;
                    }
                }
            }
        }
        self.maybe_issue(engine);
        None
    }

    /// H1's inline covering barrier (#1040): the LEGACY synchronous group commit
    /// (`commit_batch`, byte-for-byte what the legacy branch's `flush_pending` and
    /// `quiesce_to_durable` issue — barrier + histograms + retention/sweep tail), then the
    /// release of everything it covered. Callable only with no flight outstanding (a stale prior
    /// flight is impossible here, and any still-outstanding flight's completion would be a full
    /// no-op by INV-6 anyway). On failure the writer froze: fatal-fan per the legacy Err arm.
    fn commit_inline(&mut self, engine: &mut Engine<F, C>) {
        debug_assert!(
            self.in_flight.is_none(),
            "the inline barrier requires no outstanding flight (#1040)"
        );
        if engine.has_unsynced_records() {
            if let Err(e) = engine.commit_batch() {
                // Two distinct failure classes hide behind one `Err`. A BARRIER failure froze the
                // writer: `reconcile_writer_freeze` releases the durable prefix (none) and
                // fatal-fans the rest. A commit-TAIL failure (retention reap / idle sweep) AFTER a
                // durable barrier leaves the writer WRITABLE with the durable head already
                // advanced — there `reconcile` is a no-op, so we MUST fall through to
                // `release_ready` (below) or the covered waiter wedges on an idle broker with its
                // record durable but its ack never sent (the reap retries next cycle; an
                // already-durable ack must never block on it). This mirrors the async completion
                // path, which releases on the advanced durable head BEFORE its commit-tail runs.
                self.reconcile_writer_freeze(engine, Some(e));
            }
        }
        // Runs after every barrier — Ok, frozen (parked already drained by the fatal-fan, so this
        // is a no-op), or writable-tail-error (releases the durable-but-still-parked waiter).
        self.release_ready(engine);
    }

    /// E6/E7/#378-drain: waits out the in-flight barrier (via `done_rx`, never the command
    /// channel), then issues the LEGACY synchronous barrier for any remaining tail (safe: no
    /// flight outstanding), releases everything covered, and fatal-fans the rest if the writer
    /// froze. Post-conditions IDENTICAL to the legacy `flush_pending`: no flight outstanding,
    /// nothing parked, durable head == appended head or writer frozen with all replies fataled —
    /// so every barrier-site caller (shutdown checkpoint, disconnect drain, headroom re-admit)
    /// runs unchanged after it.
    fn quiesce_to_durable(&mut self, engine: &mut Engine<F, C>) {
        while self.in_flight.is_some() {
            self.wait_one_completion(engine);
        }
        if engine.has_unsynced_records() {
            if let Err(e) = engine.commit_batch() {
                self.reconcile_writer_freeze(engine, Some(e));
            }
        }
        self.release_ready(engine);
        self.reconcile_writer_freeze(engine, None);
        debug_assert!(
            self.parked.is_empty(),
            "quiesce_to_durable leaves nothing parked (#1040)"
        );
    }

    /// Drops the barrier-job sender (ending the flusher's `recv` loop) and joins the thread.
    /// Called on every `run_actor_pipelined` return path, always AFTER a quiesce, so no barrier
    /// is in flight and the join cannot hang. A flusher that already died (its panic was absorbed
    /// as the failed-barrier class) is reaped here; its panic payload is deliberately discarded.
    fn join_flusher(&mut self) {
        self.req_tx = None;
        if let Some(flusher) = self.flusher.take() {
            let _ = flusher.join();
        }
    }
}

/// Maps a parked produce's pre-sync outcome to its reply once the covering barrier RETURNED Ok —
/// the release half of the historical `flush_pending` mapping, extracted verbatim and shared by
/// the legacy batch release and the pipelined `release_ready` (#1040).
fn released_outcome(outcome: PendingOutcome) -> ProduceOutcome {
    match outcome {
        PendingOutcome::Appended(offset) => ProduceOutcome::Appended(offset),
        // A dedup hit replies PubAckDuplicate now that the covering barrier is durable (#33).
        PendingOutcome::Duplicate(offset) => ProduceOutcome::AppendedDuplicate(offset),
        // A fire-and-forget produce is durable now, but the session sends NO PubAck (#11).
        PendingOutcome::FireAndForgetAppended(offset) => {
            ProduceOutcome::FireAndForgetAppended(offset)
        }
    }
}

/// Fatal-fans a failed covering barrier to every parked reply — the Err half of the historical
/// `flush_pending` mapping, extracted verbatim and shared by the legacy batch and the pipelined
/// reconcile (#1040): the FIRST at-least-once member carries the real error (when the caller has
/// one), every later member an equivalent `WriterFrozen` (the freeze is the same event), and a
/// Level-0 `None` reply is SKIPPED WITHOUT consuming the real error — the fired-and-forgotten
/// producer is not listening, and the first at-least-once member must still receive the truth.
fn fatal_fan_replies(
    replies: impl Iterator<Item = Option<SyncSender<ProduceOutcome>>>,
    mut first: Option<EngineError>,
) {
    for reply in replies {
        let Some(reply) = reply else {
            continue;
        };
        let err = first.take().unwrap_or(EngineError::Storage(
            ironbus_storage::segment::StorageError::WriterFrozen,
        ));
        let _ = reply.send(ProduceOutcome::Fatal(err));
    }
}

/// Replies a CLOSING outcome to every produce that was queued but not processed when the actor exits on
/// a `Command::Shutdown` (#802): the still-unprocessed `tail` of the drained batch AND everything still
/// buffered in the channel. Without this, a produce that landed AFTER the `Shutdown` (reachable under
/// concurrent senders on the one shared channel) is dropped reply-less; and because a produce submission
/// keeps a co-located `tx` alive alongside its `rx`, that `rx.recv()` never observes a disconnect and the
/// waiting producer wedges FOREVER (the lost-reply + deadlock this closes).
///
/// The closing reply is [`ProduceOutcome::AtCapacity`]: a non-fatal, already wire-mapped "rejected, retry"
/// outcome. It is an EXPLICIT rejection, never a false ack — the record was NOT durably committed (the
/// actor is exiting after its final checkpoint), so the producer learns the produce did not land rather
/// than silently believing it did. No-reply produces (`ProduceNoReply`/`ProduceNoReplyBatch`) drop
/// silently by their fire-and-forget contract; a `Run` job or a second `Shutdown` drops its reply channel,
/// which its caller already reads as the typed [`ActorGone`] (a clean error, never a hang).
fn drain_shutdown_replies<F, C>(
    tail: impl Iterator<Item = Command<F, C>>,
    rx: &Receiver<Command<F, C>>,
) where
    F: Filesystem,
    C: Clock,
{
    let reply_closing = |cmd: Command<F, C>| {
        if let Command::Produce { reply, .. } = cmd {
            let _ = reply.send(ProduceOutcome::AtCapacity);
        }
    };
    // The unprocessed tail of THIS drained batch first (it holds the produces that raced ahead of a
    // still-buffered remainder), then the channel remainder. Draining the channel once is enough: once
    // this function returns, `run_actor` returns and its `Receiver` drops, so any LATER send fails at the
    // sender with `ActorGone` rather than buffering a reply-less command.
    for cmd in tail {
        reply_closing(cmd);
    }
    while let Ok(cmd) = rx.try_recv() {
        reply_closing(cmd);
    }
}

/// One produce parked in the current batch: its known outcome and the channel to reply on once the
/// covering `commit_batch` has made it durable.
struct PendingProduce {
    outcome: PendingOutcome,
    /// The reply channel for the produce outcome, or `None` for a LEVEL-0 (no-ack / fire-and-forget)
    /// produce (#495). A Level-0 produce is appended into the SAME batch and covered by the same fsync
    /// (single-writer storage / single total order), but it carries no reply channel: `flush_pending`
    /// sends nothing for it whether the commit succeeds or freezes — the producer fired and forgot. The
    /// at-least-once (Level-1 / Level-2-as-Level-1) path always carries `Some`, so its reply behavior
    /// is byte-for-byte unchanged.
    reply: Option<SyncSender<ProduceOutcome>>,
}

/// The pre-sync outcome of a parked produce. A fresh append OR a dedup hit reaches here (a shed,
/// fence, or hard error replies immediately and never parks), so the post-sync mapping is a
/// success-or-freeze decision for either.
#[derive(Clone, Copy)]
enum PendingOutcome {
    /// A fresh append at this offset, pending the covering fsync: replies `PubAck` once durable.
    Appended(Offset),
    /// A dedup hit returning this ORIGINAL offset (#33), pending the covering fsync: replies
    /// `PubAckDuplicate` once the batch is durable, so a hit on an id recorded earlier in THIS batch
    /// never replies before that id's offset is durable (I2).
    Duplicate(Offset),
    /// A FIRE-AND-FORGET (QoS-0, #11, #402) append at this offset, pending the covering fsync: it is
    /// made durable in the SAME group commit as a normal produce, but the session sends NO `PubAck`
    /// (the producer fired and forgot). On a sync FAILURE it becomes `Fatal` like any parked produce,
    /// so a frozen writer still ends the session rather than silently losing a record it appended.
    FireAndForgetAppended(Offset),
}

/// Where a produce's parkable disposition lands and how its tier drains a full admission window:
/// the seam that lets ONE `process_produce` (the admission + append path, byte-for-byte the
/// historical code) serve both actor loops (#1040).
///
/// - The LEGACY tiers implement it on the batch `Vec` itself: park is a plain push (released by
///   `flush_pending`'s covering `commit_batch`), the headroom drain IS `flush_pending`, and the
///   dirty-byte throttle is a no-op (the legacy loop drains every pass, so the covering barrier
///   already bounds the window).
/// - The PIPELINED branch implements it on [`Pipeline`]: park stamps the covering target
///   (INV-1/INV-4), the headroom drain is `quiesce_to_durable` (identical post-conditions), and
///   the throttle enforces INV-9 dispatch-before-block.
trait ProduceBatch<F: Filesystem, C: Clock + Clone> {
    /// E8 (#1040, INV-9): block (dispatch-before-block, never shed) until admitting a record of
    /// `record_bytes` LOGICAL bytes keeps the unsynced window within the configured bound. A
    /// legacy-tier no-op.
    fn throttle_admit(&mut self, engine: &mut Engine<F, C>, record_bytes: u64);
    /// The #378 fsync-headroom drain: issue the ONE covering barrier for everything parked so the
    /// un-fsynced frontier can reset before the admission re-check.
    fn drain_for_headroom(&mut self, engine: &mut Engine<F, C>);
    /// Park a parkable disposition (a fresh append, a dedup hit, a fire-and-forget append) behind
    /// its covering barrier.
    fn park(
        &mut self,
        engine: &mut Engine<F, C>,
        outcome: PendingOutcome,
        reply: Option<SyncSender<ProduceOutcome>>,
    );
}

/// The legacy tiers' batch sink: the parked `Vec` drained by `flush_pending`, byte-for-byte the
/// historical behavior (see [`ProduceBatch`]).
impl<F, C> ProduceBatch<F, C> for Vec<PendingProduce>
where
    F: Filesystem,
    C: Clock + Clone,
{
    fn throttle_admit(&mut self, _engine: &mut Engine<F, C>, _record_bytes: u64) {
        // The legacy loop commits (and on the sync tier fsyncs) every pass, so the unsynced
        // window is already bounded by the pass; the INV-9 throttle is a pipelined-tier concern.
    }

    fn drain_for_headroom(&mut self, engine: &mut Engine<F, C>) {
        flush_pending(engine, self);
    }

    fn park(
        &mut self,
        _engine: &mut Engine<F, C>,
        outcome: PendingOutcome,
        reply: Option<SyncSender<ProduceOutcome>>,
    ) {
        self.push(PendingProduce { outcome, reply });
    }
}

/// The pipelined branch's batch sink (#1040): covering-target stamping, dup-of-durable fast path,
/// quiesce-backed headroom drain, and the INV-9 throttle (see [`ProduceBatch`]).
impl<F, C> ProduceBatch<F, C> for Pipeline<'_, F, C>
where
    F: Filesystem,
    C: Clock + Clone,
{
    fn throttle_admit(&mut self, engine: &mut Engine<F, C>, record_bytes: u64) {
        if self.max_dirty_bytes == 0 {
            return;
        }
        loop {
            let unsynced = engine.unsynced_bytes();
            // The one-record floor: an EMPTY window always admits (a record larger than the bound
            // must throttle its successors, never wedge itself), and admission keeps
            // `unsynced + record <= bound` otherwise (INV-9).
            if unsynced == 0 || unsynced.saturating_add(record_bytes) <= self.max_dirty_bytes {
                return;
            }
            // DISPATCH-BEFORE-BLOCK (L3): never wait with nothing in flight. `maybe_issue` on a
            // dirtied log either dispatches (something to wait for) or hit a frozen writer (the
            // reconcile inside fataled the parked window; break and let the append surface the
            // fatal to THIS produce — throttle never sheds).
            if self.in_flight.is_none() {
                self.maybe_issue(engine);
                if self.in_flight.is_none() {
                    return;
                }
            }
            self.wait_one_completion(engine);
        }
    }

    fn drain_for_headroom(&mut self, engine: &mut Engine<F, C>) {
        // The sync tier's drain-then-admit semantics (#378), now through the pipeline-safe
        // quiesce: identical post-conditions to the legacy `flush_pending` (durable == appended
        // or frozen-with-fatals), so the caller's re-check behaves exactly as before.
        self.quiesce_to_durable(engine);
    }

    fn park(
        &mut self,
        engine: &mut Engine<F, C>,
        outcome: PendingOutcome,
        reply: Option<SyncSender<ProduceOutcome>>,
    ) {
        // E1: stamp the covering target — the appended head AFTER this produce's append.
        let covering_target = engine.append_head();
        if covering_target <= engine.durable_offset() {
            // The dup-of-durable fast path: everything at/below the target is ALREADY covered by
            // a returned barrier, which is only reachable for a disposition that appended nothing
            // on a fully-durable log (a duplicate of a long-durable id) — so reply now, with zero
            // additional fsyncs (I2 holds: the original record's covering barrier returned long
            // ago). A fresh append always has `covering_target > durable_offset` and parks.
            if let Some(reply) = reply {
                let _ = reply.send(released_outcome(outcome));
            }
            return;
        }
        // INV-4: the single writer appends with monotone offsets, so targets are non-decreasing
        // along the deque and release is a FIFO prefix drain (#917).
        debug_assert!(
            self.parked
                .back()
                .map_or(true, |b| b.covering_target <= covering_target),
            "parked covering targets must be non-decreasing (INV-4, #1040)"
        );
        self.parked.push_back(ParkedAck {
            outcome,
            reply,
            covering_target,
        });
    }
}

/// Runs one produce's admission + append on the actor, parking its reply behind the covering fsync or
/// replying/dropping it immediately on a non-appended disposition.
///
/// `reply` is `Some` for an at-least-once produce (Level 1, and Level 2 falling back to Level 1) and
/// `None` for a LEVEL-0 (no-ack / fire-and-forget) produce (#495). When `Some`, this is byte-for-byte
/// the historical produce path: every disposition sends exactly the frame it always did. When `None`,
/// every disposition is a SILENT drop with no frame (the L0 producer fired and forgot), but the
/// admission and append are IDENTICAL — an appended L0 still joins the batch and is covered by the one
/// covering barrier (single-writer storage / single total order), it just parks `None`.
///
/// A `None` (Level-0) produce always has `append.fire_and_forget == true` (the session sets it for the
/// canonical fire-and-forget bit AND the level-bit Level-0 encoding), so the fire-and-forget token
/// bucket governs it exactly as it governed the historical faf path — this is that path generalized.
///
/// `batch` is the tier's park/drain/throttle seam ([`ProduceBatch`], #1040): the legacy `Vec` batch
/// or the pipelined [`Pipeline`]. The admission + append below is shared verbatim between them.
fn process_produce<F, C>(
    engine: &mut Engine<F, C>,
    batch: &mut impl ProduceBatch<F, C>,
    append: &OwnedAppend,
    reply: Option<SyncSender<ProduceOutcome>>,
) where
    F: Filesystem,
    C: Clock + Clone,
{
    // Reply only if a channel was provided: a Level-0 produce (`None`) drops silently on every
    // disposition (the fire-and-forget no-frame contract), so each `send_outcome` below is a no-op for
    // it and the wire stays byte-identical to the historical faf path.
    let send_outcome = |reply: &Option<SyncSender<ProduceOutcome>>, outcome: ProduceOutcome| {
        if let Some(tx) = reply {
            let _ = tx.send(outcome);
        }
    };
    // E8 (#1040, INV-9): the pipelined tier's dirty-byte admission throttle, FIRST — block
    // (dispatch-before-block, drain one completion at a time) until the unsynced window can take
    // this record's LOGICAL bytes. THROTTLES, never sheds (the sync tier's semantics); a no-op on
    // the legacy tiers and when the bound is disabled.
    let throttle_record_bytes =
        u64::try_from(append.key.len() + append.headers.len() + append.payload.len())
            .unwrap_or(u64::MAX);
    batch.throttle_admit(engine, throttle_record_bytes);
    // FIRE-AND-FORGET (QoS-0, #11, #402) admission, decided FIRST and only for a produce the client
    // marked fire-and-forget (every Level-0 produce, #495). The per-connection token bucket (#336)
    // caps this un-credited tier: an exhausted bucket DROPS the produce (without acking and without
    // appending), because the QoS-0 producer accepts loss by contract. The bucket governs ONLY this
    // tier, so it NEVER touches the at-least-once path; a non-fire-and-forget produce skips this
    // entirely. When disabled (the default rate of 0), the bucket always admits, so a QoS-0 produce
    // under an unconfigured broker is appended-but-not-acked, never dropped.
    if append.fire_and_forget {
        let payload_bytes = u64::try_from(append.payload.len()).unwrap_or(u64::MAX);
        if !engine.fire_and_forget_admit(payload_bytes) {
            // Dropped by the bucket (counted in `ironbus_fire_and_forget_shed_total`): the producer
            // fired and forgot, so send NO frame and keep the session.
            send_outcome(&reply, ProduceOutcome::FireAndForgetDropped);
            return;
        }
    }
    // CoDel controlled-delay shed (#68), decided BEFORE the append so it rejects only NEW work and
    // never drops an already-accepted record (I2 holds). The sojourn is `now - enqueue` on the
    // monotonic clock seam; a sustained admission delay above TARGET sheds this produce. When CoDel is
    // disabled (the default) this is always false, so the append path is byte-for-byte unchanged. A
    // fire-and-forget produce shed by CoDel also gets no ack (the session maps the Shed outcome to no
    // frame for a fire-and-forget pub), so the contract holds either way.
    if engine.codel_admit(append.enqueue_monotonic_nanos) {
        // The shed counts as a request the broker shed (the retry-budget signal), then replies a
        // stable "shed under load" outcome; the connection stays open.
        engine.retry_budget_record_shed();
        send_outcome(&reply, ProduceOutcome::Shed);
        return;
    }
    // fsync-HEADROOM admission (#378), decided BEFORE the append so it rejects only NEW work and never
    // drops an already-accepted record (I2 / no-data-loss hold). It bounds the un-fsynced
    // (buffered-but-not-durable) write frontier to the configured headroom, reusing the engine's
    // `unsynced_bytes()` frontier (the #341 tracking). A no-op when the headroom is disabled (the
    // default), so the append path is byte-for-byte unchanged for a broker that has not opted in.
    if engine.wal_headroom_enabled() {
        // The new record's LOGICAL bytes (key + headers + payload), the same units the un-fsynced
        // frontier is measured in.
        let record_bytes =
            u64::try_from(append.key.len() + append.headers.len() + append.payload.len())
                .unwrap_or(u64::MAX);
        if !engine.wal_headroom_admit(record_bytes) {
            // The headroom is exhausted: DRAIN first — the ONE covering barrier for the parked
            // batch (`flush_pending` on the legacy tiers; `quiesce_to_durable` on the pipelined
            // tier, identical post-conditions, #1040). Under the default `sync` level (and a DUE
            // `interval` window) that is a real `fdatasync`, so it resets the un-fsynced frontier
            // to `0` and the record is then admitted by the no-wedge floor: the headroom THROTTLES
            // (drain-then-admit), never sheds, never loses. Under a relaxed `async`/`none` level a
            // commit DEFERS the fsync, so the frontier does NOT drain; the re-check still fails and
            // the new produce is SHED to keep the loss window within the headroom. The
            // already-buffered records are untouched (they stay durable-pending and are made
            // durable by their level's barrier), so only this NEW produce is rejected.
            batch.drain_for_headroom(engine);
            if !engine.wal_headroom_admit(record_bytes) {
                // The drain could not free the headroom (a relaxed level deferring the fsync): shed
                // this NEW produce with the typed, self-announcing signal, count it (a shed is never
                // silent), and keep the session open.
                engine.record_wal_headroom_shed();
                engine.retry_budget_record_shed();
                send_outcome(&reply, ProduceOutcome::WalHeadroomShed);
                return;
            }
        }
    }
    // Append (write, NO fsync) and park the reply; the covering fsync is issued once for the whole
    // batch by `flush_pending` below.
    let view = Append {
        timestamp_ms: append.timestamp_ms,
        flags: ironbus_core::types::RecordFlags::from_bits(append.flags),
        key: &append.key,
        headers: &append.headers,
        payload: &append.payload,
    };
    match engine.append_no_sync_dedup_checked(&view, dedup_request(append), append.body_checksums) {
        Ok(crate::engine::AppendOutcome::Appended(offset)) => {
            // An accepted produce feeds the broker-side retry-budget accept count (#69), so the
            // observed retry ratio stays meaningful under load.
            engine.retry_budget_record_accept();
            // Per-ack-level PRODUCE throughput (#571): attribute this freshly-appended record to its
            // ack level (c0/c1/c2). Counted on a FRESH append only (a dedup hit / fence / out-of-order
            // appended nothing), so the per-level sum equals the fresh-append count, the single-node
            // twin of the cluster ack-level counters. Allocation-free (a fixed-index array bump under
            // the actor's single-writer lock).
            engine.record_produce_ack_level(append.ack_level);
            // A fire-and-forget (QoS-0) produce is appended durably exactly like a normal produce
            // (covering group-commit fsync) but gets NO `PubAck`, so park it as the no-ack outcome; a
            // normal produce parks as `Appended`. (A Level-0 produce carries `reply: None`, so even
            // its `FireAndForgetAppended` parked outcome sends nothing on flush — `None` is the
            // generalized faf disposition.)
            let outcome = if append.fire_and_forget {
                PendingOutcome::FireAndForgetAppended(offset)
            } else {
                PendingOutcome::Appended(offset)
            };
            batch.park(engine, outcome, reply);
        }
        // A BENIGN dedup hit (#33): nothing was appended, but its original offset may be an id recorded
        // earlier in THIS uncommitted batch, so PARK the reply behind the covering fsync too (I2). On a
        // sync failure the batch is non-durable and every parked reply, hit or fresh, becomes Fatal,
        // exactly as for a fresh append. (On the pipelined tier a duplicate of a LONG-DURABLE id on a
        // fully-durable log releases immediately with zero fsyncs — the park's dup-of-durable fast
        // path, #1040; a hit on an id recorded in the current unsynced window still parks, I2 uniform.)
        Ok(crate::engine::AppendOutcome::Duplicate(offset)) => {
            batch.park(engine, PendingOutcome::Duplicate(offset), reply);
        }
        // A stale-epoch fence (#33): nothing was written, so reply immediately; it does not join the
        // durable batch.
        Ok(crate::engine::AppendOutcome::Fenced { .. }) => {
            send_outcome(&reply, ProduceOutcome::Fenced);
        }
        // An out-of-order idempotent sequence (V2-M8): nothing was written (the gap is rejected so a
        // later retry of the skipped seq cannot double-append), so reply immediately; it does not join
        // the durable batch.
        Ok(crate::engine::AppendOutcome::OutOfOrder { .. }) => {
            send_outcome(&reply, ProduceOutcome::OutOfOrder);
        }
        // A shed or a hard error is known WITHOUT the sync (nothing was written), so reply immediately;
        // it does not join the durable batch.
        Err(e) if e.is_at_capacity() => {
            // A byte-cap shed is a request the broker shed (the retry-budget signal).
            engine.retry_budget_record_shed();
            send_outcome(&reply, ProduceOutcome::AtCapacity);
        }
        Err(e) if e.is_fatal() => {
            send_outcome(&reply, ProduceOutcome::Fatal(e));
        }
        Err(e) => {
            send_outcome(&reply, ProduceOutcome::Failed(e));
        }
    }
}

/// Issues the SINGLE `commit_batch` fsync that covers every parked produce, then releases each parked
/// reply: a success once durable (I2), or, if the fsync froze the writer, a fatal error to every
/// member of the batch (so each producer ends its session rather than believing a non-durable record
/// was acked). A no-op when nothing is parked (no produce since the last commit), so a lone job or a
/// shutdown with no pending produce never issues a spurious fsync. After this returns, `pending` is
/// empty.
fn flush_pending<F, C>(engine: &mut Engine<F, C>, pending: &mut Vec<PendingProduce>)
where
    F: Filesystem,
    C: Clock + Clone,
{
    if pending.is_empty() {
        return;
    }
    // ONE fsync for the whole batch (group commit). Its result decides EVERY parked reply: only after
    // it returns Ok is any record in the batch durable, so no `PubAck` precedes it (I2).
    match engine.commit_batch() {
        Ok(()) => {
            for p in pending.drain(..) {
                // A LEVEL-0 (no-ack) parked produce carries no reply channel (#495): it is durable now
                // (covered by the same fsync), but the producer fired and forgot, so send nothing.
                let Some(reply) = p.reply else {
                    continue;
                };
                let _ = reply.send(released_outcome(p.outcome));
            }
        }
        Err(e) => {
            // The fsync froze the writer: NONE of the batch is durable. Tell every producer it was a
            // fatal storage error so each ends its session, exactly as the pre-actor per-produce path
            // did when its `log.sync()?` surfaced `WriterFrozen` — the shared fan-out mapping
            // (first member the real error, the rest `WriterFrozen`, Level-0 skipped without
            // consuming the real error).
            fatal_fan_replies(pending.drain(..).map(|p| p.reply), Some(e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{
        DiskFullPolicy, EngineConfig, Poll, DEFAULT_GROUP_IDLE_EVICT_MS, DEFAULT_MAX_GROUPS,
    };

    use ironbus_core::clock::ManualClock;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_storage::fault::{FaultControl, FaultFs};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;

    #[test]
    fn the_default_stream_always_routes_to_shard_zero() {
        // #811: the default stream `""` is PINNED to shard 0 for ANY shard count, so its byte-identical
        // single-log path is preserved when sharding lands. And with one shard, EVERY stream routes to 0,
        // so the routing seam is byte-for-byte today.
        for shards in [1usize, 2, 4, 8, 64] {
            assert_eq!(shard_of("", shards), 0, "default stream pins to shard 0");
        }
        for name in ["orders", "clicks", "a/b/c", "x"] {
            assert_eq!(
                shard_of(name, 1),
                0,
                "with one shard every stream is shard 0"
            );
        }
    }

    #[test]
    fn shard_of_is_deterministic_in_range_and_spreads_named_streams() {
        // Deterministic (same name -> same shard) and always in range; named streams spread across the
        // shards (a sanity check, not a statistical one) so a fan-out actually parallelizes.
        const K: usize = 8;
        for name in ["orders", "clicks", "telemetry", "a/b/c"] {
            let s = shard_of(name, K);
            assert!(s < K, "shard {s} in range for {K}");
            assert_eq!(s, shard_of(name, K), "deterministic for {name}");
        }
        let distinct: std::collections::HashSet<usize> = (0..200u32)
            .map(|i| shard_of(&format!("stream-{i}"), K))
            .collect();
        assert!(
            distinct.len() >= K / 2,
            "200 named streams spread across the shards (got {} of {K})",
            distinct.len()
        );
    }

    fn config() -> EngineConfig {
        EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig::default(),
            lease: LeaseConfig::default(),
            delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
            max_in_flight: 64,
            consumer_credit: 64,
            consumer_credit_bytes: 0,
            checkpoint_interval: 1024,
            max_retained_bytes: 0,
            max_age_ms: 0,
            max_messages: 0,
            max_groups: DEFAULT_MAX_GROUPS,
            // Named-stream cap OFF (#863, `0` = unlimited): preserves the historical unbounded behavior.
            max_streams: 0,
            max_open_streams: 0,
            max_metric_streams: crate::engine::DEFAULT_MAX_METRIC_STREAMS,
            group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
            ram_ceiling_bytes: 0,
            disk_full_policy: DiskFullPolicy::DropNew,
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
            sync_max_dirty_bytes: 0,
            // Compression OFF (#430): the actor tests pin the historical byte-identical image;
            // the engine compression tests cover the lz4 path.
            compression: ironbus_core::compress::Codec::None,
            // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
            // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
            default_message_ttl_ms: 0,
            dead_letter_exchange: None,
            dead_letter_expired: false,
        }
    }

    /// Builds an engine over a fault-injecting filesystem (so a test can stall/count `sync_data`) on a
    /// `ManualClock` (so no test reads the wall clock), spawns the append actor over it, and returns
    /// the handle, the actor join handle, and the shared fault control.
    #[allow(clippy::type_complexity)]
    fn rig() -> (
        EngineHandle<FaultFs<InMemoryFs>, ManualClock>,
        std::thread::JoinHandle<Engine<FaultFs<InMemoryFs>, ManualClock>>,
        FaultControl,
    ) {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        (handle, actor, control)
    }

    fn append(payload: &[u8]) -> OwnedAppend {
        OwnedAppend {
            timestamp_ms: 0,
            flags: 0,
            key: Bytes::new(),
            headers: Bytes::new(),
            payload: Bytes::copy_from_slice(payload),
            // Carry the REAL offloaded body checksum (#830) as the session does, so every actor produce
            // test drives the `encode_precomputed` path; the codec's debug_assert then pins that the
            // off-actor incremental value matches the actor-computed one across the whole suite.
            body_checksums: Some(ironbus_core::codec::BodyChecksums::compute(
                b"", b"", payload,
            )),
            dedup: None,
            enqueue_monotonic_nanos: 0,
            fire_and_forget: false,
            ack_level: ironbus_proto::message::AckLevel::ServerAck,
        }
    }

    /// A FIRE-AND-FORGET (QoS-0, #11) owned produce, for the actor-level fire-and-forget tier tests.
    /// A faf produce IS a Level-0 publish (#495), so its ack level is `NoAck`.
    fn append_faf(payload: &[u8]) -> OwnedAppend {
        OwnedAppend {
            fire_and_forget: true,
            ack_level: ironbus_proto::message::AckLevel::NoAck,
            ..append(payload)
        }
    }

    /// An owned produce that opts into dedup with `(producer_id, epoch, msg_id)` (#33), for the
    /// actor-level dedup tests.
    fn append_dedup(payload: &[u8], producer_id: &[u8], epoch: u64, msg_id: &[u8]) -> OwnedAppend {
        OwnedAppend {
            timestamp_ms: 0,
            flags: 0,
            key: Bytes::new(),
            headers: Bytes::new(),
            payload: Bytes::copy_from_slice(payload),
            body_checksums: Some(ironbus_core::codec::BodyChecksums::compute(
                b"", b"", payload,
            )),
            dedup: Some(OwnedDedup {
                producer_id: Bytes::copy_from_slice(producer_id),
                epoch,
                msg_id: Bytes::copy_from_slice(msg_id),
                seq: None,
            }),
            enqueue_monotonic_nanos: 0,
            fire_and_forget: false,
            ack_level: ironbus_proto::message::AckLevel::ServerAck,
        }
    }

    /// Drains the actor and joins it, returning the recovered engine.
    fn recover(
        handle: EngineHandle<FaultFs<InMemoryFs>, ManualClock>,
        actor: std::thread::JoinHandle<Engine<FaultFs<InMemoryFs>, ManualClock>>,
    ) -> Engine<FaultFs<InMemoryFs>, ManualClock> {
        let _ = handle.shutdown();
        drop(handle);
        actor.join().unwrap()
    }

    /// The actor test config with the durability level and the fsync-headroom overridden, sharing the
    /// default test knobs (#378). Lets a headroom test drive the real append-actor group-commit path
    /// under a chosen durability level.
    fn config_headroom(level: crate::engine::DurabilityLevel, headroom_bytes: u64) -> EngineConfig {
        EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            durability_level: level,
            wal_fsync_headroom_bytes: headroom_bytes,
            ..config()
        }
    }

    /// Builds a fault-fs + `ManualClock` rig over `config_headroom(level, headroom_bytes)` and spawns
    /// the append actor, returning the handle, the actor join handle, and the fault control (#378).
    #[allow(clippy::type_complexity)]
    fn rig_headroom(
        level: crate::engine::DurabilityLevel,
        headroom_bytes: u64,
    ) -> (
        EngineHandle<FaultFs<InMemoryFs>, ManualClock>,
        std::thread::JoinHandle<Engine<FaultFs<InMemoryFs>, ManualClock>>,
        FaultControl,
    ) {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(
            fs,
            ManualClock::new(),
            config_headroom(level, headroom_bytes),
        )
        .unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        (handle, actor, control)
    }

    /// The actor test config with a hard durable-log byte cap and the overflow policy overridden
    /// (#476), sharing the default test knobs. Lets the connection-thread fast-reject tests drive the
    /// real append-actor byte-cap shed path under a chosen policy.
    fn config_capped(cap: u64, policy: DiskFullPolicy) -> EngineConfig {
        EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig::default().with_max_total_bytes(cap),
            disk_full_policy: policy,
            ..config()
        }
    }

    /// Builds a fault-fs + `ManualClock` rig over `config_capped(cap, policy)` and spawns the append
    /// actor, returning the handle, the actor join handle, and the fault control (#476).
    #[allow(clippy::type_complexity)]
    fn rig_capped(
        cap: u64,
        policy: DiskFullPolicy,
    ) -> (
        EngineHandle<FaultFs<InMemoryFs>, ManualClock>,
        std::thread::JoinHandle<Engine<FaultFs<InMemoryFs>, ManualClock>>,
        FaultControl,
    ) {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config_capped(cap, policy)).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        (handle, actor, control)
    }

    /// Produces `payload` (awaiting each, so the actor commits and refreshes the fast-reject gate)
    /// until the engine's durable byte total has reached `cap`, i.e. until the next produce is a
    /// byte-cap shed. Returns how many records were accepted. Used to drive the log to its cap
    /// deterministically without hard-coding the per-record framed byte size.
    fn fill_to_cap(
        handle: &EngineHandle<FaultFs<InMemoryFs>, ManualClock>,
        payload: &[u8],
        cap: u64,
    ) -> u64 {
        let mut accepted = 0u64;
        loop {
            match handle.produce(append(payload)).unwrap() {
                ProduceOutcome::Appended(_) => accepted += 1,
                // The cap was reached by a prior record (the authoritative actor shed this one); the
                // log is now at/over cap, which is exactly the state we wanted to reach.
                ProduceOutcome::AtCapacity => break,
                other => panic!("unexpected fill outcome: {other:?}"),
            }
            if handle.with(|e| e.durable_record_bytes()).unwrap() >= cap {
                break;
            }
        }
        accepted
    }

    #[test]
    fn a_hung_fsync_wedges_the_actor_and_the_watchdog_detects_it() {
        // #862: a HUNG durability fsync blocks the single append actor FOREVER. The accept-loop liveness
        // beacon is deliberately decoupled and stays green, and `/readyz` (which queues a job through the
        // actor) would HANG behind the wedged fsync — a silent total stall with liveness reporting
        // healthy. The actor-progress watchdog detects it: the actor stamps `busy` BEFORE the fsync, and
        // the health server's NON-BLOCKING `actor_watchdog_overran` (which never goes through the actor)
        // trips once the in-flight batch overruns the bound, so `/healthz` and `/readyz` flip to 503.
        const BOUND: u64 = 1_000;
        let (handle, actor, control) = rig();
        handle.set_actor_watchdog_bound(BOUND);
        let t0 = handle.now_monotonic_nanos();

        // IDLE: with no in-flight batch the actor is never reported wedged, no matter how much time
        // passes — only an overrunning in-flight batch trips it (a quiet broker never false-503s).
        assert!(
            !handle.actor_watchdog_overran(t0 + BOUND + 2),
            "an idle actor is never reported wedged"
        );

        // Arm a HUNG fsync: the next produce's covering fdatasync PARKS on the closed gate forever.
        control.close_sync_gate();
        let produce = {
            let h = handle.clone();
            // This BLOCKS in the wedged fsync; it returns only once the gate is opened at teardown.
            std::thread::spawn(move || {
                let _ = h.produce(append(b"wedge"));
            })
        };
        // Deterministically wait until the actor is parked mid-fsync (so `mark_busy` has already run).
        control.wait_for_sync_gate_entered(1);

        // The actor is now BUSY (stamped at ~t0) and wedged in the fsync. Within the bound it is still
        // healthy; PAST the bound the watchdog trips — detected WITHOUT going through the wedged actor.
        assert!(
            !handle.actor_watchdog_overran(t0 + BOUND),
            "within the bound the in-flight batch is not yet wedged (strict >)"
        );
        assert!(
            handle.actor_watchdog_overran(t0 + BOUND + 2),
            "past the bound the hung-fsync wedge is DETECTED — /healthz and /readyz flip to 503 (#862)"
        );

        // Recover: open the gate so the parked fsync completes, the produce returns, and the actor joins
        // cleanly — proving the watchdog detection did not itself disturb the actor.
        control.open_sync_gate();
        produce.join().unwrap();
        let _ = handle.shutdown();
        drop(handle);
        let _ = actor.join();
    }

    #[test]
    fn the_actor_publishes_a_frozen_writer_and_readyz_reads_it_without_a_round_trip() {
        // #862 PRODUCTION PUBLISH→READ PATH: after a covering fsync RETURNS an error and freezes the
        // writer, `run_actor` publishes `engine.is_healthy()` to the watchdog, and
        // `EngineAccess::writer_appears_healthy` (what `/readyz` reads) returns that PUBLISHED flag
        // WITHOUT queuing a job through the actor. `admin_resilience` proves the `/readyz` 503 over a
        // `SharedEngine` (a direct-lock fixture); this proves the REAL actor wiring — that the running
        // append actor actually publishes the frozen state the non-blocking read reports.
        let (handle, actor, control) = rig();

        // A clean produce keeps the writer live; force the batch's post-commit publish to complete (a
        // follow-up `Run` job is processed in a LATER actor iteration, so the produce batch's publish
        // has run by the time `with` returns) and confirm the published flag reads HEALTHY.
        handle.produce(append(b"live")).expect("a clean produce");
        let _ = handle.with(|_| ());
        assert!(
            handle.writer_appears_healthy(),
            "a live writer publishes healthy"
        );

        // Arm a FATAL fsync (one that RETURNS an error, not the hang above): the next produce's covering
        // fdatasync fails and freezes the writer one-way. The produce comes back `Fatal`, and — unlike a
        // hang — the actor keeps serving (a frozen writer answers reads, refuses writes).
        control.set_fail_sync(true);
        let outcome = handle.produce(append(b"freeze"));
        assert!(
            matches!(outcome, Ok(ProduceOutcome::Fatal(_))),
            "the covering fsync error freezes the writer: {outcome:?}"
        );

        // Force the FROZEN batch's publish to complete, then assert the NON-BLOCKING read reports the
        // writer unhealthy — exactly the signal `/readyz` sheds 503 on, observed WITHOUT a hung actor.
        let _ = handle.with(|_| ());
        assert!(
            !handle.writer_appears_healthy(),
            "the actor published the frozen writer; /readyz reads it without a round-trip (#862)"
        );

        // Clear the armed fault so teardown's drain does not re-trip it, then join cleanly.
        control.set_fail_sync(false);
        let _ = handle.shutdown();
        drop(handle);
        let _ = actor.join();
    }

    #[test]
    fn an_over_cap_produce_fast_rejects_on_the_connection_thread_without_blocking() {
        // THE #465 FIX over the REAL append actor (#476): once the durable log is at/over its drop-new
        // byte cap, a produce must get a PROMPT `AtCapacity` on the CONNECTION thread, WITHOUT
        // enqueuing onto (and blocking on) the bounded actor channel. We prove "without enqueuing /
        // without blocking" by the SUBMISSION SHAPE: `produce_submit` returns `Ready(AtCapacity)`,
        // which ONLY the connection-thread fast-reject path produces — the channel path always returns
        // `Pending`. So a `Ready` is proof the produce never touched `tx.send` (and so could never
        // block on a full channel, the #465 symptom).
        const FAST_REJECTS: u64 = 8;
        let cap = 512;
        let (handle, actor, _control) = rig_capped(cap, DiskFullPolicy::DropNew);
        // Drive the log to its cap; the actor publishes the over-cap byte total to the gate on its
        // post-commit refresh.
        let accepted = fill_to_cap(&handle, &[0x5a_u8; 64], cap);
        assert!(accepted > 0, "some records were accepted before the cap");
        let bytes = handle.with(|e| e.durable_record_bytes()).unwrap();
        assert!(bytes >= cap, "the log is at/over its cap: {bytes}/{cap}");

        // The `produce_rejected` counter the broker has observed SO FAR (a `with` is a `Run` job, so
        // this also reconciles any pending fast-rejects first — here there are none yet). Some of
        // `fill_to_cap`'s tail produces may have been shed by the authoritative actor, so capture the
        // baseline rather than assuming zero.
        let rejected_before = handle.with(|e| e.counters().produce_rejected).unwrap();

        // The over-cap produce returns a fast `Ready(AtCapacity)` — no enqueue, no block. Repeated, to
        // show the gate stays engaged while the log stays over cap (every saturating produce gets the
        // prompt shed rather than stalling behind a full channel).
        for attempt in 0..FAST_REJECTS {
            match handle.produce_submit(append(b"over-cap")).unwrap() {
                ProduceSubmission::Ready(ProduceOutcome::AtCapacity) => {}
                ProduceSubmission::Ready(other) => {
                    panic!("attempt {attempt}: expected a Ready(AtCapacity) fast-reject, got Ready({other:?})")
                }
                ProduceSubmission::Pending { .. } => panic!(
                    "attempt {attempt}: the over-cap produce was ENQUEUED (Pending) instead of \
                     fast-rejected: it would have blocked on a saturated channel — the #465 bug"
                ),
            }
        }

        // A FAST-REJECT IS NEVER SILENT (#476): the actor reconciles the 8 connection-thread
        // fast-rejects into the engine's authoritative `produce_rejected`, so the counter the broker
        // exports matches the rejections the producer actually saw — exactly the equality the CLI
        // acceptance test asserts against `/metrics`. The `with` runs as a `Run` job, which folds the
        // pending fast-rejects in BEFORE the counter read.
        let rejected_after = handle.with(|e| e.counters().produce_rejected).unwrap();
        assert_eq!(
            rejected_after - rejected_before,
            FAST_REJECTS,
            "every connection-thread fast-reject is counted in produce_rejected (never a silent shed)"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_near_cap_but_admissible_produce_is_not_falsely_rejected() {
        // NO FALSE REJECTS (the conservatism property, #476): a produce that the authoritative actor
        // WOULD accept must never be fast-rejected. We sit the log JUST UNDER the cap (under-cap byte
        // total) and assert the next produce is genuinely `Appended`, going through the normal actor
        // path — the gate falls through, never short-circuits.
        let cap = 4_096;
        let (handle, actor, _control) = rig_capped(cap, DiskFullPolicy::DropNew);
        // One small record: the log is now far under the cap, so the gate must NOT fire.
        let first = handle.produce(append(b"small")).unwrap();
        assert!(
            matches!(first, ProduceOutcome::Appended(_)),
            "the first record is accepted: {first:?}"
        );
        // Confirm we are genuinely near-but-under the cap, then the next produce must be admitted (the
        // submission goes through the channel — `Pending`/`Appended` — never a fast `AtCapacity`).
        let bytes = handle.with(|e| e.durable_record_bytes()).unwrap();
        assert!(
            bytes > 0 && bytes < cap,
            "near cap but under it: {bytes}/{cap}"
        );
        let submission = handle.produce_submit(append(b"also-small")).unwrap();
        match submission {
            // The expected path: the produce was enqueued (NOT fast-rejected) and the actor accepts it.
            ProduceSubmission::Pending { .. } => {
                let outcome = submission_for_test_wait(submission);
                assert!(
                    matches!(outcome, ProduceOutcome::Appended(_)),
                    "an under-cap produce is accepted, never falsely rejected: {outcome:?}"
                );
            }
            ProduceSubmission::Ready(ProduceOutcome::AtCapacity) => {
                panic!("FALSE REJECT: an under-cap produce was fast-rejected as AtCapacity")
            }
            ProduceSubmission::Ready(other) => panic!("unexpected Ready outcome: {other:?}"),
        }
        let _ = recover(handle, actor);
    }

    #[test]
    fn drop_oldest_never_fast_rejects_even_when_over_cap() {
        // CONSERVATISM UNDER POLICY (#476): under drop-oldest the connection-thread fast-reject must
        // NEVER fire, because that policy ACCEPTS an over-cap produce after a force-reap (a fast
        // `AtCapacity` would be a false reject). The actor publishes the under-cap sentinel while the
        // policy is drop-oldest, so the gate stays DISENGAGED no matter how full the log gets. The
        // authoritative actor may still legitimately return `AtCapacity` through the CHANNEL in its
        // documented wedge-guard fall-back (only the active segment left to reap) — that is correct
        // and is NOT a gate decision; the property under test is strictly that no produce is short-
        // circuited as a `Ready(AtCapacity)` fast-reject on the connection thread.
        let cap = 512;
        let (handle, actor, _control) = rig_capped(cap, DiskFullPolicy::DropOldest);
        // Drive well past the cap. Every submission must go through the channel (`Pending`) — the gate
        // is disengaged under drop-oldest, so it never produces a `Ready(AtCapacity)`. The actor's own
        // outcome (Appended when it can reap, or the wedge-guard AtCapacity) is whatever it authorit-
        // atively decides; what matters here is that it was NEVER fast-rejected before the channel.
        let mut fast_reject_seen = false;
        let mut appended = 0u64;
        for _ in 0..64u64 {
            match handle.produce_submit(append(&[0x5a_u8; 64])).unwrap() {
                ProduceSubmission::Ready(ProduceOutcome::AtCapacity) => fast_reject_seen = true,
                ProduceSubmission::Ready(other) => panic!("unexpected Ready outcome: {other:?}"),
                // The normal, authoritative path: drain the outcome so its reply channel recycles.
                ProduceSubmission::Pending { channel, pool, .. } => {
                    if matches!(channel.rx.recv(), Ok(ProduceOutcome::Appended(_))) {
                        appended += 1;
                    }
                    drop(pool);
                }
            }
        }
        assert!(
            !fast_reject_seen,
            "FALSE REJECT under drop-oldest: the connection-thread gate fired (it must stay \
             disengaged under a policy that accepts over-cap produces)"
        );
        assert!(
            appended > 0,
            "drop-oldest admitted produces via the authoritative path (the gate never blocked them)"
        );
        let _ = recover(handle, actor);
    }

    /// Awaits a `Pending` submission's outcome in a test, recycling its channel like the real `wait`.
    /// A tiny helper so a test can assert on the SHAPE of the submission first (Pending vs Ready) and
    /// then collect its outcome without re-implementing the recv/return dance inline.
    fn submission_for_test_wait(submission: ProduceSubmission) -> ProduceOutcome {
        submission.wait().unwrap()
    }

    /// A LEVEL-0 (no-ack) owned produce: it is `append_faf` (the fire-and-forget marker), since the
    /// session sets `fire_and_forget` for every Level-0 publish — an L0 produce IS the generalized
    /// fire-and-forget produce (#495).
    fn append_l0(payload: &[u8]) -> OwnedAppend {
        append_faf(payload)
    }

    #[test]
    fn a_level0_produce_appends_durably_with_no_reply() {
        // THE L0 FAST PATH (#495): a Level-0 produce is appended on the actor's single-writer storage
        // (single total order / I2 for other records untouched), covered by the group-commit fsync,
        // but the session sent NO reply channel — `produce_no_reply` returns `Ok(())` WITHOUT waiting
        // for the fsync and never blocks on a reply that will never come. We prove the record landed by
        // reading the durable head AFTER a following at-least-once produce flushes the batch.
        let (handle, actor, _control) = rig();
        handle.produce_no_reply(append_l0(b"qos0-record")).unwrap();
        // A following Level-1 produce shares the batch, so its ack proves the L0 record was committed
        // ahead of it in the same single total order (offset 0 is the L0 record, offset 1 the L1 one).
        let l1 = handle.produce(append(b"ack-me")).unwrap();
        assert!(
            matches!(l1, ProduceOutcome::Appended(o) if o.get() == 1),
            "the L1 produce after the no-reply L0 acks at offset 1 (the L0 took offset 0): {l1:?}"
        );
        let head = handle.with(|e| e.durable_record_bytes()).unwrap();
        assert!(head > 0, "both records are durable: {head} bytes");
        let _ = recover(handle, actor);
    }

    #[test]
    fn an_over_cap_level0_produce_is_shed_at_the_connection_thread_into_fire_and_forget_shed() {
        // THE L0 CAP PRE-CHECK (#495 over #476): once the durable log is at/over its drop-new byte cap,
        // a Level-0 produce is shed at the CONNECTION THREAD by the same byte-cap gate — but counted in
        // `fire_and_forget_shed` (an over-cap L0 drop is a fire-and-forget drop), NOT `produce_rejected`
        // (the Level-1 rejection counter). `produce_no_reply` returns `Ok(())` either way (a shed L0 is
        // not an error; the producer accepted loss), so the only observable is the COUNTER delta.
        const L0_SHEDS: u64 = 6;
        let cap = 512;
        let (handle, actor, _control) = rig_capped(cap, DiskFullPolicy::DropNew);
        let accepted = fill_to_cap(&handle, &[0x5a_u8; 64], cap);
        assert!(accepted > 0, "some records were accepted before the cap");
        // Baselines AFTER a `with` (a Run job, which reconciles any pending fast-rejects first).
        let faf_before = handle
            .with(|e| e.backpressure_snapshot().fire_and_forget_shed)
            .unwrap();
        let rejected_before = handle.with(|e| e.counters().produce_rejected).unwrap();

        // Each over-cap L0 is dropped at the connection thread (no enqueue, no error).
        for _ in 0..L0_SHEDS {
            handle.produce_no_reply(append_l0(b"over-cap-l0")).unwrap();
        }

        // The actor folds the L0 sheds into `fire_and_forget_shed` (never a silent drop), and leaves
        // `produce_rejected` (the Level-1 rejection counter) untouched. The `with` runs as a Run job,
        // which reconciles the pending L0 sheds BEFORE the counter read.
        let faf_after = handle
            .with(|e| e.backpressure_snapshot().fire_and_forget_shed)
            .unwrap();
        let rejected_after = handle.with(|e| e.counters().produce_rejected).unwrap();
        assert_eq!(
            faf_after - faf_before,
            L0_SHEDS,
            "every over-cap L0 cap-shed is counted in fire_and_forget_shed (never silent)"
        );
        assert_eq!(
            rejected_after, rejected_before,
            "an L0 cap-shed must NOT touch produce_rejected (that is the Level-1 rejection counter)"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn an_over_cap_level0_batch_sheds_every_append_into_fire_and_forget_shed() {
        // THE BATCHED L0 CAP PRE-CHECK (#11 fast path, the capped `retain` arm of
        // `produce_no_reply_batch`): once the durable log is at/over its drop-new byte cap, a BATCH of
        // Level-0 produces is shed IN PLACE just like the per-message `produce_no_reply` — every shed
        // append is counted in `fire_and_forget_shed` (a fire-and-forget drop), NOT `produce_rejected`,
        // and when every append sheds NOTHING is enqueued. `produce_no_reply_batch` returns `Ok(())` (a
        // shed L0 is not an error). The only observable is the counter delta — this is the batch twin of
        // `an_over_cap_level0_produce_is_shed_...` and guards the capped admission the #11 review flagged.
        const BATCH: u64 = 7;
        let cap = 512;
        let (handle, actor, _control) = rig_capped(cap, DiskFullPolicy::DropNew);
        let accepted = fill_to_cap(&handle, &[0x5a_u8; 64], cap);
        assert!(accepted > 0, "some records were accepted before the cap");
        let faf_before = handle
            .with(|e| e.backpressure_snapshot().fire_and_forget_shed)
            .unwrap();
        let rejected_before = handle.with(|e| e.counters().produce_rejected).unwrap();

        // One batch of over-cap L0s: every append is at/over the cap, so the capped `retain` arm sheds
        // all of them at the connection thread (no enqueue, no error).
        let batch: Vec<OwnedAppend> = (0..BATCH)
            .map(|_| append_l0(b"over-cap-l0-batch"))
            .collect();
        handle.produce_no_reply_batch(batch).unwrap();

        let faf_after = handle
            .with(|e| e.backpressure_snapshot().fire_and_forget_shed)
            .unwrap();
        let rejected_after = handle.with(|e| e.counters().produce_rejected).unwrap();
        assert_eq!(
            faf_after - faf_before,
            BATCH,
            "every over-cap L0 in the batch is counted in fire_and_forget_shed (never silent)"
        );
        assert_eq!(
            rejected_after, rejected_before,
            "a batched L0 cap-shed must NOT touch produce_rejected (the Level-1 rejection counter)"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_level0_produce_dropped_by_the_fire_and_forget_bucket_sends_no_reply() {
        // THE GENERALIZED FAF BUCKET (#495): a Level-0 produce is still governed by the fire-and-forget
        // token bucket (#336). The `rig_faf` bucket ceiling is exactly 1 (10 msg/s * 100 ms), and the
        // ManualClock never advances (no refill), so the FIRST L0 is admitted-no-ack and every later L0
        // is DROPPED (no append, no reply) and counted in `fire_and_forget_shed` — exactly the
        // historical faf disposition, only now without a reply channel to suppress.
        let (handle, actor, _control) = rig_faf();
        // Five no-reply L0 produces: the bucket admits 1 and sheds 4. None blocks or errors (there is
        // no reply channel), so the only observable is the shed counter.
        for _ in 0..5u64 {
            handle.produce_no_reply(append_l0(b"bucket")).unwrap();
        }
        // A trailing at-least-once produce forces the batch to commit and lets us read the head; it is
        // never governed by the faf bucket (the bucket touches the QoS-0 tier only).
        let alo = handle.produce(append(b"alo")).unwrap();
        assert!(
            matches!(alo, ProduceOutcome::Appended(_)),
            "an at-least-once produce is never shed by the faf bucket: {alo:?}"
        );
        let (head, faf_shed) = handle
            .with(|e| {
                (
                    e.flushed_offset().get(),
                    e.backpressure_snapshot().fire_and_forget_shed,
                )
            })
            .unwrap();
        assert_eq!(
            faf_shed, 4,
            "4 of the 5 L0 produces shed by the bucket (counted, never silent)"
        );
        assert_eq!(
            head, 2,
            "exactly the 1 admitted L0 (offset 0) and the at-least-once produce (offset 1) are durable"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_relaxed_level_headroom_sheds_the_over_backlog_produce_with_no_accepted_record_lost() {
        // THE TEETH for the fsync-headroom shed over the REAL append actor (#378): under a relaxed
        // `async` level a commit DEFERS the fsync, so the un-fsynced backlog grows across produces.
        // With a tight headroom, once the backlog fills, the next produce is SHED with the typed
        // `WalHeadroomShed` (a self-announcing signal), while every accepted record stays durable
        // (no-data-loss: the shed rejects NEW work only). A 16-byte payload and a 64-byte headroom:
        // the first 4 fit (4x16 = 64), the 5th would exceed it and is shed.
        let (handle, actor, _control) = rig_headroom(crate::engine::DurabilityLevel::Async, 64);
        let payload = [0xab_u8; 16];
        // The first 4 produces fill the headroom exactly; each is accepted (async acks pre-fsync).
        for i in 0..4u64 {
            match handle.produce(append(&payload)).unwrap() {
                ProduceOutcome::Appended(o) => {
                    assert_eq!(o.get(), i, "accepted at the next offset");
                }
                other => panic!("produce {i} should be Appended, got {other:?}"),
            }
        }
        // The 5th produce would push the un-fsynced backlog past the 64-byte headroom; a drain cannot
        // free it (async defers the fsync), so it is shed with the typed headroom signal.
        match handle.produce(append(&payload)).unwrap() {
            ProduceOutcome::WalHeadroomShed => {}
            other => panic!("the over-backlog produce should be WalHeadroomShed, got {other:?}"),
        }
        // NO DATA LOSS: the 4 accepted records are still the durable-pending head; the shed dropped
        // only the NEW produce, never an accepted one. The shed counter incremented exactly once.
        let (head, sheds) = handle
            .with(|e| {
                (
                    e.flushed_offset().get(),
                    e.backpressure_snapshot().wal_headroom_shed,
                )
            })
            .unwrap();
        assert_eq!(
            head, 4,
            "the 4 accepted records are intact; only the new produce was shed"
        );
        assert_eq!(
            sheds, 1,
            "exactly one fsync-headroom shed was counted (never silent)"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn the_sync_level_headroom_throttles_via_the_group_commit_drain_and_never_sheds() {
        // THE TEETH for the safe-default composition over the REAL actor (#378 + #341): under the
        // default `sync` level each group commit issues the covering fsync, draining the un-fsynced
        // backlog to zero, so a tight headroom THROTTLES (drain-then-admit) and NEVER sheds, even for
        // records far larger than the headroom. We use an 8-byte headroom and 4 KiB payloads: every
        // produce is admitted and durable, and no headroom shed is ever counted.
        let (handle, actor, _control) = rig_headroom(crate::engine::DurabilityLevel::Sync, 8);
        let payload = [0xcd_u8; 4096];
        for i in 0..6u64 {
            match handle.produce(append(&payload)).unwrap() {
                ProduceOutcome::Appended(o) => {
                    assert_eq!(o.get(), i);
                }
                other => panic!("sync produce {i} should be Appended, got {other:?}"),
            }
        }
        let (head, sheds) = handle
            .with(|e| {
                (
                    e.flushed_offset().get(),
                    e.backpressure_snapshot().wal_headroom_shed,
                )
            })
            .unwrap();
        assert_eq!(head, 6, "every sync produce was admitted and made durable");
        assert_eq!(
            sheds, 0,
            "the sync level drains every batch, so the headroom never sheds"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_batch_of_concurrent_produces_issues_one_fdatasync_not_n() {
        // Group commit (#177): a burst of produces that the actor drains together is made durable by
        // ONE `commit_batch` fsync, not one per produce. We close the sync gate so the actor parks on
        // the first batch's fsync (guaranteeing every queued produce is in the SAME drained batch),
        // enqueue several produces, wait for the actor to reach the gate, then open it and collect the
        // replies. The fault fs counts exactly one sync for the whole batch.
        let (handle, actor, control) = rig();
        // Close the gate and send ONE primer produce. The actor appends it and parks on the primer's
        // covering fsync, which is a provable barrier: until we open the gate the actor consumes no
        // further command. We enqueue the burst WHILE the actor is parked, so every produce is in the
        // channel before the actor resumes and drains them, guaranteeing they all land in the SAME
        // batch. (Enqueuing first and racing the actor's initial drain flaked on Windows, where the
        // actor could drain a partial batch before the rest of the burst had been sent.)
        control.close_sync_gate();
        let primer = handle.produce_async(append(b"primer")).unwrap();
        control.wait_for_sync_gate_entered(1);
        // The actor is now parked on the primer's fsync; the burst queues behind it.
        let n = 8u64;
        let mut replies = Vec::new();
        for i in 0..n {
            replies.push(
                handle
                    .produce_async(append(format!("m{i}").as_bytes()))
                    .unwrap(),
            );
        }
        // Sampled while the actor is parked: only the primer's sync has run so far.
        let before = control.sync_count();
        // Open the gate: the primer's fsync completes, then the actor drains the whole queued burst
        // and makes it durable with ONE covering fsync.
        control.open_sync_gate();
        match primer.recv().unwrap() {
            ProduceOutcome::Appended(_) => {}
            other => panic!("expected Appended primer, got {other:?}"),
        }
        let mut offsets = Vec::new();
        for r in replies {
            match r.recv().unwrap() {
                ProduceOutcome::Appended(o) => offsets.push(o.get()),
                other => panic!("expected Appended, got {other:?}"),
            }
        }
        // Exactly ONE fsync covered the whole burst (group commit), not N.
        let after = control.sync_count();
        assert_eq!(
            after - before,
            1,
            "the drained burst issued exactly one fdatasync, not {n}"
        );
        // Single total durable order: the burst got the contiguous offsets 1..=n after the primer at 0.
        offsets.sort_unstable();
        assert_eq!(
            offsets,
            (1..=n).collect::<Vec<_>>(),
            "contiguous offsets after the primer"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn an_ack_is_sent_only_after_the_covering_fsync_completes_i2() {
        // I2 (ack-implies-durable): a produce's reply must NOT arrive before the covering fsync. With
        // the sync gate closed, the actor parks in `commit_batch`, so the produce reply is NOT ready;
        // only after the gate opens (the fsync completes) does the reply arrive as Appended.
        let (handle, actor, control) = rig();
        control.close_sync_gate();
        let reply = handle.produce_async(append(b"durable")).unwrap();
        control.wait_for_sync_gate_entered(1);
        // The fsync is stalled, so the produce has NOT been acked yet (no reply available).
        assert!(
            reply.try_recv().is_err(),
            "the PubAck must not precede the covering fsync (I2)"
        );
        // Release the fsync: the reply now arrives, durable.
        control.open_sync_gate();
        match reply.recv().unwrap() {
            ProduceOutcome::Appended(o) => assert_eq!(o.get(), 0),
            other => panic!("expected Appended after the fsync, got {other:?}"),
        }
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_stalled_produce_fsync_does_not_block_another_jobs_progress_to_the_actor() {
        // A stalled produce fsync on one producer's group must not wedge the actor forever: once the
        // fsync is released the actor drains and a later engine job (here an offset read, standing in
        // for an ack) completes. This is the no-deadlock half of invariant 3 at the actor boundary;
        // the ping-not-blocked acceptance (invariant 4) is proved at the session layer, where pings
        // never reach the actor at all.
        let (handle, actor, control) = rig();
        control.close_sync_gate();
        let reply = handle.produce_async(append(b"x")).unwrap();
        control.wait_for_sync_gate_entered(1);
        // A second produce piles up behind the stalled batch; releasing the gate drains everything.
        let reply2 = handle.produce_async(append(b"y")).unwrap();
        control.open_sync_gate();
        assert!(matches!(reply.recv().unwrap(), ProduceOutcome::Appended(_)));
        assert!(matches!(
            reply2.recv().unwrap(),
            ProduceOutcome::Appended(_)
        ));
        // A follow-up engine job runs to completion (the actor is not wedged).
        let committed = handle.with(|e| e.flushed_offset().get()).unwrap();
        assert_eq!(committed, 2, "both produces are durable after the stall");
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_closed_actor_is_a_typed_error_never_a_hang() {
        // No lost replies / no deadlock (invariant 3): once the actor exits, a later command returns a
        // typed ActorGone rather than hanging forever on the closed channel.
        let (handle, actor, _control) = rig();
        // Drain and stop the actor.
        handle.shutdown().unwrap().unwrap();
        actor.join().unwrap();
        // The channel is closed now: every call is a typed error, not a hang.
        assert!(
            handle.produce(append(b"z")).is_err(),
            "produce on a gone actor errors"
        );
        assert!(
            handle.with(|e| e.flushed_offset()).is_err(),
            "with on a gone actor errors"
        );
    }

    #[test]
    fn actor_alive_reads_true_while_running_and_false_after_a_graceful_exit() {
        // #922: the shared liveness flag is the health server's ONLY non-blocking way to see a gone
        // actor (the watchdog misses an idle death; the frozen-writer flag freezes at its last value).
        // Happy path: a running actor reads alive; the normal shutdown drop-guard flips it.
        let (handle, actor, _control) = rig();
        assert!(
            EngineAccess::actor_alive(&handle),
            "a running actor reads alive"
        );
        handle.shutdown().unwrap().unwrap();
        actor.join().unwrap();
        assert!(
            !EngineAccess::actor_alive(&handle),
            "the drop guard flips the flag on a graceful exit"
        );
    }

    #[test]
    fn actor_alive_flips_false_when_the_actor_panics() {
        // #922's hard case: an UNEXPECTED actor death (a panic mid-job) with the watchdog idle. The
        // ActorAliveGuard flips the flag on UNWIND (Drop runs during a panic), so the health server
        // sees the death without any actor round-trip. The `with` reply channel is a fresh (unpooled)
        // pair, so the caller observes a typed ActorGone from the disconnect — never a hang.
        let (handle, actor, _control) = rig();
        let result: Result<(), ActorGone> = handle.with(|_| panic!("injected actor death (#922)"));
        assert!(
            matches!(result, Err(ActorGone)),
            "the with() whose job panicked surfaces ActorGone"
        );
        assert!(
            actor.join().is_err(),
            "the actor thread really panicked (join reports the unwind)"
        );
        assert!(
            !EngineAccess::actor_alive(&handle),
            "the drop guard flips the flag on a PANIC exit too"
        );
    }

    #[test]
    fn a_pending_wait_returns_actorgone_when_the_actor_exited_un_replied() {
        // #949 (the residual #802 shutdown race): a `Command::Produce` whose reply the exiting actor
        // never sent leaves a `Pending` submission whose recycled reply channel STILL holds its
        // co-located `tx` (#475), so a plain `rx.recv()` would block FOREVER (the channel never
        // disconnects). The shared `actor_alive` flag — `false` once the actor's drop guard ran — is
        // what lets `wait` return the typed `ActorGone` instead of wedging. Build that exact state
        // directly: a pooled channel with NO outcome ever sent, and a flag already flipped `false`.
        //
        // MUTATION CHECK: revert `wait` to the pre-fix `channel.rx.recv()` and this test HANGS forever
        // (the co-located `tx` keeps the channel open), so it strictly discriminates the fix.
        let pool: ReplyPool = Arc::new(Mutex::new(Vec::new()));
        let channel = pool_take(&pool);
        let actor_alive = Arc::new(AtomicBool::new(false));
        let submission = ProduceSubmission::Pending {
            channel,
            pool: Arc::clone(&pool),
            spin: false,
            actor_alive,
        };
        assert!(
            matches!(submission.wait(), Err(ActorGone)),
            "a pending produce whose actor exited un-replied must return ActorGone, not wedge"
        );
    }

    #[test]
    fn a_pending_wait_delivers_a_sent_outcome_even_after_the_actor_marks_itself_gone() {
        // I2 GUARD for the #949 fix: a delivered outcome ALWAYS wins the liveness flag. The actor
        // released the ack (the produce IS durable) and only THEN flipped `actor_alive` false as it
        // exited; `wait` recv's the outcome FIRST, so it must return that ack — never a spurious
        // `ActorGone` that would tell a producer its durable record was lost.
        //
        // MUTATION CHECK: make `wait` consult the flag BEFORE recv'ing (return `ActorGone` on a false
        // flag without draining the channel) and this test fails — the buffered ack is dropped.
        let pool: ReplyPool = Arc::new(Mutex::new(Vec::new()));
        let channel = pool_take(&pool);
        channel
            .tx
            .send(ProduceOutcome::Appended(Offset::new(7)))
            .unwrap();
        let actor_alive = Arc::new(AtomicBool::new(false));
        let submission = ProduceSubmission::Pending {
            channel,
            pool: Arc::clone(&pool),
            spin: false,
            actor_alive,
        };
        assert!(
            matches!(submission.wait(), Ok(ProduceOutcome::Appended(o)) if o == Offset::new(7)),
            "a released ack must win the liveness flag (never lose a durable ack to ActorGone)"
        );
        // The channel recycled back to the pool after the successful wait (#475).
        assert_eq!(
            pool.lock().unwrap().len(),
            1,
            "the drained channel recycles"
        );
    }

    #[test]
    fn a_spinning_pending_wait_also_returns_actorgone_when_the_actor_exited() {
        // The SPIN tier (#1032) composes with the #949 liveness fix: its bounded busy-poll falls
        // back to the SAME sliced park, so a no-pre-ack-fsync connection whose actor died un-replied
        // gets the typed `ActorGone` too instead of wedging in the historical bare `recv` fallback
        // (the co-located `tx` keeps the channel open there exactly as on the sync tier).
        //
        // MUTATION CHECK: revert `recv_spin_then_park`'s fallback to `rx.recv()` and this test HANGS.
        let pool: ReplyPool = Arc::new(Mutex::new(Vec::new()));
        let channel = pool_take(&pool);
        let actor_alive = Arc::new(AtomicBool::new(false));
        let submission = ProduceSubmission::Pending {
            channel,
            pool: Arc::clone(&pool),
            spin: true,
            actor_alive,
        };
        assert!(
            matches!(submission.wait(), Err(ActorGone)),
            "a spin-tier pending produce whose actor exited must return ActorGone, not wedge"
        );
    }

    #[test]
    fn graceful_shutdown_drains_the_batch_and_checkpoints_with_no_acked_loss() {
        // Graceful shutdown (#195): a produce that was acked (durable) stays durable across a shutdown
        // drain, and the committed cursor is checkpointed so a reopen does not redeliver it. We
        // produce, fetch+ack it (so the cursor advances), shutdown (which flushes + checkpoints), then
        // reopen the SAME filesystem and assert the committed cursor persisted.
        let (handle, actor, _control) = rig();
        match handle.produce(append(b"keep")).unwrap() {
            ProduceOutcome::Appended(o) => assert_eq!(o.get(), 0),
            other => panic!("expected Appended, got {other:?}"),
        }
        // Lease then ack offset 0 so the committed cursor advances to 1. The default group is "".
        let token = handle
            .with(|e| match e.poll_now_in("") {
                Ok(Poll::Message(d)) => Some(d.token),
                _ => None,
            })
            .unwrap()
            .expect("offset 0 is deliverable");
        let acked = handle.with(move |e| e.ack_in("", &token)).unwrap();
        assert!(matches!(acked, crate::engine::AckResult::Acked));
        // Graceful shutdown drains the (empty) batch and checkpoints every group.
        handle.shutdown().unwrap().unwrap();
        drop(handle);
        let engine = actor.join().unwrap();
        // Reopen the SAME filesystem: the committed cursor (1) was checkpointed by the shutdown drain,
        // so the record is durable AND not redelivered.
        let fs = engine.into_filesystem();
        let reopened = Engine::open(fs, ManualClock::new(), config()).unwrap();
        assert_eq!(
            reopened.committed_offset().get(),
            1,
            "the shutdown drain checkpointed the committed cursor (no redelivery, no acked loss)"
        );
        assert_eq!(
            reopened.flushed_offset().get(),
            1,
            "the record stayed durable"
        );
    }

    #[test]
    fn a_produce_queued_after_shutdown_gets_a_closing_reply_never_wedges() {
        // #802: with concurrent senders on the one shared actor channel, the order
        // `[Produce, Shutdown, Produce]` is reachable, so a produce can land AFTER the `Shutdown` in the
        // SAME drained batch. The `Shutdown` arm used to `return` the instant it was reached, abandoning
        // that trailing produce with NO reply; because a produce submission keeps a co-located `tx`
        // alive, its receiver never sees a disconnect and the waiting producer wedges FOREVER. Assert the
        // trailing produce instead gets a closing reply (an explicit rejection, never a false ack).
        let (handle, actor, control) = rig();
        // Park the actor mid-fsync on a PRIMER so the following commands stage deterministically behind
        // it (they buffer in the channel while the actor is stalled, so ONE later drain sees them all).
        control.close_sync_gate();
        let primer = handle.produce_async(append(b"primer")).unwrap();
        control.wait_for_sync_gate_entered(1);
        // Stage, IN ORDER, all buffered while the actor is parked: a produce, then a raw non-blocking
        // `Shutdown` (the blocking `EngineHandle::shutdown` would deadlock here — it awaits its own
        // reply), then a TRAILING produce that lands after the `Shutdown`.
        let before_shutdown = handle.produce_async(append(b"before-shutdown")).unwrap();
        let (sd_tx, sd_rx) = sync_channel::<Result<(), EngineError>>(1);
        handle.tx.send(Command::Shutdown(sd_tx)).unwrap();
        let after_shutdown = handle.produce_async(append(b"after-shutdown")).unwrap();
        // Release the primer's fsync: the actor acks the primer, then drains
        // `[before-shutdown, Shutdown, after-shutdown]` as one batch.
        control.open_sync_gate();
        // The primer and the pre-shutdown produce are durable (both flushed at/before the shutdown drain).
        assert!(
            matches!(primer.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 0),
            "the primer appended at offset 0"
        );
        assert!(
            matches!(before_shutdown.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 1),
            "the pre-shutdown produce is flushed by the shutdown drain at offset 1"
        );
        // The shutdown itself completes its flush + checkpoint.
        sd_rx.recv().unwrap().unwrap();
        // THE FIX: the produce queued AFTER the shutdown is NOT abandoned — it gets an explicit closing
        // reply within a timeout instead of hanging forever. Without the fix `recv` blocks (the
        // co-located `tx` keeps the channel open), so the timeout fires and the test fails loudly rather
        // than wedging the suite.
        match after_shutdown
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the shutdown-queued produce must get a reply, not wedge forever (#802)")
        {
            ProduceOutcome::AtCapacity => {}
            other => panic!("expected a closing AtCapacity reply, got {other:?}"),
        }
        actor.join().unwrap();
    }

    #[test]
    fn the_in_flight_fdatasync_is_the_batching_window_and_merges_the_queued_burst() {
        // T2 (#1040), the self-clocking rewrite of the retired #454 gather test: the previous
        // fsync IS the batching window. A BURST primer pass ([p1, p2] — two parked waiters, so
        // pass end declines H1 and dispatches async) puts its covering barrier into the closed
        // gate; 32 produces queued as SEPARATE channel sends (defeating single-pass batching at
        // the submission side) are then appended by the FREE actor WHILE the barrier is in
        // flight and MERGE into the in-flight window. When the gate opens, the merged window is
        // covered by exactly ONE additional fdatasync — no wall-clock window, no latency floor,
        // unbounded amortization — and all 32 acks arrive in submission order (INV-4/#917).
        // Under sustained staged load the barrier count is exactly two: the primer window's and
        // the merged window's (the H2 linger never engages behind an outstanding flight).
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        // The inert historical window parameter (#1040): passed non-zero to pin that it is IGNORED.
        let (handle, actor) = spawn_actor_with_gather(engine, DEFAULT_CHANNEL_BOUND, 800_000);
        control.close_sync_gate();
        // Stage pass 1 = [p1, p2, hold]: while the hold keeps the pass open, the 32 sends land in
        // the channel, so the flight dispatches at pass end with the burst already queued behind
        // it — the actor then appends all 32 mid-flight (never parked on the gate itself).
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let p1 = handle.produce_async(append(b"primer-1")).unwrap();
        let p2 = handle.produce_async(append(b"primer-2")).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        // 32 separate sends, all queued while the burst pass is held open: they are drained and
        // appended WHILE barrier #1 is provably in flight, merging into ONE window. A third hold
        // rides BEHIND them in the same pass: once it reports in, all 32 are appended-and-parked
        // (FIFO within the drained pass) with the gate still closed — so the one merged window
        // is pinned BEFORE the gate opens, and the per-command completion polling can never
        // split the burst across chunked windows.
        let replies: Vec<_> = (0..32u64)
            .map(|i| {
                handle
                    .produce_async(append(format!("merged-{i}").as_bytes()))
                    .unwrap()
            })
            .collect();
        let (entered3, release3) = send_blocking_job(&handle);
        release2.send(()).unwrap();
        control.wait_for_sync_gate_entered(1);
        entered3.recv().unwrap();
        // Sampled while the primer window's barrier is still parked inside the gate and all 32
        // merged produces are provably appended behind it.
        let before = control.sync_count();
        release3.send(()).unwrap();
        control.open_sync_gate();
        for (name, rx, expected) in [("p1", p1, 0), ("p2", p2, 1)] {
            match rx.recv().unwrap() {
                ProduceOutcome::Appended(o) => assert_eq!(o.get(), expected, "{name}"),
                other => panic!("expected Appended {name}, got {other:?}"),
            }
        }
        let mut offsets = Vec::new();
        for reply in replies {
            match reply.recv().unwrap() {
                ProduceOutcome::Appended(o) => offsets.push(o.get()),
                other => panic!("expected Appended, got {other:?}"),
            }
        }
        assert_eq!(
            offsets,
            (2..=33).collect::<Vec<_>>(),
            "all 32 merged produces ack in submission order with contiguous offsets"
        );
        assert_eq!(
            control.sync_count() - before,
            1,
            "the whole merged window of 32 is covered by exactly ONE additional fdatasync"
        );
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn a_single_inflight_produce_never_pays_the_gather_window() {
        // The no-tax rule, now BY CONSTRUCTION (#1040): the retired #454 gather window parameter
        // is inert, and the self-clocking pipeline adds zero idle-start latency — a lone produce
        // dispatches its covering barrier immediately at pass end. With an 800 ms window value, a
        // gathered single produce could not ack in under 800 ms; the bound asserts the ack came
        // back far sooner (the deprecated knob is accepted and IGNORED).
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor_with_gather(engine, DEFAULT_CHANNEL_BOUND, 800_000);
        let before = control.sync_count();
        let started = std::time::Instant::now();
        let reply = handle.produce_async(append(b"solo")).unwrap();
        match reply.recv().unwrap() {
            ProduceOutcome::Appended(o) => assert_eq!(o.get(), 0),
            other => panic!("expected Appended, got {other:?}"),
        }
        assert!(
            started.elapsed() < std::time::Duration::from_millis(400),
            "a single produce must ack without waiting out the 800 ms gather window, took {:?}",
            started.elapsed()
        );
        assert_eq!(control.sync_count() - before, 1, "one produce, one fsync");
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn a_memory_backend_pipelined_batch_is_never_parked_by_the_commit_gather() {
        // #1026: the ephemeral memory backend's syncs are no-ops, so a produce ack waits on NO
        // covering fsync and the gather has nothing to amortize — a pipelined batch must ack
        // immediately, never parked to fill the window. The sync gate makes the pipelining
        // deterministic exactly as in the positive gather test above: a primer parks the actor on
        // its (no-op-at-the-bottom, but still gated) covering sync, TWO produces queue behind it,
        // and the gate opens — the next drain pass then provably holds >= 2 produces, the exact
        // shape that engages the gather on a real-barrier backend. With an 800 ms window, a
        // gathered pass could not ack in under 800 ms; the bound proves the gather never engaged.
        let (fs, control) = FaultFs::new(ironbus_storage::fs::EphemeralFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor_with_gather(engine, DEFAULT_CHANNEL_BOUND, 800_000);
        control.close_sync_gate();
        let primer = handle.produce_async(append(b"primer")).unwrap();
        control.wait_for_sync_gate_entered(1);
        let queued_a = handle.produce_async(append(b"queued-a")).unwrap();
        let queued_b = handle.produce_async(append(b"queued-b")).unwrap();
        control.open_sync_gate();
        match primer.recv().unwrap() {
            ProduceOutcome::Appended(o) => assert_eq!(o.get(), 0),
            other => panic!("expected Appended primer, got {other:?}"),
        }
        let started = std::time::Instant::now();
        for (reply, expected) in [(queued_a, 1), (queued_b, 2)] {
            match reply.recv().unwrap() {
                ProduceOutcome::Appended(o) => assert_eq!(o.get(), expected),
                other => panic!("expected Appended, got {other:?}"),
            }
        }
        assert!(
            started.elapsed() < std::time::Duration::from_millis(400),
            "a memory-backend pipelined batch must ack without the 800 ms gather park, took {:?}",
            started.elapsed()
        );
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn the_reply_wait_spin_is_gated_to_no_pre_ack_fsync_tiers() {
        // #1032: the spin-assisted reply wait engages ONLY where an ack waits on no pre-ack fsync
        // barrier (#1026). On durability `sync` over a real-barrier backend the submission must carry
        // `spin: false` — the wait parks exactly as before, so the I2 sync path's mechanics are
        // untouched BY CONSTRUCTION. On the ephemeral memory backend the same submission carries
        // `spin: true` (the reply is tens of microseconds away, so the bounded busy-poll pays off).
        let (handle, actor, _control) = rig();
        let submission = handle.produce_submit(append(b"sync-tier")).unwrap();
        assert!(
            matches!(submission, ProduceSubmission::Pending { spin: false, .. }),
            "durability sync on a real-barrier backend must NOT spin: {submission:?}"
        );
        assert!(matches!(
            submission.wait().unwrap(),
            ProduceOutcome::Appended(_)
        ));
        drop(handle);
        actor.join().unwrap();

        let (fs, _control) = FaultFs::new(ironbus_storage::fs::EphemeralFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let submission = handle.produce_submit(append(b"memory-tier")).unwrap();
        assert!(
            matches!(submission, ProduceSubmission::Pending { spin: true, .. }),
            "the memory backend's ack waits on no barrier, so the wait spins: {submission:?}"
        );
        assert!(matches!(
            submission.wait().unwrap(),
            ProduceOutcome::Appended(_)
        ));
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn spin_assisted_waits_preserve_fifo_ack_order_across_a_pipelined_window() {
        // #1032 x #917: the spin-assisted wait must yield outcomes in SUBMISSION order with the
        // position-correlated offsets, through BOTH of its paths — the spin-exhausted fallback park (a
        // reply slower than the window) AND the busy-poll hit (a reply already sent). The sync gate
        // stalls the actor's covering commit well past the 100us spin window, so the FIRST wait
        // provably exhausts its spin and parks (the fallback path); by the time it returns, the whole
        // batch's replies are sent, so the remaining waits are poll hits. Offsets must be 0,1,2 in
        // submission order — the #917 position correlation.
        let (fs, control) = FaultFs::new(ironbus_storage::fs::EphemeralFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        control.close_sync_gate();
        let first = handle.produce_submit(append(b"first")).unwrap();
        control.wait_for_sync_gate_entered(1);
        let second = handle.produce_submit(append(b"second")).unwrap();
        let third = handle.produce_submit(append(b"third")).unwrap();
        // Open the gate from a helper thread AFTER the first wait has provably out-spun its window:
        // the gate stays closed for 10ms (100x the spin window), so the first wait's busy-poll
        // exhausts and it parks in the blocking recv before the reply is released.
        let opener = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            control.open_sync_gate();
        });
        for (submission, expected) in [(first, 0u64), (second, 1), (third, 2)] {
            assert!(
                matches!(submission, ProduceSubmission::Pending { spin: true, .. }),
                "every memory-tier submission spins: {submission:?}"
            );
            match submission.wait().unwrap() {
                ProduceOutcome::Appended(o) => assert_eq!(
                    o.get(),
                    expected,
                    "acks arrive in submission order with position-correlated offsets (#917)"
                ),
                other => panic!("expected Appended({expected}), got {other:?}"),
            }
        }
        opener.join().unwrap();
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn a_relaxed_durability_pipelined_batch_is_never_parked_by_the_commit_gather() {
        // #1026: under `interval` durability an ack is released on the page-cache write — the
        // fsync (when the window is due) bounds loss, it is not what the ack waits to amortize —
        // so the gather must not park produces. The byte trigger is set to 1 so EVERY batch's
        // interval window is due and force-syncs (deterministically parking in the sync gate, the
        // same primer choreography as the positive gather test), which is the WORST case for the
        // old behavior: a real-barrier fs, real fsyncs each batch, yet the level says acks are
        // page-cache acks. With an 800 ms window, a gathered pass could not ack in under 800 ms.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let cfg = EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            durability_level: crate::engine::DurabilityLevel::Interval,
            flush_max_bytes: 1,
            ..config()
        };
        let engine = Engine::open(fs, ManualClock::new(), cfg).unwrap();
        let (handle, actor) = spawn_actor_with_gather(engine, DEFAULT_CHANNEL_BOUND, 800_000);
        control.close_sync_gate();
        let primer = handle.produce_async(append(b"primer")).unwrap();
        control.wait_for_sync_gate_entered(1);
        let queued_a = handle.produce_async(append(b"queued-a")).unwrap();
        let queued_b = handle.produce_async(append(b"queued-b")).unwrap();
        control.open_sync_gate();
        match primer.recv().unwrap() {
            ProduceOutcome::Appended(o) => assert_eq!(o.get(), 0),
            other => panic!("expected Appended primer, got {other:?}"),
        }
        let started = std::time::Instant::now();
        for (reply, expected) in [(queued_a, 1), (queued_b, 2)] {
            match reply.recv().unwrap() {
                ProduceOutcome::Appended(o) => assert_eq!(o.get(), expected),
                other => panic!("expected Appended, got {other:?}"),
            }
        }
        assert!(
            started.elapsed() < std::time::Duration::from_millis(400),
            "an interval-durability pipelined batch must ack without the 800 ms gather park, took {:?}",
            started.elapsed()
        );
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn a_gather_enabled_concurrent_batch_acks_only_after_one_covering_fsync() {
        // The SHIPPED-DEFAULT guarantee (#472): turning the gather ON (the CLI now defaults to a
        // small non-zero window) must NOT weaken I2 (ack-implies-durable) or split a concurrent
        // batch across fsyncs. The sync gate makes it deterministic and clock-independent (no
        // dependence on the real window length, so it is not racy): close the gate so the actor
        // parks on the FIRST covering fsync, queue several more produces behind it, then assert (a)
        // no ack has been released while the fsync is still parked (I2: an ack never precedes its
        // covering fsync), and (b) once the gate opens the whole queued batch is covered by exactly
        // ONE additional fsync. Run with a non-trivial gather window to exercise the on path.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor_with_gather(engine, DEFAULT_CHANNEL_BOUND, 50_000);
        control.close_sync_gate();
        // The primer parks the actor inside its covering fsync (the gate holds it there).
        let primer = handle.produce_async(append(b"primer")).unwrap();
        control.wait_for_sync_gate_entered(1);
        // Queue a concurrent batch behind the parked fsync; these all land in ONE drain pass (>= 2
        // produces, so the gather engages) and must share a single covering fsync.
        let queued: Vec<_> = (0..4)
            .map(|i| {
                handle
                    .produce_async(append(format!("queued-{i}").as_bytes()))
                    .unwrap()
            })
            .collect();
        let before = control.sync_count();
        // I2 PROOF: while the covering fsync is still parked, NOT ONE reply may have been released.
        for reply in &queued {
            assert!(
                matches!(reply.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
                "a queued produce was acked BEFORE its covering fsync returned (I2 violated)"
            );
        }
        control.open_sync_gate();
        // The primer acks at offset 0; the gate is open so its parked fsync now returns.
        match primer.recv().unwrap() {
            ProduceOutcome::Appended(o) => assert_eq!(o.get(), 0),
            other => panic!("expected Appended primer, got {other:?}"),
        }
        let mut offsets = Vec::new();
        for reply in queued {
            match reply.recv().unwrap() {
                ProduceOutcome::Appended(o) => offsets.push(o.get()),
                other => panic!("expected Appended, got {other:?}"),
            }
        }
        assert_eq!(offsets, vec![1, 2, 3, 4], "all four appended in send order");
        // ONE-FSYNC PROOF: the four queued produces are covered by exactly ONE fsync (the gather
        // collapses the concurrent batch), not one per produce.
        assert_eq!(
            control.sync_count() - before,
            1,
            "the concurrent batch of four is covered by exactly ONE fsync"
        );
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn a_single_produce_still_issues_exactly_one_sync() {
        // The lone-produce path is a one-message group commit: exactly one fsync, mirroring the old
        // per-produce behavior, so the durable order and sync accounting are unchanged for N=1.
        let (handle, actor, control) = rig();
        let before = control.sync_count();
        handle.produce(append(b"solo")).unwrap();
        assert_eq!(control.sync_count() - before, 1, "one produce, one fsync");
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_duplicate_msg_id_returns_the_original_offset_and_appends_no_second_record() {
        // The headline #33 property over the REAL actor: a fresh dedup produce appends and acks
        // PubAck(0); the SAME (producer, msg_id) again returns the ORIGINAL offset via
        // AppendedDuplicate and appends NO second record (the durable head does not move).
        let (handle, actor, _control) = rig();
        let first = handle
            .produce(append_dedup(b"v1", b"p1", 1, b"idem"))
            .unwrap();
        assert!(
            matches!(first, ProduceOutcome::Appended(o) if o.get() == 0),
            "fresh produce appends at offset 0: {first:?}"
        );
        let head_after_first = handle.with(|e| e.flushed_offset().get()).unwrap();
        assert_eq!(head_after_first, 1, "one record durable");
        // A duplicate (same producer + msg_id, payload irrelevant): the original offset, no append.
        let dup = handle
            .produce(append_dedup(b"v2-ignored", b"p1", 1, b"idem"))
            .unwrap();
        assert!(
            matches!(dup, ProduceOutcome::AppendedDuplicate(o) if o.get() == 0),
            "duplicate returns the ORIGINAL offset 0: {dup:?}"
        );
        let head_after_dup = handle.with(|e| e.flushed_offset().get()).unwrap();
        assert_eq!(
            head_after_dup, 1,
            "the durable head did NOT advance on a dedup hit"
        );
        assert_eq!(
            handle.with(|e| e.dedup_hits()).unwrap(),
            1,
            "one dedup hit counted"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_stale_epoch_produce_is_fenced_over_the_actor() {
        // Epoch fencing over the real actor: establish epoch 5, then a produce at the older epoch 4 is
        // fenced (nothing appended) while a produce at epoch 5 still works.
        let (handle, actor, _control) = rig();
        handle.produce(append_dedup(b"a", b"p1", 5, b"m1")).unwrap();
        let fenced = handle.produce(append_dedup(b"b", b"p1", 4, b"m2")).unwrap();
        assert!(
            matches!(fenced, ProduceOutcome::Fenced),
            "stale epoch is fenced: {fenced:?}"
        );
        assert_eq!(
            handle.with(|e| e.flushed_offset().get()).unwrap(),
            1,
            "the fenced produce appended nothing (head stays at the one accepted record)"
        );
        let _ = recover(handle, actor);
    }

    // ---- The #11 wire QoS-0 fire-and-forget tier over the REAL append actor (#402) ----

    /// The actor test config with the fire-and-forget token bucket enabled at a TINY message rate, so
    /// the burst ceiling is small and a test can deterministically exhaust it. `msg_rate` of 10 with a
    /// 100 ms refill gives a burst ceiling of `10 * 100 / 1000 = 1` message, so the FIRST
    /// fire-and-forget produce drains the bucket and the SECOND (at the same `ManualClock` instant) is
    /// dropped. Byte dimension off (the message dimension binds, for a crisp count).
    fn config_faf() -> EngineConfig {
        EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            fire_and_forget_msg_rate: 10,
            fire_and_forget_byte_rate: 0,
            fire_and_forget_refill_ms: 100,
            ..config()
        }
    }

    #[allow(clippy::type_complexity)]
    fn rig_faf() -> (
        EngineHandle<FaultFs<InMemoryFs>, ManualClock>,
        std::thread::JoinHandle<Engine<FaultFs<InMemoryFs>, ManualClock>>,
        FaultControl,
    ) {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config_faf()).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        (handle, actor, control)
    }

    #[test]
    fn a_fire_and_forget_produce_under_an_exhausted_bucket_is_dropped_with_no_ack_and_no_crash() {
        // THE TEETH for the QoS-0 drop-under-bucket-no-ack (#11, #402): with the fire-and-forget
        // bucket exhausted, a fire-and-forget produce is DROPPED (not appended, no ack), counted in
        // ironbus_fire_and_forget_shed_total, while the broker keeps serving (no crash). The bucket
        // governs ONLY this tier.
        let (handle, actor, _control) = rig_faf();
        // The bucket starts full at a ceiling of 1 (10 msg/s * 100 ms). The first fire-and-forget
        // produce is ADMITTED and appended durably, but gets NO PubAck.
        match handle.produce(append_faf(b"q0")).unwrap() {
            ProduceOutcome::FireAndForgetAppended(o) => assert_eq!(o.get(), 0),
            other => panic!("first QoS-0 produce should be appended-no-ack, got {other:?}"),
        }
        // The bucket is now empty (ManualClock has not advanced, so no refill). The next
        // fire-and-forget produce is DROPPED (no append, no ack).
        match handle.produce(append_faf(b"q1")).unwrap() {
            ProduceOutcome::FireAndForgetDropped => {}
            other => panic!("the over-bucket QoS-0 produce should be dropped, got {other:?}"),
        }
        // NO DATA LOSS for the at-least-once path: a normal produce is NEVER dropped, even with the
        // fire-and-forget bucket exhausted (the bucket governs only the QoS-0 tier).
        match handle.produce(append(b"alo")).unwrap() {
            ProduceOutcome::Appended(o) => {
                assert_eq!(o.get(), 1, "the at-least-once produce appended");
            }
            other => panic!("an at-least-once produce must never be dropped, got {other:?}"),
        }
        let (head, faf_shed) = handle
            .with(|e| {
                (
                    e.flushed_offset().get(),
                    e.backpressure_snapshot().fire_and_forget_shed,
                )
            })
            .unwrap();
        assert_eq!(
            head, 2,
            "exactly the admitted QoS-0 produce (offset 0) and the at-least-once produce (offset 1) \
             are durable; the dropped QoS-0 produce was never appended"
        );
        assert_eq!(
            faf_shed, 1,
            "exactly one fire-and-forget drop counted (never silent)"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_fire_and_forget_produce_with_the_bucket_disabled_is_appended_but_never_acked() {
        // The safe default: with the fire-and-forget bucket DISABLED (the default rate of 0), a QoS-0
        // produce is always APPENDED durably but still gets NO PubAck (the producer fired and forgot),
        // and it is never dropped. A normal produce on the same actor still gets its PubAck.
        let (handle, actor, _control) = rig();
        match handle.produce(append_faf(b"q")).unwrap() {
            ProduceOutcome::FireAndForgetAppended(o) => assert_eq!(o.get(), 0),
            other => panic!("a QoS-0 produce should be appended-no-ack, got {other:?}"),
        }
        // The at-least-once produce on the same actor is unchanged: a normal Appended (PubAck path).
        match handle.produce(append(b"n")).unwrap() {
            ProduceOutcome::Appended(o) => assert_eq!(o.get(), 1),
            other => panic!("a normal produce should be Appended, got {other:?}"),
        }
        assert_eq!(
            handle.with(|e| e.flushed_offset().get()).unwrap(),
            2,
            "both records are durable (the QoS-0 one too); only the ack differs"
        );
        assert_eq!(
            handle
                .with(|e| e.backpressure_snapshot().fire_and_forget_shed)
                .unwrap(),
            0,
            "a disabled bucket never drops a QoS-0 produce"
        );
        let _ = recover(handle, actor);
    }

    // ---- The #475 pooled (recycled) per-publish reply channel ----

    #[test]
    fn two_in_flight_pooled_submissions_each_get_their_own_outcome_in_order() {
        // THE TEETH for #475: the per-publish reply channel is now a RECYCLED pool channel, so this
        // proves the reuse never lets two in-flight publishes cross-deliver and never reorders their
        // outcomes. Two produces are submitted WITHOUT awaiting (the pipelined window, #450): each
        // holds its OWN pooled channel. We stall the actor on a gated primer's fsync so BOTH land in
        // the SAME drained batch (one group commit), then await them in SUBMISSION order. Each
        // submission yields ITS OWN offset (0-based: primer=0, then 1 and 2 contiguously), proving the
        // pooled channels are distinct per in-flight publish — no cross-delivery, FIFO preserved.
        let (handle, actor, control) = rig();
        control.close_sync_gate();
        let primer = handle.produce_async(append(b"primer")).unwrap();
        control.wait_for_sync_gate_entered(1);
        // Both submissions are in flight at once, each on its own recycled pool channel.
        let s1 = handle.produce_submit(append(b"first")).unwrap();
        let s2 = handle.produce_submit(append(b"second")).unwrap();
        control.open_sync_gate();
        match primer.recv().unwrap() {
            ProduceOutcome::Appended(o) => assert_eq!(o.get(), 0),
            other => panic!("expected the primer Appended at 0, got {other:?}"),
        }
        // Awaited in submission order; each gets its OWN outcome (no cross-delivery).
        match s1.wait().unwrap() {
            ProduceOutcome::Appended(o) => {
                assert_eq!(o.get(), 1, "the first submission's own offset");
            }
            other => panic!("expected Appended(1) for s1, got {other:?}"),
        }
        match s2.wait().unwrap() {
            ProduceOutcome::Appended(o) => {
                assert_eq!(o.get(), 2, "the second submission's own offset");
            }
            other => panic!("expected Appended(2) for s2, got {other:?}"),
        }
        let _ = recover(handle, actor);
    }

    #[test]
    fn a_pooled_channel_is_recycled_and_still_delivers_correctly_across_rounds() {
        // The pool RECYCLES: a channel returns to the pool on `wait`, so the next publish reuses it
        // instead of allocating. Over many sequential submit/await rounds the reused channel must keep
        // delivering exactly the right outcome (a stale value from a prior round would corrupt this).
        // Each round's offset is contiguous and matches the submission, proving the recycled channel is
        // drained and correct every time. (Sequential rounds keep the SAME one channel hot in the pool,
        // which is exactly the reuse the issue removes the per-publish alloc for.)
        let (handle, actor, _control) = rig();
        for i in 0..16u64 {
            // One submit + one await per round: the channel is taken from the pool, used, and returned,
            // so round i+1 reuses round i's channel.
            let s = handle
                .produce_submit(append(format!("r{i}").as_bytes()))
                .unwrap();
            match s.wait().unwrap() {
                ProduceOutcome::Appended(o) => assert_eq!(
                    o.get(),
                    i,
                    "round {i} reused a pooled channel and still got its own offset"
                ),
                other => panic!("round {i} expected Appended({i}), got {other:?}"),
            }
        }
        assert_eq!(
            handle.with(|e| e.flushed_offset().get()).unwrap(),
            16,
            "all 16 recycled-channel produces are durable and contiguous"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn pooled_outcomes_do_not_cross_when_an_immediate_reply_interleaves_parked_ones() {
        // THE REORDERING TEETH for #475: the actor sends a FENCE (an immediate reply) the instant it
        // sees it, but sends the surrounding APPENDED outcomes only later, from `flush_pending` after
        // the covering fsync. So within ONE batch the actor's send ORDER is NOT the submission order:
        // it sends fence FIRST, then the two appended. With the OLD per-publish channel this was
        // invisible (each publish had its own receiver). The pooled design must preserve that: each
        // in-flight submission still holds its OWN channel, so awaiting them in SUBMISSION order yields
        // append, fence, append correctly — a single shared FIFO channel would mis-deliver the fence
        // where the first append belongs. We force all three into one batch behind a gated primer.
        let (handle, actor, control) = rig();
        // Establish epoch 5 so a later epoch-4 produce is a deterministic stale-epoch FENCE.
        handle
            .produce(append_dedup(b"e0", b"p1", 5, b"m0"))
            .unwrap();
        control.close_sync_gate();
        let primer = handle.produce_async(append(b"primer")).unwrap();
        control.wait_for_sync_gate_entered(1);
        // The window, all queued behind the gated primer so they drain as ONE batch:
        //   s_a: a fresh append at epoch 5 -> PARKS, replies Appended after the fsync.
        //   s_fence: an epoch-4 produce -> FENCED, replied IMMEDIATELY (out of submission order).
        //   s_b: another fresh append at epoch 5 -> PARKS, replies Appended after the fsync.
        let s_a = handle
            .produce_submit(append_dedup(b"a", b"p1", 5, b"m_a"))
            .unwrap();
        let s_fence = handle
            .produce_submit(append_dedup(b"b", b"p1", 4, b"m_b"))
            .unwrap();
        let s_b = handle
            .produce_submit(append_dedup(b"c", b"p1", 5, b"m_c"))
            .unwrap();
        control.open_sync_gate();
        assert!(matches!(
            primer.recv().unwrap(),
            ProduceOutcome::Appended(_)
        ));
        // Awaited in SUBMISSION order; each gets its OWN, correct outcome despite the actor's send order
        // (fence first, then the two appends) — the pooled channels never cross-deliver.
        match s_a.wait().unwrap() {
            ProduceOutcome::Appended(o) => {
                assert_eq!(
                    o.get(),
                    2,
                    "the first window append's own offset (after e0=0, primer=1)"
                );
            }
            other => panic!("expected Appended for s_a, got {other:?}"),
        }
        assert!(
            matches!(s_fence.wait().unwrap(), ProduceOutcome::Fenced),
            "the fenced submission gets its OWN fence, not an append meant for a neighbor"
        );
        match s_b.wait().unwrap() {
            ProduceOutcome::Appended(o) => {
                assert_eq!(o.get(), 3, "the second window append's own offset");
            }
            other => panic!("expected Appended for s_b, got {other:?}"),
        }
        let _ = recover(handle, actor);
    }

    // ---- The pipelined sync tier (#1040): T1-T14 + the prep-review mutation gaps ----
    //
    // Per the #823 lesson, every concurrency claim below is OVERLAP-OBSERVING: interleavings are
    // asserted via the fault-fs gates (`close_sync_gate` holds a barrier provably in flight;
    // `arm_sync_rendezvous` proves two barriers were simultaneously inside their fsync) and via
    // LIVE-image probes of the shared `InMemoryFs`, never via sleeps or outcome-only checks.

    /// Like [`rig`] over `cfg`, but also returns a PROBE alias of the underlying [`InMemoryFs`]
    /// (the clones share one backing store), so a test can inspect the LIVE file image while the
    /// actor still owns the engine, or simulate a power cut mid-flight.
    #[allow(clippy::type_complexity)]
    fn rig_probed_with(
        cfg: EngineConfig,
    ) -> (
        EngineHandle<FaultFs<InMemoryFs>, ManualClock>,
        std::thread::JoinHandle<Engine<FaultFs<InMemoryFs>, ManualClock>>,
        FaultControl,
        InMemoryFs,
    ) {
        let mem = InMemoryFs::new();
        let probe = mem.clone();
        let (fs, control) = FaultFs::new(mem);
        let engine = Engine::open(fs, ManualClock::new(), cfg).unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        (handle, actor, control, probe)
    }

    /// The LIVE (unsynced-included) images of every segment file, concatenated in name order —
    /// what a reader of the page cache would see right now, via the probe alias.
    fn live_segment_bytes(probe: &InMemoryFs) -> Vec<u8> {
        use ironbus_storage::io::RandomAccessFile;
        let mut names: Vec<String> = probe
            .list()
            .unwrap()
            .into_iter()
            .filter(|n| is_segment_file(n))
            .collect();
        names.sort();
        let mut all = Vec::new();
        for name in &names {
            let Ok(file) = probe.open(name) else { continue };
            let len = usize::try_from(file.len().unwrap()).unwrap();
            let mut buf = vec![0u8; len];
            file.read_exact_at(&mut buf, 0).unwrap();
            all.extend_from_slice(&buf);
        }
        all
    }

    /// Whether `haystack` contains `needle` as a byte substring.
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Whether `name` is a segment file (`seg-<16 hex>.log`). Exact-case by design: the writer
    /// emits exactly this lowercase form (`naming::segment_file_name`), so a case-insensitive
    /// match would be wrong (a foreign `SEG-...LOG` file is NOT a segment).
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn is_segment_file(name: &str) -> bool {
        name.starts_with("seg-") && name.ends_with(".log")
    }

    /// Bounded-polls the probe's live segment image for `needle` (a progress wait on the actor
    /// thread, NOT an interleaving assumption — the interleaving is pinned by a held gate).
    fn wait_for_live_bytes(probe: &InMemoryFs, needle: &[u8]) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if contains_bytes(&live_segment_bytes(probe), needle) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        false
    }

    /// Sends a raw `Command::Run` job that signals `entered` and then BLOCKS until `release` —
    /// the deterministic pass-stager: while the job blocks, everything the test queues lands in
    /// the channel and is drained TOGETHER in a later pass (or, queued during the SAME pass's
    /// drain, in the very next one), with no sleeps and no races.
    fn send_blocking_job(
        handle: &EngineHandle<FaultFs<InMemoryFs>, ManualClock>,
    ) -> (Receiver<()>, SyncSender<()>) {
        let (entered_tx, entered_rx) = sync_channel::<()>(1);
        let (release_tx, release_rx) = sync_channel::<()>(1);
        handle
            .tx
            .send(Command::Run(Box::new(move |_e| {
                let _ = entered_tx.send(());
                let _ = release_rx.recv();
            })))
            .unwrap();
        (entered_rx, release_tx)
    }

    /// Stages ONE pass holding exactly the two produces (a BURST pass, two parked waiters), so
    /// pass end DECLINES the H1 solo-inline heuristic and DISPATCHES the covering barrier to the
    /// flusher — the deterministic way to put a real async flight into a (typically closed) sync
    /// gate while the ACTOR stays free. A SOLO staged produce would instead run the legacy
    /// inline barrier on the actor itself (H1) and wedge the actor, not the flusher, in the gate.
    fn stage_burst_pass(
        handle: &EngineHandle<FaultFs<InMemoryFs>, ManualClock>,
        a: OwnedAppend,
        b: OwnedAppend,
    ) -> (Receiver<ProduceOutcome>, Receiver<ProduceOutcome>) {
        let (entered, release) = send_blocking_job(handle);
        entered.recv().unwrap();
        let ra = handle.produce_async(a).unwrap();
        let rb = handle.produce_async(b).unwrap();
        release.send(()).unwrap();
        (ra, rb)
    }

    #[test]
    fn t1_a_produce_appends_into_the_live_segment_while_the_first_barrier_is_in_flight() {
        // T1, the HEADLINE overlap observation (#1040): while produce A's covering fdatasync is
        // provably INSIDE the held sync gate, produce B must APPEND — its frame bytes appear in
        // the active segment's LIVE image (B is larger than the writer's 256 KiB spill bound, so
        // its append flushes to the file immediately) while NEITHER reply has been released
        // (INV-1). A serialized implementation (the legacy loop) is parked inside the fsync and
        // cannot pass the mid-gate byte observation. Opening the gate releases A then B, and B's
        // merged window costs exactly ONE additional fdatasync.
        let (handle, actor, control, probe) = rig_probed_with(config());
        control.close_sync_gate();
        // Stage deterministically: while a blocking job holds a pass open, queue [A, hold2]; then,
        // while hold2 blocks (in the SAME pass that appended A), queue B in the channel. Releasing
        // hold2 ends A's pass — its covering barrier dispatches into the closed gate — and the
        // actor's next `try_recv` finds B ALREADY queued, so B is appended WHILE the barrier is in
        // flight (deterministic: never a race against the actor's idle wait, which only blocks on
        // the completion channel when the command channel is empty).
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let a = handle.produce_async(append(b"t1-first-flight")).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        // B: bigger than PENDING_SPILL_BYTES (256 KiB) so the append itself spills the frame into
        // the file — the append-during-flight observation. A distinctive marker rides at the end.
        let mut big = vec![0x42_u8; 300 * 1024];
        big.extend_from_slice(b"T1-LIVE-DURING-FLIGHT");
        let b = handle.produce_async(append(&big)).unwrap();
        release2.send(()).unwrap();
        // The flusher is now provably INSIDE fdatasync #1 (entered the closed gate).
        control.wait_for_sync_gate_entered(1);
        assert!(
            wait_for_live_bytes(&probe, b"T1-LIVE-DURING-FLIGHT"),
            "B's frame bytes must appear in the LIVE segment image WHILE barrier #1 holds the \
             gate — the append-during-flight overlap a serialized actor cannot produce"
        );
        // INV-1: no reply precedes its covering barrier — both still parked while the gate holds.
        assert!(
            a.try_recv().is_err(),
            "A must not ack before its fdatasync returned (I2)"
        );
        assert!(
            b.try_recv().is_err(),
            "B must not ack before ITS covering fdatasync (it merged into the NEXT window)"
        );
        let before = control.sync_count();
        control.open_sync_gate();
        // Acks arrive in order: A (covered by barrier #1), then B (covered by barrier #2).
        assert!(
            matches!(a.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 0),
            "A acks first, at offset 0"
        );
        assert!(
            matches!(b.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 1),
            "B acks second, at offset 1"
        );
        assert_eq!(
            control.sync_count() - before,
            1,
            "B's window is exactly ONE more fdatasync (two total for two overlapped produces)"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn t3a_a_power_cut_with_nothing_acked_recovers_with_any_loss_legal() {
        // T3(a)+(c) (#1040): gate held, A's barrier in flight, B appended-during-flight, NOTHING
        // acked — a power cut may lose any subset (no ack was released, so I2 is vacuous). The
        // assertion is the recovery invariant only: the reverted image opens cleanly and the
        // recovered heads are consistent. The wedged actor/flusher are leaked deliberately (the
        // cut happened; they no longer own the disk).
        let (handle, actor, control, probe) = rig_probed_with(config());
        control.close_sync_gate();
        // The T1 stager: A's pass is held open while B is queued, so B is appended (and, being
        // over the spill bound, lands in the live image) WHILE A's barrier is parked in the gate.
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let a = handle.produce_async(append(b"t3a-inflight")).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        let mut big = vec![0x51_u8; 300 * 1024];
        big.extend_from_slice(b"T3A-DIRTY-DURING-FLIGHT");
        let b = handle.produce_async(append(&big)).unwrap();
        release2.send(()).unwrap();
        control.wait_for_sync_gate_entered(1);
        // B provably appended (in the live image) while A's barrier is still parked: the cut
        // below lands with one staged-and-syncing record and one dirty record, nothing acked.
        assert!(wait_for_live_bytes(&probe, b"T3A-DIRTY-DURING-FLIGHT"));
        assert!(
            a.try_recv().is_err() && b.try_recv().is_err(),
            "nothing acked"
        );
        probe.simulate_power_loss();
        // Recover from the reverted image: any loss is legal; the open itself and head coherence
        // are the invariants.
        let reopened = Engine::open(probe.clone(), ManualClock::new(), config()).unwrap();
        assert_eq!(
            reopened.flushed_offset(),
            reopened.durable_offset(),
            "recovery leaves visible == durable"
        );
        assert!(
            reopened.flushed_offset().get() <= 2,
            "at most the two written records survive"
        );
        // Leak the wedged rig: the gate is never opened (the modelled machine lost power).
        std::mem::forget((handle, actor, control, a, b));
    }

    #[test]
    fn t3b_an_acked_produce_survives_a_power_cut_taken_mid_next_flight() {
        // T3(b) (#1040): A was ACKED (its covering fdatasync returned), then a cut lands while a
        // LATER window's barrier is in flight (a BURST window, so the barrier really is a
        // flusher flight, not H1's inline barrier). Acked-implies-durable must hold across the
        // cut: A's record survives recovery.
        let (handle, actor, control, probe) = rig_probed_with(config());
        assert!(
            matches!(handle.produce(append(b"t3b-acked")).unwrap(), ProduceOutcome::Appended(o) if o.get() == 0)
        );
        control.close_sync_gate();
        let (c1, c2) = stage_burst_pass(
            &handle,
            append(b"t3b-unacked-inflight-1"),
            append(b"t3b-unacked-inflight-2"),
        );
        control.wait_for_sync_gate_entered(1);
        assert!(
            c1.try_recv().is_err() && c2.try_recv().is_err(),
            "the later window is mid-flight, unacked"
        );
        probe.simulate_power_loss();
        let reopened = Engine::open(probe.clone(), ManualClock::new(), config()).unwrap();
        assert!(
            reopened.flushed_offset().get() >= 1,
            "the ACKED record must survive the cut (acked implies durable, I2)"
        );
        std::mem::forget((handle, actor, control, c1, c2));
    }

    #[test]
    fn t3d_a_roll_spanning_power_cut_with_reordered_tail_recovers_for_every_seed() {
        // T3(d) (#1040): tiny segments force rolls, the cut REORDERS/DROPS the active segment's
        // unsynced tail (the page-cache model, #164), swept across seeds. Nothing acked after the
        // gate closes, so any tail loss is legal; recovery must open cleanly at every seed.
        for seed in 0..8u64 {
            let cfg = EngineConfig {
                consume_longpoll_ms: 0,
                storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
                log: LogConfig {
                    max_segment_bytes: 192,
                    ..LogConfig::default()
                },
                ..config()
            };
            let (handle, actor, control, probe) = rig_probed_with(cfg.clone());
            // A few acked records first (rolling across segments).
            for i in 0..4u64 {
                assert!(matches!(
                    handle
                        .produce(append(&[0x60 + u8::try_from(i).unwrap(); 40]))
                        .unwrap(),
                    ProduceOutcome::Appended(_)
                ));
            }
            // Now a gated flight plus dirty appends behind it.
            control.close_sync_gate();
            let r1 = handle.produce_async(append(&[0xa1; 40])).unwrap();
            control.wait_for_sync_gate_entered(1);
            let r2 = handle.produce_async(append(&[0xa2; 40])).unwrap();
            // The ACTIVE segment is the highest-id one; reorder ITS unsynced tail.
            let active = probe
                .list()
                .unwrap()
                .into_iter()
                .filter(|n| is_segment_file(n))
                .max()
                .unwrap();
            let _kept = probe.simulate_power_loss_reorder(&active, seed);
            let reopened = Engine::open(probe.clone(), ManualClock::new(), cfg).unwrap();
            assert!(
                reopened.flushed_offset().get() >= 4,
                "seed {seed}: every ACKED record survives"
            );
            assert_eq!(
                reopened.flushed_offset(),
                reopened.durable_offset(),
                "seed {seed}: visible == durable after recovery"
            );
            std::mem::forget((handle, actor, control, r1, r2));
        }
    }

    #[test]
    fn t4_a_failed_flusher_barrier_freezes_forever_and_fatal_fans_every_parked_batch() {
        // T4, fail-closed fsyncgate (#1040, INV-7): batch N (a BURST window [a1, a2], so its
        // covering barrier is a real flusher flight — a SOLO produce would run H1's inline
        // barrier and surface the legacy `WriterFrozen` from `Log::sync` instead of the
        // flusher's raw error) is parked in the gate, batch N+1 queues behind it, then the
        // barrier FAILS. Batch N's first at-least-once waiter gets the REAL injected error, its
        // second member `WriterFrozen` in the SAME fan-out sweep; batch N+1 surfaces
        // `WriterFrozen` too (it can never become durable behind a frozen writer); zero acks
        // ever; `sync_count` freezes (no re-arm, a failed barrier is never retried); health
        // flips; clearing the fault does not resurrect.
        let (handle, actor, control) = rig();
        control.close_sync_gate();
        let (a1, a2) = stage_burst_pass(
            &handle,
            append(b"t4-batch-n-first"),
            append(b"t4-batch-n-second"),
        );
        control.wait_for_sync_gate_entered(1);
        let b = handle.produce_async(append(b"t4-batch-n1-first")).unwrap();
        let c = handle.produce_async(append(b"t4-batch-n1-second")).unwrap();
        // Arm the failure while the barrier is parked (the fail check runs after the gate), then
        // release the gate: the in-flight fdatasync returns the injected error.
        control.set_fail_sync(true);
        control.open_sync_gate();
        // A1 carries the REAL error (the first at-least-once member of the fan-out), A2 the
        // equivalent `WriterFrozen` from the same sweep...
        match a1.recv().unwrap() {
            ProduceOutcome::Fatal(EngineError::Storage(
                ironbus_storage::segment::StorageError::Io(_),
            )) => {}
            other => panic!("batch N must carry the real injected IO error, got {other:?}"),
        }
        // ...and batch N+1 is fataled as WriterFrozen behind the frozen writer.
        for (name, rx) in [("a2", a2), ("b", b), ("c", c)] {
            match rx.recv().unwrap() {
                ProduceOutcome::Fatal(EngineError::Storage(
                    ironbus_storage::segment::StorageError::WriterFrozen,
                )) => {}
                other => panic!("{name} must be fataled WriterFrozen, got {other:?}"),
            }
        }
        let frozen_syncs = control.sync_count();
        // A later produce surfaces the frozen writer; no barrier is ever dispatched again.
        assert!(
            matches!(
                handle.produce(append(b"t4-after")).unwrap(),
                ProduceOutcome::Fatal(_)
            ),
            "an append on the frozen writer is fatal"
        );
        let _ = handle.with(|_| ());
        assert!(
            !handle.writer_appears_healthy(),
            "the freeze is published for /readyz"
        );
        // Clearing the injected fault must NOT resurrect the writer (INV-7: frozen forever).
        control.set_fail_sync(false);
        assert!(
            matches!(
                handle.produce(append(b"t4-still-frozen")).unwrap(),
                ProduceOutcome::Fatal(_)
            ),
            "clearing the fault does not resurrect the frozen writer"
        );
        assert_eq!(
            control.sync_count(),
            frozen_syncs,
            "sync_count froze: no barrier was ever re-armed after the failure"
        );
        drop(handle);
        let _ = actor.join();
    }

    #[test]
    fn t5a_a_synchronous_seal_freeze_with_no_flight_fatals_the_parked_waiter_promptly() {
        // T5(a), the frozen-writer no-wedge regression (#1040, L6): a parked waiter exists, then a
        // ROLL-SEAL failure freezes the writer SYNCHRONOUSLY (no barrier in flight yet — the
        // freeze happens inside the same pass, before pass-end dispatch). The pass-end
        // `reconcile_writer_freeze` must fatal the parked waiter promptly — the exact D3 wedge
        // (a parked reply with no flight and a dead writer) this transition exists to kill.
        let cfg = EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig {
                max_segment_bytes: 192,
                ..LogConfig::default()
            },
            ..config()
        };
        let (handle, actor, control, _probe) = rig_probed_with(cfg);
        // Stage ONE pass containing [B (parks), C (forces a roll whose seal fails)]: hold the
        // actor in a blocking job while both are queued, then release.
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        // B fills segment 1 PAST the 192-byte cap (the roll triggers on the NEXT append), so C's
        // append MUST roll — the seal (`sync_all`) is the first barrier of the pass and it fails
        // BEFORE any flusher dispatch exists (the pure synchronous-freeze path; both produces are
        // in ONE pass, so no pass-end dispatch has run yet either).
        let b = handle.produce_async(append(&[0xb0; 200])).unwrap();
        let c = handle.produce_async(append(&[0xc0; 24])).unwrap();
        // Every sync now fails: the roll's seal (`sync_all`) freezes the writer mid-pass.
        control.set_fail_sync(true);
        let syncs_before = control.sync_count();
        release.send(()).unwrap();
        // C hit the failed seal inside its own append: fatal immediately.
        match c.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(ProduceOutcome::Fatal(_)) => {}
            other => panic!("the roller must surface the seal failure as Fatal, got {other:?}"),
        }
        // THE NO-WEDGE ASSERTION: B was parked before the freeze with NO flight outstanding; the
        // pass-end reconcile must fatal it promptly (a wedged implementation leaves it parked
        // forever and this recv times out).
        match b.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(ProduceOutcome::Fatal(_)) => {}
            other => panic!("the parked waiter must be fataled at pass end, got {other:?}"),
        }
        assert_eq!(
            control.sync_count() - syncs_before,
            1,
            "exactly the failed SEAL ran — the pure synchronous-freeze path, no flusher barrier \
             was ever dispatched (frozen at the pass-end stage)"
        );
        let _ = handle.with(|_| ());
        assert!(!handle.writer_appears_healthy(), "freeze published");
        control.set_fail_sync(false);
        drop(handle);
        let _ = actor.join();
    }

    #[test]
    fn t5b_a_freeze_while_an_ok_completion_is_in_flight_full_no_ops_and_fatals_everything() {
        // T5(b) (#1040): the writer freezes (an in-job engine-level freeze) WHILE an Ok barrier is
        // still in flight. Every parked reply — the in-flight batch AND the merged one — is
        // fataled promptly (while the flight is STILL parked in the gate: the no-wedge point),
        // and when the flight later returns Ok its completion is a FULL no-op: the durable head
        // never advances past the freeze and no ack is ever released (INV-1/INV-6/INV-7).
        let (handle, actor, control) = rig();
        // Stage: pass = [B, blocking job]; while held, queue [C, freeze-job]; the gate is closed
        // BEFORE the pass ends so B's dispatched barrier parks deterministically.
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let b = handle.produce_async(append(b"t5b-inflight-batch")).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        control.close_sync_gate();
        release.send(()).unwrap();
        entered2.recv().unwrap();
        // The actor is mid-pass (holding [B, job2]); queue the NEXT pass: C then the freeze.
        let c = handle.produce_async(append(b"t5b-merged-batch")).unwrap();
        handle
            .tx
            .send(Command::Run(Box::new(|e| {
                // The engine-level freeze seam (what a failed in-job inline barrier leaves): the
                // writer is dead from this instant, while B's barrier is still in the gate.
                let _ = e.fail_async_commit();
            })))
            .unwrap();
        release2.send(()).unwrap();
        // B's barrier is now provably IN FLIGHT (parked in the closed gate)...
        control.wait_for_sync_gate_entered(1);
        // ...and the freeze pass runs behind it: BOTH batches are fataled while the gate still
        // holds the flight (the mid-flight no-wedge proof — a quiesce-based design would hang).
        for (name, rx) in [("b", b), ("c", c)] {
            match rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(ProduceOutcome::Fatal(_)) => {}
                other => panic!("{name} must be fataled while the flight is parked, got {other:?}"),
            }
        }
        // Release the flight: it returns Ok AFTER the freeze — the completion must be a FULL
        // no-op (a half-applied ticket would advance the durable head past a frozen writer).
        control.open_sync_gate();
        let (flushed, durable, writable) = handle
            .with(|e| {
                (
                    e.flushed_offset().get(),
                    e.durable_offset().get(),
                    e.log_is_writable(),
                )
            })
            .unwrap();
        assert_eq!(
            flushed, 0,
            "the stale Ok completion advanced NOTHING (INV-6)"
        );
        assert_eq!(
            durable, 0,
            "the durable head never advances on a frozen writer"
        );
        assert!(!writable, "the writer stays frozen forever (INV-7)");
        drop(handle);
        let _ = actor.join();
    }

    #[test]
    fn t5c_a_synchronous_roll_seal_freeze_under_an_ok_flight_fatal_fans_at_pass_end() {
        // T5(c) (#1040, the PROMPTNESS half of L6): the writer freezes SYNCHRONOUSLY (a real
        // roll-seal failure, T5(a)'s trigger class) while an Ok barrier is STILL IN FLIGHT. In
        // this shape pass-end `maybe_issue` EARLY-RETURNS on the outstanding flight, so its
        // frozen-writer Err arm — the reconcile that happens to cover T5(a)'s no-flight shape —
        // never runs: ONLY the pass-end `reconcile_writer_freeze` can fatal the parked replies
        // now. An implementation that leans on the completion's reconcile instead fans them one
        // flight LATER. The promptness proof: every Fatal arrives while the flight is provably
        // still parked inside the closed gate (no completion — and no completion-side reconcile —
        // can have run). The stale Ok completion is then a FULL no-op, exactly as in T5(b).
        let cfg = EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig {
                max_segment_bytes: 192,
                ..LogConfig::default()
            },
            ..config()
        };
        let (handle, actor, control, _probe) = rig_probed_with(cfg);
        control.close_sync_gate();
        // Stage pass 1 = [A, job2] with the blocking-job stager (commands land in the SAME pass,
        // never a bare send racing the actor's idle wait): A parks small, and pass 1's END
        // dispatches A's covering barrier into the closed gate.
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let a = handle.produce_async(append(&[0xa5; 16])).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        // While job2 holds pass 1 open, queue ALL of pass 2 = [B, arm-job, C]: B (200 bytes,
        // buffered — no fs write) fills segment 1 PAST the 192-byte cap (the roll triggers on the
        // NEXT append); the arm-job arms `fail_write` FROM WITHIN the pass (arming any earlier
        // would fail the dispatch's own stage flush at pass 1's end); C's append must then roll,
        // and the seal's `flush_pending` of B's buffered frame is a WRITE — it fails BEFORE the
        // seal's gated `sync_all`, so the writer freezes synchronously ON THE ACTOR THREAD (the
        // actor never touches the closed gate) while the flight stays parked in it.
        let b = handle.produce_async(append(&[0xb5; 200])).unwrap();
        let arm = control.clone();
        handle
            .tx
            .send(Command::Run(Box::new(move |_e| {
                arm.set_fail_write(true);
            })))
            .unwrap();
        let c = handle.produce_async(append(&[0xc5; 24])).unwrap();
        let syncs_before = control.sync_count();
        release2.send(()).unwrap();
        // A's barrier is now provably IN FLIGHT (parked inside the closed gate)...
        control.wait_for_sync_gate_entered(1);
        // ...and pass 2 froze the writer BEHIND it. C hit the failed seal inside its own append:
        // fatal immediately, from the append path itself.
        match c.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(ProduceOutcome::Fatal(_)) => {}
            other => panic!("the roller must surface the seal failure as Fatal, got {other:?}"),
        }
        // THE PROMPTNESS ASSERTION: A and B are fataled by the PASS-END reconcile while the gate
        // still holds the flight — the gate has not been opened, so no completion exists yet. A
        // one-flight-late implementation leaves both parked until the gate opens, and these
        // bounded recvs time out instead of hanging the suite.
        for (name, rx) in [("a", a), ("b", b)] {
            match rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(ProduceOutcome::Fatal(_)) => {}
                other => panic!(
                    "{name} must be fataled at pass end, BEFORE the gate releases the flight, \
                     got {other:?}"
                ),
            }
        }
        assert_eq!(
            control.sync_count() - syncs_before,
            1,
            "only the parked in-flight fdatasync ever reached a sync: the seal died at its WRITE \
             (flush_pending), so the freeze was synchronous and no second barrier was dispatched"
        );
        // Release the flight: it returns Ok AFTER the freeze — the stale completion must be a
        // FULL no-op (INV-6): heads pinned, writer still frozen, nothing resurrected (INV-7).
        control.set_fail_write(false);
        control.open_sync_gate();
        let (flushed, durable, writable) = handle
            .with(|e| {
                (
                    e.flushed_offset().get(),
                    e.durable_offset().get(),
                    e.log_is_writable(),
                )
            })
            .unwrap();
        assert_eq!(
            flushed, 0,
            "the stale Ok completion advanced NOTHING (INV-6)"
        );
        assert_eq!(
            durable, 0,
            "the durable head never advances on a frozen writer"
        );
        assert!(!writable, "the writer stays frozen forever (INV-7)");
        assert!(!handle.writer_appears_healthy(), "freeze published");
        drop(handle);
        let _ = actor.join();
    }

    #[test]
    fn t6_an_acked_record_is_readable_on_actor_and_off_actor_planes_and_the_frontier_lags() {
        // T6 + the T15 leader-frontier assertion (#1040, INV-2/INV-10): while a barrier is in
        // flight the OFF-ACTOR read plane's flushed frontier must LAG (visible == durable — the
        // ISR leader frontier seeds from this plane, so it may never exceed the fdatasync-completed
        // offset); after the PubAck, both the actor-routed read and the off-actor plane serve the
        // record immediately (read-your-acked-write).
        let mem = InMemoryFs::new();
        let (fs, control) = FaultFs::new(mem);
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let plane = engine.read_plane().unwrap();
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        control.close_sync_gate();
        // A BURST window ([a, a2]) so the covering barrier is a real flusher FLIGHT (H1 would
        // inline a solo produce): the frontier-lag observation below is taken while the staged
        // bytes are provably in the file but the barrier has not returned.
        let (a, a2) = stage_burst_pass(
            &handle,
            append(b"t6-read-your-write"),
            append(b"t6-second-in-window"),
        );
        control.wait_for_sync_gate_entered(1);
        assert_eq!(
            plane.flushed(),
            0,
            "the off-actor frontier NEVER runs ahead of the completed fdatasync (INV-2)"
        );
        control.open_sync_gate();
        assert!(matches!(a.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 0));
        assert!(matches!(a2.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 1));
        // The ack was observed: the frontier was published BEFORE the release (INV-10), so the
        // off-actor plane already serves the record...
        assert_eq!(
            plane.flushed(),
            2,
            "the PubAck implies the published frontier covers the record (INV-10)"
        );
        // ...and so does an actor-routed poll.
        let delivered = handle
            .with(|e| match e.poll_now_in("") {
                Ok(Poll::Message(d)) => Some(d.record.payload.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            delivered.as_deref(),
            Some(b"t6-read-your-write".as_slice()),
            "an immediate actor-routed poll serves the acked record"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn t7_a_roll_under_an_in_flight_barrier_releases_pre_roll_waiters_at_the_seal() {
        // T7 (#1040, E9): a segment roll happens while the old segment's covering barrier is in
        // flight. The rendezvous PROVES the roll's seal (`sync_all`) and the flusher's `fdatasync`
        // were simultaneously inside their barriers (two threads, one shared fd — the kernel-safe
        // overlap); the seal itself is a covering barrier, so the pre-roll waiter releases off it
        // with zero extra fsyncs; the old ticket's late completion is a full no-op (pinned at the
        // log level; observed here as exact final heads/meter); and the pipeline keeps flowing
        // afterward (the meter-drift livelock regression, T10b).
        let cfg = EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig {
                max_segment_bytes: 192,
                ..LogConfig::default()
            },
            ..config()
        };
        let (handle, actor, control, _probe) = rig_probed_with(cfg);
        // Stage: pass = [B (parks, small), blocking job]; while held, queue C (forces the roll).
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        // B fills segment 1 PAST the 192-byte cap: the NEXT append (C) must roll, so C's seal is
        // issued while B's covering barrier is provably inside the rendezvous.
        let b = handle.produce_async(append(&[0xb1; 200])).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        let c = handle.produce_async(append(&[0xc1; 24])).unwrap();
        // Arm the width-2 rendezvous ONLY now (no unrelated sync can join), then release: the
        // pass ends, B's barrier dispatches and parks INSIDE the rendezvous; the next pass
        // appends C, whose roll-seal `sync_all` joins as the second participant — OVERLAP.
        control.arm_sync_rendezvous(2);
        release2.send(()).unwrap();
        assert!(
            control.wait_for_rendezvous_or_release(std::time::Duration::from_secs(10)),
            "the roll's seal and the in-flight fdatasync must overlap (two barriers, one fd)"
        );
        // B releases off the SEAL (the covering barrier at the roll boundary); C releases off its
        // own next barrier. Submission order is preserved.
        assert!(
            matches!(b.recv_timeout(std::time::Duration::from_secs(10)), Ok(ProduceOutcome::Appended(o)) if o.get() == 0),
            "the pre-roll waiter releases at the seal"
        );
        assert!(
            matches!(c.recv_timeout(std::time::Duration::from_secs(10)), Ok(ProduceOutcome::Appended(o)) if o.get() == 1),
            "the post-roll waiter releases after the next covering barrier"
        );
        // The stale old-fd completion was a FULL no-op: the meter and heads are exact, and the
        // pipeline still flows (no meter-drift livelock) — a follow-up produce acks cleanly.
        let (unsynced, flushed, durable) = handle
            .with(|e| {
                (
                    e.unsynced_bytes(),
                    e.flushed_offset().get(),
                    e.durable_offset().get(),
                )
            })
            .unwrap();
        assert_eq!(
            unsynced, 0,
            "the byte meter reconciled exactly across the roll"
        );
        assert_eq!(flushed, durable, "visible == durable");
        assert_eq!(flushed, 2, "both records durable");
        assert!(
            matches!(handle.produce(append(b"t7-after-roll")).unwrap(), ProduceOutcome::Appended(o) if o.get() == 2),
            "the pipeline keeps flowing after the roll-under-flight"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn t8_interleaved_connections_get_fifo_acks_across_merged_windows() {
        // T8 (#917 x #1040): two logical connections interleave submissions across MERGED windows
        // (a gated BURST primer guarantees a real flusher flight for them to merge behind).
        // Structural FIFO (INV-4) must hold: each connection's acks arrive in ITS submission
        // order with position-correlated offsets.
        let (handle, actor, control) = rig();
        control.close_sync_gate();
        let (p1, p2) = stage_burst_pass(&handle, append(b"t8-primer-1"), append(b"t8-primer-2"));
        control.wait_for_sync_gate_entered(1);
        // Interleaved: a1, b1, a2, b2, a3, b3 — all merged behind the parked barrier.
        let conn_a: Vec<_> = ["a1", "a2", "a3"].iter().map(|_| ()).collect();
        let mut a_replies = Vec::new();
        let mut b_replies = Vec::new();
        for i in 0..conn_a.len() {
            a_replies.push(
                handle
                    .produce_submit(append(format!("t8-a{i}").as_bytes()))
                    .unwrap(),
            );
            b_replies.push(
                handle
                    .produce_submit(append(format!("t8-b{i}").as_bytes()))
                    .unwrap(),
            );
        }
        control.open_sync_gate();
        assert!(matches!(p1.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 0));
        assert!(matches!(p2.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 1));
        // Per-connection ack order == submission order; offsets correlate with position: the
        // interleaving assigned a_i offset 2+2i and b_i offset 3+2i.
        for (i, s) in a_replies.into_iter().enumerate() {
            let expected = 2 + 2 * u64::try_from(i).unwrap();
            assert!(
                matches!(s.wait().unwrap(), ProduceOutcome::Appended(o) if o.get() == expected),
                "conn A's ack {i} must be its own offset {expected}"
            );
        }
        for (i, s) in b_replies.into_iter().enumerate() {
            let expected = 3 + 2 * u64::try_from(i).unwrap();
            assert!(
                matches!(s.wait().unwrap(), ProduceOutcome::Appended(o) if o.get() == expected),
                "conn B's ack {i} must be its own offset {expected}"
            );
        }
        let _ = recover(handle, actor);
    }

    #[test]
    fn t9_a_same_window_duplicate_waits_the_fsync_and_a_durable_duplicate_needs_none() {
        // T9, dedup I2-uniformity (#33 x #1040): (a) a duplicate of an id recorded in the CURRENT
        // unsynced window parks behind the covering fsync exactly like the fresh append (its
        // original offset is not durable yet); (b) a duplicate of a LONG-DURABLE id on an idle
        // log releases immediately with ZERO fsyncs (the dup-of-durable fast path).
        let (handle, actor, control, probe) = rig_probed_with(config());
        control.close_sync_gate();
        // Stage pass 1 = [p1, p2, hold] (a burst window, so the flight is the flusher's), and
        // queue the fresh+duplicate pair while the pass is held open: the FREE actor appends and
        // PARKS both while the gate still holds the flight — the parked observations below are
        // taken against records that were really processed mid-flight, not merely queued (the
        // fresh append is over the 256 KiB spill bound, so its bytes appearing in the LIVE image
        // prove the pass ran; the duplicate is drained in the SAME pass, right behind it).
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let p1 = handle.produce_async(append(b"t9-primer-1")).unwrap();
        let p2 = handle.produce_async(append(b"t9-primer-2")).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        // (a) Fresh dedup'd X and its same-window duplicate, queued behind the held pass.
        let mut fresh_payload = vec![0x9a_u8; 300 * 1024];
        fresh_payload.extend_from_slice(b"T9-FRESH-MID-FLIGHT");
        let fresh = handle
            .produce_async(append_dedup(&fresh_payload, b"t9-prod", 1, b"t9-idem"))
            .unwrap();
        let dup = handle
            .produce_async(append_dedup(b"x-again", b"t9-prod", 1, b"t9-idem"))
            .unwrap();
        release2.send(()).unwrap();
        control.wait_for_sync_gate_entered(1);
        assert!(
            wait_for_live_bytes(&probe, b"T9-FRESH-MID-FLIGHT"),
            "the fresh append (and, same pass, its duplicate) was processed WHILE the primer \
             window's barrier held the gate"
        );
        // I2-uniformity: the duplicate must NOT reply before the covering fsync — its original
        // offset lives in the same unsynced window (fresh is appended but NOT durable).
        assert!(fresh.try_recv().is_err(), "fresh parked behind the fsync");
        assert!(
            dup.try_recv().is_err(),
            "the same-window duplicate must WAIT for the covering fsync (I2 uniformity)"
        );
        control.open_sync_gate();
        for rx in [p1, p2] {
            assert!(matches!(rx.recv().unwrap(), ProduceOutcome::Appended(_)));
        }
        assert!(
            matches!(fresh.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 2),
            "the fresh dedup'd produce appends at offset 2"
        );
        assert!(
            matches!(dup.recv().unwrap(), ProduceOutcome::AppendedDuplicate(o) if o.get() == 2),
            "the duplicate returns the ORIGINAL offset once durable"
        );
        // (b) The log is now idle and fully durable: a duplicate of the long-durable id releases
        // with ZERO additional fsyncs.
        let before = control.sync_count();
        assert!(
            matches!(
                handle.produce(append_dedup(b"x-later", b"t9-prod", 1, b"t9-idem")).unwrap(),
                ProduceOutcome::AppendedDuplicate(o) if o.get() == 2
            ),
            "a duplicate of a durable id releases immediately"
        );
        assert_eq!(
            control.sync_count() - before,
            0,
            "the dup-of-durable fast path issues NO barrier"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn t10_the_dirty_byte_bound_throttles_admission_and_never_sheds() {
        // T10(a) (#1040, INV-9/E8): with a tiny `sync_max_dirty_bytes` and the covering barrier
        // held in the gate, the NEXT produce is THROTTLED — blocked BEFORE its append (its bytes
        // never reach the live image while the gate holds), never shed — and admitted the moment
        // the completion drains the window. The bound forces the windows apart: each throttled
        // record rides its OWN barrier (dispatch-before-block, so no deadlock either).
        let cfg = EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            sync_max_dirty_bytes: 64,
            ..config()
        };
        let (handle, actor, control, probe) = rig_probed_with(cfg);
        control.close_sync_gate();
        // Stage pass 1 = [A1 (36 logical bytes), A2 (8), hold]: a burst window (44 <= 64 admits
        // both; two parked waiters, so the pass end dispatches the flusher flight, never H1's
        // inline barrier), with B queued while the pass is held open — B's pass then runs while
        // the flight is provably in the gate, and B's throttle engages for real.
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let mut a_payload = vec![0xa0_u8; 24];
        a_payload.extend_from_slice(b"T10-A-STAGED");
        let a = handle.produce_async(append(&a_payload)).unwrap();
        let a2 = handle.produce_async(append(&[0xa1_u8; 8])).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        // B (39 logical bytes) would push the window over the 64-byte bound (44 + 39 > 64): the
        // actor must throttle BEFORE B's append, so B's bytes must NOT appear while the gate
        // holds the covering barrier.
        let mut b_payload = vec![0xb0_u8; 24];
        b_payload.extend_from_slice(b"T10-B-THROTTLED");
        let b = handle.produce_async(append(&b_payload)).unwrap();
        release2.send(()).unwrap();
        control.wait_for_sync_gate_entered(1);
        // A's frame IS staged into the file (the dispatch's stage flushed it).
        assert!(
            wait_for_live_bytes(&probe, b"T10-A-STAGED"),
            "A's staged frame is in the live image while its barrier is in flight"
        );
        let observe_until = std::time::Instant::now() + std::time::Duration::from_millis(200);
        while std::time::Instant::now() < observe_until {
            assert!(
                !contains_bytes(&live_segment_bytes(&probe), b"T10-B-THROTTLED"),
                "B must be throttled BEFORE its append while the window is over the bound"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(b.try_recv().is_err(), "B is not acked while throttled");
        let entered_before_open = control.sync_count();
        control.open_sync_gate();
        // The completion drains the window: A1/A2 ack, then B admits, appends, and rides its own
        // barrier. Zero sheds anywhere (the throttle blocks, never sheds).
        assert!(matches!(a.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 0));
        assert!(matches!(a2.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 1));
        assert!(matches!(b.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 2));
        assert_eq!(
            control.sync_count() - entered_before_open,
            1,
            "the bound split the windows: B rides exactly one barrier of its own"
        );
        let (rejected, headroom_sheds, unsynced) = handle
            .with(|e| {
                (
                    e.counters().produce_rejected,
                    e.backpressure_snapshot().wal_headroom_shed,
                    e.unsynced_bytes(),
                )
            })
            .unwrap();
        assert_eq!(rejected, 0, "the throttle never sheds (INV-9)");
        assert_eq!(headroom_sheds, 0, "no headroom shed either");
        assert_eq!(unsynced, 0, "the window fully drained");
        let _ = recover(handle, actor);
    }

    #[test]
    fn t10b_a_same_pass_burst_over_the_bound_dispatches_before_blocking_never_deadlocks() {
        // T10(b) (#1040, INV-9/L3, the dispatch-before-block proof): BOTH produces land in ONE
        // actor pass (staged exactly like T1), so B's throttle check runs MID-PASS with the
        // window over the bound and NO flight outstanding — pass-end `maybe_issue` has not run
        // yet, so this is the one shape where the THROTTLE ITSELF must dispatch. It must
        // `maybe_issue` A's covering barrier FIRST (so a completion can ever arrive) and only
        // then block; an implementation that parks on the completion channel with nothing in
        // flight deadlocks right here (or trips the depth-1 debug assert). The dispatch is
        // observed BOUNDED: the flusher enters the closed gate (`sync_count` bumps at gate entry)
        // while B is still throttled and unacked, and every later wait is a timed recv.
        let cfg = EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            sync_max_dirty_bytes: 64,
            ..config()
        };
        let (handle, actor, control, probe) = rig_probed_with(cfg);
        control.close_sync_gate();
        // Stage pass = [A, B] with the blocking-job stager (the same technique T1 uses): while
        // the job holds the actor, queue both produces; releasing the job makes the very next
        // pass drain them TOGETHER — never a bare send racing the actor's idle wait.
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        // A: 40 logical bytes — admitted on the empty-window floor, parked, unsynced = 40.
        let mut a_payload = vec![0xa6_u8; 28];
        a_payload.extend_from_slice(b"T10B-A-FIRST");
        let a = handle.produce_async(append(&a_payload)).unwrap();
        // B: 36 logical bytes — 40 + 36 > 64, so B must throttle mid-pass with NO flight yet.
        let mut b_payload = vec![0xb6_u8; 24];
        b_payload.extend_from_slice(b"T10B-B-GATED");
        let b = handle.produce_async(append(&b_payload)).unwrap();
        let syncs_before = control.sync_count();
        release.send(()).unwrap();
        // THE MUTANT-KILLING OBSERVATION: A's covering barrier is dispatched FROM INSIDE B's
        // throttle — nothing else can dispatch it, because the pass never ends while B blocks
        // mid-pass. A block-without-dispatch implementation never bumps `sync_count`, and this
        // poll fails BOUNDED instead of hanging the suite on a barrier that can never arrive.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while control.sync_count() == syncs_before && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        assert_eq!(
            control.sync_count(),
            syncs_before + 1,
            "the throttle must dispatch A's covering barrier BEFORE blocking (INV-9, L3): no \
             barrier entered the gate, so the throttle parked with nothing in flight"
        );
        control.wait_for_sync_gate_entered(1);
        // While the gate holds the flight: A's staged frame is in the live image (the dispatch's
        // stage flushed it), B is throttled BEFORE its append (its bytes never appear), and
        // neither reply has been released (INV-1).
        assert!(
            wait_for_live_bytes(&probe, b"T10B-A-FIRST"),
            "A's staged frame is in the live image while its barrier is in flight"
        );
        let observe_until = std::time::Instant::now() + std::time::Duration::from_millis(200);
        while std::time::Instant::now() < observe_until {
            assert!(
                !contains_bytes(&live_segment_bytes(&probe), b"T10B-B-GATED"),
                "B must be throttled BEFORE its append while the window is over the bound"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            a.try_recv().is_err(),
            "A is not acked while its barrier is parked (INV-1)"
        );
        assert!(b.try_recv().is_err(), "B is not acked while throttled");
        // Open the gate: the completion drains the window — A acks FIRST, B is admitted ONLY
        // after that completion, appends, and rides its OWN barrier. Acks in submission order,
        // bounded waits throughout, zero sheds anywhere (the throttle blocks, never sheds).
        control.open_sync_gate();
        match a.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(ProduceOutcome::Appended(o)) => assert_eq!(o.get(), 0, "A acks first, at offset 0"),
            other => panic!("A must ack Appended once its barrier returns, got {other:?}"),
        }
        match b.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(ProduceOutcome::Appended(o)) => {
                assert_eq!(
                    o.get(),
                    1,
                    "B admits only after the completion, at offset 1"
                );
            }
            other => panic!("B must ack Appended after ITS OWN barrier, got {other:?}"),
        }
        assert_eq!(
            control.sync_count() - syncs_before,
            2,
            "the bound split the windows: exactly A's barrier plus B's own, no third"
        );
        let (rejected, headroom_sheds, unsynced) = handle
            .with(|e| {
                (
                    e.counters().produce_rejected,
                    e.backpressure_snapshot().wal_headroom_shed,
                    e.unsynced_bytes(),
                )
            })
            .unwrap();
        assert_eq!(rejected, 0, "the throttle never sheds (INV-9)");
        assert_eq!(headroom_sheds, 0, "no headroom shed either");
        assert_eq!(unsynced, 0, "the window fully drained");
        let _ = recover(handle, actor);
    }

    #[test]
    fn t11_the_sync_inflight_stamp_sets_on_dispatch_and_clears_on_completion() {
        // T11, the actor-level wiring of INV-8 (#862 x #1040): while the flusher's barrier is
        // parked in the gate the actor itself is IDLE (its busy stamp was cleared at pass end and
        // it is blocked on the completion channel), so a tripped watchdog PROVES the dedicated
        // sync-inflight stamp is wired (the busy stamp cannot see this wedge). After the
        // completion, the stamp clears and the watchdog un-trips. The busy-broker variant (fresh
        // busy stamps masking nothing) is pinned in the liveness unit test.
        const BOUND: u64 = 1_000;
        let (handle, actor, control) = rig();
        handle.set_actor_watchdog_bound(BOUND);
        let t0 = handle.now_monotonic_nanos();
        control.close_sync_gate();
        // A BURST window so the wedged barrier is the FLUSHER's flight (a solo produce would
        // wedge the actor in H1's inline barrier — visible to the BUSY stamp, which is exactly
        // what this test must prove unnecessary for a flight).
        let (a, a2) = stage_burst_pass(&handle, append(b"t11-wedge"), append(b"t11-wedge-2"));
        control.wait_for_sync_gate_entered(1);
        // The dispatch stamped sync-inflight strictly BEFORE the flusher could enter the gate, so
        // the wedge is visible from this instant on — and it STAYS visible once the actor's pass
        // ends and it parks idle on the completion channel with its busy stamp cleared (the state
        // this scenario settles into), which only the dedicated sync-inflight stamp can see. The
        // liveness unit test isolates the two stamps; this pins the actor-level wiring.
        assert!(
            handle.actor_watchdog_overran(t0 + BOUND + 2),
            "the in-flight barrier trips the watchdog while the actor is not busy (INV-8)"
        );
        control.open_sync_gate();
        assert!(matches!(a.recv().unwrap(), ProduceOutcome::Appended(_)));
        assert!(matches!(a2.recv().unwrap(), ProduceOutcome::Appended(_)));
        // Round-trip a job so the completion has provably been processed, then bounded-poll the
        // watchdog UN-TRIPPING: the completion cleared the sync-inflight stamp, and once the
        // actor's pass ends (`mark_idle` can lag this thread on a loaded test host) neither stamp
        // can trip. With a flight still outstanding this would stay tripped FOREVER, so the flip
        // to false pins the clear.
        let _ = handle.with(|_| ());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut untripped = false;
        while std::time::Instant::now() < deadline {
            if !handle.actor_watchdog_overran(t0 + BOUND + 2) {
                untripped = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(
            untripped,
            "the completion clears the sync-inflight stamp; no flight => no wedge"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn t12a_a_run_job_does_not_quiesce_the_pipeline() {
        // T12 (#1040, E5/L9): a Run job in the same pass as a produce runs with ZERO covering
        // barriers issued beforehand (the legacy loop force-flushed exactly one) and observes a
        // consistent durable head TRAILING the appended head. The in-pass appended produce still
        // acks afterward (the pass end dispatches its barrier).
        let (handle, actor, control) = rig();
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let b = handle.produce_async(append(b"t12-appended")).unwrap();
        let (obs_tx, obs_rx) = sync_channel::<(u64, u64, u64)>(1);
        let control_in_job = control.clone();
        handle
            .tx
            .send(Command::Run(Box::new(move |e| {
                let _ = obs_tx.send((
                    e.durable_offset().get(),
                    e.append_head().get(),
                    control_in_job.sync_count(),
                ));
            })))
            .unwrap();
        let sync_baseline = control.sync_count();
        release.send(()).unwrap();
        let (durable, appended, syncs_at_job) = obs_rx.recv().unwrap();
        assert_eq!(appended, 1, "the produce appended before the job");
        assert_eq!(
            durable, 0,
            "the job observes the durable head TRAILING the appended head — no pre-job quiesce"
        );
        assert_eq!(
            syncs_at_job, sync_baseline,
            "ZERO covering barriers ran before the job (the legacy loop would have forced one)"
        );
        assert!(matches!(b.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 0));
        let _ = recover(handle, actor);
    }

    #[test]
    fn t12b_an_in_job_inline_barrier_overlaps_the_flight_and_composes_exactly() {
        // T12's inline-barrier composition (#1040, E5/INV-6): a Run job issues an INLINE
        // `commit_batch` WHILE the flusher's barrier is in flight — the rendezvous proves the two
        // barriers were simultaneously inside their fsyncs on the one shared fd. The inline
        // barrier overtakes the flight (covering the in-job window); the in-job-covered waiter
        // releases at the POST-JOB reconcile; the overtaken flight's late completion is a FULL
        // no-op; the meter stays exact and the pipeline keeps flowing.
        let (handle, actor, control) = rig();
        // Stage: pass = [B (parks), blocking job]; while held, queue the inline-barrier job.
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let b = handle
            .produce_async(append(b"t12b-covered-in-job"))
            .unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        let (job_tx, job_rx) = sync_channel::<(u64, u64)>(1);
        handle
            .tx
            .send(Command::Run(Box::new(move |e| {
                let before = (e.durable_offset().get(), e.append_head().get());
                // The in-job INLINE covering barrier (a txn commit / force_sync stand-in),
                // racing the in-flight fdatasync on the same fd.
                let _ = e.commit_batch();
                let _ = job_tx.send(before);
            })))
            .unwrap();
        // Arm the width-2 rendezvous ONLY now, then let the pass end: B's barrier dispatches into
        // the rendezvous (participant 1), the next pass runs the job whose inline barrier joins
        // as participant 2 — both provably inside their fsyncs at once.
        control.arm_sync_rendezvous(2);
        release2.send(()).unwrap();
        assert!(
            control.wait_for_rendezvous_or_release(std::time::Duration::from_secs(10)),
            "the inline in-job barrier and the in-flight fdatasync must OVERLAP"
        );
        let (durable_at_job, appended_at_job) = job_rx.recv().unwrap();
        assert_eq!(appended_at_job, 1, "B was appended before the job");
        assert_eq!(
            durable_at_job, 0,
            "the flight had not completed when the job began"
        );
        // The in-job-covered waiter releases at the post-job reconcile (or the stale completion's
        // release — either way, promptly and exactly once).
        assert!(
            matches!(b.recv_timeout(std::time::Duration::from_secs(10)), Ok(ProduceOutcome::Appended(o)) if o.get() == 0),
            "the in-job inline barrier's coverage releases the parked waiter"
        );
        // The late completion was a full no-op: meter exact, heads exact, pipeline alive.
        let (unsynced, flushed) = handle
            .with(|e| (e.unsynced_bytes(), e.flushed_offset().get()))
            .unwrap();
        assert_eq!(
            unsynced, 0,
            "the meter is exact after the overlapped barriers"
        );
        assert_eq!(flushed, 1, "exactly the one record is durable");
        assert!(
            matches!(handle.produce(append(b"t12b-after")).unwrap(), ProduceOutcome::Appended(o) if o.get() == 1),
            "the pipeline keeps flowing after the overlap"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn t13a_dropping_the_last_handle_mid_flight_releases_the_ack_and_exits_cleanly() {
        // T13(a), drop-driven shutdown (#1040): the last handle drops while a barrier is in
        // flight (a BURST window, so it really is the flusher's flight). The actor processes the
        // completion FIRST (releasing the covered acks to their still-live receivers), then
        // observes the disconnect and runs the loss-free E7 drain — clean exit, engine
        // recovered, flusher joined.
        let (handle, actor, control) = rig();
        control.close_sync_gate();
        let (a, a2) = stage_burst_pass(
            &handle,
            append(b"t13a-mid-flight"),
            append(b"t13a-mid-flight-2"),
        );
        control.wait_for_sync_gate_entered(1);
        drop(handle);
        control.open_sync_gate();
        assert!(
            matches!(a.recv_timeout(std::time::Duration::from_secs(10)), Ok(ProduceOutcome::Appended(o)) if o.get() == 0),
            "the completion is processed and the covered ack released despite the dropped handle"
        );
        assert!(
            matches!(a2.recv_timeout(std::time::Duration::from_secs(10)), Ok(ProduceOutcome::Appended(o)) if o.get() == 1),
            "the whole covered window releases"
        );
        let engine = actor.join().unwrap();
        assert_eq!(
            engine.flushed_offset().get(),
            2,
            "the records are durable in the recovered engine"
        );
    }

    #[test]
    fn t13b_an_explicit_shutdown_mid_flight_quiesces_checkpoints_and_joins_the_flusher() {
        // T13(b) (#1040): an explicit Shutdown lands while a barrier is in flight (a BURST
        // window, so it really is the flusher's flight). The E6 path quiesces (drains the
        // flight, inline-commits the tail), checkpoints, replies, and joins the flusher — the
        // actor thread exits cleanly with the engine returned.
        let (handle, actor, control) = rig();
        control.close_sync_gate();
        let (a, a2) = stage_burst_pass(
            &handle,
            append(b"t13b-mid-flight"),
            append(b"t13b-mid-flight-2"),
        );
        control.wait_for_sync_gate_entered(1);
        let (sd_tx, sd_rx) = sync_channel::<Result<(), EngineError>>(1);
        handle.tx.send(Command::Shutdown(sd_tx)).unwrap();
        // A second produce lands AFTER the Shutdown: the #802 closing-reply contract must hold
        // on the pipelined tier too.
        let late = handle
            .produce_async(append(b"t13b-after-shutdown"))
            .unwrap();
        control.open_sync_gate();
        assert!(matches!(a.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 0));
        assert!(matches!(a2.recv().unwrap(), ProduceOutcome::Appended(o) if o.get() == 1));
        sd_rx.recv().unwrap().unwrap();
        match late.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(ProduceOutcome::AtCapacity) => {}
            other => panic!("the shutdown-queued produce gets the closing reply, got {other:?}"),
        }
        let engine = actor.join().unwrap();
        assert_eq!(engine.flushed_offset().get(), 2);
    }

    #[test]
    fn t13c_a_dead_flusher_is_a_failed_barrier_never_a_hang() {
        // T13(c) (#1040): the flusher thread is GONE (both its channel halves dropped — the
        // harness variant of a crashed flusher). A dispatch cannot round-trip, so it is treated
        // as the failed-barrier class: freeze + fatal-fan, and quiesce returns instead of
        // hanging. Driven directly against the Pipeline state machine (the run loop's helpers).
        let (fs, _control) = FaultFs::new(InMemoryFs::new());
        let mut engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let watchdog = ActorWatchdog::new(0);
        let clock = ManualClock::new();
        let cap_gate = ProduceCapGate::new(0);
        let (req_tx, req_rx) =
            sync_channel::<FlushJob<<FaultFs<InMemoryFs> as Filesystem>::File>>(1);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<SyncDone>();
        // The dead flusher: nobody serves the job channel or holds the completion sender.
        drop(req_rx);
        drop(done_tx);
        let mut pipeline = Pipeline {
            parked: VecDeque::new(),
            in_flight: None,
            next_seq: 0,
            req_tx: Some(req_tx),
            done_rx,
            flusher: None,
            max_dirty_bytes: 0,
            watchdog: &watchdog,
            clock: &clock,
            cap_gate: &cap_gate,
        };
        // Append one record and park its reply through the real park path.
        let view = Append {
            timestamp_ms: 0,
            flags: ironbus_core::types::RecordFlags::from_bits(0),
            key: b"",
            headers: b"",
            payload: b"t13c",
        };
        let offset = match engine
            .append_no_sync_dedup_checked(&view, None, None)
            .unwrap()
        {
            crate::engine::AppendOutcome::Appended(o) => o,
            other => panic!("append failed: {other:?}"),
        };
        let (reply_tx, reply_rx) = sync_channel::<ProduceOutcome>(1);
        pipeline.park(
            &mut engine,
            PendingOutcome::Appended(offset),
            Some(reply_tx),
        );
        // The dispatch hits the dead flusher: failed-barrier class, immediately.
        pipeline.maybe_issue(&mut engine);
        match reply_rx.try_recv() {
            Ok(ProduceOutcome::Fatal(EngineError::Storage(
                ironbus_storage::segment::StorageError::Io(_),
            ))) => {}
            other => panic!("the parked waiter must get the synthesized fatal, got {other:?}"),
        }
        assert!(!engine.log_is_writable(), "the writer froze (INV-7)");
        assert!(pipeline.in_flight.is_none(), "no phantom flight remains");
        // And the quiesce path returns promptly on the frozen, flusher-less pipeline (no hang).
        pipeline.quiesce_to_durable(&mut engine);
        assert!(pipeline.parked.is_empty());
    }

    #[test]
    fn t14_pipelined_actor_segments_are_byte_identical_to_produce_once_segments() {
        // T14, the conformance gate (#1040): an identical produce sequence through (a) the
        // synchronous `produce_once` path and (b) the pipelined actor (including merged windows
        // and a segment roll) must leave BYTE-IDENTICAL segment files — the pipeline changes
        // WHEN fsyncs happen, never what lands on disk.
        let cfg = || EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig {
                max_segment_bytes: 512,
                ..LogConfig::default()
            },
            ..config()
        };
        let payloads: Vec<Vec<u8>> = (0..40u8)
            .map(|i| vec![i; 3 + usize::from(i % 17)])
            .collect();
        // (a) The synchronous reference: produce_once, one barrier per record.
        let mem_ref = InMemoryFs::new();
        let probe_ref = mem_ref.clone();
        let mut reference = Engine::open(mem_ref, ManualClock::new(), cfg()).unwrap();
        for p in &payloads {
            assert!(matches!(
                produce_once(&mut reference, &append(p)),
                ProduceOutcome::Appended(_)
            ));
        }
        // (b) The pipelined actor: a gated BURST primer window ([0, 1]) holds a real flusher
        // flight while [2..8) are appended mid-flight and merge into the next window; the rest
        // run solo (H1's inline barrier path), so BOTH dispatch shapes contribute bytes.
        let (handle, actor, control, probe_pipe) = rig_probed_with(cfg());
        control.close_sync_gate();
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let first = handle.produce_async(append(&payloads[0])).unwrap();
        let second = handle.produce_async(append(&payloads[1])).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        let merged: Vec<_> = payloads[2..8]
            .iter()
            .map(|p| handle.produce_async(append(p)).unwrap())
            .collect();
        release2.send(()).unwrap();
        control.wait_for_sync_gate_entered(1);
        control.open_sync_gate();
        assert!(matches!(first.recv().unwrap(), ProduceOutcome::Appended(_)));
        assert!(matches!(
            second.recv().unwrap(),
            ProduceOutcome::Appended(_)
        ));
        for r in merged {
            assert!(matches!(r.recv().unwrap(), ProduceOutcome::Appended(_)));
        }
        for p in &payloads[8..] {
            assert!(matches!(
                handle.produce(append(p)).unwrap(),
                ProduceOutcome::Appended(_)
            ));
        }
        // Quiesce the actor so the tails are flushed identically, then compare EVERY segment.
        let _ = recover(handle, actor);
        let seg_names = |probe: &InMemoryFs| -> Vec<String> {
            let mut names: Vec<String> = probe
                .list()
                .unwrap()
                .into_iter()
                .filter(|n| is_segment_file(n))
                .collect();
            names.sort();
            names
        };
        let ref_names = seg_names(&probe_ref);
        let pipe_names = seg_names(&probe_pipe);
        assert_eq!(
            ref_names, pipe_names,
            "same segment file set (rolls at the same points)"
        );
        assert!(ref_names.len() > 1, "the sequence spans a roll");
        for name in &ref_names {
            use ironbus_storage::io::RandomAccessFile;
            let read_all = |probe: &InMemoryFs| -> Vec<u8> {
                let f = probe.open(name).unwrap();
                let len = usize::try_from(f.len().unwrap()).unwrap();
                let mut buf = vec![0u8; len];
                f.read_exact_at(&mut buf, 0).unwrap();
                buf
            };
            assert_eq!(
                read_all(&probe_ref),
                read_all(&probe_pipe),
                "segment {name} must be byte-identical between produce_once and the pipeline"
            );
        }
    }

    // ---- H1 solo-inline + H2 adaptive first-dispatch linger (#1040 dispatch heuristics) ----

    /// The HELD flusher ends for a direct-[`Pipeline`] rig (the t13c construction): every
    /// dispatched `FlushJob` is observable in `req_rx` (and none can complete until the test
    /// plays flusher via `complete_one_flight`), which is what makes the H1/H2 dispatch-shape
    /// assertions exact rather than timing-inferred.
    struct HeldFlusher {
        req_rx: Receiver<FlushJob<<FaultFs<InMemoryFs> as Filesystem>::File>>,
        done_tx: std::sync::mpsc::Sender<SyncDone>,
    }

    impl HeldFlusher {
        /// Plays one flusher round: takes the ONE dispatched job, issues its barrier, and
        /// reports the completion.
        fn complete_one_flight(&self) {
            use ironbus_storage::io::RandomAccessFile;
            let job = self
                .req_rx
                .try_recv()
                .expect("a dispatched FlushJob must be on the bound-1 channel");
            job.file.sync_data().unwrap();
            self.done_tx
                .send(SyncDone {
                    seq: job.seq,
                    result: Ok(()),
                    fsync_nanos: 1_000,
                })
                .unwrap();
        }
    }

    /// Builds the held flusher plus the pipeline-side channel halves to construct a direct
    /// [`Pipeline`] over.
    #[allow(clippy::type_complexity)]
    fn held_flusher() -> (
        HeldFlusher,
        SyncSender<FlushJob<<FaultFs<InMemoryFs> as Filesystem>::File>>,
        Receiver<SyncDone>,
    ) {
        let (req_tx, req_rx) =
            sync_channel::<FlushJob<<FaultFs<InMemoryFs> as Filesystem>::File>>(1);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<SyncDone>();
        (HeldFlusher { req_rx, done_tx }, req_tx, done_rx)
    }

    /// A fresh engine over a fault fs for the direct-[`Pipeline`] rigs.
    fn direct_engine() -> Engine<FaultFs<InMemoryFs>, ManualClock> {
        let (fs, _control) = FaultFs::new(InMemoryFs::new());
        Engine::open(fs, ManualClock::new(), config()).unwrap()
    }

    #[test]
    fn h1_a_solo_produce_on_an_idle_pipelined_tier_inlines_with_zero_flusher_jobs() {
        // H1 SOLO-INLINE (#1040 regression fix, the P1 shape): a pass that parked exactly ONE
        // waiter, with no flight outstanding and the command channel verifiably empty, runs the
        // LEGACY inline barrier on the actor — ZERO flusher jobs (no `FlushJob` ever crosses the
        // job channel, held by this test), zero thread hops — and still acks DURABLY (the reply
        // is released only after the inline barrier returned; durable == appended afterward).
        // An always-dispatch mutant (H1 deleted) stages a FlushJob instead and leaves the
        // waiter parked for a flusher round-trip: it fails every assertion below.
        let mut engine = direct_engine();
        let (flusher, req_tx, done_rx) = held_flusher();
        let watchdog = ActorWatchdog::new(0);
        let clock = ManualClock::new();
        let cap_gate = ProduceCapGate::new(0);
        let mut pipeline = Pipeline {
            parked: VecDeque::new(),
            in_flight: None,
            next_seq: 0,
            req_tx: Some(req_tx),
            done_rx,
            flusher: None,
            max_dirty_bytes: 0,
            watchdog: &watchdog,
            clock: &clock,
            cap_gate: &cap_gate,
        };
        let (reply_tx, reply_rx) = sync_channel::<ProduceOutcome>(1);
        process_produce(
            &mut engine,
            &mut pipeline,
            &append(b"h1-solo"),
            Some(reply_tx),
        );
        assert_eq!(pipeline.parked.len(), 1, "the solo produce parked");
        assert!(reply_rx.try_recv().is_err(), "not acked before the barrier");
        // The pass ends with an EMPTY (still-connected) command channel.
        let (_cmd_tx, cmd_rx) = sync_channel::<Command<FaultFs<InMemoryFs>, ManualClock>>(4);
        let carry = pipeline.finish_pass(&mut engine, &cmd_rx);
        assert!(carry.is_none(), "nothing was pulled off an empty channel");
        // ZERO flusher jobs: no flight exists and nothing crossed the job channel...
        assert!(
            pipeline.in_flight.is_none(),
            "H1 went inline: no flight was staged for a solo pass"
        );
        assert!(
            matches!(flusher.req_rx.try_recv(), Err(TryRecvError::Empty)),
            "H1 went inline: no FlushJob was dispatched"
        );
        // ...yet the waiter was released DURABLY by the inline barrier (I2).
        match reply_rx.try_recv() {
            Ok(ProduceOutcome::Appended(o)) => assert_eq!(o.get(), 0),
            other => panic!("the solo produce must ack via the inline barrier, got {other:?}"),
        }
        assert!(
            !engine.has_unsynced_records(),
            "the inline barrier covered the window"
        );
        assert_eq!(
            engine.durable_offset(),
            engine.append_head(),
            "durable == appended after the inline barrier"
        );
        assert!(pipeline.parked.is_empty(), "nothing left parked");
    }

    #[test]
    fn h1_guard_a_solo_pass_with_a_flight_outstanding_parks_and_never_inlines() {
        // The H1 GUARD (#1040): a solo produce whose pass ends WHILE a barrier is in flight must
        // NOT inline (an inline barrier there would serialize the actor behind the disk — the
        // exact coupling the pipeline removes): it parks, the pass end stages nothing (depth-1),
        // the durable head does not move, and the waiter acks only after ITS covering
        // completion — the flight's completion dispatches the successor that covers it.
        let mut engine = direct_engine();
        let (flusher, req_tx, done_rx) = held_flusher();
        let watchdog = ActorWatchdog::new(0);
        let clock = ManualClock::new();
        let cap_gate = ProduceCapGate::new(0);
        let mut pipeline = Pipeline {
            parked: VecDeque::new(),
            in_flight: None,
            next_seq: 0,
            req_tx: Some(req_tx),
            done_rx,
            flusher: None,
            max_dirty_bytes: 0,
            watchdog: &watchdog,
            clock: &clock,
            cap_gate: &cap_gate,
        };
        let (_cmd_tx, cmd_rx) = sync_channel::<Command<FaultFs<InMemoryFs>, ManualClock>>(4);
        // A burst window [A, B] dispatches the ONE FlushJob (held, un-completed, by the test).
        let (a_tx, a_rx) = sync_channel::<ProduceOutcome>(1);
        let (b_tx, b_rx) = sync_channel::<ProduceOutcome>(1);
        process_produce(&mut engine, &mut pipeline, &append(b"h1g-a"), Some(a_tx));
        process_produce(&mut engine, &mut pipeline, &append(b"h1g-b"), Some(b_tx));
        assert!(pipeline.finish_pass(&mut engine, &cmd_rx).is_none());
        assert!(pipeline.in_flight.is_some(), "the burst window dispatched");
        // A SOLO produce lands in a later pass while that flight is outstanding.
        let (c_tx, c_rx) = sync_channel::<ProduceOutcome>(1);
        process_produce(&mut engine, &mut pipeline, &append(b"h1g-c"), Some(c_tx));
        assert!(pipeline.finish_pass(&mut engine, &cmd_rx).is_none());
        // THE GUARD: no inline barrier ran (the durable head is pinned at zero — an inline
        // `commit_batch` would have advanced it and released everything), and no second job was
        // staged (depth-1: the job channel still holds exactly the FIRST window's job).
        assert_eq!(
            engine.durable_offset().get(),
            0,
            "no inline barrier may run behind an outstanding flight"
        );
        assert!(
            c_rx.try_recv().is_err(),
            "the solo produce parks behind the flight (never inline-acked)"
        );
        // Play the flusher for the FIRST window: its completion releases A and B, then
        // dispatches the successor covering C (the merge), which releases C when IT completes.
        flusher.complete_one_flight();
        pipeline.poll_completions(&mut engine);
        assert!(matches!(a_rx.try_recv(), Ok(ProduceOutcome::Appended(o)) if o.get() == 0));
        assert!(matches!(b_rx.try_recv(), Ok(ProduceOutcome::Appended(o)) if o.get() == 1));
        assert!(
            c_rx.try_recv().is_err(),
            "C acks only after ITS covering completion, not the first window's"
        );
        flusher.complete_one_flight();
        pipeline.poll_completions(&mut engine);
        assert!(matches!(c_rx.try_recv(), Ok(ProduceOutcome::Appended(o)) if o.get() == 2));
        assert!(pipeline.parked.is_empty());
        assert_eq!(engine.durable_offset(), engine.append_head());
    }

    #[test]
    fn h2_the_adaptive_linger_folds_a_late_arrival_into_the_first_dispatch() {
        // H2 ADAPTIVE FIRST-DISPATCH LINGER (#1040 regression fix, the wall-dominant-barrier
        // shape): at a burst pass end about to dispatch the FIRST barrier of a window (>= 2
        // waiters, nothing in flight), the actor lingers up to min(200 us, last_fsync_nanos/10)
        // draining late arrivals into the same window. With a rig-injected 4 ms barrier cost
        // (the F_FULLFSYNC class) and C already queued when the pass ends (deterministic: a
        // queued command beats any timeout), C folds into the window: ONE covering barrier acks
        // all three. An implementation without the linger dispatches [A, B] immediately and
        // pays a SECOND barrier for C — the sync-count assertion fails.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        engine.set_last_fsync_nanos_for_test(4_000_000);
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let before = control.sync_count();
        // Stage pass = [A, B, hold]; while held, queue C: at pass end the linger's first recv
        // finds C already waiting and folds it in before staging the ticket.
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let a = handle.produce_async(append(b"h2-a")).unwrap();
        let b = handle.produce_async(append(b"h2-b")).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        let c = handle.produce_async(append(b"h2-c-during-linger")).unwrap();
        release2.send(()).unwrap();
        for (name, rx, expected) in [("a", a, 0), ("b", b, 1), ("c", c, 2)] {
            match rx.recv_timeout(std::time::Duration::from_secs(10)) {
                Ok(ProduceOutcome::Appended(o)) => {
                    assert_eq!(o.get(), expected, "{name} at its offset");
                }
                other => panic!("{name} must ack Appended, got {other:?}"),
            }
        }
        assert_eq!(
            control.sync_count() - before,
            1,
            "ONE covering barrier for all three: the linger folded C into the first dispatch"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn h2_guard_the_linger_never_engages_behind_an_outstanding_flight() {
        // The H2 GUARD (#1040): the linger exists ONLY for a window's FIRST dispatch. With a
        // flight outstanding — the sustained-load steady state — a pass end must return
        // immediately and must NOT touch the command channel (under load the in-flight barrier
        // IS the batching window; a linger there would stall every pass by up to 200 us, the
        // multi-connection regression this guard pins). The injected barrier cost is huge, so a
        // mutant that lingers despite the flight would deterministically CONSUME the queued
        // command; the guard leaves it in the channel.
        let mut engine = direct_engine();
        engine.set_last_fsync_nanos_for_test(400_000_000);
        let (flusher, req_tx, done_rx) = held_flusher();
        let watchdog = ActorWatchdog::new(0);
        let clock = ManualClock::new();
        let cap_gate = ProduceCapGate::new(0);
        let mut pipeline = Pipeline {
            parked: VecDeque::new(),
            in_flight: None,
            next_seq: 0,
            req_tx: Some(req_tx),
            done_rx,
            flusher: None,
            max_dirty_bytes: 0,
            watchdog: &watchdog,
            clock: &clock,
            cap_gate: &cap_gate,
        };
        let (cmd_tx, cmd_rx) = sync_channel::<Command<FaultFs<InMemoryFs>, ManualClock>>(4);
        // First window [A, B]: dispatches (the linger may run here — first dispatch, empty
        // channel — costing at most its 200 us cap, then staging the job the test now holds).
        let (a_tx, a_rx) = sync_channel::<ProduceOutcome>(1);
        let (b_tx, b_rx) = sync_channel::<ProduceOutcome>(1);
        process_produce(&mut engine, &mut pipeline, &append(b"h2g-a"), Some(a_tx));
        process_produce(&mut engine, &mut pipeline, &append(b"h2g-b"), Some(b_tx));
        assert!(pipeline.finish_pass(&mut engine, &cmd_rx).is_none());
        assert!(pipeline.in_flight.is_some(), "the first window dispatched");
        // Sustained staged load: a NEXT burst pass [D, E] ends while the flight is outstanding,
        // with another command already queued behind it.
        let (d_tx, d_rx) = sync_channel::<ProduceOutcome>(1);
        let (e_tx, e_rx) = sync_channel::<ProduceOutcome>(1);
        process_produce(&mut engine, &mut pipeline, &append(b"h2g-d"), Some(d_tx));
        process_produce(&mut engine, &mut pipeline, &append(b"h2g-e"), Some(e_tx));
        let (queued_tx, _queued_rx) = sync_channel::<ProduceOutcome>(1);
        cmd_tx
            .send(Command::Produce {
                append: append(b"h2g-queued"),
                reply: queued_tx,
            })
            .unwrap();
        assert!(pipeline.finish_pass(&mut engine, &cmd_rx).is_none());
        // THE GUARD: the queued command was NOT consumed (no linger engaged behind the flight),
        // and no second barrier exists in any form (depth-1 job channel; durable head pinned).
        assert!(
            matches!(cmd_rx.try_recv(), Ok(Command::Produce { .. })),
            "the linger must never drain the channel while a flight is outstanding"
        );
        assert_eq!(engine.durable_offset().get(), 0, "no barrier completed");
        // Under sustained staged load the barrier COUNT is exactly one per window: the first
        // window's completion covers [D, E] with the second job, and nothing else is ever
        // dispatched for them.
        flusher.complete_one_flight();
        pipeline.poll_completions(&mut engine);
        assert!(matches!(a_rx.try_recv(), Ok(ProduceOutcome::Appended(_))));
        assert!(matches!(b_rx.try_recv(), Ok(ProduceOutcome::Appended(_))));
        assert!(d_rx.try_recv().is_err(), "D rides the SECOND window");
        flusher.complete_one_flight();
        pipeline.poll_completions(&mut engine);
        assert!(matches!(d_rx.try_recv(), Ok(ProduceOutcome::Appended(_))));
        assert!(matches!(e_rx.try_recv(), Ok(ProduceOutcome::Appended(_))));
        assert!(
            matches!(flusher.req_rx.try_recv(), Err(TryRecvError::Empty)),
            "exactly two jobs total: one per window, none from a linger"
        );
        assert!(pipeline.parked.is_empty());
    }

    #[test]
    fn a_completed_barrier_records_fsync_append_and_produce_ack_histograms() {
        // The prep-review mutation gaps (#1040): `complete_async_commit` must feed (1) the
        // engine's fsync histogram, (2) the registry's fsync-duration and append-latency
        // histograms, and (3) the #570 produce->ack histogram — one sample per completed barrier,
        // exactly as the inline `commit_batch` records. Deleting any of those observes here. The
        // window is a BURST (two produces, one covering barrier), so the sample really comes
        // from the flusher completion — a solo produce would take H1's inline barrier, whose
        // `commit_batch` records these histograms on its own.
        let (handle, actor, _control) = rig();
        let before = handle
            .with(|e| {
                (
                    e.fsync_histogram().count(),
                    e.registry().fsync_duration().count(),
                    e.registry().append_latency().count(),
                    e.registry().produce_ack_latency().count(),
                )
            })
            .unwrap();
        let (w1, w2) = stage_burst_pass(&handle, append(b"histograms-1"), append(b"histograms-2"));
        for rx in [w1, w2] {
            assert!(matches!(
                rx.recv_timeout(std::time::Duration::from_secs(10)),
                Ok(ProduceOutcome::Appended(_))
            ));
        }
        let after = handle
            .with(|e| {
                (
                    e.fsync_histogram().count(),
                    e.registry().fsync_duration().count(),
                    e.registry().append_latency().count(),
                    e.registry().produce_ack_latency().count(),
                )
            })
            .unwrap();
        assert_eq!(
            after.0 - before.0,
            1,
            "engine fsync histogram: one sample per barrier"
        );
        assert_eq!(
            after.1 - before.1,
            1,
            "registry fsync-duration histogram observed"
        );
        assert_eq!(
            after.2 - before.2,
            1,
            "registry append-latency histogram observed"
        );
        assert_eq!(
            after.3 - before.3,
            1,
            "registry produce->ack histogram observed (#570)"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn the_commit_tail_reaps_retention_per_completion() {
        // The retention-observable commit tail (#1040 mutation gap): the pipelined completion's
        // `commit_tail_after_async_completion` must keep running the consumer-safe retention
        // reap — with tiny segments, a byte cap, and every record acked, sealed segments are
        // reclaimed as later produces complete. Deleting the tail call leaves the directory
        // growing without bound and fails here. The post-ack produces ride BURST windows (real
        // flusher completions), so the only reap path for them IS the completion tail — a solo
        // produce would reap inside H1's inline `commit_batch` and mask the mutant.
        let cfg = EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig {
                max_segment_bytes: 256,
                ..LogConfig::default()
            },
            max_retained_bytes: 512,
            ..config()
        };
        let (handle, actor, _control, probe) = rig_probed_with(cfg);
        // Fill several segments.
        for i in 0..24u8 {
            assert!(matches!(
                handle.produce(append(&[i; 48])).unwrap(),
                ProduceOutcome::Appended(_)
            ));
        }
        // Ack everything so the consumer-safe floor allows reaping.
        handle
            .with(|e| {
                while let Ok(Poll::Message(d)) = e.poll_now_in("") {
                    let _ = e.ack_in("", &d.token);
                }
            })
            .unwrap();
        // More produces as burst windows: each COMPLETION's commit tail runs the reap.
        for i in 0..4u8 {
            let (w1, w2) = stage_burst_pass(
                &handle,
                append(&[0xf0 + 2 * i; 48]),
                append(&[0xf1 + 2 * i; 48]),
            );
            for rx in [w1, w2] {
                assert!(matches!(
                    rx.recv_timeout(std::time::Duration::from_secs(10)),
                    Ok(ProduceOutcome::Appended(_))
                ));
            }
        }
        let segments = probe
            .list()
            .unwrap()
            .into_iter()
            .filter(|n| is_segment_file(n))
            .count();
        assert!(
            segments <= 6,
            "the per-completion commit tail reaps acked, over-retention segments \
             (still {segments} segment files on disk)"
        );
        let _ = recover(handle, actor);
    }

    #[test]
    fn adv_review_h1_an_inline_tail_error_must_not_wedge_the_solo_waiter() {
        // ADVERSARIAL REVIEW INTERLEAVING 1 (#1040 H1): a SOLO produce takes H1's inline
        // `commit_batch`; the barrier (fdatasync) SUCCEEDS but the commit tail's retention reap
        // fails (injected unlink error) with the writer still WRITABLE. The no-wedge lemma
        // requires the covered waiter to be released (or fataled) at this pass-end reconcile
        // point; it must never stay parked on an otherwise idle broker.
        let cfg = EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig {
                max_segment_bytes: 256,
                ..LogConfig::default()
            },
            max_retained_bytes: 512,
            ..config()
        };
        let (handle, actor, control, _probe) = rig_probed_with(cfg);
        // Fill sealed segments; solo produces reap inline (floor = head: no touched groups).
        for i in 0..24u8 {
            assert!(matches!(
                handle.produce(append(&[i; 48])).unwrap(),
                ProduceOutcome::Appended(_)
            ));
        }
        // Arm: the NEXT unlink fails. Then drive solo produces until one's inline commit tail
        // attempts the failing remove.
        control.fail_remove_on(1);
        let base_removes = control.remove_count();
        let mut wedged = None;
        for i in 0..16u8 {
            let rx = handle.produce_async(append(&[0xa0 + i; 48])).unwrap();
            if rx
                .recv_timeout(std::time::Duration::from_millis(500))
                .is_err()
            {
                wedged = Some(rx);
                break;
            }
        }
        assert!(
            control.remove_count() > base_removes,
            "the armed remove was attempted (the tail error is real)"
        );
        if let Some(rx) = wedged {
            // The waiter is parked with its record DURABLE (the sync preceded the reap) and the
            // actor idle: no completion pending, no command queued. Prove the wedge is real and
            // only a LATER unrelated command unwedges it.
            let (_e, release) = send_blocking_job(&handle);
            release.send(()).unwrap();
            let late = rx.recv_timeout(std::time::Duration::from_secs(5));
            let _ = recover(handle, actor);
            panic!(
                "no-wedge lemma violated: the solo waiter wedged across an idle actor after the \
                 inline commit tail error, and was only released by a LATER unrelated command \
                 ({late:?})"
            );
        }
        let _ = recover(handle, actor);
    }

    #[test]
    fn adv_review_h1_unit_a_commit_batch_tail_error_leaves_the_solo_waiter_parked() {
        // UNIT probe of the commit_inline Err arm: reap error (injected unlink failure) after a
        // SUCCESSFUL sync, writer still writable. Inspect the Pipeline state directly.
        let cfg = EngineConfig {
            consume_longpoll_ms: 0,
            storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
            log: LogConfig {
                max_segment_bytes: 256,
                ..LogConfig::default()
            },
            max_retained_bytes: 512,
            ..config()
        };
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut engine = Engine::open(fs, ManualClock::new(), cfg).unwrap();
        let (_flusher, req_tx, done_rx) = held_flusher();
        let watchdog = ActorWatchdog::new(0);
        let clock = ManualClock::new();
        let cap_gate = ProduceCapGate::new(0);
        let mut pipeline = Pipeline {
            parked: VecDeque::new(),
            in_flight: None,
            next_seq: 0,
            req_tx: Some(req_tx),
            done_rx,
            flusher: None,
            max_dirty_bytes: 0,
            watchdog: &watchdog,
            clock: &clock,
            cap_gate: &cap_gate,
        };
        let (_cmd_tx, cmd_rx) = sync_channel::<Command<FaultFs<InMemoryFs>, ManualClock>>(4);
        // Fill sealed segments via solo inline passes.
        for i in 0..24u8 {
            let (tx, rx) = sync_channel::<ProduceOutcome>(1);
            process_produce(&mut engine, &mut pipeline, &append(&[i; 48]), Some(tx));
            assert!(pipeline.finish_pass(&mut engine, &cmd_rx).is_none());
            assert!(
                matches!(rx.try_recv(), Ok(ProduceOutcome::Appended(_))),
                "fill {i}"
            );
        }
        // Run solo passes; arm the unlink failure ONLY across the finish_pass window, so the
        // failing remove is provably the COMMIT TAIL's reap unlink (never a roll-time unlink).
        for i in 0..16u8 {
            let (tx, rx) = sync_channel::<ProduceOutcome>(1);
            process_produce(
                &mut engine,
                &mut pipeline,
                &append(&[0xa0 + i; 48]),
                Some(tx),
            );
            control.fail_remove_on(1);
            let target = control.remove_count() + 1;
            assert!(pipeline.finish_pass(&mut engine, &cmd_rx).is_none());
            let fired = control.remove_count() >= target;
            control.fail_remove_on(0);
            let reply = rx.try_recv();
            if fired {
                assert!(
                    reply.is_ok(),
                    "no-wedge lemma violated: after the inline commit tail error the solo waiter \
                     is still parked (parked={}) with the record durable (durable={} head={}) and \
                     the writer writable={}",
                    pipeline.parked.len(),
                    engine.durable_offset().get(),
                    engine.append_head().get(),
                    engine.log_is_writable()
                );
                return;
            }
            assert!(reply.is_ok(), "pre-fire iterations release normally");
        }
        panic!("the armed remove never fired: rig assumption broken");
    }

    #[test]
    fn adv_review_h2_a_shutdown_during_the_linger_is_exactly_once_after_dispatch() {
        // ADVERSARIAL REVIEW INTERLEAVING 2 (#1040 H2 x E6): a Shutdown lands in the command
        // channel while the pass end is inside the adaptive first-dispatch linger, and the
        // window's covering barrier is HELD in the closed sync gate. The linger must end on the
        // non-produce command, dispatch the window's barrier, carry the Shutdown into the next
        // pass exactly once, quiesce (drain the gated flight), ack the parked window durably,
        // reply Ok, and join the flusher: no lost command, no lost ack, no hang.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        // Engage the linger deterministically: a huge observed barrier cost caps it at 200us.
        engine.set_last_fsync_nanos_for_test(4_000_000);
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        control.close_sync_gate();
        // Stage pass = [A, B, hold]; while held, queue the Shutdown so the linger's FIRST recv
        // finds it already waiting (a queued command beats any timeout: deterministic).
        let (entered, release) = send_blocking_job(&handle);
        entered.recv().unwrap();
        let a = handle.produce_async(append(b"adv-h2-a")).unwrap();
        let b = handle.produce_async(append(b"adv-h2-b")).unwrap();
        let (entered2, release2) = send_blocking_job(&handle);
        release.send(()).unwrap();
        entered2.recv().unwrap();
        let (sd_tx, sd_rx) = sync_channel::<Result<(), EngineError>>(1);
        handle.tx.send(Command::Shutdown(sd_tx)).unwrap();
        release2.send(()).unwrap();
        // The linger ends on the Shutdown; the window's barrier dispatches INTO the closed gate.
        control.wait_for_sync_gate_entered(1);
        // While the flight is provably held: nothing acked (INV-1), no shutdown reply yet (the
        // quiesce is draining the flight).
        assert!(a.try_recv().is_err(), "A unacked while the barrier is held");
        assert!(b.try_recv().is_err(), "B unacked while the barrier is held");
        assert!(
            sd_rx.try_recv().is_err(),
            "the shutdown reply waits on the quiesce"
        );
        control.open_sync_gate();
        // Exactly-once, in order, durable: A then B ack Appended; the shutdown replies Ok once.
        assert!(matches!(
            a.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(ProduceOutcome::Appended(o)) if o.get() == 0
        ));
        assert!(matches!(
            b.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(ProduceOutcome::Appended(o)) if o.get() == 1
        ));
        assert!(matches!(
            sd_rx.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(Ok(()))
        ));
        let engine = actor.join().unwrap();
        assert_eq!(engine.durable_offset(), engine.append_head());
        assert!(!engine.has_unsynced_records());
        drop(handle);
    }
}
