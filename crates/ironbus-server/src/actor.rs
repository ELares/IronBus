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
//! owned engine; the actor flushes any pending produce batch (one fsync) BEFORE a job runs, so a job
//! observes a consistent durable head and the total durable order is unchanged.
//!
//! ## Invariants
//!
//! - I2 (ack-implies-durable): a [`Command::Produce`] reply is sent only AFTER the covering
//!   `commit_batch` returns, so a `PubAck` never precedes the fsync that made the record durable.
//! - Single total durable order: the actor assigns offsets and appends serially in arrival order.
//! - No lost replies / no deadlock: every command gets exactly one reply; a closed channel is a typed
//!   [`ActorGone`], never a panic, so neither side hangs forever if the other dies.

use crate::engine::{DiskFullPolicy, Engine, EngineError};
use crate::produce_gate::ProduceCapGate;
use bytes::Bytes;
use ironbus_core::clock::Clock;
use ironbus_core::types::Offset;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Append;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

/// The default bound on the actor command channel: the most produce/engine commands that may be
/// in flight before a sender blocks (backpressure). Sized for the edge box's bounded connection
/// count: large enough that a healthy burst does not stall, small enough that a wedged actor bounds
/// the queued work rather than buffering without limit. It does not cap the GROUP size (the actor
/// drains everything available each pass); it caps the un-drained backlog.
pub const DEFAULT_CHANNEL_BOUND: usize = 1024;

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
    /// A stale-epoch FENCE (#33): a zombie session reusing an old `producer_id` presented an epoch
    /// below the broker's known high-water. Reply an error, keep the session (the producer can
    /// re-handshake with a fresh epoch).
    Fenced,
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
    },
}

impl ProduceSubmission {
    /// Awaits the produce outcome. For a [`ProduceSubmission::Pending`] submission this blocks until
    /// the actor has issued the covering `commit_batch` and released the reply (I2); for a
    /// [`ProduceSubmission::Ready`] one it returns immediately.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the actor exited before replying, so the session ends the
    /// connection cleanly rather than hanging on a dead actor.
    pub fn wait(self) -> Result<ProduceOutcome, ActorGone> {
        match self {
            ProduceSubmission::Ready(outcome) => Ok(outcome),
            ProduceSubmission::Pending { channel, pool } => {
                // Recv the ONE outcome the actor sent after the covering fsync (I2); the original `tx`
                // half still lives in `channel`, so a clean recv yields the value rather than seeing a
                // spurious disconnect. ActorGone only if the actor dropped its cloned `tx` un-sent
                // (it exited before replying), which closes the channel.
                let outcome = channel.rx.recv().map_err(|_| ActorGone)?;
                // The channel is now drained and ready: return the intact pair to the pool so the next
                // publish reuses it instead of allocating a fresh one (#475).
                pool_return(&pool, channel);
                Ok(outcome)
            }
        }
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
}

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
        }
    }
}

impl<F: Filesystem + 'static, C: Clock + 'static> EngineHandle<F, C> {
    /// The static per-consumer credit caps (#292): `(consumer_credit, consumer_credit_bytes)`,
    /// snapshotted from the engine config at `spawn_actor`. Read by the `Connect` handshake to
    /// negotiate the per-consumer credit WITHOUT a round-trip through the actor (so a stalled produce
    /// cannot head-of-line-block a handshake, #177). `.0` is floored to >= 1; `.1` of `0` is unlimited.
    #[must_use]
    pub fn consumer_credit_caps(&self) -> (u32, u64) {
        self.consumer_credit_caps
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

    /// Runs `job` on the engine and returns its result.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the engine is no longer reachable.
    fn with<R, J>(&self, job: J) -> Result<R, ActorGone>
    where
        R: Send + 'static,
        J: FnOnce(&mut Engine<F, C>) -> R + Send + 'static;

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
}

impl<F: Filesystem + 'static, C: Clock + Clone + 'static> EngineAccess<F, C>
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
}

/// Borrows an [`OwnedAppend`]'s dedup identity (#33) as an engine [`DedupRequest`], or `None` for a
/// no-dedup produce. The borrow is valid for the duration of the engine call (the owned bytes outlive
/// it), so the engine sees the `producer_id` / `epoch` / `msg_id` without copying again.
fn dedup_request(append: &OwnedAppend) -> Option<crate::engine::DedupRequest<'_>> {
    append.dedup.as_ref().map(|d| crate::engine::DedupRequest {
        producer_id: &d.producer_id,
        epoch: d.epoch,
        msg_id: &d.msg_id,
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
    match engine.append_no_sync_dedup(&view, dedup_request(append)) {
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
    C: Clock + Clone + 'static,
{
    spawn_actor_with_gather(engine, channel_bound, 0)
}

/// Like [`spawn_actor`] with a bounded GROUP-COMMIT GATHER (#454, #472). With `gather_micros`
/// of 0 the actor is byte-identical to the historical drain (this is what [`spawn_actor`] passes,
/// and what an operator gets from `--commit-gather-us 0`; the shipped CLI default is a small
/// non-zero window so out-of-the-box durable produce batches fsyncs, #472). With a window set, a
/// drain pass that already holds at
/// least TWO produces (evidence of a pipelining publisher; a single-produce pass never gathers,
/// so an unpipelined producer pays no window) keeps collecting commands for up to the window
/// before committing, so a pipelined publisher's whole in-flight window lands under ONE covering
/// fsync instead of self-sizing slivers (measured on the reference edge box: a 512-record client window committed as ~12
/// records per fsync, because the drain only sees what arrived during the PREVIOUS batch's
/// fsync). Acks keep their fsynced-durable meaning; the knob trades up to the window in added
/// commit latency under produce bursts for fewer, larger barriers (the `MySQL`
/// `binlog_group_commit_sync_delay` / `PostgreSQL` `commit_delay` precedent).
///
/// # Panics
/// Panics if the OS refuses to spawn the actor thread, exactly as [`spawn_actor`]: a STARTUP step,
/// not a request path, so the no-panic bar for the library hot paths is untouched.
pub fn spawn_actor_with_gather<F, C>(
    engine: Engine<F, C>,
    channel_bound: usize,
    gather_micros: u64,
) -> (EngineHandle<F, C>, std::thread::JoinHandle<Engine<F, C>>)
where
    F: Filesystem + 'static,
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
    let join = std::thread::Builder::new()
        .name("ironbus-append-actor".to_string())
        .spawn(move || run_actor(engine, &rx, gather_micros, &actor_gate))
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
        },
        join,
    )
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

/// The bounded group-commit gather (#454): keeps collecting commands into `commands` for up to
/// `gather_micros`, so the caller's batch covers a pipelined publisher's whole in-flight window
/// under ONE fsync. Wall-clock (`std::time::Instant`) is correct here: the gather is a real-time
/// IO batching decision on the actor thread, outside the engine's deterministic clock seam (the
/// sim drives the `Engine` directly and never runs this loop). A `Shutdown` gathered mid-window is
/// processed in order after the batch, exactly as if it had arrived in the same burst. A
/// disconnect ends the gather early; the caller's batch then processes and the next outer `recv`
/// observes the disconnect.
///
/// A pass holding FEWER THAN TWO produces never gathers: an unpipelined producer (one in-flight
/// produce, awaiting each ack) would otherwise stall the full window on every send and gain
/// nothing, since its next produce cannot arrive until this one is acked; and a produce-less
/// control pass (acks, polls, subscribes) has no fsync to amortize.
fn gather_commands<F, C>(
    commands: &mut Vec<Command<F, C>>,
    rx: &Receiver<Command<F, C>>,
    gather_micros: u64,
) where
    F: Filesystem,
    C: Clock + Clone,
{
    let produces = commands
        .iter()
        .filter(|c| matches!(c, Command::Produce { .. } | Command::ProduceNoReply { .. }))
        .count();
    if produces < 2 {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_micros(gather_micros);
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        if left.is_zero() {
            return;
        }
        let Ok(cmd) = rx.recv_timeout(left) else {
            return;
        };
        commands.push(cmd);
        while let Ok(c) = rx.try_recv() {
            commands.push(c);
        }
    }
}

/// The actor's run loop. It blocks for one command, then DRAINS every command already queued
/// (`try_recv`) into the same pass so a burst of produces group-commits together. Produces are
/// appended (no sync) and their replies parked; a non-produce job or the end of the drain triggers
/// the ONE `commit_batch` that covers the parked produces, after which their replies are released.
/// Returns the engine on exit so a caller can recover it.
fn run_actor<F, C>(
    mut engine: Engine<F, C>,
    rx: &Receiver<Command<F, C>>,
    gather_micros: u64,
    cap_gate: &ProduceCapGate,
) -> Engine<F, C>
where
    F: Filesystem,
    C: Clock + Clone,
{
    // Produces appended this pass but not yet durable: each parked reply is released only after the
    // single covering `commit_batch`, so a `PubAck` never precedes its fsync (I2).
    let mut pending: Vec<PendingProduce> = Vec::new();
    loop {
        // Block for the next command; a disconnect (the last handle dropped) ends the loop after a
        // final drain so no acked-but-not-durable record is lost.
        let Ok(first) = rx.recv() else {
            flush_pending(&mut engine, &mut pending);
            return engine;
        };
        let mut commands = vec![first];
        // Drain everything immediately available so a concurrent burst of produces forms one group.
        while let Ok(cmd) = rx.try_recv() {
            commands.push(cmd);
        }
        // The opt-in bounded gather (#454); a no-op unless configured AND this pass already
        // shows a pipelining publisher (two or more produces).
        if gather_micros > 0 {
            gather_commands(&mut commands, rx, gather_micros);
        }
        for cmd in commands {
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
                    return engine;
                }
            }
        }
        // The drain is exhausted: commit the parked produces with the ONE covering fsync, then release
        // their replies. This is the steady-state group commit boundary.
        flush_pending(&mut engine, &mut pending);
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

/// Runs one produce's admission + append on the actor, parking its reply behind the covering fsync or
/// replying/dropping it immediately on a non-appended disposition.
///
/// `reply` is `Some` for an at-least-once produce (Level 1, and Level 2 falling back to Level 1) and
/// `None` for a LEVEL-0 (no-ack / fire-and-forget) produce (#495). When `Some`, this is byte-for-byte
/// the historical produce path: every disposition sends exactly the frame it always did. When `None`,
/// every disposition is a SILENT drop with no frame (the L0 producer fired and forgot), but the
/// admission and append are IDENTICAL — an appended L0 still joins the batch and is covered by the one
/// `commit_batch` (single-writer storage / single total order), it just parks `None`.
///
/// A `None` (Level-0) produce always has `append.fire_and_forget == true` (the session sets it for the
/// canonical fire-and-forget bit AND the level-bit Level-0 encoding), so the fire-and-forget token
/// bucket governs it exactly as it governed the historical faf path — this is that path generalized.
fn process_produce<F, C>(
    engine: &mut Engine<F, C>,
    pending: &mut Vec<PendingProduce>,
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
            // The headroom is exhausted: DRAIN first. `flush_pending` issues the ONE group-commit
            // barrier for the parked batch. Under the default `sync` level (and a DUE `interval`
            // window) that is a real `fdatasync`, so it resets the un-fsynced frontier to `0` and the
            // record is then admitted by the no-wedge floor: the headroom THROTTLES (drain-then-admit),
            // never sheds, never loses. Under a relaxed `async`/`none` level a commit DEFERS the fsync,
            // so the frontier does NOT drain; the re-check still fails and the new produce is SHED to
            // keep the loss window within the headroom. The already-buffered records are untouched (they
            // stay durable-pending and are made durable by their level's barrier), so only this NEW
            // produce is rejected.
            flush_pending(engine, pending);
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
    match engine.append_no_sync_dedup(&view, dedup_request(append)) {
        Ok(crate::engine::AppendOutcome::Appended(offset)) => {
            // An accepted produce feeds the broker-side retry-budget accept count (#69), so the
            // observed retry ratio stays meaningful under load.
            engine.retry_budget_record_accept();
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
            pending.push(PendingProduce { outcome, reply });
        }
        // A BENIGN dedup hit (#33): nothing was appended, but its original offset may be an id recorded
        // earlier in THIS uncommitted batch, so PARK the reply behind the covering fsync too (I2). On a
        // sync failure the batch is non-durable and every parked reply, hit or fresh, becomes Fatal,
        // exactly as for a fresh append.
        Ok(crate::engine::AppendOutcome::Duplicate(offset)) => {
            pending.push(PendingProduce {
                outcome: PendingOutcome::Duplicate(offset),
                reply,
            });
        }
        // A stale-epoch fence (#33): nothing was written, so reply immediately; it does not join the
        // durable batch.
        Ok(crate::engine::AppendOutcome::Fenced { .. }) => {
            send_outcome(&reply, ProduceOutcome::Fenced);
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
                let outcome = match p.outcome {
                    PendingOutcome::Appended(offset) => ProduceOutcome::Appended(offset),
                    // A dedup hit replies PubAckDuplicate now that the covering batch is durable (#33).
                    PendingOutcome::Duplicate(offset) => ProduceOutcome::AppendedDuplicate(offset),
                    // A fire-and-forget produce is durable now, but the session sends NO PubAck (#11).
                    PendingOutcome::FireAndForgetAppended(offset) => {
                        ProduceOutcome::FireAndForgetAppended(offset)
                    }
                };
                let _ = reply.send(outcome);
            }
        }
        Err(e) => {
            // The fsync froze the writer: NONE of the batch is durable. Tell every producer it was a
            // fatal storage error so each ends its session, exactly as the pre-actor per-produce path
            // did when its `log.sync()?` surfaced `WriterFrozen`. The first member carries the real
            // error; the rest carry an equivalent frozen-writer error (the freeze is the same event).
            // A LEVEL-0 (no-ack) parked produce has no reply channel (#495), so it is SKIPPED WITHOUT
            // consuming the real error — the fired-and-forgotten producer is not listening, and the
            // first at-least-once member must still receive the true error.
            let mut first = Some(e);
            for p in pending.drain(..) {
                let Some(reply) = p.reply else {
                    continue;
                };
                let err = first.take().unwrap_or(EngineError::Storage(
                    ironbus_storage::segment::StorageError::WriterFrozen,
                ));
                let _ = reply.send(ProduceOutcome::Fatal(err));
            }
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

    fn config() -> EngineConfig {
        EngineConfig {
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
            // Compression OFF (#430): the actor tests pin the historical byte-identical image;
            // the engine compression tests cover the lz4 path.
            compression: ironbus_core::compress::Codec::None,
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
            dedup: None,
            enqueue_monotonic_nanos: 0,
            fire_and_forget: false,
        }
    }

    /// A FIRE-AND-FORGET (QoS-0, #11) owned produce, for the actor-level fire-and-forget tier tests.
    fn append_faf(payload: &[u8]) -> OwnedAppend {
        OwnedAppend {
            fire_and_forget: true,
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
            dedup: Some(OwnedDedup {
                producer_id: Bytes::copy_from_slice(producer_id),
                epoch,
                msg_id: Bytes::copy_from_slice(msg_id),
            }),
            enqueue_monotonic_nanos: 0,
            fire_and_forget: false,
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
                ProduceSubmission::Pending { channel, pool } => {
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
    fn a_commit_gather_window_collects_a_spaced_produce_into_the_pipelined_batch() {
        // The opt-in group-commit gather (#454): a drain pass holding TWO OR MORE produces (a
        // pipelining publisher) keeps gathering, so a produce that arrives WHILE the actor is
        // gathering joins the in-progress batch instead of paying its own fsync. The sync gate
        // gives a deterministic setup: a primer produce parks the actor on its covering fsync,
        // TWO produces queue behind it (so the next drain pass proves pipelining), the gate
        // opens, and a fourth produce sent mid-gather must land in the SAME batch: exactly TWO
        // syncs total (the primer's, then ONE covering the gathered three).
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), config()).unwrap();
        let (handle, actor) = spawn_actor_with_gather(engine, DEFAULT_CHANNEL_BOUND, 800_000);
        control.close_sync_gate();
        let primer = handle.produce_async(append(b"primer")).unwrap();
        control.wait_for_sync_gate_entered(1);
        let queued_a = handle.produce_async(append(b"queued-a")).unwrap();
        let queued_b = handle.produce_async(append(b"queued-b")).unwrap();
        let before = control.sync_count();
        control.open_sync_gate();
        match primer.recv().unwrap() {
            ProduceOutcome::Appended(o) => assert_eq!(o.get(), 0),
            other => panic!("expected Appended primer, got {other:?}"),
        }
        // The primer is acked, so the actor is in its next pass: it drained the two queued
        // produces (>= 2, the gather engages) and is now collecting. Real-time spacing is the
        // point under test (the gather is a wall-clock IO batching decision, outside the
        // ManualClock seam), with a 16x margin between the spacing and the window so a slow CI
        // runner cannot expire the gather before the late produce lands.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let late = handle.produce_async(append(b"gathered-late")).unwrap();
        let mut offsets = Vec::new();
        for reply in [queued_a, queued_b, late] {
            match reply.recv().unwrap() {
                ProduceOutcome::Appended(o) => offsets.push(o.get()),
                other => panic!("expected Appended, got {other:?}"),
            }
        }
        assert_eq!(offsets, vec![1, 2, 3], "all three appended in send order");
        // `sync_count` ticks when a sync ENTERS the gate, so the primer's (parked) sync is
        // already inside `before`; the gathered batch of three adds exactly ONE more.
        assert_eq!(
            control.sync_count() - before,
            1,
            "ONE covering fsync for the gathered batch of three, none for the late produce"
        );
        drop(handle);
        actor.join().unwrap();
    }

    #[test]
    fn a_single_inflight_produce_never_pays_the_gather_window() {
        // The no-tax rule (#454): a drain pass holding ONE produce never gathers, so an
        // unpipelined producer (send, await ack, send) on a gather-enabled broker keeps the
        // historical ack latency. With an 800 ms window, a gathered single produce could not ack
        // in under 800 ms; the bound asserts the ack came back far sooner.
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
}
