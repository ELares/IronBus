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

use crate::engine::{Engine, EngineError};
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
#[derive(Clone, Debug)]
pub struct OwnedAppend {
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Record flags as raw bits (the codec normalizes `HAS_KEY`; unknown bits are preserved). The
    /// wire-only dedup bit is masked OFF by the session before this crosses the channel.
    pub flags: u8,
    /// The routing or ordering key (empty if none).
    pub key: Vec<u8>,
    /// The record headers blob (empty if none).
    pub headers: Vec<u8>,
    /// The record payload.
    pub payload: Vec<u8>,
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
    pub producer_id: Vec<u8>,
    /// The producer's monotonic epoch (the fencing token).
    pub epoch: u64,
    /// The idempotency key the broker deduplicates on (never the body).
    pub msg_id: Vec<u8>,
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
    let join = std::thread::Builder::new()
        .name("ironbus-append-actor".to_string())
        .spawn(move || run_actor(engine, &rx, gather_micros))
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
        },
        join,
    )
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
        .filter(|c| matches!(c, Command::Produce { .. }))
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
                Command::Produce { append, reply } => {
                    // FIRE-AND-FORGET (QoS-0, #11, #402) admission, decided FIRST and only for a
                    // produce the client marked fire-and-forget. The per-connection token bucket
                    // (#336) caps this un-credited tier: an exhausted bucket DROPS the produce
                    // (without acking and without appending), because the QoS-0 producer accepts
                    // loss by contract. The bucket governs ONLY this tier, so it NEVER touches the
                    // at-least-once path; a non-fire-and-forget produce skips this entirely. When
                    // disabled (the default rate of 0), the bucket always admits, so a QoS-0 produce
                    // under an unconfigured broker is appended-but-not-acked, never dropped.
                    if append.fire_and_forget {
                        let payload_bytes = u64::try_from(append.payload.len()).unwrap_or(u64::MAX);
                        if !engine.fire_and_forget_admit(payload_bytes) {
                            // Dropped by the bucket (counted in `ironbus_fire_and_forget_shed_total`):
                            // the producer fired and forgot, so send NO frame and keep the session.
                            let _ = reply.send(ProduceOutcome::FireAndForgetDropped);
                            continue;
                        }
                    }
                    // CoDel controlled-delay shed (#68), decided BEFORE the append so it rejects only
                    // NEW work and never drops an already-accepted record (I2 holds). The sojourn is
                    // `now - enqueue` on the monotonic clock seam; a sustained admission delay above
                    // TARGET sheds this produce. When CoDel is disabled (the default) this is always
                    // false, so the append path is byte-for-byte unchanged. A fire-and-forget produce
                    // shed by CoDel also gets no ack (the session maps the Shed outcome to no frame
                    // for a fire-and-forget pub), so the contract holds either way.
                    if engine.codel_admit(append.enqueue_monotonic_nanos) {
                        // The shed counts as a request the broker shed (the retry-budget signal), then
                        // replies a stable "shed under load" outcome; the connection stays open.
                        engine.retry_budget_record_shed();
                        let _ = reply.send(ProduceOutcome::Shed);
                        continue;
                    }
                    // fsync-HEADROOM admission (#378), decided BEFORE the append so it rejects only
                    // NEW work and never drops an already-accepted record (I2 / no-data-loss hold). It
                    // bounds the un-fsynced (buffered-but-not-durable) write frontier to the configured
                    // headroom, reusing the engine's `unsynced_bytes()` frontier (the #341 tracking).
                    // A no-op when the headroom is disabled (the default), so the append path is
                    // byte-for-byte unchanged for a broker that has not opted in.
                    if engine.wal_headroom_enabled() {
                        // The new record's LOGICAL bytes (key + headers + payload), the same units the
                        // un-fsynced frontier is measured in.
                        let record_bytes = u64::try_from(
                            append.key.len() + append.headers.len() + append.payload.len(),
                        )
                        .unwrap_or(u64::MAX);
                        if !engine.wal_headroom_admit(record_bytes) {
                            // The headroom is exhausted: DRAIN first. `flush_pending` issues the ONE
                            // group-commit barrier for the parked batch. Under the default `sync` level
                            // (and a DUE `interval` window) that is a real `fdatasync`, so it resets the
                            // un-fsynced frontier to `0` and the record is then admitted by the no-wedge
                            // floor: the headroom THROTTLES (drain-then-admit), never sheds, never loses.
                            // Under a relaxed `async`/`none` level a commit DEFERS the fsync, so the
                            // frontier does NOT drain; the re-check still fails and the new produce is
                            // SHED to keep the loss window within the headroom. The already-buffered
                            // records are untouched (they stay durable-pending and are made durable by
                            // their level's barrier), so only this NEW produce is rejected.
                            flush_pending(&mut engine, &mut pending);
                            if !engine.wal_headroom_admit(record_bytes) {
                                // The drain could not free the headroom (a relaxed level deferring the
                                // fsync): shed this NEW produce with the typed, self-announcing signal,
                                // count it (a shed is never silent), and keep the session open.
                                engine.record_wal_headroom_shed();
                                engine.retry_budget_record_shed();
                                let _ = reply.send(ProduceOutcome::WalHeadroomShed);
                                continue;
                            }
                        }
                    }
                    // Append (write, NO fsync) and park the reply; the covering fsync is issued once
                    // for the whole batch by `flush_pending` below.
                    let view = Append {
                        timestamp_ms: append.timestamp_ms,
                        flags: ironbus_core::types::RecordFlags::from_bits(append.flags),
                        key: &append.key,
                        headers: &append.headers,
                        payload: &append.payload,
                    };
                    match engine.append_no_sync_dedup(&view, dedup_request(&append)) {
                        Ok(crate::engine::AppendOutcome::Appended(offset)) => {
                            // An accepted produce feeds the broker-side retry-budget accept count
                            // (#69), so the observed retry ratio stays meaningful under load.
                            engine.retry_budget_record_accept();
                            // A fire-and-forget (QoS-0) produce is appended durably exactly like a
                            // normal produce (covering group-commit fsync) but gets NO `PubAck`, so
                            // park it as the no-ack outcome; a normal produce parks as `Appended`.
                            let outcome = if append.fire_and_forget {
                                PendingOutcome::FireAndForgetAppended(offset)
                            } else {
                                PendingOutcome::Appended(offset)
                            };
                            pending.push(PendingProduce { outcome, reply });
                        }
                        // A BENIGN dedup hit (#33): nothing was appended, but its original offset may
                        // be an id recorded earlier in THIS uncommitted batch, so PARK the reply behind
                        // the covering fsync too (I2). On a sync failure the batch is non-durable and
                        // every parked reply, hit or fresh, becomes Fatal, exactly as for a fresh append.
                        Ok(crate::engine::AppendOutcome::Duplicate(offset)) => {
                            pending.push(PendingProduce {
                                outcome: PendingOutcome::Duplicate(offset),
                                reply,
                            });
                        }
                        // A stale-epoch fence (#33): nothing was written, so reply immediately; it does
                        // not join the durable batch.
                        Ok(crate::engine::AppendOutcome::Fenced { .. }) => {
                            let _ = reply.send(ProduceOutcome::Fenced);
                        }
                        // A shed or a hard error is known WITHOUT the sync (nothing was written), so
                        // reply immediately; it does not join the durable batch.
                        Err(e) if e.is_at_capacity() => {
                            // A byte-cap shed is a request the broker shed (the retry-budget signal).
                            engine.retry_budget_record_shed();
                            let _ = reply.send(ProduceOutcome::AtCapacity);
                        }
                        Err(e) if e.is_fatal() => {
                            let _ = reply.send(ProduceOutcome::Fatal(e));
                        }
                        Err(e) => {
                            let _ = reply.send(ProduceOutcome::Failed(e));
                        }
                    }
                }
                // A non-produce job must observe a consistent durable head and keep the total durable
                // order, so flush the parked produces (one fsync) BEFORE it runs.
                Command::Run(job) => {
                    flush_pending(&mut engine, &mut pending);
                    job(&mut engine);
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
    reply: SyncSender<ProduceOutcome>,
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
                let outcome = match p.outcome {
                    PendingOutcome::Appended(offset) => ProduceOutcome::Appended(offset),
                    // A dedup hit replies PubAckDuplicate now that the covering batch is durable (#33).
                    PendingOutcome::Duplicate(offset) => ProduceOutcome::AppendedDuplicate(offset),
                    // A fire-and-forget produce is durable now, but the session sends NO PubAck (#11).
                    PendingOutcome::FireAndForgetAppended(offset) => {
                        ProduceOutcome::FireAndForgetAppended(offset)
                    }
                };
                let _ = p.reply.send(outcome);
            }
        }
        Err(e) => {
            // The fsync froze the writer: NONE of the batch is durable. Tell every producer it was a
            // fatal storage error so each ends its session, exactly as the pre-actor per-produce path
            // did when its `log.sync()?` surfaced `WriterFrozen`. The first member carries the real
            // error; the rest carry an equivalent frozen-writer error (the freeze is the same event).
            let mut first = Some(e);
            for p in pending.drain(..) {
                let err = first.take().unwrap_or(EngineError::Storage(
                    ironbus_storage::segment::StorageError::WriterFrozen,
                ));
                let _ = p.reply.send(ProduceOutcome::Fatal(err));
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
            key: Vec::new(),
            headers: Vec::new(),
            payload: payload.to_vec(),
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
            key: Vec::new(),
            headers: Vec::new(),
            payload: payload.to_vec(),
            dedup: Some(OwnedDedup {
                producer_id: producer_id.to_vec(),
                epoch,
                msg_id: msg_id.to_vec(),
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
