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

/// The default bound on the actor command channel: the most produce/engine commands that may be
/// in flight before a sender blocks (backpressure). Sized for the edge box's bounded connection
/// count: large enough that a healthy burst does not stall, small enough that a wedged actor bounds
/// the queued work rather than buffering without limit. It does not cap the GROUP size (the actor
/// drains everything available each pass); it caps the un-drained backlog.
pub const DEFAULT_CHANNEL_BOUND: usize = 1024;

/// A produce request's payload, OWNED so it can cross the channel to the actor (the wire [`Append`]
/// borrows the connection's input buffer, which the actor cannot hold). The actor borrows it back as
/// an [`Append`] to append it. Fields mirror [`Append`].
#[derive(Clone, Debug)]
pub struct OwnedAppend {
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Record flags as raw bits (the codec normalizes `HAS_KEY`; unknown bits are preserved).
    pub flags: u8,
    /// The routing or ordering key (empty if none).
    pub key: Vec<u8>,
    /// The record headers blob (empty if none).
    pub headers: Vec<u8>,
    /// The record payload.
    pub payload: Vec<u8>,
}

/// The outcome of a produce, mapped to the wire reply by the session. It carries enough to
/// reproduce the pre-actor `handle_pub` behavior exactly: a success with the assigned offset, the
/// non-fatal drop-new shed, a fatal storage error (which ends the session), or a transient failure.
#[derive(Debug)]
pub enum ProduceOutcome {
    /// The record is durable (the covering `commit_batch` completed); reply `PubAck` with this offset.
    Appended(Offset),
    /// The durable-log byte cap shed (drop-new): reply a stable "at capacity" error, keep the session.
    AtCapacity,
    /// A fatal storage error (a frozen writer): reply an error AND end the session.
    Fatal(EngineError),
    /// A transient produce failure: reply a generic error, keep the session.
    Failed(EngineError),
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
}

// Derived `Clone` would demand `F: Clone, C: Clone`; the handle only clones the `SyncSender`, so it
// is cloneable for any `F`/`C`.
impl<F: Filesystem, C: Clock> Clone for EngineHandle<F, C> {
    fn clone(&self) -> Self {
        EngineHandle {
            tx: self.tx.clone(),
        }
    }
}

impl<F: Filesystem + 'static, C: Clock + 'static> EngineHandle<F, C> {
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
        let (reply_tx, reply_rx) = sync_channel(1);
        self.tx
            .send(Command::Produce {
                append,
                reply: reply_tx,
            })
            .map_err(|_| ActorGone)?;
        reply_rx.recv().map_err(|_| ActorGone)
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

    /// Runs `job` on the engine and returns its result.
    ///
    /// # Errors
    /// Returns [`ActorGone`] if the engine is no longer reachable.
    fn with<R, J>(&self, job: J) -> Result<R, ActorGone>
    where
        R: Send + 'static,
        J: FnOnce(&mut Engine<F, C>) -> R + Send + 'static;
}

impl<F: Filesystem + 'static, C: Clock + 'static> EngineAccess<F, C> for EngineHandle<F, C> {
    fn produce(&self, append: OwnedAppend) -> Result<ProduceOutcome, ActorGone> {
        EngineHandle::produce(self, append)
    }

    fn with<R, J>(&self, job: J) -> Result<R, ActorGone>
    where
        R: Send + 'static,
        J: FnOnce(&mut Engine<F, C>) -> R + Send + 'static,
    {
        EngineHandle::with(self, job)
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
}

/// Performs ONE one-message group commit (`append_no_sync` + `commit_batch`) on `engine`, mapping the
/// result to a [`ProduceOutcome`] exactly as the actor does, so the test-only direct access paths
/// preserve I2 (the outcome reflects the covering fsync) and the shed/freeze taxonomy.
#[cfg(test)]
fn produce_once<F: Filesystem, C: Clock + Clone>(
    engine: &mut Engine<F, C>,
    append: &OwnedAppend,
) -> ProduceOutcome {
    let view = Append {
        timestamp_ms: append.timestamp_ms,
        flags: ironbus_core::types::RecordFlags::from_bits(append.flags),
        key: &append.key,
        headers: &append.headers,
        payload: &append.payload,
    };
    match engine.append_no_sync(&view) {
        Ok(offset) => match engine.commit_batch() {
            Ok(()) => ProduceOutcome::Appended(offset),
            Err(e) => ProduceOutcome::Fatal(e),
        },
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
    let (tx, rx) = sync_channel::<Command<F, C>>(channel_bound.max(1));
    let join = std::thread::Builder::new()
        .name("ironbus-append-actor".to_string())
        .spawn(move || run_actor(engine, &rx))
        // A thread-spawn failure at startup is unrecoverable for the server, but the no-panic bar is
        // for the LIBRARY hot paths; spawning the single actor at boot is a startup step. Surface it
        // by propagating the panic only here (boot), never on a request path.
        .expect("spawning the append actor thread");
    (EngineHandle { tx }, join)
}

/// The actor's run loop. It blocks for one command, then DRAINS every command already queued
/// (`try_recv`) into the same pass so a burst of produces group-commits together. Produces are
/// appended (no sync) and their replies parked; a non-produce job or the end of the drain triggers
/// the ONE `commit_batch` that covers the parked produces, after which their replies are released.
/// Returns the engine on exit so a caller can recover it.
fn run_actor<F, C>(mut engine: Engine<F, C>, rx: &Receiver<Command<F, C>>) -> Engine<F, C>
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
        for cmd in commands {
            match cmd {
                Command::Produce { append, reply } => {
                    // Append (write, NO fsync) and park the reply; the covering fsync is issued once
                    // for the whole batch by `flush_pending` below.
                    let view = Append {
                        timestamp_ms: append.timestamp_ms,
                        flags: ironbus_core::types::RecordFlags::from_bits(append.flags),
                        key: &append.key,
                        headers: &append.headers,
                        payload: &append.payload,
                    };
                    match engine.append_no_sync(&view) {
                        Ok(offset) => pending.push(PendingProduce {
                            outcome: PendingOutcome::Appended(offset),
                            reply,
                        }),
                        // A shed or a hard error is known WITHOUT the sync (nothing was written), so
                        // reply immediately; it does not join the durable batch.
                        Err(e) if e.is_at_capacity() => {
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
    }
}

/// One produce parked in the current batch: its known outcome and the channel to reply on once the
/// covering `commit_batch` has made it durable.
struct PendingProduce {
    outcome: PendingOutcome,
    reply: SyncSender<ProduceOutcome>,
}

/// The pre-sync outcome of a parked produce. Only `Appended` records reach here (a shed or hard error
/// replies immediately and never parks), so the post-sync mapping is a success-or-freeze decision.
enum PendingOutcome {
    /// Appended at this offset, pending the covering fsync.
    Appended(Offset),
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
                let PendingOutcome::Appended(offset) = p.outcome;
                let _ = p.reply.send(ProduceOutcome::Appended(offset));
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
    fn a_single_produce_still_issues_exactly_one_sync() {
        // The lone-produce path is a one-message group commit: exactly one fsync, mirroring the old
        // per-produce behavior, so the durable order and sync accounting are unchanged for N=1.
        let (handle, actor, control) = rig();
        let before = control.sync_count();
        handle.produce(append(b"solo")).unwrap();
        assert_eq!(control.sync_count() - before, 1, "one produce, one fsync");
        let _ = recover(handle, actor);
    }
}
