// SPDX-License-Identifier: MIT OR Apache-2.0
//! The dedicated fsync FLUSHER thread for the PIPELINED sync tier (#1040).
//!
//! On the pipelined tier (durability `sync` on a real-barrier backend,
//! [`crate::engine::Engine::commit_syncs_before_ack`]) the append actor no longer issues the
//! covering `fdatasync` inline: it STAGES the barrier ([`crate::engine::Engine::begin_async_commit`],
//! which drains the writer's pending bytes into the file and snapshots a ticket at the
//! dirty-at-sync-start boundary) and hands the shared active-segment fd to this thread, then
//! returns to appending. At most ONE job is ever outstanding (the request channel is bound 1 and
//! the actor's dispatch is depth-1 by construction, INV-3), so the previous fsync IS the batching
//! window: everything appended while it is in flight merges into the next ticket, dispatched the
//! instant the previous completes — self-clocking group commit, no timer.
//!
//! Ownership rules (single-writer preserved):
//! - The flusher owns ONLY the receiving half of the bounded job channel and the sending half of
//!   the unbounded completion channel. It NEVER holds a command-channel sender (so drop-driven
//!   actor shutdown still observes the disconnect, the actor.rs spawn-docs contract) and NEVER
//!   touches `&mut` engine/log state.
//! - The one mutation it performs is `Arc<File>::sync_data()` — a `&self` call on the SAME kernel
//!   fd the writer stages into ([`ironbus_storage::io::RandomAccessFile::sync_data`]). Two threads
//!   issuing barriers on one fd (a roll's seal `sync_all` racing this `fdatasync`) is kernel-safe;
//!   either failing freezes the writer, so error attribution is moot (spec E9).
//! - Fault-injection control is automatic: the shared `Arc` IS the gated object, so a
//!   `FaultFs` sync gate / `set_fail_sync` governs the flusher's barrier exactly as it governed
//!   the inline one — the tests' interleaving control plane needs no new seam.
//!
//! The barrier duration is measured on the WALL clock (`std::time::Instant`), off the engine's
//! deterministic clock seam: same precedent as the retired gather deadline — the sim drives the
//! `Engine` directly and never runs this thread.

use ironbus_storage::io::RandomAccessFile;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

/// One staged covering barrier for the flusher to issue (#1040): the shared active-segment fd and
/// the actor's dispatch sequence number (`done.seq` must round-trip so the actor can
/// `debug_assert` the depth-1 discipline, INV-3).
pub(crate) struct FlushJob<File> {
    /// The actor's dispatch sequence number, echoed back in [`SyncDone::seq`].
    pub(crate) seq: u64,
    /// The SHARED handle to the active segment's fd ([`ironbus_storage::log::Log::prepare_async_sync`]):
    /// the same kernel fd the writer keeps appending to while this barrier is in flight. Holding it
    /// across a seal or a retention reap is harmless (an fdatasync on a sealed/unlinked inode is a
    /// no-op barrier) and merely delays the fd close by at most one flight.
    pub(crate) file: Arc<File>,
}

/// One RETURNED barrier (#1040): the echoed sequence number, the `fdatasync` result, and the
/// measured wall-clock barrier duration for the engine's fsync histograms.
pub(crate) struct SyncDone {
    /// Echo of [`FlushJob::seq`], asserted against the actor's one in-flight record (INV-3).
    pub(crate) seq: u64,
    /// The `fdatasync` result. `Err` is FATAL for the writer: the actor freezes it forever and
    /// fatal-fans every parked reply (INV-7) — a failed barrier is never retried (fsyncgate).
    pub(crate) result: std::io::Result<()>,
    /// Wall-clock duration of the barrier, in nanoseconds, for
    /// [`crate::engine::Engine::complete_async_commit`]'s histogram bookkeeping.
    pub(crate) fsync_nanos: u64,
}

/// Spawns the `ironbus-fsync-flusher` thread (#1040). It loops `recv -> sync_data -> send` until
/// the actor drops the job sender (every `run_actor` return path) or the actor is gone entirely
/// (the completion receiver dropped), then exits. The completion channel is UNBOUNDED, so the send
/// NEVER blocks: the flusher can never wedge behind a slow actor, and the actor can never miss a
/// completion.
///
/// # Panics
/// Panics if the OS refuses to spawn the thread — a STARTUP step (the flusher is spawned once,
/// when the pipelined actor branch starts, before any command is processed), exactly the
/// [`crate::actor::spawn_actor`] precedent; the no-panic bar is for the library hot paths, which
/// never spawn.
pub(crate) fn spawn_flusher<File>(
    req_rx: Receiver<FlushJob<File>>,
    done_tx: Sender<SyncDone>,
) -> std::thread::JoinHandle<()>
where
    File: RandomAccessFile + 'static,
{
    std::thread::Builder::new()
        .name("ironbus-fsync-flusher".to_string())
        .spawn(move || {
            while let Ok(FlushJob { seq, file }) = req_rx.recv() {
                let started = std::time::Instant::now();
                let result = file.sync_data();
                let fsync_nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                if done_tx
                    .send(SyncDone {
                        seq,
                        result,
                        fsync_nanos,
                    })
                    .is_err()
                {
                    // The actor is gone (completion receiver dropped): nothing left to serve.
                    break;
                }
            }
            // The actor dropped the job sender (clean exit) or the completion channel is gone:
            // the thread ends here and the actor's `join` reaps it.
        })
        .expect("spawning the fsync flusher thread")
}
