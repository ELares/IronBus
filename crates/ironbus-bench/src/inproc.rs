// SPDX-License-Identifier: MIT OR Apache-2.0
//! An IN-PROCESS broker over a fault-injecting filesystem, for the DETERMINISTIC injected-stall
//! self-test (#284).
//!
//! The live, OS-`SIGSTOP` self-test (see [`crate::injected_stall`]) proves the harness does not
//! commit coordinated omission, but the ~200 ms `SIGSTOP` freeze does NOT reliably manifest in the
//! recorded tail on GitHub's shared runners: whether the kernel actually descheduled the broker for
//! the whole window is a scheduling artifact of the shared host, so the freeze sometimes delayed no
//! client op at all (a representative failing run recorded a 2.6 ms max for a 200 ms freeze). That
//! made it flaky and so `#[ignore]`d, off the CI critical path.
//!
//! This module removes the OS-scheduling dependence. It runs the SAME components the shipping
//! `ironbus` binary runs (the `ironbus-server` [`Engine`] + the single append actor + the blocking
//! `serve` loop) IN this process, over a [`FaultFs`] wrapping an [`InMemoryFs`]. The freeze is then
//! the FaultFs SYNC GATE (#177): closing it parks the broker's group-commit `fdatasync` on a
//! condvar (no wall-clock sleep, no OS scheduling), so EVERY produce that needs that fsync blocks
//! for exactly the window the test holds the gate. The block is GUARANTEED, not probabilistic, so
//! the freeze ALWAYS lands in the open-loop tail. The harness still drives the broker through the
//! REAL #11 client over a real loopback socket and still measures from the intended send time, so
//! the open-loop honesty is untouched: only the freeze mechanism changed from "ask the OS to
//! deschedule a process and hope" to "deterministically park the fsync".
//!
//! Test-only / bench-only: this adds NO freeze hook to the shipped `serve` path. The seam is the
//! existing dev-cfg `FaultFs`, wired here in a `publish = false` crate; production timing and the
//! frozen wire/taxonomy are unchanged.
//!
//! Unix only, matching the rest of the self-test and the shipped broker.

#![cfg(unix)]

use ironbus_core::clock::{Clock as _, ManualClock};
use ironbus_core::delivery::DeliveryConfig;
use ironbus_core::lease::LeaseConfig;
use ironbus_server::actor::{spawn_actor, EngineHandle, DEFAULT_CHANNEL_BOUND};
use ironbus_server::engine::{
    DiskFullPolicy, Engine, EngineConfig, DEFAULT_GROUP_IDLE_EVICT_MS, DEFAULT_MAX_GROUPS,
};
use ironbus_server::server::serve;
use ironbus_storage::fault::{FaultControl, FaultFs};
use ironbus_storage::fs::InMemoryFs;
use ironbus_storage::log::LogConfig;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// The in-process broker's engine, with all caps OFF (a self-test never overloads), so the only
/// thing that delays a produce is the injected sync-gate freeze. The clock is the manual clock the
/// engine takes; the bench measures real time on the CLIENT side, so the engine's notion of time is
/// irrelevant to the recorded latency (it only stamps record timestamps and ages leases, neither of
/// which the open-loop proof reads). `checkpoint_interval` is 1 (checkpoint every advance) to mirror
/// the spawned-binary self-test's `--checkpoint-interval 1`.
type FaultEngine = Engine<FaultFs<InMemoryFs>, ManualClock>;

fn engine_config() -> EngineConfig {
    EngineConfig {
        log: LogConfig::default(),
        lease: LeaseConfig::default(),
        // `unwrap` is fine in this bench/test-only path (not a lib hot path): the literal args are
        // valid by construction, so this never errors.
        delivery: DeliveryConfig::new(5, false, vec![]).expect("valid delivery config"),
        max_in_flight: 1024,
        consumer_credit: 1024,
        consumer_credit_bytes: 0,
        checkpoint_interval: 1,
        max_retained_bytes: 0,
        max_age_ms: 0,
        max_messages: 0,
        max_groups: DEFAULT_MAX_GROUPS,
        group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
        disk_full_policy: DiskFullPolicy::DropNew,
    }
}

/// A running in-process broker on a loopback port, plus the [`FaultControl`] that drives the sync
/// gate. Shut down (serve loop stopped, actor drained) on drop, so a panicking self-test never
/// leaks the server thread.
pub struct InProcBroker {
    addr: String,
    control: FaultControl,
    shutdown: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
    handle: Option<EngineHandle<FaultFs<InMemoryFs>, ManualClock>>,
    actor: Option<JoinHandle<FaultEngine>>,
}

impl InProcBroker {
    /// Opens an in-memory engine behind a [`FaultFs`], spawns the append actor and the `serve` loop
    /// on an ephemeral loopback port, and returns once the listener is bound (the synchronous
    /// `TcpListener::bind` makes "returned" mean "accepting"). The returned [`FaultControl`] arms the
    /// sync gate that freezes the broker's group-commit fsync.
    ///
    /// # Errors
    /// Returns a string if the engine cannot open or the loopback listener cannot bind.
    pub fn start() -> Result<InProcBroker, String> {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let engine = Engine::open(fs, ManualClock::new(), engine_config())
            .map_err(|e| format!("opening in-process engine: {e}"))?;
        let (handle, actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);

        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("binding the in-process broker listener: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("reading the in-process broker address: {e}"))?
            .to_string();

        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let engine = handle.clone();
            let shutdown = Arc::clone(&shutdown);
            // `max_connections` matches the binary's default headroom; the self-test opens only a
            // sender + a receiver + a probe, far below this.
            move || {
                // The self-test does not read the liveness beacon (#95); the serve loop still ticks
                // it, so hand it a throwaway beacon on a ManualClock matching the engine's clock type.
                let clock = ManualClock::new();
                let beacon =
                    ironbus_server::liveness::LivenessBeacon::new(clock.now_monotonic_nanos());
                let _ = serve(&listener, &engine, &shutdown, 256, &clock, &beacon);
            }
        });

        Ok(InProcBroker {
            addr,
            control,
            shutdown,
            server: Some(server),
            handle: Some(handle),
            actor: Some(actor),
        })
    }

    /// The `host:port` the in-process broker is listening on, for the real #11 client to connect to.
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The fault control that arms the sync gate (the deterministic freeze) on the broker's
    /// group-commit fsync.
    #[must_use]
    pub fn control(&self) -> &FaultControl {
        &self.control
    }
}

impl Drop for InProcBroker {
    fn drop(&mut self) {
        // Open the sync gate first so a parked group-commit fsync (if the test panicked mid-freeze)
        // is released and the actor can drain rather than hang on shutdown.
        self.control.open_sync_gate();
        // Stop the accept loop, then drop the test's engine handle and shut the actor down so it
        // drains and returns. The server thread holds its own handle clone; flipping shutdown ends
        // its accept loop, after which the last handle drop disconnects the actor channel.
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.shutdown();
            drop(handle);
        }
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        if let Some(actor) = self.actor.take() {
            let _ = actor.join();
        }
    }
}
