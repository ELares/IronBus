// SPDX-License-Identifier: MIT OR Apache-2.0
//! The injected-stall self-test: the proof that this harness does NOT commit coordinated omission.
//!
//! It runs a short open-loop generation and, mid-run, freezes the broker with `SIGSTOP` for a fixed
//! window, then thaws it with `SIGCONT`. A harness that measured latency from the ACTUAL send time
//! (closed-loop, or "from when the sender got around to it") would record nothing unusual: the
//! sender would simply block during the freeze and the frozen interval would vanish. Because this
//! harness records from the INTENDED send time, the backlog that drains after the thaw carries its
//! original, now-old intended times, so the freeze duration lands squarely in the tail.
//!
//! The self-test ASSERTS the tail rose by roughly the stall: a healthy loopback run's p99.9 is in
//! the low milliseconds, so a recorded tail at or above a generous fraction of the stall can only
//! come from the injected freeze being measured. It FAILS if the tail does not move, which is
//! exactly the regression (a reintroduced coordinated omission) it exists to catch. It is kept
//! short and uses a generous lower-bound margin so it is fast and non-flaky on a loaded CI runner.
//!
//! Unix only: it needs `SIGSTOP`/`SIGCONT`. The shipped broker is Unix-only, so this is no loss.

#![cfg(unix)]

use crate::broker::{resume, stop, Broker};
use crate::harness::{run_open_loop, RunConfig, RunReport};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The outcome of an injected-stall experiment, enough for a test to assert on.
#[derive(Debug)]
pub struct StallOutcome {
    /// The recorded p99 latency, microseconds.
    pub p99_us: f64,
    /// The recorded p99.9 latency, microseconds.
    pub p999_us: f64,
    /// The recorded max latency, microseconds.
    pub max_us: f64,
    /// How many messages the receiver recorded (so a test can assert non-vacuity).
    pub recorded: u64,
    /// The stall window that was injected, microseconds.
    pub stall_us: f64,
}

/// Runs one open-loop generation against `broker`, freezing it with `SIGSTOP` for `stall` partway
/// through (after `stall_after` of wall time), then `SIGCONT`. Returns the recorded tail so a caller
/// can assert the stall is visible.
///
/// The freeze is driven from a watcher thread so the main run thread keeps pacing the schedule (its
/// produce blocks during the freeze, exactly as a real stalled broker would block a producer).
///
/// # Errors
/// Returns the underlying [`crate::harness::RunError`] string if the run itself fails.
pub fn run_with_injected_stall(
    broker: &Broker,
    data_dir: &Path,
    config: &RunConfig,
    stall: Duration,
    stall_after: Duration,
) -> Result<StallOutcome, String> {
    let pid = broker.pid();
    let fired = Arc::new(AtomicBool::new(false));
    let watcher = std::thread::spawn({
        let fired = Arc::clone(&fired);
        move || {
            std::thread::sleep(stall_after);
            // Freeze, hold, thaw. If the run finished early the signals hit a still-alive broker
            // (the Broker guard outlives this call), so they are harmless either way.
            stop(pid);
            std::thread::sleep(stall);
            resume(pid);
            fired.store(true, Ordering::Release);
        }
    });

    let report: RunReport =
        run_open_loop(broker.addr(), data_dir, pid, config).map_err(|e| e.to_string())?;

    // Make sure the watcher thawed the broker even if the run outpaced it, so nothing is left frozen.
    let _ = watcher.join();
    if !fired.load(Ordering::Acquire) {
        // The watcher panicked before firing; thaw defensively so a later run is not wedged.
        resume(pid);
    }

    let stall_us = duration_us(stall);
    Ok(StallOutcome {
        p99_us: report.percentiles.p99_us,
        p999_us: report.percentiles.p999_us,
        max_us: report.percentiles.max_us,
        recorded: report.recorded,
        stall_us,
    })
}

/// A `Duration` as microseconds (f64).
fn duration_us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

/// Resolves the `ironbus` binary the same way the harness binary does, for tests that need to spawn
/// a broker. Returns `None` if the layout is unexpected.
#[must_use]
pub fn ironbus_binary() -> Option<PathBuf> {
    crate::broker::resolve_ironbus_binary()
}

/// A unique temp data dir for a self-test run, removed if it already exists.
#[must_use]
pub fn fresh_data_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ironbus-bench-{tag}-{}-{}",
        std::process::id(),
        // A coarse nonce so two runs in the same process do not collide.
        crate::clock::now_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Removes a data dir best-effort (a test cleanup helper).
pub fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}
