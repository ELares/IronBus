// SPDX-License-Identifier: MIT OR Apache-2.0
//! The injected-stall self-test: the proof that this harness does NOT commit coordinated omission.
//!
//! It runs a short open-loop generation and, mid-run, FREEZES the broker for a fixed window, then
//! thaws it. A harness that measured latency from the ACTUAL send time (closed-loop, or "from when
//! the sender got around to it") would record nothing unusual: the sender would simply block during
//! the freeze and the frozen interval would vanish. Because this harness records from the INTENDED
//! send time, the backlog that drains after the thaw carries its original, now-old intended times,
//! so the freeze duration lands squarely in the tail.
//!
//! The self-test ASSERTS the recorded tail clears a separation floor (a fraction of the freeze) that
//! the un-stalled baseline stays below, so a recorded tail over the floor can only come from the
//! injected freeze being measured. It FAILS if the tail does not move, which is exactly the
//! regression (a reintroduced coordinated omission) it exists to catch.
//!
//! # Two freeze mechanisms
//!
//! - The DETERMINISTIC freeze (#284), the default and the CI gate: an IN-PROCESS broker (see
//!   [`crate::inproc`], the same `ironbus-server` engine + actor + `serve` the binary ships) over a
//!   `FaultFs` whose SYNC GATE parks the broker's group-commit `fdatasync` on a condvar. Closing the
//!   gate is GUARANTEED to block every produce that needs that fsync for exactly the held window, so
//!   the freeze ALWAYS lands in the tail. No OS scheduling, no wall-clock sleep inside the broker:
//!   [`run_with_gated_stall`] drives it. This is the reliable, non-flaky proof.
//! - The LIVE OS freeze, kept only as an `#[ignore]`d on-demand proof: [`run_with_injected_stall`]
//!   spawns the shipping `ironbus` binary and `SIGSTOP`s it. It is solid on a stable host but flaky
//!   on shared CI runners, where the kernel does not reliably deschedule the broker for the whole
//!   window, so the freeze sometimes delays no client op at all (#284). It is NOT a CI gate.
//!
//! Because the broker fsyncs every produce, its baseline tail is the fsync floor (sub-ms on a fast
//! SSD; for the in-memory `FaultFs` it is effectively the in-process round trip). The test
//! CALIBRATES the arrival rate and the freeze via [`probe_op_latency_us`], so it is non-flaky across
//! hosts.
//!
//! Unix only: the in-process broker (and the `SIGSTOP` path) are Unix-only, matching the shipped
//! broker, so this is no loss.

#![cfg(unix)]

use crate::broker::{resume, stop, Broker};
use crate::harness::{run_open_loop, RunConfig, RunReport};
use crate::inproc::InProcBroker;
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

/// Runs one open-loop generation against the IN-PROCESS broker, freezing it DETERMINISTICALLY for
/// `stall` partway through (after `stall_after` of wall time) via the `FaultFs` sync gate, then
/// thawing it. Returns the recorded tail so a caller can assert the stall is visible.
///
/// This is the reliable, non-flaky proof (#284). The freeze is driven from a watcher thread that
/// CLOSES the sync gate, holds it for `stall`, then OPENS it. While the gate is closed, the broker's
/// group-commit `fdatasync` parks on a condvar, so EVERY produce that needs that fsync blocks for
/// the whole window. There is no OS-scheduling dependence: unlike `SIGSTOP` (which only ASKS the
/// kernel to deschedule the broker and may not, on a shared runner, actually delay any client op),
/// the gate GUARANTEES the block, so the freeze always lands in the tail. The open-loop honesty is
/// untouched: the main run thread keeps pacing the schedule and its produce blocks during the freeze,
/// exactly as a real stalled disk would block a producer, and latency is still measured from the
/// intended send time.
///
/// `stall_after` is wall time so the freeze starts after a warm steady state, like the live path;
/// the determinism comes from the GATE blocking the fsync, not from any sleep timing.
///
/// # Errors
/// Returns the underlying [`crate::harness::RunError`] string if the run itself fails.
pub fn run_with_gated_stall(
    broker: &InProcBroker,
    config: &RunConfig,
    stall: Duration,
    stall_after: Duration,
) -> Result<StallOutcome, String> {
    let control = broker.control().clone();
    let fired = Arc::new(AtomicBool::new(false));
    let watcher = std::thread::spawn({
        let fired = Arc::clone(&fired);
        move || {
            // Wait for a warm steady state, then close the gate so the broker's NEXT group-commit
            // fsync (and every produce behind it) parks; hold the freeze; then open it so the backlog
            // drains carrying its old intended times. If the run finished early the open is harmless.
            std::thread::sleep(stall_after);
            control.close_sync_gate();
            std::thread::sleep(stall);
            control.open_sync_gate();
            fired.store(true, Ordering::Release);
        }
    });

    // The resource probes (RSS, data-dir bytes) are not load-bearing for the coordinated-omission
    // proof; the in-process broker has no on-disk data dir, so a throwaway dir and our own pid yield
    // harmless resource numbers while the latency path (the only thing the proof asserts on) is
    // unaffected.
    let probe_dir = std::env::temp_dir();
    let report: RunReport = run_open_loop(broker.addr(), &probe_dir, std::process::id(), config)
        .map_err(|e| e.to_string())?;

    // Make sure the watcher opened the gate even if the run outpaced it, so nothing is left frozen.
    let _ = watcher.join();
    if !fired.load(Ordering::Acquire) {
        // The watcher panicked before firing; open defensively so a later run is not wedged.
        broker.control().open_sync_gate();
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

/// Runs one open-loop generation against the spawned-binary `broker`, freezing it with `SIGSTOP` for
/// `stall` partway through (after `stall_after` of wall time), then `SIGCONT`. Returns the recorded
/// tail so a caller can assert the stall is visible.
///
/// The LIVE OS-freeze path, kept only behind `--ignored` (#284): solid on a stable host, flaky on
/// shared CI runners where the kernel does not reliably deschedule the broker for the whole window.
/// The DETERMINISTIC gate ([`run_with_gated_stall`]) is the CI gate; prefer it.
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

/// Measures the broker's UNLOADED single produce round-trip latency, in microseconds: the median of
/// a handful of sequential, well-spaced produces over the real #11 client.
///
/// This is the per-op floor the host disk's fsync imposes (sub-millisecond on a fast SSD, tens to
/// low-hundreds of milliseconds on a slow CI disk). The injected-stall self-test uses it to pick an
/// arrival rate well below saturation and a stall that clearly exceeds the floor, so the test is
/// self-tuning to any disk rather than assuming a fixed baseline. Returns `None` if the probe could
/// not connect or produce at all.
#[must_use]
pub fn probe_op_latency_us(addr: &str) -> Option<f64> {
    use ironbus_client::{Client, ClientConfig};
    use ironbus_proto::message::PubBody;

    let mut client = Client::connect_with(addr, &ClientConfig::default()).ok()?;
    let mut samples: Vec<u64> = Vec::new();
    // A short warmup followed by timed produces; spaced so each fsync completes before the next, so
    // we measure the UNLOADED per-op latency, not a queued one.
    for i in 0..12u64 {
        let payload = i.to_le_bytes();
        let start = crate::clock::now_nanos();
        let ok = client
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: &payload,
            })
            .is_ok();
        let elapsed = crate::clock::now_nanos().saturating_sub(start);
        if ok && i >= 2 {
            // Drop the first two as warmup (segment/file creation, page-cache cold start).
            samples.push(elapsed);
        }
        // Space the next produce so the disk is idle again.
        std::thread::sleep(Duration::from_millis(5));
    }
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let median_ns = samples[samples.len() / 2];
    // The precision loss above 2^52 ns (~52 days) is irrelevant for a per-op latency probe.
    #[allow(clippy::cast_precision_loss)]
    Some(median_ns as f64 / 1e3)
}
