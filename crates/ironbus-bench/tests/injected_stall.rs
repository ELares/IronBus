// SPDX-License-Identifier: MIT OR Apache-2.0
//! The coordinated-omission proof, run as a real `#[test]` (#111).
//!
//! This is the ONLY part of the macro-bench harness that runs in `cargo test`; the open-loop
//! generator itself runs on demand via the `ironbus-bench` binary and is off the per-PR CI critical
//! path (like the criterion micro-benches, #112). The self-test SIGSTOPs the shipping `ironbus`
//! broker mid-run and asserts the freeze appears in the recorded p99/p99.9 tail. It FAILS if the
//! tail does not move, which is exactly the regression (a reintroduced coordinated omission) it
//! exists to catch.
//!
//! # Self-tuning to the host disk
//!
//! The IronBus broker fsyncs every produce (durability), so its per-message latency floor is
//! whatever the host disk's fsync costs: sub-millisecond on a fast SSD, but tens to low-HUNDREDS of
//! milliseconds on a slow CI disk. A fixed arrival rate would overload a slow disk (the healthy
//! baseline tail would then exceed a fixed-200 ms stall, and the proof would be vacuous). So the
//! test CALIBRATES first: it probes the broker's unloaded single-op latency, then picks an arrival
//! rate at a low utilization (so the healthy tail stays close to that floor with little queueing)
//! and a freeze that is a large multiple of the floor (so it dwarfs the baseline on ANY disk, while
//! never going below the issue's ~200 ms target). The separation floor is a fraction of the chosen
//! freeze. The healthy baseline p99.9 must stay below the floor (non-vacuity) and the stalled p99.9
//! and max must clear it (the freeze was measured). A harness committing coordinated omission would
//! record the same low tail with and without the freeze and fail to clear the floor.
//!
//! Unix only: it needs `SIGSTOP`/`SIGCONT`, and the shipped broker is Unix-only anyway.
#![cfg(unix)]

use ironbus_bench::broker::Broker;
use ironbus_bench::harness::RunConfig;
use ironbus_bench::injected_stall::{
    cleanup, fresh_data_dir, ironbus_binary, probe_op_latency_us, run_with_injected_stall,
};
use ironbus_bench::RunReport;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The minimum freeze: the issue's ~200 ms target. A slow disk (low rate) uses a longer freeze so
/// it still spans many inter-arrivals, but never shorter than this.
const MIN_STALL: Duration = Duration::from_millis(200);
/// The freeze spans at least this many inter-arrival gaps (`STALL_OVER_INTERARRIVAL / rate`). It
/// must be SEVERAL inter-arrivals, not one, so that even at a low arrival rate the freeze reliably
/// brackets multiple scheduled sends: the earliest one lands within ~one gap of the freeze start and
/// so accumulates almost the whole freeze as latency. One inter-arrival would leave only ~one
/// affected message whose latency is a random fraction of the freeze, which is exactly what made an
/// op-latency-sized freeze flaky.
const STALL_OVER_INTERARRIVAL: f64 = 8.0;
/// Cap the freeze so a pathologically slow disk does not blow the test runtime. The run length and
/// the receiver read timeout (30 s) bound it well above this.
const MAX_STALL: Duration = Duration::from_secs(2);
/// Target utilization for the arrival rate: rate = `UTILIZATION / op_latency`. At 0.1 the broker is
/// far from saturated, so the healthy tail stays near the op-latency floor with little queueing,
/// which keeps a wide gap below the freeze on any disk.
const UTILIZATION: f64 = 0.1;
/// The separation floor as a fraction of the chosen freeze: the stalled p99.9 and max must clear it,
/// the healthy baseline p99.9 must stay below it.
const STALL_SEPARATION_FRACTION: f64 = 0.6;
/// How many messages each run aims to record. The run duration is `TARGET_SAMPLES / rate`, so a
/// slow disk (low rate) still gathers enough samples for a meaningful upper tail, bounded by
/// [`MAX_RUN`] so the test stays fast.
const TARGET_SAMPLES: f64 = 150.0;
/// The lower and upper bound on a run's duration, regardless of the calibrated rate.
const MIN_RUN: Duration = Duration::from_secs(4);
const MAX_RUN: Duration = Duration::from_secs(20);

/// Resolves the shipping `ironbus` binary from the test executable's location. Under
/// `cargo test --workspace` (CI) and after any `cargo build`, the binary sits at
/// `target/<profile>/ironbus`, one level up from the integration-test binary's `deps/` dir, which
/// the resolver finds. If it is missing, the message tells the operator to build the workspace
/// first (a lone `cargo test -p ironbus-bench` does not build a sibling crate's binary).
fn ironbus_bin() -> PathBuf {
    ironbus_binary().expect(
        "could not locate the built `ironbus` binary; run `cargo test --workspace` or \
         `cargo build` first so target/<profile>/ironbus exists",
    )
}

/// Builds the calibrated run config from the measured unloaded op latency (microseconds): a low
/// utilization arrival rate so the healthy tail stays near the fsync floor, and a duration scaled to
/// gather [`TARGET_SAMPLES`] at that rate (so a slow disk still collects a meaningful upper tail).
fn calibrated_config(op_latency_us: f64) -> RunConfig {
    // rate (per second) = utilization / op_latency(seconds). Clamp into a sane band so a tiny or
    // huge measurement cannot produce an absurd rate.
    let latency_seconds = (op_latency_us / 1e6).max(1e-6);
    let rate = (UTILIZATION / latency_seconds).clamp(5.0, 5_000.0);
    let duration = Duration::from_secs_f64(TARGET_SAMPLES / rate).clamp(MIN_RUN, MAX_RUN);
    RunConfig {
        target_rate_hz: rate,
        duration,
        payload_bytes: 128,
        fetch_batch: 256,
        seed: 0xC0FF_EE00_1111_2222,
    }
}

/// The freeze for a given arrival `rate` (msg/s): several inter-arrival gaps, clamped to
/// [`MIN_STALL`, `MAX_STALL`]. Sizing it from the rate (not the op latency) guarantees the freeze
/// spans MANY scheduled sends, so the earliest affected message accumulates nearly the whole freeze
/// as latency and the stalled tail lands well above the separation floor on any disk.
fn calibrated_stall(rate_hz: f64) -> Duration {
    let want_secs = (STALL_OVER_INTERARRIVAL / rate_hz.max(f64::MIN_POSITIVE)).max(0.0);
    // `from_secs_f64` does the float-to-Duration conversion without a manual, lint-flagged cast.
    Duration::from_secs_f64(want_secs).clamp(MIN_STALL, MAX_STALL)
}

/// Runs one healthy (un-stalled) baseline against a fresh broker, returning its report.
fn healthy_baseline(bin: &Path, config: &RunConfig) -> RunReport {
    let data_dir = fresh_data_dir("healthy");
    let broker =
        Broker::spawn(bin, &data_dir, &[]).expect("spawn ironbus serve for the healthy baseline");
    let report = ironbus_bench::run_open_loop(broker.addr(), &data_dir, broker.pid(), config)
        .expect("the healthy baseline run completed");
    drop(broker);
    cleanup(&data_dir);
    report
}

#[test]
fn an_injected_sigstop_shows_up_in_the_recorded_tail() {
    let bin = ironbus_bin();

    // 0. Calibrate: probe the broker's unloaded single-op latency, then derive the arrival rate and
    //    the freeze from it, so the test self-tunes to a fast SSD or a slow CI disk alike.
    let op_latency_us = {
        let data_dir = fresh_data_dir("calib");
        let broker =
            Broker::spawn(&bin, &data_dir, &[]).expect("spawn ironbus serve for calibration");
        let lat = probe_op_latency_us(broker.addr()).expect("probe the broker's op latency");
        drop(broker);
        cleanup(&data_dir);
        lat
    };
    let config = calibrated_config(op_latency_us);
    let stall = calibrated_stall(config.target_rate_hz);
    let stall_us = stall.as_secs_f64() * 1e6;
    let floor_us = stall_us * STALL_SEPARATION_FRACTION;
    eprintln!(
        "calibrated: op_latency={op_latency_us:.0} us, rate={:.0} msg/s, stall={:.0} us, floor={floor_us:.0} us",
        config.target_rate_hz, stall_us,
    );

    // 1. The healthy baseline: the calibrated config with NO freeze. Its tail is the broker's fsync
    //    floor plus light queueing, which the low utilization keeps well below the separation floor.
    let healthy = healthy_baseline(&bin, &config);
    assert!(
        healthy.recorded >= 30,
        "the baseline must record a meaningful sample, got {}",
        healthy.recorded
    );

    // 2. The stalled run: the same config WITH the calibrated freeze injected mid-run, so a warm
    //    steady state precedes it and the receiver records the post-thaw backlog with its old
    //    intended times.
    let data_dir = fresh_data_dir("stall");
    // Guard the broker so a panic below never leaks a (possibly frozen) serve process.
    let broker =
        Broker::spawn(&bin, &data_dir, &[]).expect("spawn ironbus serve for the stall run");
    let inject_at = config.duration / 2;
    let outcome = run_with_injected_stall(&broker, &data_dir, &config, stall, inject_at)
        .expect("the injected-stall run completed");
    drop(broker);
    cleanup(&data_dir);

    assert!(
        outcome.recorded >= 30,
        "the stall run must record a meaningful sample, got {}",
        outcome.recorded
    );

    // Non-vacuity FIRST: the healthy baseline's OWN p99.9 stayed below the separation floor, so
    // clearing the floor below is genuinely the injected freeze and not an already-saturated
    // baseline. The calibrated low rate makes this hold on any disk; if it ever fails, the
    // utilization or the stall multiple must be revisited.
    assert!(
        healthy.percentiles.p999_us < floor_us,
        "the healthy baseline p99.9 ({:.0} us) is at or above the separation floor ({:.0} us); the \
         baseline is saturated (op_latency was {:.0} us, rate {:.0} msg/s), so the calibration must \
         be revisited for the test to be non-vacuous",
        healthy.percentiles.p999_us,
        floor_us,
        op_latency_us,
        config.target_rate_hz,
    );

    // THE load-bearing assertion: the freeze appears in p99.9, the issue's headline tail. With
    // intended-send-time accounting, the messages scheduled during the freeze drain afterward
    // carrying their old intended times, so the receiver records ~stall latencies that put the
    // upper tail over the floor. A coordinated-omission regression would measure from the actual
    // send time, erase the freeze, and leave p99.9 at the healthy floor, failing this.
    assert!(
        outcome.p999_us >= floor_us,
        "the {:.0} ms broker freeze did not appear in p99.9: stalled p99.9 = {:.0} us, required >= \
         {:.0} us (healthy baseline p99.9 was {:.0} us). The harness is committing coordinated \
         omission (a frozen broker is not showing up in the tail). p99 = {:.0} us, max = {:.0} us, \
         recorded = {}",
        stall_us / 1e3,
        outcome.p999_us,
        floor_us,
        healthy.percentiles.p999_us,
        outcome.p99_us,
        outcome.max_us,
        outcome.recorded,
    );

    // The single worst message waited roughly the whole stall: an independent, stronger check that
    // the freeze was measured end to end (the max clears the same floor).
    assert!(
        outcome.max_us >= floor_us,
        "the worst recorded latency ({:.0} us) is below the separation floor ({:.0} us); the freeze \
         was not measured end to end",
        outcome.max_us,
        floor_us,
    );
}
