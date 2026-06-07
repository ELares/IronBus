// SPDX-License-Identifier: MIT OR Apache-2.0
//! The coordinated-omission proof, run as a real `#[test]` (#111).
//!
//! This is the ONLY part of the macro-bench harness that runs in `cargo test`; the open-loop
//! generator itself runs on demand via the `ironbus-bench` binary and is off the per-PR CI critical
//! path (like the criterion micro-benches, #112). The self-test SIGSTOPs the shipping `ironbus`
//! broker for ~200 ms mid-run and asserts the freeze appears in the recorded p99/p99.9 tail. It
//! FAILS if the tail does not move, which is exactly the regression (a reintroduced coordinated
//! omission) it exists to catch.
//!
//! # How the threshold is chosen (and kept non-flaky)
//!
//! The IronBus broker fsyncs every produce (durability), so its baseline per-message latency floor
//! is whatever the host disk's fsync costs (sub-millisecond on a fast SSD, ~10 ms on a slow CI
//! disk). The self-test runs a healthy baseline AND a stalled run with the SAME (deliberately low,
//! sustainable) config, and compares each to a FIXED SEPARATION FLOOR at 0.6 of the 200 ms freeze
//! (120 ms): the stalled p99.9 and max must clear it, and the healthy baseline p99.9 must stay
//! below it (the non-vacuity bound). Empirically the two populations are far apart (healthy tail
//! ~30 ms, stalled tail ~210 ms), so the floor sits in a wide gap, which is robust across disks and
//! non-flaky. Comparing each population to the fixed floor, rather than subtracting two noisy
//! upper-tail percentiles, is what removes the flakiness. A harness committing coordinated omission
//! would record the same low tail with and without the freeze and fail to clear the floor.
//!
//! Unix only: it needs `SIGSTOP`/`SIGCONT`, and the shipped broker is Unix-only anyway.
#![cfg(unix)]

use ironbus_bench::broker::Broker;
use ironbus_bench::harness::RunConfig;
use ironbus_bench::injected_stall::{
    cleanup, fresh_data_dir, ironbus_binary, run_with_injected_stall,
};
use ironbus_bench::RunReport;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The injected freeze, the issue's ~200 ms target.
const STALL: Duration = Duration::from_millis(200);
/// The freeze duration in microseconds, the unit the harness reports.
const STALL_US: f64 = 200_000.0;

/// The fraction of the stall that separates the stalled tail from the healthy baseline. The stalled
/// p99.9 and max must clear `STALL * this` (120 ms); the healthy baseline p99.9 must stay below it.
/// 0.6 sits comfortably between the broker's fsync-bound healthy tail (tens of ms) and a captured
/// 200 ms freeze (~210 ms), so both the pass and the non-vacuity bound have a wide, non-flaky margin.
const STALL_SEPARATION_FRACTION: f64 = 0.6;

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

/// The self-test config: a low, broadly sustainable arrival rate so the healthy baseline tail is the
/// broker's fsync floor (not a self-inflicted overload), held long enough to gather a couple hundred
/// samples. The 200 ms freeze blocks the per-message-fsynced producer and the receiver, so its
/// post-thaw backlog lands clearly in p99/p99.9 and the max. The rate is deliberately conservative
/// (40 msg/s) so that even on a slow CI disk whose fsync floor is ~10 ms the healthy baseline p99.9
/// stays well under the stall lift; a faster disk simply has an even lower baseline, which only
/// widens the stall's margin. 6 s yields ~240 samples, enough for a meaningful upper tail.
fn self_test_config() -> RunConfig {
    RunConfig {
        target_rate_hz: 40.0,
        duration: Duration::from_secs(6),
        payload_bytes: 128,
        fetch_batch: 256,
        seed: 0xC0FF_EE00_1111_2222,
    }
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
    let config = self_test_config();

    // 1. The healthy baseline: the same config with NO freeze. Its tail is the broker's fsync floor.
    let healthy = healthy_baseline(&bin, &config);
    assert!(
        healthy.recorded >= 200,
        "the baseline must record a meaningful sample, got {}",
        healthy.recorded
    );

    // 2. The stalled run: the same config WITH a 200 ms freeze injected ~3 s in (mid-run), so a warm
    //    steady state precedes it and the receiver records the post-thaw backlog with its old
    //    intended times.
    let data_dir = fresh_data_dir("stall");
    // Guard the broker so a panic below never leaks a (possibly frozen) serve process.
    let broker =
        Broker::spawn(&bin, &data_dir, &[]).expect("spawn ironbus serve for the stall run");
    let outcome =
        run_with_injected_stall(&broker, &data_dir, &config, STALL, Duration::from_secs(3))
            .expect("the injected-stall run completed");
    drop(broker);
    cleanup(&data_dir);

    assert!(
        outcome.recorded >= 200,
        "the stall run must record a meaningful sample, got {}",
        outcome.recorded
    );

    // The separation floor: the stalled tail must clear this, and the healthy baseline must stay
    // below it. It sits at 0.6 of the 200 ms stall (120 ms), which empirically separates the two
    // populations with a wide margin on both sides: the broker's fsync-bound healthy tail is tens
    // of milliseconds (well under 120 ms), and a captured 200 ms freeze lands the stalled tail at
    // ~210 ms (well over 120 ms). Comparing each population to a FIXED floor, rather than
    // subtracting two noisy upper-tail percentiles, is what keeps the test non-flaky.
    let floor_us = STALL_US * STALL_SEPARATION_FRACTION;

    // THE load-bearing assertion: the freeze appears in p99.9, the issue's headline tail. With
    // intended-send-time accounting, the messages scheduled during the freeze drain afterward
    // carrying their old intended times, so the receiver records ~200 ms latencies that put the
    // upper tail over the floor. A coordinated-omission regression would measure from the actual
    // send time, erase the freeze, and leave p99.9 at the healthy tens-of-ms, failing this.
    assert!(
        outcome.p999_us >= floor_us,
        "the 200 ms broker freeze did not appear in p99.9: stalled p99.9 = {:.0} us, required >= \
         {:.0} us (healthy baseline p99.9 was {:.0} us). The harness is committing coordinated \
         omission (a frozen broker is not showing up in the tail). p99 = {:.0} us, max = {:.0} us, \
         recorded = {}",
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

    // Non-vacuity: the healthy baseline's OWN p99.9 stayed well below the floor, so clearing the
    // floor above is genuinely the injected freeze and not an already-saturated baseline. If this
    // ever fails, the arrival rate is too high (the broker is overloaded even without a stall) and
    // must be lowered, otherwise the load-bearing assertion would be vacuous.
    assert!(
        healthy.percentiles.p999_us < floor_us,
        "the healthy baseline p99.9 ({:.0} us) is itself at or above the separation floor ({:.0} \
         us); the baseline is overloaded, so the rate must be lowered for the test to be \
         non-vacuous",
        healthy.percentiles.p999_us,
        floor_us,
    );
}
