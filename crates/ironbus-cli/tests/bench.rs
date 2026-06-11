// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end integration tests for `ironbus bench` (#94), driving the ACTUAL built `ironbus`
//! binary as a subprocess so the production-safety and flash-endurance guards, the isolated
//! auto-create/auto-delete lifecycle, and the honest round-trip fsync cost are proven against the
//! real product, not a stub.
//!
//! `bench` spins up the Unix-only on-disk broker (the storage path uses positioned IO the Windows
//! path lacks), so the run tests are gated to Unix. The cross-platform guard parsing is unit-tested
//! in `src/bench.rs` on every target; Windows still compiles this file to an empty module, so the
//! `-D warnings` clean-on-all-targets requirement holds.
#![cfg(unix)]
// A few tests build small ad-hoc JSON-field assertions and run the binary in a linear script; the
// pedantic style lints fire on those shapes and are not correctness lints (the CI clippy gate is
// `-D warnings` without pedantic and is clean without these). Allowing them keeps the tests
// readable.
#![allow(clippy::doc_markdown)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

/// The freshly-built `ironbus` binary (Cargo sets this for the crate's integration tests).
const BIN: &str = env!("CARGO_BIN_EXE_ironbus");

/// A per-test private temp directory, so the synthetic-directory auto-delete check is not polluted
/// by other bench tests running in parallel (they all default to the shared system temp dir). Each
/// test points the bench subprocess at this directory via `TMPDIR`, which `std::env::temp_dir`
/// honors on Unix.
struct PrivateTmp(PathBuf);

impl PrivateTmp {
    fn new() -> PrivateTmp {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ironbus-bench-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create private temp dir");
        PrivateTmp(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Counts the synthetic `ironbus-bench-*` directories under THIS private temp dir, so a test
    /// can assert auto-delete left none behind without racing sibling tests.
    fn count_bench_dirs(&self) -> usize {
        let mut n = 0;
        if let Ok(rd) = std::fs::read_dir(&self.0) {
            for entry in rd.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("ironbus-bench-")
                    && entry.path().is_dir()
                {
                    n += 1;
                }
            }
        }
        n
    }
}

impl Drop for PrivateTmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `ironbus bench <args>` with the bench subprocess pointed at `tmp` for its synthetic data
/// directories, and returns the captured output.
fn run_bench_in(tmp: &PrivateTmp, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("bench")
        .args(args)
        .env("TMPDIR", tmp.path())
        .output()
        .expect("spawn ironbus bench")
}

/// Runs `ironbus bench <args>` in a throwaway private temp dir (for guard tests that never spawn a
/// broker, so the synthetic dir is irrelevant).
fn run_bench(args: &[&str]) -> Output {
    let tmp = PrivateTmp::new();
    run_bench_in(&tmp, args)
}

/// Extracts a numeric JSON field's value (e.g. `"fsync_cost_us":5019.084`) from the one-line bench
/// JSON object, or `None` if absent or `null`. A tiny scanner so the test pulls no serde dependency.
fn json_number(json: &str, field: &str) -> Option<f64> {
    let key = format!("\"{field}\":");
    let start = json.find(&key)? + key.len();
    let rest = &json[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == 'e' || c == 'E'))
        .unwrap_or(rest.len());
    rest[..end].parse::<f64>().ok()
}

#[test]
fn round_trip_count_run_measures_fsync_cost_and_cleans_up() {
    // A small bounded round-trip run against the DEFAULT isolated synthetic broker. It must exit 0,
    // emit a versioned JSON object with the explicitly-named latency-histogram fields, measure the
    // fsync cost through the real per-ack durable path (round-trip mode, not --no-fsync), and leave
    // NO synthetic directory behind (auto-create then auto-delete).
    let tmp = PrivateTmp::new();
    let out = run_bench_in(&tmp, &["--count", "500", "--mode", "round-trip", "--json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "bench should exit 0; stderr: {stderr}\nstdout: {stdout}"
    );
    // Versioned schema.
    assert!(stdout.contains("\"schema_version\":1"), "json: {stdout}");
    assert!(stdout.contains("\"mode\":\"round-trip\""), "json: {stdout}");
    // The run is isolated by default.
    assert!(stdout.contains("\"isolated\":true"), "json: {stdout}");
    // Explicitly-named latency-histogram fields, and they are populated (not null) for a 500-message
    // round trip.
    for field in [
        "\"latency_p50_us\":",
        "\"latency_p99_us\":",
        "\"latency_p999_us\":",
        "\"latency_max_us\":",
    ] {
        assert!(stdout.contains(field), "missing {field} in json: {stdout}");
    }
    assert!(
        !stdout.contains("\"latency_p50_us\":null"),
        "p50 should be measured for a 500-message round trip: {stdout}"
    );
    // The fsync cost is measured through the real durable path (round-trip, fsync on).
    assert!(stdout.contains("\"fsync_measured\":true"), "json: {stdout}");
    assert!(
        !stdout.contains("\"fsync_cost_us\":null"),
        "fsync cost should be measured: {stdout}"
    );
    // TEETH: the fsync cost must be the ISOLATED per-produce durable-write cost, not the round-trip
    // latency (which is inflated by queue-wait under the per-ack durable path). So the fsync cost
    // must be strictly below the round-trip max latency. This FAILS if the cost is reverted to
    // attributing the round-trip p50/max as the fsync number.
    let fsync_cost = json_number(&stdout, "fsync_cost_us").expect("fsync_cost_us present");
    let max_latency = json_number(&stdout, "latency_max_us").expect("latency_max_us present");
    assert!(
        fsync_cost < max_latency,
        "fsync cost ({fsync_cost}) must be below the round-trip max latency ({max_latency}), \
         proving it isolates the durable-write cost from queue-wait: {stdout}"
    );
    // bytes/op and throughput present.
    assert!(stdout.contains("\"bytes_per_op\":"), "json: {stdout}");
    assert!(stdout.contains("\"msgs_per_sec\":"), "json: {stdout}");
    // Auto-delete: no synthetic directory left behind in the private temp dir the run used.
    assert_eq!(
        tmp.count_bench_dirs(),
        0,
        "the synthetic data directory must be auto-deleted, none should remain"
    );
}

#[test]
fn publish_mode_run_nulls_latency_and_still_cleans_up() {
    let tmp = PrivateTmp::new();
    let out = run_bench_in(&tmp, &["--count", "200", "--mode", "publish", "--json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("\"mode\":\"publish\""), "json: {stdout}");
    // Publish does not read back, so latency fields are null.
    assert!(stdout.contains("\"latency_p50_us\":null"), "json: {stdout}");
    assert_eq!(
        tmp.count_bench_dirs(),
        0,
        "synthetic dir must be cleaned up"
    );
}

#[test]
fn no_fsync_dry_run_flags_the_cost_not_measured() {
    let out = run_bench(&["--count", "100", "--no-fsync", "--json"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("\"no_fsync\":true"), "json: {stdout}");
    assert!(
        stdout.contains("\"fsync_measured\":false"),
        "json: {stdout}"
    );
    assert!(stdout.contains("\"fsync_cost_us\":null"), "json: {stdout}");
}

#[test]
fn memory_storage_run_reports_and_never_claims_an_fsync_cost() {
    // #445: `ironbus bench --storage memory` runs the isolated broker over the REAL
    // `serve --storage memory` engine path and reports honest RAM-path numbers. The load-bearing
    // assertions: the run completes and reports (exit 0, populated latency fields for a
    // round-trip), the additive `storage` JSON field names the backend, the fsync cost is
    // HONESTLY not measured (the in-memory engine issues no fsync at all, so claiming a cost
    // would be dishonest), and NO synthetic data directory is ever created (nothing to
    // auto-delete: the memory broker owns no files).
    let tmp = PrivateTmp::new();
    let out = run_bench_in(
        &tmp,
        &[
            "--count",
            "300",
            "--mode",
            "round-trip",
            "--storage",
            "memory",
            "--json",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "bench --storage memory should exit 0; stderr: {stderr}\nstdout: {stdout}"
    );
    // The additive backend echo: a recorded RAM-path run is never mistaken for a disk number.
    assert!(stdout.contains("\"storage\":\"memory\""), "json: {stdout}");
    assert!(stdout.contains("\"schema_version\":1"), "json: {stdout}");
    // It really measured: a 300-message round trip populates the latency histogram fields.
    assert!(
        !stdout.contains("\"latency_p50_us\":null"),
        "p50 should be measured for a 300-message memory round trip: {stdout}"
    );
    assert!(stdout.contains("\"msgs_per_sec\":"), "json: {stdout}");
    // THE HONESTY TEETH: no fsync exists in the in-memory engine, so the cost is not measured
    // and never reported as a number. This FAILS if memory mode starts claiming an fsync cost.
    assert!(
        stdout.contains("\"fsync_measured\":false"),
        "json: {stdout}"
    );
    assert!(stdout.contains("\"fsync_cost_us\":null"), "json: {stdout}");
    // NO files: the memory bench broker never creates a synthetic data directory at all.
    assert_eq!(
        tmp.count_bench_dirs(),
        0,
        "a memory-mode bench run must never create a synthetic data directory"
    );
}

#[test]
fn memory_storage_keeps_the_entropy_modes_and_names_the_target() {
    // #439's payload-entropy knob applies UNCHANGED over the memory backend (the fill is
    // payload-side and storage-agnostic), and the human view names the in-memory target plus the
    // memory-specific not-measured fsync wording.
    let tmp = PrivateTmp::new();
    let out = run_bench_in(
        &tmp,
        &[
            "--count",
            "100",
            "--storage",
            "memory",
            "--payload-shape",
            "random",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("isolated synthetic IN-MEMORY broker"),
        "the human view names the in-memory target: {stdout}"
    );
    assert!(
        stdout.contains("issues no fsync"),
        "the human fsync line states the memory-mode reason, not the dry-run one: {stdout}"
    );
    assert_eq!(tmp.count_bench_dirs(), 0, "no synthetic dir in memory mode");
}

#[test]
fn storage_with_a_live_addr_is_refused_at_the_binary() {
    // `--storage` shapes only the isolated spawned broker; on a live run it would silently mean
    // nothing, so the real binary refuses it (exit 1) even with the live acknowledgement, and
    // never connects.
    let out = run_bench(&[
        "--count",
        "1",
        "--storage",
        "memory",
        "--addr",
        "127.0.0.1:7777",
        "--i-understand-this-is-live",
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "--storage with --addr must be exit 1 (usage)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ISOLATED"), "stderr: {stderr}");
}

#[test]
fn a_bounded_run_is_required() {
    // FLASH-ENDURANCE guard: no --duration/--count is a usage error (exit 1). This FAILS if the
    // required-bound guard is removed.
    let out = run_bench(&["--mode", "publish"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "missing bound must be exit 1 (usage)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("bounded run"), "stderr: {stderr}");
}

#[test]
fn targeting_a_live_broker_without_the_ack_is_refused() {
    // PRODUCTION-SAFETY guard: --addr without the acknowledgement is a usage error (exit 1), and
    // crucially it never connects or produces. This FAILS if the live-target guard is removed.
    let out = run_bench(&["--count", "1", "--addr", "127.0.0.1:7777"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "live target without ack must be exit 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("i-understand-this-is-live"),
        "stderr: {stderr}"
    );
}

#[test]
fn joining_a_non_bench_group_without_the_ack_is_refused() {
    // PRODUCTION-SAFETY guard: a non-bench group name could be a real consumer group; joining it
    // would steal its messages, so it is refused without the ack (exit 1). This FAILS if the
    // named-group guard is removed.
    let out = run_bench(&["--count", "1", "--group", "orders"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "non-bench group without ack must be exit 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("real consumer group"), "stderr: {stderr}");
}

#[test]
fn a_zero_duration_is_rejected() {
    let out = run_bench(&["--duration", "0"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn human_output_describes_the_isolated_target() {
    // Without --json the human view names the isolated synthetic broker and the synthetic group.
    let out = run_bench(&["--count", "50"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("isolated synthetic broker"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("ironbus-bench-"), "stdout: {stdout}");
    assert!(stdout.contains("fsync cost"), "stdout: {stdout}");
}
