// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests for the `ironbus-regression-gate` binary (#114).
//!
//! These drive the REAL compiled binary (via Cargo's `CARGO_BIN_EXE_*` path) over real JSON files,
//! so the wiring CI relies on (read history + optional baseline, exit code, log line) is exercised,
//! not just the library `evaluate`. The dominant case the issue calls out is verified here: with NO
//! baseline (the state today, before `v0.1.0`), the gate GRACEFULLY NO-OPS (exit 0) with a logged
//! "no baseline history yet", rather than failing or erroring.

use std::path::PathBuf;
use std::process::Command;

/// The compiled gate binary, provided to this integration test by Cargo.
fn gate_bin() -> &'static str {
    env!("CARGO_BIN_EXE_ironbus-regression-gate")
}

/// The checked-in fixture history the CI gate also runs against.
fn fixture_history() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("regression-history.json")
}

/// A fresh temp path for a per-test JSON file, unique per process + call.
fn temp_json(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "ironbus-regtest-{}-{tag}-{n}.json",
        std::process::id()
    ))
}

/// Runs the gate and returns (`exit_code`, combined stdout+stderr).
fn run_gate(args: &[&str]) -> (i32, String) {
    let out = Command::new(gate_bin())
        .args(args)
        .output()
        .expect("spawn the regression-gate binary");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

#[test]
fn no_baseline_file_is_a_graceful_no_op_exit_zero() {
    // THE dominant first-run requirement: a current history with no baseline => exit 0, with a
    // logged "no baseline history yet". This test FAILS if the gate errors or fails on an empty
    // baseline.
    let history = fixture_history();
    let (code, log) = run_gate(&["--history", history.to_str().unwrap()]);
    assert_eq!(code, 0, "no-baseline must exit 0; log:\n{log}");
    assert!(
        log.contains("no baseline history yet"),
        "expected the no-baseline log; got:\n{log}"
    );
}

#[test]
fn a_missing_baseline_path_is_also_a_graceful_no_op() {
    // Pointing at a baseline file that does not exist yet (the path the release archive WILL write)
    // is the same graceful no-op, not an error.
    let history = fixture_history();
    let missing = temp_json("definitely-absent-baseline");
    let _ = std::fs::remove_file(&missing);
    let (code, log) = run_gate(&[
        "--history",
        history.to_str().unwrap(),
        "--baseline",
        missing.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "a missing baseline file must exit 0; log:\n{log}");
    assert!(log.contains("no baseline history"), "log:\n{log}");
}

#[test]
fn a_real_regression_fires_and_exits_nonzero() {
    // A baseline with a healthy median, a current history that drops throughput 33% => the gate must
    // FAIL (exit 1). This proves the wired binary has teeth, not just the library.
    let baseline = temp_json("baseline");
    std::fs::write(
        &baseline,
        r#"{"tag":"v0.1.0","runs":[
            {"device":"edge-min-pi4","unix_secs":1699000000,"throughput_msgs_per_sec":60000.0,"p99_us":5000.0,"p999_us":9000.0,"warmup_cov_ok":true}
        ]}"#,
    )
    .unwrap();
    let history = temp_json("history-regressed");
    std::fs::write(
        &history,
        r#"{"now_unix_secs":1700000000,"runs":[
            {"device":"edge-min-pi4","unix_secs":1700000000,"throughput_msgs_per_sec":40000.0,"p99_us":5000.0,"p999_us":9000.0,"warmup_cov_ok":true}
        ]}"#,
    )
    .unwrap();

    let (code, log) = run_gate(&[
        "--history",
        history.to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "a 33% throughput drop must exit 1; log:\n{log}");
    assert!(log.contains("FAIL"), "log:\n{log}");

    // And the human-ratify override converts that same regression into a documented pass (exit 0).
    let (code2, log2) = run_gate(&[
        "--history",
        history.to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
        "--ratify",
        "known CI thermal regression, ticket RB-999",
    ]);
    assert_eq!(code2, 0, "a ratified regression must exit 0; log:\n{log2}");
    assert!(log2.contains("RATIFIED"), "log:\n{log2}");

    let _ = std::fs::remove_file(&baseline);
    let _ = std::fs::remove_file(&history);
}

#[test]
fn a_within_threshold_history_passes() {
    let baseline = temp_json("baseline-ok");
    std::fs::write(
        &baseline,
        r#"{"tag":"v0.1.0","runs":[
            {"device":"edge-min-pi4","unix_secs":1699000000,"throughput_msgs_per_sec":60000.0,"p99_us":5000.0,"p999_us":9000.0,"warmup_cov_ok":true}
        ]}"#,
    )
    .unwrap();
    let history = temp_json("history-ok");
    std::fs::write(
        &history,
        r#"{"now_unix_secs":1700000000,"runs":[
            {"device":"edge-min-pi4","unix_secs":1700000000,"throughput_msgs_per_sec":59500.0,"p99_us":5100.0,"p999_us":9200.0,"warmup_cov_ok":true}
        ]}"#,
    )
    .unwrap();
    let (code, log) = run_gate(&[
        "--history",
        history.to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "a within-threshold history must pass; log:\n{log}");
    assert!(log.contains("PASS"), "log:\n{log}");
    let _ = std::fs::remove_file(&baseline);
    let _ = std::fs::remove_file(&history);
}

#[test]
fn a_missing_history_is_a_usage_error_exit_two() {
    let missing = temp_json("absent-history");
    let _ = std::fs::remove_file(&missing);
    let (code, _log) = run_gate(&["--history", missing.to_str().unwrap()]);
    assert_eq!(
        code, 2,
        "a missing --history is a usage/input error (exit 2)"
    );
}
