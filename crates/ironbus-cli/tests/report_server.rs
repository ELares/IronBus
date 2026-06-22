// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests for the V2-M6 reporting verbs (#589 `report`, #592 `server`): they drive the
//! REAL compiled `ironbus` binary against a REAL broker's health server, proving the wire path
//! (the actual `/metrics`, `/healthz`, `/readyz` round-trips), the human + global-`--json` output,
//! the FROZEN exit codes (including the Nagios `check` mapping), the broker-unreachable code, and
//! the read-only / scriptable guarantees the unit tests cannot cover.
//!
//! Unix-only: the broker `serve` itself is Unix-only in v1, so the whole file is gated like the
//! `top` end-to-end tests. The verbs themselves are cross-platform; this exercises them against a
//! live Unix broker.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_ironbus");

/// Kills and reaps the broker on drop, so a panicking assertion never leaks a serve process.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Boots `ironbus serve` with the wire and health ports on ephemeral loopback addresses (the health
/// server serves `/metrics`, `/healthz`, `/readyz` whenever `--health-addr` is set — no extra flag
/// is needed for the reporting verbs, which never touch `/admin`). Returns a kill-guard plus the
/// parsed wire and health addresses.
fn start_broker(data_dir: &str) -> (ChildGuard, String, String) {
    let child = Command::new(BIN)
        .args([
            "serve",
            "--data-dir",
            data_dir,
            "--addr",
            "127.0.0.1:0",
            "--health-addr",
            "127.0.0.1:0",
            "--checkpoint-interval",
            "1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus serve");
    let mut guard = ChildGuard(child);
    let stdout = guard.0.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        for _ in 0..8 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut wire = None;
    let mut health = None;
    while wire.is_none() || health.is_none() {
        let Ok(line) = rx.recv_timeout(Duration::from_secs(10)) else {
            break;
        };
        if let Some(a) = line
            .split("listening on ")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .map(str::trim)
        {
            wire = Some(a.to_string());
        } else if let Some(a) = line
            .split("health endpoints on ")
            .nth(1)
            .and_then(|rest| rest.split(' ').next())
            .map(str::trim)
        {
            health = Some(a.to_string());
        }
    }
    let (Some(wire), Some(health)) = (wire, health) else {
        let mut err = String::new();
        if let Some(mut se) = guard.0.stderr.take() {
            let _ = se.read_to_string(&mut err);
        }
        panic!("could not parse wire+health addresses; stderr: {err}");
    };
    (guard, wire, health)
}

/// Runs one `ironbus` subcommand to completion, returning stdout, stderr, and the exit code. The
/// child's stdin/stdout are NOT a TTY (they are pipes), so the fuzzy picker is auto-skipped — the
/// reporting verbs stay scriptable here exactly as in a real pipeline.
fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("run an ironbus subcommand");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// A unique temp data dir for one test, removed first so a prior run never leaks state.
fn fresh_dir(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("ironbus-report-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.to_str().expect("utf8 temp path").to_string()
}

/// Produces `n` messages on the wire so the broker has non-trivial counters for the report.
fn produce(addr: &str, n: usize) {
    for i in 0..n {
        let (_o, _e, code) = run(&["pub", "--addr", addr, &format!("m{i}")]);
        assert_eq!(code, 0, "pub exit code");
    }
}

/// Snapshots a directory tree as a path -> bytes map, so a test can prove a verb did NOT mutate the
/// data dir. Recurses every subdirectory.
fn snapshot_tree(root: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                out.insert(rel, bytes);
            }
        }
    }
    out
}

/// A loopback port bound then dropped: connecting to it (almost certainly) fails fast, so a verb
/// targeting it exercises the broker-unreachable path deterministically.
fn dead_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let addr = listener.local_addr().expect("addr").to_string();
    drop(listener);
    addr
}

#[test]
fn report_storage_renders_from_live_metrics_and_exits_zero() {
    let data_dir = fresh_dir("storage");
    let (_broker, wire, health) = start_broker(&data_dir);
    produce(&wire, 3);

    let (out, err, code) = run(&["report", "storage", "--health-addr", &health]);
    assert_eq!(code, 0, "report storage exits 0; stderr: {err}");
    assert!(out.contains("report storage"), "{out}");
    assert!(out.contains("segments:"), "{out}");
    assert!(out.contains("durable bytes:"), "{out}");
    // disk-free is a real on-disk broker here, so it is a number, not the in-memory sentinel.
    assert!(out.contains("disk free:"), "{out}");
}

#[test]
fn report_connections_shows_the_lifecycle_counters() {
    let data_dir = fresh_dir("connections");
    let (_broker, wire, health) = start_broker(&data_dir);
    produce(&wire, 2); // each pub is an accepted+closed connection

    let (out, err, code) = run(&["report", "connections", "--addr", &health]);
    assert_eq!(code, 0, "report connections exits 0; stderr: {err}");
    assert!(out.contains("report connections"), "{out}");
    assert!(out.contains("accepted:"), "{out}");
    assert!(out.contains("rejected (pre-auth):"), "{out}");
}

#[test]
fn report_groups_is_scriptable_off_a_tty_and_lists_the_default_group() {
    let data_dir = fresh_dir("groups");
    let (_broker, wire, health) = start_broker(&data_dir);
    produce(&wire, 4);
    // Consume one so a named group exists with a committed cursor.
    let (_o, _e, code) = run(&[
        "sub", "--addr", &wire, "--group", "orders", "--max", "1", "--ack",
    ]);
    assert_eq!(code, 0, "sub exit code");

    // No --filter and NO TTY (the child's stdout is a pipe): the fuzzy picker is SKIPPED and the
    // full table is printed — proving the scriptable path.
    let (out, err, code) = run(&["report", "groups", "--health-addr", &health]);
    assert_eq!(code, 0, "report groups exits 0; stderr: {err}");
    assert!(out.contains("report groups"), "{out}");
    assert!(out.contains("GROUP"), "the table header prints: {out}");
}

#[test]
fn report_filter_narrows_to_one_group_and_skips_the_picker() {
    let data_dir = fresh_dir("filter");
    let (_broker, wire, health) = start_broker(&data_dir);
    produce(&wire, 3);
    let (_o, _e, code) = run(&[
        "sub", "--addr", &wire, "--group", "orders", "--max", "1", "--ack",
    ]);
    assert_eq!(code, 0, "sub exit code");

    let (out, err, code) = run(&[
        "report",
        "groups",
        "--health-addr",
        &health,
        "--filter",
        "orders",
    ]);
    assert_eq!(code, 0, "report groups --filter exits 0; stderr: {err}");
    assert!(out.contains("orders"), "{out}");
}

#[test]
fn report_global_json_wraps_the_table_in_the_frozen_envelope() {
    let data_dir = fresh_dir("json");
    let (_broker, _wire, health) = start_broker(&data_dir);

    // The global --json is LEADING (before the subcommand): the whole report is the cli.v1 envelope.
    let (out, err, code) = run(&["--json", "report", "storage", "--health-addr", &health]);
    assert_eq!(code, 0, "report --json exits 0; stderr: {err}");
    assert!(
        out.contains("\"schema\":\"ironbus.cli.v1\""),
        "the frozen envelope schema: {out}"
    );
    assert!(out.contains("\"ok\":true"), "{out}");
    assert!(out.contains("\"exit_code\":0"), "{out}");
    // The human table is carried verbatim inside data.stdout.
    assert!(
        out.contains("report storage"),
        "the table is carried: {out}"
    );
}

#[test]
fn report_against_a_dead_broker_exits_five() {
    let dead = dead_addr();
    let (_out, _err, code) = run(&["report", "storage", "--health-addr", &dead]);
    assert_eq!(code, 5, "report against a down broker is unreachable (5)");
}

#[test]
fn report_is_strictly_read_only() {
    let data_dir = fresh_dir("readonly");
    let (_broker, wire, health) = start_broker(&data_dir);
    produce(&wire, 5);

    let root = std::path::Path::new(&data_dir);
    let before = snapshot_tree(root);
    assert!(!before.is_empty(), "the data dir has files before report");

    for subject in ["groups", "streams", "storage", "recovery", "connections"] {
        let (_o, err, code) = run(&["report", subject, "--health-addr", &health]);
        assert_eq!(code, 0, "report {subject} exits 0; stderr: {err}");
    }
    let after = snapshot_tree(root);
    assert_eq!(
        before, after,
        "report is strictly read-only: the data dir must be byte-identical before and after"
    );
}

#[test]
fn server_check_on_a_healthy_broker_is_ok_and_exits_zero() {
    let data_dir = fresh_dir("check-ok");
    let (_broker, _wire, health) = start_broker(&data_dir);

    let (out, err, code) = run(&["server", "check", "--health-addr", &health]);
    assert_eq!(code, 0, "a healthy broker is OK (0); stderr: {err}");
    assert!(out.contains("IRONBUS OK"), "the Nagios OK line: {out}");
    assert!(out.contains("live and ready"), "{out}");
}

#[test]
fn server_check_on_a_dead_broker_is_unreachable_and_exits_five() {
    let dead = dead_addr();
    let (out, _err, code) = run(&["server", "check", "--health-addr", &dead]);
    assert_eq!(code, 5, "a down broker is UNREACHABLE (5)");
    assert!(
        out.contains("IRONBUS UNREACHABLE"),
        "the Nagios line: {out}"
    );
}

#[test]
fn server_info_reports_version_and_uptime() {
    let data_dir = fresh_dir("info");
    let (_broker, _wire, health) = start_broker(&data_dir);

    let (out, err, code) = run(&["server", "info", "--health-addr", &health]);
    assert_eq!(code, 0, "server info exits 0; stderr: {err}");
    assert!(out.contains("version:"), "{out}");
    assert!(out.contains("uptime:"), "{out}");
}

#[test]
fn server_healthz_and_ready_probe_the_distinct_endpoints() {
    let data_dir = fresh_dir("probes");
    let (_broker, _wire, health) = start_broker(&data_dir);

    let (out, err, code) = run(&["server", "healthz", "--health-addr", &health]);
    assert_eq!(code, 0, "healthz exits 0; stderr: {err}");
    assert!(out.contains("healthz: up"), "liveness up: {out}");

    let (out, err, code) = run(&["server", "ready", "--health-addr", &health]);
    assert_eq!(code, 0, "ready exits 0; stderr: {err}");
    assert!(out.contains("ready: up"), "readiness up: {out}");
}

#[test]
fn server_check_global_json_carries_the_status_in_the_envelope() {
    let data_dir = fresh_dir("check-json");
    let (_broker, _wire, health) = start_broker(&data_dir);

    let (out, err, code) = run(&["--json", "server", "check", "--health-addr", &health]);
    assert_eq!(code, 0, "server check --json on OK exits 0; stderr: {err}");
    assert!(out.contains("\"schema\":\"ironbus.cli.v1\""), "{out}");
    assert!(out.contains("IRONBUS OK"), "the status is carried: {out}");
}
