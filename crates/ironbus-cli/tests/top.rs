// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end tests for `ironbus top` (#93): the LIVE and OFFLINE modes, the mandatory offline
//! banner, the read-only property, the broker-unreachable exit code, and the plain (escape-free)
//! degradation under `NO_COLOR` / a non-TTY stdout. These drive the REAL compiled binary against a
//! REAL broker, so they fail if any mode, the read-only guarantee, or the degradation regresses.
//!
//! Unix-only: the offline half reads the on-disk store (Unix-only in v1), and the broker `serve`
//! itself is Unix-only in v1. The whole file is gated so the Windows build does not try to spawn a
//! Unix-only broker.
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

/// Boots `ironbus serve` with the wire and health ports on ephemeral loopback addresses and the
/// read-only `/admin` endpoint enabled, returning a kill-guard plus the parsed wire and health
/// addresses. `--checkpoint-interval 1` flushes the cursor on each ack so a later offline read is
/// deterministic.
fn start_broker_with_admin(data_dir: &str) -> (ChildGuard, String, String) {
    let child = Command::new(BIN)
        .args([
            "serve",
            "--data-dir",
            data_dir,
            "--addr",
            "127.0.0.1:0",
            "--health-addr",
            "127.0.0.1:0",
            "--enable-admin",
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

/// Runs one `ironbus` subcommand to completion with `NO_COLOR=1` (so the output is the plain,
/// escape-free form regardless of where the test runs), returning stdout, stderr, and the exit code.
fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(BIN)
        .args(args)
        .env("NO_COLOR", "1")
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
    let dir = std::env::temp_dir().join(format!("ironbus-top-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.to_str().expect("utf8 temp path").to_string()
}

/// Produces `n` messages on the wire so the broker has a non-trivial head for the live view.
fn produce(addr: &str, n: usize) {
    for i in 0..n {
        let (_o, _e, code) = run(&["pub", "--addr", addr, &format!("m{i}")]);
        assert_eq!(code, 0, "pub exit code");
    }
}

/// Snapshots a directory tree as a map of relative-path -> file bytes, so a test can prove `top`
/// did NOT mutate the data dir (no new/removed file, no changed content). Recurses every
/// subdirectory (segments, cursor checkpoints, dlq/, quarantine/).
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

#[test]
fn live_top_once_renders_the_counters_and_exits_zero() {
    let data_dir = fresh_dir("live");
    let (_broker, wire, health) = start_broker_with_admin(&data_dir);
    produce(&wire, 3);

    let (out, err, code) = run(&["top", "--health-addr", &health, "--once"]);
    assert_eq!(code, 0, "live top --once exits 0; stderr: {err}");
    // The mandatory mode banner names LIVE.
    assert!(out.contains("LIVE"), "live banner: {out}");
    // The #16 counters render with their /admin source named.
    assert!(out.contains("durable_head=3"), "durable head: {out}");
    assert!(out.contains("[source: /admin"), "source attribution: {out}");
    assert!(
        out.contains("throughput: produced=3"),
        "throughput panel: {out}"
    );
    // The default group is shown with full lag (nothing consumed yet).
    assert!(
        out.contains("(default): committed=0 lag=3"),
        "per-group lag panel: {out}"
    );
    // top is read-only: it prints, never runs, an action.
    assert!(out.contains("read-only"), "read-only note: {out}");
    // Plain (NO_COLOR) output carries NO ANSI escape sequence.
    assert!(
        !out.contains('\x1b'),
        "NO_COLOR live output must be escape-free: {out:?}"
    );
}

#[test]
fn live_top_json_once_is_the_versioned_v1_shape() {
    let data_dir = fresh_dir("live-json");
    let (_broker, wire, health) = start_broker_with_admin(&data_dir);
    produce(&wire, 2);

    let (out, err, code) = run(&["top", "--addr", &health, "--once", "--json"]);
    assert_eq!(code, 0, "live top --json --once exits 0; stderr: {err}");
    assert!(
        out.contains("\"schema\":\"ironbus.cli.top.v1\""),
        "versioned schema: {out}"
    );
    assert!(out.contains("\"mode\":\"live\""), "live mode tag: {out}");
    assert!(
        out.contains("\"durable_head\":2"),
        "durable head field: {out}"
    );
    assert!(!out.contains('\x1b'), "json must be escape-free: {out:?}");
}

#[test]
fn live_top_against_a_dead_broker_exits_five() {
    // Bind a loopback port, then drop the listener so the port is (almost certainly) closed: a
    // connect fails fast and `top` maps it to broker-unreachable (exit 5).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let dead = listener.local_addr().expect("addr").to_string();
    drop(listener);

    let (_out, _err, code) = run(&["top", "--health-addr", &dead, "--once"]);
    assert_eq!(
        code, 5,
        "a live top against a down broker exits 5 (unreachable)"
    );
}

#[test]
fn offline_top_once_renders_the_file_panels_with_the_mandatory_banner() {
    let data_dir = fresh_dir("offline");
    // Create durable data, then STOP the broker so the offline read has no live server.
    {
        let (broker, wire, _health) = start_broker_with_admin(&data_dir);
        produce(&wire, 4);
        drop(broker);
    }

    let (out, err, code) = run(&["top", "--data-dir", &data_dir, "--once"]);
    assert_eq!(code, 0, "offline top --once exits 0; stderr: {err}");
    // The MANDATORY offline banner: an operator can never confuse offline with live.
    assert!(out.contains("OFFLINE"), "offline banner: {out}");
    assert!(
        out.contains("file-derived"),
        "file-derived banner text: {out}"
    );
    assert!(out.contains("NO broker"), "no-broker banner text: {out}");
    // File-derived panels render (the head reflects the 4 produces).
    assert!(
        out.contains("durable_head=4"),
        "offline durable head: {out}"
    );
    assert!(out.contains("log: segments="), "segments panel: {out}");
    assert!(
        out.contains("quarantine: blobs="),
        "quarantine panel: {out}"
    );
    // Volatile live panels are explicitly stated unavailable, never faked as zeros.
    assert!(
        out.contains("NOT available offline"),
        "offline must state volatile panels are unavailable: {out}"
    );
    assert!(
        !out.contains("throughput: produced"),
        "no live throughput panel in offline mode: {out}"
    );
    assert!(out.contains("read-only"), "read-only note: {out}");
    assert!(
        !out.contains('\x1b'),
        "NO_COLOR offline output must be escape-free: {out:?}"
    );
}

#[test]
fn offline_top_is_strictly_read_only() {
    let data_dir = fresh_dir("readonly");
    {
        let (broker, wire, _health) = start_broker_with_admin(&data_dir);
        produce(&wire, 5);
        drop(broker);
    }
    let root = std::path::Path::new(&data_dir);
    let before = snapshot_tree(root);
    assert!(!before.is_empty(), "the data dir has files before top");

    // Run the offline snapshot; it must not change a single byte on disk.
    let (_out, err, code) = run(&["top", "--data-dir", &data_dir, "--once"]);
    assert_eq!(code, 0, "offline top --once exits 0; stderr: {err}");

    let after = snapshot_tree(root);
    assert_eq!(
        before, after,
        "top is strictly read-only: the data dir must be byte-identical before and after"
    );
}

#[test]
fn top_requires_exactly_one_mode() {
    // Neither mode.
    let (_o, _e, code) = run(&["top"]);
    assert_eq!(code, 1, "top with no mode is a usage error");
    // Both modes.
    let (_o, _e, code) = run(&["top", "--addr", "127.0.0.1:1", "--data-dir", "/tmp/x"]);
    assert_eq!(code, 1, "top with both modes is a usage error");
}
