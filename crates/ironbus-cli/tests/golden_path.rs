// SPDX-License-Identifier: MIT OR Apache-2.0
//! Golden-path acceptance slice (#133): drive the real `ironbus` binary end to end through the
//! part of the promised story that is reachable today. Two scenarios run: a single default-group
//! consumer (boot, produce, consume, restart, resume past the acked messages while the durable
//! log continues), and the step-4 fan-out (one log to a broadcast group and a competing group,
//! each advancing independently and resuming durably across a restart). The rest of #133
//! (overload spill, a simulated power cut, the loss report, the installer) is not built yet and
//! stays open.
//!
//! `serve` is Unix only in v1 (on-disk storage uses positioned IO the Windows path lacks), so
//! this whole acceptance test is gated to Unix.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// The built `ironbus` binary (Cargo sets this for the crate's integration tests).
const BIN: &str = env!("CARGO_BIN_EXE_ironbus");

/// Kills and reaps the broker on drop, so a panicking assertion never leaks a serve process.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Boots `ironbus serve` on an ephemeral loopback port over `data_dir`, returning a kill-guard
/// and the bound `host:port` parsed from the broker's first stdout line. `--checkpoint-interval
/// 1` persists the cursor synchronously on each ack, so a restart resume is deterministic (no
/// race with the asynchronous close-path checkpoint).
fn start_broker(data_dir: &str) -> (ChildGuard, String) {
    let child = Command::new(BIN)
        .args([
            "serve",
            "--data-dir",
            data_dir,
            "--addr",
            "127.0.0.1:0",
            "--checkpoint-interval",
            "1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus serve");
    // Guard the child IMMEDIATELY: a bare std::process::Child does not kill on drop, so any
    // panic below (a read error, a timeout, an unparseable line) would otherwise orphan the
    // broker. With the guard in scope, every early exit kills and reaps it.
    let mut guard = ChildGuard(child);

    // Read the listening line on a worker thread bounded by a timeout, so a broker that wedges
    // without printing (and without exiting) fails the test promptly instead of hanging it.
    let stdout = guard.0.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let n = BufReader::new(stdout).read_line(&mut line).unwrap_or(0);
        let _ = tx.send((n, line));
    });
    let (n, line) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("ironbus serve did not print a listening line within 10s");
    if n == 0 {
        let mut err = String::new();
        if let Some(mut se) = guard.0.stderr.take() {
            let _ = se.read_to_string(&mut err);
        }
        panic!("ironbus serve exited before it listened: {err}");
    }
    // "ironbus listening on 127.0.0.1:<port>, data dir <dir>"
    let Some(addr) = line
        .split("listening on ")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .map(str::trim)
    else {
        panic!("could not parse the listening line: {line:?}");
    };
    (guard, addr.to_string())
}

/// Runs one `ironbus` subcommand to completion, returning its stdout and exit code.
fn run(args: &[&str]) -> (String, i32) {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("run an ironbus subcommand");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn golden_path_produce_consume_restart_resume() {
    let dir = std::env::temp_dir().join(format!("ironbus-golden-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);

    // 1. Boot the broker.
    let (broker, addr) = start_broker(&data_dir);

    // 2. Produce three messages; each ack carries the next durable offset.
    for (i, payload) in ["m0", "m1", "m2"].iter().enumerate() {
        let (out, code) = run(&["pub", "--addr", &addr, payload]);
        assert_eq!(code, 0, "pub exit code");
        assert_eq!(out.trim(), i.to_string(), "pub returned the durable offset");
    }

    // 3. Consume the whole batch and ack every message.
    let (out, code) = run(&["sub", "--addr", &addr, "--max", "10", "--ack"]);
    assert_eq!(code, 0, "sub exit code");
    assert!(
        out.contains("payload=m0") && out.contains("payload=m1") && out.contains("payload=m2"),
        "all three delivered: {out}"
    );
    assert_eq!(
        out.matches("ack committed").count(),
        3,
        "all three acked: {out}"
    );
    assert!(
        out.contains("fetched 3 message(s)"),
        "delivered count: {out}"
    );

    // 4. Restart the broker on the SAME data directory.
    drop(broker);
    let (broker2, addr2) = start_broker(&data_dir);

    // 5. Resume: the acked messages do not redeliver (the cursor was durable), and the log
    //    continues at offset 3 (the records were fsynced before their offsets were returned).
    let (out, code) = run(&["sub", "--addr", &addr2, "--max", "10"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("fetched 0 message(s)"),
        "resumed past the acked messages: {out}"
    );
    let (out, code) = run(&["pub", "--addr", &addr2, "m3"]);
    assert_eq!(code, 0);
    assert_eq!(
        out.trim(),
        "3",
        "the durable log continued across the restart"
    );

    drop(broker2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Extracts the `mN` payloads from a `sub` run's stdout. Each delivered message prints a line
/// `#<n> gen=<g> key=<k> payload=<value>`, so the value is the token right after `payload=`.
fn payloads(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split("payload=").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

#[test]
fn golden_path_broadcast_and_competing_groups_fan_out() {
    // #133 step 4: one durable log fans out to a BROADCAST group (its own cursor, sees every
    // message) and a COMPETING group (several members sharing one cursor, each message to one
    // member), every group advancing independently, and both resuming past their acks after a
    // restart via the durable per-group cursors (#9, #60, #248). Sequential `sub` calls keep it
    // deterministic: each consumer fully acks before the next runs, so the competing members get
    // disjoint sets. `--checkpoint-interval 1` checkpoints each group synchronously per ack, so
    // the restart resume below races nothing.
    let dir = std::env::temp_dir().join(format!("ironbus-golden-groups-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);

    let (broker, addr) = start_broker(&data_dir);

    // Produce four messages onto the single log.
    for (i, payload) in ["m0", "m1", "m2", "m3"].iter().enumerate() {
        let (out, code) = run(&["pub", "--addr", &addr, payload]);
        assert_eq!(code, 0, "pub exit code");
        assert_eq!(out.trim(), i.to_string(), "pub returned the durable offset");
    }

    // Broadcast group "bcast": its own cursor, so it sees the whole batch and acks it.
    let (out, code) = run(&[
        "sub", "--addr", &addr, "--group", "bcast", "--max", "10", "--ack",
    ]);
    assert_eq!(code, 0, "bcast sub exit code");
    assert!(
        out.contains("fetched 4 message(s)"),
        "the broadcast group sees the whole batch: {out}"
    );
    let mut bcast = payloads(&out);
    bcast.sort();
    assert_eq!(
        bcast,
        ["m0", "m1", "m2", "m3"],
        "the broadcast group received every message"
    );

    // Competing group "work": two members sharing one cursor. Member 1 takes (and acks) two;
    // member 2 then drains the rest. The two acks advance the shared cursor, so the members'
    // sets are disjoint and together cover the batch exactly once (per-group at-least-once).
    let (out1, code) = run(&[
        "sub", "--addr", &addr, "--group", "work", "--max", "2", "--ack",
    ]);
    assert_eq!(code, 0, "work member 1 exit code");
    let (out2, code) = run(&[
        "sub", "--addr", &addr, "--group", "work", "--max", "10", "--ack",
    ]);
    assert_eq!(code, 0, "work member 2 exit code");
    let m1 = payloads(&out1);
    let m2 = payloads(&out2);
    assert_eq!(
        m1.len(),
        2,
        "member 1 took exactly its credit of two: {out1}"
    );
    let mut combined: Vec<String> = m1.iter().chain(&m2).cloned().collect();
    combined.sort();
    assert_eq!(
        combined,
        ["m0", "m1", "m2", "m3"],
        "the competing members together consumed the batch exactly once, none dropped or doubled"
    );

    // The two groups advanced INDEPENDENTLY over the same log: a fresh fetch on each now sees
    // nothing, proving neither group's progress consumed the other's view.
    for g in ["bcast", "work"] {
        let (out, code) = run(&["sub", "--addr", &addr, "--group", g, "--max", "10"]);
        assert_eq!(code, 0);
        assert!(
            out.contains("fetched 0 message(s)"),
            "group {g} fully consumed its own view: {out}"
        );
    }

    // Restart: the durable per-group cursors resume both groups past their acks (#248).
    drop(broker);
    let (broker2, addr2) = start_broker(&data_dir);
    for g in ["bcast", "work"] {
        let (out, code) = run(&["sub", "--addr", &addr2, "--group", g, "--max", "10"]);
        assert_eq!(code, 0);
        assert!(
            out.contains("fetched 0 message(s)"),
            "group {g}'s durable cursor resumed past its acks after the restart: {out}"
        );
    }

    drop(broker2);
    let _ = std::fs::remove_dir_all(&dir);
}
