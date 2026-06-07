// SPDX-License-Identifier: MIT OR Apache-2.0
//! Golden-path acceptance slice (#133): drive the real `ironbus` binary end to end through the
//! parts of the promised story that are reachable today. The scenarios run: a single default-group
//! consumer (boot, produce, consume, restart, resume past the acked messages while the durable log
//! continues); the step-4 fan-out (one log to a broadcast group and a competing group, each
//! advancing independently and resuming durably across a restart); step-9 offline inspection
//! (`peek`/`dump` over a stopped broker agrees with recovery up to the durable head); and steps 6
//! and 7, power-cut recovery (a torn tail is truncated, the durable prefix survives, and the loss
//! is reported consistently offline and online). Only the overload spill (step 5) and the
//! installer (step 1) remain.
//!
//! `serve` is Unix only in v1 (on-disk storage uses positioned IO the Windows path lacks), so
//! this whole acceptance test is gated to Unix.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
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

/// Extracts the offsets from an offline `peek` / `dump` run's stdout. Each record prints a line
/// `offset=<n> ts_ms=<t> bytes=<b> key_bytes=<k> crc=ok codec=none`, so the offset is the token
/// right after `offset=`. A trailing `note:` loss line carries no `offset=` token, so it is
/// skipped: only real record offsets are returned, in the order the reader emitted them.
fn offline_offsets(out: &str) -> Vec<u64> {
    out.lines()
        .filter_map(|l| l.strip_prefix("offset="))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|tok| tok.parse::<u64>().ok())
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

#[test]
fn golden_path_offline_inspection_agrees_with_recovery() {
    // #133 step 9: with the broker STOPPED, the offline inspection verbs (`dump`, `peek`) read
    // exactly the produced records up to the durable high-water mark and no further, agreeing
    // with what recovery would resume. Records are fsynced before `pub` returns the offset, so
    // the data directory is durable even after the broker exits, and the offline reader sees the
    // committed log without a server running. This drives the REAL `ironbus` binary end to end.
    const N: u64 = 4;

    let dir = std::env::temp_dir().join(format!("ironbus-golden-offline-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);

    // 1. Boot the broker and produce N records; each `pub` returns its durable offset.
    let (broker, addr) = start_broker(&data_dir);
    for i in 0..N {
        let payload = format!("m{i}");
        let (out, code) = run(&["pub", "--addr", &addr, &payload]);
        assert_eq!(code, 0, "pub exit code");
        assert_eq!(out.trim(), i.to_string(), "pub returned the durable offset");
    }

    // 2. Cleanly stop the broker (drop the kill-guard) before reading the directory offline.
    drop(broker);

    // 3. With the broker STOPPED, `dump` streams every durable record, one per line. It must show
    //    exactly offsets 0..N, in order, with no phantom record past the durable high-water mark.
    let (dump_out, code) = run(&["dump", "--data-dir", &data_dir]);
    assert_eq!(code, 0, "dump exit code: {dump_out}");
    let dumped = offline_offsets(&dump_out);
    let expected: Vec<u64> = (0..N).collect();
    assert_eq!(
        dumped, expected,
        "dump showed exactly the produced offsets 0..N, in order: {dump_out}"
    );
    // No phantom records: the offline reader stops at the durable high-water mark.
    assert!(
        !dump_out.contains(&format!("offset={N}")),
        "dump shows nothing past the durable high-water mark: {dump_out}"
    );
    // A clean directory has no torn or corrupt tail, so no loss note is emitted.
    assert!(
        !dump_out.contains("note:"),
        "a clean directory reports no loss: {dump_out}"
    );

    // `peek` with no window shows the same prefix (N < the default window of 10).
    let (peek_out, code) = run(&["peek", "--data-dir", &data_dir]);
    assert_eq!(code, 0, "peek exit code: {peek_out}");
    assert_eq!(
        offline_offsets(&peek_out),
        expected,
        "peek shows the same durable records as dump: {peek_out}"
    );

    // `peek --limit` shows a bounded subset: the first two records only, and never past N.
    let (window_out, code) = run(&["peek", "--data-dir", &data_dir, "--limit", "2"]);
    assert_eq!(code, 0, "peek --limit exit code: {window_out}");
    assert_eq!(
        offline_offsets(&window_out),
        vec![0, 1],
        "peek --limit bounds the window to the first two records: {window_out}"
    );

    // `peek --from-offset` plus `--limit` reads a bounded window starting mid-log, still bounded
    // by the durable high-water mark (offsets 2 and 3 only, never a phantom offset N).
    let (tail_out, code) = run(&[
        "peek",
        "--data-dir",
        &data_dir,
        "--from-offset",
        "2",
        "--limit",
        "10",
    ]);
    assert_eq!(code, 0, "peek --from-offset exit code: {tail_out}");
    assert_eq!(
        offline_offsets(&tail_out),
        vec![2, 3],
        "peek --from-offset reads only up to the durable high-water mark: {tail_out}"
    );

    // 4. `dump --json` produces valid NDJSON: exactly one JSON object per record, offsets 0..N in
    //    order, each a record object (not the loss object), and nothing past the high-water mark.
    let (json_out, code) = run(&["dump", "--data-dir", &data_dir, "--json"]);
    assert_eq!(code, 0, "dump --json exit code: {json_out}");
    let json_lines: Vec<&str> = json_out.lines().collect();
    assert_eq!(
        json_lines.len(),
        usize::try_from(N).unwrap(),
        "one NDJSON line per record, no loss object on a clean directory: {json_out}"
    );
    for (i, line) in json_lines.iter().enumerate() {
        assert!(
            line.starts_with('{') && line.ends_with('}'),
            "each line is one JSON object: {line}"
        );
        assert!(
            line.contains(&format!("\"offset\":{i}")),
            "line {i} carries offset {i}: {line}"
        );
        assert!(
            line.contains("\"crc\":\"ok\""),
            "the offline reader only yields CRC-clean records: {line}"
        );
        assert!(
            !line.contains("\"loss\""),
            "a clean directory has no loss object: {line}"
        );
    }
    assert!(
        !json_out.contains(&format!("\"offset\":{N}")),
        "dump --json shows nothing past the durable high-water mark: {json_out}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Like [`start_broker`] but also opens the health endpoints on their own ephemeral loopback
/// port, returning `(guard, wire_addr, health_addr)`. The broker prints the wire listening line
/// then the health line, so this reads both (order-independently) under a timeout.
fn start_broker_with_health(data_dir: &str) -> (ChildGuard, String, String) {
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
        for _ in 0..2 {
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
    for _ in 0..2 {
        let line = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("ironbus serve did not print its addresses within 10s");
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

/// Minimal blocking HTTP/1.0 GET against a loopback `host:port`, returning the full response
/// (headers and body). Used to read the broker's `/metrics` exposition. Retries briefly so a
/// just-spawned health thread that has not yet entered its accept loop does not flake a slow runner.
fn http_get(addr: &str, path: &str) -> String {
    for _ in 0..40 {
        if let Ok(body) = http_get_once(addr, path) {
            if !body.is_empty() {
                return body;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("health endpoint {addr} did not answer GET {path} in time");
}

fn http_get_once(addr: &str, path: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    let mut body = String::new();
    stream.read_to_string(&mut body)?;
    Ok(body)
}

/// Reads a Prometheus gauge/counter value by exact metric name from an exposition body, skipping
/// the `# HELP` / `# TYPE` lines (the sample line is `<name> <value>`).
fn metric_value(body: &str, name: &str) -> Option<u64> {
    let prefix = format!("{name} ");
    body.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse().ok())
    })
}

/// Reads the byte count from a `dump`/`peek` human loss note (`note: <n> byte(s) ...`).
fn dump_loss_bytes(out: &str) -> Option<u64> {
    out.lines().find_map(|line| {
        line.trim()
            .strip_prefix("note: ")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse().ok())
    })
}

/// Appends `garbage` to the active (lexicographically-last) `seg-*.log` in `data_dir`, modeling a
/// power cut that left a partial record never completed at the tail. Segments grow (they are not
/// pre-allocated), so this lands the torn bytes immediately past the last durable record.
fn append_torn_tail(data_dir: &str, garbage: &[u8]) {
    let seg = std::fs::read_dir(data_dir)
        .expect("read data dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("log")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("seg-"))
        })
        .max()
        .expect("an active segment file");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&seg)
        .expect("open the active segment for append");
    f.write_all(garbage).expect("append the torn tail");
    f.sync_all().expect("persist the torn tail");
}

#[test]
fn golden_path_power_cut_recovers_the_durable_prefix_and_reports_loss() {
    // #133 steps 6 and 7: a power cut leaves a torn tail (a partial record never completed) in
    // the active segment. On restart, recovery must truncate the torn tail (never read past it),
    // preserve the durable prefix (I1: no acked record lost), and report the loss in BOTH the
    // offline reader (dump) and the online recovery counter (/metrics), and the two must AGREE on
    // the byte count. Records are fsynced before pub returns, so the four below are durable.
    const TORN: usize = 40;
    let dir = std::env::temp_dir().join(format!("ironbus-golden-powercut-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);

    // Produce four durable records, then stop the broker.
    let (broker, addr) = start_broker(&data_dir);
    for (i, p) in ["m0", "m1", "m2", "m3"].iter().enumerate() {
        let (out, code) = run(&["pub", "--addr", &addr, p]);
        assert_eq!(code, 0, "pub exit code");
        assert_eq!(out.trim(), i.to_string(), "pub returned the durable offset");
    }
    drop(broker);

    // Simulate the power cut: append a torn tail (0xFF bytes, which cannot start a valid record
    // since they are not the 0x4942 record magic) past the last durable record.
    append_torn_tail(&data_dir, &[0xFF_u8; TORN]);

    // Offline (broker stopped): dump shows the four durable records AND reports the torn tail,
    // never reading past the durable head.
    let (dumped, code) = run(&["dump", "--data-dir", &data_dir]);
    assert_eq!(
        code, 0,
        "dump over a torn dir still succeeds (the tail is reported, not fatal)"
    );
    assert_eq!(
        offline_offsets(&dumped),
        vec![0, 1, 2, 3],
        "the durable prefix is intact and nothing past the head is read: {dumped}"
    );
    let offline_loss =
        dump_loss_bytes(&dumped).expect("dump reports a torn-tail loss note over a torn dir");
    assert_eq!(
        offline_loss, TORN as u64,
        "the reported loss equals the torn-tail length"
    );
    assert!(
        dumped.contains("torn or corrupt"),
        "the loss note names the cause: {dumped}"
    );

    // Online: restart the broker. Recovery truncates the torn tail and records the dropped bytes,
    // which /metrics exposes; it must agree with the offline dump's loss.
    let (broker2, addr2, health2) = start_broker_with_health(&data_dir);
    let metrics = http_get(&health2, "/metrics");
    let truncated = metric_value(&metrics, "ironbus_recovery_truncated_bytes")
        .expect("/metrics exposes ironbus_recovery_truncated_bytes");
    assert_eq!(
        truncated, offline_loss,
        "the online recovery counter agrees with the offline loss report"
    );

    // The durable prefix survived and is fully consumable after the power cut.
    let (out, code) = run(&["sub", "--addr", &addr2, "--max", "10", "--ack"]);
    assert_eq!(code, 0, "sub exit code");
    let mut got = payloads(&out);
    got.sort();
    assert_eq!(
        got,
        ["m0", "m1", "m2", "m3"],
        "every durable record survived the power cut"
    );

    // Recovery truncated the torn tail, so the durable log continues cleanly from offset 4.
    let (out, code) = run(&["pub", "--addr", &addr2, "m4"]);
    assert_eq!(code, 0);
    assert_eq!(
        out.trim(),
        "4",
        "the durable log continues from the truncated head"
    );

    drop(broker2);
    let _ = std::fs::remove_dir_all(&dir);
}
