// SPDX-License-Identifier: MIT OR Apache-2.0
//! Golden-path acceptance slice (#133): drive the real `ironbus` binary end to end through the
//! parts of the promised story that are reachable today. The scenarios run: a single default-group
//! consumer (boot, produce, consume, restart, resume past the acked messages while the durable log
//! continues); the step-2 health probes (`/healthz` and `/readyz` come up and report healthy,
//! bound to loopback only, with an unknown path returning a real 404); the step-4 fan-out (one log
//! to a broadcast group and a competing group, each advancing independently and resuming durably
//! across a restart); step-9 offline inspection (`peek`/`dump` over a stopped broker agrees with
//! recovery up to the durable head); and steps 6 and 7, power-cut recovery (a torn tail is
//! truncated, the durable prefix survives, and the loss is reported consistently offline and
//! online); step-5 overload (the durable log spills to disk and absorbs the accepted prefix,
//! then sheds drop-new once it is at or over its byte cap, with the client shed count agreeing
//! exactly with the server's reject counter); and step-8 disk-full drop-oldest (a stuck
//! consumer's records are force-reaped under the byte cap, so its next fetch gets exactly one
//! truncation, resumes at the oldest record still retained, and makes progress without
//! re-truncating). Only the installer and in-place upgrade steps, which need a release, remain.
//!
//! `serve` is Unix only in v1 (on-disk storage uses positioned IO the Windows path lacks), so
//! this whole acceptance test is gated to Unix.
#![cfg(unix)]

use ironbus_client::Client;
use ironbus_proto::message::PubBody;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
    let (stdout, _stderr, code) = run_err(args);
    (stdout, code)
}

/// Like [`run`] but also returns stderr, so a test can read the human error a failed subcommand
/// printed (for example the shed producer's "at capacity" message) alongside the exit code.
fn run_err(args: &[&str]) -> (String, String, i32) {
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

/// Extracts the delivered record offsets from a `sub` run's stdout. Each delivered message prints
/// a line `#<n> gen=<g> key=<k> payload=<value>`, so the offset is the token right after the `#`
/// at the start of the line. The `  ack ...`, `truncated: ...`, and `fetched ...` lines carry no
/// leading `#`, so they are skipped: only real delivered offsets are returned, in delivery order.
fn delivered_offsets(out: &str) -> Vec<u64> {
    out.lines()
        .filter_map(|l| l.strip_prefix('#'))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|tok| tok.parse::<u64>().ok())
        .collect()
}

/// Extracts the resume offsets from a `sub` run's truncation advisories. `ironbus sub` prints a
/// line `truncated: resumed at offset <n>, skipped <k> record(s)` once per cursor reset below the
/// oldest retained record (#82, #84). Returns one `<n>` per such line, so a test can assert both
/// the COUNT of truncations (exactly one per gap, never re-truncated) and the resume offset.
fn truncation_resume_offsets(out: &str) -> Vec<u64> {
    out.lines()
        .filter_map(|l| l.trim().strip_prefix("truncated: resumed at offset "))
        .filter_map(|rest| rest.split(',').next())
        .filter_map(|tok| tok.trim().parse::<u64>().ok())
        .collect()
}

/// Produces `n` records of `payload` to `addr` via the real `pub` binary, asserting each one is
/// ACCEPTED (exit 0) and lands at the next contiguous offset starting from `base`. Under the
/// drop-oldest policy every produce succeeds (force-reap makes room) rather than shedding, so a
/// non-zero exit here would mean the drop-oldest path did not engage; the contiguous offsets prove
/// none was lost. Kept out of the test body so the scenario reads as steps, not a produce loop.
fn produce_contiguous(addr: &str, payload: &str, base: usize, n: usize) {
    for i in 0..n {
        let (out, code) = run(&["pub", "--addr", addr, payload]);
        assert_eq!(
            code, 0,
            "drop-oldest accepts every produce (no shed): {out}"
        );
        assert_eq!(
            out.trim(),
            (base + i).to_string(),
            "the durable log marched on under drop-oldest, no gaps: {out}"
        );
    }
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
    start_broker_with_health_args(data_dir, &[])
}

/// Like [`start_broker_with_health`] but threads `extra` serve flags (for example a
/// `--max-total-bytes` cap) onto the same boot path, so a test can configure the broker without
/// duplicating the spawn-and-parse logic. The base flags (ephemeral wire and health ports,
/// `--checkpoint-interval 1`) are always present; `extra` is appended verbatim.
fn start_broker_with_health_args(data_dir: &str, extra: &[&str]) -> (ChildGuard, String, String) {
    let mut args = vec![
        "serve",
        "--data-dir",
        data_dir,
        "--addr",
        "127.0.0.1:0",
        "--health-addr",
        "127.0.0.1:0",
        "--checkpoint-interval",
        "1",
    ];
    args.extend_from_slice(extra);
    let child = Command::new(BIN)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus serve");
    let mut guard = ChildGuard(child);
    let stdout = guard.0.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        // Forward the startup lines: "listening on" and "health
        // endpoints on" (a few extra to absorb any future startup line), so the consumer can find
        // both addresses regardless of their relative order.
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
    // Read startup lines until BOTH addresses are seen (or the stream ends): the materialized-config
    // line (#87) now sits between the listen and health lines, so a fixed two-line read would miss
    // the health address.
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

/// Splits a minimal HTTP/1.0 response (as returned by [`http_get`]) into its status line and its
/// body, so a test can assert the exact status AND the exact body marker, not merely a 200. The
/// header block ends at the first blank line (`\r\n\r\n`); everything after it is the body.
fn split_status_and_body(resp: &str) -> (&str, &str) {
    let status = resp.lines().next().unwrap_or("").trim_end();
    let body = resp
        .split_once("\r\n\r\n")
        .map_or("", |(_, body)| body)
        .trim_end();
    (status, body)
}

#[test]
fn golden_path_health_endpoints_come_up_on_loopback() {
    // #133 step 2: boot zero-config and assert the health endpoints come up, report healthy, and
    // are bound to LOOPBACK only (#16, #18). Drive the real `ironbus` binary: serve binds the
    // health HTTP port on an ephemeral loopback address (`--health-addr 127.0.0.1:0`) and prints
    // it, then `/healthz` is liveness and `/readyz` is readiness. The markers are exact (the
    // status line AND the body health.rs returns), so the test cannot pass on an empty or wrong
    // response, and an UNKNOWN path must NOT be a blanket 200, proving the router is real.
    let dir = std::env::temp_dir().join(format!("ironbus-golden-health-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);

    // 1. Boot the broker with the health endpoints on an ephemeral loopback port.
    let (broker, _wire, health) = start_broker_with_health(&data_dir);

    // 2. The bound health address is LOOPBACK only: an IPv4 `127.x` or the IPv6 `::1` (never a
    //    routable interface). The serve flag pins 127.0.0.1, so a regression that bound 0.0.0.0
    //    or a public address (no-auth-on-loopback would then leak) fails here.
    let host = health
        .rsplit_once(':')
        .map_or(health.as_str(), |(host, _port)| host);
    assert!(
        host.starts_with("127.") || host == "::1" || host == "[::1]",
        "the health endpoints are bound to loopback only, got {health}"
    );

    // 3. GET /healthz: liveness. health.rs answers `HTTP/1.1 200 OK` with the body `ok` for a
    //    live loop. Assert BOTH the status line carries 200 AND the body is exactly `ok`.
    let resp = http_get(&health, "/healthz");
    let (status, body) = split_status_and_body(&resp);
    assert_eq!(
        status, "HTTP/1.1 200 OK",
        "/healthz reports healthy with a 200 status line: {resp:?}"
    );
    assert_eq!(
        body, "ok",
        "/healthz body is the exact healthy marker: {resp:?}"
    );

    // 4. GET /readyz: readiness. A freshly booted broker's writer is live (an active segment is
    //    open), so health.rs answers `HTTP/1.1 200 OK` with the body `ready` (a frozen writer
    //    would answer 503 "writer frozen"). `http_get` already retries a just-spawned health
    //    thread, so a brief readiness lag converges; we then assert the EXACT ready marker.
    let resp = http_get(&health, "/readyz");
    let (status, body) = split_status_and_body(&resp);
    assert_eq!(
        status, "HTTP/1.1 200 OK",
        "/readyz reports ready with a 200 status line once the broker is up: {resp:?}"
    );
    assert_eq!(
        body, "ready",
        "/readyz body is the exact ready marker: {resp:?}"
    );

    // 5. An UNKNOWN path is NOT a blanket 200: health.rs routes everything else to 404 with the
    //    body `unknown endpoint`. This proves the router is real (a 200-for-everything stub would
    //    fail here), so the healthy assertions above are non-vacuous.
    let resp = http_get(&health, "/nope");
    let (status, body) = split_status_and_body(&resp);
    assert_eq!(
        status, "HTTP/1.1 404 Not Found",
        "an unknown path is a real 404, not a blanket 200: {resp:?}"
    );
    assert_eq!(
        body, "unknown endpoint",
        "the 404 body is the exact unknown-endpoint marker: {resp:?}"
    );

    drop(broker);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn golden_path_overload_spills_then_sheds_at_the_byte_cap() {
    // #133 step 5: under overload, the durable log SPILLS to disk and absorbs the accepted
    // prefix, then SHEDS (drop-new) once it is at or over its byte cap (#10). Drive the real
    // binary: boot with a small `--max-total-bytes` so only a few small records fit, then pub a
    // fixed batch and watch the split. The shed is non-fatal (the connection stays open and the
    // server replies a distinct "at capacity" Err), so a shed `pub` exits non-zero but the
    // broker keeps serving. The load-bearing, NON-VACUOUS checks are: the client shed count
    // EQUALS the server's `ironbus_produce_rejected_total`, and every accepted record is durably
    // consumable in order. Acking does not free cap space (retention is #13, not built), so once
    // the cap engages every later pub is shed regardless of consumption: we do not consume
    // between pubs.
    //
    // The split is deterministic. Each `pub` carries an empty key, empty headers, and a 2-byte
    // payload (`m0`..`m9`), so each durable record is 46 bytes on disk (36-byte header + 0 key +
    // 0 headers + 2 payload + 8-byte trailer). The cap check rejects a produce when the durable
    // record bytes are at or over the cap AND non-zero, but the FIRST record on an empty log
    // always writes. With a 100-byte cap: record 0 writes (log empty), record 1 writes (46 < 100
    // -> 92), record 2 writes (92 < 100 -> 138), and from record 3 on the log is over the cap, so
    // every further pub is shed. That is exactly three accepted, the rest shed.
    const CAP: u64 = 100;
    const N: usize = 10;
    let dir = std::env::temp_dir().join(format!("ironbus-golden-overload-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);

    // 1. Boot the broker with a small total-byte cap and the health endpoints (for /metrics).
    let (broker, addr, health) =
        start_broker_with_health_args(&data_dir, &["--max-total-bytes", &CAP.to_string()]);

    // 2. Produce N small records. A record that spilled exits 0 and prints its durable offset; a
    //    shed record exits non-zero (the server's "at capacity" Err maps to ClientError::Server,
    //    which the CLI classifies as an internal failure, exit 70) and its stderr names the shed.
    let mut accepted: Vec<String> = Vec::new();
    let mut shed = 0u64;
    for i in 0..N {
        let payload = format!("m{i}");
        let (out, err, code) = run_err(&["pub", "--addr", &addr, &payload]);
        if code == 0 {
            assert_eq!(
                out.trim(),
                accepted.len().to_string(),
                "an accepted pub prints the next durable offset (no gaps in the accepted prefix)"
            );
            accepted.push(payload);
        } else {
            shed += 1;
            assert!(
                err.contains("at capacity"),
                "a shed pub names the deliberate shed, not a transient failure: stderr {err:?}"
            );
        }
    }

    // 3. Non-vacuity: the log SPILLED (at least one accepted) AND the cap ENGAGED (at least one
    //    shed). Without both, the scenario would not exercise spill-then-shed.
    assert!(
        !accepted.is_empty(),
        "at least one pub spilled to disk and was accepted"
    );
    assert!(shed >= 1, "at least one pub was shed once the cap engaged");
    assert_eq!(
        accepted.len() + usize::try_from(shed).expect("shed fits usize"),
        N,
        "every pub either spilled or was shed, none lost track of"
    );

    // 4. LOAD-BEARING: the client shed count equals the server's shed counter EXACTLY. The
    //    rejections the producer saw are precisely the produces the broker dropped, no more, no
    //    fewer (never a silent drop the counter missed, never a phantom rejection it overcounted).
    let metrics = http_get(&health, "/metrics");
    let rejected = metric_value(&metrics, "ironbus_produce_rejected_total")
        .expect("/metrics exposes ironbus_produce_rejected_total");
    assert_eq!(
        rejected, shed,
        "the server's produce-rejected counter equals the client's observed shed count: {metrics}"
    );

    // 5. The broker is STILL ALIVE after the shed: a further pub is promptly rejected again
    //    (never a hang, never a silent success). This is the "never a silent drop and never an
    //    indefinite hang" requirement. The counter advances by exactly one for this one rejection.
    let (_out, err, code) = run_err(&["pub", "--addr", &addr, "after-shed"]);
    assert_ne!(
        code, 0,
        "a pub over the engaged cap is rejected, not accepted"
    );
    assert!(
        err.contains("at capacity"),
        "the further pub is shed too, not a silent success: stderr {err:?}"
    );
    let metrics2 = http_get(&health, "/metrics");
    let rejected2 = metric_value(&metrics2, "ironbus_produce_rejected_total")
        .expect("/metrics still exposes the counter after the further shed");
    assert_eq!(
        rejected2,
        rejected + 1,
        "the further shed incremented the live counter by exactly one: {metrics2}"
    );

    // 6. LOAD-BEARING: every accepted record is durably consumable, in order, and nothing else.
    //    The accepted prefix survived the overload exactly; nothing accepted was lost, and no
    //    shed record leaked into the log. A credit far above the batch drains it in one fetch.
    let (out, code) = run(&["sub", "--addr", &addr, "--max", "100", "--ack"]);
    assert_eq!(code, 0, "sub exit code: {out}");
    assert_eq!(
        payloads(&out),
        accepted,
        "the consumable log is exactly the accepted prefix, in order: {out}"
    );
    assert!(
        out.contains(&format!("fetched {} message(s)", accepted.len())),
        "exactly the accepted records were delivered, none extra: {out}"
    );

    drop(broker);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn golden_path_drop_oldest_truncates_a_stuck_consumer() {
    // #133 step 8: under the disk-full DROP-OLDEST policy (#82), producing past the byte cap
    // FORCE-reaps the oldest sealed segments to make room, even ones a slow consumer has not
    // consumed. A consumer whose committed cursor falls below the oldest record still retained
    // then gets EXACTLY ONE truncation on its next fetch (#84): its cursor resets up to the
    // earliest retained offset, delivery resumes there, and the gap is closed so it never
    // re-truncates. Drive the real binary end to end and assert the relationships, not a brittle
    // exact offset (the resume offset depends on roll and reap timing): the truncation appears
    // exactly once, its resume offset is above where the consumer was stuck (it skipped a reaped
    // span), the consumer resumes AT that offset and makes progress, the server's force-reap
    // counter advanced, and a later fetch sees no second truncation.
    //
    // Sizing the roll and the reap deterministically. The CLI floors `--max-segment-bytes` at
    // 4096, so each record carries a ~956-byte payload (empty key and headers) for ~1000 record
    // bytes on disk (36-byte header + 956 payload + 8-byte trailer = 1000), which seals a 4096-byte
    // segment after ~4 records. A 7000-byte total cap (above one sealed segment, so at least one
    // segment seals before the cap engages and a sealed segment is always available to force-reap)
    // makes a steady producer trip the cap repeatedly; under drop-oldest every produce is ACCEPTED
    // (force-reap makes room) rather than shed, and force-reaping marches the earliest retained
    // offset well past the stuck consumer's cursor. Producing many more records makes the reaped
    // span (and so the resume offset) comfortably exceed the stuck cursor on any timing.
    const PAYLOAD_BYTES: usize = 956;
    const EXTRA: usize = 60;
    let payload = "a".repeat(PAYLOAD_BYTES);

    let dir =
        std::env::temp_dir().join(format!("ironbus-golden-dropoldest-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);

    // 1. Boot the broker with drop-oldest, a small segment cap (records roll and seal), a small
    //    total cap (producing more trips it), and the health endpoints (for /metrics). The base
    //    helper already supplies the ephemeral wire and health ports and `--checkpoint-interval 1`.
    let (broker, addr, health) = start_broker_with_health_args(
        &data_dir,
        &[
            "--disk-full-policy",
            "drop-oldest",
            "--max-segment-bytes",
            "4096",
            "--max-total-bytes",
            "7000",
            // Compression OFF: this test's roll/reap sizing arithmetic (above) is defined over
            // the RAW payload bytes on disk. The now-wired default `lz4` (#430) would shrink the
            // repeated-"a" payload far below the segment/total caps so no reap would ever
            // trigger; the force-reap behavior under test is codec-independent.
            "--compression",
            "none",
        ],
    );

    // 2. Produce the first record and consume ONLY it on group `stuck`, acking it so the group's
    //    committed cursor advances to offset 1 and then STAYS there: we never fetch this group
    //    again until after the reap, so it is stuck below the records about to be reaped.
    let (out, code) = run(&["pub", "--addr", &addr, &payload]);
    assert_eq!(code, 0, "first pub exit code: {out}");
    assert_eq!(out.trim(), "0", "the first record lands at offset 0");
    let (out, code) = run(&[
        "sub", "--addr", &addr, "--group", "stuck", "--max", "1", "--ack",
    ]);
    assert_eq!(code, 0, "stuck consumer's first fetch exit code: {out}");
    assert_eq!(
        delivered_offsets(&out),
        vec![0],
        "the stuck consumer consumed exactly the first record: {out}"
    );
    assert!(
        out.contains("ack committed"),
        "the stuck consumer acked offset 0, so its committed cursor is now 1: {out}"
    );
    // It is stuck at the low cursor: it must NOT have truncated on this first, caught-up fetch.
    assert_eq!(
        truncation_resume_offsets(&out),
        Vec::<u64>::new(),
        "a caught-up consumer is not truncated: {out}"
    );

    // 3. Produce many more records (offsets 1.. under drop-oldest). Every produce is ACCEPTED (the
    //    cap is made room for by force-reaping the oldest sealed segments) rather than shed, and the
    //    offsets march contiguously: the helper asserts both, so none was lost.
    produce_contiguous(&addr, &payload, 1, EXTRA);

    // 4. Confirm the FORCE happened: the server's force-reap counter is above zero, proving
    //    drop-oldest force-reaped sealed segments (including records the stuck group had not
    //    consumed) rather than merely shedding. This is the non-vacuity anchor for the truncation.
    let metrics = http_get(&health, "/metrics");
    let force_reaped = metric_value(&metrics, "ironbus_segments_force_reaped_total")
        .expect("/metrics exposes ironbus_segments_force_reaped_total");
    assert!(
        force_reaped > 0,
        "drop-oldest force-reaped at least one sealed segment: {metrics}"
    );

    // 5. The stuck consumer fetches again on its group. Its committed cursor (1) is now below the
    //    oldest retained record, so it gets EXACTLY ONE truncation: the cursor resets up to the
    //    earliest retained offset, delivery resumes there, and the consumer makes progress.
    let (out, code) = run(&[
        "sub", "--addr", &addr, "--group", "stuck", "--max", "100", "--ack",
    ]);
    assert_eq!(
        code, 0,
        "the stuck consumer's resume fetch exit code: {out}"
    );
    let resumes = truncation_resume_offsets(&out);
    assert_eq!(
        resumes.len(),
        1,
        "exactly one truncation line on the resume fetch, never zero or repeated: {out}"
    );
    let resume = resumes[0];
    // The resume offset is above where the consumer was stuck (committed 1): it skipped the reaped
    // span [1, resume). This proves records the stuck group had not consumed were force-reaped.
    assert!(
        resume > 1,
        "the resume offset is past the stuck cursor (1), so a span was skipped: {resume} in {out}"
    );
    // The consumer resumes AT the earliest retained offset: the first record it now delivers is
    // exactly the truncation's resume offset (it did not silently skip past the oldest record).
    let delivered = delivered_offsets(&out);
    assert!(
        !delivered.is_empty(),
        "the consumer made progress after the truncation, delivering from the resume point: {out}"
    );
    assert_eq!(
        delivered[0], resume,
        "the consumer resumed exactly at the earliest retained offset it was told: {out}"
    );
    // The delivered offsets are contiguous from the resume point (it streams the retained tail in
    // order, none dropped or doubled within the batch).
    let expected_tail: Vec<u64> = (resume..resume + delivered.len() as u64).collect();
    assert_eq!(
        delivered, expected_tail,
        "the resumed delivery is contiguous from the earliest retained offset: {out}"
    );
    assert!(
        out.contains(&format!("fetched {} message(s)", delivered.len())),
        "the fetched count matches the delivered records exactly: {out}"
    );

    // 6. It does NOT re-truncate: the reset closed the gap (committed == earliest retained), so a
    //    further fetch on the same group delivers normally with NO second truncation line. The
    //    stuck consumer acked the resumed batch above, so this fetch sees only whatever the live
    //    log holds beyond it (possibly nothing, but never another truncation for the closed gap).
    let (out, code) = run(&[
        "sub", "--addr", &addr, "--group", "stuck", "--max", "100", "--ack",
    ]);
    assert_eq!(
        code, 0,
        "the stuck consumer's follow-up fetch exit code: {out}"
    );
    assert_eq!(
        truncation_resume_offsets(&out),
        Vec::<u64>::new(),
        "no second truncation: the gap is closed after the one-time reset: {out}"
    );

    drop(broker);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Boots `ironbus serve` like [`start_broker`] but with a LARGE `--checkpoint-interval`, so the
/// per-ack `maybe_checkpoint` never fires within the test. Returns the raw `Child` (NOT a
/// `ChildGuard`, so the caller can SIGTERM it and read its exit status without the guard's
/// drop-time SIGKILL) and the bound wire address. With a large interval the committed cursor can
/// become durable ONLY via a connection's clean-disconnect close-path flush or the new
/// graceful-shutdown flush, which is exactly what the shutdown test isolates.
fn start_broker_large_interval(data_dir: &str) -> (Child, String) {
    let mut child = Command::new(BIN)
        .args([
            "serve",
            "--data-dir",
            data_dir,
            "--addr",
            "127.0.0.1:0",
            // Far above the three acks below, so no interval checkpoint ever runs in this test.
            "--checkpoint-interval",
            "1000000",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus serve");
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let n = BufReader::new(stdout).read_line(&mut line).unwrap_or(0);
        let _ = tx.send((n, line));
    });
    let (n, line) = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(v) => v,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ironbus serve did not print a listening line within 10s: {e}");
        }
    };
    if n == 0 {
        let mut err = String::new();
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut err);
        }
        let _ = child.wait();
        panic!("ironbus serve exited before it listened: {err}");
    }
    let Some(addr) = line
        .split("listening on ")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .map(str::trim)
    else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("could not parse the listening line: {line:?}");
    };
    (child, addr.to_string())
}

/// Sends SIGTERM to `pid` via the `kill` binary (std-only; the test crate pulls no signal crate),
/// modeling an operator's `systemctl stop` / `kill <pid>`. The broker's `ctrlc` handler flips the
/// serve loop's shutdown flag, which its non-blocking accept observes within ~50 ms.
fn send_sigterm(pid: u32) {
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("run kill -TERM");
    assert!(status.success(), "kill -TERM {pid} succeeded");
}

/// Waits up to `deadline` for `child` to exit, returning its exit code. SIGKILLs and fails the test
/// if it does not exit in time, so a broker that ignores SIGTERM cannot hang the suite.
fn wait_for_exit(child: &mut Child, deadline: Duration) -> i32 {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll the broker's exit status") {
            return status.code().unwrap_or(-1);
        }
        if start.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("broker did not exit within {deadline:?} of SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn graceful_shutdown_on_sigterm_checkpoints_the_cursor_and_does_not_redeliver() {
    // #195: a clean operator stop (SIGTERM) must flush the committed cursor so a restart does NOT
    // redeliver acked messages. This isolates the GRACEFUL-SHUTDOWN flush specifically: the broker
    // runs with a huge --checkpoint-interval (so the per-ack interval checkpoint never fires), and
    // the consumer is STILL CONNECTED when the signal arrives (so the clean-disconnect close-path
    // checkpoint never fires either). The ONLY path that can persist the cursor here is the new
    // signal handler's checkpoint-all-groups on the way out. Without it the restart would redeliver
    // the three acked messages; with it the restart resumes past them. Drives the real binary end to
    // end over the real #11 client.
    let dir = std::env::temp_dir().join(format!("ironbus-graceful-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);

    // 1. Boot the broker with a large checkpoint interval (no interval checkpoint will run).
    let (mut broker, addr) = start_broker_large_interval(&data_dir);

    // 2. Open ONE long-lived connection. Produce three messages, fetch all three, ack all three.
    //    The client stays connected past the acks, so no clean-disconnect flush fires.
    let mut client = Client::connect(&addr).expect("connect to the broker");
    for payload in [b"m0".as_slice(), b"m1", b"m2"] {
        client
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload,
            })
            .expect("produce");
    }
    let fetched = client.fetch(10).expect("fetch the batch");
    assert_eq!(
        fetched.messages.len(),
        3,
        "all three messages were delivered before the shutdown"
    );
    for m in &fetched.messages {
        assert!(
            client.ack(m.offset, m.generation).expect("ack"),
            "the ack committed (offset {})",
            m.offset
        );
    }

    // 3. SIGTERM the broker while the consumer is STILL CONNECTED (the client is not dropped). The
    //    handler flips the shutdown flag; the serve loop stops accepting and flushes every cursor.
    send_sigterm(broker.id());

    // 4. The broker exits cleanly: a graceful, signalled shutdown is exit code 0.
    let code = wait_for_exit(&mut broker, Duration::from_secs(10));
    assert_eq!(code, 0, "a SIGTERM graceful shutdown exits 0");

    // Now the connection is moot (the broker is gone); release it.
    drop(client);

    // 5. Restart on the SAME data dir. If the shutdown flush persisted the cursor at 3, a fresh
    //    fetch sees NOTHING; if the cursor was lost, the three acked messages redeliver here.
    let (mut broker2, addr2) = start_broker_large_interval(&data_dir);
    let mut client2 = Client::connect(&addr2).expect("reconnect after restart");
    let resumed = client2.fetch(10).expect("fetch after restart");
    assert!(
        resumed.messages.is_empty(),
        "the graceful shutdown flushed the cursor, so the acked messages did NOT redeliver; \
         got {} message(s) back: {:?}",
        resumed.messages.len(),
        resumed
            .messages
            .iter()
            .map(|m| m.offset)
            .collect::<Vec<_>>(),
    );

    // 6. The durable log still continues from offset 3 (the records were fsynced before their
    //    offsets were returned), proving the data dir is intact, not wiped.
    let next = client2
        .produce(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: None,
            fire_and_forget: false,
            payload: b"m3",
        })
        .expect("produce after restart");
    assert_eq!(
        next, 3,
        "the durable log continued across the graceful restart"
    );

    drop(client2);
    let _ = broker2.kill();
    let _ = broker2.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Boots `ironbus serve --storage memory` (NO `--data-dir`) on an ephemeral loopback port,
/// returning the un-guarded `Child` (so the caller can SIGTERM it and read its exit status), the
/// bound wire address, the second stdout line (the #443 ephemeral-contract banner), and a join
/// handle yielding the broker's accumulated STDERR, where the materialized-config line lands.
fn start_memory_broker() -> (
    Child,
    String,
    String,
    std::thread::JoinHandle<String>,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    // NO-FILES HARNESS (#443 review): the broker runs with a scratch CWD and an isolated TMPDIR,
    // both created empty, so the test can assert after the clean exit that the ephemeral broker
    // created NO file anywhere it could plausibly write (a regression that starts touching disk,
    // e.g. an unconditional data-dir prepare or a lock file leaking past the Filesystem trait,
    // fails the emptiness assertion instead of passing silently).
    let cwd_scratch = std::env::temp_dir().join(format!("ironbus-memcwd-{}", std::process::id()));
    let tmp_scratch = std::env::temp_dir().join(format!("ironbus-memtmp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cwd_scratch);
    let _ = std::fs::remove_dir_all(&tmp_scratch);
    std::fs::create_dir_all(&cwd_scratch).expect("create scratch cwd");
    std::fs::create_dir_all(&tmp_scratch).expect("create scratch tmpdir");
    let mut child = Command::new(BIN)
        .args([
            "serve",
            "--storage",
            "memory",
            "--ephemeral-loss-ack",
            "--max-total-bytes",
            "16777216",
            "--addr",
            "127.0.0.1:0",
            "--checkpoint-interval",
            "1",
        ])
        .current_dir(&cwd_scratch)
        .env("TMPDIR", &tmp_scratch)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus serve --storage memory");
    // Accumulate the WHOLE stderr stream on a worker thread for the duration of the broker's
    // life, so the pipe can never fill and block the broker, and the test can assert on the
    // materialized-config line after the clean exit.
    let stderr = child.stderr.take().expect("piped stderr");
    let stderr_handle = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut reader = BufReader::new(stderr);
        let _ = reader.read_to_string(&mut buf);
        buf
    });
    // The startup-protocol contract on stdout: line 1 is the listening line, line 2 is the
    // ephemeral banner (written immediately after, before any connection is accepted).
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut first = String::new();
        let n = reader.read_line(&mut first).unwrap_or(0);
        let mut second = String::new();
        let m = if n > 0 {
            reader.read_line(&mut second).unwrap_or(0)
        } else {
            0
        };
        let _ = tx.send((n.min(1) + m.min(1), first, second));
    });
    let (lines, first, second) = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(v) => v,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("memory-mode serve did not print its startup lines within 10s: {e}");
        }
    };
    if lines < 2 {
        let _ = child.kill();
        let _ = child.wait();
        let err = stderr_handle.join().unwrap_or_default();
        panic!("memory-mode serve exited before its startup lines: {err}");
    }
    let Some(addr) = first
        .split("listening on ")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .map(str::trim)
    else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("could not parse the memory-mode listening line: {first:?}");
    };
    assert!(
        first.contains("storage memory (ephemeral)"),
        "the listening line names the memory backend, never a path that does not exist: {first}"
    );
    (
        child,
        addr.to_string(),
        second,
        stderr_handle,
        cwd_scratch,
        tmp_scratch,
    )
}

#[test]
fn memory_mode_round_trips_on_the_real_wire_and_exits_clean() {
    // #443: the OPT-IN ephemeral in-memory backend serves the SAME wire protocol end to end.
    // Boot the real binary with `--storage memory` (consent + byte cap, NO --data-dir), produce
    // over real loopback sockets, fan in with acks, then stop it cleanly with SIGTERM and assert
    // exit 0 plus the machine-checkable `storage=memory` materialized-config echo. The default
    // disk path is byte-for-byte unchanged; every other scenario in this suite proves that.
    let (mut broker, addr, banner, stderr_handle, cwd_scratch, tmp_scratch) = start_memory_broker();

    // The ephemeral-contract banner is the broker's second startup line on EVERY memory boot.
    assert!(
        banner.contains("EPHEMERAL") && banner.contains("NO power-loss or restart durability"),
        "the startup banner states the loss contract: {banner}"
    );

    // Produce three messages; each ack carries the next durable-within-this-process offset.
    for (i, payload) in ["m0", "m1", "m2"].iter().enumerate() {
        let (out, code) = run(&["pub", "--addr", &addr, payload]);
        assert_eq!(code, 0, "pub exit code in memory mode");
        assert_eq!(out.trim(), i.to_string(), "pub returned the next offset");
    }

    // Consume the whole batch and ack every message: the wire surface, group semantics, and the
    // ack path are the disk engine's, just over the in-memory filesystem.
    let (out, code) = run(&["sub", "--addr", &addr, "--max", "10", "--ack"]);
    assert_eq!(code, 0, "sub exit code in memory mode");
    assert!(
        out.contains("payload=m0") && out.contains("payload=m1") && out.contains("payload=m2"),
        "all three delivered: {out}"
    );
    assert_eq!(
        out.matches("ack committed").count(),
        3,
        "all three acked: {out}"
    );

    // Within the process lifetime an ack holds exactly as on disk: a re-fetch sees nothing.
    let (out, code) = run(&["sub", "--addr", &addr, "--max", "10"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("fetched 0 message(s)"),
        "the acked messages do not redeliver within the process lifetime: {out}"
    );

    // A clean operator stop: SIGTERM exits 0 (the graceful drain runs over the in-memory fs).
    send_sigterm(broker.id());
    let code = wait_for_exit(&mut broker, Duration::from_secs(10));
    assert_eq!(
        code, 0,
        "a SIGTERM graceful shutdown exits 0 in memory mode"
    );

    // The #443 machine-checkable echo on the stderr log stream: an operator (or a script) reads
    // the backend straight off the startup materialized-config line.
    let logs = stderr_handle.join().expect("join the stderr reader");
    let config_line = logs
        .lines()
        .find(|l| l.contains("materialized-config"))
        .unwrap_or_else(|| panic!("no materialized-config line on stderr: {logs}"));
    assert!(
        config_line.contains("storage=memory"),
        "the materialized-config line says storage=memory: {config_line}"
    );
    assert!(
        config_line.contains("data_dir=none"),
        "no data dir exists in memory mode (the none sentinel): {config_line}"
    );

    // THE NO-FILES CONTRACT: across boot, produce, consume, ack, and the graceful drain, the
    // ephemeral broker wrote NOTHING under its cwd and NOTHING under its TMPDIR. Any entry at
    // all (a data dir, a lock, a checkpoint, a stray temp) is a regression of the whole point.
    let leftovers = |dir: &std::path::Path| -> Vec<String> {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    assert!(
        leftovers(&cwd_scratch).is_empty(),
        "memory mode created files in its cwd: {:?}",
        leftovers(&cwd_scratch)
    );
    assert!(
        leftovers(&tmp_scratch).is_empty(),
        "memory mode created files in its TMPDIR: {:?}",
        leftovers(&tmp_scratch)
    );
    let _ = std::fs::remove_dir_all(&cwd_scratch);
    let _ = std::fs::remove_dir_all(&tmp_scratch);
}
