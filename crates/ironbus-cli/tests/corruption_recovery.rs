// SPDX-License-Identifier: MIT OR Apache-2.0
//! The IronBus side of the #644 corruption-recovery HEAD-TO-HEAD vs NATS (V2-M12).
//!
//! Four scenario classes reproduce the failure modes reported against the NATS JetStream file
//! store — a single-bit flip in a stored block (`nats-server` #7549), a >= 32 MB record
//! (`nats-server` #6797), a torn tail (power-cut partial write), and a stale/corrupt index or
//! checkpoint (`nats-server` #5412, #7556) — and MEASURE what IronBus does with the same on-disk
//! damage. Each leg writes a known corpus over the real `ironbus` binary in the durable disk
//! mode, stops the broker, injects the corruption into the data dir, reopens, and asserts the
//! four properties the head-to-head grades:
//!
//!   (a) BOUNDED   — the loss (if any) is a contiguous, capped span, never the whole stream;
//!   (b) REPORTED  — a structured loss event (reason + byte span) on `/metrics`, `dump --json`,
//!                   and `verify`, never a silent drop;
//!   (c) NO SILENT MISREAD — a record that fails its CRC is never delivered as truth;
//!   (d) SERVED    — the surviving records are consumable, byte-exact, and the log continues.
//!
//! The NATS side of the head-to-head is scripted in
//! `docs/benchmarks/corruption_recovery_nats.sh`, and the measured results table lives in
//! `docs/benchmarks/corruption-recovery.md`. This file is the REPEATABLE IronBus leg: it runs
//! in the normal `cargo test` suite (`cargo test -p ironbus-cli --test corruption_recovery`),
//! so the recovery differentiator is demonstrated on every CI run, not asserted.
//!
//! The harness helpers mirror `acceptance.rs` (the golden-path release gate), which already
//! exercises the torn-tail leg inside its ten-step story; here each corruption class is a
//! focused, independent test so a single failing assertion names one scenario and one property.
//!
//! `serve` and the offline verbs are Unix-only in v1, so this whole file is gated to Unix
//! (Windows still compiles it to an empty module, keeping `-D warnings` clean on all targets).
#![cfg(unix)]
// The same shape-not-correctness style allowances the sibling `acceptance.rs` harness carries:
// deliberately-sequential scenario bodies, and prose that names products ("NATS JetStream").
#![allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The freshly-built `ironbus` binary under test (Cargo sets this for integration tests).
const BIN: &str = env!("CARGO_BIN_EXE_ironbus");

/// The `verify` exit code for handled (reported, non-structural) corruption spans.
const EXIT_HANDLED_CORRUPTION: i32 = 3;
/// The offline exit code for a structurally corrupt directory the tools refuse to interpret.
const EXIT_STRUCTURAL_CORRUPTION: i32 = 4;

/// Kills and reaps the broker on drop, so a panicking assertion never leaks a serve process.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A self-cleaning scratch directory under the system temp root, unique per test.
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "ironbus-corruption-recovery-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create the scratch dir");
        Scratch(p)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Boots `ironbus serve` on ephemeral loopback wire + health ports over `data_dir`, returning a
/// kill-guard and the parsed `(wire, health)` addresses. `--checkpoint-interval 1` persists the
/// cursor synchronously per ack so a restart resume is deterministic. Same pattern as
/// `acceptance.rs`.
fn start_broker(data_dir: &str, extra: &[&str]) -> (ChildGuard, String, String) {
    let mut args: Vec<String> = vec![
        "serve".into(),
        "--data-dir".into(),
        data_dir.into(),
        "--addr".into(),
        "127.0.0.1:0".into(),
        "--health-addr".into(),
        "127.0.0.1:0".into(),
        "--checkpoint-interval".into(),
        "1".into(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_string()));
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

/// Runs one `ironbus` subcommand to completion, returning stdout, stderr, and the exit code.
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

/// Publishes `payload` via `pub` reading from STDIN (the documented path for a payload too large
/// or too awkward for an argv), returning stdout, stderr, and the exit code.
fn run_pub_stdin(addr: &str, payload: &[u8]) -> (String, String, i32) {
    let mut child = Command::new(BIN)
        .args(["pub", "--addr", addr])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus pub");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(payload)
        .expect("write the stdin payload");
    let out = child.wait_with_output().expect("wait for ironbus pub");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// The delivered record offsets from a `sub` run's stdout (the `#<n>` lines).
fn delivered_offsets(out: &str) -> Vec<u64> {
    out.lines()
        .filter_map(|l| l.strip_prefix('#'))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|tok| tok.parse::<u64>().ok())
        .collect()
}

/// The delivered payloads from a `sub` run's stdout (`payload=<value>`).
fn payloads(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split("payload=").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// A minimal blocking HTTP/1.0 GET against a loopback `host:port`, retrying a just-spawned
/// health thread.
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

/// Reads a single Prometheus sample value by EXACT line key (labels included).
fn metric_value(body: &str, key: &str) -> Option<u64> {
    let prefix = format!("{key} ");
    body.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        line.strip_prefix(&prefix)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse().ok())
    })
}

/// The segment files of `data_dir` in name order (name order is id order: zero-padded hex).
fn segment_files(data_dir: &str) -> Vec<PathBuf> {
    let mut segs: Vec<PathBuf> = std::fs::read_dir(data_dir)
        .expect("read data dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("log")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("seg-"))
        })
        .collect();
    segs.sort();
    segs
}

/// Flips the LOWEST BIT of the first byte of `needle`'s first occurrence in `path` — the
/// single-bit media error of nats-server #7549 — and returns the flipped byte's file offset.
/// Panics if the needle is absent (the corpus payloads are stored raw below the compression
/// threshold, or with `--compression none`, precisely so the injection point is findable).
fn flip_one_bit_at(path: &PathBuf, needle: &[u8]) -> u64 {
    let mut bytes = std::fs::read(path).expect("read the file to corrupt");
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("the corpus payload must be present raw in the file");
    bytes[pos] ^= 0x01;
    std::fs::write(path, &bytes).expect("write back the flipped file");
    pos as u64
}

/// The trailing `{"loss":{...}}` object from a `dump --json` run.
fn dump_loss_json(data_dir: &str) -> String {
    let (out, _err, code) = run(&["dump", "--data-dir", data_dir, "--json"]);
    assert_eq!(
        code, 0,
        "dump --json over a reported-corruption dir succeeds (reported, not fatal): {out}"
    );
    out.lines()
        .find(|l| l.trim_start().starts_with("{\"loss\":"))
        .expect("dump --json emits the structured loss object")
        .trim()
        .to_string()
}

/// A `\"key\":<u64>` field from a compact hand-rolled JSON line (no serde in the test).
fn json_u64(json: &str, key: &str) -> u64 {
    let pat = format!("\"{key}\":");
    let rest = &json[json.find(&pat).unwrap_or_else(|| panic!("{key} in {json}")) + pat.len()..];
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("numeric {key} in {json}"))
}

/// An 8 MiB effectively-incompressible single-token payload (alphanumeric xorshift stream), so
/// the stored bytes are ~the payload size and the round-trip is a real large-record exercise.
fn incompressible_payload(len: usize) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let idx = usize::try_from(state % ALPHABET.len() as u64).expect("index fits usize");
        out.push(ALPHABET[idx]);
    }
    out
}

// =================================================================================================
// SCENARIO 1a (nats-server #7549): a SINGLE-BIT FLIP in a stored block, in the ACTIVE segment.
//
// NATS (2.12.1, Jepsen): single-bit .blk errors caused the silent loss of acknowledged records
// from the MIDDLE of the log ("Stream state outdated, last block has additional entries, will
// rebuild"), with the node starting and serving as if nothing happened.
//
// IronBus measured behavior: recovery's fail-closed CRC stops at the flipped record; the loss is
// the contiguous span from that record to the end of the written bytes — BOUNDED, REPORTED as a
// structured `corrupt_record_body` event (offline dump/verify AND the online metrics agree on
// the byte count), the poisoned span is QUARANTINED for forensics, the intact prefix is SERVED
// byte-exact, and the log continues accepting appends. The flipped record itself is NEVER
// delivered.
// =================================================================================================
#[test]
fn bit_flip_in_active_segment_is_bounded_reported_quarantined_and_served() {
    let scratch = Scratch::new("bitflip-active");
    let dir = scratch.join("data");
    let dir = dir.to_str().expect("utf8 data dir");

    // A 20-record corpus of distinct sub-64-byte payloads (stored raw: below the lz4 threshold),
    // fsync-per-ack durable disk mode (the zero-config default).
    let (broker, addr, _h) = start_broker(dir, &[]);
    for i in 0..20 {
        let payload = format!("bitflip-rec-{i:02}");
        let (out, _e, code) = run(&["pub", "--addr", &addr, &payload]);
        assert_eq!(code, 0, "produce {i} accepted");
        assert_eq!(out.trim(), i.to_string(), "contiguous durable offsets");
    }
    drop(broker);

    // INJECT: flip one bit inside record 10's stored payload (mid-corpus, like the Jepsen runs
    // that lost records from the middle).
    let segs = segment_files(dir);
    assert_eq!(
        segs.len(),
        1,
        "the small corpus lives in one active segment"
    );
    let seg_len = std::fs::metadata(&segs[0]).expect("segment metadata").len();
    let flip_off = flip_one_bit_at(&segs[0], b"bitflip-rec-10");

    // REPORTED (offline, pre-recovery): `verify` is a read-only fsck that finds the exact span
    // and exits with the handled-corruption code; `dump --json` emits the structured loss object.
    let (vout, _verr, vcode) = run(&["verify", "--data-dir", dir]);
    assert_eq!(
        vcode, EXIT_HANDLED_CORRUPTION,
        "verify reports handled corruption: {vout}"
    );
    assert!(
        vout.contains("corrupt_record_body"),
        "verify names the reason: {vout}"
    );
    let loss = dump_loss_json(dir);
    assert!(
        loss.contains("\"reason\":\"corrupt_record_body\""),
        "the loss report names the reason: {loss}"
    );
    let loss_bytes = json_u64(&loss, "bytes");
    let span_start = json_u64(&loss, "start");
    let span_end = json_u64(&loss, "end");
    // BOUNDED: one contiguous span, from the flipped record's frame (at or before the flipped
    // payload byte) to the end of the written bytes — never the whole stream, never unbounded.
    assert_eq!(
        span_end - span_start,
        loss_bytes,
        "the loss span and byte count agree: {loss}"
    );
    assert!(
        span_start <= flip_off && flip_off < span_end,
        "the loss span covers the flipped byte at {flip_off}: {loss}"
    );
    assert!(
        loss_bytes < seg_len,
        "the loss is a bounded tail span of the {seg_len}-byte segment, not the whole log: {loss}"
    );

    // RECOVER: reopen and let recovery truncate + quarantine the poisoned span.
    let (broker2, addr2, health2) = start_broker(dir, &[]);
    // REPORTED (online): the metrics loss series agrees with the offline report BYTE FOR BYTE.
    let metrics = http_get(&health2, "/metrics");
    assert_eq!(
        metric_value(
            &metrics,
            "ironbus_recovery_loss_bytes{reason=\"corrupt_record_body\"}"
        ),
        Some(loss_bytes),
        "the online recovery counter agrees with the offline loss report"
    );
    assert!(
        metric_value(
            &metrics,
            "ironbus_recovery_loss_records{reason=\"corrupt_record_body\"}"
        )
        .is_some_and(|r| r >= 1),
        "the per-reason lost-records series is present: {metrics}"
    );

    // NO SILENT MISREAD + SERVED: the surviving prefix (records 0..=9) is delivered byte-exact;
    // the flipped record is NEVER delivered (neither corrupt nor "repaired"), and nothing past it
    // is invented.
    let (out, _e, code) = run(&["sub", "--addr", &addr2, "--max", "100", "--ack"]);
    assert_eq!(code, 0, "consume after recovery succeeds");
    assert_eq!(
        delivered_offsets(&out),
        (0..10).collect::<Vec<u64>>(),
        "exactly the intact prefix survives, in order: {out}"
    );
    let got = payloads(&out);
    let want: Vec<String> = (0..10).map(|i| format!("bitflip-rec-{i:02}")).collect();
    assert_eq!(got, want, "the surviving records are byte-exact: {out}");

    // SERVED (continues): the log accepts new appends at the truncated head.
    let (out, _e, code) = run(&["pub", "--addr", &addr2, "after-flip"]);
    assert_eq!(code, 0, "the log continues accepting appends");
    assert_eq!(out.trim(), "10", "the append lands at the truncated head");

    // The poisoned span was QUARANTINED (a forensic copy, not a silent unlink).
    drop(broker2);
    let quarantined: Vec<String> = std::fs::read_dir(scratch.join("data").join("quarantine"))
        .expect("the quarantine dir exists after a corruption skip")
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    assert!(
        quarantined
            .iter()
            .any(|n| n.contains("corrupt_record_body")),
        "the corrupt span has a forensic quarantine copy: {quarantined:?}"
    );
}

// =================================================================================================
// SCENARIO 1b (nats-server #7549, the sealed-block variant): a SINGLE-BIT FLIP in a SEALED
// (non-final) segment — corruption of previously-durable MIDDLE-of-log data.
//
// NATS started anyway and silently lost acked records from the middle of the log. IronBus
// measured behavior: FAIL CLOSED — the broker REFUSES to open (a precise error naming the
// segment), the offline tools refuse to interpret the directory as truth (exit 4, structural),
// and every on-disk byte is left untouched for repair/forensics. No record is ever served from
// an unverifiable chain, and nothing is silently dropped. Availability is traded for integrity;
// the operator restores from a replica or backup with the evidence intact.
// =================================================================================================
#[test]
fn bit_flip_in_a_sealed_segment_fails_closed_and_preserves_evidence() {
    let scratch = Scratch::new("bitflip-sealed");
    let dir = scratch.join("data");
    let dir = dir.to_str().expect("utf8 data dir");

    // Roll small segments (`--compression none` keeps the payloads findable and the sizing
    // deterministic): 20 records of ~415 bytes over 4 KiB segments = several SEALED segments.
    let filler = "x".repeat(400);
    let (broker, addr, _h) = start_broker(
        dir,
        &["--max-segment-bytes", "4096", "--compression", "none"],
    );
    for i in 0..20 {
        let payload = format!("sealedflip-{i:02}-{filler}");
        let (out, _e, code) = run(&["pub", "--addr", &addr, &payload]);
        assert_eq!(code, 0, "produce {i} accepted");
        assert_eq!(out.trim(), i.to_string());
    }
    drop(broker);
    let segs = segment_files(dir);
    assert!(
        segs.len() >= 2,
        "the corpus spans multiple segments (got {})",
        segs.len()
    );

    // Snapshot every segment image, then flip ONE bit in a record of the FIRST (sealed) segment.
    let before: Vec<Vec<u8>> = segs
        .iter()
        .map(|p| std::fs::read(p).expect("read segment"))
        .collect();
    flip_one_bit_at(&segs[0], b"sealedflip-01");

    // FAIL CLOSED (broker): serve refuses to open the directory, promptly and with a precise
    // structural error, rather than serving records past an unverifiable predecessor.
    let mut child = Command::new(BIN)
        .args([
            "serve",
            "--data-dir",
            dir,
            "--addr",
            "127.0.0.1:0",
            "--health-addr",
            "127.0.0.1:0",
            "--max-segment-bytes",
            "4096",
            "--compression",
            "none",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus serve on the corrupt dir");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll serve") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "serve must exit promptly on a corrupt sealed segment, not hang or serve"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        !status.success(),
        "serve refuses to start on a corrupt sealed segment"
    );
    let mut serr = String::new();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut serr)
        .expect("read serve stderr");
    assert!(
        serr.contains("not sealed") && serr.contains("segment 0"),
        "the refusal names the failing segment precisely: {serr}"
    );

    // FAIL CLOSED (offline tools): the directory is not interpreted as truth either.
    let (_vout, verr, vcode) = run(&["verify", "--data-dir", dir]);
    assert_eq!(
        vcode, EXIT_STRUCTURAL_CORRUPTION,
        "verify refuses a structurally corrupt chain: {verr}"
    );

    // EVIDENCE PRESERVED: the refusal changed NOTHING on disk — every segment is byte-identical
    // to its post-flip image (the corruption is exactly the one injected bit; nothing was
    // truncated, unlinked, or "repaired" behind the operator's back).
    let segs_after = segment_files(dir);
    assert_eq!(segs.len(), segs_after.len(), "no segment was unlinked");
    for (i, (path, before_img)) in segs_after.iter().zip(&before).enumerate() {
        let after_img = std::fs::read(path).expect("re-read segment");
        if i == 0 {
            let diffs = before_img
                .iter()
                .zip(&after_img)
                .filter(|(a, b)| a != b)
                .count();
            assert_eq!(
                diffs, 1,
                "segment 0 differs from its pre-flip image by exactly the injected byte"
            );
        } else {
            assert_eq!(
                &after_img, before_img,
                "segment {i} is byte-identical (nothing else was touched)"
            );
        }
    }
}

// =================================================================================================
// SCENARIO 2 (nats-server #6797): a >= 32 MB record.
//
// NATS accepted a 32 MB publish (below its configured 64 MB max_payload), stored it, and then
// could not read it back: "indexCacheBuf corrupt record state" server-side, "malformed or
// corrupt message" to the consumer — an accepted write the store corrupts.
//
// IronBus measured behavior: the limit is enforced UP FRONT at the frame layer (16 MiB record
// cap, 16 MiB + 64 KiB frame cap, both encode- and decode-side): the 32 MiB publish is REFUSED
// with an explicit error naming the cap, NOTHING is stored, the broker and log are unharmed,
// and the next publish lands at the contiguous next offset. A large record WITHIN the cap
// (8 MiB, effectively incompressible) is stored durably and round-trips byte-exact across a
// restart. Accept-then-corrupt is replaced by refuse-or-serve.
// =================================================================================================
#[test]
fn oversize_record_is_refused_upfront_and_in_cap_large_records_round_trip() {
    let scratch = Scratch::new("bigrec");
    let dir = scratch.join("data");
    let dir = dir.to_str().expect("utf8 data dir");

    let (broker, addr, _h) = start_broker(dir, &[]);
    let (out, _e, code) = run(&["pub", "--addr", &addr, "before-big"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "0");

    // The 32 MiB record: REFUSED with an explicit cap error; no partial write, no corruption.
    let oversize = vec![b'A'; 32 * 1024 * 1024];
    let (_o, err, code) = run_pub_stdin(&addr, &oversize);
    assert_ne!(
        code, 0,
        "a 32 MiB record is refused, not accepted-then-corrupted"
    );
    assert!(
        err.contains("exceeds") && err.contains("cap"),
        "the refusal names the cap explicitly: {err}"
    );

    // The broker is alive and the log is uncorrupted: the next publish lands at offset 1
    // (nothing of the refused record was appended).
    let (out, _e, code) = run(&["pub", "--addr", &addr, "after-big"]);
    assert_eq!(code, 0, "the broker survives the oversize refusal");
    assert_eq!(
        out.trim(),
        "1",
        "nothing of the refused record reached the log"
    );

    // A large record WITHIN the cap: 8 MiB, effectively incompressible, published via stdin.
    let big = incompressible_payload(8 * 1024 * 1024);
    let (out, err, code) = run_pub_stdin(&addr, &big);
    assert_eq!(code, 0, "an in-cap 8 MiB record is accepted: {err}");
    assert_eq!(out.trim(), "2");
    drop(broker);

    // Round-trip across a RESTART (recovery re-validates the stored frames): byte-exact.
    let (broker2, addr2, _h2) = start_broker(dir, &[]);
    let (out, _e, code) = run(&["sub", "--addr", &addr2, "--max", "10", "--ack"]);
    assert_eq!(code, 0);
    assert_eq!(delivered_offsets(&out), vec![0, 1, 2]);
    let got = payloads(&out);
    assert_eq!(got.len(), 3, "three records delivered: {}", out.len());
    assert_eq!(got[0], "before-big");
    assert_eq!(got[1], "after-big");
    assert_eq!(
        got[2].as_bytes(),
        &big[..],
        "the 8 MiB record round-trips byte-exact across a restart (got {} bytes)",
        got[2].len()
    );
    drop(broker2);

    // The store is clean: no loss, no corruption, no residue of the refused record.
    let (vout, _verr, vcode) = run(&["verify", "--data-dir", dir]);
    assert_eq!(
        vcode, 0,
        "verify is clean after the refusal + round-trip: {vout}"
    );
}

// =================================================================================================
// SCENARIO 3 (the power-cut class the golden path also gates): a TORN TAIL — a partial record
// appended past the last durable one, as an interrupted write leaves it.
//
// IronBus measured behavior: recovery truncates exactly the torn bytes, reports them as a
// structured `torn_tail` event whose byte count the offline report and the online counter agree
// on, serves EVERY acked record byte-exact, and continues at the truncated head. (The NATS side
// of this scenario is measured by `docs/benchmarks/corruption_recovery_nats.sh`.)
// =================================================================================================
#[test]
fn torn_tail_is_bounded_reported_and_every_acked_record_survives() {
    let scratch = Scratch::new("torntail");
    let dir = scratch.join("data");
    let dir = dir.to_str().expect("utf8 data dir");

    let (broker, addr, _h) = start_broker(dir, &[]);
    for i in 0..10 {
        let payload = format!("torn-rec-{i}");
        let (out, _e, code) = run(&["pub", "--addr", &addr, &payload]);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), i.to_string());
    }
    drop(broker);

    // INJECT: a 14-byte partial record at the tail (0xFF can never begin a valid frame).
    const TORN_TAIL: [u8; 14] = [0xFF; 14];
    const TORN: u64 = TORN_TAIL.len() as u64;
    let segs = segment_files(dir);
    let seg = segs.last().expect("an active segment");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(seg)
        .expect("open the active segment for append");
    f.write_all(&TORN_TAIL).expect("append the torn tail");
    f.sync_all().expect("persist the torn tail");
    drop(f);

    // REPORTED offline: the exact byte count and reason, before any recovery ran.
    let loss = dump_loss_json(dir);
    assert!(
        loss.contains("\"reason\":\"torn_tail\""),
        "the loss report names torn_tail: {loss}"
    );
    assert_eq!(
        json_u64(&loss, "bytes"),
        TORN,
        "the reported loss is exactly the torn bytes"
    );

    // RECOVER: the online counter agrees with the offline report; every acked record survives.
    let (_broker2, addr2, health2) = start_broker(dir, &[]);
    let metrics = http_get(&health2, "/metrics");
    assert_eq!(
        metric_value(&metrics, "ironbus_recovery_truncated_bytes"),
        Some(TORN),
        "the online truncation counter equals the offline report"
    );
    assert_eq!(
        metric_value(
            &metrics,
            "ironbus_recovery_loss_bytes{reason=\"torn_tail\"}"
        ),
        Some(TORN),
        "the per-reason series agrees too"
    );
    let (out, _e, code) = run(&["sub", "--addr", &addr2, "--max", "100", "--ack"]);
    assert_eq!(code, 0);
    assert_eq!(
        delivered_offsets(&out),
        (0..10).collect::<Vec<u64>>(),
        "every acked record survived the torn tail: {out}"
    );
    let got = payloads(&out);
    let want: Vec<String> = (0..10).map(|i| format!("torn-rec-{i}")).collect();
    assert_eq!(got, want, "the surviving records are byte-exact");
    let (out, _e, code) = run(&["pub", "--addr", &addr2, "after-torn"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "10", "the log continues at the truncated head");
}

// =================================================================================================
// SCENARIO 4 (nats-server #5412 / #7556): a STALE or CORRUPT INDEX/CHECKPOINT.
//
// NATS #5412: after a power cut, index.db referenced a message block that no longer existed;
// the server restored the stream to ZERO messages (LastSeq=0) and every consumer was
// permanently wedged ("ack floor 14084 is ahead of stream's last sequence 0"). #7556: corrupt
// snapshot state escalated to whole-stream deletion cluster-wide.
//
// IronBus measured behavior: the LOG is the single source of truth and the cursor checkpoint is
// derived state with a dual-slot CRC discipline. Corrupting the newest slot regresses the
// cursor to the previous durable value (bounded redelivery, at-least-once). Corrupting the
// WHOLE checkpoint file resets the cursor to the log start (full redelivery). In BOTH cases:
// the broker starts, no record is lost, the cursor never invents a forward position (never
// "ack floor ahead"), the consumer is never wedged, and after the redelivery drain the group
// is fully caught up.
// =================================================================================================
#[test]
fn corrupt_cursor_checkpoint_never_wedges_consumers_and_never_loses_the_log() {
    // --- Variant A: the whole checkpoint file corrupted (both slots fail their CRC). ---
    let scratch = Scratch::new("ckpt");
    let dir_a = scratch.join("data-a");
    let dir_a = dir_a.to_str().expect("utf8 data dir");
    let (broker, addr, _h) = start_broker(dir_a, &[]);
    for i in 0..10 {
        let (out, _e, code) = run(&["pub", "--addr", &addr, &format!("ckpt-rec-{i}")]);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), i.to_string());
    }
    // The default group consumes and durably acks records 0..=4 (checkpoint-interval 1).
    let (out, _e, code) = run(&["sub", "--addr", &addr, "--max", "5", "--ack"]);
    assert_eq!(code, 0);
    assert_eq!(delivered_offsets(&out), vec![0, 1, 2, 3, 4]);
    drop(broker);

    let ckpt = scratch.join("data-a").join("cursor.ckpt");
    let len = std::fs::metadata(&ckpt).expect("cursor.ckpt exists").len();
    assert!(len > 0, "the acked cursor was checkpointed");
    std::fs::write(
        &ckpt,
        vec![0xFF_u8; usize::try_from(len).expect("checkpoint length fits usize")],
    )
    .expect("corrupt the whole checkpoint");

    // The broker STARTS (a corrupt derived index never blocks the log), the log is intact, and
    // the consumer redelivers from the log start — at-least-once, never wedged, never a cursor
    // ahead of the data.
    let (broker2, addr2, _h2) = start_broker(dir_a, &[]);
    let (out, _e, code) = run(&["sub", "--addr", &addr2, "--max", "100", "--ack"]);
    assert_eq!(
        code, 0,
        "the consumer is not wedged by the corrupt checkpoint"
    );
    assert_eq!(
        delivered_offsets(&out),
        (0..10).collect::<Vec<u64>>(),
        "a fully-corrupt cursor resets to the log start: full at-least-once redelivery, \
         zero data loss: {out}"
    );
    // After the drain the group is caught up: the cursor machinery still works.
    let (out, _e, code) = run(&["sub", "--addr", &addr2, "--max", "100", "--ack"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("fetched 0 message(s)"),
        "the redelivered drain committed; the group is caught up, not looping: {out}"
    );
    drop(broker2);

    // --- Variant B: a single-bit flip in the checkpoint file (at most one slot invalidated). ---
    let dir_b = scratch.join("data-b");
    let dir_b = dir_b.to_str().expect("utf8 data dir");
    let (broker, addr, _h) = start_broker(dir_b, &[]);
    for i in 0..10 {
        let (out, _e, code) = run(&["pub", "--addr", &addr, &format!("ckpt-rec-{i}")]);
        assert_eq!(code, 0);
        assert_eq!(out.trim(), i.to_string());
    }
    let (out, _e, code) = run(&["sub", "--addr", &addr, "--max", "5", "--ack"]);
    assert_eq!(code, 0);
    assert_eq!(delivered_offsets(&out), vec![0, 1, 2, 3, 4]);
    drop(broker);

    let ckpt = scratch.join("data-b").join("cursor.ckpt");
    let mut bytes = std::fs::read(&ckpt).expect("read cursor.ckpt");
    bytes[0] ^= 0x01; // flip one bit in the first slot's sequence field
    std::fs::write(&ckpt, &bytes).expect("write back the flipped checkpoint");

    // The dual-slot discipline: the winner is either the intact newest slot (cursor unchanged)
    // or the previous durable slot (bounded regression). It is NEVER a torn/invented value and
    // NEVER ahead of the durable floor of 5, so the un-acked suffix 5..=9 always redelivers and
    // the drain always ends at the log head.
    let (_broker2, addr2, _h2) = start_broker(dir_b, &[]);
    let (out, _e, code) = run(&["sub", "--addr", &addr2, "--max", "100", "--ack"]);
    assert_eq!(
        code, 0,
        "the consumer is not wedged by the flipped checkpoint"
    );
    let delivered = delivered_offsets(&out);
    let first = *delivered.first().expect("the consumer makes progress");
    assert!(
        first <= 5,
        "the recovered cursor is never AHEAD of the durable ack floor (first={first}): {out}"
    );
    assert_eq!(
        delivered,
        (first..10).collect::<Vec<u64>>(),
        "a contiguous suffix through the log head redelivers (at-least-once): {out}"
    );
    let (out, _e, code) = run(&["sub", "--addr", &addr2, "--max", "100", "--ack"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("fetched 0 message(s)"),
        "the group is caught up after the drain: {out}"
    );
}
