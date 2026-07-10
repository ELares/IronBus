// SPDX-License-Identifier: MIT OR Apache-2.0
//! The IronBus side of the #647 effectively-once SURVIVAL head-to-head vs NATS (V2-M12).
//!
//! The scenario family injects the two things that lapse a time-bounded dedup window — a broker
//! RESTART and a LONG PRODUCER-OFFLINE GAP — and MEASURES whether a producer's retry of an
//! already-acknowledged publish is deduplicated or double-appended. IronBus carries TWO distinct
//! dedup primitives (see `ironbus_core::dedup` and `ironbus_core::producer_seq`), and this
//! harness measures BOTH honestly:
//!
//!   - the `msg_id` WINDOW (#3, #33): per-producer, bounded by a count AND a monotonic TIME
//!     window (default 2 minutes), held IN MEMORY ONLY. It is the same primitive class as the
//!     NATS `Nats-Msg-Id` duplicate window: a republish outside the window (or after the state
//!     is lost) reads FRESH and is appended again — measured below, not hidden;
//!   - the idempotent-producer SEQUENCE (V2-M8, #638/#639): a per-producer
//!     `(producer_id, epoch, last_seq, last_offset)` high-water, persisted to
//!     `producer-seq.ckpt` on the cursor-checkpoint cadence, the graceful-shutdown flush, and
//!     inline at txn commit. The bound is SEQUENCE STATE, not wall-clock, so a retry is deduped
//!     across a restart AND an arbitrarily long gap — the effectively-once survival this
//!     head-to-head exists to demonstrate. Its honest durability bound is also measured: an
//!     UNCLEAN kill before any checkpoint tick loses the un-flushed high-water and degrades
//!     exactly those retries to at-least-once (`unclean_kill_before_any_checkpoint_...` below).
//!
//! The NATS side of the head-to-head is scripted in
//! `docs/benchmarks/effectively_once_nats.sh`, and the measured results table lives in
//! `docs/benchmarks/effectively-once.md`. This file is the REPEATABLE IronBus leg: it runs in
//! the normal `cargo test` suite (`cargo test -p ironbus-cli --test effectively_once`), so the
//! survival differentiator is demonstrated on every CI run, not asserted.
//!
//! Scenario 5 is the CONSUMER-side twin (#547): the durable per-message DELIVERY COUNT — a
//! poison message nacked mid-retry across a kill -9 resumes its count and dead-letters after
//! exactly `MaxDeliver` observed deliveries TOTAL, where NATS's volatile redelivery count (and
//! `MaxDeliver=-1` default) redelivers it forever. See `docs/DURABILITY.md` for the contract.
//!
//! Methodology note (mirrors the NATS leg): the "long offline gap" is measured against a
//! deliberately SHORTENED window — `--dedup-window-ms 3000` here, `duplicates: 5s` on the NATS
//! stream — and the gap sleeps PAST it. Waiting out the real 2-minute defaults would measure
//! the same lapse, only slower; shortening the window on BOTH sides is the standard, symmetric
//! methodology. The sequence path's assertions are wall-clock-INDEPENDENT, which is the point.
//!
//! The harness helpers mirror `corruption_recovery.rs` (the #644 head-to-head) and
//! `acceptance.rs`. `serve` is Unix-only in v1, so this whole file is gated to Unix (Windows
//! still compiles it to an empty module, keeping `-D warnings` clean on all targets).
#![cfg(unix)]
// The same shape-not-correctness style allowances the sibling #644 harness carries:
// deliberately-sequential scenario bodies, and prose that names products ("NATS JetStream").
#![allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use ironbus_client::proto::{PubBody, PubDedup};
use ironbus_client::{Client, ProduceAck};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The freshly-built `ironbus` binary under test (Cargo sets this for integration tests).
const BIN: &str = env!("CARGO_BIN_EXE_ironbus");

/// The stable idempotent-producer identity every sequenced leg publishes under.
const PRODUCER: &[u8] = b"survival-producer";

/// The producer epoch (the fencing token) for the whole harness: one live session, never fenced.
const EPOCH: u64 = 1;

/// The SHORTENED `msg_id` dedup window for the gap legs, in milliseconds (see the module doc:
/// the symmetric stand-in for the 2-minute default, mirroring the NATS leg's `duplicates: 5s`).
const SHORT_WINDOW_MS: u64 = 3_000;

/// How long the "producer-offline gap" sleeps: comfortably PAST [`SHORT_WINDOW_MS`].
const GAP: Duration = Duration::from_millis(4_500);

/// Kills and reaps the broker on drop, so a panicking assertion never leaks a serve process.
/// Dropping the guard is the harness's UNCLEAN stop (SIGKILL: no drain, no shutdown flush).
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
            "ironbus-effectively-once-{tag}-{}-{}",
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
/// cursor (and, on the same tick, the producer-seq high-water) synchronously per ack, so a
/// restart resume is deterministic. Same pattern as `corruption_recovery.rs`.
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

/// Stops the broker GRACEFULLY (SIGTERM: the #637 drain flushes the pending batch and
/// checkpoints every group, INCLUDING the producer-seq high-water) and waits for the exit.
/// The clean operational restart, as opposed to the guard-drop SIGKILL.
fn stop_gracefully(mut guard: ChildGuard) {
    let pid = guard.0.id().to_string();
    let status = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("send SIGTERM to serve");
    assert!(status.success(), "SIGTERM delivered to the broker");
    let deadline = Instant::now() + Duration::from_secs(30);
    while guard.0.try_wait().expect("poll serve").is_none() {
        assert!(
            Instant::now() < deadline,
            "serve must drain and exit promptly on SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // The guard's drop now signals an already-reaped process, which is harmless.
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

/// Publishes `payload` on the idempotent-producer SEQUENCE path: the dedup block carries
/// [`PRODUCER`]/[`EPOCH`] plus the per-producer monotonic `seq`, which routes the produce
/// through the DURABLE sequence high-water instead of the time-bounded `msg_id` window.
fn publish_seq(client: &mut Client, seq: u64, payload: &[u8]) -> ProduceAck {
    let msg_id = format!("seq-{seq}");
    client
        .produce_dedup(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: Some(PubDedup {
                producer_id: PRODUCER,
                epoch: EPOCH,
                msg_id: msg_id.as_bytes(),
                seq: Some(seq),
            }),
            fire_and_forget: false,
            payload,
        })
        .expect("sequenced produce")
}

/// Publishes `payload` on the `msg_id` WINDOW path (`seq: None`): the NATS-`Nats-Msg-Id`-class
/// time-bounded dedup, measured here for the honest comparison.
fn publish_window(client: &mut Client, msg_id: &str, payload: &[u8]) -> ProduceAck {
    client
        .produce_dedup(&PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            dedup: Some(PubDedup {
                producer_id: b"window-producer",
                epoch: 0,
                msg_id: msg_id.as_bytes(),
                seq: None,
            }),
            fire_and_forget: false,
            payload,
        })
        .expect("windowed produce")
}

/// Publishes a plain no-dedup record and returns its offset: the "next fresh offset" probe that
/// proves exactly how many records the retries appended (or did not).
fn publish_plain(client: &mut Client, payload: &[u8]) -> u64 {
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
        .expect("plain produce")
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

/// The delivered payloads from a `sub` run's stdout (`payload=<value>`).
fn payloads(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.split("payload=").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

// =================================================================================================
// SCENARIO 1: RETRY AFTER A CLEAN RESTART — a producer whose acks were lost in transit retries
// every publish after the broker comes back.
//
// IronBus measured behavior, sequence path: the graceful-shutdown flush persisted the
// `(producer_id, epoch, last_seq, last_offset)` high-water to `producer-seq.ckpt`, so every
// retry is a BENIGN duplicate (`duplicate = true`, nothing appended) — 0 duplicate records
// out of 10 retries. Per the high-water contract, a retry of an OLDER seq returns the
// LAST-accepted offset ("already durable, do not re-append"), not the per-seq original.
//
// IronBus measured behavior, `msg_id` window path (the honest half): the window is in-memory
// and does NOT survive the restart — the same retry re-appends (1 duplicate record out of 1).
// That is exactly the volatile-window class NATS's `Nats-Msg-Id` lives in; the durable seq path
// is the differentiator, not the window.
// =================================================================================================
#[test]
fn retry_after_clean_restart_is_deduped_by_the_durable_seq_highwater() {
    let scratch = Scratch::new("restart");
    let dir = scratch.join("data");
    let dir = dir.to_str().expect("utf8 data dir");

    // Publish a 10-record sequenced corpus (seq 1..=10) plus one msg_id-window record, all acked.
    let (broker, addr, _h) = start_broker(dir, &[]);
    let mut client = Client::connect(&addr).expect("connect the producer");
    for seq in 1..=10_u64 {
        let ack = publish_seq(&mut client, seq, format!("rec-{seq}").as_bytes());
        assert!(!ack.duplicate, "seq {seq} is a fresh publish");
        assert_eq!(ack.offset, seq - 1, "contiguous durable offsets");
    }
    let ack = publish_window(&mut client, "w-1", b"window-rec");
    assert!(!ack.duplicate, "the windowed publish is fresh");
    assert_eq!(ack.offset, 10);
    drop(client);

    // RESTART: the clean operational restart (SIGTERM drain, then a fresh serve over the dir).
    stop_gracefully(broker);
    let (_broker2, addr2, health2) = start_broker(dir, &[]);
    let mut client = Client::connect(&addr2).expect("reconnect after the restart");

    // The producer retries EVERY sequenced publish (its acks were "lost"): all deduped, nothing
    // appended, each retry answered with the durable high-water offset (9, the last accepted).
    for seq in 1..=10_u64 {
        let ack = publish_seq(&mut client, seq, format!("rec-{seq}").as_bytes());
        assert!(
            ack.duplicate,
            "seq {seq} retried across the restart is a benign duplicate, not a re-append"
        );
        assert_eq!(
            ack.offset, 9,
            "a retry of an older seq returns the high-water offset (the last-accepted append)"
        );
    }
    let metrics = http_get(&health2, "/metrics");
    assert_eq!(
        metric_value(&metrics, "ironbus_dedup_hits_total"),
        Some(10),
        "every one of the 10 cross-restart retries is a counted dedup hit"
    );

    // The honest window half: the SAME retry shape on the msg_id window re-appends, because the
    // window is in-memory and the restart cleared it (measured, recorded in the results table).
    let ack = publish_window(&mut client, "w-1", b"window-rec");
    assert!(
        !ack.duplicate,
        "the msg_id window does NOT survive a restart: the retry reads fresh (the volatile class)"
    );
    assert_eq!(ack.offset, 11, "the windowed retry was re-appended");

    // The duplicate-count ground truth: exactly ONE record was appended since the restart (the
    // windowed retry), ZERO from the ten sequenced retries.
    assert_eq!(
        publish_plain(&mut client, b"fresh-after-retries"),
        12,
        "10 sequenced retries appended nothing; only the windowed retry re-appended"
    );
    let (out, _e, code) = run(&["sub", "--addr", &addr2, "--max", "100", "--ack"]);
    assert_eq!(code, 0, "consume the whole log");
    let got = payloads(&out);
    assert_eq!(
        got.len(),
        13,
        "10 + window original + window dup + probe: {out}"
    );
    for seq in 1..=10_u64 {
        let rec = format!("rec-{seq}");
        assert_eq!(
            got.iter().filter(|p| **p == rec).count(),
            1,
            "sequenced record {rec} appears EXACTLY once (effectively-once held): {out}"
        );
    }
    assert_eq!(
        got.iter().filter(|p| *p == "window-rec").count(),
        2,
        "the windowed record appears twice (the measured, honest window lapse): {out}"
    );
}

// =================================================================================================
// SCENARIO 2: a LONG PRODUCER-OFFLINE GAP, no restart — the producer comes back after the dedup
// window has aged out and retries.
//
// IronBus measured behavior: the `msg_id` window lapses BY DESIGN (time-bounded, like NATS's
// `duplicate_window`) — the retry re-appends and the `ironbus_dedup_out_of_window_total`
// operator signal fires. The SEQUENCE path is wall-clock-independent: the same gap dedups every
// retry (0 duplicates out of 5).
// =================================================================================================
#[test]
fn offline_gap_lapses_the_msg_id_window_but_never_the_seq_highwater() {
    let scratch = Scratch::new("gap");
    let dir = scratch.join("data");
    let dir = dir.to_str().expect("utf8 data dir");

    // The SHORTENED window (see the module doc): 3 s here vs `duplicates: 5s` on the NATS leg.
    let window_ms = SHORT_WINDOW_MS.to_string();
    let (_broker, addr, health) = start_broker(dir, &["--dedup-window-ms", &window_ms]);
    let mut client = Client::connect(&addr).expect("connect the producer");

    for seq in 1..=5_u64 {
        let ack = publish_seq(&mut client, seq, format!("rec-{seq}").as_bytes());
        assert!(!ack.duplicate);
        assert_eq!(ack.offset, seq - 1);
    }
    let ack = publish_window(&mut client, "gap-1", b"gap-rec");
    assert!(!ack.duplicate);
    assert_eq!(ack.offset, 5);

    // The producer goes OFFLINE past the whole window, then comes back and retries everything.
    std::thread::sleep(GAP);

    let ack = publish_window(&mut client, "gap-1", b"gap-rec");
    assert!(
        !ack.duplicate,
        "the msg_id window lapsed over the gap: the retry reads fresh (time-bounded by design)"
    );
    assert_eq!(ack.offset, 6, "the windowed retry was re-appended");
    let metrics = http_get(&health, "/metrics");
    assert_eq!(
        metric_value(&metrics, "ironbus_dedup_out_of_window_total"),
        Some(1),
        "the window lapse is an operator-visible signal, never silent"
    );

    for seq in 1..=5_u64 {
        let ack = publish_seq(&mut client, seq, format!("rec-{seq}").as_bytes());
        assert!(
            ack.duplicate,
            "seq {seq} retried after the gap is still a duplicate: the high-water is sequence \
             state, not wall-clock"
        );
        assert_eq!(ack.offset, 4, "the high-water offset answers the retry");
    }

    // Ground truth: the gap retries appended exactly ONE record (the lapsed-window one).
    assert_eq!(
        publish_plain(&mut client, b"fresh-after-gap"),
        7,
        "5 sequenced retries appended nothing across the gap; only the windowed retry re-appended"
    );
}

// =================================================================================================
// SCENARIO 3: the COMBINED injection — an UNCLEAN kill (SIGKILL, no shutdown flush) PLUS an
// offline gap past the window, the worst case of the head-to-head.
//
// IronBus measured behavior: the sequenced corpus was consumed and acked before the kill, so the
// cursor-checkpoint tick (`--checkpoint-interval 1`) had already persisted the producer-seq
// high-water; every sequenced retry after kill + gap is STILL deduped (0 duplicates out of 5).
// The `msg_id` window loses on BOTH axes at once (state gone AND time lapsed): its retry
// re-appends, measured.
// =================================================================================================
#[test]
fn unclean_kill_plus_offline_gap_still_dedupes_the_checkpointed_seq_highwater() {
    let scratch = Scratch::new("combined");
    let dir = scratch.join("data");
    let dir = dir.to_str().expect("utf8 data dir");

    let window_ms = SHORT_WINDOW_MS.to_string();
    let (broker, addr, _h) = start_broker(dir, &["--dedup-window-ms", &window_ms]);
    let mut client = Client::connect(&addr).expect("connect the producer");
    for seq in 1..=5_u64 {
        let ack = publish_seq(&mut client, seq, format!("rec-{seq}").as_bytes());
        assert!(!ack.duplicate);
        assert_eq!(ack.offset, seq - 1);
    }
    let ack = publish_window(&mut client, "c-1", b"combined-rec");
    assert!(!ack.duplicate);
    assert_eq!(ack.offset, 5);
    drop(client);

    // A downstream consumer drains and acks the corpus: each ack's checkpoint tick persists the
    // cursor AND the producer-seq high-water (the cadence a real pipeline runs on).
    let (out, _e, code) = run(&["sub", "--addr", &addr, "--max", "6", "--ack"]);
    assert_eq!(code, 0, "the consumer drains the corpus: {out}");
    assert_eq!(
        payloads(&out).len(),
        6,
        "all six records consumed and acked"
    );

    // KILL -9 (no drain, no shutdown flush), then the offline gap, then the restart.
    drop(broker);
    std::thread::sleep(GAP);
    let (_broker2, addr2, _h2) = start_broker(dir, &["--dedup-window-ms", &window_ms]);
    let mut client = Client::connect(&addr2).expect("reconnect after kill + gap");

    for seq in 1..=5_u64 {
        let ack = publish_seq(&mut client, seq, format!("rec-{seq}").as_bytes());
        assert!(
            ack.duplicate,
            "seq {seq} retried across kill -9 PLUS the gap is still deduped: the checkpointed \
             high-water survives both"
        );
        assert_eq!(
            ack.offset, 4,
            "the recovered high-water offset answers the retry"
        );
    }
    let ack = publish_window(&mut client, "c-1", b"combined-rec");
    assert!(
        !ack.duplicate,
        "the msg_id window lost both ways (restart AND gap): the retry re-appends, measured"
    );
    assert_eq!(ack.offset, 6);

    assert_eq!(
        publish_plain(&mut client, b"fresh-after-combined"),
        7,
        "5 sequenced retries appended nothing across kill + gap; only the windowed retry re-appended"
    );
}

// =================================================================================================
// SCENARIO 4 (the HONEST BOUND of the sequence path): an unclean kill BEFORE any checkpoint
// tick, graceful flush, or txn commit has persisted the high-water.
//
// IronBus measured behavior: the high-water recorded since the last durability point is LOST —
// the retries read FRESH and re-append (3 duplicates out of 3), the documented at-least-once
// degrade. The bound on the durable seq path is CHECKPOINT LAG (an unclean kill may lose
// high-waters newer than the last ack-driven checkpoint tick / graceful shutdown / txn-commit
// flush), plus the [`ironbus_core::producer_seq::DEFAULT_MAX_SEQ_PRODUCERS`] LRU cap on tracked
// producers — never wall-clock. This leg exists so the results table states the real contract
// instead of claiming infinity.
// =================================================================================================
#[test]
fn unclean_kill_before_any_checkpoint_degrades_unflushed_highwaters_to_at_least_once() {
    let scratch = Scratch::new("unflushed");
    let dir = scratch.join("data");
    let dir = dir.to_str().expect("utf8 data dir");

    let (broker, addr, _h) = start_broker(dir, &[]);
    let mut client = Client::connect(&addr).expect("connect the producer");
    for seq in 1..=3_u64 {
        let ack = publish_seq(&mut client, seq, format!("rec-{seq}").as_bytes());
        assert!(!ack.duplicate);
        assert_eq!(ack.offset, seq - 1);
    }
    drop(client);

    // KILL -9 with ZERO durability points for the high-water: no consumer ever acked (no
    // checkpoint tick), no SIGTERM (no shutdown flush), no txn. The RECORDS are durable (each
    // PubAck is fsync-backed); only the dedup high-water since the last tick is not.
    drop(broker);
    let (_broker2, addr2, _h2) = start_broker(dir, &[]);
    let mut client = Client::connect(&addr2).expect("reconnect after the unclean kill");

    for (i, seq) in (1..=3_u64).enumerate() {
        let ack = publish_seq(&mut client, seq, format!("rec-{seq}").as_bytes());
        assert!(
            !ack.duplicate,
            "seq {seq}: the un-checkpointed high-water was lost with the unclean kill, so the \
             retry reads fresh — the measured at-least-once degrade, recorded honestly"
        );
        assert_eq!(
            ack.offset,
            3 + i as u64,
            "the degraded retry re-appends at the head"
        );
    }
    // Ground truth: all three retries re-appended (3 originals + 3 duplicates + this probe).
    assert_eq!(
        publish_plain(&mut client, b"fresh-after-degrade"),
        6,
        "every un-checkpointed retry re-appended: the honest bound is checkpoint lag"
    );
}

// =================================================================================================
// SCENARIO 5 (the CONSUMER-side twin of scenario 4, #547): MaxDeliver -> DLQ fires ACROSS a
// kill -9 mid-retry — the durable per-message DELIVERY COUNT survival that scenario 4's
// producer-side measurement left unasserted.
//
// IronBus measured behavior: a poison message nacked K times before an UNCLEAN kill (SIGKILL, no
// drain) resumes its delivery count at the durable floor after the restart, so it dead-letters
// after EXACTLY MaxDeliver observed deliveries TOTAL across the crash — never 2 x MaxDeliver, and
// never the NATS failure mode (redelivery count volatile, default MaxDeliver=-1: a poison
// redelivers FOREVER across restarts). The count is made durable by the #547 redelivery-driven
// attempts flush on the per-pass checkpoint seam (a poison retry loop never advances the cursor,
// so the interval checkpoint alone would never persist it) plus the clean-disconnect flush; the
// honest lag bound — an attempt-1-only kill loses at most that single first attempt, and a
// disabled trigger degrades to interval/disconnect cadence — is measured at the engine level
// (`engine::tests::an_unclean_kill_before_any_redelivery_costs_at_most_one_extra_delivery` and
// `a_threshold_of_zero_disables_the_trigger_and_the_dlq_fires_late_but_fires`: LATE by exactly
// the lag, but it FIRES).
// =================================================================================================
#[test]
fn max_deliver_dead_letters_after_a_kill_minus_nine_mid_retry_never_redelivers_forever() {
    const MAX_DELIVER: u32 = 5;
    let scratch = Scratch::new("poison");
    let dir = scratch.join("data");
    let dir = dir.to_str().expect("utf8 data dir");

    let (broker, addr, _h) = start_broker(dir, &["--max-deliver", "5"]);
    let mut client = Client::connect(&addr).expect("connect the producer");
    assert_eq!(publish_plain(&mut client, b"poison-rec"), 0);
    drop(client);

    // Deliver + NACK the poison twice (attempts 1 and 2). Each `sub --nack` run takes one
    // window-bounded batch and disconnects; the explicit 1 ms delay overrides the escalating
    // backoff schedule so the next run redelivers immediately.
    let mut observed_deliveries = 0u32;
    for attempt in 1..=2u32 {
        let (out, _e, code) = run(&[
            "sub",
            "--addr",
            &addr,
            "--max",
            "1",
            "--nack",
            "--delay-ms",
            "1",
        ]);
        assert_eq!(code, 0, "nack run {attempt}: {out}");
        let got = payloads(&out);
        assert_eq!(got, vec!["poison-rec".to_string()], "attempt {attempt}");
        observed_deliveries += 1;
    }
    // Let the broker's actor drain the per-pass attempts flush + the close-path checkpoint the
    // second run scheduled (both are broker-side and complete in microseconds; this sleep only
    // de-flakes a pathologically loaded CI runner) — then KILL -9 MID-RETRY: the poison is
    // nacked, its retry pending, its delivery count 2. No drain, no shutdown flush.
    std::thread::sleep(Duration::from_millis(500));
    drop(broker);

    // RESTART over the same dir: the delivery count must RESUME (NATS restarts it at zero).
    let (broker2, addr2, health2) = start_broker(dir, &["--max-deliver", "5"]);
    for run_idx in 3..=MAX_DELIVER {
        let (out, _e, code) = run(&[
            "sub",
            "--addr",
            &addr2,
            "--max",
            "1",
            "--nack",
            "--delay-ms",
            "1",
        ]);
        assert_eq!(code, 0, "post-restart nack run {run_idx}: {out}");
        let got = payloads(&out);
        assert_eq!(
            got,
            vec!["poison-rec".to_string()],
            "post-restart delivery {run_idx} still under the resumed MaxDeliver budget"
        );
        observed_deliveries += 1;
    }
    assert_eq!(
        observed_deliveries, MAX_DELIVER,
        "exactly MaxDeliver observed deliveries TOTAL across the kill -9"
    );

    // The NEXT fetch dead-letters the poison instead of delivering it: the count resumed at the
    // durable floor, so this is attempt MaxDeliver + 1 ACROSS the crash — the assertion NATS
    // cannot make (its redelivery count is volatile and its default MaxDeliver is unlimited).
    let (out, _e, code) = run(&[
        "sub",
        "--addr",
        &addr2,
        "--max",
        "1",
        "--nack",
        "--delay-ms",
        "1",
    ]);
    assert_eq!(code, 0, "the dead-lettering fetch: {out}");
    assert!(
        payloads(&out).is_empty(),
        "the poison is PARKED, not redelivered a 6th time: {out}"
    );
    let metrics = http_get(&health2, "/metrics");
    assert_eq!(
        metric_value(&metrics, "ironbus_dead_lettered_total"),
        Some(1),
        "MaxDeliver -> DLQ fired exactly once, across the kill -9"
    );
    assert_eq!(
        metric_value(&metrics, "ironbus_delivered_total"),
        Some(u64::from(MAX_DELIVER - 2)),
        "this broker run delivered only the RESUMED budget (3), not a fresh MaxDeliver"
    );

    // The durable ground truth, offline: stop the broker and stream the DLQ sink itself. The one
    // entry records attempt 6 (MaxDeliver + 1) — the count was TOTAL across the restart.
    drop(broker2);
    let (out, _e, code) = run(&["dump", "--data-dir", dir, "--dlq"]);
    assert_eq!(code, 0, "offline dlq dump: {out}");
    let dlq_lines: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("source_offset="))
        .collect();
    assert_eq!(dlq_lines.len(), 1, "exactly one dead-letter record: {out}");
    assert!(
        dlq_lines[0].contains("source_offset=0") && dlq_lines[0].contains("attempt=6"),
        "the poison dead-lettered as attempt MaxDeliver + 1, counted across the kill -9: {out}"
    );
}
