// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end test for `ironbus dev` (#796), the one-command local quickstart.
//!
//! It launches the REAL compiled `ironbus dev` as a subprocess (so it exercises the exact
//! orchestration a newcomer runs: `dev` mints an ephemeral temp dir, spawns the SAME `ironbus serve`,
//! pre-declares the demo topology, prints the snippet, and seeds), then proves the issue's
//! acceptance against the live broker:
//!
//! * the demo stream is PRE-DECLARED (`stream_info("demo").exists`),
//! * `--seed N` makes N messages consumable from the demo stream (a CONSUME COUNT),
//! * a produce->consume ROUNDTRIP works on the wire (`ironbus pub` then `ironbus sub`),
//! * the printed snippet references the demo stream and the REAL bound wire address, and
//! * the ephemeral data dir is REMOVED after the process is SIGTERM'd.
//!
//! Unix-only: `dev` (like `serve`) is Unix-only in v1, and the test SIGTERMs a child + reads
//! `/proc`-style process state, so the whole file is gated off the Windows build.
#![cfg(unix)]

use ironbus_client::{Client, ClientConfig};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ironbus");

/// A backstop guard: on drop (including a panicking assertion) it SIGTERMs `ironbus dev` so its own
/// cleanup runs (broker reaped, temp dir removed), then hard-kills if it does not exit promptly, so a
/// failing test never leaks the broker or the temp dir.
struct DevGuard(Child);

impl Drop for DevGuard {
    fn drop(&mut self) {
        term_and_reap(&mut self.0);
    }
}

/// Sends SIGTERM to `child`, waits up to 3s for a graceful exit, then hard-kills and reaps. A no-op
/// if the child was already reaped (the happy path terminates it explicitly).
fn term_and_reap(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let pid = child.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &pid]).status();
    if wait_for_exit(child, Duration::from_secs(3)) {
        return;
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Polls `child` until it exits or `budget` elapses; returns `true` if it exited in time.
fn wait_for_exit(child: &mut Child, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(_) => return false,
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs one `ironbus` subcommand to completion, returning (stdout, exit code).
fn run(args: &[&str]) -> (String, i32) {
    let out = Command::new(BIN)
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run an ironbus subcommand");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// Extracts the value after `marker` on a line that contains it, trimmed; the demo banner prints
/// `wire (produce/consume): <addr>` and `ephemeral data dir: <path> (removed on exit)`.
fn field_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.split_once(marker).map(|(_, rest)| rest.trim())
}

/// Launches the real `ironbus dev --seed <seed>` (no explicit ports: `dev` binds its friendly
/// default, or an OS-assigned free port if busy, and REPORTS the bound address — so the test is
/// robust under parallelism without racing on a fixed port), drains its output over a channel, and
/// returns the kill-guard plus the parsed wire address, the ephemeral data-dir path, and the full
/// startup transcript (captured through the final "press Ctrl-C" banner line).
fn start_dev(seed: u32) -> (DevGuard, String, String, String) {
    let mut child = Command::new(BIN)
        .args(["dev", "--seed", &seed.to_string()])
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus dev");

    // Drain stdout (dev's banner + the inherited broker logs) line-by-line over a channel, and drain
    // stderr in the background so neither pipe can fill and wedge the child.
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut sink = String::new();
        while reader.read_line(&mut sink).unwrap_or(0) != 0 {
            sink.clear();
        }
    });

    let guard = DevGuard(child);

    // Collect banner lines until the final "press Ctrl-C" marker, capturing the wire address and the
    // ephemeral data-dir path along the way.
    let mut transcript = String::new();
    let mut wire: Option<String> = None;
    let mut data_dir: Option<String> = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut ready = false;
    while Instant::now() < deadline {
        let Ok(line) = rx.recv_timeout(Duration::from_secs(5)) else {
            break;
        };
        transcript.push_str(&line);
        if let Some(a) = field_after(&line, "wire (produce/consume):") {
            wire = Some(a.to_string());
        }
        if let Some(rest) = field_after(&line, "ephemeral data dir:") {
            // `<path> (removed on exit)` -> keep just the path.
            let path = rest.split_once(" (removed").map_or(rest, |(p, _)| p).trim();
            data_dir = Some(path.to_string());
        }
        if line.contains("press Ctrl-C to stop") {
            ready = true;
            break;
        }
    }

    let wire = wire.unwrap_or_else(|| panic!("dev never reported its wire address:\n{transcript}"));
    let data_dir =
        data_dir.unwrap_or_else(|| panic!("dev never reported its data dir:\n{transcript}"));
    assert!(
        ready,
        "dev never finished its startup banner:\n{transcript}"
    );
    (guard, wire, data_dir, transcript)
}

#[test]
fn dev_quickstart_declares_seeds_roundtrips_and_cleans_up_on_sigterm() {
    let (mut guard, wire, data_dir, transcript) = start_dev(5);

    // The ephemeral data dir exists while dev runs.
    assert!(
        Path::new(&data_dir).exists(),
        "the ephemeral data dir should exist while dev runs: {data_dir}"
    );

    // --- Acceptance 1 + 2: the demo stream is pre-declared, and --seed 5 is consumable from it. ---
    let config = ClientConfig {
        understands_streams: true,
        ..ClientConfig::default()
    };
    let mut client = Client::connect_with(&wire, &config).expect("connect a streams client to dev");
    assert!(
        client.streams_enabled(),
        "dev broker should negotiate stream addressing"
    );
    let (exists, _head) = client.stream_info("demo").expect("stream_info(demo)");
    assert!(exists, "the `demo` stream should be PRE-DECLARED by dev");

    // Consume the seeded messages from the demo stream: a fresh group starts at the earliest offset.
    client
        .subscribe_to("demo", "e2e-seedcheck")
        .expect("subscribe_to demo");
    let mut consumed = 0u32;
    let mut idle = 0u32;
    while consumed < 5 && idle < 400 {
        let batch = client.fetch(64).expect("fetch from demo");
        if batch.messages.is_empty() {
            idle += 1;
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        for m in &batch.messages {
            let _ = client.ack(m.offset, m.generation);
            consumed += 1;
        }
    }
    assert_eq!(
        consumed, 5,
        "--seed 5 should make exactly 5 messages consumable from the demo stream"
    );
    drop(client);

    // --- Acceptance 3: a produce->consume ROUNDTRIP works on the wire (the default stream). ---
    let (_p, pcode) = run(&["pub", "--addr", &wire, "--key", "k1", "hello-roundtrip"]);
    assert_eq!(pcode, 0, "pub should succeed against the dev broker");
    let (sout, scode) = run(&[
        "sub", "--addr", &wire, "--group", "rt", "--max", "1", "--ack",
    ]);
    assert_eq!(scode, 0, "sub should succeed against the dev broker");
    assert!(
        sout.contains("payload=hello-roundtrip"),
        "the roundtrip message should come back from sub; got:\n{sout}"
    );

    // --- Acceptance 4: the printed snippet references the demo stream + the real bound wire addr. ---
    assert!(
        transcript.contains(&format!("ironbus pub --addr {wire}")),
        "snippet should show a paste-and-run pub at the bound wire addr:\n{transcript}"
    );
    assert!(
        transcript.contains(&format!("ironbus sub --addr {wire}")),
        "snippet should show a paste-and-run sub at the bound wire addr:\n{transcript}"
    );
    assert!(
        transcript.contains("demo"),
        "snippet should reference the demo stream:\n{transcript}"
    );

    // --- Acceptance 5: SIGTERM removes the ephemeral data dir. ---
    let pid = guard.0.id().to_string();
    Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("kill -TERM dev");
    assert!(
        wait_for_exit(&mut guard.0, Duration::from_secs(15)),
        "dev should exit cleanly after SIGTERM"
    );
    assert!(
        !Path::new(&data_dir).exists(),
        "the ephemeral data dir MUST be removed after dev exits on SIGTERM: {data_dir}"
    );
}
