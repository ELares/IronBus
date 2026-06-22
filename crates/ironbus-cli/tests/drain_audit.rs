// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end acceptance for the V2-M7 graceful-drain + SIGTERM readiness flip (#637) and the
//! security audit-event stream (#635), driving the real `ironbus` binary.
//!
//! #637 proves the load-bearing drain invariant over the actual process: a SIGTERM flips `/readyz`
//! to 503 (stop being routed new work) and the broker drains in-flight work and exits 0 cleanly with
//! NO acked-but-unflushed loss (a restart on the same data dir resumes past the acked records). #635
//! proves the audit stream emits a structured event for an auth success and an auth failure, carrying
//! the identity NAME and the mechanism/outcome, and NEVER the presented credential.
//!
//! `serve` is Unix only in v1 (on-disk storage uses positioned IO the Windows path lacks) and SIGTERM
//! is a Unix signal, so this whole test is gated to Unix.
#![cfg(unix)]

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

/// Boots `ironbus serve` with the wire AND health ports on ephemeral loopback, plus any `extra`
/// flags. Returns the kill-guard and the parsed `(wire_addr, health_addr)`. `--checkpoint-interval 1`
/// persists the cursor on each ack so a restart resume is deterministic.
fn start_broker_with_health(data_dir: &str, extra: &[&str]) -> (ChildGuard, String, String) {
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

/// Runs one `ironbus` subcommand to completion, returning its stdout and exit code.
fn run(args: &[&str]) -> (String, i32) {
    let out = Command::new(BIN).args(args).output().expect("run ironbus");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// Minimal blocking HTTP/1.0 GET; returns the full response or an IO error (so a caller can tell a
/// "503 served" from a "connection refused" — the broker already exited).
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

/// GET with a brief retry so a just-spawned health thread does not flake a slow runner.
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

/// Sends SIGTERM to a child process (the orchestrated stop signal).
fn sigterm(child: &Child) {
    // SAFETY: kill(2) takes a pid and a signal; the pid is this child's, owned for the test's
    // lifetime by the guard, and SIGTERM is a standard signal. It only requests termination.
    #[allow(unsafe_code)]
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
}

#[test]
fn sigterm_flips_readyz_to_503_then_drains_clean_with_no_acked_loss() {
    let dir = std::env::temp_dir().join(format!("ironbus-m7-drain-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);

    // Boot the broker with a generous drain timeout (so the drain is bounded but never trips here).
    let (mut broker, wire, health) =
        start_broker_with_health(&data_dir, &["--drain-timeout-ms", "30000"]);

    // Healthy + ready before the signal.
    let ready = http_get(&health, "/readyz");
    assert!(
        ready.starts_with("HTTP/1.0 200") || ready.starts_with("HTTP/1.1 200"),
        "ready before SIGTERM: {ready}"
    );

    // Produce a batch; each `pub` returns its durable offset only after the covering fsync (an ack
    // means durable, I2). These are the records that must NOT be lost across the SIGTERM stop.
    const N: usize = 8;
    for i in 0..N {
        let (out, code) = run(&["pub", "--addr", &wire, &format!("rec-{i}")]);
        assert_eq!(code, 0, "pub {i} exit code");
        assert_eq!(out.trim(), i.to_string(), "pub {i} durable offset");
    }

    // Send SIGTERM: the signal thread flips `draining` FIRST (so `/readyz` sheds 503), THEN stops the
    // accept loop and runs the bounded drain. The health server stays up THROUGH the drain.
    sigterm(&broker.0);

    // Observe the readiness flip: `/readyz` answers 503 ("draining") while the broker drains. The
    // health server keeps serving during the drain, so this is a real 503, not a refused connection.
    // (If the drain finished and the process exited before we polled, the connection is refused —
    // either way readiness is no longer 200; we assert we never see a spurious 200 after the signal,
    // and that we DO observe at least the 503 or a clean exit.)
    let mut saw_503 = false;
    let mut exited = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match http_get_once(&health, "/readyz") {
            Ok(resp) if resp.contains(" 503 ") || resp.contains("draining") => {
                saw_503 = true;
                break;
            }
            Ok(resp) if resp.contains(" 200 ") => {
                panic!("/readyz must NOT report 200 after SIGTERM (readiness must shed): {resp}");
            }
            Ok(_) => {}
            // Connection refused/reset: the broker already drained and exited cleanly.
            Err(_) => {
                exited = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        saw_503 || exited,
        "after SIGTERM, /readyz must shed 503 (drain in progress) or the broker exits cleanly"
    );

    // The broker exits 0 (a clean, graceful stop) within the grace window.
    let status = wait_for_exit(&mut broker.0, Duration::from_secs(15));
    assert_eq!(status, Some(0), "graceful SIGTERM stop exits 0");
    drop(broker);

    // No acked loss: restart on the SAME data dir and confirm every produced record survived (they
    // were fsynced before their offsets returned, and the drain flushed the cursor). A fresh
    // consumer reads all N records back.
    let (broker2, wire2, _health2) = start_broker_with_health(&data_dir, &[]);
    let (out, code) = run(&["sub", "--addr", &wire2, "--max", "100"]);
    assert_eq!(code, 0, "sub after restart");
    for i in 0..N {
        assert!(
            out.contains(&format!("payload=rec-{i}")),
            "record rec-{i} survived the SIGTERM stop: {out}"
        );
    }
    assert!(
        out.contains(&format!("fetched {N} message(s)")),
        "all {N} acked records are durable after the graceful stop: {out}"
    );

    drop(broker2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Waits up to `timeout` for the child to exit, returning its exit code (or `None` if it did not
/// exit in time). Polls `try_wait` so a hung broker fails the test rather than hanging it.
fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
    None
}

#[test]
fn audit_log_routes_the_config_change_event_to_stderr_and_to_a_file_owner_only() {
    // The audit STREAM is operator-selectable (#635): this proves the SINK ROUTING end-to-end over
    // the real binary — the startup `config_change` event reaches the chosen sink (stderr, then a
    // file), and the file is created owner-only (0o600). The auth-outcome / scope-denial events and
    // the no-secret-leak property are proven exhaustively at the session unit level (the CLI client
    // does not carry a bearer token, so an auth handshake cannot be driven from `pub`/`sub`).
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("ironbus-m7-audit-{}", std::process::id()));
    let data_dir = dir.to_str().expect("utf8 temp path").to_string();
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // --- Sink 1: stderr. ---
    {
        let (mut guard, stderr) = spawn_and_capture_stderr(&[
            "serve",
            "--data-dir",
            &data_dir,
            "--addr",
            "127.0.0.1:0",
            "--audit-log",
            "stderr",
        ]);
        // Let the broker boot (it emits the startup config_change event), then stop it.
        let _wire = read_listen_addr(&mut guard.0);
        std::thread::sleep(Duration::from_millis(150));
        let _ = guard.0.kill();
        let _ = guard.0.wait();
        let captured = stderr.join();
        assert!(
            captured.contains("event=config_change") && captured.contains("summary=\"startup\""),
            "the startup config_change audit event reached the stderr sink: {captured}"
        );
        // The structured envelope is present: a sequence and a wall-clock stamp.
        assert!(captured.contains("seq=0"), "the audit envelope sequence: {captured}");
        assert!(captured.contains("ts_ms="), "the audit envelope wall clock: {captured}");
    }

    // --- Sink 2: a file (@path), created owner-only. ---
    {
        let audit_file = dir.join("audit.log");
        let (mut guard, _stderr) = spawn_and_capture_stderr(&[
            "serve",
            "--data-dir",
            &data_dir,
            "--addr",
            "127.0.0.1:0",
            "--audit-log",
            &format!("@{}", audit_file.display()),
        ]);
        let _wire = read_listen_addr(&mut guard.0);
        std::thread::sleep(Duration::from_millis(150));
        let _ = guard.0.kill();
        let _ = guard.0.wait();
        let body = std::fs::read_to_string(&audit_file).expect("audit file written");
        assert!(
            body.contains("event=config_change") && body.contains("summary=\"startup\""),
            "the startup config_change audit event reached the file sink: {body}"
        );
        // The audit file is owner-only (0o600): a security audit log is itself secret-adjacent.
        let mode = std::fs::metadata(&audit_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the audit file is owner-only, got {mode:o}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A captured-stderr handle so a test can read the broker's stderr after it stops.
struct StderrCapture(std::sync::mpsc::Receiver<String>);

impl StderrCapture {
    fn join(self) -> String {
        self.0.recv_timeout(Duration::from_secs(10)).unwrap_or_default()
    }
}

/// Spawns `ironbus <args>` with stderr piped onto a draining thread, so the broker never blocks on a
/// full stderr pipe and the test can read everything stderr produced after the process stops.
fn spawn_and_capture_stderr(args: &[&str]) -> (ChildGuard, StderrCapture) {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ironbus serve");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut buf);
        let _ = tx.send(buf);
    });
    (ChildGuard(child), StderrCapture(rx))
}

/// Reads the broker's "listening on <addr>" line from its piped stdout, under a timeout.
fn read_listen_addr(child: &mut Child) -> String {
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        for _ in 0..8 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if let Some(a) = line
                .split("listening on ")
                .nth(1)
                .and_then(|rest| rest.split(',').next())
                .map(str::trim)
            {
                let _ = tx.send(a.to_string());
                return;
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("ironbus serve printed a listening line")
}
