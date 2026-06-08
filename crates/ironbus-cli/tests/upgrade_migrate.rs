// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end proof for the atomic in-place upgrade/rollback and the `migrate` format gate (#104).
//!
//! These drive the REAL `ironbus` binary (the same artifact a release ships) over real files, in
//! the style of `installer_verify.rs` and `acceptance.rs`, so the product invariants are proved on
//! the shipped surface, not only on the library's unit tests:
//!
//! - `upgrade` swaps an already-verified new binary over the live one, retains the prior binary as
//!   `<dest>.prev`, and `rollback` restores it; the start-attempt counter (`record-start`) drives
//!   the fall-back-after-N decision.
//! - `migrate` REFUSES a silent on-disk format bump (a data dir whose stamped format version differs
//!   from this build's), and reports "no migration needed" for a same-major (current-version) data
//!   dir, which opens with no migration.
//!
//! The on-disk verbs are Unix-only in v1 (the storage uses positioned IO the Windows path lacks),
//! so the whole file is gated to Unix, matching `serve`/`peek`/`dump`.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// The freshly-built `ironbus` binary under test (cargo sets this for an integration test).
const BUILT_BIN: &str = env!("CARGO_BIN_EXE_ironbus");

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique scratch directory under the system temp dir, created fresh and removed on drop.
struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "ironbus-upgrade-it-{tag}-{}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `ironbus <args...>` and returns (`exit_code`, stdout, stderr).
fn run_ironbus(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BUILT_BIN)
        .args(args)
        .output()
        .expect("failed to run the ironbus binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// --- upgrade / rollback / fall-back-counter over the real binary --------------------------------

#[test]
fn upgrade_retains_prev_and_rollback_restores_it() {
    // The core lifecycle (#104): `ironbus upgrade` swaps a (stand-in) verified new binary over the
    // live one and retains the prior bytes as `<dest>.prev`; `ironbus rollback` restores them. The
    // live binary is NEVER overwritten in place (atomic rename), so a power cut mid-upgrade keeps
    // either the old or the new binary intact.
    let scr = Scratch::new("lifecycle");
    let dest = scr.path().join("ironbus");
    let prev = scr.path().join("ironbus.prev");

    // A prior install: bytes already at the destination.
    let old = b"ironbus v1 (prior installed bytes)";
    std::fs::write(&dest, old).unwrap();

    // The "verified new binary" the installer would have downloaded and checked. upgrade is the
    // post-verify atomic swap, so a plain file stands in for the verified download here.
    let new = b"ironbus v2 (the upgrade)";
    let staged = scr.path().join("staged-new");
    std::fs::write(&staged, new).unwrap();

    let (code, out, err) = run_ironbus(&[
        "upgrade",
        "--new-binary",
        staged.to_str().unwrap(),
        "--dest",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "upgrade must succeed (stdout={out} stderr={err})");
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        new,
        "the new binary is installed"
    );
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        old,
        "the prior binary is retained verbatim as ironbus.prev (the rollback copy)"
    );

    // Roll back: the retained prior bytes come back over the destination.
    let (code, out, err) = run_ironbus(&["rollback", "--dest", dest.to_str().unwrap()]);
    assert_eq!(code, 0, "rollback must succeed (stdout={out} stderr={err})");
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        old,
        "rollback restored the prior known-good bytes over the destination"
    );
}

#[test]
fn a_fresh_upgrade_creates_no_prev() {
    // A fresh install (nothing at the destination) must not fabricate a `.prev`.
    let scr = Scratch::new("freshit");
    let dest = scr.path().join("ironbus");
    let prev = scr.path().join("ironbus.prev");

    let new = b"ironbus v1 (first install)";
    let staged = scr.path().join("staged");
    std::fs::write(&staged, new).unwrap();

    let (code, _o, err) = run_ironbus(&[
        "upgrade",
        "--new-binary",
        staged.to_str().unwrap(),
        "--dest",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "fresh upgrade must succeed (stderr={err})");
    assert_eq!(std::fs::read(&dest).unwrap(), new);
    assert!(!prev.exists(), "a fresh install creates no ironbus.prev");
}

#[test]
fn the_fall_back_counter_reaches_the_threshold_after_n_failed_starts() {
    // The fall-back-after-N decision (#104), driven through the real `record-start` verb the
    // systemd unit calls: with a `.prev` present and the default N=3, the third failed start
    // reports that the fall-back threshold is reached; a healthy `--ok` clears the budget.
    let scr = Scratch::new("counter");
    let dest = scr.path().join("ironbus");
    std::fs::write(&dest, b"new (failing) binary").unwrap();
    std::fs::write(scr.path().join("ironbus.prev"), b"old known-good binary").unwrap();

    // Below the threshold: no fall-back yet.
    for n in 1..=2 {
        let (code, out, _e) =
            run_ironbus(&["record-start", "--dest", dest.to_str().unwrap(), "--failed"]);
        assert_eq!(code, 0);
        assert!(
            out.contains(&format!("failed start {n}/3")) && out.contains("no fall-back yet"),
            "below the threshold reports no fall-back (got: {out})"
        );
    }
    // The third failed start: the threshold is reached and a .prev exists, so it instructs rollback.
    let (code, out, _e) =
        run_ironbus(&["record-start", "--dest", dest.to_str().unwrap(), "--failed"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("failed start 3/3") && out.contains("fall-back threshold reached"),
        "the third failed start reaches the fall-back threshold (got: {out})"
    );

    // A healthy start clears the budget back to a clean slate.
    let (code, out, _e) = run_ironbus(&["record-start", "--dest", dest.to_str().unwrap(), "--ok"]);
    assert_eq!(code, 0);
    assert!(out.contains("start counter cleared"), "got: {out}");
    let (_c, out, _e) =
        run_ironbus(&["record-start", "--dest", dest.to_str().unwrap(), "--failed"]);
    assert!(
        out.contains("failed start 1/3"),
        "the counter restarted from 1 after a healthy start (got: {out})"
    );
}

#[test]
fn upgrade_rejects_a_missing_new_binary() {
    // Fail-closed: upgrade refuses to run if the (would-be verified) new binary is absent, rather
    // than touching the live binary.
    let scr = Scratch::new("missing");
    let dest = scr.path().join("ironbus");
    std::fs::write(&dest, b"live binary").unwrap();
    let (code, _o, err) = run_ironbus(&[
        "upgrade",
        "--new-binary",
        scr.path().join("does-not-exist").to_str().unwrap(),
        "--dest",
        dest.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 1,
        "a missing new binary is a usage error (stderr={err})"
    );
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"live binary",
        "the live binary is untouched when the swap is refused"
    );
}

// --- migrate format gate over the real binary ---------------------------------------------------

/// Boots `ironbus serve` against `data_dir` just long enough to produce one record (so the data dir
/// has a real, current-format segment on disk), then stops it. Returns once a record is durable.
fn seed_data_dir_with_one_record(data_dir: &Path) {
    use std::io::{BufRead, BufReader};
    // A free loopback port for this broker.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let addr = addr.to_string();

    let mut child = Command::new(BUILT_BIN)
        .args([
            "serve",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--addr",
            &addr,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("serve must spawn");

    // Wait for the broker to announce it is listening, then produce one record over the wire.
    if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        for _ in 0..50 {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if line.contains("listening") || line.contains(&addr) {
                break;
            }
        }
    }
    // Retry the produce briefly in case the listen line raced ahead of the accept loop.
    let mut produced = false;
    for _ in 0..50 {
        let (code, _o, _e) = run_ironbus(&["pub", "--addr", &addr, "a durable record"]);
        if code == 0 {
            produced = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(produced, "failed to produce a record into the data dir");
}

#[test]
fn migrate_reports_no_migration_for_a_current_major_data_dir() {
    // A data dir written by THIS build is on the current on-disk format version, so `migrate` opens
    // it with NO migration (the format-compat-within-major guarantee), exit 0.
    let scr = Scratch::new("samever");
    let data_dir = scr.path().join("data");
    seed_data_dir_with_one_record(&data_dir);

    let (code, out, err) = run_ironbus(&["migrate", "--data-dir", data_dir.to_str().unwrap()]);
    assert_eq!(
        code, 0,
        "a same-major data dir needs no migration (stderr={err})"
    );
    assert!(
        out.contains("no migration needed"),
        "migrate reports no migration for the current major (got: {out})"
    );
}

#[test]
fn migrate_reports_no_migration_for_a_fresh_empty_data_dir() {
    // A fresh data dir with no segments opens at the current format with no migration.
    let scr = Scratch::new("empty");
    let data_dir = scr.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let (code, out, _e) = run_ironbus(&["migrate", "--data-dir", data_dir.to_str().unwrap()]);
    assert_eq!(code, 0, "a fresh data dir needs no migration");
    assert!(out.contains("no migration needed"), "got: {out}");
}

#[test]
fn migrate_refuses_a_silent_format_bump() {
    // THE GATE (#104, #132): a data dir whose stamped on-disk format version differs from this
    // build's must NOT be opened/migrated silently. We simulate a future format by rewriting the
    // version byte (offset 8) of the first segment header to a value this build does not write;
    // `migrate` reads that byte RAW and REFUSES with a usage error unless `--allow` is passed.
    let scr = Scratch::new("bump");
    let data_dir = scr.path().join("data");
    seed_data_dir_with_one_record(&data_dir);

    // Find the first segment file and bump its header version byte at offset 8 to 2 (a future
    // format this v1 build does not understand).
    let seg = std::fs::read_dir(&data_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            let is_seg_name = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("seg-"));
            let is_log = p.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("log"));
            is_seg_name && is_log
        })
        .expect("a segment file must exist after seeding");
    let mut bytes = std::fs::read(&seg).unwrap();
    assert!(bytes.len() > 8, "the segment file holds a header");
    assert_eq!(bytes[8], 1, "the seeded data dir is on-disk format v1");
    bytes[8] = 2; // a future format version
    std::fs::write(&seg, &bytes).unwrap();

    // Without --allow: refused as a usage error (exit 1), naming the gate.
    let (code, _o, err) = run_ironbus(&["migrate", "--data-dir", data_dir.to_str().unwrap()]);
    assert_eq!(
        code, 1,
        "a silent format bump is refused with a usage error"
    );
    assert!(
        err.contains("REFUSING a silent format bump") && err.contains("--allow"),
        "migrate refuses and points at the explicit --allow gate (got stderr: {err})"
    );

    // Even WITH --allow <current>, this v1 build has no in-place migrator from v2, so it still
    // refuses (honestly) rather than reinterpreting the bytes; the point is it is NEVER silent.
    let (code, _o, err) = run_ironbus(&[
        "migrate",
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--allow",
        "1",
    ]);
    assert_eq!(
        code, 1,
        "no in-place migration path exists, so it is still refused"
    );
    assert!(
        err.contains("no in-place migration path"),
        "migrate explains there is no migrator rather than faking one (got stderr: {err})"
    );
}
