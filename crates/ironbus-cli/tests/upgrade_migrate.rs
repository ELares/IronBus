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

/// Drives the EXACT `record-start` sequence the packaged systemd unit performs at its three
/// lifecycle hooks, so the unit wiring (not just the pure functions) is proved. The hooks map to:
///
/// - `ExecStartPre`  -> `record-start --check`  (CONSULT only; rolls back iff it reports the
///   threshold reached). Returns whether the unit would roll back at this boot.
/// - `ExecStartPost` -> `record-start --ok`     (CLEAR; runs only once the broker survived the
///   readiness grace window, i.e. a genuine successful start).
/// - `ExecStopPost`  -> `record-start --failed` (the SINGLE increment, only on a non-clean exit).
fn unit_check_says_roll_back(dest: &Path) -> bool {
    // ExecStartPre: consult only, never bump. The unit greps this line to decide on a rollback.
    let (code, out, _e) =
        run_ironbus(&["record-start", "--dest", dest.to_str().unwrap(), "--check"]);
    assert_eq!(code, 0, "record-start --check must succeed");
    out.contains("fall-back threshold reached")
}
fn unit_exec_stop_post_failed(dest: &Path) {
    // ExecStopPost on a non-clean exit: the SINGLE increment.
    let (code, _o, _e) =
        run_ironbus(&["record-start", "--dest", dest.to_str().unwrap(), "--failed"]);
    assert_eq!(code, 0, "record-start --failed must succeed");
}
fn unit_exec_start_post_ok(dest: &Path) {
    // ExecStartPost after the readiness grace window: a genuine successful start clears the budget.
    let (code, _o, _e) = run_ironbus(&["record-start", "--dest", dest.to_str().unwrap(), "--ok"]);
    assert_eq!(code, 0, "record-start --ok must succeed");
}

#[test]
fn unit_wiring_three_genuine_failed_starts_roll_back() {
    // The fixed unit wiring (#104): a genuine failed start at boot consults (ExecStartPre --check,
    // no bump) then bumps once (ExecStopPost --failed) because the crash happens before the
    // ExecStartPost --ok grace window. Exactly N=3 such consecutive cycles trigger the rollback, and
    // ExecStartPre never double-counts.
    let scr = Scratch::new("unit-3fail");
    let dest = scr.path().join("ironbus");
    std::fs::write(&dest, b"new (failing) binary").unwrap();
    std::fs::write(scr.path().join("ironbus.prev"), b"old known-good binary").unwrap();

    // Boots 1 and 2: consult says no rollback yet; the crash bumps once each (no --ok, no double).
    for boot in 1..=2 {
        assert!(
            !unit_check_says_roll_back(&dest),
            "boot {boot}: below the threshold, ExecStartPre must not roll back"
        );
        unit_exec_stop_post_failed(&dest); // the binary crashed in the grace window
    }
    // Boot 3: the consult now sees the count at N=3 (each crash bumped by exactly 1, never +2), so
    // ExecStartPre would roll back. The count reaching 3 after exactly 3 crashes proves no
    // double-count from ExecStartPre.
    assert!(
        !unit_check_says_roll_back(&dest),
        "the consult before the 3rd crash is still below the threshold"
    );
    unit_exec_stop_post_failed(&dest);
    assert!(
        unit_check_says_roll_back(&dest),
        "after exactly 3 genuine failed starts the unit rolls back (no ExecStartPre double-count)"
    );
}

#[test]
fn unit_wiring_an_ok_in_between_resets_the_budget() {
    // A genuine successful start (ExecStartPost --ok after the grace window) in the middle of a
    // failure streak resets the budget, so the streak must restart from scratch and a later pair of
    // failures does NOT cross the threshold a single contiguous run of 3 would.
    let scr = Scratch::new("unit-reset");
    let dest = scr.path().join("ironbus");
    std::fs::write(&dest, b"binary").unwrap();
    std::fs::write(scr.path().join("ironbus.prev"), b"prev").unwrap();

    // Two failed starts...
    unit_exec_stop_post_failed(&dest);
    unit_exec_stop_post_failed(&dest);
    // ...then a healthy start (survived the grace window) clears the budget.
    unit_exec_start_post_ok(&dest);
    // Two more failed starts: the count is 2 (NOT 4), so still below the N=3 threshold.
    unit_exec_stop_post_failed(&dest);
    assert!(
        !unit_check_says_roll_back(&dest),
        "after a reset, one failed start is below the threshold"
    );
    unit_exec_stop_post_failed(&dest);
    assert!(
        !unit_check_says_roll_back(&dest),
        "after a reset, two failed starts are still below the threshold (an --ok reset the streak)"
    );
}

#[test]
fn unit_wiring_a_healthy_binary_does_not_roll_back_on_unclean_power_loss() {
    // THE power-loss hazard #104 centers on: a HEALTHY broker that loses power uncleanly must NOT
    // accumulate toward a rollback. After a genuine successful start (ExecStartPost --ok cleared the
    // budget), an unclean power loss runs NO ExecStopPost (power was cut), and the next boot's
    // ExecStartPre is a CONSULT ONLY (no bump). So repeated unclean power losses of a perfectly good
    // binary never roll it back.
    let scr = Scratch::new("unit-powerloss");
    let dest = scr.path().join("ironbus");
    std::fs::write(&dest, b"healthy binary").unwrap();
    std::fs::write(scr.path().join("ironbus.prev"), b"prev binary").unwrap();

    // A genuine successful start: ExecStartPost --ok clears the budget.
    unit_exec_start_post_ok(&dest);

    // Now simulate many unclean power losses of the HEALTHY binary. Each boot:
    //   - ExecStartPre --check (consult only, no bump),
    //   - the broker comes up and stays up (no ExecStopPost --failed runs),
    //   - power is cut uncleanly (so NO ExecStopPost runs at all on this boot).
    // The only counter call per boot is the consult, which never bumps.
    for boot in 1..=10 {
        assert!(
            !unit_check_says_roll_back(&dest),
            "boot {boot}: a healthy binary must never roll back on an unclean power loss"
        );
        // A power cut leaves no ExecStopPost; nothing increments the counter.
    }
    // The healthy binary is still in place; nothing was ever rolled back.
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"healthy binary",
        "the healthy binary survived repeated unclean power losses untouched"
    );
}

// --- #420: the packaged unit file's privileged-helper wiring ------------------------------------

#[test]
fn the_packaged_unit_keeps_the_privileged_helper_wiring() {
    // The root cause of #420 was that NOTHING asserted the shipped unit's content: dropping a `+`
    // Exec prefix re-ships the fleet-wide healthy-broker kill loop (the EROFS-failed ExecStartPost
    // makes systemd kill a HEALTHY broker at the end of the grace window, and Restart=on-failure
    // with the rate limiter disabled retries forever), and no compile, unit-test, or release gate
    // catches it. So this test pins the unit file's load-bearing lines: the three lifecycle helpers
    // run privileged (`+`), the broker itself does NOT, and the directives the fall-back-after-N
    // design leans on are present.
    let unit_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd/ironbus.service");
    let unit = std::fs::read_to_string(&unit_path).unwrap_or_else(|e| {
        panic!(
            "the packaged unit must exist at {}: {e}",
            unit_path.display()
        )
    });

    // (a) Each lifecycle hook appears EXACTLY once (the counter means "consecutive genuinely-failed
    // starts" only if each hook has ONE job) and runs with the `+` full-privilege prefix.
    for hook in ["ExecStartPre=", "ExecStartPost=", "ExecStopPost="] {
        let values: Vec<&str> = unit.lines().filter_map(|l| l.strip_prefix(hook)).collect();
        assert_eq!(
            values.len(),
            1,
            "{hook} must appear exactly once in the packaged unit, got {values:?}"
        );
        assert!(
            values[0].starts_with("+/bin/sh"),
            "{hook} must run privileged via `+/bin/sh` (#420): a dropped `+` makes every counter \
             write fail with EROFS under ProtectSystem=strict and re-ships the healthy-broker \
             kill loop (got: {hook}{})",
            values[0]
        );
    }

    // (b) The broker itself stays fully sandboxed: no `+` on ExecStart. (strip_prefix("ExecStart=")
    // cannot match the Pre/Post hook lines above, whose prefix continues with "Pre="/"Post=".)
    let exec_start: Vec<&str> = unit
        .lines()
        .filter_map(|l| l.strip_prefix("ExecStart="))
        .collect();
    assert_eq!(
        exec_start.len(),
        1,
        "the packaged unit must hold exactly one ExecStart=, got {exec_start:?}"
    );
    assert!(
        !exec_start[0].starts_with('+'),
        "ExecStart (the broker) must NOT carry the `+` prefix; the sandbox exemption is for the \
         three helpers only (got: ExecStart={})",
        exec_start[0]
    );

    // (c) The directives the fall-back-after-N design leans on. Losing any of these silently
    // changes the failure semantics the unit-wiring lifecycle tests above prove.
    for line in [
        "StartLimitIntervalSec=0",
        "Restart=on-failure",
        "ProtectSystem=strict",
        "User=ironbus",
    ] {
        assert!(
            unit.lines().any(|l| l.trim() == line),
            "the packaged unit must keep `{line}` (the fall-back-after-N design depends on it)"
        );
    }
}

// --- #348: two-rename re-entry window, over the real binary -------------------------------------

/// The fingerprint the CLI records for the known-bad guard: `"<crc32c hex>-<len>"`. Kept in lockstep
/// with `upgrade::fingerprint_bytes`; the integration test recomputes it to assert the guard file.
fn known_bad_fingerprint(bytes: &[u8]) -> String {
    format!("{:08x}-{}", crc32c::crc32c(bytes), bytes.len())
}

#[test]
fn a_power_cut_between_the_renames_never_promotes_the_bad_binary_over_the_real_binary() {
    // #348 over the SHIPPED verbs: drive `record-start --failed` to the cap (which records the
    // known-bad guard), then reproduce the EXACT on-disk state a power cut between the two rollback
    // renames leaves (dest holding nothing useful, `ironbus.prev` holding the BAD bytes), then run
    // the real `ironbus rollback` as the next boot's ExecStartPre would. It MUST refuse to promote
    // the known-bad `.prev` rather than installing the bad binary.
    let scr = Scratch::new("powercut-it");
    let dest = scr.path().join("ironbus");
    let prev = scr.path().join("ironbus.prev");
    let good = b"ironbus v1 (known good)";
    let bad = b"ironbus v2 (broken upgrade)";

    // The failing binary is at dest with a good rollback copy; N=3 failed starts record the guard.
    std::fs::write(&dest, bad).unwrap();
    std::fs::write(&prev, good).unwrap();
    for _ in 0..3 {
        let (code, _o, _e) =
            run_ironbus(&["record-start", "--dest", dest.to_str().unwrap(), "--failed"]);
        assert_eq!(code, 0);
    }
    let guard = scr.path().join(".ironbus-failed-fingerprint");
    assert_eq!(
        std::fs::read_to_string(&guard).unwrap().trim(),
        known_bad_fingerprint(bad),
        "reaching the cap records the failing binary's fingerprint as the known-bad guard"
    );

    // Reproduce the mid-rollback crash state: the first rename (dest -> .prev) landed, so `.prev`
    // now holds the BAD bytes and dest is gone. This is the precise hazard window.
    std::fs::rename(&dest, &prev).unwrap();
    assert!(!dest.exists());
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        bad,
        "the crash left .prev bad"
    );

    // Re-enter the rollback as the next boot would. It must REFUSE (exit 1), never promoting the bad
    // bytes to the destination.
    let (code, _o, err) = run_ironbus(&["rollback", "--dest", dest.to_str().unwrap()]);
    assert_eq!(
        code, 1,
        "the re-entry refuses to promote the known-bad .prev (stderr={err})"
    );
    assert!(
        err.contains("known-bad"),
        "the refusal names the known-bad guard (stderr={err})"
    );
    assert!(
        !dest.exists() || std::fs::read(&dest).unwrap() != bad,
        "the known-bad bytes were never promoted to the destination"
    );
}

#[test]
fn a_crash_during_rollback_then_re_entry_converges_to_the_good_binary_over_the_real_binary() {
    // CRASH-DURING-ROLLBACK over the shipped verbs: the counter reached the cap (guard recorded) and
    // a rollback was attempted but power was cut BEFORE the dest rename landed, so dest still holds
    // the bad bytes and `ironbus.prev` is still good. Re-entering `ironbus rollback` must complete
    // the rollback and converge dest to the GOOD binary (the good `.prev` is not the known-bad bytes).
    let scr = Scratch::new("crash-during-it");
    let dest = scr.path().join("ironbus");
    let prev = scr.path().join("ironbus.prev");
    let good = b"ironbus v1 (known good)";
    let bad = b"ironbus v2 (broken upgrade)";

    std::fs::write(&dest, bad).unwrap();
    std::fs::write(&prev, good).unwrap();
    for _ in 0..3 {
        let (code, _o, _e) =
            run_ironbus(&["record-start", "--dest", dest.to_str().unwrap(), "--failed"]);
        assert_eq!(code, 0);
    }

    // Re-enter: the good `.prev` does NOT match the known-bad guard, so the rollback proceeds.
    let (code, out, err) = run_ironbus(&["rollback", "--dest", dest.to_str().unwrap()]);
    assert_eq!(
        code, 0,
        "the re-entry completes the rollback (stdout={out} stderr={err})"
    );
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        good,
        "the re-entry converged the destination to the good binary"
    );
    // The completed rollback cleared the counter and the known-bad guard.
    assert!(
        !scr.path().join(".ironbus-start-attempts").exists(),
        "the completed rollback reset the failure budget"
    );
    assert!(
        !scr.path().join(".ironbus-failed-fingerprint").exists(),
        "the completed rollback cleared the known-bad guard"
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
    // Let the broker pick a free loopback port and REPORT it, then parse the actual bound address
    // from its "listening on <addr>," line (the same pattern the acceptance test uses). Pre-picking
    // a :0 port, dropping the listener, and handing that port to serve is a TOCTOU race: another
    // parallel test can grab the freed port before the broker binds it, so serve fails to bind and
    // every produce fails. That flaked on the shared macOS CI runner. Binding :0 in serve itself and
    // reading back the real address removes the race.
    let mut child = Command::new(BUILT_BIN)
        .args([
            "serve",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--addr",
            "127.0.0.1:0",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("serve must spawn");

    // Read the broker's stdout until it announces the address it actually bound.
    let mut addr = String::new();
    if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        for _ in 0..50 {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            if let Some(rest) = line.split("listening on ").nth(1) {
                if let Some(bound) = rest.split(',').next() {
                    addr = bound.trim().to_string();
                    break;
                }
            }
        }
    }
    assert!(!addr.is_empty(), "broker did not report its bound address");

    // Retry the produce until it succeeds, in case the listen line raced ahead of the accept loop or
    // the broker is starved on a heavily-loaded shared CI runner (the acceptance gate runs a 40s
    // job in parallel on macOS). A generous window (~30s: 300 attempts x 100ms) tolerates a badly
    // contended runner without flaking, and bails early if the broker process has already exited so a
    // crashed broker fails fast with its reason instead of burning the whole window.
    let mut produced = false;
    for _ in 0..300 {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("broker exited before a record was produced (status: {status})");
        }
        let (code, _o, _e) = run_ironbus(&["pub", "--addr", &addr, "a durable record"]);
        if code == 0 {
            produced = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
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
            let is_log = p
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("log"));
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
