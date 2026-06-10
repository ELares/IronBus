// SPDX-License-Identifier: MIT OR Apache-2.0
//! Fail-closed proof for the installer's checksum verification (#103).
//!
//! `scripts/install.sh` is the `curl | sh` installer; its security-critical core is
//! `verify_checksum`, which must accept a binary whose SHA256 matches the release `SHA256SUMS` and
//! REJECT everything else (a tampered binary, an asset with no checksum entry, an empty or missing
//! checksum file, a malformed digest). The function is factored to be sourced and called in
//! isolation, with no network access: the harness sets `IRONBUS_INSTALL_SH_SOURCED=1` so sourcing
//! defines the helpers without running `main`, then calls `verify_checksum` over fixtures and
//! asserts the exit status. This pins the fail-closed contract over a fixture even though no real
//! release exists yet, so a regression that makes the installer accept an unverified binary is a
//! CI failure (refs #103, #133).
//!
//! The installer is a POSIX `sh` script, so these tests are gated to Unix where `/bin/sh` exists.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

/// Absolute path to `scripts/install.sh` in the repository (two dirs up from this crate).
fn installer_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("install.sh")
        .canonicalize()
        .expect("scripts/install.sh must exist at the repo root")
}

/// Source the installer and invoke `verify_checksum <bin> <asset> <sums>` in the given working
/// directory. Returns the process exit code (0 = verification passed, non-zero = rejected).
///
/// Running through `/bin/sh -c` with `IRONBUS_INSTALL_SH_SOURCED=1` exercises exactly the same
/// function the live installer calls, with no network and no install side effects.
fn run_verify(dir: &std::path::Path, bin: &str, asset: &str, sums: &str) -> i32 {
    let script = installer_path();
    let cmd = format!(". \"$IB_INSTALLER\"; verify_checksum \"{bin}\" \"{asset}\" \"{sums}\"");
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(dir)
        .env("IRONBUS_INSTALL_SH_SOURCED", "1")
        .env("IB_INSTALLER", &script)
        .status()
        .expect("failed to run /bin/sh");
    status.code().unwrap_or(-1)
}

/// Source the installer and invoke its pure `install_binary <src> <dest>` helper, returning the
/// process exit code (0 = installed). This exercises the EXACT atomic-swap-plus-`.prev`-retention
/// code path the live installer's `main` calls, with no network and no checksum step (the caller
/// has already verified; `install_binary` is the post-verification install), so the rollback-safety
/// behavior is proved over the real script.
fn run_install_binary(src: &std::path::Path, dest: &std::path::Path) -> i32 {
    let script = installer_path();
    let cmd = format!(
        ". \"$IB_INSTALLER\"; install_binary \"{}\" \"{}\"",
        src.display(),
        dest.display()
    );
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .env("IRONBUS_INSTALL_SH_SOURCED", "1")
        .env("IB_INSTALLER", &script)
        .status()
        .expect("failed to run /bin/sh");
    status.code().unwrap_or(-1)
}

/// `sha256sum`/`shasum`-style line for a payload, as the release `SHA256SUMS` carries it.
fn sums_line(payload: &[u8], name: &str) -> String {
    use std::fmt::Write as _;
    // Compute the digest with the same tool the installer uses, so the fixture is tool-agnostic.
    let out = sha256_hex(payload);
    let mut line = String::new();
    writeln!(line, "{out}  {name}").unwrap();
    line
}

/// SHA256 of `bytes` as lowercase hex, shelling out to whatever the platform provides (the test
/// has no crypto dependency, matching the installer's own `sha256sum || shasum` approach). The
/// payload is piped over stdin, so there is no shared temp file and no race when the tests run in
/// parallel.
fn sha256_hex(bytes: &[u8]) -> String {
    use std::io::Write as _;
    let (prog, args): (&str, &[&str]) = if which("sha256sum") {
        ("sha256sum", &[])
    } else {
        ("shasum", &["-a", "256"])
    };
    let mut child = Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("a sha256 tool (sha256sum or shasum) is required to run this test");
    child.stdin.take().expect("stdin").write_all(bytes).unwrap();
    let out = child.wait_with_output().expect("sha256 tool output");
    assert!(out.status.success(), "sha256 tool failed");
    String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .expect("digest")
        .to_string()
}

fn which(prog: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {prog}"))
        .output()
        .is_ok_and(|o| o.status.success())
}

/// A self-contained fixture release dir with a binary and a matching `SHA256SUMS`.
struct Fixture {
    dir: tempdir::TempDir,
    asset: String,
}
impl Fixture {
    fn dir(&self) -> &std::path::Path {
        self.dir.path()
    }
}

/// Build a fixture: write the friendly-named asset (`ironbus-linux-amd64`) with `payload`, and a
/// `SHA256SUMS` over it (plus a second, unrelated asset entry so the "select the right line" path is
/// exercised). The asset names match the published, human-friendly release assets, not the internal
/// build triple.
fn fixture(payload: &[u8]) -> Fixture {
    let dir = tempdir::TempDir::new("ib-installer");
    let asset = "ironbus-linux-amd64".to_string();
    std::fs::write(dir.path().join(&asset), payload).unwrap();

    let other = b"a different architecture's bytes";
    std::fs::write(dir.path().join("ironbus-linux-arm64"), other).unwrap();

    let mut sums = String::new();
    sums.push_str(&sums_line(other, "ironbus-linux-arm64"));
    sums.push_str(&sums_line(payload, &asset));
    std::fs::write(dir.path().join("SHA256SUMS"), sums).unwrap();

    Fixture { dir, asset }
}

#[test]
fn a_matching_binary_is_accepted() {
    let payload = b"the genuine ironbus binary bytes";
    let fx = fixture(payload);
    let code = run_verify(fx.dir(), &fx.asset, &fx.asset, "SHA256SUMS");
    assert_eq!(
        code, 0,
        "verify_checksum must accept a binary whose SHA256 matches SHA256SUMS"
    );
}

#[test]
fn a_tampered_binary_is_rejected() {
    let payload = b"the genuine ironbus binary bytes";
    let fx = fixture(payload);
    // Overwrite the on-disk binary with tampered bytes AFTER SHA256SUMS was computed over the
    // genuine bytes; the digests no longer agree, so verification must fail closed.
    std::fs::write(
        fx.dir().join(&fx.asset),
        b"the genuine ironbus binary bytes + MALWARE",
    )
    .unwrap();
    let code = run_verify(fx.dir(), &fx.asset, &fx.asset, "SHA256SUMS");
    assert_ne!(
        code, 0,
        "verify_checksum MUST reject a tampered binary (fail-closed)"
    );
}

#[test]
fn an_asset_absent_from_sha256sums_is_rejected() {
    let payload = b"unlisted bytes";
    let fx = fixture(payload);
    // Ask to verify an asset name that has no entry in SHA256SUMS; a missing checksum is a
    // failure, never a pass.
    std::fs::write(fx.dir().join("ironbus-linux-armv7"), payload).unwrap();
    let code = run_verify(
        fx.dir(),
        "ironbus-linux-armv7",
        "ironbus-linux-armv7",
        "SHA256SUMS",
    );
    assert_ne!(
        code, 0,
        "an asset with no SHA256SUMS entry MUST be rejected"
    );
}

#[test]
fn an_empty_checksum_file_is_rejected() {
    let payload = b"bytes with an empty sums file";
    let fx = fixture(payload);
    std::fs::write(fx.dir().join("EMPTY_SUMS"), b"").unwrap();
    let code = run_verify(fx.dir(), &fx.asset, &fx.asset, "EMPTY_SUMS");
    assert_ne!(
        code, 0,
        "an empty SHA256SUMS MUST be rejected (fail-closed)"
    );
}

#[test]
fn a_missing_binary_is_rejected() {
    let fx = fixture(b"present");
    let code = run_verify(fx.dir(), "does-not-exist", &fx.asset, "SHA256SUMS");
    assert_ne!(code, 0, "a missing binary file MUST be rejected");
}

#[test]
fn a_malformed_checksum_line_is_rejected() {
    let fx = fixture(b"genuine");
    // A SHA256SUMS whose digest field is not 64 hex chars must be treated as a failure, not a
    // pass, so a corrupted or truncated sums line cannot wave a binary through.
    std::fs::write(
        fx.dir().join("BAD_SUMS"),
        format!("not-a-real-digest  {}\n", fx.asset),
    )
    .unwrap();
    let code = run_verify(fx.dir(), &fx.asset, &fx.asset, "BAD_SUMS");
    assert_ne!(code, 0, "a malformed checksum line MUST be rejected");
}

#[test]
fn an_upgrade_retains_the_prior_binary_as_ironbus_prev() {
    // ROLLBACK SAFETY (#133 step 10): installing over an existing binary must retain the PRIOR
    // bytes as `ironbus.prev` next to the destination, so an operator can roll back. This proves
    // the REAL product invariant via the installer's own `install_binary`, not a harness rename.
    let dir = tempdir::TempDir::new("ib-prev-upgrade");
    let dest = dir.path().join("ironbus");
    let prev = dir.path().join("ironbus.prev");

    // A prior install: there is already a binary at the destination.
    let old_bytes = b"ironbus v1 (the prior installed binary)";
    std::fs::write(&dest, old_bytes).unwrap();
    assert!(!prev.exists(), "no .prev exists before the upgrade");

    // Upgrade: install a NEW binary's bytes over it.
    let new_bytes = b"ironbus v2 (the upgrade)";
    let src = dir.path().join("staged-new");
    std::fs::write(&src, new_bytes).unwrap();
    let code = run_install_binary(&src, &dest);
    assert_eq!(code, 0, "install_binary must succeed on an upgrade");

    // The destination now holds the NEW bytes, and the PRIOR bytes are retained verbatim as
    // ironbus.prev (the rollback copy).
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        new_bytes,
        "the upgrade installed the new binary at the destination"
    );
    assert!(
        prev.exists(),
        "an upgrade MUST retain the prior binary as ironbus.prev (#133 step 10 rollback)"
    );
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        old_bytes,
        "ironbus.prev holds the EXACT prior binary bytes (a real rollback copy)"
    );
}

#[test]
fn a_fresh_install_creates_no_ironbus_prev() {
    // On a FRESH install (no prior binary at the destination) the installer must NOT fabricate an
    // `ironbus.prev`: there is nothing to roll back to, so a spurious `.prev` would be a lie.
    let dir = tempdir::TempDir::new("ib-prev-fresh");
    let dest = dir.path().join("ironbus");
    let prev = dir.path().join("ironbus.prev");
    assert!(
        !dest.exists(),
        "the destination starts empty (a fresh install)"
    );

    let bytes = b"ironbus v1 (the first install)";
    let src = dir.path().join("staged-fresh");
    std::fs::write(&src, bytes).unwrap();
    let code = run_install_binary(&src, &dest);
    assert_eq!(code, 0, "install_binary must succeed on a fresh install");

    assert_eq!(
        std::fs::read(&dest).unwrap(),
        bytes,
        "the fresh install placed the binary at the destination"
    );
    assert!(
        !prev.exists(),
        "a FRESH install MUST NOT create an ironbus.prev (nothing to retain)"
    );
}

/// A minimal, dependency-free temp-dir module (the workspace forbids adding new crates casually,
/// so the test brings its own RAII temp dir under the system temp root).
mod tempdir {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    // The tests in this file run in parallel under one test process, so `process::id()` is
    // identical for every fixture and `SystemTime::now()` is too coarse on the CI macOS runner to
    // separate two dirs created in the same tick. A collision used to share one directory (because
    // `create_dir_all` is idempotent), and whichever `TempDir` dropped first would `remove_dir_all`
    // the sibling's dir mid-run, surfacing as a spurious `verify_checksum` failure. This
    // process-wide counter makes every name unique, and `create_dir` (below) fails loudly instead
    // of silently sharing a directory if a name ever collides anyway.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub struct TempDir(PathBuf);
    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            let base = std::env::temp_dir();
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            let p = base.join(format!(
                "{prefix}-{}-{}-{seq}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&p).expect("create unique temp dir");
            TempDir(p)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Like [`run_install_binary`], but with `mv` overridden (after sourcing) so that any rename whose
/// TARGET is exactly the destination fails, simulating an ENOSPC / IO error on the FINAL swap (the
/// #421 stranded-host case). Every other `mv` (the `.prev` retention rename) passes through to the
/// real tool, so the function runs all the way to the final swap and fails exactly there.
fn run_install_binary_with_failing_final_swap(
    src: &std::path::Path,
    dest: &std::path::Path,
) -> i32 {
    let script = installer_path();
    let cmd = format!(
        ". \"$IB_INSTALLER\"; \
         mv() {{ for ib_last do :; done; \
                 if [ \"$ib_last\" = \"$IB_FAIL_DEST\" ]; then return 1; fi; \
                 command mv \"$@\"; }}; \
         install_binary \"{}\" \"{}\"",
        src.display(),
        dest.display()
    );
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .env("IRONBUS_INSTALL_SH_SOURCED", "1")
        .env("IB_INSTALLER", &script)
        .env("IB_FAIL_DEST", dest)
        .status()
        .expect("failed to run /bin/sh");
    status.code().unwrap_or(-1)
}

#[test]
fn a_same_version_rerun_is_a_noop_that_preserves_ironbus_prev() {
    // IDEMPOTENT RE-RUN (#422): re-running the installer with bytes IDENTICAL to the live binary
    // (a config-management convergence run, a retry after an unrelated failure) must be a no-op
    // SUCCESS. In particular it must NOT overwrite `ironbus.prev`: doing so would replace the
    // only rollback copy with bytes identical to the live binary, so "rollback" would reinstall
    // the very build it is rolling back from.
    let dir = tempdir::TempDir::new("ib-same-version");
    let dest = dir.path().join("ironbus");
    let prev = dir.path().join("ironbus.prev");

    // The host is at v2, with v1 retained as the rollback copy from a prior upgrade.
    let v1 = b"ironbus v1 (the rollback copy)";
    let v2 = b"ironbus v2 (the live binary)";
    std::fs::write(&dest, v2).unwrap();
    std::fs::write(&prev, v1).unwrap();

    // Re-run the install with the SAME v2 bytes.
    let src = dir.path().join("staged-v2-again");
    std::fs::write(&src, v2).unwrap();
    let code = run_install_binary(&src, &dest);
    assert_eq!(
        code, 0,
        "a same-version re-run must exit 0 (idempotent success)"
    );

    assert_eq!(
        std::fs::read(&dest).unwrap(),
        v2,
        "the live binary is unchanged by a same-version re-run"
    );
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        v1,
        "a same-version re-run MUST NOT clobber ironbus.prev (the only rollback copy)"
    );
}

#[test]
fn the_rollback_copy_survives_an_upgrade_then_a_same_version_rerun() {
    // The #422 end-to-end sequence: upgrade v1 to v2, then re-run the v2 install. After BOTH runs
    // `ironbus.prev` must still hold the v1 bytes, so `ironbus rollback` (and the systemd
    // fall-back-after-N mechanism) can actually return to the prior version instead of
    // reinstalling the live one.
    let dir = tempdir::TempDir::new("ib-upgrade-rerun");
    let dest = dir.path().join("ironbus");
    let prev = dir.path().join("ironbus.prev");

    let v1 = b"ironbus v1 (the prior version)";
    let v2 = b"ironbus v2 (the upgrade)";
    std::fs::write(&dest, v1).unwrap();

    // Upgrade v1 to v2: the rollback copy is v1.
    let src_upgrade = dir.path().join("staged-v2");
    std::fs::write(&src_upgrade, v2).unwrap();
    assert_eq!(
        run_install_binary(&src_upgrade, &dest),
        0,
        "the upgrade must succeed"
    );
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        v1,
        "after the upgrade, .prev = v1"
    );

    // Same-version re-run of v2.
    let src_rerun = dir.path().join("staged-v2-rerun");
    std::fs::write(&src_rerun, v2).unwrap();
    assert_eq!(
        run_install_binary(&src_rerun, &dest),
        0,
        "the same-version re-run must exit 0"
    );

    assert_eq!(
        std::fs::read(&dest).unwrap(),
        v2,
        "the live binary is still v2"
    );
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        v1,
        "ironbus.prev still holds the OLD version's bytes after the re-run (rollback intact)"
    );
}

#[test]
fn a_failed_swap_leaves_the_original_binary_at_the_destination() {
    // FAILURE SAFETY (#421): a failed install must leave the host with the binary it already had.
    // The old implementation moved the live binary to `.prev` BEFORE the final rename, so a
    // failure at the final step stranded the host with NO binary at the destination. With
    // copy-based retention the live binary is never moved, so EVERY failure point (staging,
    // retention, the final rename) leaves the original present at the destination.
    let old = b"ironbus v1 (the live binary)";

    // Phase 1: point dest at a path whose parent directory is read-only after the original binary
    // is staged into it, so every write into that directory fails. The install must fail without
    // touching the original (and without fabricating a `.prev`). A root user bypasses directory
    // permissions, so this phase is skipped under root (CI runs unprivileged).
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|s| s.trim() == "0");
    if !is_root {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir::TempDir::new("ib-failed-swap-rodir");
        let ro_dir = dir.path().join("ro-bin");
        std::fs::create_dir(&ro_dir).unwrap();
        let dest = ro_dir.join("ironbus");
        std::fs::write(&dest, old).unwrap();
        let src = dir.path().join("staged-v2");
        std::fs::write(&src, b"ironbus v2 (the upgrade)").unwrap();

        let mut perms = std::fs::metadata(&ro_dir).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&ro_dir, perms).unwrap();

        let code = run_install_binary(&src, &dest);

        // Restore write permission FIRST so the TempDir cleanup can remove the tree even if an
        // assertion below fails.
        let mut perms = std::fs::metadata(&ro_dir).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&ro_dir, perms).unwrap();

        assert_ne!(code, 0, "an install into a read-only directory must fail");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            old,
            "the ORIGINAL binary must still be present at the destination after the failure"
        );
        assert!(
            !ro_dir.join("ironbus.prev").exists(),
            "a failed install must not fabricate an ironbus.prev"
        );
    }

    // Phase 2: drive the function all the way to the FINAL swap and fail exactly there (the
    // ENOSPC / IO-error case from #421), via an `mv` override that rejects only a rename onto the
    // destination. The live binary must still be at the destination afterwards; under the old
    // two-rename swap it had already been moved to `.prev` and the destination was left EMPTY.
    let dir = tempdir::TempDir::new("ib-failed-swap-final");
    let dest = dir.path().join("ironbus");
    let prev = dir.path().join("ironbus.prev");
    std::fs::write(&dest, old).unwrap();
    let src = dir.path().join("staged-v2");
    std::fs::write(&src, b"ironbus v2 (the upgrade)").unwrap();

    let code = run_install_binary_with_failing_final_swap(&src, &dest);
    assert_ne!(code, 0, "a failed final swap must report failure");
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        old,
        "a failed FINAL swap must leave the live binary untouched at the destination (#421)"
    );
    // The retention ran before the failed swap and COPIED the live bytes, so `.prev` exists and
    // holds the same known-good bytes; the host stays healthy with its rollback copy intact.
    assert_eq!(
        std::fs::read(&prev).unwrap(),
        old,
        "the rollback copy holds the live (old) bytes after a failed final swap"
    );
}
