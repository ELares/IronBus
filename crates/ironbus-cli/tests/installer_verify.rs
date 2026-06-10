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

/// Write an executable `sh` stub tool named `name` into `dir`. The stub body must use only shell
/// builtins (`printf`, `case`, `exit`), because `run_download` restricts PATH to the stub dir and
/// an external command would not resolve there.
fn write_stub(dir: &std::path::Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Source the installer and invoke its `download <url> <dest>` helper with PATH restricted to
/// `stub_dir` ONLY, so the helper sees exactly the stub `curl`/`wget` placed there and nothing
/// else (in particular, the host's real curl is invisible when no curl stub exists). Returns the
/// exit code plus the captured stderr, so a test can assert both the fail-closed status and the
/// clarity of the error message. No network is touched: a stub is the only tool that can run.
fn run_download(stub_dir: &std::path::Path, url: &str, dest: &std::path::Path) -> (i32, String) {
    let script = installer_path();
    let cmd = format!(
        ". \"$IB_INSTALLER\"; download \"{url}\" \"{}\"",
        dest.display()
    );
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .env("IRONBUS_INSTALL_SH_SOURCED", "1")
        .env("IB_INSTALLER", &script)
        .env("PATH", stub_dir)
        .output()
        .expect("failed to run /bin/sh");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_gnu_wget_1x_is_refused_with_no_download() {
    // FAIL-CLOSED (#423): GNU wget 1.x honors --https-only ONLY in recursive mode (verified on
    // GNU Wget 1.25.0: a plain-http URL and an https-to-http 302 both fetch over plaintext with
    // exit 0), so the helper must classify it from `wget --version` and refuse before any fetch.
    let dir = tempdir::TempDir::new("ib-wget-gnu1");
    let fetched = dir.path().join("wget-fetched");
    write_stub(
        dir.path(),
        "wget",
        &format!(
            concat!(
                "case \"$1\" in\n",
                "  --version) printf '%s\\n' 'GNU Wget 1.21.3 built on linux-gnu.'; exit 0 ;;\n",
                "esac\n",
                "printf '%s\\n' \"$@\" > \"{log}\"\n",
                "exit 0\n"
            ),
            log = fetched.display()
        ),
    );
    let dest = dir.path().join("dest");
    let (code, stderr) = run_download(dir.path(), "https://example.invalid/asset", &dest);
    assert_ne!(
        code, 0,
        "GNU wget 1.x MUST be refused, never trusted to pin HTTPS"
    );
    assert!(
        !fetched.exists(),
        "the refusal must happen BEFORE any fetch is attempted"
    );
    assert!(
        stderr.contains("recursive mode") && stderr.contains("install curl"),
        "the error must name the wget 1.x reason and the remedy, stderr: {stderr}"
    );
    assert!(!dest.exists(), "nothing may be downloaded");
}

#[test]
fn a_wget2_is_refused_with_no_download() {
    // FAIL-CLOSED (#423): wget2's enforcement was empirically DISPROVEN on wget2 2.2.1
    // (--https-only skips the command-line URL; its redirect refusal exits 0 with no output
    // file; --https-enforce=hard silently falls back to plaintext when the TLS connect fails),
    // so wget2 is refused exactly like wget 1.x: classified from --version, no fetch attempted.
    let dir = tempdir::TempDir::new("ib-wget2");
    let fetched = dir.path().join("wget-fetched");
    write_stub(
        dir.path(),
        "wget",
        &format!(
            concat!(
                "case \"$1\" in\n",
                "  --version) printf '%s\\n' 'GNU Wget2 2.2.1 - multithreaded metalink/file/website downloader'; exit 0 ;;\n",
                "esac\n",
                "printf '%s\\n' \"$@\" > \"{log}\"\n",
                "exit 0\n"
            ),
            log = fetched.display()
        ),
    );
    let dest = dir.path().join("dest");
    let (code, stderr) = run_download(dir.path(), "https://example.invalid/asset", &dest);
    assert_ne!(
        code, 0,
        "wget2 MUST be refused: its enforcement is disproven, not just unproven"
    );
    assert!(
        !fetched.exists(),
        "the refusal must happen BEFORE any fetch is attempted"
    );
    assert!(
        stderr.contains("wget2") && stderr.contains("install curl"),
        "the error must name the wget2 evidence and the remedy, stderr: {stderr}"
    );
    assert!(!dest.exists(), "nothing may be downloaded");
}

#[test]
fn a_busybox_or_unrecognized_wget_is_refused_with_no_download() {
    // FAIL-CLOSED (#423): BusyBox wget rejects --version with a usage error and has no HTTPS
    // enforcement flags at all; anything the classifier cannot recognize is refused the same way.
    let dir = tempdir::TempDir::new("ib-wget-busybox");
    let fetched = dir.path().join("wget-fetched");
    write_stub(
        dir.path(),
        "wget",
        &format!(
            concat!(
                "case \"$1\" in\n",
                "  --version) printf '%s\\n' 'wget: unrecognized option: version' >&2; exit 1 ;;\n",
                "esac\n",
                "printf '%s\\n' \"$@\" > \"{log}\"\n",
                "exit 0\n"
            ),
            log = fetched.display()
        ),
    );
    let dest = dir.path().join("dest");
    let (code, stderr) = run_download(dir.path(), "https://example.invalid/asset", &dest);
    assert_ne!(
        code, 0,
        "an unrecognized wget MUST fail closed, never downgrade"
    );
    assert!(
        !fetched.exists(),
        "the refusal must happen BEFORE any fetch is attempted"
    );
    assert!(
        stderr.contains("cannot enforce HTTPS") && stderr.contains("install curl"),
        "the error must say why and name the remedy, stderr: {stderr}"
    );
    assert!(!dest.exists(), "nothing may be downloaded");
}

#[test]
fn curl_is_preferred_over_wget_when_both_exist() {
    // The helper's tool ordering is part of its interface: curl first, wget only as the
    // fallback. With both stubs present, curl must be the one invoked (with its TLS pin), and
    // the wget stub must never run, not even for the --help probe.
    let dir = tempdir::TempDir::new("ib-curl-preferred");
    let curl_log = dir.path().join("curl-argv");
    let wget_log = dir.path().join("wget-invoked");
    write_stub(
        dir.path(),
        "curl",
        &format!(
            "printf '%s\\n' \"$@\" > \"{}\"\nexit 0\n",
            curl_log.display()
        ),
    );
    write_stub(
        dir.path(),
        "wget",
        &format!(
            "printf '%s\\n' \"$@\" > \"{}\"\nexit 0\n",
            wget_log.display()
        ),
    );
    let dest = dir.path().join("dest");
    let (code, stderr) = run_download(dir.path(), "https://example.invalid/asset", &dest);
    assert_eq!(
        code, 0,
        "the stubbed download must succeed, stderr: {stderr}"
    );
    let recorded = std::fs::read_to_string(&curl_log).expect("the curl stub recorded its argv");
    let args: Vec<&str> = recorded.lines().collect();
    assert!(
        args.contains(&"--proto") && args.contains(&"=https") && args.contains(&"--tlsv1.2"),
        "the curl path keeps its TLS pin, argv: {args:?}"
    );
    assert!(
        !wget_log.exists(),
        "wget must not run at all when curl exists"
    );
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
