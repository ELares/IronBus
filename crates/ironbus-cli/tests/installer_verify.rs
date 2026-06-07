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

/// Build a fixture: write `ironbus-<target>` with `payload`, and a `SHA256SUMS` over it (plus a
/// second, unrelated asset entry so the "select the right line" path is exercised).
fn fixture(payload: &[u8]) -> Fixture {
    let dir = tempdir::TempDir::new("ib-installer");
    let asset = "ironbus-x86_64-unknown-linux-musl".to_string();
    std::fs::write(dir.path().join(&asset), payload).unwrap();

    let other = b"a different architecture's bytes";
    std::fs::write(dir.path().join("ironbus-aarch64-unknown-linux-musl"), other).unwrap();

    let mut sums = String::new();
    sums.push_str(&sums_line(other, "ironbus-aarch64-unknown-linux-musl"));
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
    std::fs::write(
        fx.dir().join("ironbus-armv7-unknown-linux-musleabihf"),
        payload,
    )
    .unwrap();
    let code = run_verify(
        fx.dir(),
        "ironbus-armv7-unknown-linux-musleabihf",
        "ironbus-armv7-unknown-linux-musleabihf",
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

/// A minimal, dependency-free temp-dir module (the workspace forbids adding new crates casually,
/// so the test brings its own RAII temp dir under the system temp root).
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);
    impl TempDir {
        pub fn new(prefix: &str) -> Self {
            let base = std::env::temp_dir();
            let p = base.join(format!(
                "{prefix}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).expect("create temp dir");
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
