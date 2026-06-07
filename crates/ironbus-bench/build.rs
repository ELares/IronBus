// SPDX-License-Identifier: MIT OR Apache-2.0
//! Build script: stamp the rustc target triple and the IronBus git SHA into the harness binary so
//! every provenance record can attribute a run to the exact build, with no runtime `git` call.

use std::process::Command;

fn main() {
    // The target triple the harness is built for, recorded verbatim in the provenance host block.
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=IRONBUS_BENCH_TARGET={target}");

    // The git SHA and dirty state at build time. A best-effort `git` invocation: outside a checkout
    // (or with no git) it degrades to "unknown" / clean rather than failing the build.
    let (sha, dirty) = git_sha_and_dirty();
    println!("cargo:rustc-env=IRONBUS_BENCH_GIT_SHA={sha}");
    println!("cargo:rustc-env=IRONBUS_BENCH_GIT_DIRTY={dirty}");

    // Re-run if the HEAD or index moves so the stamped SHA stays current. These paths may not exist
    // (a release tarball build); cargo tolerates a missing rerun-if-changed path.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
}

/// Returns `(short_sha, "true"|"false")`. On any failure returns `("unknown", "false")`.
fn git_sha_and_dirty() -> (String, &'static str) {
    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| !o.stdout.is_empty());

    (sha, if dirty { "true" } else { "false" })
}
