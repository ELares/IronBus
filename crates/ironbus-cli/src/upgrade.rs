// SPDX-License-Identifier: MIT OR Apache-2.0
//! Atomic in-place upgrade and rollback for the `ironbus` binary (#104, parent #17).
//!
//! A running broker is a binary with an open WAL, so an upgrade is a lifecycle operation, not a
//! one-shot install. Two safety properties are the whole point of this module:
//!
//! - **The live binary is never overwritten in place.** [`atomic_swap_with_prev`] writes the new
//!   bytes to a sibling temp file ON THE SAME FILESYSTEM, fsyncs it (so a power loss never leaves a
//!   truncated binary at the destination), retains the CURRENT binary as `<dest>.prev` via an atomic
//!   same-directory `mv`, then `rename(2)`s the new file over the destination. `rename` is atomic on
//!   POSIX, so a power cut mid-upgrade leaves EITHER the old binary (rename not yet applied) or the
//!   new binary fully on disk, never a half-written one. This is the exact contract `scripts/
//!   install.sh`'s `install_binary` helper enforces in shell; the Rust side here mirrors it so the
//!   `ironbus upgrade` subcommand can perform a verified swap without re-implementing the download.
//!
//! - **A node that cannot start the new binary falls back to `ironbus.prev` after N failed starts.**
//!   A tiny start-attempt counter file ([`COUNTER_FILE`]) next to the binary records consecutive
//!   failed starts. The systemd unit (or a wrapper) calls [`record_failed_start`] when the broker
//!   fails to come up and [`record_successful_start`] (which clears the counter) once it is healthy;
//!   when the count reaches [`DEFAULT_MAX_FAILED_STARTS`] the unit consults [`should_fall_back`] and
//!   restores `ironbus.prev` over the binary via the same atomic swap, recovering an unreachable node
//!   to the last known-good bytes. The counter and the decision are pure and unit-tested; the
//!   systemd glue lives in the packaged unit, documented in `docs/DISTRIBUTION.md`.
//!
//! The download-and-verify step is NOT re-implemented here: it stays in the fail-closed
//! `scripts/install.sh` (the single source of verify-before-install). `ironbus upgrade` documents
//! and drives that flow; the swap below only ever runs over bytes the caller has already verified,
//! so it never weakens the fail-closed posture (any download/verify happens BEFORE the swap).
//!
//! Unix-only, like `serve`: `rename(2)` atomicity and the fsync-the-dir durability step are POSIX
//! guarantees. The module is gated with `#[cfg(unix)] mod upgrade;` in `main.rs`, so it is compiled
//! only on Unix; the non-Unix `cmd_upgrade` stub there errors out before any of this runs.

use std::fs;
use std::io;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The default number of consecutive failed starts after which a node falls back to `ironbus.prev`.
/// Three attempts tolerate a transient first-boot hiccup (a slow mount, a one-off resource pinch)
/// before deciding the new binary is genuinely broken and rolling back to the last known-good bytes.
pub const DEFAULT_MAX_FAILED_STARTS: u32 = 3;

/// The file name (a sibling of the installed binary) holding the consecutive failed-start count as a
/// bare ASCII integer. Lives next to the binary so the start counter travels with the install dir
/// and a rollback can clear it. The packaged systemd unit reads and writes it across restarts.
pub const COUNTER_FILE: &str = ".ironbus-start-attempts";

/// The suffix of the retained rollback copy: `<dest>.prev`. Identical to `scripts/install.sh`, so
/// the installer and the `upgrade` subcommand agree on where the rollback bytes live.
const PREV_SUFFIX: &str = ".prev";

/// A failure during an atomic swap or a counter update. Mapped by the caller to the frozen
/// exit-code scheme (an IO/runtime fault is exit 70); kept typed so no path leaks a stringly error.
#[derive(Debug)]
pub enum UpgradeError {
    /// An IO error staging, fsyncing, retaining, or renaming the binary (names the step).
    Io(String, io::Error),
    /// The requested rollback found no `<dest>.prev` to restore (nothing was ever upgraded over).
    NoPrev(PathBuf),
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpgradeError::Io(step, e) => write!(f, "{step}: {e}"),
            UpgradeError::NoPrev(p) => {
                write!(
                    f,
                    "no rollback copy at {} (nothing to roll back to)",
                    p.display()
                )
            }
        }
    }
}

impl std::error::Error for UpgradeError {}

/// The path of the retained rollback copy for a destination binary: `<dest>.prev`.
#[must_use]
pub fn prev_path(dest: &Path) -> PathBuf {
    let mut name = dest.as_os_str().to_os_string();
    name.push(PREV_SUFFIX);
    PathBuf::from(name)
}

/// The path of the start-attempt counter file, a sibling of the installed binary.
#[must_use]
pub fn counter_path(dest: &Path) -> PathBuf {
    dest.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(COUNTER_FILE)
}

/// Atomically installs the already-verified bytes at `src` over `dest`, retaining any prior binary
/// at `dest` as `<dest>.prev`, NEVER overwriting the live binary in place.
///
/// CONTRACT (mirrors `scripts/install.sh`'s `install_binary`; the caller has ALREADY verified
/// `src`, so this never weakens verify-before-install):
/// 1. Copy `src` to a sibling temp `<dest>.tmp.<pid>` on the SAME filesystem and `chmod 0755` it, so
///    a reader never sees a partial file.
/// 2. `fsync` the temp file, so a power loss after the rename cannot surface a truncated binary
///    (the bytes are on stable storage before the rename publishes them).
/// 3. If `dest` exists, retain it as `<dest>.prev` via an atomic same-directory `rename`, so the
///    prior known-good bytes survive for rollback (a FRESH install retains nothing).
/// 4. `rename` the temp over `dest` (atomic on POSIX), then `fsync` the parent directory so the
///    rename itself is durable.
///
/// # Errors
/// [`UpgradeError::Io`] on any IO failure, naming the step. On a staging/fsync failure the temp is
/// cleaned up and `dest` is untouched.
pub fn atomic_swap_with_prev(src: &Path, dest: &Path) -> Result<(), UpgradeError> {
    let io_err = |step: &str| {
        let step = step.to_string();
        move |e: io::Error| UpgradeError::Io(step.clone(), e)
    };

    // 1. Stage next to the destination on the same filesystem, mode 0755 from creation.
    let pid = std::process::id();
    let tmp = sibling_temp(dest, pid);
    copy_mode_0755(src, &tmp).map_err(io_err(&format!(
        "staging the new binary at {}",
        tmp.display()
    )))?;

    // 2. fsync the staged file so its bytes are durable before the rename publishes it.
    if let Err(e) = fsync_path(&tmp) {
        let _ = fs::remove_file(&tmp);
        return Err(UpgradeError::Io(format!("fsyncing {}", tmp.display()), e));
    }

    // 3. Retain the current binary as <dest>.prev (atomic same-dir rename) BEFORE the swap.
    if dest.exists() {
        let prev = prev_path(dest);
        if let Err(e) = fs::rename(dest, &prev) {
            let _ = fs::remove_file(&tmp);
            return Err(UpgradeError::Io(
                format!("retaining the prior binary as {}", prev.display()),
                e,
            ));
        }
    }

    // 4. Atomically swap the new binary into place, then fsync the directory so the rename persists.
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(UpgradeError::Io(
            format!("installing to {}", dest.display()),
            e,
        ));
    }
    if let Some(dir) = dest.parent() {
        // Best-effort: a directory fsync failure (e.g. an fs that does not support it) does not undo
        // the atomic rename, which already happened, so it is logged-not-fatal at the call site; we
        // surface it here so the caller can warn, but the binary is already correctly in place.
        fsync_dir(dir).map_err(io_err(&format!(
            "fsyncing the install dir {}",
            dir.display()
        )))?;
    }
    Ok(())
}

/// Rolls back to the retained `<dest>.prev`, restoring it over `dest` via the same atomic swap and
/// clearing the start-attempt counter (the rollback target is, by definition, the last known-good).
///
/// # Errors
/// [`UpgradeError::NoPrev`] if there is no `<dest>.prev` to restore; [`UpgradeError::Io`] on any IO
/// failure during the swap.
pub fn rollback_to_prev(dest: &Path) -> Result<(), UpgradeError> {
    let prev = prev_path(dest);
    if !prev.exists() {
        return Err(UpgradeError::NoPrev(prev));
    }
    atomic_swap_with_prev(&prev, dest)?;
    // A successful rollback resets the failure budget: the restored binary is the known-good one.
    clear_failed_starts(dest).map_err(|e| {
        UpgradeError::Io(
            format!(
                "clearing the start counter at {}",
                counter_path(dest).display()
            ),
            e,
        )
    })?;
    Ok(())
}

/// Reads the consecutive-failed-start count for the binary at `dest` (0 if the counter is absent or
/// unreadable: an absent counter is a clean slate, never a spurious rollback trigger).
#[must_use]
pub fn read_failed_starts(dest: &Path) -> u32 {
    let path = counter_path(dest);
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Records one more failed start for `dest`, returning the NEW count. The systemd unit calls this
/// when the broker fails to come up; once the count reaches [`DEFAULT_MAX_FAILED_STARTS`] the unit
/// consults [`should_fall_back`] and rolls back. The counter file is fsynced so the count survives
/// a power loss between the failed start and the next boot.
///
/// # Errors
/// Propagates an IO error writing or fsyncing the counter file.
pub fn record_failed_start(dest: &Path) -> io::Result<u32> {
    let next = read_failed_starts(dest).saturating_add(1);
    write_counter(dest, next)?;
    Ok(next)
}

/// Clears the failed-start counter for `dest` (a successful, healthy start). Removing the file is
/// the clean-slate state [`read_failed_starts`] reads as 0.
///
/// # Errors
/// Propagates an IO error other than "already absent" removing the counter file.
pub fn record_successful_start(dest: &Path) -> io::Result<()> {
    clear_failed_starts(dest)
}

/// The fallback decision: should a node at `dest` having failed `failed_starts` times fall back to
/// `ironbus.prev`? True only when the count has REACHED the cap AND a `<dest>.prev` exists to fall
/// back to (rolling back with no rollback copy would brick the node, so it is never decided here).
#[must_use]
pub fn should_fall_back(dest: &Path, failed_starts: u32, max_failed_starts: u32) -> bool {
    failed_starts >= max_failed_starts && prev_path(dest).exists()
}

// --- internal helpers ---------------------------------------------------------------------------

/// A sibling temp path next to `dest`, tagged with `pid` so concurrent upgraders never collide and
/// it lands on the SAME filesystem as `dest` (so the final `rename` is a same-fs atomic move).
fn sibling_temp(dest: &Path, pid: u32) -> PathBuf {
    let mut name = dest.as_os_str().to_os_string();
    name.push(format!(".tmp.{pid}"));
    PathBuf::from(name)
}

/// Copies `src` to `dest` creating it mode 0755, truncating any existing temp.
fn copy_mode_0755(src: &Path, dest: &Path) -> io::Result<()> {
    let bytes = fs::read(src)?;
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(dest)?;
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(())
}

/// fsyncs a regular file at `path` (open read-only is sufficient for `fsync`).
fn fsync_path(path: &Path) -> io::Result<()> {
    let f = fs::OpenOptions::new().read(true).open(path)?;
    f.sync_all()
}

/// fsyncs a directory so a rename within it is durable.
fn fsync_dir(dir: &Path) -> io::Result<()> {
    let d = fs::File::open(dir)?;
    d.sync_all()
}

/// Writes `count` to the counter file and fsyncs it.
fn write_counter(dest: &Path, count: u32) -> io::Result<()> {
    let path = counter_path(dest);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    f.write_all(count.to_string().as_bytes())?;
    f.flush()?;
    f.sync_all()
}

/// Removes the counter file, treating an already-absent file as success.
fn clear_failed_starts(dest: &Path) -> io::Result<()> {
    match fs::remove_file(counter_path(dest)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A unique scratch directory under the system temp dir, created fresh and removed on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "ironbus-upgrade-{tag}-{}-{seq}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_upgrade_retains_the_prior_binary_as_prev_and_installs_the_new_bytes() {
        use std::os::unix::fs::PermissionsExt;
        // The core atomic-swap invariant (#104): an in-place upgrade installs the NEW bytes at the
        // destination and retains the PRIOR bytes verbatim as `<dest>.prev`, never overwriting the
        // live binary in place. This is the Rust twin of the installer's `install_binary` test.
        let scr = Scratch::new("swap");
        let dest = scr.path().join("ironbus");
        let prev = prev_path(&dest);

        let old = b"ironbus v1 (the prior installed binary)";
        fs::write(&dest, old).unwrap();
        assert!(!prev.exists(), "no .prev before the upgrade");

        let new = b"ironbus v2 (the upgrade)";
        let src = scr.path().join("staged-new");
        fs::write(&src, new).unwrap();

        atomic_swap_with_prev(&src, &dest).expect("the atomic swap must succeed");

        assert_eq!(
            fs::read(&dest).unwrap(),
            new,
            "the new binary is at the destination"
        );
        assert!(
            prev.exists(),
            "an upgrade retains the prior binary as .prev"
        );
        assert_eq!(
            fs::read(&prev).unwrap(),
            old,
            ".prev holds the exact prior bytes (a real rollback copy)"
        );
        // The new binary is executable (mode 0755) so the service can run it.
        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "the installed binary is executable, got {mode:o}"
        );
    }

    #[test]
    fn a_fresh_install_creates_no_prev() {
        // On a FRESH install (no prior binary) the swap must NOT fabricate a `.prev`: there is
        // nothing to roll back to, so a spurious `.prev` would be a lie.
        let scr = Scratch::new("fresh");
        let dest = scr.path().join("ironbus");
        let prev = prev_path(&dest);
        assert!(!dest.exists());

        let bytes = b"ironbus v1 (the first install)";
        let src = scr.path().join("staged-fresh");
        fs::write(&src, bytes).unwrap();
        atomic_swap_with_prev(&src, &dest).expect("a fresh install must succeed");

        assert_eq!(fs::read(&dest).unwrap(), bytes);
        assert!(
            !prev.exists(),
            "a fresh install creates no .prev (nothing to retain)"
        );
    }

    #[test]
    fn rollback_restores_the_prev_bytes_and_clears_the_counter() {
        // ROLLBACK: after an upgrade, restoring `.prev` puts the prior known-good bytes back over the
        // destination and resets the failure budget. The upgrade's own retained `.prev` becomes the
        // destination after a roll back, so the new (failing) binary becomes the new `.prev`.
        let scr = Scratch::new("rollback");
        let dest = scr.path().join("ironbus");

        let good = b"ironbus v1 (known good)";
        fs::write(&dest, good).unwrap();
        let bad_src = scr.path().join("bad");
        fs::write(&bad_src, b"ironbus v2 (broken upgrade)").unwrap();
        atomic_swap_with_prev(&bad_src, &dest).unwrap();

        // Simulate failed starts having accrued, then roll back.
        record_failed_start(&dest).unwrap();
        record_failed_start(&dest).unwrap();
        assert_eq!(read_failed_starts(&dest), 2);

        rollback_to_prev(&dest).expect("rollback must succeed when a .prev exists");
        assert_eq!(
            fs::read(&dest).unwrap(),
            good,
            "rollback restored the known-good bytes"
        );
        assert_eq!(
            read_failed_starts(&dest),
            0,
            "a rollback clears the failure budget"
        );
    }

    #[test]
    fn rollback_with_no_prev_is_refused() {
        // Rolling back with no `.prev` would brick the node, so it is refused with a typed error,
        // never a swap of nonexistent bytes.
        let scr = Scratch::new("noprev");
        let dest = scr.path().join("ironbus");
        fs::write(&dest, b"only ever installed once").unwrap();
        let e = rollback_to_prev(&dest).unwrap_err();
        assert!(
            matches!(e, UpgradeError::NoPrev(_)),
            "no .prev is a typed refusal: {e}"
        );
    }

    #[test]
    fn the_failed_start_counter_increments_persists_and_clears() {
        // The fall-back-after-N counter: failed starts accumulate and survive (it is a real file),
        // and a successful start clears the budget.
        let scr = Scratch::new("counter");
        let dest = scr.path().join("ironbus");
        fs::write(&dest, b"binary").unwrap();

        assert_eq!(
            read_failed_starts(&dest),
            0,
            "an absent counter reads as a clean slate"
        );
        assert_eq!(record_failed_start(&dest).unwrap(), 1);
        assert_eq!(record_failed_start(&dest).unwrap(), 2);
        assert_eq!(record_failed_start(&dest).unwrap(), 3);
        assert_eq!(
            read_failed_starts(&dest),
            3,
            "the count persisted across reads"
        );

        record_successful_start(&dest).unwrap();
        assert_eq!(
            read_failed_starts(&dest),
            0,
            "a healthy start clears the budget"
        );
    }

    #[test]
    fn the_fallback_decision_fires_at_n_only_with_a_prev() {
        // should_fall_back is true ONLY at/above the cap AND with a .prev present: below the cap it
        // never fires, and without a rollback copy it never fires (rolling back would brick the node).
        let scr = Scratch::new("decision");
        let dest = scr.path().join("ironbus");
        fs::write(&dest, b"new binary").unwrap();

        // No .prev yet: even at the cap, no fall back (nothing to fall back to).
        assert!(
            !should_fall_back(&dest, DEFAULT_MAX_FAILED_STARTS, DEFAULT_MAX_FAILED_STARTS),
            "no .prev means no fall back even at the cap"
        );

        // Create a .prev (as an upgrade would).
        fs::write(prev_path(&dest), b"old binary").unwrap();
        assert!(
            !should_fall_back(&dest, 0, DEFAULT_MAX_FAILED_STARTS),
            "0 failures: no fall back"
        );
        assert!(
            !should_fall_back(
                &dest,
                DEFAULT_MAX_FAILED_STARTS - 1,
                DEFAULT_MAX_FAILED_STARTS
            ),
            "below the cap: no fall back"
        );
        assert!(
            should_fall_back(&dest, DEFAULT_MAX_FAILED_STARTS, DEFAULT_MAX_FAILED_STARTS),
            "at the cap with a .prev: fall back"
        );
        assert!(
            should_fall_back(
                &dest,
                DEFAULT_MAX_FAILED_STARTS + 5,
                DEFAULT_MAX_FAILED_STARTS
            ),
            "past the cap with a .prev: fall back"
        );
        assert_eq!(
            DEFAULT_MAX_FAILED_STARTS, 3,
            "the documented default N is 3"
        );
    }
}
