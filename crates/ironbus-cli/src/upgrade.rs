// SPDX-License-Identifier: MIT OR Apache-2.0
//! Atomic in-place upgrade and rollback for the `ironbus` binary (#104, parent #17).
//!
//! A running broker is a binary with an open WAL, so an upgrade is a lifecycle operation, not a
//! one-shot install. Two safety properties are the whole point of this module:
//!
//! - **The live binary is never overwritten in place, and no failure path can strand the host
//!   without it (#421).** [`atomic_swap_with_prev`] writes the new bytes to a sibling temp file ON
//!   THE SAME FILESYSTEM and fsyncs it (so a power loss never leaves a truncated binary at the
//!   destination), stages a COPY of the CURRENT binary to a second sibling temp (also fsynced; the
//!   live binary is never moved), performs the SINGLE atomic `rename(2)` of the new bytes over the
//!   destination, and only THEN commits the staged copy onto `<dest>.prev`. `rename` is atomic on
//!   POSIX, so a power cut mid-upgrade leaves EITHER the old binary (rename not yet applied) or the
//!   new binary fully on disk, never a half-written one. A FAILED final rename leaves the
//!   destination AND any pre-existing `<dest>.prev` exactly as they were (only the two temps are
//!   removed). DELIBERATE TRADE: a crash between the swap and the `.prev` commit leaves `.prev`
//!   one version stale, an OLDER known-good binary, which is safer than committing first and
//!   leaving `.prev` byte-identical to the possibly-bad binary just installed. A SAME-VERSION
//!   re-run (the destination already holds exactly the new bytes) is a no-op that touches neither
//!   the destination nor `.prev` (#422). These are the same swap semantics `scripts/install.sh`'s
//!   `install_binary` helper enforces in shell, so the `ironbus upgrade` subcommand can perform a
//!   verified swap without re-implementing the download; POSIX sh cannot portably fsync, though,
//!   so this Rust verb is the durably-synced path of the pair.
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
//! ## Re-entry hardening against the two-rename window (#348, a #104 follow-up)
//!
//! A generic [`atomic_swap_with_prev`] does a two-rename swap (retain `dest` as `<dest>.prev`, then
//! rename the new bytes over `dest`) and the original rollback reused it. That has a sub-microsecond
//! window: between the two `rename(2)`s `<dest>.prev` holds the bytes that were AT `dest` (the bad,
//! just-failed binary), and `dest` is momentarily absent. If power is lost there (or after the swap
//! but before the counter clear), a re-entered `record-start --check` could re-fire the rollback and
//! PROMOTE the known-bad bytes that now sit in `.prev`. Two changes close that window so a re-entry
//! deterministically converges to the GOOD binary instead of re-applying a half-done rollback:
//!
//! - **A rollback swap that never destroys the good `.prev`.** [`rollback_to_prev`] no longer reuses
//!   the generic retain-then-swap; it uses [`restore_prev_over_dest`], which stages the `.prev` bytes
//!   to a sibling temp, fsyncs, then renames the temp OVER `dest` directly (and fsyncs the dir),
//!   WITHOUT first moving `dest` onto `.prev`. So `.prev` (the last known-good bytes) is preserved
//!   for the whole rollback: a crash at any single point leaves `dest` holding either the bad bytes
//!   (rename not yet applied) or the good bytes (applied), with `.prev` ALWAYS still good, so a
//!   re-entered rollback repeats safely and converges to the good binary.
//! - **A durable known-bad content guard recorded with the counter.** When the failed-start count
//!   reaches the fall-back cap, [`record_failed_start`] also records the content fingerprint of the
//!   binary that is failing (a `crc32c` + byte-length identity, fsynced via the atomic write-temp +
//!   rename + dir-fsync discipline). [`rollback_to_prev`] REFUSES to promote `<dest>.prev` if its
//!   fingerprint matches that recorded known-bad fingerprint, so even a pathological state in which
//!   `.prev` somehow holds the just-failed bytes can never promote them. The guard is cleared (also
//!   durably) only AFTER a rollback has restored the bytes and reset the counter, so a crash between
//!   the swap and the counter clear leaves the guard in place and the re-entry stays deterministic.
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

/// The file name (a sibling of the installed binary) holding the content fingerprint of the binary
/// that reached the fall-back cap: the durable known-bad guard (#348). It is written (fsynced) when
/// the counter reaches the cap and cleared (fsynced) only after a rollback restores the bytes and
/// resets the counter, so a re-entered rollback after a crash in the two-rename window can never
/// PROMOTE the known-bad bytes. Its presence is harmless if absent (no guard = nothing refused).
pub const FAILED_FINGERPRINT_FILE: &str = ".ironbus-failed-fingerprint";

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
    /// The rollback target `<dest>.prev` holds the bytes recorded as known-bad (the binary that just
    /// failed N starts), so promoting it is REFUSED (#348). This only arises from a re-entry after a
    /// crash in the two-rename window; promoting the known-bad bytes is the exact hazard the guard
    /// closes. The `dest` already holds the bytes the prior rollback restored, so the node is not
    /// bricked; this refusal just prevents re-applying a half-done rollback onto the bad binary.
    PrevIsKnownBad(PathBuf),
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
            UpgradeError::PrevIsKnownBad(p) => {
                write!(
                    f,
                    "refusing to promote {}: it holds the bytes recorded as known-bad (the binary \
                     that failed N starts); a rollback was already applied, so this re-entry is a \
                     no-op rather than promoting the known-bad binary",
                    p.display()
                )
            }
        }
    }
}

impl std::error::Error for UpgradeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UpgradeError::Io(_, e) => Some(e),
            _ => None,
        }
    }
}

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

/// The path of the known-bad fingerprint guard file, a sibling of the installed binary (#348).
#[must_use]
pub fn failed_fingerprint_path(dest: &Path) -> PathBuf {
    dest.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(FAILED_FINGERPRINT_FILE)
}

/// The outcome of a successful [`atomic_swap_with_prev`]: either the new bytes were installed, or
/// the destination already held exactly those bytes and the swap was a deliberate no-op (#422).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapOutcome {
    /// The staged new bytes were renamed onto the destination (and, on an upgrade, the prior
    /// binary's bytes were committed to `<dest>.prev`).
    Installed,
    /// The destination already held byte-identical content: nothing was changed, and in particular
    /// `<dest>.prev` (the rollback copy) was NOT clobbered with bytes identical to the live binary.
    SkippedSameVersion,
}

/// Atomically installs the already-verified bytes at `src` over `dest`, retaining any prior binary
/// at `dest` as `<dest>.prev`, NEVER overwriting the live binary in place and NEVER letting a
/// failure destroy either the live binary or a pre-existing rollback copy.
///
/// CONTRACT (the same swap semantics as `scripts/install.sh`'s `install_binary`; the caller has
/// ALREADY verified `src`, so this never weakens verify-before-install):
/// 1. SAME-VERSION GUARD (#422): if `dest` exists and its bytes equal `src`'s, return
///    [`SwapOutcome::SkippedSameVersion`] touching NOTHING. Retaining here would overwrite the only
///    rollback copy with bytes identical to the live binary, leaving nothing to roll back to.
/// 2. Copy `src` to a sibling temp `<dest>.tmp.<pid>` on the SAME filesystem and `chmod 0755` it, so
///    a reader never sees a partial file; `fsync` it so a power loss after the rename cannot
///    surface a truncated binary.
/// 3. If `dest` exists, STAGE its bytes to a second sibling temp `<dest>.prev.tmp.<pid>` by COPY
///    (the live binary is never moved) and `fsync` that copy too. `<dest>.prev` is not touched yet.
///    This reads the live binary, so an existing-but-unreadable `dest` fails closed (the older
///    rename-based retention needed no read access). A FRESH install stages nothing.
/// 4. `rename` the new-binary temp over `dest`: the SINGLE operation that changes `dest`, atomic on
///    POSIX. Then `fsync` the parent directory so the rename itself is durable. If the rename
///    fails, both temps are removed and `dest` AND any pre-existing `<dest>.prev` are left exactly
///    as they were.
/// 5. Only THEN commit the staged copy onto `<dest>.prev` (atomic same-directory `rename`), and
///    `fsync` the directory again. DELIBERATE TRADE: a crash between step 4 and step 5 leaves
///    `.prev` one version stale, an OLDER known-good binary, which is safer than committing first
///    and leaving `.prev` byte-identical to the possibly-bad binary just installed.
///
/// The `rollback` side deliberately does NOT reuse this swap: `rollback_to_prev` must never move
/// the live binary onto `.prev` at all (#348), so it uses [`restore_prev_over_dest`].
///
/// # Errors
/// [`UpgradeError::Io`] on any IO failure, naming the step. No failure path removes `dest` or
/// clobbers a pre-existing `<dest>.prev`; failures before or at the final rename leave the host
/// with the binary (and rollback copy) it already had, and a failure after it (the `.prev` commit
/// or a directory fsync) leaves the new binary correctly installed with the OLD `.prev` retained.
pub fn atomic_swap_with_prev(src: &Path, dest: &Path) -> Result<SwapOutcome, UpgradeError> {
    let io_err = |step: &str| {
        let step = step.to_string();
        move |e: io::Error| UpgradeError::Io(step.clone(), e)
    };

    // 1. SAME-VERSION GUARD (#422): a byte-identical re-run is a no-op that touches nothing, so an
    //    idempotent re-provision can never clobber the rollback copy. Reading either file is
    //    required anyway (src is staged below; dest is read for retention), so a read failure here
    //    is a hard error rather than an ambiguous fall-through.
    if dest.exists() {
        let new_bytes = fs::read(src).map_err(io_err(&format!(
            "reading the new binary at {}",
            src.display()
        )))?;
        let cur_bytes = fs::read(dest).map_err(io_err(&format!(
            "reading the live binary at {} for the same-version comparison",
            dest.display()
        )))?;
        if new_bytes == cur_bytes {
            return Ok(SwapOutcome::SkippedSameVersion);
        }
    }

    // 2. Stage next to the destination on the same filesystem, mode 0755 from creation, and fsync
    //    so the bytes are durable before the rename publishes them.
    let pid = std::process::id();
    let tmp = sibling_temp(dest, pid);
    copy_mode_0755(src, &tmp).map_err(io_err(&format!(
        "staging the new binary at {}",
        tmp.display()
    )))?;
    if let Err(e) = fsync_path(&tmp) {
        let _ = fs::remove_file(&tmp);
        return Err(UpgradeError::Io(format!("fsyncing {}", tmp.display()), e));
    }

    // 3. STAGE the retention copy of the current binary (never moving it), fsynced. `<dest>.prev`
    //    itself is untouched until after the swap succeeds, so a failed swap cannot have replaced a
    //    pre-existing good rollback copy with bytes identical to the live binary.
    let staged_prev = if dest.exists() {
        let prev_tmp = prev_sibling_temp(dest, pid);
        if let Err(e) = copy_mode_0755(dest, &prev_tmp) {
            let _ = fs::remove_file(&tmp);
            let _ = fs::remove_file(&prev_tmp);
            return Err(UpgradeError::Io(
                format!(
                    "staging the prior binary for retention at {}",
                    prev_tmp.display()
                ),
                e,
            ));
        }
        if let Err(e) = fsync_path(&prev_tmp) {
            let _ = fs::remove_file(&tmp);
            let _ = fs::remove_file(&prev_tmp);
            return Err(UpgradeError::Io(
                format!("fsyncing {}", prev_tmp.display()),
                e,
            ));
        }
        Some(prev_tmp)
    } else {
        None
    };

    // 4. Atomically swap the new binary into place: the SINGLE operation that changes `dest`. On
    //    failure, remove both temps; `dest` and any pre-existing `.prev` are exactly as they were.
    if let Err(e) = final_rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        if let Some(prev_tmp) = &staged_prev {
            let _ = fs::remove_file(prev_tmp);
        }
        return Err(UpgradeError::Io(
            format!("installing to {}", dest.display()),
            e,
        ));
    }
    if let Some(dir) = dest.parent() {
        // A directory fsync failure does not undo the atomic rename, which already happened; the
        // new binary is correctly in place. Surface the error (the caller warns), after discarding
        // the uncommitted retention temp so no failure path leaves stray temps behind.
        if let Err(e) = fsync_dir(dir) {
            if let Some(prev_tmp) = &staged_prev {
                let _ = fs::remove_file(prev_tmp);
            }
            return Err(UpgradeError::Io(
                format!("fsyncing the install dir {}", dir.display()),
                e,
            ));
        }
    }

    // 5. COMMIT the retention only now that the new binary is live: one atomic same-directory
    //    rename replaces `.prev` with the staged copy of the just-replaced binary, then the
    //    directory fsync makes the commit durable. A failure here never removes `dest` (the new
    //    binary stands) and never clobbers the old `.prev` (one version stale, an older known-good).
    if let Some(prev_tmp) = staged_prev {
        let prev = prev_path(dest);
        if let Err(e) = fs::rename(&prev_tmp, &prev) {
            let _ = fs::remove_file(&prev_tmp);
            return Err(UpgradeError::Io(
                format!("committing the rollback copy to {}", prev.display()),
                e,
            ));
        }
        if let Some(dir) = dest.parent() {
            fsync_dir(dir).map_err(io_err(&format!(
                "fsyncing the install dir {} after committing the rollback copy",
                dir.display()
            )))?;
        }
    }
    Ok(SwapOutcome::Installed)
}

/// The final `rename(2)` of the staged new binary onto the destination, with a TEST-ONLY failpoint:
/// in a debug build, setting `IRONBUS_TEST_FAIL_FINAL_RENAME` forces the rename to fail WITHOUT
/// touching anything, so the failure-path contract (the destination stays present and a
/// pre-existing `.prev` stays intact) is provable over the real shipped binary in
/// `crates/ironbus-cli/tests/upgrade_migrate.rs`. The failpoint can only force the FAILURE path
/// (fail-closed; never a bogus success) and is compiled out of release builds entirely.
fn final_rename(tmp: &Path, dest: &Path) -> io::Result<()> {
    #[cfg(debug_assertions)]
    if std::env::var_os("IRONBUS_TEST_FAIL_FINAL_RENAME").is_some() {
        return Err(io::Error::other(
            "injected failure (IRONBUS_TEST_FAIL_FINAL_RENAME is set; debug builds only)",
        ));
    }
    fs::rename(tmp, dest)
}

/// Rolls back to the retained `<dest>.prev`, restoring it over `dest` and clearing the start-attempt
/// counter (the rollback target is, by definition, the last known-good).
///
/// Hardened against the two-rename re-entry window (#348):
/// - It uses [`restore_prev_over_dest`], which NEVER moves `dest` onto `.prev`, so the good `.prev`
///   bytes survive a crash at any point and a re-entered rollback converges to the good binary.
/// - It REFUSES to promote `.prev` if `.prev`'s content fingerprint matches the known-bad
///   fingerprint recorded by [`record_failed_start`] at the cap, so a re-entry can never promote the
///   just-failed bytes.
/// - It clears the known-bad guard (durably) only AFTER the swap AND the counter reset, so a crash
///   in between leaves the guard in place and the next `--check` stays deterministic.
///
/// # Errors
/// [`UpgradeError::NoPrev`] if there is no `<dest>.prev` to restore; [`UpgradeError::PrevIsKnownBad`]
/// if `.prev` holds the recorded known-bad bytes; [`UpgradeError::Io`] on any IO failure.
pub fn rollback_to_prev(dest: &Path) -> Result<(), UpgradeError> {
    let prev = prev_path(dest);
    if !prev.exists() {
        return Err(UpgradeError::NoPrev(prev));
    }
    // Content guard: never promote bytes recorded as the binary that just failed N starts. This is
    // the case a power cut in the two-rename window leaves behind (`.prev` momentarily holds the bad
    // dest bytes). The guard is best-effort to READ: an unreadable/absent guard simply does not
    // refuse (a missing guard is "no known-bad recorded"), so it never blocks a legitimate rollback.
    if let Some(bad) = read_failed_fingerprint(dest) {
        let prev_fp = fingerprint_file(&prev).map_err(|e| {
            UpgradeError::Io(
                format!("fingerprinting the rollback copy at {}", prev.display()),
                e,
            )
        })?;
        if prev_fp == bad {
            return Err(UpgradeError::PrevIsKnownBad(prev));
        }
    }
    restore_prev_over_dest(&prev, dest)?;
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
    // Only AFTER the bytes are restored and the counter is reset do we clear the known-bad guard, so
    // a crash before this point keeps the guard for the next deterministic re-entry.
    clear_failed_fingerprint(dest).map_err(|e| {
        UpgradeError::Io(
            format!(
                "clearing the known-bad guard at {}",
                failed_fingerprint_path(dest).display()
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
/// when the broker fails to come up; once the count reaches `max_failed_starts` the unit consults
/// [`should_fall_back`] and rolls back. The counter file is fsynced so the count survives a power
/// loss between the failed start and the next boot.
///
/// When the new count REACHES the cap, this also records the content fingerprint of the binary at
/// `dest` as the known-bad guard (#348), durably (atomic write-temp + fsync + rename + dir-fsync),
/// so a rollback re-entered after a power cut in the two-rename window can refuse to promote those
/// exact bytes. Recording the guard is best-effort: a guard-write IO failure is swallowed (the
/// counter itself is the authority; a missing guard only forgoes the extra refusal), so a failed
/// guard write never turns a normal failed-start record into a hard error.
///
/// # Errors
/// Propagates an IO error writing or fsyncing the counter file.
pub fn record_failed_start(dest: &Path, max_failed_starts: u32) -> io::Result<u32> {
    let next = read_failed_starts(dest).saturating_add(1);
    write_counter(dest, next)?;
    if next >= max_failed_starts {
        // Best-effort: the guard is a defense-in-depth refusal, not the rollback authority.
        if let Ok(fp) = fingerprint_file(dest) {
            let _ = write_failed_fingerprint(dest, &fp);
        }
    }
    Ok(next)
}

/// Clears the failed-start counter for `dest` (a successful, healthy start). Removing the file is
/// the clean-slate state [`read_failed_starts`] reads as 0. Also clears the known-bad guard (#348):
/// a healthy start means the binary at `dest` is good, so any stale known-bad record is obsolete.
///
/// # Errors
/// Propagates an IO error other than "already absent" removing the counter file.
pub fn record_successful_start(dest: &Path) -> io::Result<()> {
    clear_failed_starts(dest)?;
    clear_failed_fingerprint(dest)
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

/// The sibling temp the retention copy is STAGED to (`<dest>.prev.tmp.<pid>`) before it is
/// committed onto `<dest>.prev`; same-directory so the commit rename is a same-fs atomic move.
/// Matches the `${dest}.prev.tmp.$$` name `scripts/install.sh` uses for the same purpose.
fn prev_sibling_temp(dest: &Path, pid: u32) -> PathBuf {
    let mut name = dest.as_os_str().to_os_string();
    name.push(format!("{PREV_SUFFIX}.tmp.{pid}"));
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

/// Restores the `.prev` bytes over `dest` WITHOUT moving `dest` onto `.prev` (#348). Unlike the
/// generic [`atomic_swap_with_prev`] (which retains `dest` as `.prev` BEFORE the swap, destroying the
/// good rollback copy in the two-rename window), this preserves `.prev` for the whole operation:
///
/// 1. Copy `src` (the `.prev` bytes) to a sibling temp on the SAME filesystem, mode 0755.
/// 2. `fsync` the temp so a power loss after the rename cannot surface a truncated binary.
/// 3. `rename` the temp over `dest` (atomic on POSIX), then `fsync` the parent dir so it is durable.
///
/// `.prev` is never touched, so a crash at any point leaves `dest` holding either the prior bytes
/// (rename not yet applied) or the restored good bytes (applied), and `.prev` ALWAYS still good. A
/// re-entered rollback therefore repeats safely and converges to the good binary.
fn restore_prev_over_dest(src: &Path, dest: &Path) -> Result<(), UpgradeError> {
    let io_err = |step: &str| {
        let step = step.to_string();
        move |e: io::Error| UpgradeError::Io(step.clone(), e)
    };

    // 1. Stage the rollback bytes next to the destination on the same filesystem, mode 0755.
    let pid = std::process::id();
    let tmp = sibling_temp(dest, pid);
    copy_mode_0755(src, &tmp).map_err(io_err(&format!(
        "staging the rollback binary at {}",
        tmp.display()
    )))?;

    // 2. fsync the staged file so its bytes are durable before the rename publishes it.
    if let Err(e) = fsync_path(&tmp) {
        let _ = fs::remove_file(&tmp);
        return Err(UpgradeError::Io(format!("fsyncing {}", tmp.display()), e));
    }

    // 3. Atomically swap the rollback bytes into place (NEVER moving dest onto .prev), then fsync the
    //    directory so the rename persists. `.prev` is left intact for a deterministic re-entry.
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(UpgradeError::Io(
            format!("restoring the rollback binary to {}", dest.display()),
            e,
        ));
    }
    if let Some(dir) = dest.parent() {
        fsync_dir(dir).map_err(io_err(&format!(
            "fsyncing the install dir {}",
            dir.display()
        )))?;
    }
    Ok(())
}

/// A content fingerprint of a file: `"<crc32c>-<len>"` (#348). A non-cryptographic content identity,
/// never a security boundary; pairing the crc32c with the byte length makes an accidental collision
/// between two real binaries effectively impossible. Used to record the known-bad binary and to
/// compare a rollback candidate against it.
fn fingerprint_bytes(bytes: &[u8]) -> String {
    let crc = crc32c::crc32c(bytes);
    format!("{crc:08x}-{}", bytes.len())
}

/// Reads a file and returns its [`fingerprint_bytes`].
fn fingerprint_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(fingerprint_bytes(&bytes))
}

/// Writes the known-bad fingerprint `fp` for `dest`, durably (atomic write-temp + fsync + rename +
/// dir-fsync), so the guard survives a power loss and a reader never sees a partial fingerprint.
fn write_failed_fingerprint(dest: &Path, fp: &str) -> io::Result<()> {
    let path = failed_fingerprint_path(dest);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = {
        let mut name = path.as_os_str().to_os_string();
        name.push(format!(".tmp.{}", std::process::id()));
        PathBuf::from(name)
    };
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    f.write_all(fp.as_bytes())?;
    f.flush()?;
    f.sync_all()?;
    drop(f);
    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fsync_dir(dir)
}

/// Reads the recorded known-bad fingerprint for `dest` (`None` if absent or unreadable: a missing
/// guard means "no known-bad recorded", so it never blocks a legitimate rollback).
fn read_failed_fingerprint(dest: &Path) -> Option<String> {
    fs::read_to_string(failed_fingerprint_path(dest))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Removes the known-bad guard file, treating an already-absent file as success.
fn clear_failed_fingerprint(dest: &Path) -> io::Result<()> {
    match fs::remove_file(failed_fingerprint_path(dest)) {
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

        let outcome = atomic_swap_with_prev(&src, &dest).expect("the atomic swap must succeed");
        assert_eq!(
            outcome,
            SwapOutcome::Installed,
            "differing bytes take the real install path"
        );

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
    fn a_same_version_swap_is_a_noop_that_preserves_prev() {
        // SAME-VERSION GUARD (#422), the Rust twin of the installer's: a swap whose new bytes are
        // identical to the live binary's is a no-op SUCCESS that touches NOTHING. In particular it
        // must not overwrite `.prev`: that would replace the only rollback copy with bytes
        // identical to the live binary, so "rollback" would reinstall the very build it is rolling
        // back from.
        let scr = Scratch::new("same-version");
        let dest = scr.path().join("ironbus");
        let prev = prev_path(&dest);
        let v1 = b"ironbus v1 (the rollback copy)";
        let v2 = b"ironbus v2 (the live binary)";
        fs::write(&dest, v2).unwrap();
        fs::write(&prev, v1).unwrap();

        let src = scr.path().join("staged-v2-again");
        fs::write(&src, v2).unwrap();
        let outcome = atomic_swap_with_prev(&src, &dest)
            .expect("a same-version re-run is a no-op SUCCESS, not an error");
        assert_eq!(
            outcome,
            SwapOutcome::SkippedSameVersion,
            "byte-identical bytes are reported as the deliberate skip"
        );
        assert_eq!(fs::read(&dest).unwrap(), v2, "the live binary is unchanged");
        assert_eq!(
            fs::read(&prev).unwrap(),
            v1,
            "a same-version re-run MUST NOT clobber .prev (the only rollback copy)"
        );
    }

    // NOTE: the failed-FINAL-rename path (dest present and a pre-existing `.prev` intact after the
    // failure) is proved over the REAL shipped binary in tests/upgrade_migrate.rs via the
    // debug-only IRONBUS_TEST_FAIL_FINAL_RENAME failpoint, where the env var is set on the child
    // process only (setting it in this multi-threaded unit-test process would be racy).

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
        record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap();
        record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap();
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
        assert_eq!(
            record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap(),
            1
        );
        assert_eq!(
            record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap(),
            2
        );
        assert_eq!(
            record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap(),
            3
        );
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

    // --- #348: two-rename re-entry window hardening -------------------------------------------

    /// Reproduces the EXACT mid-rollback state a power cut in the two-rename window of the ORIGINAL
    /// (generic-swap) rollback would leave: `dest` is absent (it was renamed away to `.prev`), and
    /// `.prev` holds the BAD, just-failed bytes (the bytes that were at `dest`). The good bytes
    /// survive only in `.prev` BEFORE this step in the old shape; here they are lost, exactly the
    /// hazard. A re-entered `--check` would then promote `.prev`'s bad bytes.
    fn simulate_crash_between_renames(dest: &Path, good: &[u8], bad: &[u8]) {
        // The destination currently holds the bad (failing) binary; `.prev` holds the good one.
        fs::write(dest, bad).unwrap();
        fs::write(prev_path(dest), good).unwrap();
        // The original rollback's first rename: dest -> .prev. After this, `.prev` = bad bytes and
        // dest is gone. (The good bytes existed only in a pid-named temp the next boot cannot find.)
        fs::rename(dest, prev_path(dest)).unwrap();
        assert!(!dest.exists(), "the crash left dest absent");
        assert_eq!(
            fs::read(prev_path(dest)).unwrap(),
            bad,
            "the crash left .prev holding the BAD bytes (the two-rename hazard)"
        );
    }

    #[test]
    fn a_power_cut_between_the_renames_never_promotes_the_bad_binary() {
        // #348 TEETH: drive the failed-start counter to the cap (recording the known-bad guard),
        // then reproduce the mid-rollback crash state (dest absent, .prev = bad bytes), then re-enter
        // the rollback as the next boot would. The content guard MUST refuse to promote the known-bad
        // `.prev`, so the bad binary is NEVER promoted to the destination.
        //
        // PROOF OF TEETH: without the guard (the pre-fix shape that reused the generic swap),
        // `rollback_to_prev` here would happily install `.prev`'s BAD bytes at `dest` and return Ok,
        // promoting the known-bad binary. The refusal below is exactly what closes that window.
        let scr = Scratch::new("powercut");
        let dest = scr.path().join("ironbus");
        let good = b"ironbus v1 (known good)";
        let bad = b"ironbus v2 (broken upgrade)";

        // The failing binary is at dest with a good `.prev`; N failed starts record the guard.
        fs::write(&dest, bad).unwrap();
        fs::write(prev_path(&dest), good).unwrap();
        for _ in 0..DEFAULT_MAX_FAILED_STARTS {
            record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap();
        }
        assert_eq!(
            read_failed_fingerprint(&dest).as_deref(),
            Some(fingerprint_bytes(bad).as_str()),
            "reaching the cap records the failing binary's fingerprint as the known-bad guard"
        );

        // A power cut in the two-rename window leaves dest absent and `.prev` holding the bad bytes.
        simulate_crash_between_renames(&dest, good, bad);

        // Re-enter the rollback as the next boot's --check would. The guard REFUSES to promote the
        // known-bad `.prev`, rather than installing the bad bytes at dest.
        let e = rollback_to_prev(&dest).unwrap_err();
        assert!(
            matches!(e, UpgradeError::PrevIsKnownBad(_)),
            "the re-entry must refuse to promote the known-bad .prev, got: {e}"
        );
        // The bad binary was never promoted to the destination (the whole point of the guard).
        assert!(
            !dest.exists() || fs::read(&dest).unwrap() != bad,
            "the known-bad bytes were never promoted to the destination"
        );
        // The guard is still present (a refusing re-entry never clears it), so the refusal is stable
        // across repeated re-entries until a genuine good binary clears it.
        assert!(
            read_failed_fingerprint(&dest).is_some(),
            "a refused re-entry keeps the known-bad guard for the next deterministic re-entry"
        );
    }

    #[test]
    fn the_hardened_rollback_never_destroys_the_good_prev() {
        // The structural half of the fix: a normal rollback restores `.prev` over `dest` WITHOUT
        // moving `dest` onto `.prev`, so the good `.prev` bytes are preserved for a re-entry. This
        // is what makes a crash mid-rollback converge to the good binary instead of losing it.
        let scr = Scratch::new("preserve-prev");
        let dest = scr.path().join("ironbus");
        let good = b"ironbus v1 (known good)";
        let bad = b"ironbus v2 (broken upgrade)";
        fs::write(&dest, bad).unwrap();
        fs::write(prev_path(&dest), good).unwrap();

        restore_prev_over_dest(&prev_path(&dest), &dest).unwrap();

        assert_eq!(
            fs::read(&dest).unwrap(),
            good,
            "the rollback restored the good bytes at the destination"
        );
        assert_eq!(
            fs::read(prev_path(&dest)).unwrap(),
            good,
            "the good .prev is PRESERVED (never overwritten with the bad dest bytes)"
        );
    }

    #[test]
    fn a_crash_during_rollback_then_re_entry_converges_to_the_good_binary() {
        // CRASH-DURING-ROLLBACK: with the hardened swap, a re-entry after a crash before the counter
        // clear still converges to the good binary. Here dest still holds the bad bytes (the rename
        // had not landed when power was cut) and `.prev` is still good. The re-entry must restore the
        // good bytes and clear the counter and the guard.
        let scr = Scratch::new("crash-during");
        let dest = scr.path().join("ironbus");
        let good = b"ironbus v1 (known good)";
        let bad = b"ironbus v2 (broken upgrade)";
        fs::write(&dest, bad).unwrap();
        fs::write(prev_path(&dest), good).unwrap();
        // The counter reached the cap (guard recorded), and a rollback was attempted but power was
        // cut BEFORE the dest rename landed: dest still bad, .prev still good, counter still at N.
        for _ in 0..DEFAULT_MAX_FAILED_STARTS {
            record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap();
        }
        assert_eq!(read_failed_starts(&dest), DEFAULT_MAX_FAILED_STARTS);

        // Re-enter: `.prev` (good) does NOT match the known-bad guard, so the rollback proceeds.
        rollback_to_prev(&dest)
            .expect("the re-entry must complete the rollback to the good binary");
        assert_eq!(
            fs::read(&dest).unwrap(),
            good,
            "the re-entry converged the destination to the good binary"
        );
        assert_eq!(
            read_failed_starts(&dest),
            0,
            "the completed rollback reset the failure budget"
        );
        assert!(
            read_failed_fingerprint(&dest).is_none(),
            "a completed rollback clears the known-bad guard"
        );
    }

    #[test]
    fn a_healthy_start_clears_the_known_bad_guard() {
        // A genuine successful start means the binary at dest is good, so any stale known-bad guard
        // is obsolete and must be cleared (otherwise a later legitimate rollback to those bytes,
        // were they to become good-again `.prev`, could be wrongly refused).
        let scr = Scratch::new("ok-clears-guard");
        let dest = scr.path().join("ironbus");
        fs::write(&dest, b"binary").unwrap();
        for _ in 0..DEFAULT_MAX_FAILED_STARTS {
            record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap();
        }
        assert!(
            read_failed_fingerprint(&dest).is_some(),
            "guard recorded at the cap"
        );

        record_successful_start(&dest).unwrap();
        assert!(
            read_failed_fingerprint(&dest).is_none(),
            "a healthy start clears the known-bad guard"
        );
        assert_eq!(read_failed_starts(&dest), 0, "and the counter");
    }

    #[test]
    fn the_guard_is_only_recorded_at_the_cap_not_below() {
        // Below the cap, no known-bad guard is written: only reaching N records the failing binary,
        // so a transient single failure of a healthy binary never arms the refusal.
        let scr = Scratch::new("guard-at-cap");
        let dest = scr.path().join("ironbus");
        fs::write(&dest, b"binary").unwrap();
        record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap();
        record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap();
        assert!(
            read_failed_fingerprint(&dest).is_none(),
            "below the cap there is no known-bad guard"
        );
        record_failed_start(&dest, DEFAULT_MAX_FAILED_STARTS).unwrap();
        assert!(
            read_failed_fingerprint(&dest).is_some(),
            "the guard is recorded exactly when the count reaches the cap"
        );
    }

    #[test]
    fn the_content_fingerprint_distinguishes_distinct_binaries() {
        // The guard's identity must distinguish a good binary from a bad one (same fingerprint for
        // identical bytes, different for different bytes), so it never confuses the two.
        assert_eq!(
            fingerprint_bytes(b"ironbus good"),
            fingerprint_bytes(b"ironbus good"),
            "identical bytes have an identical fingerprint"
        );
        assert_ne!(
            fingerprint_bytes(b"ironbus good"),
            fingerprint_bytes(b"ironbus bad"),
            "distinct bytes have distinct fingerprints"
        );
    }
}
