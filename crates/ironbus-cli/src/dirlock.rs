// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `serve` data-directory lifecycle and the single-broker lock (#89).
//!
//! Two safety features live here, Unix-only (so is `serve`):
//!
//! - [`prepare_data_dir`] is the startup lifecycle: create the data directory (and parents) at
//!   `0700` if it is absent, reject a path that exists but is not a directory, and prove the
//!   directory is WRITABLE with a probe file that is created, fsynced, and removed. A read-only or
//!   unwritable mount is a fatal startup error naming the path, not a silent loss of durability.
//!
//! - [`DirLock`] is the corruption guard: an exclusive OS advisory lock (`flock(LOCK_EX|LOCK_NB)`)
//!   on a `LOCK` file in the data directory. TWO `serve` processes writing the SAME segmented log
//!   would interleave appends and corrupt it; the lock makes the second `serve` FAIL FAST with a
//!   typed error rather than double-open. The lock is held for the lifetime of the [`DirLock`] and
//!   released by `close(2)` on drop (and unconditionally by the kernel on process exit), so a crash
//!   never leaves a stale lock the way a lock FILE's mere existence would.

use std::fmt;
use std::path::{Path, PathBuf};

/// A failure preparing or locking the data directory. Mapped by the caller to the frozen exit-code
/// scheme (a usage problem is exit 1, an IO/runtime fault exit 70); kept a distinct typed error here
/// so the lifecycle has no stringly-typed leakage and the lock-contention case is matchable.
#[derive(Debug)]
pub enum DirError {
    /// The data-dir path exists but is not a directory (e.g. a regular file), so it cannot hold the
    /// segmented log. Names the path. A usage-level misconfiguration.
    NotADirectory(PathBuf),
    /// The data directory could not be created, or is not writable (the probe write/fsync failed).
    /// Names the path and the underlying IO error. A read-only or unwritable mount.
    NotWritable(PathBuf, std::io::Error),
    /// Another `ironbus` broker already holds the exclusive lock on this data directory, so opening
    /// it here would risk concurrent writers to one log. Names the path. Fail fast, never double-open.
    AlreadyLocked(PathBuf),
    /// An IO error acquiring the lock (opening the `LOCK` file, or an unexpected `flock` errno).
    /// Names the path and the underlying error. Distinct from the clean contention case above.
    LockIo(PathBuf, std::io::Error),
}

impl fmt::Display for DirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirError::NotADirectory(p) => {
                write!(f, "data dir {} exists but is not a directory", p.display())
            }
            DirError::NotWritable(p, e) => {
                write!(f, "data dir {} is not writable: {e}", p.display())
            }
            DirError::AlreadyLocked(p) => write!(
                f,
                "another ironbus broker is already running on {} (its data dir is locked)",
                p.display()
            ),
            DirError::LockIo(p, e) => {
                write!(f, "cannot lock data dir {}: {e}", p.display())
            }
        }
    }
}

impl std::error::Error for DirError {}

/// The name of the lock file inside the data directory. It lives alongside the segments and the
/// cursor checkpoints; the storage layer never reads or writes it (segment/checkpoint names are
/// disjoint), so it is inert to the log.
const LOCK_FILE: &str = "LOCK";

/// The mode the data directory is created with when absent: owner-only `rwx` (`0700`), so a freshly
/// provisioned device's queue is not world- or group-readable. An existing directory's mode is left
/// untouched (the operator may have set it deliberately).
const DATA_DIR_MODE: u32 = 0o700;

/// Prepares the `serve` data directory (#89): create it (and parents) at `0700` if absent, reject a
/// non-directory path, and verify it is writable with a probe file that is created, fsynced, and
/// removed. Idempotent: an already-present writable directory passes unchanged.
///
/// # Errors
/// [`DirError::NotADirectory`] if the path exists but is not a directory; [`DirError::NotWritable`]
/// if it cannot be created or the probe write/fsync fails (a read-only or unwritable mount).
pub fn prepare_data_dir(data_dir: &Path) -> Result<(), DirError> {
    match std::fs::symlink_metadata(data_dir) {
        Ok(meta) => {
            // A symlink to a directory still reports `is_dir()` false here (we used `symlink_metadata`
            // to not follow), but the on-disk path resolves through it for the engine, so accept a
            // symlink that ultimately points at a directory and reject only a true non-directory.
            let resolved_is_dir = std::fs::metadata(data_dir).is_ok_and(|m| m.is_dir());
            if !meta.is_dir() && !resolved_is_dir {
                return Err(DirError::NotADirectory(data_dir.to_path_buf()));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => create_data_dir(data_dir)?,
        Err(e) => return Err(DirError::NotWritable(data_dir.to_path_buf(), e)),
    }
    probe_writable(data_dir)
}

/// Creates the data directory and its parents at `0700` (`mkdir -p` semantics with an explicit
/// owner-only mode). A race where another process created it between the existence check and here is
/// benign: a second create on an existing directory is `Ok`.
fn create_data_dir(data_dir: &Path) -> Result<(), DirError> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DATA_DIR_MODE)
        .create(data_dir)
        .map_err(|e| DirError::NotWritable(data_dir.to_path_buf(), e))
}

/// Proves the data directory is writable by creating, fsyncing, and removing a probe file. A
/// read-only mount fails the create or the fsync, surfacing as [`DirError::NotWritable`] BEFORE the
/// broker opens the log (so durability is never silently lost to an unwritable mount). The probe
/// file is `.ironbus-write-probe`; it is removed on success and a best-effort cleanup on failure.
fn probe_writable(data_dir: &Path) -> Result<(), DirError> {
    let probe = data_dir.join(".ironbus-write-probe");
    let map = |e: std::io::Error| DirError::NotWritable(data_dir.to_path_buf(), e);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&probe)
        .map_err(map)?;
    // fsync the probe so a mount that accepts the write into cache but cannot persist it (a failing
    // or read-only-after-mount device) is caught here, not at the first real append.
    let sync = file.sync_all().map_err(map);
    drop(file);
    let _ = std::fs::remove_file(&probe);
    sync
}

/// An exclusive, advisory, whole-file lock on the data directory's `LOCK` file, held for as long as
/// this value lives (#89). Acquired with `flock(LOCK_EX | LOCK_NB)` so a second concurrent `serve`
/// on the same data dir fails fast ([`DirError::AlreadyLocked`]) instead of double-opening the log
/// and corrupting it. Released by `close(2)` when the held file descriptor drops, and unconditionally
/// by the kernel on process exit, so neither a graceful shutdown nor a crash leaves a stale lock.
#[cfg(unix)]
#[derive(Debug)]
pub struct DirLock {
    /// The open `LOCK` file. The advisory lock is bound to this open file description; dropping the
    /// `File` closes the fd and releases the lock. Kept solely to own that lifetime.
    _file: std::fs::File,
}

#[cfg(unix)]
impl DirLock {
    /// Acquires the exclusive lock on `<data_dir>/LOCK`, creating the lock file if absent. Must be
    /// called AFTER [`prepare_data_dir`] (the directory must exist).
    ///
    /// # Errors
    /// [`DirError::AlreadyLocked`] if another process holds the lock (the fail-fast case);
    /// [`DirError::LockIo`] if the lock file cannot be opened or `flock` fails unexpectedly.
    pub fn acquire(data_dir: &Path) -> Result<DirLock, DirError> {
        use std::os::unix::io::AsRawFd;
        let lock_path = data_dir.join(LOCK_FILE);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| DirError::LockIo(data_dir.to_path_buf(), e))?;
        // SAFETY: `flock_ex_nb` is a thin wrapper over the libc `flock(2)` syscall. The fd is valid
        // and open for the duration of the call (we hold the owning `File` in `file`), and `flock`
        // has no other safety precondition: it is a kernel advisory-lock operation that only reads
        // the fd and sets the lock, never touching user memory. We pass `LOCK_EX | LOCK_NB`, so it
        // returns immediately with `EWOULDBLOCK` rather than blocking when the lock is held.
        #[allow(unsafe_code)]
        let rc = unsafe { flock_ex_nb(file.as_raw_fd()) };
        if rc == 0 {
            return Ok(DirLock { _file: file });
        }
        let err = std::io::Error::last_os_error();
        // `EWOULDBLOCK` (== `EAGAIN` on Linux) is the clean "lock already held" signal under
        // `LOCK_NB`: report it as the typed contention error. Any other errno is an unexpected IO
        // fault.
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Err(DirError::AlreadyLocked(data_dir.to_path_buf()))
        } else {
            Err(DirError::LockIo(data_dir.to_path_buf(), err))
        }
    }
}

/// Applies `flock(fd, LOCK_EX | LOCK_NB)`: a non-blocking request for an exclusive advisory lock on
/// the open file description behind `fd`. Returns `0` on success or `-1` (with `errno` set, read by
/// the caller via [`std::io::Error::last_os_error`]) on failure; `EWOULDBLOCK` means the lock is
/// already held by another open file description.
///
/// # Safety
/// `fd` must be a valid, open file descriptor for the duration of the call. The caller (`acquire`)
/// guarantees this by holding the owning [`std::fs::File`]. `flock` reads only the descriptor and
/// the kernel's lock table; it touches no user-supplied memory, so there is no further precondition.
#[cfg(unix)]
#[allow(unsafe_code)]
unsafe fn flock_ex_nb(fd: std::os::unix::io::RawFd) -> i32 {
    libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB)
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    /// A unique scratch directory path under the system temp dir (not created), tagged so parallel
    /// tests never collide. Removed first so a prior run's leftovers do not taint the case.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ironbus-dirlock-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn prepare_creates_a_missing_data_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("missing");
        assert!(!dir.exists());
        prepare_data_dir(&dir).unwrap();
        assert!(dir.is_dir(), "the data dir was created");
        // Created owner-only (0700) on Unix.
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "created 0700, got {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_creates_parents_too() {
        let base = scratch("parents");
        let nested = base.join("a/b/c");
        prepare_data_dir(&nested).unwrap();
        assert!(
            nested.is_dir(),
            "the nested data dir and its parents were created"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn prepare_accepts_an_existing_writable_dir_idempotently() {
        let dir = scratch("existing");
        std::fs::create_dir_all(&dir).unwrap();
        prepare_data_dir(&dir).unwrap();
        prepare_data_dir(&dir).unwrap(); // idempotent
                                         // The probe file must not linger.
        assert!(
            !dir.join(".ironbus-write-probe").exists(),
            "probe cleaned up"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_rejects_a_non_directory_path() {
        let base = scratch("notadir");
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("a-file");
        std::fs::write(&file, b"i am a file").unwrap();
        let e = prepare_data_dir(&file).unwrap_err();
        assert!(
            matches!(e, DirError::NotADirectory(_)),
            "a regular file is not a directory: {e}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn lock_is_acquired_and_a_second_acquire_fails_fast() {
        let dir = scratch("lock");
        prepare_data_dir(&dir).unwrap();
        let first = DirLock::acquire(&dir).unwrap();
        // A SECOND acquire on the same data dir, while the first is held, must fail fast with the
        // contention error, NOT corrupt by double-opening.
        let second = DirLock::acquire(&dir);
        assert!(
            matches!(second, Err(DirError::AlreadyLocked(_))),
            "the second acquire fails fast: {second:?}"
        );
        drop(first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lock_releases_on_drop_so_a_fresh_acquire_succeeds() {
        let dir = scratch("release");
        prepare_data_dir(&dir).unwrap();
        {
            let _held = DirLock::acquire(&dir).unwrap();
            // Held here: a concurrent acquire would fail (covered by the test above).
        } // dropped -> close(2) -> lock released by the OS
          // A fresh acquire after the drop succeeds, proving the lock was released.
        let again = DirLock::acquire(&dir);
        assert!(
            again.is_ok(),
            "a fresh acquire after drop succeeds: {again:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
