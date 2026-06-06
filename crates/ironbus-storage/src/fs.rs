// SPDX-License-Identifier: MIT OR Apache-2.0
//! The data-directory seam for IronBus storage.
//!
//! A queue's on-disk state is one directory of self-describing segment files. Storage
//! manages that directory through the [`Filesystem`] seam rather than calling the OS
//! directly, so the deterministic simulation can substitute an in-memory directory it
//! fully controls, including directory-entry durability across a simulated power loss
//! (a created-but-not-dir-synced segment vanishes; a not-yet-durable removal is undone).

use crate::io::{InMemoryFile, RandomAccessFile};
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[cfg(unix)]
use crate::io::{sync_dir, StdFile};

/// A flat directory of named files: the seam through which the storage engine
/// creates, opens, lists, and removes the segment files of one data directory.
///
/// Names are single path components (a segment file name), never nested paths:
/// IronBus lays one logical topic out as one flat directory of files. Every method
/// takes `&self` so the directory can be shared; the one-writer-per-file rule is
/// enforced by the layers above, exactly as for [`RandomAccessFile`].
pub trait Filesystem: Send + Sync {
    /// The file handle this filesystem hands out.
    type File: RandomAccessFile;

    /// Opens an existing file for reading and writing.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::NotFound`] if the file does not exist, or an IO error.
    fn open(&self, name: &str) -> io::Result<Self::File>;

    /// Creates a new file for reading and writing, failing with
    /// [`io::ErrorKind::AlreadyExists`] if a file of that name already exists. This is
    /// the safe primitive for creating a durable segment: it can never clobber one.
    ///
    /// # Errors
    /// Returns `AlreadyExists` if the name is taken, or an IO error.
    fn create_new(&self, name: &str) -> io::Result<Self::File>;

    /// Removes a file by name.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::NotFound`] if the file does not exist, or an IO error.
    fn remove(&self, name: &str) -> io::Result<()>;

    /// Lists the names of the regular files in the directory, in sorted order.
    ///
    /// Only regular files are reported (not subdirectories), and every returned name
    /// can be passed to [`Filesystem::open`]. The order is deterministic across
    /// backends so recovery never depends on raw directory order.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn list(&self) -> io::Result<Vec<String>>;

    /// Reports whether a regular file of this name exists (consistent with
    /// [`Filesystem::list`], which reports only regular files).
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn exists(&self, name: &str) -> io::Result<bool>;

    /// Fsyncs the directory so a create or remove is crash-durable. Per the
    /// segment-create ordering, call this AFTER the new file's own `sync_all`, so the
    /// sequence is fsync-the-file, then full-fsync-the-parent-directory, then ack.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn sync_dir(&self) -> io::Result<()>;
}

#[derive(Debug, Default)]
struct DirState {
    /// The current directory entries.
    live: BTreeMap<String, Arc<InMemoryFile>>,
    /// The entries as of the last `sync_dir`: the only entries that survive a power
    /// loss. An entry created but not dir-synced vanishes; a removal not dir-synced is
    /// undone.
    durable: BTreeMap<String, Arc<InMemoryFile>>,
}

/// An in-memory [`Filesystem`] for tests and the deterministic simulation.
///
/// It models directory-entry durability the way a real filesystem does: a created or
/// removed entry becomes durable only at [`Filesystem::sync_dir`], and
/// [`InMemoryFs::simulate_power_loss`] reverts the directory to its last-synced entry
/// set and reverts every surviving file to its own last-synced content. With this the
/// simulation can prove recovery never resurrects a half-created segment and never
/// loses a durably created one.
#[derive(Clone, Debug, Default)]
pub struct InMemoryFs {
    /// Shared behind an `Arc`, so cloning a handle aliases the SAME disk. A test can keep a
    /// probe handle to drive [`InMemoryFs::simulate_power_loss`] or inspect the durable image
    /// after the fs has been moved into an engine or wrapped in a fault layer.
    state: Arc<Mutex<DirState>>,
}

impl InMemoryFs {
    /// Creates an empty in-memory directory.
    #[must_use]
    pub fn new() -> InMemoryFs {
        InMemoryFs::default()
    }

    // See [`InMemoryFile`]: recovering a poisoned guard keeps the simulation process
    // alive, and the only mutations here are map and `Arc` operations that never leave
    // the state structurally torn.
    fn lock(&self) -> MutexGuard<'_, DirState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Discards every directory change since the last `sync_dir` and reverts each
    /// surviving file to its last-synced content, modelling a power loss.
    pub fn simulate_power_loss(&self) {
        let mut g = self.lock();
        g.live = g.durable.clone();
        for f in g.live.values() {
            f.simulate_power_loss();
        }
    }
}

impl Filesystem for InMemoryFs {
    type File = Arc<InMemoryFile>;

    fn open(&self, name: &str) -> io::Result<Self::File> {
        self.lock()
            .live
            .get(name)
            .map(Arc::clone)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file"))
    }

    fn create_new(&self, name: &str) -> io::Result<Self::File> {
        let mut g = self.lock();
        if g.live.contains_key(name) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "file already exists",
            ));
        }
        let file = Arc::new(InMemoryFile::new());
        g.live.insert(name.to_owned(), Arc::clone(&file));
        Ok(file)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        if self.lock().live.remove(name).is_some() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "no such file"))
        }
    }

    fn list(&self) -> io::Result<Vec<String>> {
        Ok(self.lock().live.keys().cloned().collect())
    }

    fn exists(&self, name: &str) -> io::Result<bool> {
        Ok(self.lock().live.contains_key(name))
    }

    fn sync_dir(&self) -> io::Result<()> {
        let mut g = self.lock();
        g.durable = g.live.clone();
        Ok(())
    }
}

/// A production [`Filesystem`] rooted at a real data directory, using positioned IO
/// for each file (Unix targets; Windows is a v1 non-goal, see [`StdFile`]).
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct StdFs {
    root: std::path::PathBuf,
}

#[cfg(unix)]
impl StdFs {
    /// Roots a filesystem at `root`. The directory itself must already exist.
    #[must_use]
    pub fn new(root: std::path::PathBuf) -> StdFs {
        StdFs { root }
    }

    /// Resolves `name` to a path inside the data directory, rejecting anything that is
    /// not a single, safe path component so a segment name can never escape the root.
    fn resolve(&self, name: &str) -> io::Result<std::path::PathBuf> {
        // A backslash is a legal byte in a Unix filename, so it is NOT rejected here:
        // rejecting it would make `list` (which does not filter it) return names this
        // `resolve` then refuses, an asymmetry the recovery walk would trip over. The
        // checks below are exactly what keeps a name from escaping the data directory.
        let is_plain = !name.is_empty()
            && name != "."
            && name != ".."
            && !name.contains('/')
            && !name.contains('\0');
        if !is_plain {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file name must be a single path component",
            ));
        }
        Ok(self.root.join(name))
    }
}

#[cfg(unix)]
impl Filesystem for StdFs {
    type File = StdFile;

    fn open(&self, name: &str) -> io::Result<StdFile> {
        StdFile::open(&self.resolve(name)?)
    }

    fn create_new(&self, name: &str) -> io::Result<StdFile> {
        StdFile::create_new(&self.resolve(name)?)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        std::fs::remove_file(self.resolve(name)?)
    }

    fn list(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            // A non-UTF-8 entry cannot be an IronBus segment (segment names are ASCII),
            // so skip it rather than failing the whole listing on one foreign file.
            // Everything returned is therefore a regular file that `open` can resolve.
            if let Ok(name) = entry.file_name().into_string() {
                names.push(name);
            }
        }
        // Sorted, so `list` is deterministic across backends (an in-memory `BTreeMap`
        // is already sorted); recovery must not depend on raw `read_dir` order.
        names.sort();
        Ok(names)
    }

    fn exists(&self, name: &str) -> io::Result<bool> {
        // Match `list`: report true only for a regular file (not a directory or a
        // dangling symlink), so the two backends answer `exists` identically.
        match std::fs::symlink_metadata(self.resolve(name)?) {
            Ok(meta) => Ok(meta.is_file()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn sync_dir(&self) -> io::Result<()> {
        sync_dir(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_all(f: &Arc<InMemoryFile>, bytes: &[u8]) {
        f.write_all_at(bytes, 0).unwrap();
    }

    #[test]
    fn a_clone_aliases_the_same_disk() {
        let fs = InMemoryFs::new();
        let probe = fs.clone();
        // A file created and synced through one handle is visible on the clone, durably.
        let f = fs.create_new("seg").unwrap();
        write_all(&f, b"hello");
        f.sync_data().unwrap();
        fs.sync_dir().unwrap();
        assert!(probe.exists("seg").unwrap());
        // A power loss driven through the clone reverts the other handle's view too: the
        // synced bytes survive, an unsynced overwrite does not.
        f.write_all_at(b"WORLD", 0).unwrap(); // unsynced
        probe.simulate_power_loss();
        let mut buf = [0u8; 5];
        fs.open("seg").unwrap().read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(
            &buf, b"hello",
            "the unsynced overwrite was reverted on both handles"
        );
    }

    #[test]
    fn create_open_list_roundtrip() {
        let fs = InMemoryFs::new();
        let a = fs.create_new("a.log").unwrap();
        write_all(&a, b"alpha");
        fs.create_new("b.log").unwrap();
        let mut names = fs.list().unwrap();
        names.sort();
        assert_eq!(names, vec!["a.log".to_owned(), "b.log".to_owned()]);
        // Opening returns a handle to the same bytes.
        let again = fs.open("a.log").unwrap();
        let mut buf = [0u8; 5];
        again.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"alpha");
    }

    #[test]
    fn create_new_refuses_existing_and_open_missing_errors() {
        let fs = InMemoryFs::new();
        fs.create_new("x").unwrap();
        assert_eq!(
            fs.create_new("x").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs.open("nope").unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn remove_then_absent() {
        let fs = InMemoryFs::new();
        fs.create_new("gone").unwrap();
        assert!(fs.exists("gone").unwrap());
        fs.remove("gone").unwrap();
        assert!(!fs.exists("gone").unwrap());
        assert_eq!(
            fs.remove("gone").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn power_loss_drops_a_file_created_without_a_dir_sync() {
        let fs = InMemoryFs::new();
        let f = fs.create_new("fresh").unwrap();
        write_all(&f, b"data");
        f.sync_data().unwrap(); // the file's bytes are durable...
                                // ...but the directory entry was never synced.
        fs.simulate_power_loss();
        assert!(!fs.exists("fresh").unwrap());
        assert!(fs.list().unwrap().is_empty());
    }

    #[test]
    fn power_loss_keeps_a_dir_synced_file_with_its_synced_content() {
        let fs = InMemoryFs::new();
        let f = fs.create_new("kept").unwrap();
        write_all(&f, b"durable");
        f.sync_data().unwrap();
        fs.sync_dir().unwrap();
        // A further write that is not file-synced is lost; the file itself survives.
        f.write_all_at(b"!!!", 7).unwrap();
        fs.simulate_power_loss();
        assert!(fs.exists("kept").unwrap());
        let g = fs.open("kept").unwrap();
        let mut buf = [0u8; 7];
        g.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"durable");
        assert_eq!(g.len().unwrap(), 7);
    }

    #[test]
    fn power_loss_undoes_a_removal_that_was_not_dir_synced() {
        let fs = InMemoryFs::new();
        let f = fs.create_new("seg").unwrap();
        write_all(&f, b"body");
        f.sync_data().unwrap();
        fs.sync_dir().unwrap();
        // Remove but do not sync the directory: the unlink is not yet durable.
        fs.remove("seg").unwrap();
        assert!(!fs.exists("seg").unwrap());
        fs.simulate_power_loss();
        assert!(fs.exists("seg").unwrap());
        let g = fs.open("seg").unwrap();
        let mut buf = [0u8; 4];
        g.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"body");
    }

    #[test]
    fn power_loss_keeps_a_removal_that_was_dir_synced() {
        let fs = InMemoryFs::new();
        fs.create_new("seg").unwrap();
        fs.sync_dir().unwrap();
        fs.remove("seg").unwrap();
        fs.sync_dir().unwrap();
        fs.simulate_power_loss();
        assert!(!fs.exists("seg").unwrap());
    }

    #[test]
    fn power_loss_after_remove_and_recreate_same_name_restores_original_inode() {
        // The durable directory keeps the ORIGINAL file object when a name is removed
        // and recreated before a dir-sync, so power loss restores the original inode's
        // content, not the replacement's. This pins that load-bearing Arc-identity
        // behavior: a future change that deep-copied content or reused the Arc on
        // recreate would silently break recovery while every other test still passed.
        let fs = InMemoryFs::new();
        let original = fs.create_new("a").unwrap();
        original.write_all_at(b"ORIGINAL", 0).unwrap();
        original.sync_all().unwrap();
        fs.sync_dir().unwrap();

        fs.remove("a").unwrap();
        let replacement = fs.create_new("a").unwrap();
        replacement.write_all_at(b"NEW", 0).unwrap();
        replacement.sync_all().unwrap(); // file-synced, but the directory is not synced

        fs.simulate_power_loss();
        let g = fs.open("a").unwrap();
        let mut buf = [0u8; 8];
        g.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"ORIGINAL");
        assert_eq!(g.len().unwrap(), 8);
    }
}

#[cfg(all(test, unix))]
mod std_tests {
    use super::*;

    #[test]
    fn create_list_open_remove_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFs::new(dir.path().to_path_buf());
        let f = fs.create_new("seg-000001.log").unwrap();
        f.write_all_at(b"hello", 0).unwrap();
        f.sync_all().unwrap();
        fs.sync_dir().unwrap();
        assert_eq!(fs.list().unwrap(), vec!["seg-000001.log".to_owned()]);
        assert!(fs.exists("seg-000001.log").unwrap());
        let g = fs.open("seg-000001.log").unwrap();
        let mut buf = [0u8; 5];
        g.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"hello");
        fs.remove("seg-000001.log").unwrap();
        assert!(fs.list().unwrap().is_empty());
    }

    #[test]
    fn create_new_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFs::new(dir.path().to_path_buf());
        fs.create_new("x").unwrap();
        assert_eq!(
            fs.create_new("x").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn names_must_be_single_components() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFs::new(dir.path().to_path_buf());
        for bad in [
            "../escape",
            "a/b",
            "",
            ".",
            "..",
            "with\0nul",
            "/etc/passwd",
        ] {
            assert_eq!(
                fs.create_new(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "name {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn list_returns_files_not_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        let fs = StdFs::new(dir.path().to_path_buf());
        fs.create_new("a.log").unwrap();
        assert_eq!(fs.list().unwrap(), vec!["a.log".to_owned()]);
        // A subdirectory is never reported as an existing file.
        assert!(!fs.exists("subdir").unwrap());
        assert!(fs.exists("a.log").unwrap());
    }

    #[test]
    fn every_listed_name_is_openable_and_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFs::new(dir.path().to_path_buf());
        // Created out of lexicographic order, including a backslash name (a legal Unix
        // filename byte that resolve must accept so list/open stay consistent).
        for name in [
            "seg-000003.log",
            "seg-000001.log",
            "odd\\name",
            "seg-000002.log",
        ] {
            fs.create_new(name).unwrap();
        }
        let listed = fs.list().unwrap();
        let mut sorted = listed.clone();
        sorted.sort();
        assert_eq!(listed, sorted, "list must be sorted");
        for name in &listed {
            // The whole point of the consistency fix: nothing list returns is rejected.
            fs.open(name).unwrap();
            assert!(fs.exists(name).unwrap());
        }
    }
}
