// SPDX-License-Identifier: MIT OR Apache-2.0
//! The data-directory seam for IronBus storage.
//!
//! A queue's on-disk state is one directory of self-describing segment files. Storage
//! manages that directory through the [`Filesystem`] seam rather than calling the OS
//! directly, so the deterministic simulation can substitute an in-memory directory it
//! fully controls, including directory-entry durability across a simulated power loss
//! (a created-but-not-dir-synced segment vanishes; a not-yet-durable removal is undone).

use crate::io::{EphemeralFile, InMemoryFile, RandomAccessFile};
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

    /// Returns a [`Filesystem`] of the SAME type rooted at the `name` subdirectory of this
    /// one, creating the subdirectory if it does not yet exist. This is how a secondary
    /// durable store (the dead-letter sink, #63) gets its own isolated, recoverable segment
    /// set under the data directory without escaping it: the returned filesystem's `list`,
    /// `open`, `create_new`, `remove`, and `sync_dir` operate only within the subdirectory.
    ///
    /// `name` must be a single, safe path component (no `/`, `.`, `..`, or NUL), exactly as
    /// the other methods require of a file name; an unsafe name is rejected with
    /// [`io::ErrorKind::InvalidInput`] so a subdirectory can never escape the root.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::InvalidInput`] for an unsafe `name`, or an IO error creating
    /// the subdirectory.
    fn subdir(&self, name: &str) -> io::Result<Self>
    where
        Self: Sized;

    /// Whether the `name` subdirectory already exists, WITHOUT creating it. The complement to
    /// [`Filesystem::subdir`] (which creates on demand): a caller probes here first to avoid
    /// materializing a subdirectory as a side effect (the DLQ sink is opened only when a prior run
    /// created it, #63).
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::InvalidInput`] for an unsafe `name`, or an IO error.
    fn subdir_exists(&self, name: &str) -> io::Result<bool>;

    /// Lists the names of the immediate SUBDIRECTORIES of this directory, in sorted order, WITHOUT
    /// creating any. This is the directory-level complement to [`Filesystem::list`] (which reports
    /// only regular files): it is what lets a multi-store layer enumerate its children, e.g. the
    /// `StreamSet` enumerating each `streams/<name>/` per-stream log at open (M2-I2), the same way
    /// segment recovery enumerates `seg-<id>.log` files. Each returned name is a single, safe path
    /// component that can be passed to [`Filesystem::subdir`]. The order is deterministic across
    /// backends so recovery never depends on raw directory order. A directory with no
    /// subdirectories yields an empty list, never an error.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn list_subdirs(&self) -> io::Result<Vec<String>>;
}

/// Validates that `name` is a single, safe path component (no separator, no `.`/`..`, no NUL),
/// so a subdirectory or file name can never escape the data directory. Shared by the `StdFs`
/// path resolution and the subdirectory check.
fn is_plain_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
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
    /// The key prefix this handle operates under, so a [`InMemoryFs::subdir`] view shares the
    /// SAME backing store (hence the same power-loss and durability model) while seeing only the
    /// keys under its prefix. The root handle has an empty prefix. The flat in-memory store has
    /// no real directories, so a subdirectory is modeled as a `"<name>/"` key prefix.
    prefix: String,
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
    /// surviving file to its last-synced content, modelling a power loss. This is a
    /// disk-wide event: it reverts EVERY key in the store, including those under a
    /// [`InMemoryFs::subdir`] prefix, since they share one backing image.
    pub fn simulate_power_loss(&self) {
        let mut g = self.lock();
        g.live = g.durable.clone();
        for f in g.live.values() {
            f.simulate_power_loss();
        }
    }

    /// Models a power loss with page-cache reorder/drop of the unsynced tail (#164, #55).
    ///
    /// Like [`simulate_power_loss`](InMemoryFs::simulate_power_loss), the directory reverts to its
    /// last `sync_dir` image and every surviving file reverts its unsynced bytes. The difference is
    /// the ACTIVE segment named `active_name`: instead of the all-or-nothing revert, its unsynced
    /// tail is reordered/dropped to a seeded strict prefix (only fsync'd bytes are guaranteed
    /// durable), via [`InMemoryFile::simulate_power_loss_reorder`]. Every other surviving file does
    /// the plain revert (the sealed predecessors carry only fsync'd bytes anyway). Deterministic in
    /// `seed`. Returns the number of unsynced tail bytes the cut KEPT on the active segment (0 if it
    /// did not survive the directory revert), so a caller can assert the byte state crossed the
    /// modelled boundary.
    ///
    /// [`simulate_power_loss`]: InMemoryFs::simulate_power_loss
    /// [`InMemoryFile::simulate_power_loss_reorder`]: crate::io::InMemoryFile::simulate_power_loss_reorder
    #[must_use]
    pub fn simulate_power_loss_reorder(&self, active_name: &str, seed: u64) -> u64 {
        let mut g = self.lock();
        g.live = g.durable.clone();
        let active_key = format!("{}{}", self.prefix, active_name);
        let mut kept = 0u64;
        for (key, f) in &g.live {
            if *key == active_key {
                kept = f.simulate_power_loss_reorder(seed);
            } else {
                f.simulate_power_loss();
            }
        }
        kept
    }

    /// Maps a caller-visible name to its backing-store key by prepending this handle's prefix.
    fn key(&self, name: &str) -> String {
        format!("{}{}", self.prefix, name)
    }
}

impl Filesystem for InMemoryFs {
    type File = Arc<InMemoryFile>;

    fn open(&self, name: &str) -> io::Result<Self::File> {
        self.lock()
            .live
            .get(&self.key(name))
            .map(Arc::clone)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file"))
    }

    fn create_new(&self, name: &str) -> io::Result<Self::File> {
        let key = self.key(name);
        let mut g = self.lock();
        if g.live.contains_key(&key) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "file already exists",
            ));
        }
        let file = Arc::new(InMemoryFile::new());
        g.live.insert(key, Arc::clone(&file));
        Ok(file)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        if self.lock().live.remove(&self.key(name)).is_some() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "no such file"))
        }
    }

    fn list(&self) -> io::Result<Vec<String>> {
        // Only the entries under this handle's prefix, with the prefix stripped, and never an
        // entry that lies in a deeper subdirectory (one whose remainder still contains a `/`),
        // so a subdir view never reports its own children's children as flat files.
        Ok(self
            .lock()
            .live
            .keys()
            .filter_map(|k| k.strip_prefix(&self.prefix))
            .filter(|rest| !rest.is_empty() && !rest.contains('/'))
            .map(ToOwned::to_owned)
            .collect())
    }

    fn exists(&self, name: &str) -> io::Result<bool> {
        Ok(self.lock().live.contains_key(&self.key(name)))
    }

    fn sync_dir(&self) -> io::Result<()> {
        let mut g = self.lock();
        g.durable = g.live.clone();
        Ok(())
    }

    fn subdir(&self, name: &str) -> io::Result<InMemoryFs> {
        if !is_plain_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "subdirectory name must be a single path component",
            ));
        }
        // A subdirectory is a deeper key prefix over the SAME shared store, so the subdir's
        // segment files share the parent's power-loss and durability image. No backing entry
        // needs creating: the flat store materializes a directory lazily as its files appear.
        Ok(InMemoryFs {
            state: Arc::clone(&self.state),
            prefix: format!("{}{name}/", self.prefix),
        })
    }

    fn subdir_exists(&self, name: &str) -> io::Result<bool> {
        if !is_plain_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "subdirectory name must be a single path component",
            ));
        }
        // The flat store has no standalone directory entries: a subdirectory "exists" iff at least
        // one key under its `<prefix><name>/` namespace is present (a power loss that reverted every
        // such key leaves the directory effectively gone, which is the correct, conservative answer
        // for the DLQ probe).
        let dir_prefix = format!("{}{name}/", self.prefix);
        Ok(self.lock().live.keys().any(|k| k.starts_with(&dir_prefix)))
    }

    fn list_subdirs(&self) -> io::Result<Vec<String>> {
        // The flat store models a subdirectory as a deeper key prefix, so an immediate subdirectory
        // is the FIRST path component of any key under this handle's prefix whose remainder still
        // contains a `/` (i.e. the key lives in a child directory, not directly here). A `BTreeSet`
        // dedupes the many keys that share one subdir and yields the names in sorted order, matching
        // `list`'s deterministic ordering. A subdir "exists" iff it holds at least one live key,
        // consistent with `subdir_exists`.
        let g = self.lock();
        let mut dirs = std::collections::BTreeSet::new();
        for k in g.live.keys() {
            if let Some(rest) = k.strip_prefix(&self.prefix) {
                if let Some((head, _)) = rest.split_once('/') {
                    if !head.is_empty() {
                        dirs.insert(head.to_owned());
                    }
                }
            }
        }
        Ok(dirs.into_iter().collect())
    }
}

/// An EPHEMERAL in-memory [`Filesystem`] for the real `--storage memory` broker (#492).
///
/// It is the directory-level companion to [`EphemeralFile`]: a flat namespace of named ephemeral
/// files with NO `durable` directory shadow and a no-op `sync_dir`. [`InMemoryFs`] keeps a second
/// `durable` `BTreeMap` (and each file keeps its own `durable` byte image) ONLY so the deterministic
/// crash-recovery simulation can revert created/removed entries and unsynced bytes at a modelled
/// power loss. The real `--storage memory` path models no power loss — it is ephemeral, a crash
/// loses everything — so that second map is pure overhead, the directory half of the ~2x RSS blowup
/// (#492). This backend drops it, so directory state is ~1x and `sync_dir` is O(1).
///
/// It is deliberately MISSING `simulate_power_loss` / `simulate_power_loss_reorder`: the crash
/// simulation must keep using [`InMemoryFs`], which still carries the durable images those models
/// revert to. Like [`InMemoryFs`], a clone aliases the SAME backing store (an `Arc`) and a
/// [`subdir`](Filesystem::subdir) is a key-prefix view over it (the DLQ sink lives there), so the
/// engine's subdirectory and multi-handle behavior is unchanged.
///
/// [`EphemeralFile`]: crate::io::EphemeralFile
#[derive(Clone, Debug, Default)]
pub struct EphemeralFs {
    /// The single live directory image, shared behind an `Arc` so a clone aliases the same store.
    /// There is no `durable` companion map: an ephemeral directory has no power loss to model.
    files: Arc<Mutex<BTreeMap<String, Arc<EphemeralFile>>>>,
    /// The key prefix this handle operates under, so a [`subdir`](Filesystem::subdir) view shares
    /// the SAME backing store while seeing only the keys under its prefix. The root handle's prefix
    /// is empty; the flat store models a subdirectory as a `"<name>/"` key prefix, exactly as
    /// [`InMemoryFs`] does.
    prefix: String,
}

impl EphemeralFs {
    /// Creates an empty ephemeral in-memory directory.
    #[must_use]
    pub fn new() -> EphemeralFs {
        EphemeralFs::default()
    }

    // As in [`InMemoryFs::lock`]: recovering a poisoned guard keeps the broker process alive, and
    // the only mutations are map and `Arc` operations that never leave the state structurally torn.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Arc<EphemeralFile>>> {
        self.files.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Maps a caller-visible name to its backing-store key by prepending this handle's prefix.
    fn key(&self, name: &str) -> String {
        format!("{}{}", self.prefix, name)
    }
}

impl Filesystem for EphemeralFs {
    type File = Arc<EphemeralFile>;

    fn open(&self, name: &str) -> io::Result<Self::File> {
        self.lock()
            .get(&self.key(name))
            .map(Arc::clone)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file"))
    }

    fn create_new(&self, name: &str) -> io::Result<Self::File> {
        let key = self.key(name);
        let mut g = self.lock();
        if g.contains_key(&key) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "file already exists",
            ));
        }
        let file = Arc::new(EphemeralFile::new());
        g.insert(key, Arc::clone(&file));
        Ok(file)
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        if self.lock().remove(&self.key(name)).is_some() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "no such file"))
        }
    }

    fn list(&self) -> io::Result<Vec<String>> {
        // Only the entries directly under this handle's prefix (not a deeper subdirectory's), with
        // the prefix stripped — exactly the InMemoryFs flat-listing rule.
        Ok(self
            .lock()
            .keys()
            .filter_map(|k| k.strip_prefix(&self.prefix))
            .filter(|rest| !rest.is_empty() && !rest.contains('/'))
            .map(ToOwned::to_owned)
            .collect())
    }

    fn exists(&self, name: &str) -> io::Result<bool> {
        Ok(self.lock().contains_key(&self.key(name)))
    }

    // No durable directory image to advance and no device to flush: directory durability is not a
    // concept for an ephemeral store, so this is a faithful O(1) no-op (cf. InMemoryFs::sync_dir,
    // which clones the whole live map into a durable shadow purely for the power-loss simulation).
    fn sync_dir(&self) -> io::Result<()> {
        Ok(())
    }

    fn subdir(&self, name: &str) -> io::Result<EphemeralFs> {
        if !is_plain_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "subdirectory name must be a single path component",
            ));
        }
        // A subdirectory is a deeper key prefix over the SAME shared store, so the subdir's files
        // share the parent's image (the DLQ sink, #63). The flat store materializes a directory
        // lazily as its files appear, so nothing is created here.
        Ok(EphemeralFs {
            files: Arc::clone(&self.files),
            prefix: format!("{}{name}/", self.prefix),
        })
    }

    fn subdir_exists(&self, name: &str) -> io::Result<bool> {
        if !is_plain_component(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "subdirectory name must be a single path component",
            ));
        }
        // The flat store has no standalone directory entries: a subdirectory "exists" iff at least
        // one key under its `<prefix><name>/` namespace is present.
        let dir_prefix = format!("{}{name}/", self.prefix);
        Ok(self.lock().keys().any(|k| k.starts_with(&dir_prefix)))
    }

    fn list_subdirs(&self) -> io::Result<Vec<String>> {
        // Same flat-store rule as `InMemoryFs::list_subdirs`: the immediate subdirectories are the
        // first path components of the keys under this handle's prefix whose remainder still holds a
        // `/`, deduped and sorted.
        let g = self.lock();
        let mut dirs = std::collections::BTreeSet::new();
        for k in g.keys() {
            if let Some(rest) = k.strip_prefix(&self.prefix) {
                if let Some((head, _)) = rest.split_once('/') {
                    if !head.is_empty() {
                        dirs.insert(head.to_owned());
                    }
                }
            }
        }
        Ok(dirs.into_iter().collect())
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
        if !is_plain_component(name) {
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

    fn subdir(&self, name: &str) -> io::Result<StdFs> {
        let path = self.resolve(name)?;
        // Create the subdirectory if it does not exist; an existing one is fine (the DLQ sink
        // is opened on demand, and a reopen must reuse it). The parent directory entry for the
        // new subdir is made durable so a power loss right after creation does not lose it.
        match std::fs::create_dir(&path) {
            Ok(()) => sync_dir(&self.root)?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        Ok(StdFs { root: path })
    }

    fn subdir_exists(&self, name: &str) -> io::Result<bool> {
        match std::fs::symlink_metadata(self.resolve(name)?) {
            Ok(meta) => Ok(meta.is_dir()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn list_subdirs(&self) -> io::Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            // Only real directories (the segment file `list` reports only files; this is its mirror
            // for directories). A symlink to a directory is NOT followed: `file_type` reports the
            // link itself, so a planted symlink cannot make enumeration escape the data dir.
            if !entry.file_type()?.is_dir() {
                continue;
            }
            // A non-UTF-8 name cannot be an IronBus subdir (stream subdir names are ASCII hex), so
            // skip it rather than failing the whole listing on one foreign entry — exactly as `list`
            // does for files.
            if let Ok(name) = entry.file_name().into_string() {
                names.push(name);
            }
        }
        // Sorted, so `list_subdirs` is deterministic across backends; recovery must not depend on
        // raw `read_dir` order.
        names.sort();
        Ok(names)
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
    fn a_subdir_is_isolated_from_the_parent_keyspace() {
        let fs = InMemoryFs::new();
        fs.create_new("seg-0.log").unwrap();
        let dlq = fs.subdir("dlq").unwrap();
        dlq.create_new("seg-0.log").unwrap();
        dlq.create_new("seg-1.log").unwrap();
        // The subdir sees only its own files (not the parent's), and the parent's flat list does
        // not surface the subdir's deeper keys (they still contain a `/` after the prefix strip).
        let mut sub = dlq.list().unwrap();
        sub.sort();
        assert_eq!(sub, vec!["seg-0.log".to_owned(), "seg-1.log".to_owned()]);
        assert_eq!(fs.list().unwrap(), vec!["seg-0.log".to_owned()]);
        // Same-named files in the parent and the subdir are distinct objects.
        dlq.open("seg-0.log")
            .unwrap()
            .write_all_at(b"sub", 0)
            .unwrap();
        fs.open("seg-0.log")
            .unwrap()
            .write_all_at(b"PARENT", 0)
            .unwrap();
        let mut buf = [0u8; 3];
        dlq.open("seg-0.log")
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        assert_eq!(&buf, b"sub");
    }

    #[test]
    fn list_subdirs_enumerates_immediate_children_only_sorted() {
        let fs = InMemoryFs::new();
        // A flat file at the root is not a subdir.
        fs.create_new("seg-0.log").unwrap();
        // Two immediate subdirs (materialized lazily as a file appears in each), each with a deeper
        // child that must NOT be reported as a top-level subdir of the root.
        let beta = fs.subdir("beta").unwrap();
        beta.create_new("seg-0.log").unwrap();
        let alpha = fs.subdir("alpha").unwrap();
        alpha.create_new("seg-0.log").unwrap();
        alpha.subdir("nested").unwrap().create_new("x").unwrap();
        // Sorted, deduped, immediate children only (not "nested", which is alpha's child).
        assert_eq!(
            fs.list_subdirs().unwrap(),
            vec!["alpha".to_owned(), "beta".to_owned()]
        );
        // From inside alpha, only its own immediate child is reported.
        assert_eq!(alpha.list_subdirs().unwrap(), vec!["nested".to_owned()]);
        // A leaf subdir with no children reports none.
        assert!(beta.list_subdirs().unwrap().is_empty());
        // A subdir with only files (no child dirs) is itself listed by its parent but lists nothing.
        assert_eq!(fs.list().unwrap(), vec!["seg-0.log".to_owned()]);
    }

    #[test]
    fn a_subdir_shares_the_power_loss_image_with_the_parent() {
        let fs = InMemoryFs::new();
        let dlq = fs.subdir("dlq").unwrap();
        let f = dlq.create_new("seg-0.log").unwrap();
        f.write_all_at(b"durable", 0).unwrap();
        f.sync_all().unwrap();
        fs.sync_dir().unwrap(); // the subdir's directory entry is durable through the shared store
                                // An unsynced overwrite is reverted by a power loss driven through the PARENT handle, since
                                // the subdir shares the one backing image.
        f.write_all_at(b"X", 0).unwrap();
        fs.simulate_power_loss();
        let mut buf = [0u8; 7];
        dlq.open("seg-0.log")
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        assert_eq!(&buf, b"durable");
    }

    #[test]
    fn subdir_rejects_an_unsafe_name() {
        let fs = InMemoryFs::new();
        for bad in ["", ".", "..", "a/b", "with\0nul"] {
            assert_eq!(
                fs.subdir(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "subdir name {bad:?} should be rejected"
            );
        }
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

#[cfg(test)]
mod ephemeral_fs_tests {
    use super::*;

    fn write_all(f: &Arc<EphemeralFile>, bytes: &[u8]) {
        f.write_all_at(bytes, 0).unwrap();
    }

    #[test]
    fn create_open_list_remove_roundtrip() {
        let fs = EphemeralFs::new();
        let a = fs.create_new("a.log").unwrap();
        write_all(&a, b"alpha");
        fs.create_new("b.log").unwrap();
        let mut names = fs.list().unwrap();
        names.sort();
        assert_eq!(names, vec!["a.log".to_owned(), "b.log".to_owned()]);
        // Opening returns a handle to the same bytes (the same Arc-backed file).
        let again = fs.open("a.log").unwrap();
        let mut buf = [0u8; 5];
        again.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"alpha");
        // Remove drops it; create_new refuses an existing name; open of a missing name errors.
        fs.remove("a.log").unwrap();
        assert!(!fs.exists("a.log").unwrap());
        assert_eq!(
            fs.create_new("b.log").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs.open("a.log").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            fs.remove("a.log").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn list_subdirs_enumerates_immediate_children_only() {
        // The ephemeral backend uses the same flat-store subdir rule as InMemoryFs, so list_subdirs
        // must report immediate children only, sorted, deduped.
        let fs = EphemeralFs::new();
        fs.create_new("seg-0.log").unwrap();
        let alpha = fs.subdir("alpha").unwrap();
        alpha.create_new("seg-0.log").unwrap();
        fs.subdir("beta").unwrap().create_new("seg-0.log").unwrap();
        alpha.subdir("nested").unwrap().create_new("x").unwrap();
        assert_eq!(
            fs.list_subdirs().unwrap(),
            vec!["alpha".to_owned(), "beta".to_owned()]
        );
        assert_eq!(alpha.list_subdirs().unwrap(), vec!["nested".to_owned()]);
    }

    #[test]
    fn a_clone_aliases_the_same_disk_with_no_durable_revert() {
        // A clone shares the one backing store. The whole point of #492: there is NO durable shadow,
        // so syncs are no-ops and nothing is ever reverted — the live bytes are the only truth.
        let fs = EphemeralFs::new();
        let probe = fs.clone();
        let f = fs.create_new("seg").unwrap();
        write_all(&f, b"hello");
        f.sync_all().unwrap();
        fs.sync_dir().unwrap();
        assert!(probe.exists("seg").unwrap());
        // An overwrite is immediately visible on the clone; a sync changes nothing (no revert).
        f.write_all_at(b"WORLD", 0).unwrap();
        let mut buf = [0u8; 5];
        probe
            .open("seg")
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        assert_eq!(&buf, b"WORLD");
    }

    #[test]
    fn a_subdir_is_isolated_and_shares_the_store() {
        let fs = EphemeralFs::new();
        fs.create_new("seg-0.log").unwrap();
        assert!(!fs.subdir_exists("dlq").unwrap());
        let dlq = fs.subdir("dlq").unwrap();
        dlq.create_new("seg-0.log").unwrap();
        dlq.create_new("seg-1.log").unwrap();
        assert!(fs.subdir_exists("dlq").unwrap());
        // The subdir sees only its own files; the parent's flat list never surfaces the deeper keys.
        let mut sub = dlq.list().unwrap();
        sub.sort();
        assert_eq!(sub, vec!["seg-0.log".to_owned(), "seg-1.log".to_owned()]);
        assert_eq!(fs.list().unwrap(), vec!["seg-0.log".to_owned()]);
        // Same-named files in the parent and the subdir are distinct objects.
        dlq.open("seg-0.log")
            .unwrap()
            .write_all_at(b"sub", 0)
            .unwrap();
        fs.open("seg-0.log")
            .unwrap()
            .write_all_at(b"PARENT", 0)
            .unwrap();
        let mut buf = [0u8; 3];
        dlq.open("seg-0.log")
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        assert_eq!(&buf, b"sub");
    }

    #[test]
    fn subdir_rejects_an_unsafe_name() {
        let fs = EphemeralFs::new();
        for bad in ["", ".", "..", "a/b", "with\0nul"] {
            assert_eq!(
                fs.subdir(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "subdir name {bad:?} should be rejected"
            );
            assert_eq!(
                fs.subdir_exists(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
            );
        }
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
    fn subdir_creates_an_isolated_child_directory_reopenable() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFs::new(dir.path().to_path_buf());
        fs.create_new("a.log").unwrap();
        let dlq = fs.subdir("dlq").unwrap();
        dlq.create_new("seg.log").unwrap();
        // The child sees only its own files; the parent's flat list never surfaces the subdir.
        assert_eq!(dlq.list().unwrap(), vec!["seg.log".to_owned()]);
        assert_eq!(fs.list().unwrap(), vec!["a.log".to_owned()]);
        // Reopening the same subdir name reuses the existing directory (no AlreadyExists error)
        // and sees the file written before.
        let dlq_again = fs.subdir("dlq").unwrap();
        assert_eq!(dlq_again.list().unwrap(), vec!["seg.log".to_owned()]);
    }

    #[test]
    fn list_subdirs_reports_directories_not_files_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFs::new(dir.path().to_path_buf());
        // Files at the root are never reported as subdirs.
        fs.create_new("a.log").unwrap();
        fs.create_new("layout.meta").unwrap();
        // Real subdirectories, created out of lexicographic order.
        let streams = fs.subdir("streams").unwrap();
        fs.subdir("dlq").unwrap();
        // Children of `streams/` are not top-level subdirs of the root.
        streams.subdir("6f7264657273").unwrap(); // streams/<hex("orders")>
                                                 // The root reports exactly its two immediate subdirs, sorted, never the files or grandchildren.
        assert_eq!(
            fs.list_subdirs().unwrap(),
            vec!["dlq".to_owned(), "streams".to_owned()]
        );
        assert_eq!(
            streams.list_subdirs().unwrap(),
            vec!["6f7264657273".to_owned()]
        );
        // A leaf subdir with no child directories reports none, and matches the in-memory backend.
        assert!(fs.subdir("dlq").unwrap().list_subdirs().unwrap().is_empty());
    }

    #[test]
    fn subdir_rejects_an_unsafe_name() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFs::new(dir.path().to_path_buf());
        for bad in ["../escape", "a/b", "", ".", "..", "with\0nul"] {
            assert_eq!(
                fs.subdir(bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "subdir name {bad:?} should be rejected"
            );
        }
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
