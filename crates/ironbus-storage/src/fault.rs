// SPDX-License-Identifier: MIT OR Apache-2.0
//! A deterministic fault-injecting wrapper over the storage seams, for testing the recovery
//! and freeze paths a healthy filesystem never exercises. Wrap an
//! [`InMemoryFs`](crate::fs::InMemoryFs) (or any [`Filesystem`]) in a [`FaultFs`], then arm a
//! fault through the shared [`FaultControl`]; the next matching operation fails deterministically
//! (no ambient randomness). This first slice injects fsync failures (the fsyncgate / EIO mode);
//! injected write failures, partial writes, and page-cache reordering are follow-ups under #164.

use crate::fs::Filesystem;
use crate::io::RandomAccessFile;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A shared handle for arming and disarming injected faults. Cloning shares the same state,
/// so a test can keep a handle while the [`FaultFs`] is moved into the engine under test.
#[derive(Clone, Debug, Default)]
pub struct FaultControl {
    fail_sync: Arc<AtomicBool>,
}

impl FaultControl {
    /// Arms (or disarms) sync failure: while armed, every `sync_data` and `sync_all` on any
    /// file of the owning [`FaultFs`] returns an injected IO error instead of flushing.
    pub fn set_fail_sync(&self, fail: bool) {
        self.fail_sync.store(fail, Ordering::SeqCst);
    }

    fn sync_should_fail(&self) -> bool {
        self.fail_sync.load(Ordering::SeqCst)
    }
}

/// A [`Filesystem`] that wraps another and hands out [`FaultFile`]s sharing one
/// [`FaultControl`]. Directory operations delegate unchanged; only the files can fault.
#[derive(Debug)]
pub struct FaultFs<F> {
    inner: F,
    control: FaultControl,
}

impl<F: Filesystem> FaultFs<F> {
    /// Wraps `inner`, returning the fault filesystem and a [`FaultControl`] to arm faults.
    #[must_use]
    pub fn new(inner: F) -> (FaultFs<F>, FaultControl) {
        let control = FaultControl::default();
        (
            FaultFs {
                inner,
                control: control.clone(),
            },
            control,
        )
    }
}

impl<F: Filesystem> Filesystem for FaultFs<F> {
    type File = FaultFile<F::File>;

    fn open(&self, name: &str) -> io::Result<Self::File> {
        Ok(FaultFile {
            inner: self.inner.open(name)?,
            control: self.control.clone(),
        })
    }

    fn create_new(&self, name: &str) -> io::Result<Self::File> {
        Ok(FaultFile {
            inner: self.inner.create_new(name)?,
            control: self.control.clone(),
        })
    }

    fn remove(&self, name: &str) -> io::Result<()> {
        self.inner.remove(name)
    }

    fn list(&self) -> io::Result<Vec<String>> {
        self.inner.list()
    }

    fn exists(&self, name: &str) -> io::Result<bool> {
        self.inner.exists(name)
    }

    fn sync_dir(&self) -> io::Result<()> {
        self.inner.sync_dir()
    }
}

/// A [`RandomAccessFile`] that wraps another and fails its syncs while the shared
/// [`FaultControl`] is armed. Reads, writes, length, and truncation delegate unchanged.
#[derive(Debug)]
pub struct FaultFile<F> {
    inner: F,
    control: FaultControl,
}

fn injected_sync_error() -> io::Error {
    io::Error::other("injected fault: fsync failed")
}

impl<F: RandomAccessFile> RandomAccessFile for FaultFile<F> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.inner.read_at(buf, offset)
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        self.inner.write_all_at(buf, offset)
    }

    fn sync_data(&self) -> io::Result<()> {
        if self.control.sync_should_fail() {
            return Err(injected_sync_error());
        }
        self.inner.sync_data()
    }

    fn sync_all(&self) -> io::Result<()> {
        if self.control.sync_should_fail() {
            return Err(injected_sync_error());
        }
        self.inner.sync_all()
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;

    fn faulted() -> (FaultFs<InMemoryFs>, FaultControl) {
        FaultFs::new(InMemoryFs::new())
    }

    #[test]
    fn unarmed_syncs_and_io_pass_through() {
        let (fs, _control) = faulted();
        let f = fs.create_new("seg").unwrap();
        f.write_all_at(b"hello", 0).unwrap();
        // A round-trip read returns exactly what was written.
        let mut buf = [0u8; 5];
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 5);
        assert_eq!(&buf, b"hello");
        // Unarmed, both syncs succeed and the length is the inner length.
        f.sync_data().unwrap();
        f.sync_all().unwrap();
        assert_eq!(f.len().unwrap(), 5);
    }

    #[test]
    fn arming_fails_both_sync_data_and_sync_all_but_not_io() {
        let (fs, control) = faulted();
        let f = fs.create_new("seg").unwrap();
        f.write_all_at(b"x", 0).unwrap();
        control.set_fail_sync(true);
        assert!(f.sync_data().is_err(), "sync_data faults while armed");
        assert!(f.sync_all().is_err(), "sync_all faults while armed");
        // Only fsync is injected: writes and reads still go through.
        f.write_all_at(b"y", 1).unwrap();
        let mut buf = [0u8; 2];
        f.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"xy");
    }

    #[test]
    fn disarming_restores_passthrough() {
        let (fs, control) = faulted();
        let f = fs.create_new("seg").unwrap();
        control.set_fail_sync(true);
        assert!(f.sync_data().is_err());
        control.set_fail_sync(false);
        // Disarmed, the syncs flow to the inner file again.
        f.sync_data().unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn the_control_is_shared_across_files_and_clones() {
        let (fs, control) = faulted();
        let a = fs.create_new("a").unwrap();
        let b = fs.create_new("b").unwrap();
        // Arming through a clone of the handle affects every file the FaultFs handed out.
        let cloned = control.clone();
        cloned.set_fail_sync(true);
        assert!(a.sync_all().is_err());
        assert!(b.sync_all().is_err());
    }

    #[test]
    fn directory_operations_delegate_even_while_armed() {
        let (fs, control) = faulted();
        fs.create_new("one").unwrap();
        fs.create_new("two").unwrap();
        // Arming fsync faults must not touch the directory-level operations.
        control.set_fail_sync(true);
        assert!(fs.exists("one").unwrap());
        let mut names = fs.list().unwrap();
        names.sort();
        assert_eq!(names, vec!["one".to_string(), "two".to_string()]);
        fs.remove("one").unwrap();
        assert!(!fs.exists("one").unwrap());
        fs.sync_dir().unwrap();
    }

    #[test]
    fn set_len_and_len_delegate_while_armed() {
        let (fs, control) = faulted();
        let f = fs.create_new("seg").unwrap();
        f.write_all_at(&[0u8; 10], 0).unwrap();
        control.set_fail_sync(true);
        // Truncation and length delegate unchanged even while syncs fault.
        f.set_len(4).unwrap();
        assert_eq!(f.len().unwrap(), 4);
    }
}
