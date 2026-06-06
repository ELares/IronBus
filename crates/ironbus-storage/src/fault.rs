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
