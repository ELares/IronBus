// SPDX-License-Identifier: MIT OR Apache-2.0
//! A deterministic fault-injecting wrapper over the storage seams, for testing the recovery
//! and freeze paths a healthy filesystem never exercises. Wrap an
//! [`InMemoryFs`](crate::fs::InMemoryFs) (or any [`Filesystem`]) in a [`FaultFs`], then arm a
//! fault through the shared [`FaultControl`]; the next matching operation fails deterministically
//! (no ambient randomness). It injects fsync failures (the fsyncgate / EIO mode), clean write
//! failures, one-shot torn (partial) writes, short reads (a `read_at` returning fewer bytes than
//! asked while data remains), and read errors (an injected `read_at` IO error). A seeded fault
//! scheduler that drives these primitives from one PRNG is a follow-up (#151); page-cache
//! reordering and both-slots-torn are follow-ups under #164.

use crate::fs::Filesystem;
use crate::io::RandomAccessFile;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// A shared handle for arming and disarming injected faults. Cloning shares the same state,
/// so a test can keep a handle while the [`FaultFs`] is moved into the engine under test.
#[derive(Clone, Debug, Default)]
pub struct FaultControl {
    fail_sync: Arc<AtomicBool>,
    fail_write: Arc<AtomicBool>,
    fail_read: Arc<AtomicBool>,
    torn_write_armed: Arc<AtomicBool>,
    torn_write_prefix: Arc<AtomicU64>,
    /// While non-zero, every `read_at` returns at most this many bytes (a short read). Zero
    /// disables it. The model never returns zero bytes while data remains (that would be a
    /// spurious EOF, not a short read), so the limit must be at least 1 to take effect.
    short_read_limit: Arc<AtomicU64>,
}

impl FaultControl {
    /// Arms (or disarms) sync failure: while armed, every `sync_data` and `sync_all` on any
    /// file of the owning [`FaultFs`] returns an injected IO error instead of flushing.
    pub fn set_fail_sync(&self, fail: bool) {
        self.fail_sync.store(fail, Ordering::SeqCst);
    }

    /// Arms (or disarms) write failure: while armed, every `write_all_at` returns an injected
    /// IO error WITHOUT writing any bytes, modelling a write that fails cleanly.
    pub fn set_fail_write(&self, fail: bool) {
        self.fail_write.store(fail, Ordering::SeqCst);
    }

    /// Arms (or disarms) read failure: while armed, every `read_at` returns an injected IO error
    /// instead of reading, modelling a read that hits a bad block.
    pub fn set_fail_read(&self, fail: bool) {
        self.fail_read.store(fail, Ordering::SeqCst);
    }

    /// Arms (or disarms) short reads: while `limit` is non-zero, every `read_at` returns at most
    /// `limit` bytes even when more are available, so a caller that does not loop over a partial
    /// read is exposed. `0` disables it. A short read never returns zero bytes while data remains
    /// (that would be a spurious EOF), so a `limit` of `0` simply means "off".
    pub fn set_short_read(&self, limit: u64) {
        self.short_read_limit.store(limit, Ordering::SeqCst);
    }

    /// Arms a one-shot torn write: the NEXT `write_all_at` persists only the first
    /// `prefix_len` bytes of its buffer (clamped to the buffer length), then returns an
    /// injected IO error, modelling a write interrupted mid-record by a crash. It fires once
    /// and disarms; the partial bytes remain on disk for recovery to find and truncate.
    pub fn arm_torn_write(&self, prefix_len: u64) {
        self.torn_write_prefix.store(prefix_len, Ordering::SeqCst);
        self.torn_write_armed.store(true, Ordering::SeqCst);
    }

    fn sync_should_fail(&self) -> bool {
        self.fail_sync.load(Ordering::SeqCst)
    }

    fn write_should_fail(&self) -> bool {
        self.fail_write.load(Ordering::SeqCst)
    }

    fn read_should_fail(&self) -> bool {
        self.fail_read.load(Ordering::SeqCst)
    }

    fn short_read_limit(&self) -> u64 {
        self.short_read_limit.load(Ordering::SeqCst)
    }

    /// If a torn write is armed, consume it (one-shot) and return its byte prefix.
    fn take_torn_write(&self) -> Option<u64> {
        if self.torn_write_armed.swap(false, Ordering::SeqCst) {
            Some(self.torn_write_prefix.load(Ordering::SeqCst))
        } else {
            None
        }
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

    /// Borrows the wrapped filesystem, so a test can reach through the fault layer to the
    /// underlying disk: for example to drive `simulate_power_loss` on an
    /// [`InMemoryFs`](crate::fs::InMemoryFs) after arming a fault, or to inspect its durable
    /// image. The fault layer holds no state of its own beyond the shared [`FaultControl`].
    #[must_use]
    pub fn inner(&self) -> &F {
        &self.inner
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

/// A [`RandomAccessFile`] that wraps another and injects faults while the shared
/// [`FaultControl`] is armed: a failed fsync, a clean write failure, a one-shot torn write that
/// persists a byte prefix then errors, a read error, or a short read that returns fewer bytes
/// than asked. Length and truncation delegate unchanged.
#[derive(Debug)]
pub struct FaultFile<F> {
    inner: F,
    control: FaultControl,
}

fn injected_sync_error() -> io::Error {
    io::Error::other("injected fault: fsync failed")
}

fn injected_write_error() -> io::Error {
    io::Error::other("injected fault: write failed")
}

fn injected_read_error() -> io::Error {
    io::Error::other("injected fault: read failed")
}

impl<F: RandomAccessFile> RandomAccessFile for FaultFile<F> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if self.control.read_should_fail() {
            return Err(injected_read_error());
        }
        let limit = self.control.short_read_limit();
        if limit > 0 {
            // Cap the read to `limit` bytes: the inner read returns at most that many, so a
            // caller that does not loop over a partial read sees fewer bytes than it asked for.
            let cap = usize::try_from(limit).unwrap_or(usize::MAX).min(buf.len());
            return self.inner.read_at(&mut buf[..cap], offset);
        }
        self.inner.read_at(buf, offset)
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        // A one-shot torn write: persist a prefix of the bytes, then fail, modelling a write
        // interrupted mid-record by a crash (the partial bytes survive for recovery to find).
        if let Some(prefix) = self.control.take_torn_write() {
            let n = buf.len().min(usize::try_from(prefix).unwrap_or(usize::MAX));
            self.inner.write_all_at(&buf[..n], offset)?;
            return Err(injected_write_error());
        }
        if self.control.write_should_fail() {
            return Err(injected_write_error());
        }
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

    #[test]
    fn inner_reaches_the_wrapped_filesystem() {
        let (fs, _control) = faulted();
        // A file created through the fault layer is visible on the inner filesystem, and
        // inner() hands back that same wrapped filesystem.
        let f = fs.create_new("seg").unwrap();
        f.write_all_at(b"abc", 0).unwrap();
        let inner = fs.inner();
        assert!(inner.exists("seg").unwrap());
        assert_eq!(inner.list().unwrap(), vec!["seg".to_string()]);
    }

    #[test]
    fn arming_write_failure_fails_writes_cleanly() {
        let (fs, control) = faulted();
        let f = fs.create_new("seg").unwrap();
        control.set_fail_write(true);
        assert!(
            f.write_all_at(b"abc", 0).is_err(),
            "writes fault while armed"
        );
        // A clean failure persisted no bytes, and sync is unaffected (only writes fault).
        assert_eq!(f.len().unwrap(), 0);
        f.sync_data().unwrap();
        control.set_fail_write(false);
        f.write_all_at(b"abc", 0).unwrap();
        assert_eq!(f.len().unwrap(), 3);
    }

    #[test]
    fn arming_read_failure_fails_reads_only() {
        let (fs, control) = faulted();
        let f = fs.create_new("seg").unwrap();
        f.write_all_at(b"hello", 0).unwrap();
        control.set_fail_read(true);
        let mut buf = [0u8; 5];
        assert!(f.read_at(&mut buf, 0).is_err(), "reads fault while armed");
        // Only reads are injected: writes and syncs still go through.
        f.write_all_at(b"!", 5).unwrap();
        f.sync_all().unwrap();
        control.set_fail_read(false);
        // Disarmed, the read flows to the inner file again.
        let n = f.read_at(&mut buf, 0).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn a_short_read_returns_fewer_bytes_but_read_exact_still_fills() {
        let (fs, control) = faulted();
        let f = fs.create_new("seg").unwrap();
        f.write_all_at(b"0123456789", 0).unwrap();
        // Cap every read to 3 bytes even though 10 are available.
        control.set_short_read(3);
        let mut buf = [0u8; 10];
        let n = f.read_at(&mut buf, 0).unwrap();
        assert_eq!(
            n, 3,
            "a short read returns at most the cap, not the full request"
        );
        assert_eq!(&buf[..3], b"012");
        // read_exact_at loops over the short reads and still fills the whole buffer.
        let mut full = [0u8; 10];
        f.read_exact_at(&mut full, 0).unwrap();
        assert_eq!(&full, b"0123456789");
        // Disarmed, a single read returns everything again.
        control.set_short_read(0);
        let mut all = [0u8; 10];
        assert_eq!(f.read_at(&mut all, 0).unwrap(), 10);
    }

    #[test]
    fn a_short_read_at_the_end_still_signals_eof_not_a_spurious_zero() {
        let (fs, control) = faulted();
        let f = fs.create_new("seg").unwrap();
        f.write_all_at(b"ab", 0).unwrap();
        control.set_short_read(4);
        // Reading past the end returns 0 (real EOF), and reading the 2 available returns 2 (the
        // short cap of 4 does not invent bytes).
        let mut buf = [0u8; 8];
        assert_eq!(
            f.read_at(&mut buf, 2).unwrap(),
            0,
            "past the end is a real EOF"
        );
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 2);
        assert_eq!(&buf[..2], b"ab");
    }

    #[test]
    fn a_torn_write_persists_a_prefix_then_fails_once() {
        let (fs, control) = faulted();
        let f = fs.create_new("seg").unwrap();
        // A one-shot torn write of 2 bytes: the next write persists "he" then errors.
        control.arm_torn_write(2);
        assert!(f.write_all_at(b"hello", 0).is_err());
        let mut buf = [0u8; 2];
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 2);
        assert_eq!(&buf, b"he");
        assert_eq!(f.len().unwrap(), 2, "only the torn prefix persisted");
        // It fired once: the next write succeeds in full.
        f.write_all_at(b"world!", 0).unwrap();
        let mut buf2 = [0u8; 6];
        f.read_at(&mut buf2, 0).unwrap();
        assert_eq!(&buf2, b"world!");
    }
}
