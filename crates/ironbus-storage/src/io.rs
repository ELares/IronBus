// SPDX-License-Identifier: MIT OR Apache-2.0
//! The file IO seam for IronBus storage.
//!
//! Storage code reads and writes through [`RandomAccessFile`] rather than calling
//! the filesystem directly, so the deterministic simulation can substitute an
//! in-memory disk it fully controls. Production wires a real file (added later);
//! tests and the simulation wire [`InMemoryFile`].

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

/// A file supporting positioned (offset-addressed) reads and writes plus an explicit
/// data sync.
///
/// All methods take `&self`. The single-logical-writer rule is enforced by the
/// layers above, not the borrow checker, so a file can be shared with lock-free
/// readers.
pub trait RandomAccessFile: Send + Sync {
    /// Reads into `buf` starting at `offset`, returning the number of bytes read.
    ///
    /// Like `pread`: it may read fewer bytes than requested (for example near the
    /// end of the file) and returns `0` at or past the end.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;

    /// Writes all of `buf` starting at `offset`, extending the file with zero bytes
    /// if `offset` lies beyond the current end.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()>;

    /// Flushes file data (not necessarily metadata) to durable storage, like
    /// `fdatasync`.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn sync_data(&self) -> io::Result<()>;

    /// Returns the current file length in bytes.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn len(&self) -> io::Result<u64>;

    /// Truncates or extends the file to `len` bytes; extension zero-fills.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn set_len(&self, len: u64) -> io::Result<()>;

    /// Returns `true` if the file is empty.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
}

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// An in-memory [`RandomAccessFile`] for tests and the deterministic simulation.
///
/// It counts calls to [`sync_data`](RandomAccessFile::sync_data) and can
/// [`snapshot`](InMemoryFile::snapshot) its bytes, so a simulation can model power
/// loss by treating only the bytes present at the last sync as durable.
#[derive(Debug, Default)]
pub struct InMemoryFile {
    data: Mutex<Vec<u8>>,
    syncs: AtomicU64,
}

impl InMemoryFile {
    /// Creates an empty in-memory file.
    #[must_use]
    pub fn new() -> InMemoryFile {
        InMemoryFile::default()
    }

    /// Creates an in-memory file pre-populated with `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> InMemoryFile {
        InMemoryFile {
            data: Mutex::new(bytes),
            syncs: AtomicU64::new(0),
        }
    }

    /// Returns how many times `sync_data` has been called.
    #[must_use]
    pub fn sync_count(&self) -> u64 {
        self.syncs.load(Ordering::SeqCst)
    }

    /// Returns a copy of the file's current bytes.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        self.data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RandomAccessFile for InMemoryFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let off = usize::try_from(offset).map_err(|_| invalid_input("offset out of range"))?;
        let data = self.data.lock().unwrap_or_else(PoisonError::into_inner);
        if off >= data.len() {
            return Ok(0);
        }
        let n = (data.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        let off = usize::try_from(offset).map_err(|_| invalid_input("offset out of range"))?;
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| invalid_input("write extends past the addressable range"))?;
        let mut data = self.data.lock().unwrap_or_else(PoisonError::into_inner);
        if data.len() < end {
            data.resize(end, 0);
        }
        data[off..end].copy_from_slice(buf);
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self
            .data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len() as u64)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| invalid_input("length out of range"))?;
        self.data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .resize(len, 0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn write_then_read_roundtrip() {
        let f = InMemoryFile::new();
        f.write_all_at(b"hello", 0).unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(f.len().unwrap(), 5);
        assert!(!f.is_empty().unwrap());
    }

    #[test]
    fn write_past_end_zero_fills_the_gap() {
        let f = InMemoryFile::new();
        f.write_all_at(b"ab", 4).unwrap();
        assert_eq!(f.len().unwrap(), 6);
        assert_eq!(f.snapshot(), vec![0, 0, 0, 0, b'a', b'b']);
    }

    #[test]
    fn read_past_end_returns_zero_and_partial_near_end() {
        let f = InMemoryFile::from_bytes(b"abcd".to_vec());
        let mut buf = [0u8; 8];
        assert_eq!(f.read_at(&mut buf, 4).unwrap(), 0); // at end
        assert_eq!(f.read_at(&mut buf, 100).unwrap(), 0); // past end
        let n = f.read_at(&mut buf, 2).unwrap(); // partial: only 2 bytes left
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"cd");
    }

    #[test]
    fn set_len_truncates_and_extends() {
        let f = InMemoryFile::from_bytes(b"abcdef".to_vec());
        f.set_len(3).unwrap();
        assert_eq!(f.snapshot(), b"abc");
        f.set_len(5).unwrap();
        assert_eq!(f.snapshot(), vec![b'a', b'b', b'c', 0, 0]);
    }

    #[test]
    fn sync_is_counted() {
        let f = InMemoryFile::new();
        assert_eq!(f.sync_count(), 0);
        f.write_all_at(b"x", 0).unwrap();
        f.sync_data().unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.sync_count(), 2);
    }

    #[test]
    fn empty_file_reports_empty() {
        let f = InMemoryFile::new();
        assert!(f.is_empty().unwrap());
        assert_eq!(f.len().unwrap(), 0);
        let mut buf = [0u8; 4];
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 0);
    }

    #[test]
    fn shared_across_threads_as_trait_object() {
        let f: Arc<dyn RandomAccessFile> = Arc::new(InMemoryFile::new());
        let f2 = Arc::clone(&f);
        std::thread::scope(|s| {
            s.spawn(move || f2.write_all_at(b"data", 0).unwrap());
        });
        let mut buf = [0u8; 4];
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 4);
        assert_eq!(&buf, b"data");
    }
}
