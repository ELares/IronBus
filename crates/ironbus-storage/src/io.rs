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

/// A file supporting positioned (offset-addressed) reads and writes plus explicit
/// data and metadata syncs.
///
/// All methods take `&self`. The single-logical-writer rule is enforced by the
/// layers above, not the borrow checker, so a file can be shared with lock-free
/// readers. The production implementation relies on that upper-layer invariant: it
/// does not itself guard against two concurrent `&self` writers.
pub trait RandomAccessFile: Send + Sync {
    /// Reads into `buf` starting at `offset`, returning the number of bytes read.
    ///
    /// Like `pread`: it may read fewer bytes than requested (for example near the
    /// end of the file) and returns `0` at or past the end.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;

    /// Fills `buf` exactly from `offset`, erroring with [`io::ErrorKind::UnexpectedEof`]
    /// if the file ends first. This is the primitive sealed-segment readers use to
    /// read fixed-size headers and footers.
    ///
    /// # Errors
    /// Propagates the underlying IO error, or `UnexpectedEof` on a short file.
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        while !buf.is_empty() {
            match self.read_at(buf, offset)? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "read past end of file",
                    ))
                }
                n => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
            }
        }
        Ok(())
    }

    /// Writes all of `buf` starting at `offset`, extending the file with zero bytes
    /// if `offset` lies beyond the current end.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()>;

    /// Flushes file data to durable storage, like `fdatasync`. Does not guarantee
    /// that metadata such as the file length is persisted; use [`sync_all`] after a
    /// [`set_len`] that must survive a crash.
    ///
    /// [`sync_all`]: RandomAccessFile::sync_all
    /// [`set_len`]: RandomAccessFile::set_len
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn sync_data(&self) -> io::Result<()>;

    /// Flushes file data and metadata (including length) to durable storage, like
    /// `fsync`.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn sync_all(&self) -> io::Result<()>;

    /// Returns the current file length in bytes.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    fn len(&self) -> io::Result<u64>;

    /// Truncates or extends the file to `len` bytes; extension zero-fills. The new
    /// length is metadata, so it is only crash-durable after [`sync_all`].
    ///
    /// [`sync_all`]: RandomAccessFile::sync_all
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

#[derive(Debug, Default)]
struct State {
    /// The current (possibly-unsynced) bytes.
    live: Vec<u8>,
    /// The bytes as of the last sync: the only bytes that survive a power loss.
    durable: Vec<u8>,
}

/// An in-memory [`RandomAccessFile`] for tests and the deterministic simulation.
///
/// It tracks two images: the `live` bytes and the `durable` bytes (a copy taken at
/// each sync). [`simulate_power_loss`](InMemoryFile::simulate_power_loss) discards
/// every write made since the last sync, so a simulation can verify that no
/// acknowledged-and-synced data is ever lost and that unsynced writes may vanish.
#[derive(Debug, Default)]
pub struct InMemoryFile {
    state: Mutex<State>,
    syncs: AtomicU64,
}

impl InMemoryFile {
    /// Creates an empty in-memory file.
    #[must_use]
    pub fn new() -> InMemoryFile {
        InMemoryFile::default()
    }

    /// Creates an in-memory file whose `bytes` are already durable (as if loaded
    /// from disk).
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> InMemoryFile {
        InMemoryFile {
            state: Mutex::new(State {
                live: bytes.clone(),
                durable: bytes,
            }),
            syncs: AtomicU64::new(0),
        }
    }

    // A panic mid-method cannot leave `State` torn: the only mutations are
    // `copy_from_slice`/`resize`/`clone`, none of which unwind partway through a
    // structurally invalid state, so recovering the guard from poison is safe and
    // keeps the test or simulation process alive.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns how many times `sync_data` or `sync_all` has been called.
    #[must_use]
    pub fn sync_count(&self) -> u64 {
        self.syncs.load(Ordering::SeqCst)
    }

    /// Returns a copy of the current (live) bytes.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        self.lock().live.clone()
    }

    /// Returns a copy of the durable bytes: the file as of the last sync.
    #[must_use]
    pub fn durable_snapshot(&self) -> Vec<u8> {
        self.lock().durable.clone()
    }

    /// Discards every write made since the last sync, modelling a power loss: the
    /// live bytes revert to the durable image.
    pub fn simulate_power_loss(&self) {
        let mut guard = self.lock();
        let s = &mut *guard;
        s.live.clone_from(&s.durable);
    }
}

impl RandomAccessFile for InMemoryFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let off = usize::try_from(offset).map_err(|_| invalid_input("offset out of range"))?;
        let s = self.lock();
        if off >= s.live.len() {
            return Ok(0);
        }
        let n = (s.live.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&s.live[off..off + n]);
        Ok(n)
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        let off = usize::try_from(offset).map_err(|_| invalid_input("offset out of range"))?;
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| invalid_input("write extends past the addressable range"))?;
        let mut s = self.lock();
        if s.live.len() < end {
            s.live.resize(end, 0);
        }
        s.live[off..end].copy_from_slice(buf);
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        // In-memory has no separate metadata, so data and metadata sync are identical.
        let mut guard = self.lock();
        let s = &mut *guard;
        s.durable.clone_from(&s.live);
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn sync_all(&self) -> io::Result<()> {
        self.sync_data()
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.lock().live.len() as u64)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| invalid_input("length out of range"))?;
        self.lock().live.resize(len, 0);
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
        assert_eq!(f.read_at(&mut buf, 4).unwrap(), 0);
        assert_eq!(f.read_at(&mut buf, 100).unwrap(), 0);
        let n = f.read_at(&mut buf, 2).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"cd");
    }

    #[test]
    fn read_exact_at_fills_or_errors() {
        let f = InMemoryFile::from_bytes(b"abcdef".to_vec());
        let mut buf = [0u8; 4];
        f.read_exact_at(&mut buf, 2).unwrap();
        assert_eq!(&buf, b"cdef");
        // Not enough bytes left: UnexpectedEof.
        let err = f.read_exact_at(&mut buf, 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
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
    fn sync_captures_durable_image_and_is_counted() {
        let f = InMemoryFile::new();
        assert_eq!(f.sync_count(), 0);
        f.write_all_at(b"one", 0).unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.sync_count(), 1);
        assert_eq!(f.durable_snapshot(), b"one");
        // A write after the sync is live but not yet durable.
        f.write_all_at(b"two", 3).unwrap();
        assert_eq!(f.snapshot(), b"onetwo");
        assert_eq!(f.durable_snapshot(), b"one");
        f.sync_all().unwrap();
        assert_eq!(f.sync_count(), 2);
        assert_eq!(f.durable_snapshot(), b"onetwo");
    }

    #[test]
    fn power_loss_discards_unsynced_writes_only() {
        let f = InMemoryFile::new();
        f.write_all_at(b"durable", 0).unwrap();
        f.sync_data().unwrap();
        f.write_all_at(b"!!!", 7).unwrap(); // unsynced
        assert_eq!(f.snapshot(), b"durable!!!");
        f.simulate_power_loss();
        // Only the synced prefix survives.
        assert_eq!(f.snapshot(), b"durable");
        assert_eq!(f.durable_snapshot(), b"durable");
    }

    #[test]
    fn from_bytes_is_already_durable() {
        let f = InMemoryFile::from_bytes(b"loaded".to_vec());
        f.write_all_at(b"X", 0).unwrap();
        f.simulate_power_loss();
        assert_eq!(f.snapshot(), b"loaded");
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
