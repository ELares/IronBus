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

    /// Reserves `len` bytes of backing storage for this file up front, so the appends that
    /// follow write into already-allocated space instead of growing it a block at a time.
    ///
    /// This is the cross-platform preallocation primitive (the four-primitive shim in
    /// `docs/PREALLOCATION.md`). It is a BEST-EFFORT optimization, never a correctness
    /// requirement: it does not change the bytes a reader sees, it does not advance the
    /// append cursor (the write position stays the logical length), and a backend that
    /// cannot reserve blocks is free to do less. Two payoffs on the slow flash an edge node
    /// runs on: the segment is placed as one contiguous extent (less fragmentation, faster
    /// sequential scan), and the steady-state append writes into already-allocated space so
    /// the per-commit `fdatasync` need not also persist a length-grow (less flash wear, lower
    /// commit latency).
    ///
    /// The reservation is NOT the durability barrier: the ack-implies-durable guarantee is
    /// always the commit `sync_data` (I2), independent of preallocation. A preallocated tail
    /// reads back as ZEROS, and a zero word is never a valid record-frame magic, so recovery's
    /// torn-tail scan stops at the first unwritten byte and truncates the unwritten tail
    /// exactly as it truncates a torn one (the zero-window end-of-data rule, the frozen #45
    /// fixture). A freshly preallocated, empty segment (header then zeros) therefore recovers
    /// as no records.
    ///
    /// The DEFAULT body is a no-op: a backend with no preallocation primitive degrades to
    /// today's grow-on-append, which is correct, only without the wear/latency benefit. The
    /// production [`StdFile`] overrides it with the per-OS KEEP-SIZE reservation (Linux
    /// `fallocate` with `FALLOC_FL_KEEP_SIZE`, macOS `fcntl(F_PREALLOCATE)`), which reserves
    /// blocks WITHOUT advancing the logical length, falling back to grow-on-append on a
    /// filesystem that supports none of them.
    ///
    /// # Errors
    /// Propagates an underlying IO error (for example `ENOSPC`, which an implementation may
    /// surface so a caller can route it to the disk-full overflow path at segment create
    /// time, rather than mid-append). The default no-op never errors.
    fn preallocate(&self, len: u64) -> io::Result<()> {
        let _ = len;
        Ok(())
    }
}

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

#[derive(Debug, Default)]
struct State {
    /// The current (possibly-unsynced) bytes.
    live: Vec<u8>,
    /// The bytes that survive a power loss. Its length is the durable file length, which
    /// `sync_data` (fdatasync) advances for data but never shrinks for a `set_len`
    /// truncation (length is metadata): only `sync_all` (fsync) makes a truncation
    /// durable. See the sync methods below and [`InMemoryFile`] for the contract.
    durable: Vec<u8>,
}

/// An in-memory [`RandomAccessFile`] for tests and the deterministic simulation.
///
/// It tracks two images: the `live` bytes and the `durable` bytes (a copy taken at
/// each sync). [`simulate_power_loss`](InMemoryFile::simulate_power_loss) discards
/// every write made since the last sync, so a simulation can verify that no
/// acknowledged-and-synced data is ever lost and that unsynced writes may vanish.
///
/// Durability contract (the fsync policy this models, #158): `sync_data` models
/// `fdatasync`, which flushes file data and any growth that data caused, but is not
/// required to persist a length-shrink from `set_len` (a truncation is metadata).
/// `sync_all` models `fsync`, a full barrier that persists data and the length. So a
/// `set_len` truncation becomes durable only after a `sync_all`; a truncation followed
/// by only `sync_data` is reverted by a simulated power loss, which restores the
/// pre-truncation length and the bytes beyond the truncation point. Truncation is the
/// only length change IronBus makes through `set_len` (recovery drops a torn tail, then
/// `sync_all`s, in `Log::recover`), and this model now enforces that pairing.
#[derive(Debug, Default)]
pub struct InMemoryFile {
    state: Mutex<State>,
    syncs: AtomicU64,
    /// The highest `len` ever passed to [`preallocate`](RandomAccessFile::preallocate), or `0` if
    /// it was never called. The in-memory backend models preallocation as a TRACKED RESERVATION,
    /// not a length change: a real `fallocate` reserves backing blocks without advancing the file's
    /// logical length or its bytes, and the deterministic simulation must mirror that so a
    /// preallocated active segment is byte-identical to a grow-on-append one (the determinism and
    /// crash-recovery sweeps stay green, and recovery's truncated-tail accounting is unchanged).
    /// A test reads this back via [`InMemoryFile::preallocated_to`] to assert the roll-size
    /// reservation was requested.
    preallocated_to: AtomicU64,
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
            preallocated_to: AtomicU64::new(0),
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

    /// Returns the highest `len` ever requested through
    /// [`preallocate`](RandomAccessFile::preallocate), or `0` if it was never called. The
    /// in-memory backend tracks the reservation request without changing the file's bytes or
    /// length (mirroring a real `fallocate`), so a test can assert a fresh active segment was
    /// preallocated to the roll size while the deterministic disk image stays byte-identical.
    #[must_use]
    pub fn preallocated_to(&self) -> u64 {
        self.preallocated_to.load(Ordering::SeqCst)
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

    /// Models a power loss with page-cache reorder/drop of the UNSYNCED tail (#164, #55).
    ///
    /// A real power cut guarantees only that fsync'd bytes survive: the not-yet-synced page-cache
    /// writes beyond the durable image may persist out of order, or partially, or not at all. The
    /// all-or-nothing [`simulate_power_loss`](InMemoryFile::simulate_power_loss) reverts the whole
    /// unsynced tail; this weaker, adversarial model keeps a seeded, arbitrary STRICT-PREFIX
    /// length of the unsynced region durable and drops (reverts to the durable image) the rest,
    /// so the surviving tail can end at any byte boundary, never past the last fsync'd byte. That
    /// is the worst case recovery must still survive: a torn-at-an-arbitrary-point unsynced tail.
    ///
    /// It is deterministic in `seed` (a xorshift step, no ambient randomness), so a failing case
    /// replays exactly. The durable prefix (every fsync'd byte) is ALWAYS retained, so this can
    /// never lose an acknowledged record; only the unsynced surplus is reordered/dropped. Returns
    /// the number of unsynced tail bytes that were KEPT durable by this power cut, so a caller can
    /// assert the on-disk byte state actually crossed the modelled boundary.
    ///
    /// [`simulate_power_loss`]: InMemoryFile::simulate_power_loss
    pub fn simulate_power_loss_reorder(&self, seed: u64) -> u64 {
        let mut guard = self.lock();
        let s = &mut *guard;
        let durable_len = s.durable.len();
        if s.live.len() <= durable_len {
            // No unsynced surplus (the live image is within the durable one): a power cut here is
            // the plain all-or-nothing revert, with nothing extra to keep.
            s.live.clone_from(&s.durable);
            return 0;
        }
        // The unsynced surplus is `live[durable_len..]`. A power cut may persist any strict prefix
        // of it; choose a seeded length in `[0, surplus)` (strictly fewer than all the unsynced
        // bytes, so the cut always drops at least one, modelling a real truncation of the tail).
        let surplus = (s.live.len() - durable_len) as u64;
        // xorshift64* so the choice is deterministic in `seed` with no external RNG.
        let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let mixed = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        // `mixed % surplus < surplus <= live.len()`, so it always fits a usize (the surplus is a
        // usize length to begin with). 0..surplus, so the cut never keeps the whole surplus.
        let kept = usize::try_from(mixed % surplus).unwrap_or(0);
        // Capture the unsynced prefix that survives BEFORE restoring the durable image, then rebuild
        // the post-cut file as the durable image (every fsync'd byte) plus exactly that kept prefix
        // of the unsynced surplus. Restoring the durable prefix first is load-bearing: only fsync'd
        // bytes are guaranteed durable, so an unsynced in-place edit inside the durable range must
        // NOT survive either, even though the appended surplus partly does.
        let surviving_tail = s.live[durable_len..durable_len + kept].to_vec();
        s.live.clone_from(&s.durable);
        s.live.extend_from_slice(&surviving_tail);
        // After a power cut the on-disk state IS what survived, so the durable image equals the
        // post-cut live image: a later `simulate_power_loss` then resurrects nothing, and the kept
        // unsynced prefix is now itself durable (the cut is the new ground truth).
        s.durable.clone_from(&s.live);
        kept as u64
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
        // fdatasync: flush data and any growth that data caused, but NOT a length shrink
        // from `set_len`. A truncation is metadata that a real fdatasync need not persist
        // (#158), so the durable image keeps its old length and the bytes beyond the new
        // live length until a `sync_all` makes the truncation durable. In-place edits and
        // writes that extend the file are data, so they DO become durable here.
        let mut guard = self.lock();
        let s = &mut *guard;
        if s.live.len() >= s.durable.len() {
            s.durable.clone_from(&s.live);
        } else {
            // An unsynced truncation: flush the surviving data in place, keep the old
            // durable length, and retain the un-truncated tail so a power loss can still
            // expose it (exactly until a `sync_all` persists the shorter length).
            s.durable[..s.live.len()].copy_from_slice(&s.live);
        }
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn sync_all(&self) -> io::Result<()> {
        // fsync: a full barrier. Data AND metadata (the file length, including a
        // `set_len` truncation) become durable, so the durable image equals the live one.
        let mut guard = self.lock();
        let s = &mut *guard;
        s.durable.clone_from(&s.live);
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.lock().live.len() as u64)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| invalid_input("length out of range"))?;
        self.lock().live.resize(len, 0);
        Ok(())
    }

    fn preallocate(&self, len: u64) -> io::Result<()> {
        // Model `fallocate`: RESERVE backing space without changing the file's bytes or its
        // logical length, so a preallocated active segment is byte-identical to a grow-on-append
        // one and the determinism / crash-recovery sweeps stay green. Only the requested reservation
        // is recorded (a high-water mark a test can read via `preallocated_to`).
        self.preallocated_to.fetch_max(len, Ordering::SeqCst);
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
    fn a_truncation_is_durable_only_after_sync_all() {
        // fdatasync (sync_data) does not persist a `set_len` shrink: a power loss restores
        // the pre-truncation length and the bytes beyond the new end. fsync (sync_all)
        // does persist it. This pins the fdatasync-vs-fsync metadata contract (#158).
        let f = InMemoryFile::from_bytes(b"abcdef".to_vec());
        f.sync_all().unwrap(); // the full 6-byte image is durable
        f.set_len(3).unwrap(); // truncate to "abc"
        assert_eq!(f.snapshot(), b"abc");
        f.sync_data().unwrap(); // fdatasync must NOT persist the truncation
        f.simulate_power_loss();
        assert_eq!(
            f.snapshot(),
            b"abcdef",
            "a truncation that was only fdatasync'd is reverted by a power loss"
        );
        assert_eq!(f.len().unwrap(), 6, "the pre-truncation length is restored");

        // Truncate again and this time fsync: now the shorter length is durable.
        f.set_len(3).unwrap();
        f.sync_all().unwrap();
        f.simulate_power_loss();
        assert_eq!(
            f.snapshot(),
            b"abc",
            "an fsync'd truncation survives a power loss"
        );
        assert_eq!(f.len().unwrap(), 3);
    }

    #[test]
    fn fdatasync_persists_an_in_place_edit_under_an_unsynced_truncation() {
        // A compound case: a data edit inside the surviving range is durable via fdatasync
        // even while a concurrent truncation is not, so the power-loss image keeps the
        // edit AND the un-truncated tail. This guards the model's per-byte faithfulness.
        let f = InMemoryFile::from_bytes(b"ABCDEF".to_vec());
        f.sync_all().unwrap();
        f.set_len(3).unwrap(); // live = "ABC" (truncation pending, not yet durable)
        f.write_all_at(b"X", 0).unwrap(); // edit within the surviving range: live = "XBC"
        f.sync_data().unwrap(); // fdatasync: the edit is durable, the truncation is not
        f.simulate_power_loss();
        assert_eq!(
            f.snapshot(),
            b"XBCDEF",
            "the edit survives via fdatasync, the truncated tail returns (length not synced)"
        );
    }

    #[test]
    fn power_loss_reorder_keeps_the_durable_prefix_and_a_strict_unsynced_prefix() {
        // The page-cache reorder/drop model (#164, #55): only fsync'd bytes are guaranteed
        // durable, so a power cut keeps the whole synced prefix and at most a STRICT prefix of the
        // unsynced surplus, dropping the rest. The durable bytes always survive; the kept count is
        // strictly fewer than the unsynced surplus (the cut always truncates at least one byte).
        let f = InMemoryFile::new();
        f.write_all_at(b"DURABLE", 0).unwrap();
        f.sync_data().unwrap(); // 7 synced bytes
        f.write_all_at(b"0123456789", 7).unwrap(); // 10 unsynced surplus bytes
        let kept = f.simulate_power_loss_reorder(0xDEAD_BEEF);
        assert!(
            kept < 10,
            "the cut keeps a STRICT prefix of the unsynced surplus"
        );
        let after = f.snapshot();
        assert_eq!(
            &after[..7],
            b"DURABLE",
            "every synced byte survived the power cut"
        );
        assert_eq!(
            after.len() as u64,
            7 + kept,
            "the file ends at the durable bytes plus the kept unsynced prefix"
        );
        // The surviving unsynced bytes are an in-order prefix of what was written (no invention).
        let kept = usize::try_from(kept).unwrap();
        assert_eq!(&after[7..], &b"0123456789"[..kept]);
    }

    #[test]
    fn power_loss_reorder_is_deterministic_in_the_seed() {
        // Same seed, same write history => byte-identical post-cut image, so a failing case
        // replays exactly. Two different seeds may keep different lengths (the model is varied).
        let build = || {
            let f = InMemoryFile::new();
            f.write_all_at(b"abcd", 0).unwrap();
            f.sync_all().unwrap();
            f.write_all_at(b"EFGHIJKLMN", 4).unwrap();
            f
        };
        let a = build();
        let b = build();
        let ka = a.simulate_power_loss_reorder(42);
        let kb = b.simulate_power_loss_reorder(42);
        assert_eq!(ka, kb);
        assert_eq!(
            a.snapshot(),
            b.snapshot(),
            "the reorder cut is deterministic in the seed"
        );
    }

    #[test]
    fn power_loss_reorder_with_no_unsynced_surplus_is_the_plain_revert() {
        // When the live image is within the durable one (no appended surplus), the reorder cut is
        // the all-or-nothing revert and keeps nothing extra.
        let f = InMemoryFile::from_bytes(b"synced".to_vec());
        f.write_all_at(b"X", 0).unwrap(); // an unsynced in-place edit, no length growth
        let kept = f.simulate_power_loss_reorder(1);
        assert_eq!(kept, 0);
        assert_eq!(
            f.snapshot(),
            b"synced",
            "the unsynced in-place edit did not survive"
        );
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

    #[test]
    fn preallocate_tracks_the_reservation_without_changing_bytes_or_length() {
        // The in-memory backend models `fallocate`: it RESERVES space (recorded so a test can
        // assert the roll-size request) but does NOT change the file's bytes or its logical length.
        // This is load-bearing: a preallocated active segment must be byte-identical to a
        // grow-on-append one, or the determinism and crash-recovery sweeps would diverge.
        let f = InMemoryFile::new();
        assert_eq!(f.preallocated_to(), 0, "never preallocated yet");
        f.write_all_at(b"hdr", 0).unwrap();
        f.preallocate(4096).unwrap();
        assert_eq!(f.preallocated_to(), 4096, "the reservation is tracked");
        // The bytes and the length are unchanged: only the 3 written bytes exist, no zero tail.
        assert_eq!(
            f.len().unwrap(),
            3,
            "preallocate does not advance the length"
        );
        assert_eq!(f.snapshot(), b"hdr", "preallocate writes no bytes");
        // It is a high-water mark: a smaller later reservation does not lower it.
        f.preallocate(100).unwrap();
        assert_eq!(f.preallocated_to(), 4096, "high-water, never lowered");
    }

    #[test]
    fn the_default_preallocate_is_a_no_op() {
        // A backend that does not override `preallocate` gets the trait default: a no-op that
        // never errors and changes nothing, so adding the method is non-breaking and IO-free-safe.
        struct Minimal(InMemoryFile);
        impl RandomAccessFile for Minimal {
            fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
                self.0.read_at(buf, offset)
            }
            fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
                self.0.write_all_at(buf, offset)
            }
            fn sync_data(&self) -> io::Result<()> {
                self.0.sync_data()
            }
            fn sync_all(&self) -> io::Result<()> {
                self.0.sync_all()
            }
            fn len(&self) -> io::Result<u64> {
                self.0.len()
            }
            fn set_len(&self, len: u64) -> io::Result<()> {
                self.0.set_len(len)
            }
            // No `preallocate` override: the trait default (no-op) is used.
        }
        let f = Minimal(InMemoryFile::new());
        f.write_all_at(b"ok", 0).unwrap();
        // The default no-op succeeds and leaves the bytes and length untouched.
        f.preallocate(1 << 20).unwrap();
        assert_eq!(f.len().unwrap(), 2);
        let mut buf = [0u8; 2];
        f.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"ok");
    }
}

/// A production [`RandomAccessFile`] backed by an OS file, using cursor-free
/// positioned IO (`pread`/`pwrite`) so concurrent readers never contend on a shared
/// file cursor. Available on Unix targets (the v1 production targets are Linux musl
/// and macOS); Windows is a v1 non-goal and gets only the trait and [`InMemoryFile`].
#[cfg(unix)]
#[derive(Debug)]
pub struct StdFile {
    file: std::fs::File,
}

#[cfg(unix)]
impl StdFile {
    /// Opens an existing file for reading and writing.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    pub fn open(path: &std::path::Path) -> io::Result<StdFile> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        Ok(StdFile { file })
    }

    /// Creates a file for reading and writing, TRUNCATING any existing file at the
    /// path. This is destructive: for a durable segment that must never clobber an
    /// existing one, use [`StdFile::create_new`]. Intended for scratch and tests.
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    pub fn create(path: &std::path::Path) -> io::Result<StdFile> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(StdFile { file })
    }

    /// Creates a new file for reading and writing, failing with
    /// [`io::ErrorKind::AlreadyExists`] if the path already exists (`O_EXCL`). This is
    /// the safe primitive for creating a durable segment: it can never clobber an
    /// existing one.
    ///
    /// # Errors
    /// Returns `AlreadyExists` if the path exists, or propagates the underlying IO error.
    pub fn create_new(path: &std::path::Path) -> io::Result<StdFile> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        Ok(StdFile { file })
    }

    /// Wraps an already-open file, for a preallocated or handed-off descriptor. The
    /// caller is responsible for opening it read and write.
    #[must_use]
    pub fn from_file(file: std::fs::File) -> StdFile {
        StdFile { file }
    }
}

#[cfg(unix)]
impl RandomAccessFile for StdFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(&self.file, buf, offset)
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::write_all_at(&self.file, buf, offset)
    }

    // Durability barrier (the load-bearing guarantee behind ack-implies-durable, I2).
    //
    // These delegate straight to `std`, and that is deliberate, not an oversight (#153):
    // - Linux (the production target, musl on ext4/f2fs): `sync_data` is `fdatasync(2)`
    //   and `sync_all` is `fsync(2)`, both true write-barriers to the device.
    // - Apple (a developer and CI target): `std` maps BOTH `sync_data` and `sync_all` to
    //   `fcntl(fd, F_FULLFSYNC)`, which flushes the drive's volatile write cache to
    //   permanent storage. Plain `fsync(2)` on Darwin does NOT issue that barrier, so the
    //   correct path is exactly the `F_FULLFSYNC` that `std` already performs; wrapping
    //   our own `fcntl` here would only duplicate the barrier. Verified against the
    //   `std::sys::fs::unix` source (`os_fsync`/`os_datasync`, `target_vendor = \"apple\"`).
    //
    // `std` issues `F_FULLFSYNC` unconditionally, with no `ENOTSUP` fallback to a weaker
    // `fsync`. We rely on that on purpose: on the rare filesystem that cannot honour the
    // barrier, surfacing the error (which the engine turns into a frozen writer) and
    // refusing to ack is the fail-closed outcome a durability system wants, never a
    // silent downgrade that would let an ack outrun a real flush.
    fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }

    fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }

    // Preallocation (the `docs/PREALLOCATION.md` shim). Reserve `len` backing blocks for the
    // segment up front so the steady-state appends write into already-allocated space. This is a
    // BEST-EFFORT optimization: the fallback ladder bottoms out at today's grow-on-append, which is
    // correct, only without the wear/latency win. It never advances the append cursor and never
    // changes a byte a reader sees; the preallocated tail is zeros that recovery's torn-tail scan
    // truncates exactly as it would a torn tail (the frozen #45 zero-window fixture).
    fn preallocate(&self, len: u64) -> io::Result<()> {
        preallocate_file(&self.file, len)
    }
}

/// Reserves `len` backing blocks for `file`, with the per-OS reservation recipe and a fallback
/// ladder that bottoms out at grow-on-append (the `docs/PREALLOCATION.md` shim, primitive (a)).
///
/// CRUCIAL invariant: the reservation reserves blocks WITHOUT advancing the file's LOGICAL length.
/// The append cursor is the logical end of data, and recovery and the offline scan tools find the
/// end of data from `file.len()`; if preallocation grew the logical length to `len`, every reader
/// would see a 64 MiB zero tail and (correctly but needlessly) report it as a torn/zero window. So
/// each OS uses the keep-size form: Linux `fallocate` with `FALLOC_FL_KEEP_SIZE`, macOS
/// `F_PREALLOCATE` alone (which never advances the size). The appends then extend the logical
/// length the normal way (a positioned write past the current end), landing in already-reserved
/// blocks.
///
/// - **Linux**: `fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, len)` reserves real extents on ext4/f2fs/xfs
///   (the edge targets) and keeps the apparent size. On `EOPNOTSUPP`/`ENOSYS` (a filesystem with no
///   allocation support, e.g. some tmpfs) it falls back to grow-on-append.
/// - **Apple**: `fcntl(fd, F_PREALLOCATE)` requesting contiguous blocks (`F_ALLOCATECONTIG`) then
///   any blocks (`F_ALLOCATEALL`); it reserves blocks and never advances the logical size, so no
///   `ftruncate` pairing is used. On `ENOTSUP` it falls back to grow-on-append.
/// - **Any other Unix**: no portable keep-size reservation syscall, so it is grow-on-append (a
///   no-op here).
///
/// `len == 0` is a no-op (nothing to reserve). The reservation is never the durability barrier: the
/// commit `sync_data` (I2) is, independent of this call. A genuine `ENOSPC` is surfaced so the
/// caller can route a create-time out-of-space to the overflow path rather than discover it
/// mid-append.
#[cfg(unix)]
fn preallocate_file(file: &std::fs::File, len: u64) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        preallocate_linux(file, len)
    }
    #[cfg(target_vendor = "apple")]
    {
        preallocate_apple(file, len)
    }
    // Any other Unix (no portable keep-size reservation primitive): grow-on-append, the bottom rung.
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        let _ = (file, len);
        Ok(())
    }
}

/// Linux: `fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, len)` reserves real extents while KEEPING the
/// apparent file size (so the logical length still grows only with appends). A filesystem that
/// cannot allocate (`EOPNOTSUPP`/`ENOSYS`) degrades to grow-on-append; any other error (e.g.
/// `ENOSPC`) is surfaced so a create-time out-of-space is not masked.
#[cfg(target_os = "linux")]
fn preallocate_linux(file: &std::fs::File, len: u64) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let len =
        libc::off_t::try_from(len).map_err(|_| invalid_input("preallocate length out of range"))?;
    // SAFETY: `fallocate` is a plain libc syscall wrapper (a foreign function, not a memory-unsafe
    // operation). `fd` is a valid, open, writable descriptor owned by `file` and outlives the call;
    // the mode flag and the two `off_t` arguments are passed by value. It reads and writes no
    // process memory and cannot read or write past any buffer (there is none); the only state it
    // touches is the kernel's block map for `fd`. `FALLOC_FL_KEEP_SIZE` keeps the logical size
    // unchanged. This is the one justified FFI call on Linux (`docs/PREALLOCATION.md`, primitive
    // (a)).
    #[allow(unsafe_code)]
    let rc = unsafe { libc::fallocate(fd, libc::FALLOC_FL_KEEP_SIZE, 0, len) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        // The filesystem does not support allocation: fall back to grow-on-append (still correct).
        Some(libc::EOPNOTSUPP | libc::ENOSYS) => Ok(()),
        // A real failure (e.g. ENOSPC): surface it so a create-time out-of-space is not masked.
        _ => Err(err),
    }
}

/// Apple: `fcntl(fd, F_PREALLOCATE)` reserves blocks (contiguous if possible) WITHOUT advancing the
/// logical size, which is exactly the keep-size reservation we want (no `ftruncate` pairing, so the
/// logical length still grows only with appends). If `F_PREALLOCATE` is unsupported (`ENOTSUP`),
/// fall back to grow-on-append.
#[cfg(target_vendor = "apple")]
fn preallocate_apple(file: &std::fs::File, len: u64) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let want =
        libc::off_t::try_from(len).map_err(|_| invalid_input("preallocate length out of range"))?;
    // Reserve blocks contiguously if we can, otherwise allow a fragmented reservation. `fst_length`
    // is the number of bytes to allocate from `fst_offset` (0 = the start of the file).
    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATECONTIG,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: want,
        fst_bytesalloc: 0,
    };
    // SAFETY: `fcntl` is a plain libc syscall wrapper (a foreign function, not a memory-unsafe
    // operation). `fd` is a valid, open, writable descriptor owned by `file` and outlives the call.
    // `F_PREALLOCATE` reads and writes the single fully-owned, stack-allocated `fstore_t` whose
    // address we pass; the kernel cannot read or write past that struct. This is the one justified
    // FFI call on Apple (`docs/PREALLOCATION.md`, primitive (a)).
    #[allow(unsafe_code)]
    let contiguous = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut store) };
    if contiguous != -1 {
        return Ok(());
    }
    // Could not place it contiguously: retry allowing any blocks.
    store.fst_flags = libc::F_ALLOCATEALL;
    store.fst_bytesalloc = 0;
    // SAFETY: identical to the call above; same valid `fd` and same fully-owned `fstore_t`.
    #[allow(unsafe_code)]
    let any = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut store) };
    if any != -1 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    // F_PREALLOCATE unsupported on this filesystem: fall back to grow-on-append (still correct, only
    // without the contiguity win). Any other error is surfaced.
    if err.raw_os_error() == Some(libc::ENOTSUP) {
        Ok(())
    } else {
        Err(err)
    }
}

/// Fsyncs the directory at `path` so a newly created, renamed, or removed entry in
/// it is crash-durable. Without this, a power loss after creating a segment file but
/// before syncing its directory can leave the file absent on restart.
///
/// Ordering: call this AFTER the new file's own `sync_all`, so the create path is
/// fsync-the-file, then full-fsync-the-parent-directory, then ack.
///
/// # Errors
/// Propagates the underlying IO error.
#[cfg(unix)]
pub fn sync_dir(path: &std::path::Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(all(test, unix))]
mod std_file_tests {
    use super::*;

    #[test]
    fn stdfile_roundtrip_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.log");
        let f = StdFile::create(&path).unwrap();
        f.write_all_at(b"hello world", 0).unwrap();
        f.sync_data().unwrap();
        let mut buf = [0u8; 11];
        f.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"hello world");
        assert_eq!(f.len().unwrap(), 11);
        drop(f);
        // Reopen and verify the bytes persisted.
        let g = StdFile::open(&path).unwrap();
        let mut b2 = [0u8; 5];
        assert_eq!(g.read_at(&mut b2, 6).unwrap(), 5);
        assert_eq!(&b2, b"world");
    }

    #[test]
    fn stdfile_set_len_truncate_and_extend() {
        let dir = tempfile::tempdir().unwrap();
        let f = StdFile::create(&dir.path().join("x")).unwrap();
        f.write_all_at(b"abcdef", 0).unwrap();
        f.set_len(3).unwrap();
        assert_eq!(f.len().unwrap(), 3);
        f.set_len(5).unwrap();
        let mut buf = [9u8; 5];
        f.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, &[b'a', b'b', b'c', 0, 0]);
    }

    #[test]
    fn stdfile_read_past_end_is_zero() {
        let dir = tempfile::tempdir().unwrap();
        let f = StdFile::create(&dir.path().join("e")).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 0);
    }

    #[test]
    fn create_new_refuses_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg");
        let _f = StdFile::create_new(&path).unwrap();
        let err = StdFile::create_new(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn concurrent_positioned_reads_are_race_free() {
        let dir = tempfile::tempdir().unwrap();
        let f = StdFile::create(&dir.path().join("seg")).unwrap();
        f.write_all_at(b"0123456789", 0).unwrap();
        f.sync_data().unwrap();
        let f = std::sync::Arc::new(f);
        std::thread::scope(|sc| {
            for k in 0u64..8 {
                let f = std::sync::Arc::clone(&f);
                sc.spawn(move || {
                    let off = k % 7;
                    let start = usize::try_from(off).unwrap();
                    for _ in 0..200 {
                        let mut buf = [0u8; 3];
                        f.read_exact_at(&mut buf, off).unwrap();
                        assert_eq!(&buf, &b"0123456789"[start..start + 3]);
                    }
                });
            }
        });
    }

    #[test]
    fn sync_dir_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let f = StdFile::create(&dir.path().join("f")).unwrap();
        f.sync_all().unwrap();
        sync_dir(dir.path()).unwrap();
    }

    // On Apple targets `std` maps both `sync_data` and `sync_all` to
    // `fcntl(fd, F_FULLFSYNC)` (the device-cache flush, not a plain `fsync`). This
    // exercises that durability-barrier path on the macOS CI runner and asserts it
    // succeeds on a regular file and the bytes survive a close/reopen. It cannot, in CI,
    // prove the physical platter flush happened (that needs a real power cut, which #133
    // and the device gates own); it pins that the `F_FULLFSYNC` syscall path is taken and
    // does not error, so a regression that stopped issuing the barrier here would be
    // caught the moment the call started failing or the round-trip broke (#153).
    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_durable_sync_takes_the_full_fsync_barrier_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("barrier.log");
        let f = StdFile::create(&path).unwrap();
        f.write_all_at(b"durable", 0).unwrap();
        // Both durable-sync entry points reach `F_FULLFSYNC` on Apple; both must succeed.
        f.sync_data().unwrap();
        f.sync_all().unwrap();
        drop(f);
        let g = StdFile::open(&path).unwrap();
        let mut buf = [0u8; 7];
        g.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(&buf, b"durable");
    }

    #[test]
    fn preallocate_reserves_real_blocks_on_a_supporting_fs() {
        // On the Unix CI targets (Linux musl, macOS) the per-OS reservation reserves REAL backing
        // blocks. We assert the on-disk block count (`st_blocks`, in 512-byte units) covers the
        // requested length, the syscall path that actually reserves space. This is the
        // "preallocate reserves the space" tooth (the in-memory backend tracks the request; this
        // proves the production file truly reserves blocks).
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prealloc.log");
        let f = StdFile::create(&path).unwrap();
        let want: u64 = 256 * 1024; // 256 KiB, comfortably more than a couple of blocks.
        f.preallocate(want).unwrap();
        f.sync_all().unwrap();
        let blocks = std::fs::metadata(&path).unwrap().blocks();
        // `blocks` counts 512-byte units; a real reservation covers the requested bytes. Allow the
        // filesystem a little slack but require it to be in the right order of magnitude (not the 0
        // a no-op grow-on-append would leave on a still-empty file).
        assert!(
            blocks * 512 >= want,
            "preallocate should reserve at least {want} bytes of blocks, got {} bytes",
            blocks * 512
        );
    }

    #[test]
    fn preallocate_keeps_the_logical_length_and_appends_round_trip() {
        // The keep-size reservation reserves blocks WITHOUT advancing the logical length: the
        // header written at 0 is intact, the logical length stays at the written length (no zero
        // tail a reader or the offline scan tools would see), and an append into the reserved range
        // round-trips. This is the load-bearing property: the logical length grows only with
        // appends, so recovery and the offline `dump`/`scrub` tools find the end of data unchanged.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.log");
        let f = StdFile::create(&path).unwrap();
        f.write_all_at(b"HEADER", 0).unwrap();
        f.preallocate(64 * 1024).unwrap();
        f.sync_all().unwrap();
        // The header is intact and the LOGICAL length is unchanged (the reservation grew no bytes).
        let mut hdr = [0u8; 6];
        f.read_exact_at(&mut hdr, 0).unwrap();
        assert_eq!(&hdr, b"HEADER");
        assert_eq!(
            f.len().unwrap(),
            6,
            "keep-size preallocation does not advance the logical length"
        );
        // A read past the logical end is a real EOF, exactly as before preallocation (no zero tail).
        let mut buf = [0u8; 4];
        assert_eq!(
            f.read_at(&mut buf, 6).unwrap(),
            0,
            "no zero tail past the end"
        );
        // An append extends the logical length into the reserved range and round-trips.
        f.write_all_at(b"record", 6).unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.len().unwrap(), 12);
        let mut back = [0u8; 12];
        f.read_exact_at(&mut back, 0).unwrap();
        assert_eq!(&back, b"HEADERrecord");
    }

    #[test]
    fn preallocate_zero_is_a_no_op() {
        // A zero-length reservation has nothing to reserve and must not error or touch the file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("z.log");
        let f = StdFile::create(&path).unwrap();
        f.preallocate(0).unwrap();
        assert_eq!(f.len().unwrap(), 0);
    }
}

/// Sharing a file behind a reference forwards to the inner implementation, so the
/// single writer and the lock-free readers can hold the same file.
impl<F: RandomAccessFile + ?Sized> RandomAccessFile for &F {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        (**self).read_at(buf, offset)
    }
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        (**self).write_all_at(buf, offset)
    }
    fn sync_data(&self) -> io::Result<()> {
        (**self).sync_data()
    }
    fn sync_all(&self) -> io::Result<()> {
        (**self).sync_all()
    }
    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        (**self).set_len(len)
    }
    fn preallocate(&self, len: u64) -> io::Result<()> {
        (**self).preallocate(len)
    }
}

/// Sharing a file behind an [`std::sync::Arc`] forwards to the inner implementation.
impl<F: RandomAccessFile + ?Sized> RandomAccessFile for std::sync::Arc<F> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        (**self).read_at(buf, offset)
    }
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        (**self).write_all_at(buf, offset)
    }
    fn sync_data(&self) -> io::Result<()> {
        (**self).sync_data()
    }
    fn sync_all(&self) -> io::Result<()> {
        (**self).sync_all()
    }
    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        (**self).set_len(len)
    }
    fn preallocate(&self, len: u64) -> io::Result<()> {
        (**self).preallocate(len)
    }
}
