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
    /// # Contract
    /// On `Ok(())` EVERY byte of `buf` has been written. An implementation must only
    /// WRITE `buf` (never read it) and must not return `Ok` with any byte left unwritten:
    /// [`SegmentReader::read_into_fresh`](crate::segment) reads straight into uninitialized
    /// reserved capacity and relies on both halves of this contract for soundness. The
    /// default implementation upholds it (it loops issuing positioned reads until the buffer
    /// is full or errors); any override must too.
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
    /// requirement: it does not change any byte that was ever written, it never SHRINKS the
    /// file, it does not advance the append cursor (the writer's position is tracked by the
    /// layers above, not derived from the file length), and a backend that cannot reserve
    /// blocks is free to do less. The production [`StdFile`] does two things:
    ///
    /// 1. Reserves backing blocks (Linux `fallocate` with `FALLOC_FL_KEEP_SIZE`, macOS
    ///    `fcntl(F_PREALLOCATE)`), so the segment is placed as one contiguous extent (less
    ///    fragmentation, faster sequential scan) and appends never grow the block map.
    /// 2. ADVANCES the LOGICAL length up to `len` (`set_len` up, never down), so every
    ///    subsequent append lands INSIDE the logical size: the per-commit `fdatasync` no longer
    ///    journals an inode-size (`i_size`) update on every commit. (It is NOT metadata-free:
    ///    on ext4 the first append into each reserved-but-unwritten extent still journals that
    ///    extent's one-time unwritten→written state conversion — both probe arms paid those —
    ///    so what the extension eliminates is precisely the EVERY-COMMIT `i_size` update.
    ///    Measured on the ext4/virtio bench VM: ~13us / 7% p50 and ~26us / 10% p99 saved per
    ///    fdatasync versus the keep-size form whose every append grew `i_size`.)
    ///
    /// The logical extension makes the unwritten remainder READ BACK AS ZEROS, and a zero word
    /// is never a valid record-frame magic, so recovery's torn-tail scan stops at the first
    /// unwritten byte and truncates the unwritten tail (the zero-window end-of-data rule, the
    /// frozen #45 fixture); recovery treats a provably all-zero tail as never-written space
    /// (truncated silently, not reported as loss), and the seal path truncates the file back
    /// down to the footer end (with the documented `set_len`-shrink-needs-`sync_all` pairing)
    /// so a SEALED segment's on-disk image is byte-identical to a never-preallocated one and
    /// footer discovery at the file end still works. A freshly preallocated, empty segment
    /// (header then zeros) recovers as no records.
    ///
    /// The reservation is NOT the durability barrier: the ack-implies-durable guarantee is
    /// always the commit `sync_data` (I2), independent of preallocation, and losing the
    /// logical extension in a crash merely shortens the file back toward its data.
    ///
    /// The DEFAULT body is a no-op: a backend with no preallocation primitive degrades to
    /// today's grow-on-append, which is correct, only without the wear/latency benefit. The
    /// deterministic-simulation [`InMemoryFile`] deliberately only TRACKS the request (see its
    /// docs); the ephemeral in-RAM backend keeps the no-op (it has no fsync cost to save).
    ///
    /// # Errors
    /// Propagates an underlying IO error (for example `ENOSPC`, which an implementation may
    /// surface so a caller can route it to the disk-full overflow path at segment create
    /// time, rather than mid-append). The default no-op never errors.
    fn preallocate(&self, len: u64) -> io::Result<()> {
        let _ = len;
        Ok(())
    }

    /// A borrowed OS file descriptor to splice a STORED byte range straight from the page cache to a
    /// socket with Linux `sendfile(2)` — the zero-copy Tier-S consume path (#1034 / #658) — or `None`
    /// when this backend has no descriptor safe to splice from. `None` is the always-available signal
    /// to take the ordinary copy path; it is never a correctness compromise, so a backend that cannot
    /// (or should not) be spliced simply keeps the default.
    ///
    /// The default is `None`; a backend opts IN by returning its descriptor. The in-memory and
    /// ephemeral backends keep the default (no OS fd), and the `O_DIRECT` [`DirectFile`] returns `None`
    /// on purpose (its page-cache coherence model makes a `sendfile` splice unsafe to assume — see its
    /// override). Only the buffered production file ([`StdFile`], and the buffered arm of
    /// [`MaybeDirectFile`]) returns `Some`.
    ///
    /// The returned descriptor BORROWS `self`: the caller MUST keep this file (or the reader owning it)
    /// alive for the whole splice, because the fd must stay open while the kernel reads it. The method
    /// exists only on unix (a `BorrowedFd` is unix-only; the disk backend is a v1 non-goal off unix).
    #[cfg(unix)]
    fn splice_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        None
    }
}

/// Returns one past the LAST non-zero byte of `file` in `[start, end)`, or `start` when the
/// whole region is zero. Scans BACKWARD in bounded 4 KiB chunks, so a roll-size region costs no
/// large allocation (and, on a filesystem with unwritten-extent tracking, the zero portion costs
/// no device IO: a preallocated hole reads back as zeros straight from the kernel).
///
/// This is the shared ZERO-TAIL BOUNDING rule for a preallocated, logically-extended active
/// segment (`docs/PREALLOCATION.md`): the tail past the durable valid prefix may be up to a roll
/// size of never-written zeros, so both recovery ([`Log::recover`](crate::log::Log)) and the
/// offline inspector ([`OfflineReader`](crate::offline::OfflineReader)) bound what they REPORT
/// (loss events, quarantine capture) at one past the tail's last non-zero byte — the end of the
/// bytes that were ever plausibly written. An all-zero tail (`start` returned) is unwritten
/// space, not loss. The bound can exclude trailing zero bytes of a genuinely torn frame (a frame
/// whose last written bytes happen to be zero); that under-report of informationless zeros is
/// deliberate and bounded, whereas reporting up to the FILE length would claim a roll size of
/// "loss" per event, flood quarantine with near-all-zero blobs, and trip the I3 per-event cap on
/// any segment size above it.
///
/// # Errors
/// Propagates the underlying IO error from the positioned reads.
pub(crate) fn last_nonzero_end<F: RandomAccessFile>(
    file: &F,
    start: u64,
    end: u64,
) -> io::Result<u64> {
    let mut hi = end;
    let mut buf = [0u8; 4096];
    while hi > start {
        let lo = hi.saturating_sub(buf.len() as u64).max(start);
        // `hi - lo` is at most the 4 KiB buffer, so the conversion never truncates.
        let want = usize::try_from(hi - lo).unwrap_or(buf.len());
        let chunk = &mut buf[..want];
        file.read_exact_at(chunk, lo)?;
        if let Some(i) = chunk.iter().rposition(|&b| b != 0) {
            return Ok(lo + i as u64 + 1);
        }
        hi = lo;
    }
    Ok(start)
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
    /// The byte ranges of `live` written since the last sync: sorted, disjoint, half-open.
    /// `sync_data` copies ONLY these into the durable image (#456) instead of cloning the whole
    /// file, so an in-memory group commit costs O(bytes appended since the last sync) like a real
    /// fdatasync, not O(file). Soundness invariant: every byte of `live` that differs from the
    /// corresponding `durable` byte is inside a dirty range (every `live` mutation marks its
    /// range, including a zero-fill growth gap; the power-loss models rewrite `live` from the
    /// durable image and clear the list). For the append-only log writer this is almost always a
    /// single coalesced range.
    dirty: Vec<(usize, usize)>,
}

/// Records `[a, b)` as written-since-last-sync, keeping `dirty` sorted, disjoint, and coalesced.
/// The fast path is the log writer's append pattern (the new range starts at or inside the last
/// one); an arbitrary overlap falls back to a sort-and-merge pass.
fn mark_dirty(dirty: &mut Vec<(usize, usize)>, a: usize, b: usize) {
    if a >= b {
        return;
    }
    match dirty.last_mut() {
        None => dirty.push((a, b)),
        // At or after the last range's start: earlier ranges all end before it, so the new range
        // either merges with the last one or goes after it. O(1), the append fast path.
        Some(last) if a >= last.0 => {
            if a <= last.1 {
                last.1 = last.1.max(b);
            } else {
                dirty.push((a, b));
            }
        }
        // A write behind the frontier (a header patch, a compaction rewrite): general coalesce.
        Some(_) => {
            dirty.push((a, b));
            dirty.sort_unstable();
            let mut merged: Vec<(usize, usize)> = Vec::with_capacity(dirty.len());
            for &(x, y) in dirty.iter() {
                if let Some(m) = merged.last_mut() {
                    if x <= m.1 {
                        m.1 = m.1.max(y);
                        continue;
                    }
                }
                merged.push((x, y));
            }
            *dirty = merged;
        }
    }
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
    /// not a length change. The production [`StdFile`] now ALSO advances the logical length up to
    /// the reservation (so its per-commit fdatasync carries no `i_size` update), but mirroring that here
    /// would materialize `max_segment_bytes` of zeros in RAM for every active segment across every
    /// simulation and server test (and double again in the durable image), so the simulation keeps
    /// the compact reservation-only model: a preallocated active segment stays byte-identical to a
    /// grow-on-append one, the determinism and crash-recovery sweeps stay green, and the
    /// extended-zero-tail recovery behavior is pinned by explicit tests and the frozen #45
    /// zero-window fixture, which write the zero tail out for real. A test reads this back via
    /// [`InMemoryFile::preallocated_to`] to assert the roll-size reservation was requested.
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
                dirty: Vec::new(),
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
        // The unsynced writes are gone with the live image: live == durable again.
        s.dirty.clear();
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
        s.dirty.clear();
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
        let mut guard = self.lock();
        let s = &mut *guard;
        let old_len = s.live.len();
        if old_len < end {
            s.live.resize(end, 0);
        }
        s.live[off..end].copy_from_slice(buf);
        // The zero-fill gap of a past-EOF write is new data too: a real fdatasync persists the
        // allocated zeros, so the dirty range starts at the old length when the write grew the file.
        mark_dirty(&mut s.dirty, off.min(old_len), end);
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
        if s.live.len() > s.durable.len() {
            // Data grew the file: the durable length advances with it (the grown range is in a
            // dirty range, so the zeros materialized here are overwritten just below).
            s.durable.resize(s.live.len(), 0);
        }
        // Copy ONLY the bytes written since the last sync (#456). Outside the dirty ranges, live
        // and durable already agree (the soundness invariant on `State::dirty`), so this is
        // byte-for-byte the old clone-the-whole-file image at O(written) cost. Under an unsynced
        // truncation the ranges were clamped by `set_len`, the durable image keeps its old length,
        // and the un-truncated durable tail survives so a power loss can still expose it (exactly
        // until a `sync_all` persists the shorter length).
        for &(a, b) in &s.dirty {
            debug_assert!(b <= s.live.len(), "dirty range past live length");
            let b = b.min(s.live.len());
            let a = a.min(b);
            s.durable[a..b].copy_from_slice(&s.live[a..b]);
        }
        s.dirty.clear();
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn sync_all(&self) -> io::Result<()> {
        // fsync: a full barrier. Data AND metadata (the file length, including a
        // `set_len` truncation) become durable, so the durable image equals the live one.
        let mut guard = self.lock();
        let s = &mut *guard;
        s.durable.clone_from(&s.live);
        s.dirty.clear();
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.lock().live.len() as u64)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| invalid_input("length out of range"))?;
        let mut guard = self.lock();
        let s = &mut *guard;
        let old_len = s.live.len();
        s.live.resize(len, 0);
        if len > old_len {
            // Growth zero-fills: new live bytes that must reach the durable image at the next sync
            // (matching the old clone-everything image, which carried the grown zeros and length).
            mark_dirty(&mut s.dirty, old_len, len);
        } else {
            // Truncation: the dropped bytes no longer exist in `live`, so no range may reach past
            // the new length (the durable image keeps its own longer tail until `sync_all`).
            s.dirty.retain_mut(|r| {
                if r.0 >= len {
                    return false;
                }
                r.1 = r.1.min(len);
                r.0 < r.1
            });
        }
        Ok(())
    }

    fn preallocate(&self, len: u64) -> io::Result<()> {
        // Model the RESERVATION half only: record the request without changing the file's bytes or
        // its logical length, so a preallocated active segment is byte-identical to a grow-on-append
        // one and the determinism / crash-recovery sweeps stay green. The production `StdFile` also
        // extends the logical length; the simulation deliberately does not (see the field docs on
        // `preallocated_to` for why), and the zero-tail recovery behavior that extension creates is
        // pinned by tests that write the zero tail explicitly. Only the requested reservation is
        // recorded (a high-water mark a test can read via `preallocated_to`).
        self.preallocated_to.fetch_max(len, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn dirty_range_sync_matches_the_clone_everything_durable_image() {
        // The incremental sync (#456) must be observationally identical to the old
        // clone-the-whole-file `sync_data`. Each step mutates the live image, syncs, and asserts
        // the durable snapshot is exactly what the old semantics produced, through the tricky
        // cases: an in-place edit inside the synced prefix, an append, a past-EOF write with a
        // zero-fill gap, an unsynced truncation (durable keeps its longer tail), a write after
        // the truncation, the power-loss revert clearing pending writes, and the sync_all length
        // barrier.
        let f = InMemoryFile::new();
        f.write_all_at(b"AAAAAAAAAA", 0).unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.durable_snapshot(), b"AAAAAAAAAA");
        // An in-place edit inside the already-synced prefix.
        f.write_all_at(b"B", 2).unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.durable_snapshot(), b"AABAAAAAAA");
        // A past-EOF write: the zero-fill gap (10..12) is data and becomes durable with it.
        f.write_all_at(b"CC", 12).unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.durable_snapshot(), b"AABAAAAAAA\x00\x00CC");
        // An unsynced truncation + fdatasync: durable keeps its OLD length and un-truncated tail
        // (a shrink is metadata; only sync_all persists it), exactly the old prefix-copy image.
        f.set_len(4).unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.durable_snapshot(), b"AABAAAAAAA\x00\x00CC");
        // A write after the truncation flushes in place under the longer durable tail.
        f.write_all_at(b"D", 1).unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.durable_snapshot(), b"ADBAAAAAAA\x00\x00CC");
        assert_eq!(f.snapshot(), b"ADBA");
        // sync_all is the full barrier: the truncation becomes durable.
        f.sync_all().unwrap();
        assert_eq!(f.durable_snapshot(), b"ADBA");
        // Unsynced writes vanish at a power loss and must NOT resurface at the next sync.
        f.write_all_at(b"EEEE", 4).unwrap();
        f.simulate_power_loss();
        assert_eq!(f.snapshot(), b"ADBA");
        f.sync_data().unwrap();
        assert_eq!(f.durable_snapshot(), b"ADBA");
        // A behind-the-frontier write coalesces with an append (the slow merge path).
        f.write_all_at(b"FF", 6).unwrap();
        f.write_all_at(b"G", 0).unwrap();
        f.sync_data().unwrap();
        assert_eq!(f.durable_snapshot(), b"GDBA\x00\x00FF");
    }

    #[test]
    fn last_nonzero_end_bounds_a_zero_tail_at_the_last_written_byte() {
        // The zero-tail bounding rule recovery and the offline inspector share: the returned
        // end is one past the LAST non-zero byte of the region, `start` for an all-zero region,
        // exact across the backward 4 KiB chunk boundaries.
        let f = InMemoryFile::new();
        // An all-zero region (a pure preallocated extension) bounds to `start`.
        f.set_len(3 * 4096 + 17).unwrap();
        assert_eq!(last_nonzero_end(&f, 100, f.len().unwrap()).unwrap(), 100);
        // A single non-zero byte in the FIRST chunk of the region: found across the backward
        // chunk walk (two full zero chunks are scanned and skipped first).
        f.write_all_at(&[0xAB], 334).unwrap();
        assert_eq!(last_nonzero_end(&f, 100, f.len().unwrap()).unwrap(), 335);
        // A later non-zero byte wins (the LAST one bounds), including exactly on a chunk edge.
        f.write_all_at(&[0x01], 2 * 4096 - 1).unwrap();
        assert_eq!(
            last_nonzero_end(&f, 100, f.len().unwrap()).unwrap(),
            2 * 4096
        );
        // A non-zero byte at `start` itself is inside the region; one just below is not.
        assert_eq!(last_nonzero_end(&f, 334, 4096).unwrap(), 335);
        assert_eq!(last_nonzero_end(&f, 335, 4096).unwrap(), 335);
        // An empty region is `start`.
        assert_eq!(last_nonzero_end(&f, 42, 42).unwrap(), 42);
    }

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

    #[test]
    fn ephemeral_read_write_set_len_match_the_in_memory_file() {
        // The ephemeral backend's read/write/set_len/len contract is byte-for-byte the in-memory
        // file's, only without the durable bookkeeping. Mirror the core round-trips so a regression
        // that diverged the production in-RAM path from the simulation one is caught.
        let f = EphemeralFile::new();
        assert!(f.is_empty().unwrap());
        f.write_all_at(b"hello", 0).unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(f.len().unwrap(), 5);
        assert_eq!(f.snapshot(), b"hello");
        // A past-EOF write zero-fills the gap, exactly like InMemoryFile.
        f.write_all_at(b"ab", 7).unwrap();
        assert_eq!(f.snapshot(), b"hello\x00\x00ab");
        // read past end is 0; a partial read near the end returns the remainder.
        let mut tail = [0u8; 8];
        assert_eq!(f.read_at(&mut tail, 9).unwrap(), 0);
        let n = f.read_at(&mut tail, 7).unwrap();
        assert_eq!(&tail[..n], b"ab");
        // set_len truncates then zero-fill-extends.
        f.set_len(3).unwrap();
        assert_eq!(f.snapshot(), b"hel");
        f.set_len(5).unwrap();
        assert_eq!(f.snapshot(), b"hel\x00\x00");
        // read_exact_at fills exactly or errors UnexpectedEof.
        let mut three = [0u8; 3];
        f.read_exact_at(&mut three, 0).unwrap();
        assert_eq!(&three, b"hel");
        assert_eq!(
            f.read_exact_at(&mut [0u8; 6], 0).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn ephemeral_sync_is_a_noop_and_never_loses_live_bytes() {
        // The whole point of #492: sync_data/sync_all do nothing (no durable copy to refresh, no
        // device to flush) and are O(1). After a sync the bytes are simply still the bytes — there
        // is no power loss to model, so nothing is ever reverted.
        let f = EphemeralFile::new();
        f.write_all_at(b"durable-by-process-lifetime", 0).unwrap();
        f.sync_data().unwrap();
        f.sync_all().unwrap();
        assert_eq!(f.snapshot(), b"durable-by-process-lifetime");
        // A write after a sync is immediately visible; there is no "unsynced tail" concept.
        f.write_all_at(b"!", 27).unwrap();
        f.sync_all().unwrap();
        assert_eq!(f.snapshot(), b"durable-by-process-lifetime!");
    }

    #[test]
    fn ephemeral_default_preallocate_is_a_noop_and_changes_nothing() {
        // EphemeralFile does not override preallocate: the trait default no-op applies, reserving
        // nothing and leaving the bytes and length untouched (a Vec has no up-front reservation a
        // reader could observe).
        let f = EphemeralFile::new();
        f.write_all_at(b"ok", 0).unwrap();
        f.preallocate(1 << 20).unwrap();
        assert_eq!(f.len().unwrap(), 2);
        assert_eq!(f.snapshot(), b"ok");
    }

    #[test]
    fn ephemeral_shared_across_threads_as_trait_object() {
        let f: Arc<dyn RandomAccessFile> = Arc::new(EphemeralFile::new());
        let f2 = Arc::clone(&f);
        std::thread::scope(|s| {
            s.spawn(move || f2.write_all_at(b"data", 0).unwrap());
        });
        let mut buf = [0u8; 4];
        assert_eq!(f.read_at(&mut buf, 0).unwrap(), 4);
        assert_eq!(&buf, b"data");
    }
}

/// An EPHEMERAL in-memory [`RandomAccessFile`] for the real `--storage memory` broker: a single
/// `Vec` of bytes, NO durable second copy, and `sync_data`/`sync_all` no-ops.
///
/// This is the production in-RAM backend (#492). The deterministic simulation backend
/// [`InMemoryFile`] keeps TWO images — `live` plus a `durable` copy taken at each sync — purely so
/// [`simulate_power_loss`](InMemoryFile::simulate_power_loss) can model a crash by reverting the
/// unsynced tail. The real `--storage memory` path models no power loss (it is ephemeral: a crash
/// loses everything, there is no restart durability to simulate), so that `durable` copy is pure
/// overhead: it doubles RSS to ~2x the configured cap and makes every `sync_all` clone the whole
/// file (O(file)). This backend drops it. RSS is ~1x the cap and a sync is O(1).
///
/// Durability semantics: there are none, by design. `sync_data`/`sync_all` succeed without doing
/// anything — there is no device, so there is nothing to flush. Within the process the bytes are
/// always the live bytes; the [`RandomAccessFile`] read/write/`set_len`/`len` contract is identical
/// to [`InMemoryFile`]'s, only WITHOUT the durable-image bookkeeping, so the engine, recovery scan,
/// CRC checks, retention, and compression all behave exactly the same while the process is alive.
/// There is deliberately NO `simulate_power_loss` on this type: the crash-recovery simulation must
/// stay on [`InMemoryFile`], which retains the `durable` copy it depends on.
#[derive(Debug, Default)]
pub struct EphemeralFile {
    /// The one and only image: the current bytes. No `durable` shadow, no `dirty` ledger — an
    /// ephemeral file has no power loss to model and no sync barrier to honor.
    bytes: Mutex<Vec<u8>>,
}

impl EphemeralFile {
    /// Creates an empty ephemeral file.
    #[must_use]
    pub fn new() -> EphemeralFile {
        EphemeralFile::default()
    }

    // As in [`InMemoryFile::lock`]: the only mutations are `Vec` slice copies and resizes, none of
    // which unwind partway through a structurally invalid state, so recovering a poisoned guard
    // keeps the broker process alive rather than cascading a panic.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<u8>> {
        self.bytes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns a copy of the current bytes (the only image there is).
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        self.lock().clone()
    }
}

impl RandomAccessFile for EphemeralFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let off = usize::try_from(offset).map_err(|_| invalid_input("offset out of range"))?;
        let bytes = self.lock();
        if off >= bytes.len() {
            return Ok(0);
        }
        let n = (bytes.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&bytes[off..off + n]);
        Ok(n)
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        let off = usize::try_from(offset).map_err(|_| invalid_input("offset out of range"))?;
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| invalid_input("write extends past the addressable range"))?;
        let mut bytes = self.lock();
        if bytes.len() < end {
            bytes.resize(end, 0);
        }
        bytes[off..end].copy_from_slice(buf);
        Ok(())
    }

    // No device, nothing to flush: the bytes are already the live bytes and there is no durable
    // image to advance. O(1), unlike [`InMemoryFile`]'s dirty-range copy. There is no power loss to
    // survive, so this is a faithful no-op, not a weakened barrier.
    fn sync_data(&self) -> io::Result<()> {
        Ok(())
    }

    fn sync_all(&self) -> io::Result<()> {
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.lock().len() as u64)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len).map_err(|_| invalid_input("length out of range"))?;
        // Truncation drops the tail, extension zero-fills, exactly like [`InMemoryFile::set_len`]
        // and [`StdFile::set_len`] — minus the durable-image truncation-is-metadata bookkeeping,
        // which is meaningless without a durable image.
        self.lock().resize(len, 0);
        Ok(())
    }

    // `preallocate` keeps the trait default (a no-op): an in-RAM `Vec` reserves nothing up front and
    // a reservation that changed no bytes would be invisible anyway, exactly the default's contract.
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
    // segment up front AND advance the logical length to the reservation boundary, so the
    // steady-state appends land inside already-allocated space AND inside the logical size: the
    // per-commit `fdatasync` then carries no `i_size` update (first-touch unwritten→written
    // extent-state conversions are still journaled; see the trait doc for the honest
    // accounting). This is a BEST-EFFORT optimization: the fallback ladder bottoms out at today's
    // grow-on-append, which is correct, only without the wear/latency win. It never advances the
    // append cursor and never changes a byte that was written; the unwritten tail is zeros that
    // recovery's torn-tail scan truncates (the frozen #45 zero-window fixture), and the seal path
    // truncates the file back down to the footer end.
    fn preallocate(&self, len: u64) -> io::Result<()> {
        preallocate_file(&self.file, len)
    }

    // The buffered production file IS spliceable: `sendfile(2)` reads it straight from the page cache
    // to the socket with no userspace copy of the record bodies (#1034 / #658). The borrow is tied to
    // `self`, so the caller keeps this `StdFile` (or the `SegmentReader` owning it) alive across the
    // whole splice.
    fn splice_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        Some(self.file.as_fd())
    }
}

/// Reserves `len` backing blocks for `file` AND advances its LOGICAL length up to `len`, with the
/// per-OS reservation recipe and a fallback ladder that bottoms out at grow-on-append (the
/// `docs/PREALLOCATION.md` shim, primitive (a)).
///
/// Two halves, deliberately paired (the Redpanda `segment_appender` recipe: `fallocate` then
/// truncate UP to the preallocation boundary):
///
/// 1. **Block reservation** (keep-size form): Linux `fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, len)`
///    reserves real extents on ext4/f2fs/xfs (the edge targets); Apple
///    `fcntl(fd, F_PREALLOCATE)` requests contiguous blocks (`F_ALLOCATECONTIG`) then any blocks
///    (`F_ALLOCATEALL`). A filesystem with no allocation support
///    (`EOPNOTSUPP`/`ENOSYS`/`ENOTSUP`) degrades to no reservation; any other Unix has no portable
///    reservation syscall and skips this half.
/// 2. **Logical extension**: `set_len` UP to `len` (never down — a file already longer is left
///    alone). Every subsequent append then lands INSIDE the logical size, so the per-commit
///    `fdatasync` no longer journals an `i_size` update per sync. It is NOT metadata-free: an
///    append's first touch of a reserved-but-unwritten extent still journals that extent's
///    one-time unwritten→written state conversion (both measurement arms paid those); the
///    EVERY-COMMIT `i_size` update is what the extension eliminates. Measured on the
///    ext4/virtio bench VM this saves ~13us (7%) p50 and ~26us (10%) p99 per fdatasync versus
///    the keep-size-only form. The one-time size-grow metadata commit is paid by the first
///    sync after this call.
///
/// The extension is what the rest of the engine is built to absorb: the writer's append cursor is
/// tracked by the layers above (never derived from `file.len()`), the unwritten tail reads back as
/// zeros that recovery's zero-window rule truncates silently (never-written space, not loss), and
/// the seal path truncates the file back down to the footer end so a sealed segment's image is
/// byte-identical to a never-preallocated one.
///
/// `len == 0` is a no-op (nothing to reserve). The call is never the durability barrier: the
/// commit `sync_data` (I2) is, independent of this call, and an extension lost to a crash merely
/// leaves a shorter file that recovery handles like any other. A genuine `ENOSPC` is surfaced so
/// the caller can route a create-time out-of-space to the overflow path rather than discover it
/// mid-append.
#[cfg(unix)]
fn preallocate_file(file: &std::fs::File, len: u64) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    // Half 1: reserve backing blocks (best-effort per OS; unsupported filesystems degrade inside).
    #[cfg(target_os = "linux")]
    preallocate_linux(file, len)?;
    #[cfg(target_vendor = "apple")]
    preallocate_apple(file, len)?;
    // Half 2: advance the logical length up to the reservation boundary (never shrink). Done even
    // when the reservation half degraded (or does not exist, on another Unix): a sparse extension
    // still moves the size-grow metadata commit off the per-commit fdatasync path, which is the
    // measured win; only the contiguity/wear benefit needs real reserved blocks.
    if file.metadata()?.len() < len {
        file.set_len(len)?;
    }
    Ok(())
}

/// Linux: `fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, len)` reserves real extents while KEEPING the
/// apparent file size; the caller ([`preallocate_file`]) then advances the logical length with a
/// single `ftruncate`-up, which together are equivalent to a mode-0 `fallocate` (reserve + size).
/// A filesystem that cannot allocate (`EOPNOTSUPP`/`ENOSYS`) degrades to the extension alone; any
/// other error (e.g. `ENOSPC`) is surfaced so a create-time out-of-space is not masked.
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
/// logical size; the caller ([`preallocate_file`]) then advances the logical length with a single
/// `set_len`-up (the `ftruncate` pairing Apple's own docs describe for a full preallocation). If
/// `F_PREALLOCATE` is unsupported (`ENOTSUP`), fall back to the extension alone.
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
    fn splice_fd_some_for_buffered_none_for_memory_backends() {
        // The zero-copy Tier-S consume path (#1034 / #658) gates on `splice_fd()`: `Some` means the
        // stored bytes can `sendfile(2)` straight from the page cache, `None` means take the copy path.
        // Pin the contract so a backend that forgets to opt in fails SAFE (the default `None` = copy).
        assert!(
            InMemoryFile::new().splice_fd().is_none(),
            "the in-memory backend has no OS fd"
        );
        assert!(
            EphemeralFile::new().splice_fd().is_none(),
            "the ephemeral backend has no OS fd"
        );
        let dir = tempfile::tempdir().unwrap();
        let f = StdFile::create(&dir.path().join("splice.log")).unwrap();
        assert!(
            f.splice_fd().is_some(),
            "the buffered production file is spliceable"
        );
        // `StdFs::File` IS `MaybeDirectFile`, so the delegating override is what actually engages on
        // the disk read path: the buffered arm stays spliceable.
        let mdf = MaybeDirectFile::Buffered(StdFile::create(&dir.path().join("mdf.log")).unwrap());
        assert!(
            mdf.splice_fd().is_some(),
            "the buffered MaybeDirectFile delegates to Some"
        );
    }

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
    fn preallocate_extends_the_logical_length_and_appends_land_inside() {
        // The production preallocation reserves blocks AND advances the LOGICAL length up to the
        // reservation boundary, so subsequent appends land inside the logical size and the
        // per-commit fdatasync carries no i_size update. The unwritten remainder
        // reads back as ZEROS (the zero-window end-of-data rule recovery relies on), the written
        // header is intact, and an append inside the extension round-trips.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.log");
        let f = StdFile::create(&path).unwrap();
        f.write_all_at(b"HEADER", 0).unwrap();
        let want: u64 = 64 * 1024;
        f.preallocate(want).unwrap();
        f.sync_all().unwrap();
        // The header is intact and the LOGICAL length is the preallocation boundary.
        let mut hdr = [0u8; 6];
        f.read_exact_at(&mut hdr, 0).unwrap();
        assert_eq!(&hdr, b"HEADER");
        assert_eq!(
            f.len().unwrap(),
            want,
            "preallocation advances the logical length to the boundary"
        );
        // The unwritten tail reads back as zeros (never garbage): the zero-window rule's premise.
        let mut tail = [0xFFu8; 32];
        f.read_exact_at(&mut tail, 6).unwrap();
        assert!(
            tail.iter().all(|&b| b == 0),
            "the unwritten extension reads back as zeros"
        );
        // An append at the cursor (INSIDE the logical size) round-trips and does not grow the file.
        f.write_all_at(b"record", 6).unwrap();
        f.sync_data().unwrap();
        assert_eq!(
            f.len().unwrap(),
            want,
            "an in-size append never grows i_size"
        );
        let mut back = [0u8; 12];
        f.read_exact_at(&mut back, 0).unwrap();
        assert_eq!(&back, b"HEADERrecord");
        // The seal-path shape: a shrink back to the true end (set_len + sync_all) works.
        f.set_len(12).unwrap();
        f.sync_all().unwrap();
        assert_eq!(
            f.len().unwrap(),
            12,
            "the seal truncates the zero tail away"
        );
    }

    #[test]
    fn preallocate_never_shrinks_a_longer_file() {
        // A reservation smaller than the current length must never truncate data: the extension
        // half is set_len UP only.
        let dir = tempfile::tempdir().unwrap();
        let f = StdFile::create(&dir.path().join("long.log")).unwrap();
        let data = vec![7u8; 8192];
        f.write_all_at(&data, 0).unwrap();
        f.preallocate(4096).unwrap();
        assert_eq!(
            f.len().unwrap(),
            8192,
            "a smaller preallocation never shrinks the file"
        );
        let mut back = vec![0u8; 8192];
        f.read_exact_at(&mut back, 0).unwrap();
        assert_eq!(back, data);
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

// ============================================================================
// Direct-write (O_DIRECT) backend — the SAFE T1 durable io-mode (perf/iomode-direct).
//
// `DirectFile` is the `direct` io-mode's [`RandomAccessFile`]: it writes record bytes
// straight to the device with `O_DIRECT` (no page cache) over segments whose extents are
// pre-formatted `written` at create time, and KEEPS the durability barrier (`fdatasync` /
// `fsync`) exactly as buffered mode does. The speed comes from making that barrier
// metadata-free (written extents => no `unwritten->written` conversion, no `i_size` update)
// and page-cache-free (O_DIRECT), NOT from dropping it, so ack-implies-durable (I2) holds
// identically to buffered: an ack releases only after the covering write's `pwrite` returned
// AND the barrier returned. See `docs`/the io-mode spec for the full durability argument.
//
// The whole O_DIRECT complexity lives HERE, behind the `RandomAccessFile` seam, so the
// buffered [`StdFile`] path is byte-and-behavior identical to today. The on-disk byte IMAGE
// a `DirectFile` produces is identical to [`StdFile`]'s (same header/frames, and the tail
// past the write frontier is zeros in both — pre-format zeros here, preallocated-hole zeros
// there), so recovery, the offline reader, and the conformance byte-identity gate are
// mode-agnostic (the mode is an IO strategy, not a format).
//
// `DirectFile` is `#[cfg(unix)]` (not linux-only) SO ITS RMW/ALIGNMENT/PRE-FORMAT LOGIC IS
// EXERCISED BY THE UNIX TEST SUITE (macOS CI included): those bytes are platform-independent.
// The `O_DIRECT` OPEN FLAG — the only genuinely-linux-specific piece — is applied only on
// Linux (`open_direct_write_fd`); on other unix the fds are ordinary (still block-aligned IO,
// still a real barrier via `F_FULLFSYNC`), which is a faithful model of the byte path. In
// PRODUCTION `direct` is selected only where the substrate probe confirms it (Linux); the
// resolver fails closed to `buffered` on non-Linux (see `substrate.rs`), so a `DirectFile` is
// constructed on macOS ONLY by a test that asks for one directly.
// ============================================================================

/// The `O_DIRECT` alignment IronBus uses for every direct-mode write: buffer address, file
/// offset, and length are all multiples of this. 4096 is a superset of every common device's
/// logical block size (512 and 4096 both divide it), so a single fixed alignment satisfies
/// 512-sector and 4K-native devices alike without probing `BLKSSZGET`. A device with a larger
/// logical block (rare) would reject the `O_DIRECT` write with `EINVAL`, which surfaces as a
/// fatal writer error (fail-closed) rather than a silent downgrade.
///
/// `cfg(unix)`: only the `O_DIRECT` `DirectFile` path consumes it; on non-unix (buffered-only) it
/// would be dead code.
#[cfg(unix)]
pub(crate) const DIO_ALIGN: usize = 4096;

/// The pre-format zero-write chunk (a multiple of [`DIO_ALIGN`]): the whole segment is made
/// `written` at create by streaming zeros through one reusable aligned buffer of this size, so
/// pre-format costs O(1) heap regardless of the segment size (~213ms/64MiB at ~300MB/s).
#[cfg(unix)]
const PREFORMAT_CHUNK_BYTES: usize = 1024 * 1024;

/// Rounds `x` down to the nearest multiple of `align` (a power of two).
#[cfg(unix)]
#[inline]
fn align_down(x: u64, align: usize) -> u64 {
    let mask = align as u64 - 1;
    x & !mask
}

/// Rounds `x` up to the nearest multiple of `align` (a power of two), saturating at [`u64::MAX`]
/// (an offset that near the top of the address space is never reached by a bounded segment).
#[cfg(unix)]
#[inline]
fn align_up(x: u64, align: usize) -> u64 {
    let mask = align as u64 - 1;
    x.saturating_add(mask) & !mask
}

/// A heap buffer whose start address is [`DIO_ALIGN`]-aligned and whose length is a multiple of
/// [`DIO_ALIGN`], the buffer `O_DIRECT` requires. Allocated zeroed (so the tail padding of a
/// sub-block write, and the whole pre-format image, is zeros with no extra fill). It is only ever a
/// method-local temporary (never stored in a shared struct, never moved across a thread), so it
/// needs no `Send`/`Sync` impl.
#[cfg(unix)]
struct AlignedBuf {
    ptr: std::ptr::NonNull<u8>,
    layout: std::alloc::Layout,
}

#[cfg(unix)]
impl AlignedBuf {
    /// Allocates a zeroed, [`DIO_ALIGN`]-aligned buffer of exactly `len` bytes, where `len` must
    /// be a nonzero multiple of [`DIO_ALIGN`].
    fn zeroed(len: usize) -> io::Result<AlignedBuf> {
        debug_assert!(
            len > 0 && len % DIO_ALIGN == 0,
            "aligned buffer length must be a nonzero multiple of the block size"
        );
        let layout = std::alloc::Layout::from_size_align(len, DIO_ALIGN)
            .map_err(|_| invalid_input("aligned buffer layout out of range"))?;
        // SAFETY: `layout` has a nonzero size (guaranteed by the debug assert / caller contract),
        // which is the sole precondition of `alloc_zeroed`. The returned pointer is checked for
        // null below and is deallocated with the identical `layout` in `Drop`.
        #[allow(unsafe_code)]
        let raw = unsafe { std::alloc::alloc_zeroed(layout) };
        let ptr = std::ptr::NonNull::new(raw).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "aligned allocation failed")
        })?;
        Ok(AlignedBuf { ptr, layout })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` points to `layout.size()` initialized bytes owned by `self` (allocated
        // zeroed, only ever written through `as_mut_slice`), and the returned slice borrows `self`,
        // so no aliasing `&mut` can exist for its lifetime.
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size())
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `self` is borrowed mutably, so this is the unique reference to the `layout.size()`
        // owned, initialized bytes at `ptr` for the returned slice's lifetime.
        #[allow(unsafe_code)]
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size())
        }
    }
}

#[cfg(unix)]
impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `alloc_zeroed` with exactly `self.layout` and has not been freed
        // elsewhere (unique ownership), so freeing it with the same layout is sound.
        #[allow(unsafe_code)]
        unsafe {
            std::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

/// The cached image of the current partial *frontier block* (the block that holds the last
/// written byte), so a frontier append can preserve that block's committed prefix WITHOUT a
/// device read. It is a strict cache: whenever it is present it equals what a device read of
/// `[base, base+DIO_ALIGN)` would return, and `None` simply forces the read — so the cache can
/// never cause an incorrect write, only save a read on the hot append path.
#[cfg(unix)]
struct FrontierBlock {
    base: u64,
    bytes: Box<[u8]>,
}

/// The mutable write-side state of a [`DirectFile`], guarded by a `Mutex` because
/// [`RandomAccessFile`] writes take `&self`. There is a single logical writer (the append
/// actor), so the lock is uncontended; the off-actor durability barrier (`sync_data`, #1040)
/// touches NEITHER field, so it never contends here.
#[cfg(unix)]
struct DirectWriteState {
    /// One past the highest byte the CALLER has written (the log's header/records/footer), i.e.
    /// the RMW high-water. A block entirely at or above `data_end` is known-fresh (pre-format
    /// zeros) and needs no read-back on a re-write; a block below it holds committed bytes and is
    /// read (unless it is the cached frontier block). Pre-format zeros do NOT advance it — they
    /// are the background, not caller data — which is what keeps a fresh segment's appends
    /// read-free. Initialized to the file length on `open` (conservative: every existing byte is
    /// treated as committed) and to 0 on `create_new`.
    data_end: u64,
    /// The cached frontier block (see [`FrontierBlock`]).
    tail: Option<FrontierBlock>,
}

/// A production [`RandomAccessFile`] that writes with ``O_DIRECT`` (Linux) and keeps the durability
/// barrier — the `direct` io-mode's file (the T1 tier). See the module section header above.
#[cfg(unix)]
pub struct DirectFile {
    /// The write fd: opened ``O_DIRECT`` on Linux (all writes block-aligned, cache-bypassing), plain
    /// on other unix. Every append and the pre-format go through it; it is also the fd the kept
    /// barrier (`sync_data`/`sync_all`) flushes.
    write: std::fs::File,
    /// The read fd: always buffered, for arbitrary unaligned `pread`s (reads are not the
    /// bottleneck, and an `O_DIRECT` read would force the caller's buffers to be aligned). On Linux
    /// an `O_DIRECT` write invalidates the overlapping page-cache pages, so a subsequent buffered
    /// read re-reads fresh from the device — coherent as long as readers use `pread` (never mmap),
    /// which IronBus does.
    read: std::fs::File,
    state: Mutex<DirectWriteState>,
}

#[cfg(unix)]
impl std::fmt::Debug for DirectFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectFile").finish_non_exhaustive()
    }
}

/// Opens the write fd for a [`DirectFile`], adding ``O_DIRECT`` on Linux (the only platform where it
/// is a cache-bypass; on other unix the flag is omitted and the fds are ordinary, which the tests
/// exercise). `create_new` selects `O_EXCL` create vs open-existing.
#[cfg(unix)]
fn open_direct_write_fd(path: &std::path::Path, create_new: bool) -> io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true);
    if create_new {
        opts.create_new(true);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_DIRECT: bytes go straight to the device, bypassing the page cache. Its per-arch value
        // is provided by `libc` (0o40000 on x86_64, 0o200000 on aarch64, ...).
        opts.custom_flags(libc::O_DIRECT);
    }
    opts.open(path)
}

#[cfg(unix)]
impl DirectFile {
    /// Opens an existing file in direct mode (both the `O_DIRECT` write fd and the buffered read fd).
    ///
    /// # Errors
    /// Propagates the underlying IO error.
    pub fn open(path: &std::path::Path) -> io::Result<DirectFile> {
        let write = open_direct_write_fd(path, false)?;
        let read = std::fs::OpenOptions::new().read(true).open(path)?;
        let data_end = write.metadata()?.len();
        Ok(DirectFile {
            write,
            read,
            state: Mutex::new(DirectWriteState {
                data_end,
                tail: None,
            }),
        })
    }

    /// Creates a new file (`O_EXCL`) in direct mode, failing with
    /// [`io::ErrorKind::AlreadyExists`] if it exists.
    ///
    /// # Errors
    /// Returns `AlreadyExists` if the path exists, or propagates the underlying IO error.
    pub fn create_new(path: &std::path::Path) -> io::Result<DirectFile> {
        let write = open_direct_write_fd(path, true)?;
        let read = std::fs::OpenOptions::new().read(true).open(path)?;
        Ok(DirectFile {
            write,
            read,
            state: Mutex::new(DirectWriteState {
                data_end: 0,
                tail: None,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DirectWriteState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Writes `buf` to `file` at `offset` with positioned writes, looping until every byte lands.
/// For an `O_DIRECT` fd the caller guarantees `buf`'s address, `offset`, and `buf.len()` are all
/// block-aligned; a partial write returned by the kernel is itself block-aligned, so the
/// continuation stays aligned.
#[cfg(unix)]
fn pwrite_all(file: &std::fs::File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !buf.is_empty() {
        match file.write_at(buf, offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "direct write returned zero bytes",
                ))
            }
            Ok(n) => {
                buf = &buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Reads up to a full block of `file` into `block` at `offset` via the buffered read fd,
/// zero-filling any bytes past the current end of file (a block that straddles EOF reads back
/// as its bytes plus zeros, exactly the RMW background a partial trailing block needs).
#[cfg(unix)]
fn read_block_background(file: &std::fs::File, block: &mut [u8], offset: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    let mut filled = 0usize;
    while filled < block.len() {
        match file.read_at(&mut block[filled..], offset + filled as u64) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    for b in &mut block[filled..] {
        *b = 0;
    }
    Ok(())
}

#[cfg(unix)]
impl RandomAccessFile for DirectFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        // Always the BUFFERED read fd: reads may be unaligned, and O_DIRECT invalidates the
        // overlapping page-cache pages on write, so this re-reads fresh from the device.
        self.read.read_at(buf, offset)
    }

    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let bs = DIO_ALIGN;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| invalid_input("write extends past the addressable range"))?;
        let blo = align_down(offset, bs);
        let bhi = align_up(end, bs);
        let span =
            usize::try_from(bhi - blo).map_err(|_| invalid_input("aligned span out of range"))?;
        let mut chunk = AlignedBuf::zeroed(span)?;
        let cbuf = chunk.as_mut_slice();

        let mut guard = self.lock();
        let st = &mut *guard;

        // Materialize the correct on-device background for every block that this write does not
        // FULLY cover (a fully-covered block is overwritten wholesale, so its prior content is
        // irrelevant). A partially-covered block gets its content from, in order: the cached
        // frontier block (no read); known-fresh zeros if it sits at or above `data_end`; else a
        // device read (a header re-write, a checkpoint's other slot, or a resumed segment's tail).
        let bs_u64 = bs as u64;
        let mut b = blo;
        while b < bhi {
            let bo = usize::try_from(b - blo).expect("block offset fits (span already fits usize)");
            let covers_lo = offset <= b;
            let covers_hi = end >= b + bs_u64;
            if !(covers_lo && covers_hi) {
                let block = &mut cbuf[bo..bo + bs];
                let cache_hit = st.tail.as_ref().is_some_and(|t| t.base == b);
                if cache_hit {
                    block.copy_from_slice(&st.tail.as_ref().expect("cache_hit implies Some").bytes);
                } else if b >= st.data_end {
                    // Known-fresh (pre-format zeros): `AlignedBuf` already zeroed this block.
                } else {
                    read_block_background(&self.read, block, b)?;
                }
            }
            b += bs_u64;
        }

        // Overlay the caller's bytes.
        let ov = usize::try_from(offset - blo).expect("overlay offset fits");
        cbuf[ov..ov + buf.len()].copy_from_slice(buf);

        // One O_DIRECT write of the whole aligned span (so a group-commit batch is one write, and
        // the barrier stays a real group commit).
        debug_assert_eq!(blo % bs_u64, 0, "aligned write offset");
        debug_assert_eq!(cbuf.len() % bs, 0, "aligned write length");
        debug_assert_eq!(
            cbuf.as_ptr() as usize % bs,
            0,
            "aligned write buffer address"
        );
        pwrite_all(&self.write, cbuf, blo)?;

        // Advance the high-water and refresh the frontier-block cache. Capturing the frontier
        // block from the just-written image keeps the cache device-consistent with no extra read.
        st.data_end = st.data_end.max(end);
        if st.data_end % bs_u64 == 0 {
            // A block-aligned frontier: the next append starts a fresh block, nothing partial to
            // cache.
            st.tail = None;
        } else {
            let fbase = align_down(st.data_end, bs);
            if fbase >= blo && fbase < bhi {
                let fo = usize::try_from(fbase - blo).expect("frontier offset within span");
                let mut bytes = vec![0u8; bs].into_boxed_slice();
                bytes.copy_from_slice(&cbuf[fo..fo + bs]);
                st.tail = Some(FrontierBlock { base: fbase, bytes });
            }
            // else: this write did not touch the frontier block (a pure back-patch below it), so
            // the existing cache is still valid — leave it.
        }
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        // The KEPT durability barrier (T1). On a pre-formatted written extent with O_DIRECT data
        // already on the device this is metadata-free — its cost is exactly the substrate's true
        // flush cost — but it is a real barrier and is what makes an ack durable (I2), identical to
        // buffered mode. Off-actor via the #1040 flusher; touches no write-side state.
        self.write.sync_data()
    }

    fn sync_all(&self) -> io::Result<()> {
        self.write.sync_all()
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.write.metadata()?.len())
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.write.set_len(len)?;
        let mut guard = self.lock();
        let st = &mut *guard;
        // A shrink (the seal's truncate-to-footer-end) drops any high-water and cached block past
        // the new end; a grow zero-fills sparsely (never used on the segment path, which
        // pre-formats instead) and leaves the caller high-water alone.
        if len < st.data_end {
            st.data_end = len;
        }
        if st
            .tail
            .as_ref()
            .is_some_and(|t| t.base + DIO_ALIGN as u64 > len)
        {
            st.tail = None;
        }
        Ok(())
    }

    fn preallocate(&self, len: u64) -> io::Result<()> {
        // The WRITTEN-EXTENT PRE-FORMAT (direct mode's replacement for the buffered keep-size
        // fallocate, spec §4): make every extent of the segment `written` and journal-durable ONCE
        // at create, so every steady-state append is an overwrite of a written extent — no
        // `unwritten->written` conversion, no `i_size` update, no per-op metadata journaling. After
        // this the kept barrier is metadata-free. `len == 0` is a no-op.
        //
        // PRECONDITION: this zero-writes `[0, len)`, so it MUST run on a freshly-created, still-empty
        // segment — exactly where the log calls it (`create_new` then `preallocate`, before the
        // header write). A resumed segment is `SegmentWriter::resume`d and NEVER re-preallocated, so
        // this never zeroes committed data. The debug assert pins that invariant against future
        // misuse (a release build still zeroes from 0, correct for the only real call path).
        if len == 0 {
            return Ok(());
        }
        debug_assert_eq!(
            self.lock().data_end,
            0,
            "pre-format (preallocate) must run on a freshly-created empty segment, before any write"
        );
        let bs = DIO_ALIGN;
        let hi = align_up(len, bs);
        // 1) Reserve the blocks (Linux). Best-effort: an fs without allocation support degrades to
        //    the zero-write below allocating on demand.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let off = libc::off_t::try_from(hi)
                .map_err(|_| invalid_input("preallocate length out of range"))?;
            // SAFETY: `fallocate` is a libc syscall wrapper; `self.write` owns a valid, open,
            // writable fd that outlives the call; the mode flag and two `off_t` args are passed by
            // value and it touches only the kernel block map for that fd.
            #[allow(unsafe_code)]
            let rc = unsafe {
                libc::fallocate(self.write.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, off)
            };
            if rc != 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EOPNOTSUPP | libc::ENOSYS) => {}
                    _ => return Err(err),
                }
            }
        }
        // 2) Sequentially O_DIRECT-write zeros over the whole logical length, one reusable aligned
        //    chunk at a time, so every extent becomes `written`. `hi` and `PREFORMAT_CHUNK_BYTES`
        //    are both block multiples, so their min is a block-aligned buffer length (>= one block).
        let cap = (PREFORMAT_CHUNK_BYTES as u64).min(hi);
        let chunk_len = usize::try_from(cap).unwrap_or(PREFORMAT_CHUNK_BYTES);
        let zeros = AlignedBuf::zeroed(chunk_len)?;
        let mut off = 0u64;
        while off < hi {
            let n =
                usize::try_from((hi - off).min(chunk_len as u64)).expect("chunk length fits usize");
            pwrite_all(&self.write, &zeros.as_slice()[..n], off)?;
            off += n as u64;
        }
        // 3) Trim the block-rounded tail back to the exact logical length so the file length is
        //    byte-identical to the buffered preallocation (`set_len` up to `len`); the trimmed tail
        //    was zeros anyway.
        if self.write.metadata()?.len() > len {
            self.write.set_len(len)?;
        }
        // 4) One barrier makes the extent map + length durable (the metadata domain, closed once).
        self.write.sync_all()?;
        // The pre-format zeros are BACKGROUND, not caller data: the RMW high-water stays where it
        // was (0 for a fresh create), which is what keeps the following appends read-free.
        Ok(())
    }

    // NOT spliceable — return `None` so the splice caller takes the copy path (#1034 / #658). A
    // `DirectFile` writes O_DIRECT (cache-bypassing) and reads through a SEPARATE buffered fd, relying
    // on the write-invalidates-page-cache coherence rule that holds for `pread`; a `sendfile(2)` on the
    // read fd would read through the very page cache the direct writes deliberately bypass, so whether
    // it observes the freshest bytes for a still-active segment is exactly the kind of coherence
    // question the design says to sidestep. A SEALED segment can be opened as a `DirectFile` when the
    // io-mode is `direct`, so this case is reachable; the task's rule is to return `None` on any
    // uncertainty, which keeps direct-mode consumes on the always-correct copy path.
    fn splice_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        None
    }
}

/// The [`Filesystem`](crate::fs::Filesystem)-selected production file: either the buffered
/// [`StdFile`] (the default, byte-and-behavior identical to today) or the [`DirectFile`] `O_DIRECT`
/// backend, chosen once by the resolved io-mode when the filesystem is built. Dispatch is a plain
/// enum (no `Box<dyn>`) so the file stays `Clone`-free-`Send + Sync` and every method is a direct
/// delegation — the buffered arm adds nothing but a match to today's path.
#[cfg(unix)]
#[derive(Debug)]
pub enum MaybeDirectFile {
    /// The default buffered file. Delegates VERBATIM to [`StdFile`], so buffered mode is unchanged.
    Buffered(StdFile),
    /// The `O_DIRECT` direct-write file (the T1 tier).
    Direct(DirectFile),
}

#[cfg(unix)]
impl RandomAccessFile for MaybeDirectFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match self {
            MaybeDirectFile::Buffered(f) => f.read_at(buf, offset),
            MaybeDirectFile::Direct(f) => f.read_at(buf, offset),
        }
    }
    fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
        match self {
            MaybeDirectFile::Buffered(f) => f.write_all_at(buf, offset),
            MaybeDirectFile::Direct(f) => f.write_all_at(buf, offset),
        }
    }
    fn sync_data(&self) -> io::Result<()> {
        match self {
            MaybeDirectFile::Buffered(f) => f.sync_data(),
            MaybeDirectFile::Direct(f) => f.sync_data(),
        }
    }
    fn sync_all(&self) -> io::Result<()> {
        match self {
            MaybeDirectFile::Buffered(f) => f.sync_all(),
            MaybeDirectFile::Direct(f) => f.sync_all(),
        }
    }
    fn len(&self) -> io::Result<u64> {
        match self {
            MaybeDirectFile::Buffered(f) => f.len(),
            MaybeDirectFile::Direct(f) => f.len(),
        }
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        match self {
            MaybeDirectFile::Buffered(f) => f.set_len(len),
            MaybeDirectFile::Direct(f) => f.set_len(len),
        }
    }
    fn preallocate(&self, len: u64) -> io::Result<()> {
        match self {
            MaybeDirectFile::Buffered(f) => f.preallocate(len),
            MaybeDirectFile::Direct(f) => f.preallocate(len),
        }
    }
    // Delegate so the filesystem-selected file reports its true spliceability: the buffered arm hands
    // out its fd (splice-eligible), the O_DIRECT arm returns `None` (copy path). This delegation is
    // load-bearing — `StdFs::File` IS `MaybeDirectFile`, so without it every disk read would report no
    // fd and the zero-copy path would never engage.
    fn splice_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        match self {
            MaybeDirectFile::Buffered(f) => f.splice_fd(),
            MaybeDirectFile::Direct(f) => f.splice_fd(),
        }
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
    #[cfg(unix)]
    fn splice_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        (**self).splice_fd()
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
    #[cfg(unix)]
    fn splice_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        (**self).splice_fd()
    }
}

// The direct-write backend's byte-level correctness (alignment, the partial-tail read-modify-write,
// pre-format, and byte-identity with the buffered `StdFile`) is platform-independent, so these run
// on EVERY unix target (macOS CI included), not just Linux. On non-Linux the `DirectFile` fds are
// ordinary (no O_DIRECT), which is a faithful model of the exact byte path; the Linux-only property
// (O_DIRECT truly bypasses the page cache) plus the physical-device durability are validated by the
// separate real-fs / t4g step.
#[cfg(all(test, unix))]
mod direct_file_tests {
    use super::*;

    const BS: usize = DIO_ALIGN;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn splice_fd_none_for_o_direct() {
        // A `DirectFile` (O_DIRECT, page-cache-bypassing writes with a SEPARATE buffered read fd) is
        // NOT spliceable: a `sendfile(2)` on the read fd would read through the very page cache the
        // direct writes bypass, so it returns `None` and direct-mode consumes take the copy path
        // (#1034 / #658). A SEALED segment can be opened as a DirectFile, so this case is reachable.
        let d = dir();
        let df = DirectFile::create_new(&d.path().join("seg")).unwrap();
        assert!(
            df.splice_fd().is_none(),
            "an O_DIRECT DirectFile is not spliceable"
        );
        let mdf = MaybeDirectFile::Direct(df);
        assert!(
            mdf.splice_fd().is_none(),
            "the direct MaybeDirectFile delegates to None"
        );
    }

    /// Reads the whole file (through the buffered read fd) into a `Vec` for oracle comparison.
    fn read_all(f: &DirectFile, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        let mut filled = 0;
        while filled < len {
            match f.read_at(&mut v[filled..], filled as u64).unwrap() {
                0 => break,
                k => filled += k,
            }
        }
        v.truncate(filled);
        v
    }

    #[test]
    fn direct_write_read_roundtrip_and_persists_across_reopen() {
        let d = dir();
        let path = d.path().join("seg");
        {
            let f = DirectFile::create_new(&path).unwrap();
            f.write_all_at(b"hello world", 0).unwrap();
            f.sync_all().unwrap();
            let mut buf = [0u8; 11];
            f.read_exact_at(&mut buf, 0).unwrap();
            assert_eq!(&buf, b"hello world");
        }
        // Reopen (models a process restart): the synced bytes survive.
        let g = DirectFile::open(&path).unwrap();
        let mut buf = [0u8; 5];
        assert_eq!(g.read_at(&mut buf, 6).unwrap(), 5);
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn direct_matches_a_byte_oracle_across_alignment_edge_cases() {
        // The load-bearing RMW test: an arbitrary write sequence covering header@0, sub-block
        // frontier appends, an append that SPANS a block boundary, a multi-block append with a
        // sub-block tail, and a back-patch (rewriting offset 0 after records exist) must leave the
        // file byte-identical to a plain in-memory oracle for EVERY case.
        let d = dir();
        let f = DirectFile::create_new(&d.path().join("seg")).unwrap();
        let mut oracle: Vec<u8> = Vec::new();
        let writes: Vec<(u64, Vec<u8>)> = vec![
            (0, vec![0xA1; 64]),                               // header@0 (sub-block)
            (64, vec![0xB2; 100]),                             // frontier append within block 0
            (164, vec![0xC3; (BS - 164) + 10]),                // append SPANS the block boundary
            (u64::try_from(BS + 10).unwrap(), vec![0xD4; BS]), // a full-block-sized append mid-block
            (u64::try_from(2 * BS + 10).unwrap(), vec![0xE5; 3 * BS + 7]), // multi-block, sub-block tail
            (0, vec![0xFF; 64]), // back-patch: rewrite the header
        ];
        for (off, bytes) in &writes {
            let start = usize::try_from(*off).unwrap();
            let end = start + bytes.len();
            if oracle.len() < end {
                oracle.resize(end, 0);
            }
            oracle[start..end].copy_from_slice(bytes);
            f.write_all_at(bytes, *off).unwrap();
            f.sync_data().unwrap();
            assert_eq!(
                read_all(&f, oracle.len()),
                oracle,
                "mismatch after write at {off}"
            );
        }
        f.sync_all().unwrap();
        drop(f);
        let g = DirectFile::open(&d.path().join("seg")).unwrap();
        assert_eq!(read_all(&g, oracle.len()), oracle, "mismatch after reopen");
    }

    #[test]
    fn direct_is_byte_identical_to_buffered_over_the_same_record_stream() {
        // The byte-identity guarantee (spec §7): the SAME write sequence through the buffered
        // `StdFile` and the `DirectFile` yields the same durable byte prefix. (The direct file may be
        // block-padded LONGER; the data prefix `[0, logical_end)` is identical.)
        let d = dir();
        let sf = StdFile::create(&d.path().join("buffered")).unwrap();
        let df = DirectFile::create_new(&d.path().join("direct")).unwrap();
        let header = vec![0x5A; 64];
        sf.write_all_at(&header, 0).unwrap();
        df.write_all_at(&header, 0).unwrap();
        let mut off = 64u64;
        for i in 0..200u32 {
            let len = 1 + (i as usize * 37) % 900; // spans sub-block, block, multi-block writes
            let rec = vec![u8::try_from(i % 251).unwrap(); len];
            sf.write_all_at(&rec, off).unwrap();
            df.write_all_at(&rec, off).unwrap();
            off += len as u64;
        }
        sf.sync_all().unwrap();
        df.sync_all().unwrap();
        let end = usize::try_from(off).unwrap();
        let mut a = vec![0u8; end];
        let mut b = vec![0u8; end];
        sf.read_exact_at(&mut a, 0).unwrap();
        df.read_exact_at(&mut b, 0).unwrap();
        assert_eq!(
            a, b,
            "direct-mode durable image differs from buffered over [0, {end})"
        );
    }

    #[test]
    fn direct_partial_tail_rmw_preserves_the_committed_prefix_byte_for_byte() {
        // The crux of the §3 crash-consistency proof: re-writing a partial frontier block to append
        // more re-writes the already-committed prefix bytes BYTE-IDENTICALLY (and the padding stays
        // zero), so a torn re-write can only ever damage the newly-appended, not-yet-acked bytes —
        // never a committed byte. Assert the re-write leaves the committed prefix untouched.
        let d = dir();
        let f = DirectFile::create_new(&d.path().join("seg")).unwrap();
        f.write_all_at(b"HDR", 0).unwrap();
        f.write_all_at(b"AAAAAAAA", 3).unwrap();
        f.sync_data().unwrap();
        let committed_end = 11usize;
        let mut before = vec![0u8; committed_end];
        f.read_exact_at(&mut before, 0).unwrap();
        f.write_all_at(b"BBBB", committed_end as u64).unwrap(); // a tail-block RMW
        let mut after = vec![0u8; committed_end];
        f.read_exact_at(&mut after, 0).unwrap();
        assert_eq!(
            before, after,
            "the tail-block RMW must not disturb the committed prefix"
        );
        let mut all = vec![0u8; 15];
        f.read_exact_at(&mut all, 0).unwrap();
        assert_eq!(&all, b"HDRAAAAAAAABBBB");
    }

    #[test]
    fn direct_preformat_makes_written_zeros_and_composes_with_the_zero_tail_rule() {
        // Pre-format (`preallocate`) writes zeros over the whole segment (making the extents
        // `written`) and trims the length back to exactly the requested size — byte-identical to the
        // buffered preallocation's zero tail. After a header + records, the tail past the frontier is
        // all zeros and `last_nonzero_end` bounds recovery exactly at the last written byte.
        let d = dir();
        let f = DirectFile::create_new(&d.path().join("seg")).unwrap();
        let seg_bytes = 64 * 1024u64; // block-aligned
        f.preallocate(seg_bytes).unwrap();
        assert_eq!(
            f.len().unwrap(),
            seg_bytes,
            "pre-format trims to the exact logical length"
        );
        assert_eq!(
            last_nonzero_end(&f, 0, seg_bytes).unwrap(),
            0,
            "a pre-formatted segment is all zeros"
        );
        f.write_all_at(b"HEADERHEADER", 0).unwrap();
        f.write_all_at(&[0x11; 300], 12).unwrap();
        f.sync_data().unwrap();
        let frontier = 12 + 300u64;
        assert_eq!(
            last_nonzero_end(&f, 0, seg_bytes).unwrap(),
            frontier,
            "the zero tail past the frontier bounds recovery at the last written byte"
        );
        assert_eq!(
            f.len().unwrap(),
            seg_bytes,
            "appends land inside the pre-format, no i_size churn"
        );
    }

    #[test]
    fn direct_seal_shape_truncates_to_the_exact_footer_end() {
        // The seal path (footer `write_all_at` at the frontier, then `set_len` down + `sync_all`)
        // must leave the file at EXACTLY the footer end — byte-identical to a buffered seal, so
        // footer-at-file-end discovery still works — even though the O_DIRECT footer write padded to
        // a block first.
        let d = dir();
        let f = DirectFile::create_new(&d.path().join("seg")).unwrap();
        f.preallocate(64 * 1024).unwrap();
        f.write_all_at(b"HEADER", 0).unwrap();
        f.write_all_at(&[0x22; 500], 6).unwrap();
        let write_pos = 506u64;
        f.write_all_at(&[0x33; 32], write_pos).unwrap(); // the footer at the frontier
        let end = write_pos + 32;
        if f.len().unwrap() > end {
            f.set_len(end).unwrap();
        }
        f.sync_all().unwrap();
        assert_eq!(
            f.len().unwrap(),
            end,
            "sealed length is the exact footer end"
        );
        let mut footer = [0u8; 32];
        f.read_exact_at(&mut footer, write_pos).unwrap();
        assert_eq!(footer, [0x33; 32]);
    }

    #[test]
    fn direct_resumed_segment_appends_correctly_after_reopen() {
        // A resumed (reopened) segment sets its RMW high-water to the file length (conservative), so
        // the first append after reopen preserves the boundary block via a device read; the bytes
        // must still be correct.
        let d = dir();
        let path = d.path().join("seg");
        {
            let f = DirectFile::create_new(&path).unwrap();
            f.preallocate(64 * 1024).unwrap();
            f.write_all_at(b"HEADER", 0).unwrap();
            f.write_all_at(b"first", 6).unwrap();
            f.sync_all().unwrap();
        }
        let g = DirectFile::open(&path).unwrap();
        g.write_all_at(b"second", 11).unwrap(); // append at the recovered frontier
        g.sync_data().unwrap();
        let mut all = vec![0u8; 17];
        g.read_exact_at(&mut all, 0).unwrap();
        assert_eq!(&all, b"HEADERfirstsecond");
    }

    #[test]
    fn direct_empty_write_is_a_noop() {
        let d = dir();
        let f = DirectFile::create_new(&d.path().join("seg")).unwrap();
        f.write_all_at(b"", 0).unwrap();
        assert_eq!(f.len().unwrap(), 0);
    }

    #[test]
    fn aligned_buf_address_and_length_are_block_aligned() {
        // O_DIRECT's precondition: the buffer ADDRESS and length must both be block multiples.
        let b = AlignedBuf::zeroed(BS).unwrap();
        assert_eq!(
            b.as_slice().as_ptr() as usize % BS,
            0,
            "buffer address is block-aligned"
        );
        assert_eq!(
            b.as_slice().len() % BS,
            0,
            "buffer length is a block multiple"
        );
        assert!(b.as_slice().iter().all(|&x| x == 0), "allocated zeroed");
        let big = AlignedBuf::zeroed(4 * BS).unwrap();
        assert_eq!(big.as_slice().as_ptr() as usize % BS, 0);
    }
}
