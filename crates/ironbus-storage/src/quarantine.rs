// SPDX-License-Identifier: MIT OR Apache-2.0
//! The forensic QUARANTINE store: a capped, copy-not-move capture of the corrupt bytes a
//! recovery skip dropped, for offline forensics (#134).
//!
//! When recovery skips a CORRUPT region (a record header or body that failed its checksum, the
//! corruption skip path in [`Log::recover`](crate::log::Log::open), distinct from a clean torn
//! tail) it truncates to the last intact record and continues, by design. The dropped bytes are
//! gone from the live log. This store keeps a FORENSIC COPY of exactly those bytes under a
//! `quarantine/` subdirectory of the data directory, so a bit-rotting node's poison can be pulled
//! off-device and inspected later, WITHOUT ever changing what recovery recovered.
//!
//! ## The three load-bearing properties
//! - COPY, never move. The source segment is read read-only and left byte-for-byte untouched;
//!   recovery's own truncation is what trims the live segment, exactly as before. A crash that
//!   interrupts the copy can at worst leave a partial or absent blob, never lose the source
//!   evidence (the source is the truncated-away tail recovery already accounts for, and the live
//!   segment is independent).
//! - CAPPED. A total quarantine byte budget ([`LogConfig::max_quarantine_bytes`]) bounds the
//!   store so a forensic copy can never exhaust a small edge disk. On reaching the cap the store
//!   evicts OLDEST blobs first (true FIFO by the parsed numeric `(segment_id, start, end)` tuple,
//!   #315) to make room; a single blob larger than the whole cap is
//!   SKIPPED rather than written (the metadata-only fallback the issue describes is a follow-up,
//!   refs #134). `0` means UNLIMITED, matching the repo's `0`-as-off convention for the other
//!   byte caps; the default is a finite 256 MiB.
//! - NEVER blocks recovery. Every method is best-effort: a quarantine IO failure is swallowed
//!   (surfaced only as the store giving up on that one blob), exactly as the resilience-counters
//!   snapshot is a forensic aid and not correctness state. [`Log::open`](crate::log::Log::open)
//!   wraps the whole capture so no quarantine error can ever fail the open or affect the live log.
//!
//! ## Never re-read as live data
//! The store lives in the `quarantine/` SUBDIRECTORY. Recovery enumerates the live log with
//! [`segment_ids`](crate::naming::segment_ids), which lists only the data directory's flat files
//! and never descends into a subdirectory, so a quarantined blob is structurally invisible to the
//! live recovery walk. Blobs are also named `q-...bin`, not `seg-...log`, so even a future flat
//! enumerator would skip them.

use crate::fs::Filesystem;
use crate::io::RandomAccessFile;
use crate::loss::{LossEvent, ReasonCode};
use crate::naming::segment_file_name;

/// The subdirectory of the data directory that holds the forensic quarantine blobs.
pub const QUARANTINE_SUBDIR: &str = "quarantine";

/// The fixed prefix of a quarantine blob file name. Distinct from the `seg-` segment prefix so a
/// blob can never be mistaken for a live segment by any enumerator.
const BLOB_PREFIX: &str = "q-";
/// The fixed suffix of a quarantine blob file name.
const BLOB_SUFFIX: &str = ".bin";

/// The width of the fixed hex segment-id field in a blob name: a `u64` is exactly 16 hex digits,
/// matching [`crate::naming::segment_file_name`].
const SEGMENT_ID_HEX_LEN: usize = 16;

/// The file name for the forensic copy of the corrupt span `[start, end)` of `segment_id`, dropped
/// for `reason`. The name is traceable on its own: the segment id (fixed-width hex, so blobs sort
/// in segment order), the reason's stable metric label, and the byte offset span, so an operator
/// pulling `quarantine/` off-device knows exactly which segment and which bytes each blob holds
/// without opening it. Example: `q-0000000000000003-corrupt_record_body-4096-8192.bin`.
///
/// The `start`/`end` offsets are unpadded decimal (human-readable), so within ONE segment two blob
/// names do not sort numerically by offset (`-100-` precedes `-9-` lexically). Eviction therefore
/// orders blobs by the PARSED numeric tuple via [`parse_blob_sort_key`], not the lexical name, so
/// FIFO is true offset-then-recency order (#315).
#[must_use]
pub fn blob_file_name(segment_id: u64, reason: ReasonCode, start: u64, end: u64) -> String {
    format!(
        "{BLOB_PREFIX}{segment_id:016x}-{}-{start}-{end}{BLOB_SUFFIX}",
        reason.metric_label()
    )
}

/// The numeric eviction-order key `(segment_id, start, end)` parsed from a quarantine blob name, or
/// `None` for any name that is not the canonical [`blob_file_name`] shape (a foreign or OLD-format
/// file left in the dir by a prior version). Eviction sorts on this tuple so FIFO is true numeric
/// (oldest-first) order rather than the lexical name order, in which the unpadded decimal offsets
/// misorder two blobs of the same segment (`-100-` before `-9-`).
///
/// Parsing is best-effort and never panics: the reason label is opaque here (it can contain `-`),
/// so the offsets are taken as the LAST two `-`-separated fields, which is unambiguous because the
/// offsets are decimal and trailing. A name that does not parse is handled by the caller as a
/// best-effort "unknown order" entry, never a crash.
#[must_use]
fn parse_blob_sort_key(name: &str) -> Option<(u64, u64, u64)> {
    let body = name.strip_prefix(BLOB_PREFIX)?.strip_suffix(BLOB_SUFFIX)?;
    // The fixed-width hex segment id, then a `-`, then `<label>-<start>-<end>`.
    let id_hex = body.get(..SEGMENT_ID_HEX_LEN)?;
    if id_hex.len() != SEGMENT_ID_HEX_LEN
        || !id_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let segment_id = u64::from_str_radix(id_hex, 16).ok()?;
    let rest = body.get(SEGMENT_ID_HEX_LEN..)?.strip_prefix('-')?;
    // `<label>-<start>-<end>`. The label may itself contain `-`, but the two trailing decimal
    // offsets never do, so split off the last two fields from the right.
    let (head, end) = rest.rsplit_once('-')?;
    let (_label, start) = head.rsplit_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    Some((segment_id, start, end))
}

/// `true` if `reason` is a CORRUPTION skip that quarantine captures, as opposed to a clean torn or
/// unsynced tail. A [`ReasonCode::TornTail`] is the expected power-loss case (the bytes after the
/// last durable record were simply never fully written); there is nothing forensic to keep, so it
/// is NOT quarantined. Every other reason is a genuine corruption (a failed header or body
/// checksum, a bad magic or version) whose bytes are worth keeping for offline analysis.
#[must_use]
pub fn is_corruption_skip(reason: ReasonCode) -> bool {
    !matches!(reason, ReasonCode::TornTail)
}

/// A capped, copy-not-move forensic store of the corrupt bytes recovery skipped, rooted at the
/// `quarantine/` subdirectory of the data directory (#134).
///
/// Best-effort by construction: every method returns the bytes it actually captured (or `0`) and
/// never an error that could propagate into recovery. The total captured byte count is tracked so
/// the cap is O(1) to enforce and so an operator can expose it as `ironbus_quarantine_bytes`.
#[derive(Debug)]
pub struct QuarantineStore<F: Filesystem> {
    fs: F,
    /// The total bytes of forensic blobs currently held, reconstructed at open from the directory
    /// and advanced on each capture and eviction. The cap is checked against this.
    bytes: u64,
    /// The total quarantine byte budget. `0` means UNLIMITED (the cap is off). A capture that
    /// would push `bytes` over this evicts oldest blobs first to make room.
    cap: u64,
}

/// One quarantine blob on disk: its file name, its captured byte length, and the parsed numeric
/// eviction-order key `(segment_id, start, end)` (or `None` for an unrecognized/old-format name),
/// so eviction can pick the oldest by TRUE numeric order without opening the file.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlobEntry {
    name: String,
    len: u64,
    /// The parsed `(segment_id, start, end)` eviction order, or `None` for a name that is not the
    /// canonical [`blob_file_name`] shape (handled best-effort, never a crash).
    sort_key: Option<(u64, u64, u64)>,
}

impl<F: Filesystem> QuarantineStore<F> {
    /// Opens (creating on demand) the quarantine store rooted at the `quarantine/` subdirectory of
    /// `parent_fs`, reconstructing the held-byte total from the blobs already present so the cap is
    /// enforced across restarts. `cap` is the total byte budget (`0` = unlimited).
    ///
    /// This is best-effort: a failure to create or scan the subdirectory yields an EMPTY,
    /// no-op-ish store (cap-aware but holding nothing) rather than an error, so opening the store
    /// can never fail recovery. The caller treats a failure here as "quarantine unavailable", which
    /// is a forensic gap, not a correctness problem.
    #[must_use]
    pub fn open(parent_fs: &F, cap: u64) -> Option<QuarantineStore<F>> {
        let fs = parent_fs.subdir(QUARANTINE_SUBDIR).ok()?;
        let bytes = Self::scan_bytes(&fs);
        Some(QuarantineStore { fs, bytes, cap })
    }

    /// Sums the byte lengths of every blob already in the subdirectory (best-effort: an entry that
    /// cannot be stat'd is skipped, never fatal). Reconstructs the held-byte total at open.
    fn scan_bytes(fs: &F) -> u64 {
        Self::entries(fs)
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.len))
    }

    /// Lists the quarantine blobs (those whose name has the `q-` / `.bin` shape), in the
    /// filesystem's sorted order, each with its current byte length. Best-effort: a list failure
    /// yields an empty set and a blob whose length cannot be read is skipped, so eviction and the
    /// byte total never fail recovery.
    fn entries(fs: &F) -> Vec<BlobEntry> {
        let Ok(names) = fs.list() else {
            return Vec::new();
        };
        names
            .into_iter()
            .filter(|n| n.starts_with(BLOB_PREFIX) && n.ends_with(BLOB_SUFFIX))
            .filter_map(|name| {
                let len = fs.open(&name).ok()?.len().ok()?;
                let sort_key = parse_blob_sort_key(&name);
                Some(BlobEntry {
                    name,
                    len,
                    sort_key,
                })
            })
            .collect()
    }

    /// The total bytes of forensic blobs currently held. Exposed for the `ironbus_quarantine_bytes`
    /// gauge so a bit-rotting node's forensic copies show up as real disk usage.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The total quarantine byte budget (`0` = unlimited).
    #[must_use]
    pub fn cap(&self) -> u64 {
        self.cap
    }

    /// Borrows the underlying quarantine filesystem (for inspection and tests).
    #[must_use]
    pub fn filesystem(&self) -> &F {
        &self.fs
    }

    /// Copies the corrupt bytes `[event.byte_offset_start, event.byte_offset_end)` of the segment
    /// `event.segment_id` into a forensic blob, reading them read-only from `source` (the live
    /// segment file, untouched). Returns the number of bytes actually captured (`0` if the span was
    /// empty, skipped by the cap, or a best-effort IO step gave up).
    ///
    /// This is the COPY-NOT-MOVE capture: `source` is only ever read here. The cap is enforced
    /// BEFORE the write by evicting oldest blobs first; a single span larger than the whole cap is
    /// skipped (returns `0`) rather than written, since it could never fit (the metadata-only
    /// fallback for that case is a follow-up, refs #134). Best-effort throughout: any IO failure
    /// aborts THIS capture and returns the bytes captured so far (`0`), never an error, so a
    /// quarantine failure can never fail recovery.
    pub fn capture<S: RandomAccessFile>(&mut self, source: &S, event: &LossEvent) -> u64 {
        let start = event.byte_offset_start;
        let end = event.byte_offset_end;
        let span = end.saturating_sub(start);
        if span == 0 {
            return 0;
        }
        // A span that could never fit even an empty store is skipped, not written: capturing a
        // prefix would be misleading forensics (it would not be the whole corrupt region), and the
        // metadata-only record for that case is deferred (refs #134).
        if self.cap != 0 && span > self.cap {
            return 0;
        }
        // Make room under the cap by evicting OLDEST blobs first (FIFO by segment-then-name order),
        // so a steady drip of corruption keeps the most RECENT evidence rather than the stalest.
        if !self.make_room_for(span) {
            return 0;
        }
        let Ok(len) = usize::try_from(span) else {
            return 0;
        };
        // Read the corrupt span read-only from the live segment. A short or failed read gives up on
        // this blob (best-effort) rather than capturing a misleading partial.
        let mut buf = vec![0u8; len];
        if source.read_exact_at(&mut buf, start).is_err() {
            return 0;
        }
        self.write_blob(event, &buf)
    }

    /// Writes one forensic blob, making it durable (file fsync plus the subdirectory dir-sync) so a
    /// power loss right after capture does not lose the evidence's directory entry. Best-effort: any
    /// IO step gives up (returns `0`) and removes a partial file so the byte accounting stays
    /// honest. On success advances the held-byte total and returns the captured byte count.
    fn write_blob(&mut self, event: &LossEvent, bytes: &[u8]) -> u64 {
        let name = blob_file_name(
            event.segment_id,
            event.reason_code,
            event.byte_offset_start,
            event.byte_offset_end,
        );
        // create_new never clobbers; a name collision (the exact same segment/reason/span captured
        // twice) means the blob is already there, so this capture is a no-op rather than an error.
        let Ok(file) = self.fs.create_new(&name) else {
            return 0;
        };
        let captured = bytes.len() as u64;
        let ok = file.write_all_at(bytes, 0).is_ok()
            && file.sync_all().is_ok()
            && self.fs.sync_dir().is_ok();
        if !ok {
            // Roll back a partial blob so it is neither counted nor pulled off-device as truncated
            // forensics. The remove is itself best-effort (a leftover file is at worst stale).
            let _ = self.fs.remove(&name);
            return 0;
        }
        self.bytes = self.bytes.saturating_add(captured);
        captured
    }

    /// Evicts OLDEST blobs (TRUE FIFO by the parsed numeric `(segment_id, start, end)` tuple) until
    /// at least `needed` bytes of headroom exist under the cap, or there is nothing left to evict.
    /// Returns whether `needed` bytes now fit. With the cap off (`0`) it is a no-op that always fits.
    ///
    /// `needed` is already known to be `<= cap` (the single-span-over-cap case is rejected before
    /// this), so evicting every blob always frees enough room; the loop just stops as soon as it
    /// has freed enough, keeping the most RECENT evidence.
    ///
    /// Ordering on the PARSED tuple (not the lexical name) makes FIFO true offset-then-recency
    /// order: the unpadded decimal offsets in the name otherwise misorder two blobs of the same
    /// segment (`-100-` sorts before `-9-` lexically) (#315). An old-format or foreign name that
    /// does not parse sorts AFTER every canonical blob (by `None > Some` here), so it is evicted
    /// only as a last resort and never disturbs the canonical FIFO order; the name tiebreaks for a
    /// stable, deterministic result.
    fn make_room_for(&mut self, needed: u64) -> bool {
        if self.cap == 0 {
            return true;
        }
        if self.bytes.saturating_add(needed) <= self.cap {
            return true;
        }
        let mut blobs = Self::entries(&self.fs);
        // Sort by the TRUE numeric eviction key so oldest (lowest segment id, then lowest start,
        // then lowest end) is first; unparseable names (key `None`) sort last and tiebreak by name.
        blobs.sort_by(|a, b| match (a.sort_key, b.sort_key) {
            (Some(ka), Some(kb)) => ka.cmp(&kb).then_with(|| a.name.cmp(&b.name)),
            (Some(_), None) => core::cmp::Ordering::Less,
            (None, Some(_)) => core::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        });
        // Evict from the front (oldest) until enough fits.
        for blob in &blobs {
            if self.bytes.saturating_add(needed) <= self.cap {
                break;
            }
            if self.fs.remove(&blob.name).is_ok() {
                self.bytes = self.bytes.saturating_sub(blob.len);
            }
        }
        self.bytes.saturating_add(needed) <= self.cap
    }
}

/// Best-effort, READ-ONLY: the total bytes of forensic blobs already persisted in the
/// `quarantine/` subdirectory of `parent_fs`, reconstructed from the durable blobs alone, so the
/// `ironbus_quarantine_bytes` gauge reflects the PERSISTED on-disk footprint a bit-rotting node's
/// prior recoveries left, surviving a restart (#315).
///
/// This is the scan-on-open companion to [`quarantine_corrupt_span`]: a clean reopen with no new
/// corruption skip never calls `capture`, yet the prior blobs still occupy real disk, so the gauge
/// is seeded from this scan rather than reading `0`.
///
/// It must NEVER fail or even side-effect recovery, so it preserves the #134 safety properties:
/// - It is strictly read-only: it lists and stats blobs, never writes, moves, or removes one.
/// - It probes [`Filesystem::subdir_exists`] FIRST and returns `0` without materializing the
///   subdirectory when it is absent, so a clean log that never had a corruption skip keeps the
///   subdir un-created (the same contract [`quarantine_recovery_losses`] honors).
/// - A missing, unreadable, or empty quarantine dir degrades to `0`; nothing here can return an
///   error, so [`Log::open`](crate::log::Log::open) can call it unconditionally.
#[must_use]
pub fn persisted_bytes<F: Filesystem>(parent_fs: &F) -> u64 {
    // Probe first so a clean log never materializes the subdir as a side effect of the scan.
    if !matches!(parent_fs.subdir_exists(QUARANTINE_SUBDIR), Ok(true)) {
        return 0;
    }
    let Ok(fs) = parent_fs.subdir(QUARANTINE_SUBDIR) else {
        return 0;
    };
    QuarantineStore::scan_bytes(&fs)
}

/// Best-effort: copies the corrupt bytes of ONE corruption-skip loss event into the quarantine
/// store, reading them read-only from `source` (the live segment file, still holding its full
/// pre-truncation image). Returns the bytes captured (`0` if nothing was, for any reason).
///
/// This is the entry point [`Log::open`](crate::log::Log::open) calls on the active-segment
/// recovery path: it already holds the open segment handle just before truncating the corrupt
/// tail, so the copy reads the corrupt bytes that the truncation is about to drop. Best-effort and
/// forensic throughout: opening the store and writing the blob are swallowed on failure, so this
/// can never fail the open. The caller must only invoke this for a corruption skip (it does not
/// re-check `event.reason_code`); a clean torn tail should never be passed here.
pub fn quarantine_corrupt_span<F: Filesystem, S: RandomAccessFile>(
    parent_fs: &F,
    source: &S,
    event: &LossEvent,
    cap: u64,
) -> u64 {
    let Some(mut store) = QuarantineStore::open(parent_fs, cap) else {
        return 0;
    };
    store.capture(source, event)
}

/// Best-effort: copies the corrupt bytes of EACH corruption-skip loss event into the quarantine
/// store, reading them read-only from the live segment file via `parent_fs`. A clean torn tail is
/// never quarantined (see [`is_corruption_skip`]). Returns the total bytes captured across all
/// events.
///
/// This is the single entry point [`Log::open`](crate::log::Log::open) calls after recovery has
/// recorded its loss events. It is wrapped so that NOTHING here can fail the open: opening the
/// store, reading the source, and writing each blob are all best-effort. Recovery's own truncation
/// and bounded-loss accounting are entirely independent of whether any byte was quarantined.
pub fn quarantine_recovery_losses<F: Filesystem>(
    parent_fs: &F,
    events: &[LossEvent],
    cap: u64,
) -> u64 {
    // Capture only the corruption skips; if there are none, never even materialize the subdir.
    if !events.iter().any(|e| is_corruption_skip(e.reason_code)) {
        return 0;
    }
    let Some(mut store) = QuarantineStore::open(parent_fs, cap) else {
        return 0;
    };
    let mut captured = 0u64;
    for event in events {
        if !is_corruption_skip(event.reason_code) {
            continue;
        }
        // Open the live segment read-only; a failure here just skips this one blob.
        let Ok(source) = parent_fs.open(&segment_file_name(event.segment_id)) else {
            continue;
        };
        captured = captured.saturating_add(store.capture(&source, event));
    }
    captured
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;

    /// Writes a fake "segment" file of `bytes` onto a fresh disk, so a capture can read a known span
    /// back out. The quarantine path only ever reads this file, so its content need not be a real
    /// segment.
    fn disk_with_source(segment_id: u64, bytes: &[u8]) -> InMemoryFs {
        let fs = InMemoryFs::new();
        let f = fs.create_new(&segment_file_name(segment_id)).unwrap();
        f.write_all_at(bytes, 0).unwrap();
        f.sync_all().unwrap();
        fs.sync_dir().unwrap();
        fs
    }

    fn event(segment_id: u64, start: u64, end: u64, reason: ReasonCode) -> LossEvent {
        LossEvent::span(segment_id, start, end, 1, reason)
    }

    #[test]
    fn blob_name_is_traceable_and_distinct_from_a_segment() {
        let name = blob_file_name(3, ReasonCode::CorruptRecordBody, 4096, 8192);
        assert_eq!(name, "q-0000000000000003-corrupt_record_body-4096-8192.bin");
        // It can never be parsed as a live segment (different prefix and suffix).
        assert!(crate::naming::parse_segment_file_name(&name).is_none());
    }

    #[test]
    fn only_corruption_skips_are_quarantined() {
        assert!(!is_corruption_skip(ReasonCode::TornTail));
        assert!(is_corruption_skip(ReasonCode::CorruptRecordHeader));
        assert!(is_corruption_skip(ReasonCode::CorruptRecordBody));
        assert!(is_corruption_skip(ReasonCode::CorruptSegmentHeader));
        assert!(is_corruption_skip(ReasonCode::SequenceGap));
    }

    #[test]
    fn capture_copies_the_corrupt_span_verbatim() {
        let source_bytes: Vec<u8> = (0u8..100).collect();
        let fs = disk_with_source(0, &source_bytes);
        let mut store = QuarantineStore::open(&fs, 0).unwrap();
        let e = event(0, 40, 60, ReasonCode::CorruptRecordBody);
        let captured = store.capture(&fs.open(&segment_file_name(0)).unwrap(), &e);
        assert_eq!(captured, 20);
        assert_eq!(store.bytes(), 20);
        // The blob holds EXACTLY the corrupt span, byte for byte.
        let blob = store
            .filesystem()
            .open(&blob_file_name(0, ReasonCode::CorruptRecordBody, 40, 60))
            .unwrap();
        let mut buf = vec![0u8; 20];
        blob.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(buf, source_bytes[40..60]);
        // The source segment is left untouched (copy, not move).
        assert_eq!(fs.open(&segment_file_name(0)).unwrap().len().unwrap(), 100);
    }

    #[test]
    fn an_empty_span_captures_nothing() {
        let fs = disk_with_source(0, &[1, 2, 3]);
        let mut store = QuarantineStore::open(&fs, 0).unwrap();
        let e = event(0, 2, 2, ReasonCode::CorruptRecordHeader);
        assert_eq!(
            store.capture(&fs.open(&segment_file_name(0)).unwrap(), &e),
            0
        );
        assert_eq!(store.bytes(), 0);
    }

    #[test]
    fn the_byte_total_survives_a_reopen() {
        let source_bytes: Vec<u8> = (0u8..100).collect();
        let fs = disk_with_source(0, &source_bytes);
        {
            let mut store = QuarantineStore::open(&fs, 0).unwrap();
            store.capture(
                &fs.open(&segment_file_name(0)).unwrap(),
                &event(0, 10, 30, ReasonCode::CorruptRecordBody),
            );
        }
        // A fresh store reconstructs the held-byte total from the durable blobs alone.
        let reopened = QuarantineStore::open(&fs, 0).unwrap();
        assert_eq!(reopened.bytes(), 20);
    }

    #[test]
    fn the_cap_evicts_oldest_first_to_make_room() {
        let source_bytes: Vec<u8> = (0u8..255).collect();
        let fs = disk_with_source(0, &source_bytes);
        // Cap of 50 bytes. Capture three 20-byte spans: the third must evict the first.
        let mut store = QuarantineStore::open(&fs, 50).unwrap();
        let src = fs.open(&segment_file_name(0)).unwrap();
        // Distinct segment ids so the blob names sort oldest-first by segment id.
        let fs1 = disk_with_source(1, &source_bytes);
        let fs2 = disk_with_source(2, &source_bytes);
        assert_eq!(
            store.capture(&src, &event(0, 0, 20, ReasonCode::CorruptRecordBody)),
            20
        );
        assert_eq!(
            store.capture(
                &fs1.open(&segment_file_name(1)).unwrap(),
                &event(1, 0, 20, ReasonCode::CorruptRecordBody)
            ),
            20
        );
        assert_eq!(store.bytes(), 40);
        // The third 20-byte blob (total would be 60 > 50) evicts the oldest (segment 0).
        assert_eq!(
            store.capture(
                &fs2.open(&segment_file_name(2)).unwrap(),
                &event(2, 0, 20, ReasonCode::CorruptRecordBody)
            ),
            20
        );
        assert_eq!(store.bytes(), 40, "still two blobs after eviction");
        assert!(
            store
                .filesystem()
                .open(&blob_file_name(0, ReasonCode::CorruptRecordBody, 0, 20))
                .is_err(),
            "the oldest blob (segment 0) was evicted"
        );
        assert!(store
            .filesystem()
            .open(&blob_file_name(2, ReasonCode::CorruptRecordBody, 0, 20))
            .is_ok());
    }

    #[test]
    fn eviction_is_true_fifo_within_a_segment_not_lexical() {
        // Two blobs in the SAME segment whose offsets sort DIFFERENTLY lexically vs numerically:
        // start 9 (`-9-`) is numerically older than start 100 (`-100-`), but `-100-` sorts BEFORE
        // `-9-` lexically. True-FIFO must evict the numerically-older one (start 9) first (#315).
        let source_bytes: Vec<u8> = (0u8..255).collect();
        let fs = disk_with_source(0, &source_bytes);
        let src = fs.open(&segment_file_name(0)).unwrap();
        // Cap 40: holds two 20-byte blobs; a third evicts the oldest.
        let mut store = QuarantineStore::open(&fs, 40).unwrap();
        // Capture start=9 (numerically older) THEN start=100 (numerically newer). Both 20 bytes.
        assert_eq!(
            store.capture(&src, &event(0, 9, 29, ReasonCode::CorruptRecordBody)),
            20
        );
        assert_eq!(
            store.capture(&src, &event(0, 100, 120, ReasonCode::CorruptRecordBody)),
            20
        );
        assert_eq!(store.bytes(), 40);
        // The names: `-100-` sorts lexically BEFORE `-9-`, so a lexical FIFO would wrongly evict the
        // start=100 blob. Confirm the lexical trap is real.
        let name_9 = blob_file_name(0, ReasonCode::CorruptRecordBody, 9, 29);
        let name_100 = blob_file_name(0, ReasonCode::CorruptRecordBody, 100, 120);
        assert!(name_100 < name_9, "lexically -100- precedes -9-: the trap");
        // A third blob (start=200) forces an eviction. True-FIFO evicts the numerically-OLDEST
        // (start=9), keeping the newer start=100.
        assert_eq!(
            store.capture(&src, &event(0, 200, 220, ReasonCode::CorruptRecordBody)),
            20
        );
        assert_eq!(store.bytes(), 40, "still two blobs after eviction");
        assert!(
            store.filesystem().open(&name_9).is_err(),
            "the numerically-oldest blob (start=9) was evicted, not the lexically-first"
        );
        assert!(
            store.filesystem().open(&name_100).is_ok(),
            "the numerically-newer blob (start=100) was kept"
        );
    }

    #[test]
    fn an_old_format_blob_name_is_handled_best_effort_and_evicted_last() {
        // A blob left on disk by a prior version (an unrecognized `q-...bin` name that does NOT
        // parse to a sort key) must not crash eviction and must sort AFTER every canonical blob, so
        // a canonical blob is always evicted first. The old blob is still counted toward the cap.
        let fs = disk_with_source(0, &(0u8..255).collect::<Vec<_>>());
        // Hand-write an "old-format" blob: q- prefix, .bin suffix, but a shape parse_blob_sort_key
        // rejects (no fixed-width hex id), so its sort_key is None.
        let old_name = "q-legacy-blob-shape.bin";
        assert_eq!(parse_blob_sort_key(old_name), None);
        {
            let store = QuarantineStore::open(&fs, 40).unwrap();
            let f = store.filesystem().create_new(old_name).unwrap();
            f.write_all_at(&[0u8; 20], 0).unwrap();
            f.sync_all().unwrap();
        }
        // Re-open so the store scans the hand-written old blob into its byte total.
        let mut store = QuarantineStore::open(&fs, 40).unwrap();
        assert_eq!(
            store.bytes(),
            20,
            "the old-format blob counts toward the cap"
        );
        let src = fs.open(&segment_file_name(0)).unwrap();
        // Add a canonical blob, then a second canonical blob forces an eviction. The canonical one
        // (sort_key Some) is evicted before the old-format one (sort_key None).
        assert_eq!(
            store.capture(&src, &event(0, 0, 20, ReasonCode::CorruptRecordBody)),
            20
        );
        assert_eq!(store.bytes(), 40);
        assert_eq!(
            store.capture(&src, &event(1, 0, 20, ReasonCode::CorruptRecordBody)),
            20
        );
        assert_eq!(store.bytes(), 40, "still two blobs after eviction");
        assert!(
            store.filesystem().open(old_name).is_ok(),
            "the old-format blob is evicted LAST (kept here)"
        );
        assert!(
            store
                .filesystem()
                .open(&blob_file_name(0, ReasonCode::CorruptRecordBody, 0, 20))
                .is_err(),
            "the canonical blob was evicted before the old-format one"
        );
    }

    #[test]
    fn parse_blob_sort_key_round_trips_the_canonical_name() {
        // The parsed key is exactly (segment_id, start, end) for every reason label, including one
        // whose label contains characters, and rejects foreign or old-format shapes.
        for reason in [
            ReasonCode::CorruptRecordHeader,
            ReasonCode::CorruptRecordBody,
            ReasonCode::CorruptSegmentHeader,
            ReasonCode::SequenceGap,
        ] {
            let name = blob_file_name(0xab, reason, 9, 100);
            assert_eq!(parse_blob_sort_key(&name), Some((0xab, 9, 100)));
        }
        // Foreign / old-format names parse to None (handled best-effort, never a crash).
        for bad in [
            "README.md",
            "q-.bin",
            "q-legacy-blob-shape.bin",
            "seg-0000000000000003.log",
            "q-0000000000000003-corrupt_record_body-4096.bin", // missing the end field
            "q-000000000000000g-corrupt_record_body-1-2.bin",  // non-hex id
        ] {
            assert_eq!(parse_blob_sort_key(bad), None, "should reject {bad:?}");
        }
    }

    #[test]
    fn persisted_bytes_reflects_the_on_disk_total_without_materializing_an_absent_subdir() {
        // persisted_bytes is the read-only scan-on-open the gauge uses (#315): it returns the total
        // on a populated dir, 0 on an absent one, and NEVER creates the subdir for an absent one.
        let fs = disk_with_source(0, &(0u8..100).collect::<Vec<_>>());
        // No quarantine dir yet: 0, and the probe must not materialize it.
        assert_eq!(persisted_bytes(&fs), 0);
        assert!(!fs.subdir_exists(QUARANTINE_SUBDIR).unwrap());
        // After a capture, persisted_bytes reflects the durable blob's bytes.
        {
            let mut store = QuarantineStore::open(&fs, 0).unwrap();
            store.capture(
                &fs.open(&segment_file_name(0)).unwrap(),
                &event(0, 10, 30, ReasonCode::CorruptRecordBody),
            );
        }
        assert_eq!(persisted_bytes(&fs), 20, "reflects the persisted footprint");
    }

    #[test]
    fn a_span_larger_than_the_whole_cap_is_skipped() {
        let source_bytes: Vec<u8> = (0u8..100).collect();
        let fs = disk_with_source(0, &source_bytes);
        let mut store = QuarantineStore::open(&fs, 10).unwrap();
        // A 50-byte span can never fit a 10-byte cap: skipped, not partially written.
        let captured = store.capture(
            &fs.open(&segment_file_name(0)).unwrap(),
            &event(0, 0, 50, ReasonCode::CorruptRecordBody),
        );
        assert_eq!(captured, 0);
        assert_eq!(store.bytes(), 0);
        assert!(store.filesystem().list().unwrap().is_empty());
    }

    #[test]
    fn quarantine_recovery_losses_skips_a_clean_torn_tail() {
        let fs = disk_with_source(0, &(0u8..100).collect::<Vec<_>>());
        // A torn tail is not forensic: nothing is captured and the subdir is never materialized.
        let captured =
            quarantine_recovery_losses(&fs, &[event(0, 10, 30, ReasonCode::TornTail)], 0);
        assert_eq!(captured, 0);
        assert!(!fs.subdir_exists(QUARANTINE_SUBDIR).unwrap());
    }

    #[test]
    fn quarantine_recovery_losses_copies_each_corruption_skip() {
        let source_bytes: Vec<u8> = (0u8..100).collect();
        let fs = disk_with_source(0, &source_bytes);
        let captured = quarantine_recovery_losses(
            &fs,
            &[
                event(0, 10, 30, ReasonCode::CorruptRecordBody),
                event(0, 30, 30, ReasonCode::TornTail), // skipped (clean tail)
            ],
            0,
        );
        assert_eq!(captured, 20);
        let store = QuarantineStore::open(&fs, 0).unwrap();
        assert_eq!(store.bytes(), 20);
    }
}
