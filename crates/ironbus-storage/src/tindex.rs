// SPDX-License-Identifier: MIT OR Apache-2.0
//! The per-sealed-segment timestamp -> offset SPARSE index sidecar (`.tindex`, #772; the format
//! specified but never built in #135).
//!
//! # What it is
//! A small, DERIVED, REBUILDABLE accelerator written next to each SEALED segment
//! (`seg-<id>.tindex` beside `seg-<id>.log`, see [`crate::naming::segment_tindex_name`]). It lets a
//! consumer SEEK to a wall-clock timestamp — "give me the first record whose append time is at or
//! after T" — in `O(log segments)` + a bounded per-segment forward scan, instead of a full log
//! scan. It reaches parity with NATS JetStream `DeliverByStartTime`, Kafka `offsetsForTimes`, and
//! Pulsar time-seek.
//!
//! # The sparse anchors
//! An anchor is a `(offset, prefix_max_ts)` pair where `prefix_max_ts` is the MAXIMUM producer
//! timestamp across every record STRICTLY BEFORE `offset` in the segment (an exclusive prefix max).
//! One anchor is taken every `stride` records (the tunable [`crate::log::LogConfig::
//! tindex_stride_records`]), plus one always at the segment base. Two invariants make a seek exact
//! even when producer timestamps are NON-MONOTONIC (delayed messages, #555):
//! - anchors ascend by `offset`;
//! - `prefix_max_ts` is NON-DECREASING in `offset` (a running max), so a threshold query is a
//!   binary search.
//!
//! # Why prefix-MAX (the correctness crux)
//! Producer timestamps are non-monotonic, so a naive "largest indexed ts <= T then scan" would SKIP
//! an out-of-order matching record that sits before the anchor. Anchoring on the exclusive
//! prefix-max makes the anchor a true LOWER BOUND: if `prefix_max_ts(offset) < T` then NO record
//! before `offset` has `ts >= T`, so the first match is at or after `offset`. The seek therefore
//! lands on exactly the same offset a brute-force full scan would (proven in the storage
//! differential test), with the only honest caveat being retention (a match in a reaped segment is
//! gone; the seek clamps to the earliest retained record).
//!
//! # Source of truth
//! The segment records are authoritative; the `.tindex` is a pure accelerator. A missing, torn, or
//! corrupt `.tindex` is REBUILT from a segment scan ([`crate::segment::SegmentReader::
//! time_anchors`]); it never fails a log open and never gates durability. It is a SEPARATE file, so
//! it never perturbs the byte-identity of the segment `.log`.

use ironbus_core::format::CHECKSUM_ALGO_CRC32C;

/// The `.tindex` file magic (`b"TIDX"`), distinguishing it from a segment `.log` and any foreign
/// file. A file whose leading bytes are not this is treated as absent (rebuild from the segment).
pub const TINDEX_MAGIC: [u8; 4] = *b"TIDX";

/// The `.tindex` on-disk format version. Version 1 is the first (and only) layout; a reader that
/// does not recognise the version treats the sidecar as absent and rebuilds, never mis-parsing it.
pub const TINDEX_VERSION: u8 = 1;

/// The bytes of a `.tindex` header preceding the anchor entries: `magic(4) + version(1) +
/// checksum_algo(1) + reserved(2) + segment_id(8) + base_offset(8) + record_count(8) + stride(4) +
/// entry_count(4)`.
const HEADER_LEN: usize = 4 + 1 + 1 + 2 + 8 + 8 + 8 + 4 + 4;

/// The bytes of one anchor entry: `offset(8) + prefix_max_ts(8)`, both little-endian.
const ENTRY_LEN: usize = 16;

/// The trailing CRC32C length (over every preceding byte).
const CRC_LEN: usize = 4;

/// Builds the SPARSE `(offset, prefix_max_ts)` anchors for a segment from its records' producer
/// timestamps IN OFFSET ORDER. One anchor is taken per `stride` records (index `0, stride,
/// 2*stride, ...`), each carrying the EXCLUSIVE prefix max — the maximum timestamp across the
/// records strictly before that anchor's offset. `stride` is clamped up to 1 so a degenerate `0`
/// cannot anchor every record.
///
/// This is the single source of the anchor shape. A SEALED segment's on-disk sidecar is built by
/// scanning its durable frames through [`crate::segment::SegmentReader::time_anchors`] (which uses
/// this rule) the first time it is seeked by time; the ACTIVE segment's anchors are accumulated
/// incrementally as it appends (`Log::append`) with the identical rule — so the scanned, the
/// append-seeded, and the persisted anchors are all byte-identical and a seek resolves the same
/// offset however the anchors were obtained.
#[must_use]
pub fn build_anchors<I: IntoIterator<Item = u64>>(
    timestamps: I,
    base_offset: u64,
    stride: u32,
) -> Vec<(u64, u64)> {
    let stride = u64::from(stride.max(1));
    let mut anchors: Vec<(u64, u64)> = Vec::new();
    let mut running_max = 0u64;
    let mut idx = 0u64;
    for ts in timestamps {
        if idx % stride == 0 {
            // `running_max` is the max over records `[0, idx)` = the exclusive prefix max at this
            // anchor's offset (`base + idx`).
            anchors.push((base_offset.saturating_add(idx), running_max));
        }
        running_max = running_max.max(ts);
        idx = idx.saturating_add(1);
    }
    anchors
}

/// Resolves the bounded forward-scan WINDOW `[scan_from, scan_bound)` within a single segment for
/// the FIRST record whose timestamp satisfies `meets`, using the sparse `anchors` (ascending
/// offset, NON-DECREASING prefix max) and the segment's exclusive record end `seg_end`.
///
/// `meets` is the record-timestamp predicate — `ts >= T` for a start seek (at-or-after) or `ts > T`
/// for an exclusive end bound. Because the prefix max is non-decreasing, `meets(prefix_max)`
/// partitions the anchors into a `false` prefix and a `true` suffix; the last `false` anchor is a
/// LOWER BOUND (no record before it meets), and the first `true` anchor upper-bounds the match, so
/// the first matching record lies in `[scan_from, scan_bound)`. The caller reads that window and
/// returns the first record satisfying `meets`.
///
/// `scan_from` is never below `base_offset`; `scan_bound` never below `scan_from`. When no anchor
/// meets (an empty index, or the only matches sit in the segment's tail past the last anchor), the
/// window extends to `seg_end`, so the bounded scan still finds a tail match.
#[must_use]
pub fn scan_window<M: Fn(u64) -> bool>(
    anchors: &[(u64, u64)],
    base_offset: u64,
    seg_end: u64,
    meets: M,
) -> (u64, u64) {
    // The number of leading anchors whose prefix max does NOT meet: the index of the first anchor
    // that meets (`anchors.len()` if none do). `prefix_max` is non-decreasing, so this is a clean
    // partition point (O(log anchors)).
    let first_meeting = anchors.partition_point(|&(_, pmax)| !meets(pmax));
    // Scan from the anchor JUST BEFORE the first meeting one (the lower bound), or the base when the
    // very first anchor meets (only when `meets` accepts the empty-prefix sentinel, e.g. a start
    // seek to time 0 — the answer is then the segment's first record).
    let lo = first_meeting.saturating_sub(1);
    // The bound is the first meeting anchor's offset. When the first anchor itself meets, use the
    // NEXT anchor so the window is non-empty (`base` up to the end of the first stride bucket).
    let hi = first_meeting.max(lo + 1);
    let scan_from = anchors.get(lo).map_or(base_offset, |&(off, _)| off);
    let scan_bound = anchors.get(hi).map_or(seg_end, |&(off, _)| off);
    (scan_from.max(base_offset), scan_bound.max(scan_from))
}

/// Encodes a segment's sparse time index to its on-disk `.tindex` bytes: the header, the anchor
/// entries, and a trailing CRC32C over everything before it. `record_count` is the sealed segment's
/// record count (a staleness cross-check on load); `stride` is the density the anchors were built
/// at (informational). The bytes are self-describing and self-checking so a torn write is detected
/// (bad CRC) and rebuilt.
#[must_use]
pub fn encode(
    segment_id: u64,
    base_offset: u64,
    record_count: u64,
    stride: u32,
    anchors: &[(u64, u64)],
) -> Vec<u8> {
    let entry_count = u32::try_from(anchors.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(HEADER_LEN + anchors.len() * ENTRY_LEN + CRC_LEN);
    out.extend_from_slice(&TINDEX_MAGIC);
    out.push(TINDEX_VERSION);
    out.push(CHECKSUM_ALGO_CRC32C);
    out.extend_from_slice(&[0u8; 2]); // reserved
    out.extend_from_slice(&segment_id.to_le_bytes());
    out.extend_from_slice(&base_offset.to_le_bytes());
    out.extend_from_slice(&record_count.to_le_bytes());
    out.extend_from_slice(&stride.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    for &(offset, pmax) in anchors {
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&pmax.to_le_bytes());
    }
    let crc = crc32c::crc32c(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// A parsed, validated `.tindex`: its identifying fields and the sparse anchors. Obtained only via
/// [`decode`], which enforces every structural invariant, so a `TimeIndex` value is always
/// well-formed (magic/version/CRC ok, anchors ascending, prefix max non-decreasing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeIndex {
    /// The segment this index describes (cross-checked against the segment header/slot on load).
    pub segment_id: u64,
    /// The segment's base offset (the first anchor's offset).
    pub base_offset: u64,
    /// The sealed segment's record count when the index was built (a staleness cross-check).
    pub record_count: u64,
    /// The record stride the anchors were built at (informational).
    pub stride: u32,
    /// The sparse `(offset, prefix_max_ts)` anchors, ascending by offset, prefix max non-decreasing.
    pub anchors: Vec<(u64, u64)>,
}

/// Decodes and FULLY VALIDATES a `.tindex` from `bytes`, returning `None` for ANY problem — too
/// short, wrong magic/version/checksum-algo, a CRC mismatch (a torn write), an entry count that
/// overflows the buffer, or a structural violation (anchors not strictly ascending by offset, the
/// first anchor not at the base, or the prefix max decreasing). A `None` means "treat as absent and
/// rebuild from the segment", so a corrupt sidecar is NEVER trusted and never fails the caller.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<TimeIndex> {
    if bytes.len() < HEADER_LEN + CRC_LEN {
        return None;
    }
    if bytes[0..4] != TINDEX_MAGIC {
        return None;
    }
    if bytes[4] != TINDEX_VERSION || bytes[5] != CHECKSUM_ALGO_CRC32C {
        return None;
    }
    let entry_count = read_u32(bytes, 36) as usize;
    let body_end = HEADER_LEN.checked_add(entry_count.checked_mul(ENTRY_LEN)?)?;
    // The declared entries must exactly fill the buffer up to the trailing CRC — no more, no less —
    // so a truncated or over-declared file is rejected rather than partially read.
    if body_end.checked_add(CRC_LEN)? != bytes.len() {
        return None;
    }
    let stored_crc = read_u32(bytes, body_end);
    if crc32c::crc32c(&bytes[..body_end]) != stored_crc {
        return None;
    }
    let segment_id = read_u64(bytes, 8);
    let base_offset = read_u64(bytes, 16);
    let record_count = read_u64(bytes, 24);
    let stride = read_u32(bytes, 32);
    let mut anchors: Vec<(u64, u64)> = Vec::with_capacity(entry_count);
    let mut prev_off: Option<u64> = None;
    let mut prev_pmax = 0u64;
    for i in 0..entry_count {
        let at = HEADER_LEN + i * ENTRY_LEN;
        let offset = read_u64(bytes, at);
        let pmax = read_u64(bytes, at + 8);
        // Structural invariants: strictly ascending offsets (first at the base), non-decreasing
        // prefix max. A violation means a bit-flip the CRC somehow missed or a foreign file — reject.
        match prev_off {
            None if offset != base_offset => return None,
            Some(p) if offset <= p => return None,
            _ => {}
        }
        if pmax < prev_pmax {
            return None;
        }
        prev_off = Some(offset);
        prev_pmax = pmax;
        anchors.push((offset, pmax));
    }
    Some(TimeIndex {
        segment_id,
        base_offset,
        record_count,
        stride,
        anchors,
    })
}

fn read_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn read_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // A brute-force reference: the first offset in `[base, base+timestamps.len())` whose timestamp
    // satisfies `meets`, or `base + len` (the tail) if none does. This is the ground truth a seek
    // via the sparse anchors MUST match, for arbitrary (including non-monotonic) timestamps.
    fn brute_force<M: Fn(u64) -> bool>(timestamps: &[u64], base: u64, meets: M) -> u64 {
        for (i, &ts) in timestamps.iter().enumerate() {
            if meets(ts) {
                return base + i as u64;
            }
        }
        base + timestamps.len() as u64
    }

    // Resolve a threshold seek through the anchors + a bounded window scan, exactly as `Log` does,
    // and assert it equals the brute-force offset.
    fn seek_via_anchors<M: Fn(u64) -> bool + Copy>(
        timestamps: &[u64],
        base: u64,
        stride: u32,
        meets: M,
    ) -> u64 {
        let anchors = build_anchors(timestamps.iter().copied(), base, stride);
        let seg_end = base + timestamps.len() as u64;
        let (scan_from, scan_bound) = scan_window(&anchors, base, seg_end, meets);
        // The window must be a valid lower bound: no record BEFORE `scan_from` may meet.
        for (i, &ts) in timestamps.iter().enumerate() {
            let off = base + i as u64;
            if off < scan_from {
                assert!(
                    !meets(ts),
                    "anchor skipped a matching record before scan_from"
                );
            }
        }
        // Forward scan the bounded window for the first match.
        let mut off = scan_from;
        while off < scan_bound {
            let ts = timestamps[usize::try_from(off - base).unwrap()];
            if meets(ts) {
                return off;
            }
            off += 1;
        }
        // No match inside the window: the whole segment has none at or after the lower bound.
        seg_end
    }

    #[test]
    fn seek_equals_brute_force_for_monotonic_and_non_monotonic() {
        let cases: Vec<Vec<u64>> = vec![
            vec![],
            vec![5],
            vec![10, 20, 30, 40, 50],                    // monotonic
            vec![50, 40, 30, 20, 10],                    // strictly decreasing
            vec![10, 5, 30, 2, 50, 1, 40],               // non-monotonic
            vec![7, 7, 7, 7, 7],                         // all equal
            vec![100, 1, 100, 1, 100, 1, 100],           // sawtooth
            (0..300u64).map(|i| (i * 7) % 53).collect(), // pseudo-random, spans several strides
        ];
        for ts in &cases {
            for &base in &[0u64, 1000] {
                for &stride in &[1u32, 2, 3, 8, 1024] {
                    for &t in &[0u64, 1, 2, 5, 7, 30, 49, 50, 53, 100, 101, 1000] {
                        let start = seek_via_anchors(ts, base, stride, |x| x >= t);
                        assert_eq!(
                            start,
                            brute_force(ts, base, |x| x >= t),
                            "start seek ts={ts:?} base={base} stride={stride} t={t}"
                        );
                        let end = seek_via_anchors(ts, base, stride, |x| x > t);
                        assert_eq!(
                            end,
                            brute_force(ts, base, |x| x > t),
                            "end seek ts={ts:?} base={base} stride={stride} t={t}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn encode_decode_round_trips() {
        let anchors = build_anchors([10u64, 5, 30, 2, 50, 1, 40], 1000, 2);
        let bytes = encode(9, 1000, 7, 2, &anchors);
        let parsed = decode(&bytes).expect("valid");
        assert_eq!(parsed.segment_id, 9);
        assert_eq!(parsed.base_offset, 1000);
        assert_eq!(parsed.record_count, 7);
        assert_eq!(parsed.stride, 2);
        assert_eq!(parsed.anchors, anchors);
    }

    #[test]
    fn decode_rejects_torn_and_corrupt() {
        let anchors = build_anchors([10u64, 20, 30, 40], 0, 2);
        let good = encode(1, 0, 4, 2, &anchors);
        assert!(decode(&good).is_some());
        // Truncated.
        assert!(decode(&good[..good.len() - 1]).is_none());
        assert!(decode(&good[..HEADER_LEN]).is_none());
        // A single flipped byte anywhere fails the CRC.
        for i in 0..good.len() {
            let mut torn = good.clone();
            torn[i] ^= 0xff;
            assert!(decode(&torn).is_none(), "flip at {i} should reject");
        }
        // Wrong magic / version.
        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert!(decode(&bad_magic).is_none());
        // Empty / garbage.
        assert!(decode(&[]).is_none());
        assert!(decode(b"not a tindex at all really").is_none());
    }

    #[test]
    fn decode_rejects_structural_violations() {
        // Anchors not ascending: hand-build bytes with a descending offset pair.
        let bad = encode(1, 0, 4, 2, &[(0, 0), (0, 5)]); // equal offsets, not strictly ascending
        assert!(decode(&bad).is_none());
        let bad2 = encode(1, 0, 4, 2, &[(5, 0), (10, 0)]); // first anchor not at base
        assert!(decode(&bad2).is_none());
        let bad3 = encode(1, 0, 4, 2, &[(0, 10), (5, 3)]); // prefix max decreases
        assert!(decode(&bad3).is_none());
    }

    #[test]
    fn build_anchors_places_one_per_stride_with_exclusive_prefix_max() {
        let anchors = build_anchors([10u64, 5, 30, 2, 50], 100, 2);
        // Anchors at indices 0, 2, 4 -> offsets 100, 102, 104.
        // prefix max: [) empty=0, over [100,102)=max(10,5)=10, over [100,104)=max(10,5,30,2)=30.
        assert_eq!(anchors, vec![(100, 0), (102, 10), (104, 30)]);
    }
}
