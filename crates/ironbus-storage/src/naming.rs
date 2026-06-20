// SPDX-License-Identifier: MIT OR Apache-2.0
//! Segment file naming and directory enumeration.
//!
//! A segment file is named `seg-<id>.log`, where `<id>` is the 16-digit, zero-padded,
//! lowercase hexadecimal segment id. Sixteen hex digits is exactly the width of a
//! `u64`, so the name is fixed width and its lexicographic order equals the numeric
//! segment-id order. Recovery discovers segments by listing the data directory and
//! parsing these names, skipping any foreign file: the directory of self-describing
//! files is the authority, no manifest required.

use crate::fs::Filesystem;
use std::io;

/// The fixed prefix of a segment file name.
const PREFIX: &str = "seg-";
/// The fixed suffix of a segment file name.
const SUFFIX: &str = ".log";
/// The width of the hex id field: a `u64` is exactly 16 hex digits.
const ID_HEX_LEN: usize = 16;

/// The on-disk file name for the segment with this id. Segment 1 is
/// `seg-0000000000000001.log`; the id is fixed-width lowercase hex so names sort
/// lexicographically in segment-id order.
#[must_use]
pub fn segment_file_name(segment_id: u64) -> String {
    format!("{PREFIX}{segment_id:016x}{SUFFIX}")
}

/// The on-disk file name of the default work-group's durable cursor checkpoint (`cursor.ckpt`).
/// The empty group name is the default; a path-unsafe name in [`cursor_checkpoint_name`] is
/// lowercase-hex-encoded, so the default and the named files never collide (`cursor.` vs
/// `cursor-`). This is the SAME name the broker writes (`ironbus-server`'s engine), kept here so
/// the storage layer (and the offline admin verbs) and the engine agree on one set of names.
const DEFAULT_CURSOR_CHECKPOINT: &str = "cursor.ckpt";
/// The filename prefix of a NAMED work-group's durable cursor checkpoint, ahead of the hex name.
const NAMED_CURSOR_PREFIX: &str = "cursor-";
/// The filename suffix of a named work-group's durable cursor checkpoint.
const NAMED_CURSOR_SUFFIX: &str = ".ckpt";

/// The durable cursor-checkpoint file name for a work-group: `cursor.ckpt` for the default group
/// (the empty name), else `cursor-<hex(name)>.ckpt` with the name lowercase-hex-encoded so a
/// path-unsafe character (`/`, `:`, ...) never reaches the filesystem. This is the canonical name
/// the broker writes and the offline admin verbs (consumer-reset, #299) rewrite.
#[must_use]
pub fn cursor_checkpoint_name(group: &str) -> String {
    if group.is_empty() {
        DEFAULT_CURSOR_CHECKPOINT.to_string()
    } else {
        format!(
            "{NAMED_CURSOR_PREFIX}{}{NAMED_CURSOR_SUFFIX}",
            hex_encode(group.as_bytes())
        )
    }
}

/// Lowercase-hex-encodes bytes, for embedding a graphic-ASCII work-group name in a safe,
/// reversible filename. A 16-entry nibble table makes the encoding total (no fallback, the index
/// is provably in bounds), so it can never silently emit a wrong digit.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Decodes a lowercase-hex string back to its bytes, the inverse of [`hex_encode`], returning `None`
/// for any string that is not canonical lowercase hex of even length (an odd length, an uppercase
/// digit, or a non-hex byte). This is how a `streams/<hex>/` subdir name is decoded back to its
/// original stream name at open ([`parse_stream_subdir_name`]): a foreign or non-canonical directory
/// is rejected (a `None`) rather than misread, exactly as [`parse_segment_file_name`] rejects a
/// non-canonical segment name.
#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// The on-disk directory name for a NAMED stream's per-stream log, under the data-dir's reserved
/// `streams/` subtree (M2-I2). The stream NAME is lowercase-hex-encoded (the same reversible,
/// path-safe encoding [`cursor_checkpoint_name`] uses for a work-group name), so a path-unsafe byte
/// (`/`, `.`, `..`, NUL) in the name never reaches the filesystem as a directory separator or a
/// traversal. The default stream `""` is NOT named here — it is today's ROOT log, not a `streams/`
/// child — so this is only ever called for a non-empty, validated name.
///
/// `streams/<hex(name)>/` mirrors the `dlq/` subdir pattern (one self-contained
/// [`crate::log::Log`] per directory), generalized to N streams; the hex encoding makes the round
/// trip exact so [`parse_stream_subdir_name`] recovers the original name byte-for-byte.
#[must_use]
pub fn stream_subdir_name(name: &str) -> String {
    hex_encode(name.as_bytes())
}

/// Parses a `streams/` child directory name back to its stream name, the inverse of
/// [`stream_subdir_name`], returning `None` for any directory that is not a canonical hex-encoded
/// stream name (a foreign directory, or one whose decoded bytes are not a valid stream name). A
/// `None` is skipped at open exactly as a foreign segment file is skipped by [`segment_ids`], so a
/// stray directory under `streams/` never opens as (or shadows) a real stream.
///
/// The decoded bytes must themselves pass [`is_valid_stream_name`] (non-empty, within the length
/// bound, graphic-ASCII): the empty name decodes to the default stream `""`, which does NOT live
/// under `streams/`, so an empty (`""` -> `""`) decode is rejected here rather than aliasing the
/// root log.
#[must_use]
pub fn parse_stream_subdir_name(dir: &str) -> Option<String> {
    let bytes = hex_decode(dir)?;
    let name = String::from_utf8(bytes).ok()?;
    if is_valid_stream_name(&name) {
        Some(name)
    } else {
        None
    }
}

/// The fixed prefix of a partition sub-log directory name, ahead of its zero-padded hex index.
const PARTITION_PREFIX: &str = "p-";
/// The width of a partition index's hex field: a `u32` is exactly 8 hex digits, so the name is
/// fixed-width and sorts lexicographically in partition-index order (mirroring `seg-<016x>.log`).
const PARTITION_IDX_HEX_LEN: usize = 8;

/// The on-disk directory name for partition `idx` of a stream subdivided into `P > 1` partitions
/// (M2-I11): `p-<08x>/` under the stream's root, with the index zero-padded lowercase hex so the
/// names sort in index order. Partition 0 is `p-00000000`.
///
/// This mirrors the `streams/<hex(name)>/` and `seg-<016x>.log` discipline: a self-describing,
/// path-safe, fixed-width name parsed back by [`parse_partition_subdir_name`], so a foreign directory
/// under a partitioned stream's root is skipped, never opened as a partition. A SINGLE-partition
/// stream (`P = 1`) does NOT use this — its one partition IS the stream's own log (the root log for
/// the default stream, `streams/<hex>/` for a named one), with NO `p-*/` subdir, so a single-partition
/// stream is byte-for-byte a non-partitioned stream on disk.
#[must_use]
pub fn partition_subdir_name(idx: u32) -> String {
    format!("{PARTITION_PREFIX}{idx:08x}")
}

/// Parses a partition sub-log directory name back to its index, the inverse of
/// [`partition_subdir_name`], returning `None` for any directory that is not a canonical
/// `p-<8 lowercase hex>` name (a foreign directory, or a non-canonical width/case). A `None` is
/// skipped at open exactly as a foreign segment file is skipped, so a stray directory under a
/// partitioned stream's root never opens as a partition.
#[must_use]
pub fn parse_partition_subdir_name(dir: &str) -> Option<u32> {
    let idx = dir.strip_prefix(PARTITION_PREFIX)?;
    if idx.len() != PARTITION_IDX_HEX_LEN {
        return None;
    }
    // Canonical lowercase hex only (not uppercase, not a sign), so the round trip is exact.
    if !idx.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u32::from_str_radix(idx, 16).ok()
}

/// The maximum byte length of a NAMED stream's name, matching the engine's `MAX_GROUP_NAME_LEN`
/// (128): a stream id is named under the same graphic-ASCII, length-bounded discipline as a
/// work-group, so the two name spaces validate identically and a stream name is always short enough
/// to hex-encode into a path component well within any filesystem's name limit (128 bytes -> 256 hex
/// chars).
pub const MAX_STREAM_NAME_LEN: usize = 128;

/// Whether `name` is a valid NAMED stream name: 1 to [`MAX_STREAM_NAME_LEN`] graphic-ASCII bytes.
/// This is the SAME rule the engine's `validate_group_name` (and `admin::validate_group`) applies to
/// a work-group name, reused so a stream id and a work-group id share one validation contract.
///
/// Note the DEFAULT stream `""` (the empty name) is intentionally NOT valid here: it is today's root
/// log, addressed by the empty name as a special case by the caller, never created as a `streams/`
/// child. So `is_valid_stream_name("")` is `false` — the empty name is the default stream, not a
/// named one.
#[must_use]
pub fn is_valid_stream_name(name: &str) -> bool {
    (1..=MAX_STREAM_NAME_LEN).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_graphic())
}

/// Parses a segment file name back to its segment id, returning `None` for any name
/// that is not a canonical segment file (any foreign file in the data directory).
///
/// Parsing is strict and canonical: only the exact form [`segment_file_name`] produces
/// is accepted (lowercase hex, exact width), so `segment_file_name` and this function
/// are inverses on the set of valid names.
#[must_use]
pub fn parse_segment_file_name(name: &str) -> Option<u64> {
    let id = name.strip_prefix(PREFIX)?.strip_suffix(SUFFIX)?;
    if id.len() != ID_HEX_LEN {
        return None;
    }
    // Accept only canonical lowercase hex digits (not uppercase, not a leading sign),
    // so the round trip is exact. After this check the 16-digit value always fits a u64.
    if !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u64::from_str_radix(id, 16).ok()
}

/// Lists the segment ids present in the data directory, in ascending order, skipping
/// any file that is not a segment.
///
/// # Errors
/// Propagates the underlying [`Filesystem`] error.
pub fn segment_ids<F: Filesystem>(fs: &F) -> io::Result<Vec<u64>> {
    let mut ids: Vec<u64> = fs
        .list()?
        .iter()
        .filter_map(|name| parse_segment_file_name(name))
        .collect();
    // Sort here so `segment_ids` does not depend on any `Filesystem::list` ordering
    // guarantee: a third-party backend that lists in arbitrary order still yields
    // ascending ids. (Both shipped backends already list sorted, so this is a no-op
    // for them.)
    ids.sort_unstable();
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use proptest::prelude::*;

    #[test]
    fn known_names() {
        assert_eq!(segment_file_name(0), "seg-0000000000000000.log");
        assert_eq!(segment_file_name(1), "seg-0000000000000001.log");
        assert_eq!(segment_file_name(255), "seg-00000000000000ff.log");
        assert_eq!(segment_file_name(u64::MAX), "seg-ffffffffffffffff.log");
    }

    #[test]
    fn cursor_checkpoint_names_match_the_brokers() {
        // The default group is `cursor.ckpt`; a named group is `cursor-<hex(name)>.ckpt`. These are
        // the exact names the broker engine writes, so the offline consumer-reset rewrites the same
        // file the broker resumes from.
        assert_eq!(cursor_checkpoint_name(""), "cursor.ckpt");
        assert_eq!(cursor_checkpoint_name("orders"), "cursor-6f7264657273.ckpt");
        // A path-unsafe name is hex-encoded, never reaching the filesystem as `/` or `:`.
        assert_eq!(cursor_checkpoint_name("a/b"), "cursor-612f62.ckpt");
        // The default and named forms can never collide (`cursor.` vs `cursor-`).
        assert!(cursor_checkpoint_name("").starts_with("cursor."));
        assert!(cursor_checkpoint_name("x").starts_with("cursor-"));
    }

    #[test]
    fn hex_encode_is_lowercase_and_two_digits_per_byte() {
        assert_eq!(hex_encode(b""), "");
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_encode(b"AB"), "4142");
    }

    #[test]
    fn hex_decode_is_the_inverse_of_encode_and_rejects_non_canonical() {
        // Round-trips every byte value.
        for b in 0u8..=255 {
            let enc = hex_encode(&[b]);
            assert_eq!(hex_decode(&enc), Some(vec![b]));
        }
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("000fff"), Some(vec![0x00, 0x0f, 0xff]));
        // Odd length, uppercase (non-canonical), and a non-hex digit are all rejected, so a foreign
        // directory name never decodes to a real stream name.
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("AB"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn stream_subdir_name_round_trips_through_parse() {
        for name in [
            "orders",
            "a/b",
            "metrics.cpu",
            "x",
            &"n".repeat(MAX_STREAM_NAME_LEN),
        ] {
            let dir = stream_subdir_name(name);
            // The on-disk dir is path-safe hex (no `/`, `.`, `..`), so it is a single safe component.
            assert!(!dir.contains('/') && dir != "." && dir != "..");
            assert_eq!(parse_stream_subdir_name(&dir).as_deref(), Some(name));
        }
    }

    #[test]
    fn parse_stream_subdir_rejects_foreign_and_the_empty_default() {
        // The empty stream (the default root log) is NOT a `streams/` child: its hex-encoding is the
        // empty string, which must NOT parse back to a valid named stream.
        assert_eq!(stream_subdir_name(""), "");
        assert_eq!(parse_stream_subdir_name(""), None);
        // A foreign directory under streams/ (non-hex, uppercase, odd length) is skipped, never read
        // as a stream.
        assert_eq!(parse_stream_subdir_name("not-hex"), None);
        assert_eq!(parse_stream_subdir_name("4142z"), None);
        // Hex that decodes to bytes that are not a valid stream name (a control byte) is rejected.
        assert_eq!(parse_stream_subdir_name(&hex_encode(b"a\nb")), None);
        // Hex that decodes to a too-long name is rejected.
        let too_long = hex_encode(&[b'x'; MAX_STREAM_NAME_LEN + 1]);
        assert_eq!(parse_stream_subdir_name(&too_long), None);
    }

    #[test]
    fn partition_subdir_name_round_trips_through_parse() {
        for idx in [0u32, 1, 15, 255, 4096, 1_000_000, u32::MAX] {
            let dir = partition_subdir_name(idx);
            // Path-safe, fixed-width, single component (no `/`, `.`, `..`).
            assert!(!dir.contains('/') && dir != "." && dir != "..");
            assert_eq!(dir.len(), PARTITION_PREFIX.len() + PARTITION_IDX_HEX_LEN);
            assert_eq!(parse_partition_subdir_name(&dir), Some(idx));
        }
        assert_eq!(partition_subdir_name(0), "p-00000000");
        assert_eq!(partition_subdir_name(255), "p-000000ff");
    }

    #[test]
    fn parse_partition_subdir_rejects_foreign_and_non_canonical() {
        // A foreign directory (a stream subdir, a segment file, a non-`p-` name) is skipped.
        assert_eq!(parse_partition_subdir_name("streams"), None);
        assert_eq!(parse_partition_subdir_name("not-a-partition"), None);
        assert_eq!(
            parse_partition_subdir_name(&stream_subdir_name("orders")),
            None
        );
        // Wrong width, uppercase, a non-hex digit, and a missing prefix are all rejected.
        assert_eq!(parse_partition_subdir_name("p-0"), None);
        assert_eq!(parse_partition_subdir_name("p-000000FF"), None);
        assert_eq!(parse_partition_subdir_name("p-0000000g"), None);
        assert_eq!(parse_partition_subdir_name("00000000"), None);
        assert_eq!(parse_partition_subdir_name("p-000000001"), None);
    }

    #[test]
    fn partition_names_sort_in_index_order() {
        // Fixed-width hex means lexicographic order is numeric order, so a directory listing of a
        // partitioned stream enumerates its partitions in index order.
        let mut names: Vec<String> = [255u32, 1, 16, 0, 4096]
            .iter()
            .map(|idx| partition_subdir_name(*idx))
            .collect();
        names.sort();
        let idxs: Vec<u32> = names
            .iter()
            .map(|n| parse_partition_subdir_name(n).unwrap())
            .collect();
        assert_eq!(idxs, vec![0, 1, 16, 255, 4096]);
    }

    #[test]
    fn is_valid_stream_name_matches_the_group_rule() {
        // 1..=128 graphic-ASCII bytes, exactly like a work-group name.
        assert!(is_valid_stream_name("orders"));
        assert!(is_valid_stream_name("a/b")); // graphic ASCII; the filesystem-unsafe `/` is handled by hex-encoding
        assert!(is_valid_stream_name(&"n".repeat(MAX_STREAM_NAME_LEN)));
        // The default stream "" is NOT a valid NAMED stream (it is the root log).
        assert!(!is_valid_stream_name(""));
        // Too long, whitespace, a control byte, and non-ASCII are all rejected.
        assert!(!is_valid_stream_name(&"n".repeat(MAX_STREAM_NAME_LEN + 1)));
        assert!(!is_valid_stream_name("has space"));
        assert!(!is_valid_stream_name("tab\tname"));
        assert!(!is_valid_stream_name("café"));
    }

    #[test]
    fn names_sort_in_segment_id_order() {
        // Fixed-width hex means lexicographic order is numeric order.
        let mut names: Vec<String> = [255u64, 1, 16, 0, 4096]
            .iter()
            .map(|id| segment_file_name(*id))
            .collect();
        names.sort();
        let ids: Vec<u64> = names
            .iter()
            .map(|n| parse_segment_file_name(n).unwrap())
            .collect();
        assert_eq!(ids, vec![0, 1, 16, 255, 4096]);
    }

    #[test]
    fn foreign_names_are_rejected() {
        for bad in [
            "",
            "README.md",
            "seg-.log",
            "seg-1.log",                    // too short
            "seg-00000000000000001.log",    // 17 digits, too long
            "seg-000000000000000g.log",     // non-hex digit
            "seg-000000000000000A.log",     // uppercase is not canonical
            "seg-0000000000000001.txt",     // wrong suffix
            "segment-0000000000000001.log", // wrong prefix
            "seg-+000000000000001.log",     // sign is not a hex digit
            "0000000000000001.log",         // no prefix
        ] {
            assert_eq!(parse_segment_file_name(bad), None, "should reject {bad:?}");
        }
    }

    #[test]
    fn enumerates_segment_ids_in_order_skipping_foreign_files() {
        let fs = InMemoryFs::new();
        for id in [3u64, 1, 10, 2] {
            fs.create_new(&segment_file_name(id)).unwrap();
        }
        // Foreign files that must be ignored.
        fs.create_new("README.md").unwrap();
        fs.create_new("seg-bogus.log").unwrap();
        assert_eq!(segment_ids(&fs).unwrap(), vec![1, 2, 3, 10]);
    }

    #[test]
    fn formatter_width_matches_parser_width() {
        // Pin the formatter literal (`:016x`) and the parser's `ID_HEX_LEN` together so
        // they cannot drift apart silently: a name is exactly prefix + id field + suffix.
        assert_eq!(
            segment_file_name(0).len(),
            PREFIX.len() + ID_HEX_LEN + SUFFIX.len()
        );
        assert_eq!(
            segment_file_name(u64::MAX).len(),
            segment_file_name(0).len()
        );
    }

    #[test]
    fn near_miss_names_never_alias_a_canonical_id() {
        // The parser is canonical, so a near miss of a real name (here, uppercased hex)
        // is not a duplicate of the canonical id; it is simply skipped. Enumeration must
        // therefore report the id exactly once.
        let fs = InMemoryFs::new();
        let canonical = segment_file_name(0xab);
        fs.create_new(&canonical).unwrap();
        fs.create_new(&canonical.to_uppercase()).unwrap(); // SEG-...AB.LOG: foreign
        assert_eq!(parse_segment_file_name(&canonical.to_uppercase()), None);
        assert_eq!(segment_ids(&fs).unwrap(), vec![0xab]);
    }

    proptest! {
        #[test]
        fn parse_is_the_inverse_of_name(id in any::<u64>()) {
            prop_assert_eq!(parse_segment_file_name(&segment_file_name(id)), Some(id));
        }

        #[test]
        fn name_is_the_inverse_of_parse(id in any::<u64>()) {
            // Round-tripping a parsed canonical name reproduces it exactly.
            let name = segment_file_name(id);
            let parsed = parse_segment_file_name(&name).unwrap();
            prop_assert_eq!(segment_file_name(parsed), name);
        }

        #[test]
        fn mutating_one_hex_digit_never_aliases_the_original_id(
            id in any::<u64>(),
            pos in 0usize..ID_HEX_LEN,
        ) {
            // Flip one hex digit of a canonical name. A fixed-width hex name has a unique
            // id, so the mutated name parses to a DIFFERENT id or to None, never back to
            // the original id.
            let mut bytes = segment_file_name(id).into_bytes();
            let idx = PREFIX.len() + pos;
            let new = if bytes[idx] == b'0' { b'1' } else { b'0' };
            bytes[idx] = new;
            let mutated = String::from_utf8(bytes).unwrap();
            prop_assert_ne!(parse_segment_file_name(&mutated), Some(id));
        }
    }
}

#[cfg(all(test, unix))]
mod std_tests {
    use super::*;
    use crate::fs::StdFs;

    #[test]
    fn segment_ids_matches_in_memory_on_a_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        let fs = StdFs::new(dir.path().to_path_buf());
        for id in [5u64, 1, 256, 2] {
            fs.create_new(&segment_file_name(id)).unwrap();
        }
        // Foreign files (and a subdirectory) that enumeration must ignore.
        fs.create_new("notes.txt").unwrap();
        fs.create_new("seg-zzzz.log").unwrap();
        std::fs::create_dir(dir.path().join("seg-0000000000000099.log.d")).unwrap();
        assert_eq!(segment_ids(&fs).unwrap(), vec![1, 2, 5, 256]);
    }
}
