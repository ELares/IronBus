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
