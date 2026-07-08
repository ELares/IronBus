// SPDX-License-Identifier: MIT OR Apache-2.0
//! The frozen on-disk binary format for IronBus, version 1.
//!
//! Every multi-byte field is little-endian. A record frame is a fixed 36-byte
//! header, a variable body (key, headers, payload), and an 8-byte trailer. Records
//! are record-aligned within a segment: there is no block layer and no fragment
//! types. See the record-format design (issue #5) for the rationale.
//!
//! A record whose stored body is at least [`XXH3_PAYLOAD_THRESHOLD`] bytes carries a
//! second, independent xxh3-64 checksum (issue #8) in an 8-byte little-endian field
//! placed immediately before the 8-byte trailer and counted in `total_len`. The
//! presence of that field is signalled by the [`RecordFlags::HAS_XXH3`] bit on the
//! header. A record without the bit has the exact byte-for-byte layout it had before
//! the field existed, so 8-byte-trailer parsing and `total_len`-authoritative framing
//! are unchanged for it. CRC32C remains the resync-gating checksum.
//!
//! A record published on a SUBJECT (#594, V2-M2) carries the stored subject in an optional
//! length-prefixed field signalled by the [`RecordFlags::HAS_SUBJECT`] bit: a
//! [`RECORD_SUBJECT_LEN_PREFIX`]-byte `subject_len`, the subject bytes, then a
//! [`RECORD_SUBJECT_CRC_LEN`]-byte CRC32C over the prefix and the subject. It sits IMMEDIATELY
//! after the 36-byte header (at the fixed offset [`RECORD_HEADER_LEN`]) and BEFORE the stored
//! body, and is counted in `total_len`. The fixed offset is what lets the header-only length
//! walk read `subject_len` and size the whole frame from the header plus this prefix alone. A
//! record WITHOUT the bit is byte-for-byte the pre-subject layout, and the body CRC32C/xxh3 and
//! their threshold are computed over the stored body EXACTLY as before (the subject has its own
//! CRC and never enters the body-checksum range). Because the bit is additive and an old reader
//! never sets it (nor writes it), the on-disk [`FORMAT_VERSION`] stays `1`.
//!
//! This module defines only the layout constants and field offsets. Encoding and
//! decoding live in a separate module so the numbers here are the single source of
//! truth that both the codec and its tests refer to.

/// The on-disk format version this build writes and is the baseline it reads.
pub const FORMAT_VERSION: u8 = 1;

/// Record frame magic. On disk the two bytes are `0x42 0x49` (`b'B'`, `b'I'`),
/// which read back as the little-endian `u16` `0x4942`.
pub const RECORD_MAGIC: u16 = 0x4942;

/// Total size in bytes of a record header.
pub const RECORD_HEADER_LEN: usize = 36;

/// Size in bytes of a record trailer (`body_crc: u32` then `total_len: u32`).
pub const RECORD_TRAILER_LEN: usize = 8;

/// Size in bytes of the optional xxh3-64 checksum field (`xxh3: u64`, little-endian)
/// that precedes the trailer on a record carrying the [`RecordFlags::HAS_XXH3`] bit.
pub const RECORD_XXH3_LEN: usize = 8;

/// Size in bytes of the length prefix (`subject_len: u16`, little-endian) that OPENS the optional
/// subject field of a record carrying the [`RecordFlags::HAS_SUBJECT`] bit (#594, V2-M2). The
/// subject field is `subject_len` then `subject_len` subject bytes then a [`RECORD_SUBJECT_CRC_LEN`]
/// -byte CRC32C, placed immediately AFTER the 36-byte header and BEFORE the stored body, and counted
/// in `total_len`. It sits at a FIXED offset ([`RECORD_HEADER_LEN`]) so the header-only length walk
/// ([`crate::codec::decoded_len`]) can read `subject_len` and size the frame from the header plus
/// this prefix alone. A record WITHOUT the bit is byte-for-byte the pre-subject layout.
pub const RECORD_SUBJECT_LEN_PREFIX: usize = 2;

/// Size in bytes of the CRC32C field that CLOSES the optional subject field of a record carrying the
/// [`RecordFlags::HAS_SUBJECT`] bit (#594): `4`. It covers the `subject_len` prefix and the subject
/// bytes (the bytes in `[RECORD_HEADER_LEN, RECORD_HEADER_LEN + RECORD_SUBJECT_LEN_PREFIX +
/// subject_len)`), so a corrupted STORED subject is caught independently of the body CRC — the body
/// CRC32C/xxh3 machinery and the stored-body layout stay byte-for-byte unchanged by the subject.
pub const RECORD_SUBJECT_CRC_LEN: usize = 4;

/// The byte range of the header that the `header_crc` field protects: `[0, 32)`.
pub const RECORD_HEADER_CRC_RANGE: core::ops::Range<usize> = 0..32;

/// Eight-byte magic at the start of a segment file.
pub const SEGMENT_MAGIC: [u8; 8] = *b"IRONBUS\0";

/// Total size in bytes of a segment header (the file starts 4 KiB-aligned).
pub const SEGMENT_HEADER_LEN: usize = 64;

/// Total size in bytes of a segment footer, written when the segment is sealed.
pub const SEGMENT_FOOTER_LEN: usize = 32;

/// Identifier for CRC32C (Castagnoli) in the segment header `checksum_algo` field.
/// Version-1 readers must reject any other value.
pub const CHECKSUM_ALGO_CRC32C: u8 = 0x1;

/// Default hard cap on a single record's total size: 16 MiB.
pub const DEFAULT_MAX_RECORD_BYTES: u32 = 16 * 1024 * 1024;

/// Configurable ceiling on the maximum record size: 1 GiB, bounded by the `u32`
/// length fields in the frame.
pub const MAX_RECORD_BYTES_CEILING: u32 = 1024 * 1024 * 1024;

/// Compile-time invariant: the default maximum record size never exceeds the ceiling.
const _: () = assert!(DEFAULT_MAX_RECORD_BYTES <= MAX_RECORD_BYTES_CEILING);

/// Stored body size at or above which a second, independent xxh3-64 checksum is
/// added to a record in addition to the mandatory CRC32C: 64 KiB.
///
/// The threshold is measured on the STORED body (key + headers + payload as actually
/// written, i.e. post-compression when the `COMPRESSED` bit is set), not the
/// uncompressed payload: the xxh3-64 protects the bytes on disk, and resync and verify
/// operate on those same stored bytes. The xxh3-64 covers the same byte range as the
/// `body_crc`.
pub const XXH3_PAYLOAD_THRESHOLD: u32 = 64 * 1024;

/// Default target size at which an active segment is rolled and sealed: 64 MiB.
///
/// The startup config validator enforces that the configured maximum record size
/// is smaller than the active segment size, so a record never spans two segments.
/// On the edge profile the segment size drops (see [`EDGE_SEGMENT_BYTES`]), which
/// also lowers the permitted maximum record size.
pub const DEFAULT_SEGMENT_BYTES: u32 = 64 * 1024 * 1024;

/// Active-segment roll size on the constrained edge profile: 8 MiB.
pub const EDGE_SEGMENT_BYTES: u32 = 8 * 1024 * 1024;

/// Default maximum age before an active segment is rolled, in hours: 1.
pub const DEFAULT_SEGMENT_ROLL_HOURS: u32 = 1;

/// Byte offsets of each field within the record header. The header is little-endian
/// and tightly packed: `magic(2) version(1) flags(1) seq(8) timestamp(8) key_len(4)
/// hdr_len(4) payload_len(4) header_crc(4)`.
pub mod header_offsets {
    /// Offset of the `magic: u16` field.
    pub const MAGIC: usize = 0;
    /// Offset of the `version: u8` field.
    pub const VERSION: usize = 2;
    /// Offset of the `flags: u8` field.
    pub const FLAGS: usize = 3;
    /// Offset of the `seq: u64` field.
    pub const SEQ: usize = 4;
    /// Offset of the `timestamp: u64` (milliseconds) field.
    pub const TIMESTAMP: usize = 12;
    /// Offset of the `key_len: u32` field.
    pub const KEY_LEN: usize = 20;
    /// Offset of the `hdr_len: u32` field.
    pub const HDR_LEN: usize = 24;
    /// Offset of the `payload_len: u32` field.
    pub const PAYLOAD_LEN: usize = 28;
    /// Offset of the `header_crc: u32` field. The CRC covers bytes `[0, 32)`.
    pub const HEADER_CRC: usize = 32;
}

/// Byte offsets of each field within the 64-byte segment header (little-endian). The
/// header is 4 KiB-aligned at the start of a segment file. Bytes `[44, 60)` are
/// reserved (zero) and `header_crc` covers `[0, 60)`.
pub mod segment_header_offsets {
    /// Offset of the 8-byte `magic` field (`SEGMENT_MAGIC`).
    pub const MAGIC: usize = 0;
    /// Offset of the `version: u8` field.
    pub const VERSION: usize = 8;
    /// Offset of the `checksum_algo: u8` field.
    pub const CHECKSUM_ALGO: usize = 9;
    /// Offset of the `flags: u16` field.
    pub const FLAGS: usize = 10;
    /// Offset of the `segment_id: u64` field.
    pub const SEGMENT_ID: usize = 12;
    /// Offset of the `base_seq: u64` field.
    pub const BASE_SEQ: usize = 20;
    /// Offset of the `base_offset: u64` field.
    pub const BASE_OFFSET: usize = 28;
    /// Offset of the `created_unix_ms: u64` field.
    pub const CREATED_MS: usize = 36;
    /// Offset of the `header_crc: u32` field. The CRC covers bytes `[0, 60)`.
    pub const HEADER_CRC: usize = 60;
}

/// Byte range the segment header CRC32C covers: `[0, 60)`.
pub const SEGMENT_HEADER_CRC_RANGE: core::ops::Range<usize> = 0..60;

/// Two-byte magic at the start of a segment footer (`b"SF"` = `0x4653`,
/// little-endian), distinct from the record magic so a torn tail cannot be mistaken
/// for a footer on a CRC collision alone.
pub const SEGMENT_FOOTER_MAGIC: u16 = 0x4653;

/// Byte offsets of each field within the 32-byte segment footer (little-endian),
/// written when the segment is sealed. Bytes `[24, 28)` are reserved (zero) and
/// `footer_crc` covers `[0, 28)`.
pub mod segment_footer_offsets {
    /// Offset of the 2-byte `magic` field (`SEGMENT_FOOTER_MAGIC`).
    pub const MAGIC: usize = 0;
    /// Offset of the `version: u8` field.
    pub const VERSION: usize = 2;
    /// Offset of the `checksum_algo: u8` field.
    pub const CHECKSUM_ALGO: usize = 3;
    /// Offset of the `segment_id: u64` field (binds the footer to its header).
    pub const SEGMENT_ID: usize = 4;
    /// Offset of the `last_seq: u64` field.
    pub const LAST_SEQ: usize = 12;
    /// Offset of the `record_count: u32` field.
    pub const RECORD_COUNT: usize = 20;
    /// Offset of the `footer_crc: u32` field. The CRC covers bytes `[0, 28)`.
    pub const FOOTER_CRC: usize = 28;
}

/// Byte range the segment footer CRC32C covers: `[0, 28)`.
pub const SEGMENT_FOOTER_CRC_RANGE: core::ops::Range<usize> = 0..28;

// --- Optional key-based compaction: the additive v2 on-disk delta (#337). ---
//
// A compacted segment is the only segment that carries `version` = 2. It is structurally a
// normal segment (a 64-byte header, record frames, a 32-byte footer) with two ADDITIVE facts:
// the `COMPACTED` header flag bit, and a 44-byte compaction-metadata block written immediately
// AFTER the sealed footer as the file's final bytes. A v1 (`version` = 1) segment is UNCHANGED
// byte-for-byte: the version byte is stamped `2` ONLY when the `COMPACTED` flag is set, so a
// non-compacted header and footer encode exactly as before. A v1-only reader REFUSES a
// `version` = 2 segment (the fail-closed bump). See `docs/COMPACTION.md` and `docs/CONTRACTS.md`.

/// The on-disk format version a COMPACTED segment stamps in its header and footer `version`
/// bytes (#337): `2`. A v1-only reader refuses it, so an old reader fail-closed REFUSES a
/// compacted log rather than silently misreading its sparse offsets. Only a compacted segment
/// ever carries this version; an ordinary segment stays [`FORMAT_VERSION`] (`1`).
pub const FORMAT_VERSION_COMPACTED: u8 = 2;

/// The segment-header `flags` bit (at `[10, 12)`, inside the CRC-covered bytes `[0, 60)`) that
/// marks a segment as the output of a key-compaction clean (#337): `0x0001`. It is a DISTINCT
/// bit from the at-rest encryption flag (a compacted segment may also be encrypted), and a
/// segment carrying it stamps `version` = [`FORMAT_VERSION_COMPACTED`]. A v1 reader treats the
/// `flags` field as preserved-but-not-interpreted, so it never looks for the trailing block; the
/// `version` = 2 bump is what makes such a reader fail closed rather than mis-stitch the sparse
/// chain.
pub const SEGMENT_FLAG_COMPACTED: u16 = 0x0001;

/// Total size in bytes of the v2 compaction-metadata block (#337), written immediately AFTER the
/// 32-byte sealed footer as a compacted segment's final bytes: `44`. It carries the source set's
/// covered offset and sequence spans plus the highest covered source id, CRC32C-protected on its
/// own so a torn trailing block is rejected exactly like a torn footer (it then falls into the
/// crash-before-commit recovery case).
pub const COMPACTION_META_LEN: usize = 44;

/// Byte offsets of each field within the 44-byte v2 compaction-metadata block (little-endian),
/// written after the footer as a compacted segment's final bytes (#337). The block self-describes
/// the ORIGINAL source set this compacted segment supersedes: its true covered offset span
/// `[covered_base_offset, covered_end_offset)` and the parallel covered SEQUENCE span
/// `[covered_base_seq, covered_end_seq)` (recovery advances both expectations across the segment),
/// plus the highest covered source segment id (the recovery tie-break). `block_crc` covers
/// `[0, 40)`.
pub mod compaction_meta_offsets {
    /// Offset of the `covered_base_offset: u64` field (the source set's TRUE starting offset, its
    /// own field, never an alias of the header `base_offset`).
    pub const COVERED_BASE_OFFSET: usize = 0;
    /// Offset of the `covered_end_offset: u64` field (one past the highest covered SOURCE offset).
    pub const COVERED_END_OFFSET: usize = 8;
    /// Offset of the `covered_base_seq: u64` field (the source set's TRUE starting sequence).
    pub const COVERED_BASE_SEQ: usize = 16;
    /// Offset of the `covered_end_seq: u64` field (one past the highest covered SOURCE sequence).
    pub const COVERED_END_SEQ: usize = 24;
    /// Offset of the `highest_covered_source_id: u64` field (the highest segment id this clean
    /// supersedes, the deterministic recovery tie-break).
    pub const HIGHEST_COVERED_SOURCE_ID: usize = 32;
    /// Offset of the `block_crc: u32` field. The CRC covers bytes `[0, 40)`.
    pub const BLOCK_CRC: usize = 40;
}

/// Byte range the v2 compaction-metadata block CRC32C covers: `[0, 40)`.
pub const COMPACTION_META_CRC_RANGE: core::ops::Range<usize> = 0..40;

#[cfg(test)]
mod tests {
    use super::header_offsets as off;
    use super::*;

    #[test]
    fn frozen_sizes() {
        assert_eq!(RECORD_HEADER_LEN, 36);
        assert_eq!(RECORD_TRAILER_LEN, 8);
        assert_eq!(SEGMENT_HEADER_LEN, 64);
        assert_eq!(SEGMENT_FOOTER_LEN, 32);
        assert_eq!(RECORD_HEADER_CRC_RANGE, 0..32);
    }

    #[test]
    fn header_field_offsets_are_tightly_packed() {
        // Absolute offsets freeze the exact layout: a consistent-but-wrong shift of
        // two interior fields (which preserves the running sum) is still caught.
        assert_eq!(off::MAGIC, 0);
        assert_eq!(off::VERSION, 2);
        assert_eq!(off::FLAGS, 3);
        assert_eq!(off::SEQ, 4);
        assert_eq!(off::TIMESTAMP, 12);
        assert_eq!(off::KEY_LEN, 20);
        assert_eq!(off::HDR_LEN, 24);
        assert_eq!(off::PAYLOAD_LEN, 28);
        assert_eq!(off::HEADER_CRC, 32);
        // The CRC field sits exactly at the end of the protected range and the
        // header ends right after it.
        assert_eq!(off::HEADER_CRC, RECORD_HEADER_CRC_RANGE.end);
        assert_eq!(off::HEADER_CRC + 4, RECORD_HEADER_LEN);
    }

    #[test]
    fn segment_header_and_footer_offsets() {
        use segment_footer_offsets as foff;
        use segment_header_offsets as hoff;
        assert_eq!(hoff::MAGIC, 0);
        assert_eq!(hoff::VERSION, 8);
        assert_eq!(hoff::CHECKSUM_ALGO, 9);
        assert_eq!(hoff::FLAGS, 10);
        assert_eq!(hoff::SEGMENT_ID, 12);
        assert_eq!(hoff::BASE_SEQ, 20);
        assert_eq!(hoff::BASE_OFFSET, 28);
        assert_eq!(hoff::CREATED_MS, 36);
        assert_eq!(hoff::HEADER_CRC, 60);
        assert_eq!(hoff::HEADER_CRC + 4, SEGMENT_HEADER_LEN);
        assert_eq!(SEGMENT_HEADER_CRC_RANGE, 0..60);
        assert_eq!(foff::MAGIC, 0);
        assert_eq!(foff::VERSION, 2);
        assert_eq!(foff::CHECKSUM_ALGO, 3);
        assert_eq!(foff::SEGMENT_ID, 4);
        assert_eq!(foff::LAST_SEQ, 12);
        assert_eq!(foff::RECORD_COUNT, 20);
        assert_eq!(foff::FOOTER_CRC, 28);
        assert_eq!(foff::FOOTER_CRC + 4, SEGMENT_FOOTER_LEN);
        assert_eq!(SEGMENT_FOOTER_CRC_RANGE, 0..28);
        assert_eq!(SEGMENT_FOOTER_MAGIC, 0x4653);
    }

    #[test]
    fn frozen_values() {
        assert_eq!(FORMAT_VERSION, 1);
        assert_eq!(RECORD_MAGIC, 0x4942);
        assert_eq!(SEGMENT_MAGIC, *b"IRONBUS\0");
        assert_eq!(CHECKSUM_ALGO_CRC32C, 0x1);
        assert_eq!(XXH3_PAYLOAD_THRESHOLD, 64 * 1024);
        assert_eq!(DEFAULT_SEGMENT_BYTES, 64 * 1024 * 1024);
        assert_eq!(EDGE_SEGMENT_BYTES, 8 * 1024 * 1024);
        assert_eq!(DEFAULT_SEGMENT_ROLL_HOURS, 1);
    }

    #[test]
    fn magic_byte_order() {
        // Little-endian 0x4942 is the bytes 0x42, 0x49 = b'B', b'I'.
        assert_eq!(RECORD_MAGIC.to_le_bytes(), [b'B', b'I']);
    }

    #[test]
    fn record_size_limits() {
        assert_eq!(DEFAULT_MAX_RECORD_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_RECORD_BYTES_CEILING, 1024 * 1024 * 1024);
    }

    #[test]
    fn frozen_compaction_v2_values_and_offsets() {
        use compaction_meta_offsets as moff;
        // The v2 compaction delta (#337) is ADDITIVE and pinned: a compacted segment carries
        // version 2, the COMPACTED flag is bit 0, and the trailing block is exactly 44 bytes.
        assert_eq!(FORMAT_VERSION_COMPACTED, 2);
        assert_eq!(SEGMENT_FLAG_COMPACTED, 0x0001);
        assert_eq!(COMPACTION_META_LEN, 44);
        // The block's five u64 fields are tightly packed, then a u32 CRC at the end.
        assert_eq!(moff::COVERED_BASE_OFFSET, 0);
        assert_eq!(moff::COVERED_END_OFFSET, 8);
        assert_eq!(moff::COVERED_BASE_SEQ, 16);
        assert_eq!(moff::COVERED_END_SEQ, 24);
        assert_eq!(moff::HIGHEST_COVERED_SOURCE_ID, 32);
        assert_eq!(moff::BLOCK_CRC, 40);
        assert_eq!(moff::BLOCK_CRC + 4, COMPACTION_META_LEN);
        assert_eq!(COMPACTION_META_CRC_RANGE, 0..40);
        // The v2 version is exactly 2 and the v1 baseline is 1, so refuse-on-unknown fails closed
        // (a v1-only reader rejects the higher version). Pinned as concrete values to keep the
        // assertion non-constant and the bump explicit.
        assert_eq!(FORMAT_VERSION_COMPACTED, 2);
        assert_eq!(FORMAT_VERSION, 1);
    }
}
