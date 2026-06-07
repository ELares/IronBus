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
}
