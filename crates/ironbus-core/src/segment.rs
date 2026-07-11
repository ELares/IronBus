// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encoding and decoding of the IronBus segment header and footer (version 1).
//!
//! Every segment file begins with a 64-byte header (4 KiB-aligned) and, once sealed,
//! ends with a 32-byte footer. Both are little-endian and CRC32C-protected. The
//! records between them use the frame in [`crate::codec`].

use crate::format::{
    compaction_meta_offsets as moff, segment_footer_offsets as foff,
    segment_header_offsets as hoff, AEAD_SUITE_NONE, CHECKSUM_ALGO_CRC32C,
    COMPACTION_META_CRC_RANGE, COMPACTION_META_LEN, FORMAT_VERSION, FORMAT_VERSION_COMPACTED,
    SEGMENT_FLAG_COMPACTED, SEGMENT_FLAG_ENCRYPTED, SEGMENT_FOOTER_CRC_RANGE, SEGMENT_FOOTER_LEN,
    SEGMENT_FOOTER_MAGIC, SEGMENT_HEADER_CRC_RANGE, SEGMENT_HEADER_LEN, SEGMENT_MAGIC,
};
use crate::raw::{read_u16, read_u32, read_u64};
use crate::types::{Offset, Seq};

/// The fixed 64-byte header at the start of every segment file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentHeader {
    /// Monotonic identifier of this segment.
    pub segment_id: u64,
    /// Sequence number of the first record in the segment.
    pub base_seq: Seq,
    /// Log offset of the first record in the segment.
    pub base_offset: Offset,
    /// Wall-clock creation time, milliseconds since the Unix epoch.
    pub created_unix_ms: u64,
    /// Segment flag bits. Reserved in version 1 (zero); preserved on read but not
    /// interpreted, so a future writer can add flags without older readers corrupting them.
    pub flags: u16,
}

/// The fixed 32-byte footer written when a segment is sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentFooter {
    /// Identifier of the segment this footer belongs to (must match the header).
    pub segment_id: u64,
    /// Sequence number of the last record in the sealed segment.
    pub last_seq: Seq,
    /// Number of records in the sealed segment.
    pub record_count: u32,
}

/// An error decoding a segment header or footer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SegmentError {
    /// The input is shorter than the fixed structure.
    Truncated,
    /// The segment header or footer magic did not match.
    BadMagic,
    /// The format version is not understood by this build.
    UnsupportedVersion(u8),
    /// The checksum algorithm id is not CRC32C.
    UnsupportedChecksumAlgo(u8),
    /// The CRC32C did not match: the structure is corrupt.
    BadCrc,
}

impl core::fmt::Display for SegmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SegmentError::Truncated => write!(f, "segment structure is truncated"),
            SegmentError::BadMagic => write!(f, "segment header has a bad magic number"),
            SegmentError::UnsupportedVersion(v) => {
                write!(f, "unsupported segment format version {v}")
            }
            SegmentError::UnsupportedChecksumAlgo(a) => {
                write!(f, "unsupported segment checksum algorithm {a}")
            }
            SegmentError::BadCrc => write!(f, "segment structure CRC mismatch"),
        }
    }
}
impl std::error::Error for SegmentError {}

impl SegmentHeader {
    /// Whether this header marks a COMPACTED segment (the output of a key-compaction clean,
    /// #337): the [`SEGMENT_FLAG_COMPACTED`] bit is set in `flags`. A compacted segment is the
    /// only one that stamps `version` = [`FORMAT_VERSION_COMPACTED`] and carries a trailing v2
    /// compaction-metadata block; an ordinary segment never sets the bit.
    #[must_use]
    pub fn is_compacted(&self) -> bool {
        self.flags & SEGMENT_FLAG_COMPACTED != 0
    }

    /// Whether this header marks an AEAD-ENCRYPTED segment (#780): the [`SEGMENT_FLAG_ENCRYPTED`] bit
    /// is set in `flags`. An encrypted segment additionally records its AEAD suite and key-id in the
    /// header's reserved `[44, 60)` bytes (see [`SegmentHeader::encode_encrypted`] /
    /// [`SegmentHeader::aead_params`]). It is a DISTINCT bit from [`SEGMENT_FLAG_COMPACTED`]: a
    /// segment may be both compacted and encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.flags & SEGMENT_FLAG_ENCRYPTED != 0
    }

    /// Encodes the header into its fixed 64-byte on-disk form.
    ///
    /// The `version` byte is stamped [`FORMAT_VERSION_COMPACTED`] (`2`) ONLY when the
    /// [`SEGMENT_FLAG_COMPACTED`] bit is set in `flags` (#337); otherwise it stays
    /// [`FORMAT_VERSION`] (`1`), so a non-compacted header is byte-for-byte the v1 layout. A v1
    /// reader refuses the version-2 bump (fail-closed) rather than mis-stitching the sparse chain.
    /// The reserved `[44, 60)` bytes (the at-rest encryption slots) are written as zero here; an
    /// encrypted segment uses [`SegmentHeader::encode_encrypted`] instead.
    #[must_use]
    pub fn encode(&self) -> [u8; SEGMENT_HEADER_LEN] {
        self.encode_inner(self.flags, AEAD_SUITE_NONE, 0)
    }

    /// Encodes the header for an AEAD-ENCRYPTED segment (#780), setting the [`SEGMENT_FLAG_ENCRYPTED`]
    /// flag bit and writing `aead_suite` and `key_id` into the reserved `[44, 60)` region (still
    /// inside the frozen `header_crc` scope `[0, 60)`, so they are integrity-protected for free with
    /// no offset move). The `version` byte is UNCHANGED by encryption — it stays `1` (or `2` if the
    /// segment is also compacted) — because encryption reuses reserved bytes rather than bumping the
    /// format version. `key_id` identifies the key (NEVER the key itself); `aead_suite` records the
    /// primitive so a read is unambiguous regardless of the reading host's CPU.
    #[must_use]
    pub fn encode_encrypted(&self, aead_suite: u8, key_id: u64) -> [u8; SEGMENT_HEADER_LEN] {
        self.encode_inner(self.flags | SEGMENT_FLAG_ENCRYPTED, aead_suite, key_id)
    }

    fn encode_inner(&self, flags: u16, aead_suite: u8, key_id: u64) -> [u8; SEGMENT_HEADER_LEN] {
        let mut h = [0u8; SEGMENT_HEADER_LEN];
        h[hoff::MAGIC..hoff::MAGIC + 8].copy_from_slice(&SEGMENT_MAGIC);
        h[hoff::VERSION] = if self.is_compacted() {
            FORMAT_VERSION_COMPACTED
        } else {
            FORMAT_VERSION
        };
        h[hoff::CHECKSUM_ALGO] = CHECKSUM_ALGO_CRC32C;
        h[hoff::FLAGS..hoff::FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
        h[hoff::SEGMENT_ID..hoff::SEGMENT_ID + 8].copy_from_slice(&self.segment_id.to_le_bytes());
        h[hoff::BASE_SEQ..hoff::BASE_SEQ + 8].copy_from_slice(&self.base_seq.get().to_le_bytes());
        h[hoff::BASE_OFFSET..hoff::BASE_OFFSET + 8]
            .copy_from_slice(&self.base_offset.get().to_le_bytes());
        h[hoff::CREATED_MS..hoff::CREATED_MS + 8]
            .copy_from_slice(&self.created_unix_ms.to_le_bytes());
        // The at-rest encryption slots (#780) in the reserved [44, 60) region. Both are zero on a
        // plaintext segment, so `encode()` reproduces the pre-encryption bytes exactly.
        h[hoff::AEAD_SUITE] = aead_suite;
        h[hoff::KEY_ID..hoff::KEY_ID + 8].copy_from_slice(&key_id.to_le_bytes());
        let crc = crc32c::crc32c(&h[SEGMENT_HEADER_CRC_RANGE]);
        h[hoff::HEADER_CRC..hoff::HEADER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        h
    }

    /// Reads the at-rest AEAD parameters (`aead_suite`, `key_id`) from a 64-byte segment-header
    /// buffer (#780). Returns `Some((aead_suite, key_id))` iff the [`SEGMENT_FLAG_ENCRYPTED`] flag
    /// bit is set, else `None` (a plaintext segment). The caller should already have validated the
    /// header via [`SegmentHeader::decode`] (which checks the CRC that covers these bytes), so this is
    /// a plain field read; it returns `None` for a buffer shorter than a header rather than panicking.
    #[must_use]
    pub fn aead_params(bytes: &[u8]) -> Option<(u8, u64)> {
        if bytes.len() < SEGMENT_HEADER_LEN {
            return None;
        }
        let flags = read_u16(bytes, hoff::FLAGS);
        if flags & SEGMENT_FLAG_ENCRYPTED == 0 {
            return None;
        }
        Some((bytes[hoff::AEAD_SUITE], read_u64(bytes, hoff::KEY_ID)))
    }

    /// Decodes a header from the first 64 bytes of `bytes`, accepting BOTH the v1 layout
    /// (`version` = 1, no [`SEGMENT_FLAG_COMPACTED`] bit) and the additive v2 compacted layout
    /// (`version` = [`FORMAT_VERSION_COMPACTED`] with the [`SEGMENT_FLAG_COMPACTED`] bit set, #337).
    /// The version and the flag must AGREE: a `version` = 2 without the flag, or the flag without
    /// `version` = 2, is a structural inconsistency rejected as [`SegmentError::UnsupportedVersion`]
    /// (a half-written or foreign header never parses as a valid compacted segment).
    ///
    /// # Errors
    /// Returns a [`SegmentError`] if the input is too short, the magic, version, or checksum
    /// algorithm is wrong, the version and the COMPACTED flag disagree, or the header CRC does not
    /// match.
    pub fn decode(bytes: &[u8]) -> Result<SegmentHeader, SegmentError> {
        Self::decode_inner(bytes, true)
    }

    /// Decodes a header as a STRICTLY v1 reader would: it REFUSES the v2 compacted layout with
    /// [`SegmentError::UnsupportedVersion`]`(2)` rather than interpret it (#337). This is the
    /// fail-closed contract a pre-compaction reader follows, kept as an explicit, testable path so
    /// the "a v1 reader refuses a compacted log" guarantee is provable, not just asserted. The
    /// online recovery path uses [`SegmentHeader::decode`] (which understands v2); this is the
    /// old-binary-meets-new-data refusal.
    ///
    /// # Errors
    /// Returns [`SegmentError::UnsupportedVersion`] for ANY `version` other than `1`, plus the
    /// same structural errors as [`SegmentHeader::decode`].
    pub fn decode_v1_only(bytes: &[u8]) -> Result<SegmentHeader, SegmentError> {
        Self::decode_inner(bytes, false)
    }

    fn decode_inner(bytes: &[u8], allow_v2: bool) -> Result<SegmentHeader, SegmentError> {
        if bytes.len() < SEGMENT_HEADER_LEN {
            return Err(SegmentError::Truncated);
        }
        if bytes[hoff::MAGIC..hoff::MAGIC + 8] != SEGMENT_MAGIC {
            return Err(SegmentError::BadMagic);
        }
        let version = bytes[hoff::VERSION];
        let flags = read_u16(bytes, hoff::FLAGS);
        let compacted = flags & SEGMENT_FLAG_COMPACTED != 0;
        // Fail-closed version gate (#337). A v1 reader refuses any non-1 version. A v2-aware reader
        // additionally accepts version 2, but ONLY when it is paired with the COMPACTED flag, and
        // rejects a v1 header that nonetheless carries the COMPACTED flag (a contradiction a
        // half-written or foreign file could leave). So the version and the flag are mutually gating:
        // neither without the other parses as valid.
        let v1_ok = version == FORMAT_VERSION && !compacted;
        let v2_ok = allow_v2 && version == FORMAT_VERSION_COMPACTED && compacted;
        if !(v1_ok || v2_ok) {
            return Err(SegmentError::UnsupportedVersion(version));
        }
        let algo = bytes[hoff::CHECKSUM_ALGO];
        if algo != CHECKSUM_ALGO_CRC32C {
            return Err(SegmentError::UnsupportedChecksumAlgo(algo));
        }
        if crc32c::crc32c(&bytes[SEGMENT_HEADER_CRC_RANGE]) != read_u32(bytes, hoff::HEADER_CRC) {
            return Err(SegmentError::BadCrc);
        }
        Ok(SegmentHeader {
            segment_id: read_u64(bytes, hoff::SEGMENT_ID),
            base_seq: Seq::new(read_u64(bytes, hoff::BASE_SEQ)),
            base_offset: Offset::new(read_u64(bytes, hoff::BASE_OFFSET)),
            created_unix_ms: read_u64(bytes, hoff::CREATED_MS),
            flags,
        })
    }
}

impl SegmentFooter {
    /// Encodes the footer into its fixed 32-byte on-disk form, stamping the v1 `version` byte.
    #[must_use]
    pub fn encode(&self) -> [u8; SEGMENT_FOOTER_LEN] {
        self.encode_with_version(FORMAT_VERSION)
    }

    /// Encodes the footer stamping the v2 compacted `version` byte ([`FORMAT_VERSION_COMPACTED`]),
    /// for a compacted segment's footer (#337). The layout is byte-for-byte the v1 footer except
    /// for the one `version` byte, so a v2 footer is the same 32-byte shape; the trailing v2
    /// compaction-metadata block follows it as the file's final bytes. A v1-only reader refuses
    /// this footer's version exactly as it refuses the v2 header.
    #[must_use]
    pub fn encode_v2(&self) -> [u8; SEGMENT_FOOTER_LEN] {
        self.encode_with_version(FORMAT_VERSION_COMPACTED)
    }

    fn encode_with_version(&self, version: u8) -> [u8; SEGMENT_FOOTER_LEN] {
        let mut f = [0u8; SEGMENT_FOOTER_LEN];
        f[foff::MAGIC..foff::MAGIC + 2].copy_from_slice(&SEGMENT_FOOTER_MAGIC.to_le_bytes());
        f[foff::VERSION] = version;
        f[foff::CHECKSUM_ALGO] = CHECKSUM_ALGO_CRC32C;
        f[foff::SEGMENT_ID..foff::SEGMENT_ID + 8].copy_from_slice(&self.segment_id.to_le_bytes());
        f[foff::LAST_SEQ..foff::LAST_SEQ + 8].copy_from_slice(&self.last_seq.get().to_le_bytes());
        f[foff::RECORD_COUNT..foff::RECORD_COUNT + 4]
            .copy_from_slice(&self.record_count.to_le_bytes());
        let crc = crc32c::crc32c(&f[SEGMENT_FOOTER_CRC_RANGE]);
        f[foff::FOOTER_CRC..foff::FOOTER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        f
    }

    /// Decodes a footer from the first 32 bytes of `bytes` (the last 32 bytes of a sealed
    /// segment, or, for a compacted segment, the 32 bytes immediately before the trailing v2
    /// block). The footer SHAPE is identical for v1 and v2; only the `version` byte differs, so
    /// this accepts both v1 (`version` = 1) and the v2 compacted footer (#337). The caller should
    /// also verify `segment_id` matches the header and `last_seq >= header.base_seq`.
    ///
    /// # Errors
    /// Returns a [`SegmentError`] if too short, the magic is wrong, the version is neither 1 nor
    /// 2, the checksum algorithm is wrong, or the footer CRC does not match.
    pub fn decode(bytes: &[u8]) -> Result<SegmentFooter, SegmentError> {
        if bytes.len() < SEGMENT_FOOTER_LEN {
            return Err(SegmentError::Truncated);
        }
        if read_u16(bytes, foff::MAGIC) != SEGMENT_FOOTER_MAGIC {
            return Err(SegmentError::BadMagic);
        }
        let version = bytes[foff::VERSION];
        if version != FORMAT_VERSION && version != FORMAT_VERSION_COMPACTED {
            return Err(SegmentError::UnsupportedVersion(version));
        }
        let algo = bytes[foff::CHECKSUM_ALGO];
        if algo != CHECKSUM_ALGO_CRC32C {
            return Err(SegmentError::UnsupportedChecksumAlgo(algo));
        }
        if crc32c::crc32c(&bytes[SEGMENT_FOOTER_CRC_RANGE]) != read_u32(bytes, foff::FOOTER_CRC) {
            return Err(SegmentError::BadCrc);
        }
        Ok(SegmentFooter {
            segment_id: read_u64(bytes, foff::SEGMENT_ID),
            last_seq: Seq::new(read_u64(bytes, foff::LAST_SEQ)),
            record_count: read_u32(bytes, foff::RECORD_COUNT),
        })
    }
}

/// The v2 compaction-metadata block (#337): a 44-byte CRC-protected trailer written immediately
/// AFTER a compacted segment's footer as the file's final bytes. It self-describes the ORIGINAL
/// source set this compacted segment supersedes, so recovery resolves an overlapping offset range
/// (a compacted segment plus the not-yet-retired originals it replaced) from the file alone, with
/// no manifest. The covered SPANS are the source set's TRUE offset and sequence range, NOT the
/// (sparse) survivor range, so recovery advances its chain-continuity expectation across the
/// compacted segment by the covered span, not the survivor count.
///
/// It is pure and IO-free (the encode/decode live in `ironbus-core` per the layering rule); the
/// storage cleaner writes it and recovery reads it. A torn or mismatched block fails `block_crc`
/// and is rejected exactly like a torn footer, which is indistinguishable from a crash before the
/// compaction commit point and is recovered as such.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactionMeta {
    /// The source set's TRUE starting offset (the lowest covered SOURCE offset), its OWN field,
    /// never an alias of the header `base_offset`: they differ when the first source segment's
    /// leading records were all superseded. Recovery abuts the predecessor here.
    pub covered_base_offset: u64,
    /// One past the highest covered SOURCE offset: where this compacted segment's covered range
    /// ends and the successor segment must begin.
    pub covered_end_offset: u64,
    /// The source set's TRUE starting sequence (parallel to `covered_base_offset`).
    pub covered_base_seq: u64,
    /// One past the highest covered SOURCE sequence: recovery advances the sequence expectation by
    /// this across the compacted segment (the survivors are sparse, so the survivor count does
    /// not).
    pub covered_end_seq: u64,
    /// The highest segment id this clean supersedes: the deterministic recovery tie-break for two
    /// overlapping compacted segments (the higher-id, later clean wins).
    pub highest_covered_source_id: u64,
}

impl CompactionMeta {
    /// Encodes the block into its fixed 44-byte on-disk form, with `block_crc` over `[0, 40)`.
    #[must_use]
    pub fn encode(&self) -> [u8; COMPACTION_META_LEN] {
        let mut b = [0u8; COMPACTION_META_LEN];
        b[moff::COVERED_BASE_OFFSET..moff::COVERED_BASE_OFFSET + 8]
            .copy_from_slice(&self.covered_base_offset.to_le_bytes());
        b[moff::COVERED_END_OFFSET..moff::COVERED_END_OFFSET + 8]
            .copy_from_slice(&self.covered_end_offset.to_le_bytes());
        b[moff::COVERED_BASE_SEQ..moff::COVERED_BASE_SEQ + 8]
            .copy_from_slice(&self.covered_base_seq.to_le_bytes());
        b[moff::COVERED_END_SEQ..moff::COVERED_END_SEQ + 8]
            .copy_from_slice(&self.covered_end_seq.to_le_bytes());
        b[moff::HIGHEST_COVERED_SOURCE_ID..moff::HIGHEST_COVERED_SOURCE_ID + 8]
            .copy_from_slice(&self.highest_covered_source_id.to_le_bytes());
        let crc = crc32c::crc32c(&b[COMPACTION_META_CRC_RANGE]);
        b[moff::BLOCK_CRC..moff::BLOCK_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Decodes the block from its 44 trailing bytes, validating `block_crc`. A short or
    /// CRC-mismatched block is rejected the same way a torn footer is, so a half-written compacted
    /// segment never parses as a valid compacted segment.
    ///
    /// # Errors
    /// Returns [`SegmentError::Truncated`] if shorter than [`COMPACTION_META_LEN`], or
    /// [`SegmentError::BadCrc`] if `block_crc` does not match.
    pub fn decode(bytes: &[u8]) -> Result<CompactionMeta, SegmentError> {
        if bytes.len() < COMPACTION_META_LEN {
            return Err(SegmentError::Truncated);
        }
        if crc32c::crc32c(&bytes[COMPACTION_META_CRC_RANGE]) != read_u32(bytes, moff::BLOCK_CRC) {
            return Err(SegmentError::BadCrc);
        }
        Ok(CompactionMeta {
            covered_base_offset: read_u64(bytes, moff::COVERED_BASE_OFFSET),
            covered_end_offset: read_u64(bytes, moff::COVERED_END_OFFSET),
            covered_base_seq: read_u64(bytes, moff::COVERED_BASE_SEQ),
            covered_end_seq: read_u64(bytes, moff::COVERED_END_SEQ),
            highest_covered_source_id: read_u64(bytes, moff::HIGHEST_COVERED_SOURCE_ID),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> SegmentHeader {
        SegmentHeader {
            segment_id: 9,
            base_seq: Seq::new(100),
            base_offset: Offset::new(4096),
            created_unix_ms: 1_700_000_000_000,
            flags: 0,
        }
    }

    #[test]
    fn header_roundtrip() {
        let h = sample_header();
        let bytes = h.encode();
        assert_eq!(bytes.len(), SEGMENT_HEADER_LEN);
        assert_eq!(SegmentHeader::decode(&bytes).unwrap(), h);
    }

    #[test]
    fn footer_roundtrip() {
        let f = SegmentFooter {
            segment_id: 9,
            last_seq: Seq::new(141),
            record_count: 42,
        };
        let bytes = f.encode();
        assert_eq!(bytes.len(), SEGMENT_FOOTER_LEN);
        assert_eq!(SegmentFooter::decode(&bytes).unwrap(), f);
    }

    #[test]
    fn header_bad_magic() {
        let mut b = sample_header().encode();
        b[0] ^= 0xff;
        assert_eq!(SegmentHeader::decode(&b), Err(SegmentError::BadMagic));
    }

    #[test]
    fn header_bad_version_and_algo() {
        let mut b = sample_header().encode();
        b[hoff::VERSION] = 2;
        // recompute the CRC so we reach the version check, not the CRC check
        let crc = crc32c::crc32c(&b[SEGMENT_HEADER_CRC_RANGE]);
        b[hoff::HEADER_CRC..hoff::HEADER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            SegmentHeader::decode(&b),
            Err(SegmentError::UnsupportedVersion(2))
        );

        let mut b2 = sample_header().encode();
        b2[hoff::CHECKSUM_ALGO] = 9;
        let crc2 = crc32c::crc32c(&b2[SEGMENT_HEADER_CRC_RANGE]);
        b2[hoff::HEADER_CRC..hoff::HEADER_CRC + 4].copy_from_slice(&crc2.to_le_bytes());
        assert_eq!(
            SegmentHeader::decode(&b2),
            Err(SegmentError::UnsupportedChecksumAlgo(9))
        );
    }

    #[test]
    fn header_corruption_caught() {
        let mut b = sample_header().encode();
        b[hoff::SEGMENT_ID] ^= 0x01;
        assert_eq!(SegmentHeader::decode(&b), Err(SegmentError::BadCrc));
    }

    #[test]
    fn footer_corruption_caught() {
        let f = SegmentFooter {
            segment_id: 1,
            last_seq: Seq::new(1),
            record_count: 1,
        };
        let mut b = f.encode();
        b[foff::RECORD_COUNT] ^= 0x01;
        assert_eq!(SegmentFooter::decode(&b), Err(SegmentError::BadCrc));
    }

    #[test]
    fn truncated() {
        let b = sample_header().encode();
        assert_eq!(
            SegmentHeader::decode(&b[..40]),
            Err(SegmentError::Truncated)
        );
        let fb = SegmentFooter {
            segment_id: 0,
            last_seq: Seq::new(0),
            record_count: 0,
        }
        .encode();
        assert_eq!(
            SegmentFooter::decode(&fb[..20]),
            Err(SegmentError::Truncated)
        );
    }

    fn compacted_header() -> SegmentHeader {
        SegmentHeader {
            segment_id: 50,
            base_seq: Seq::new(7),
            base_offset: Offset::new(7),
            created_unix_ms: 1_700_000_000_000,
            flags: SEGMENT_FLAG_COMPACTED,
        }
    }

    #[test]
    fn a_non_compacted_header_is_byte_identical_to_v1() {
        // Backward compat: a header with no COMPACTED flag encodes the EXACT v1 bytes (version
        // byte 1), so a v1-only reader reads it unchanged. The version-2 bump is opt-in per the
        // flag, never stamped on an ordinary segment.
        let h = sample_header();
        let bytes = h.encode();
        assert_eq!(bytes[hoff::VERSION], FORMAT_VERSION);
        assert!(!h.is_compacted());
        // It decodes both v2-aware and v1-only, identically (no behavior change for v1 segments).
        assert_eq!(SegmentHeader::decode(&bytes).unwrap(), h);
        assert_eq!(SegmentHeader::decode_v1_only(&bytes).unwrap(), h);
    }

    #[test]
    fn a_compacted_header_stamps_v2_and_round_trips() {
        let h = compacted_header();
        let bytes = h.encode();
        assert_eq!(bytes[hoff::VERSION], FORMAT_VERSION_COMPACTED);
        assert!(h.is_compacted());
        assert_eq!(SegmentHeader::decode(&bytes).unwrap(), h);
    }

    #[test]
    fn a_plaintext_header_leaves_the_encryption_reserved_bytes_zero() {
        // DEFAULT-OFF byte identity (#780): a plaintext header writes the reserved [44, 60) region
        // (the at-rest encryption slots) as ALL zero, so it is byte-for-byte the pre-encryption
        // layout, and `aead_params` reports it as unencrypted.
        let h = sample_header();
        assert!(!h.is_encrypted());
        let bytes = h.encode();
        assert!(
            bytes[44..60].iter().all(|&b| b == 0),
            "the at-rest reserved [44, 60) region must be zero on a plaintext segment"
        );
        assert_eq!(SegmentHeader::aead_params(&bytes), None);
        // The encryption flag bit is clear.
        assert_eq!(read_u16(&bytes, hoff::FLAGS) & SEGMENT_FLAG_ENCRYPTED, 0);
    }

    #[test]
    fn an_encrypted_header_records_suite_and_key_id_and_round_trips() {
        use crate::format::AEAD_SUITE_AES_256_GCM;
        let h = sample_header();
        let key_id = 0x0102_0304_0506_0708u64;
        let bytes = h.encode_encrypted(AEAD_SUITE_AES_256_GCM, key_id);
        // Encryption does NOT bump the version (an encrypted, non-compacted segment stays v1).
        assert_eq!(bytes[hoff::VERSION], FORMAT_VERSION);
        // The reserved region carries the suite (byte 44) and the key-id ([45, 53)).
        assert_eq!(bytes[44], AEAD_SUITE_AES_256_GCM);
        // The header decodes: the ENCRYPTED flag is set and preserved, the base fields are intact.
        let decoded = SegmentHeader::decode(&bytes).unwrap();
        assert!(decoded.is_encrypted());
        assert_eq!(decoded.segment_id, h.segment_id);
        assert_eq!(decoded.base_seq, h.base_seq);
        // aead_params recovers the recorded suite and key-id (never the key).
        assert_eq!(
            SegmentHeader::aead_params(&bytes),
            Some((AEAD_SUITE_AES_256_GCM, key_id))
        );
        // The suite and key-id are CRC-protected for free: flipping the suite byte fails the header CRC.
        let mut corrupt = bytes;
        corrupt[44] ^= 0xFF;
        assert_eq!(SegmentHeader::decode(&corrupt), Err(SegmentError::BadCrc));
    }

    #[test]
    fn an_encrypted_and_compacted_header_keeps_both_flags_and_v2() {
        use crate::format::AEAD_SUITE_CHACHA20_POLY1305;
        // A segment may be BOTH compacted and encrypted: the version is 2 (compaction), and both flag
        // bits plus the AEAD params are present.
        let h = compacted_header();
        let bytes = h.encode_encrypted(AEAD_SUITE_CHACHA20_POLY1305, 42);
        assert_eq!(bytes[hoff::VERSION], FORMAT_VERSION_COMPACTED);
        let decoded = SegmentHeader::decode(&bytes).unwrap();
        assert!(decoded.is_compacted());
        assert!(decoded.is_encrypted());
        assert_eq!(
            SegmentHeader::aead_params(&bytes),
            Some((AEAD_SUITE_CHACHA20_POLY1305, 42))
        );
    }

    #[test]
    fn a_v1_only_reader_fails_closed_on_a_compacted_header() {
        // The fail-closed guarantee (#337): a pre-compaction (v1-only) reader REFUSES a compacted
        // segment with a typed UnsupportedVersion(2) rather than silently mis-reading its sparse
        // offsets. This is the old-binary-meets-new-data refusal.
        let bytes = compacted_header().encode();
        assert_eq!(
            SegmentHeader::decode_v1_only(&bytes),
            Err(SegmentError::UnsupportedVersion(FORMAT_VERSION_COMPACTED))
        );
    }

    #[test]
    fn version_and_compacted_flag_must_agree() {
        // A version-2 header WITHOUT the COMPACTED flag, or a v1 header WITH the flag, is a
        // structural contradiction (a half-written or foreign file) and is refused, so neither
        // half can parse without the other.
        let mut v2_no_flag = compacted_header().encode();
        v2_no_flag[hoff::FLAGS..hoff::FLAGS + 2].copy_from_slice(&0u16.to_le_bytes());
        let crc = crc32c::crc32c(&v2_no_flag[SEGMENT_HEADER_CRC_RANGE]);
        v2_no_flag[hoff::HEADER_CRC..hoff::HEADER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            SegmentHeader::decode(&v2_no_flag),
            Err(SegmentError::UnsupportedVersion(FORMAT_VERSION_COMPACTED))
        );

        // v1 version byte but the COMPACTED flag set: rejected as UnsupportedVersion(1).
        let mut v1_with_flag = sample_header().encode();
        v1_with_flag[hoff::FLAGS..hoff::FLAGS + 2]
            .copy_from_slice(&SEGMENT_FLAG_COMPACTED.to_le_bytes());
        let crc = crc32c::crc32c(&v1_with_flag[SEGMENT_HEADER_CRC_RANGE]);
        v1_with_flag[hoff::HEADER_CRC..hoff::HEADER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            SegmentHeader::decode(&v1_with_flag),
            Err(SegmentError::UnsupportedVersion(FORMAT_VERSION))
        );
    }

    #[test]
    fn a_v2_footer_round_trips_and_only_the_version_byte_differs() {
        let f = SegmentFooter {
            segment_id: 50,
            last_seq: Seq::new(42),
            record_count: 3,
        };
        let v1 = f.encode();
        let v2 = f.encode_v2();
        assert_eq!(v1[foff::VERSION], FORMAT_VERSION);
        assert_eq!(v2[foff::VERSION], FORMAT_VERSION_COMPACTED);
        // Everything except the version byte and the recomputed CRC is identical.
        assert_eq!(
            v1[foff::SEGMENT_ID..foff::FOOTER_CRC],
            v2[foff::SEGMENT_ID..foff::FOOTER_CRC]
        );
        // Both decode to the same footer (the version byte is not part of the decoded struct).
        assert_eq!(SegmentFooter::decode(&v1).unwrap(), f);
        assert_eq!(SegmentFooter::decode(&v2).unwrap(), f);
    }

    #[test]
    fn compaction_meta_round_trips_and_rejects_corruption() {
        let m = CompactionMeta {
            covered_base_offset: 100,
            covered_end_offset: 130,
            covered_base_seq: 100,
            covered_end_seq: 130,
            highest_covered_source_id: 4,
        };
        let bytes = m.encode();
        assert_eq!(bytes.len(), COMPACTION_META_LEN);
        assert_eq!(CompactionMeta::decode(&bytes).unwrap(), m);
        // A short block is truncated; a flipped byte fails the block CRC (so a torn trailing block
        // is rejected exactly like a torn footer).
        assert_eq!(
            CompactionMeta::decode(&bytes[..40]),
            Err(SegmentError::Truncated)
        );
        let mut torn = bytes;
        torn[0] ^= 0x01;
        assert_eq!(CompactionMeta::decode(&torn), Err(SegmentError::BadCrc));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn header_roundtrip(id in any::<u64>(), bs in any::<u64>(), bo in any::<u64>(), ts in any::<u64>(), fl in any::<u16>()) {
            let h = SegmentHeader { segment_id: id, base_seq: Seq::new(bs), base_offset: Offset::new(bo), created_unix_ms: ts, flags: fl };
            prop_assert_eq!(SegmentHeader::decode(&h.encode()).unwrap(), h);
        }

        #[test]
        fn footer_roundtrip(id in any::<u64>(), ls in any::<u64>(), rc in any::<u32>()) {
            let f = SegmentFooter { segment_id: id, last_seq: Seq::new(ls), record_count: rc };
            prop_assert_eq!(SegmentFooter::decode(&f.encode()).unwrap(), f);
        }

        #[test]
        fn footer_bit_flip_always_rejected(id in any::<u64>(), idx in any::<prop::sample::Index>(), bit in 0u8..8) {
            let f = SegmentFooter { segment_id: id, last_seq: Seq::new(7), record_count: 3 };
            let mut b = f.encode();
            let i = idx.index(b.len());
            b[i] ^= 1u8 << bit;
            // CRC32C catches every single-bit error in a 32-byte structure, and magic
            // and version flips are caught structurally, so a flip is always rejected.
            prop_assert!(SegmentFooter::decode(&b).is_err());
        }

        #[test]
        fn header_bit_flip_never_clean(id in any::<u64>(), idx in any::<prop::sample::Index>(), bit in 0u8..8) {
            let h = SegmentHeader { segment_id: id, base_seq: Seq::new(1), base_offset: Offset::new(0), created_unix_ms: 0, flags: 0 };
            let mut b = h.encode();
            let i = idx.index(b.len());
            b[i] ^= 1u8 << bit;
            // CRC32C catches every single-bit error in a 64-byte structure, and magic,
            // version, and checksum-algo flips are caught structurally.
            prop_assert!(SegmentHeader::decode(&b).is_err());
        }

        #[test]
        fn compaction_meta_roundtrip(
            cbo in any::<u64>(), ceo in any::<u64>(), cbs in any::<u64>(),
            ces in any::<u64>(), hid in any::<u64>(),
        ) {
            let m = CompactionMeta {
                covered_base_offset: cbo,
                covered_end_offset: ceo,
                covered_base_seq: cbs,
                covered_end_seq: ces,
                highest_covered_source_id: hid,
            };
            prop_assert_eq!(CompactionMeta::decode(&m.encode()).unwrap(), m);
        }

        #[test]
        fn compaction_meta_bit_flip_always_rejected(
            cbo in any::<u64>(), idx in any::<prop::sample::Index>(), bit in 0u8..8,
        ) {
            let m = CompactionMeta {
                covered_base_offset: cbo,
                covered_end_offset: cbo.wrapping_add(10),
                covered_base_seq: cbo,
                covered_end_seq: cbo.wrapping_add(10),
                highest_covered_source_id: 3,
            };
            let mut b = m.encode();
            let i = idx.index(b.len());
            b[i] ^= 1u8 << bit;
            // CRC32C catches every single-bit error in the 44-byte block, so a torn or rotted
            // trailing block is always rejected (and recovery then treats it as crash-before-commit).
            prop_assert!(CompactionMeta::decode(&b).is_err());
        }
    }
}
