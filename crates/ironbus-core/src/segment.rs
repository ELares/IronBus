// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encoding and decoding of the IronBus segment header and footer (version 1).
//!
//! Every segment file begins with a 64-byte header (4 KiB-aligned) and, once sealed,
//! ends with a 32-byte footer. Both are little-endian and CRC32C-protected. The
//! records between them use the frame in [`crate::codec`].

use crate::format::{
    segment_footer_offsets as foff, segment_header_offsets as hoff, CHECKSUM_ALGO_CRC32C,
    FORMAT_VERSION, SEGMENT_FOOTER_CRC_RANGE, SEGMENT_FOOTER_LEN, SEGMENT_HEADER_CRC_RANGE,
    SEGMENT_HEADER_LEN, SEGMENT_MAGIC,
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
    /// Segment flag bits (reserved; zero in version 1).
    pub flags: u16,
}

/// The fixed 32-byte footer written when a segment is sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentFooter {
    /// Number of records in the sealed segment.
    pub record_count: u64,
    /// Sequence number of the last record in the sealed segment.
    pub last_seq: Seq,
    /// Wall-clock seal time, milliseconds since the Unix epoch.
    pub sealed_unix_ms: u64,
}

/// An error decoding a segment header or footer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SegmentError {
    /// The input is shorter than the fixed structure.
    Truncated,
    /// The segment magic did not match (header only).
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
    /// Encodes the header into its fixed 64-byte on-disk form.
    #[must_use]
    pub fn encode(&self) -> [u8; SEGMENT_HEADER_LEN] {
        let mut h = [0u8; SEGMENT_HEADER_LEN];
        h[hoff::MAGIC..hoff::MAGIC + 8].copy_from_slice(&SEGMENT_MAGIC);
        h[hoff::VERSION] = FORMAT_VERSION;
        h[hoff::CHECKSUM_ALGO] = CHECKSUM_ALGO_CRC32C;
        h[hoff::FLAGS..hoff::FLAGS + 2].copy_from_slice(&self.flags.to_le_bytes());
        h[hoff::SEGMENT_ID..hoff::SEGMENT_ID + 8].copy_from_slice(&self.segment_id.to_le_bytes());
        h[hoff::BASE_SEQ..hoff::BASE_SEQ + 8].copy_from_slice(&self.base_seq.get().to_le_bytes());
        h[hoff::BASE_OFFSET..hoff::BASE_OFFSET + 8]
            .copy_from_slice(&self.base_offset.get().to_le_bytes());
        h[hoff::CREATED_MS..hoff::CREATED_MS + 8]
            .copy_from_slice(&self.created_unix_ms.to_le_bytes());
        let crc = crc32c::crc32c(&h[SEGMENT_HEADER_CRC_RANGE]);
        h[hoff::HEADER_CRC..hoff::HEADER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        h
    }

    /// Decodes a header from the first 64 bytes of `bytes`.
    ///
    /// # Errors
    /// Returns a [`SegmentError`] if the input is too short, the magic, version, or
    /// checksum algorithm is wrong, or the header CRC does not match.
    pub fn decode(bytes: &[u8]) -> Result<SegmentHeader, SegmentError> {
        if bytes.len() < SEGMENT_HEADER_LEN {
            return Err(SegmentError::Truncated);
        }
        if bytes[hoff::MAGIC..hoff::MAGIC + 8] != SEGMENT_MAGIC {
            return Err(SegmentError::BadMagic);
        }
        let version = bytes[hoff::VERSION];
        if version != FORMAT_VERSION {
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
            flags: read_u16(bytes, hoff::FLAGS),
        })
    }
}

impl SegmentFooter {
    /// Encodes the footer into its fixed 32-byte on-disk form.
    #[must_use]
    pub fn encode(&self) -> [u8; SEGMENT_FOOTER_LEN] {
        let mut f = [0u8; SEGMENT_FOOTER_LEN];
        f[foff::RECORD_COUNT..foff::RECORD_COUNT + 8]
            .copy_from_slice(&self.record_count.to_le_bytes());
        f[foff::LAST_SEQ..foff::LAST_SEQ + 8].copy_from_slice(&self.last_seq.get().to_le_bytes());
        f[foff::SEALED_MS..foff::SEALED_MS + 8].copy_from_slice(&self.sealed_unix_ms.to_le_bytes());
        let crc = crc32c::crc32c(&f[SEGMENT_FOOTER_CRC_RANGE]);
        f[foff::FOOTER_CRC..foff::FOOTER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        f
    }

    /// Decodes a footer from the first 32 bytes of `bytes` (the last 32 bytes of a
    /// sealed segment).
    ///
    /// # Errors
    /// Returns [`SegmentError::Truncated`] if too short, or [`SegmentError::BadCrc`]
    /// if the footer CRC does not match.
    pub fn decode(bytes: &[u8]) -> Result<SegmentFooter, SegmentError> {
        if bytes.len() < SEGMENT_FOOTER_LEN {
            return Err(SegmentError::Truncated);
        }
        if crc32c::crc32c(&bytes[SEGMENT_FOOTER_CRC_RANGE]) != read_u32(bytes, foff::FOOTER_CRC) {
            return Err(SegmentError::BadCrc);
        }
        Ok(SegmentFooter {
            record_count: read_u64(bytes, foff::RECORD_COUNT),
            last_seq: Seq::new(read_u64(bytes, foff::LAST_SEQ)),
            sealed_unix_ms: read_u64(bytes, foff::SEALED_MS),
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
            record_count: 42,
            last_seq: Seq::new(141),
            sealed_unix_ms: 1_700_000_005_000,
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
            record_count: 1,
            last_seq: Seq::new(1),
            sealed_unix_ms: 0,
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
            record_count: 0,
            last_seq: Seq::new(0),
            sealed_unix_ms: 0,
        }
        .encode();
        assert_eq!(
            SegmentFooter::decode(&fb[..20]),
            Err(SegmentError::Truncated)
        );
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
        fn footer_roundtrip(rc in any::<u64>(), ls in any::<u64>(), ts in any::<u64>()) {
            let f = SegmentFooter { record_count: rc, last_seq: Seq::new(ls), sealed_unix_ms: ts };
            prop_assert_eq!(SegmentFooter::decode(&f.encode()).unwrap(), f);
        }

        #[test]
        fn header_bit_flip_never_clean(id in any::<u64>(), idx in any::<prop::sample::Index>(), bit in 0u8..8) {
            let h = SegmentHeader { segment_id: id, base_seq: Seq::new(1), base_offset: Offset::new(0), created_unix_ms: 0, flags: 0 };
            let mut b = h.encode();
            let i = idx.index(b.len());
            b[i] ^= 1u8 << bit;
            match SegmentHeader::decode(&b) {
                Err(_) => {}
                Ok(got) => prop_assert_eq!(got, h),
            }
        }
    }
}
