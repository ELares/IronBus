// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encoding and decoding of the IronBus record frame, version 1.
//!
//! A frame is a fixed 36-byte header, a variable body (key, then headers, then
//! payload), and an 8-byte trailer, all little-endian. The `header_crc` (CRC32C)
//! protects header bytes `[0, 32)`; the `body_crc` (CRC32C) protects the body; and
//! `total_len` is the whole frame length, which lets a reader find the trailer and
//! scan forward or backward.
//!
//! The optional second xxh3-64 checksum for large payloads (see the corruption
//! design) is not encoded yet: the frozen trailer has no field for it. That gap is
//! tracked separately; this codec implements the mandatory CRC32C path.

use crate::format::{
    header_offsets as off, FORMAT_VERSION, MAX_RECORD_BYTES_CEILING, RECORD_HEADER_CRC_RANGE,
    RECORD_HEADER_LEN, RECORD_MAGIC, RECORD_TRAILER_LEN,
};
use crate::types::{RecordFlags, Seq};

/// A borrowed view of a record, used both as the input to [`encode`] and the
/// output of [`decode`]. It owns no memory; slices borrow the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordView<'a> {
    /// The record's sequence number within its segment.
    pub seq: Seq,
    /// Producer timestamp in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// Record flags as stored. On [`encode`], the `HAS_KEY` bit is derived from the
    /// key length and overwritten; other bits are taken from the caller.
    pub flags: RecordFlags,
    /// Optional routing or ordering key (empty if none).
    pub key: &'a [u8],
    /// Optional record headers blob (empty if none).
    pub headers: &'a [u8],
    /// The record payload (possibly compressed; that is signalled by `COMPRESSED`).
    pub payload: &'a [u8],
}

/// An error returned by [`encode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// The record's total framed size exceeds the format ceiling of 1 GiB.
    TooLarge,
}

/// An error returned by [`decode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ends before a complete frame (a torn or partially written tail).
    Truncated,
    /// The leading magic number did not match a record frame.
    BadMagic,
    /// The format version is not understood by this build.
    UnsupportedVersion(u8),
    /// The header CRC32C did not match: the header is corrupt.
    BadHeaderCrc,
    /// The body CRC32C did not match: the body is corrupt.
    BadBodyCrc,
    /// The encoded length fields are internally inconsistent.
    BadLength,
    /// The encoded total length exceeds the format ceiling of 1 GiB.
    TooLarge,
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncodeError::TooLarge => write!(f, "record exceeds the maximum frame size"),
        }
    }
}
impl std::error::Error for EncodeError {}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "record frame is truncated"),
            DecodeError::BadMagic => write!(f, "record frame has a bad magic number"),
            DecodeError::UnsupportedVersion(v) => {
                write!(f, "unsupported record format version {v}")
            }
            DecodeError::BadHeaderCrc => write!(f, "record header CRC mismatch"),
            DecodeError::BadBodyCrc => write!(f, "record body CRC mismatch"),
            DecodeError::BadLength => write!(f, "record frame has inconsistent length fields"),
            DecodeError::TooLarge => write!(f, "record frame exceeds the maximum size"),
        }
    }
}
impl std::error::Error for DecodeError {}

#[inline]
fn read_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
#[inline]
fn read_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
#[inline]
fn read_u64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Encodes `rec` into a complete record frame appended to `out`.
///
/// Returns the number of bytes written. The `HAS_KEY` flag is set automatically
/// when the key is non-empty.
///
/// # Errors
/// Returns [`EncodeError::TooLarge`] if the total framed size would exceed the
/// 1 GiB format ceiling.
pub fn encode(rec: &RecordView<'_>, out: &mut Vec<u8>) -> Result<usize, EncodeError> {
    let key_len = u32::try_from(rec.key.len()).map_err(|_| EncodeError::TooLarge)?;
    let hdr_len = u32::try_from(rec.headers.len()).map_err(|_| EncodeError::TooLarge)?;
    let payload_len = u32::try_from(rec.payload.len()).map_err(|_| EncodeError::TooLarge)?;

    let body_len = rec.key.len() + rec.headers.len() + rec.payload.len();
    let total = RECORD_HEADER_LEN + body_len + RECORD_TRAILER_LEN;
    let total_u32 = u32::try_from(total).map_err(|_| EncodeError::TooLarge)?;
    if total_u32 > MAX_RECORD_BYTES_CEILING {
        return Err(EncodeError::TooLarge);
    }

    let mut flags = rec.flags;
    flags = if rec.key.is_empty() {
        RecordFlags::from_bits(flags.bits() & !RecordFlags::HAS_KEY.bits())
    } else {
        flags.with(RecordFlags::HAS_KEY)
    };

    // Header bytes [0, 32), then the header CRC at [32, 36).
    let mut header = [0u8; RECORD_HEADER_LEN];
    header[off::MAGIC..off::MAGIC + 2].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
    header[off::VERSION] = FORMAT_VERSION;
    header[off::FLAGS] = flags.bits();
    header[off::SEQ..off::SEQ + 8].copy_from_slice(&rec.seq.get().to_le_bytes());
    header[off::TIMESTAMP..off::TIMESTAMP + 8].copy_from_slice(&rec.timestamp_ms.to_le_bytes());
    header[off::KEY_LEN..off::KEY_LEN + 4].copy_from_slice(&key_len.to_le_bytes());
    header[off::HDR_LEN..off::HDR_LEN + 4].copy_from_slice(&hdr_len.to_le_bytes());
    header[off::PAYLOAD_LEN..off::PAYLOAD_LEN + 4].copy_from_slice(&payload_len.to_le_bytes());
    let header_crc = crc32c::crc32c(&header[RECORD_HEADER_CRC_RANGE]);
    header[off::HEADER_CRC..off::HEADER_CRC + 4].copy_from_slice(&header_crc.to_le_bytes());

    out.reserve(total);
    out.extend_from_slice(&header);
    let body_start = out.len();
    out.extend_from_slice(rec.key);
    out.extend_from_slice(rec.headers);
    out.extend_from_slice(rec.payload);
    let body_crc = crc32c::crc32c(&out[body_start..body_start + body_len]);
    out.extend_from_slice(&body_crc.to_le_bytes());
    out.extend_from_slice(&total_u32.to_le_bytes());
    Ok(total)
}

/// Decodes one record frame from the front of `input`.
///
/// On success returns the decoded [`RecordView`] (borrowing `input`) and the total
/// number of bytes the frame occupied, so the caller can advance to the next frame.
///
/// # Errors
/// Returns a [`DecodeError`] describing the first inconsistency found. A
/// [`DecodeError::Truncated`] means more bytes may complete the frame; the other
/// variants mean the frame is corrupt and must be skipped by recovery.
pub fn decode(input: &[u8]) -> Result<(RecordView<'_>, usize), DecodeError> {
    if input.len() < RECORD_HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    if read_u16(input, off::MAGIC) != RECORD_MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = input[off::VERSION];
    if version != FORMAT_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let stored_header_crc = read_u32(input, off::HEADER_CRC);
    if crc32c::crc32c(&input[RECORD_HEADER_CRC_RANGE]) != stored_header_crc {
        return Err(DecodeError::BadHeaderCrc);
    }

    let key_len = read_u32(input, off::KEY_LEN) as usize;
    let hdr_len = read_u32(input, off::HDR_LEN) as usize;
    let payload_len = read_u32(input, off::PAYLOAD_LEN) as usize;
    let body_len = key_len + hdr_len + payload_len;
    let total = RECORD_HEADER_LEN + body_len + RECORD_TRAILER_LEN;
    if u32::try_from(total).map_or(true, |t| t > MAX_RECORD_BYTES_CEILING) {
        return Err(DecodeError::TooLarge);
    }
    if input.len() < total {
        return Err(DecodeError::Truncated);
    }

    let body = &input[RECORD_HEADER_LEN..RECORD_HEADER_LEN + body_len];
    let trailer = &input[RECORD_HEADER_LEN + body_len..total];
    let stored_body_crc = read_u32(trailer, 0);
    let stored_total = read_u32(trailer, 4) as usize;
    if stored_total != total {
        return Err(DecodeError::BadLength);
    }
    if crc32c::crc32c(body) != stored_body_crc {
        return Err(DecodeError::BadBodyCrc);
    }

    let view = RecordView {
        seq: Seq::new(read_u64(input, off::SEQ)),
        timestamp_ms: read_u64(input, off::TIMESTAMP),
        flags: RecordFlags::from_bits(input[off::FLAGS]),
        key: &body[..key_len],
        headers: &body[key_len..key_len + hdr_len],
        payload: &body[key_len + hdr_len..],
    };
    Ok((view, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let rec = RecordView {
            seq: Seq::new(7),
            timestamp_ms: 1234,
            flags: RecordFlags::EMPTY,
            key: b"k",
            headers: b"h",
            payload: b"hello",
        };
        let mut buf = Vec::new();
        let n = encode(&rec, &mut buf).unwrap();
        assert_eq!(n, buf.len());
        buf
    }

    #[test]
    fn roundtrip_basic() {
        let buf = sample();
        let (got, n) = decode(&buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(got.seq, Seq::new(7));
        assert_eq!(got.timestamp_ms, 1234);
        assert_eq!(got.key, b"k");
        assert_eq!(got.headers, b"h");
        assert_eq!(got.payload, b"hello");
        // HAS_KEY was derived because the key is non-empty.
        assert!(got.flags.contains(RecordFlags::HAS_KEY));
    }

    #[test]
    fn empty_key_clears_has_key() {
        let rec = RecordView {
            seq: Seq::new(1),
            timestamp_ms: 0,
            flags: RecordFlags::HAS_KEY, // caller wrongly set it
            key: b"",
            headers: b"",
            payload: b"x",
        };
        let mut buf = Vec::new();
        encode(&rec, &mut buf).unwrap();
        let (got, _) = decode(&buf).unwrap();
        assert!(!got.flags.contains(RecordFlags::HAS_KEY));
    }

    #[test]
    fn truncated_is_detected() {
        let buf = sample();
        assert_eq!(decode(&buf[..10]), Err(DecodeError::Truncated));
        assert_eq!(decode(&buf[..buf.len() - 1]), Err(DecodeError::Truncated));
    }

    #[test]
    fn bad_magic_is_detected() {
        let mut buf = sample();
        buf[0] ^= 0xff;
        assert_eq!(decode(&buf), Err(DecodeError::BadMagic));
    }

    #[test]
    fn header_corruption_is_detected() {
        let mut buf = sample();
        buf[off::SEQ] ^= 0x01; // a header byte inside the CRC range
        assert_eq!(decode(&buf), Err(DecodeError::BadHeaderCrc));
    }

    #[test]
    fn body_corruption_is_detected() {
        let mut buf = sample();
        let body = RECORD_HEADER_LEN + 2; // somewhere in the payload
        buf[body] ^= 0x01;
        assert_eq!(decode(&buf), Err(DecodeError::BadBodyCrc));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip(
            seq in any::<u64>(),
            ts in any::<u64>(),
            extra_flag in any::<bool>(),
            key in proptest::collection::vec(any::<u8>(), 0..300),
            headers in proptest::collection::vec(any::<u8>(), 0..300),
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            // Only COMPRESSED is a caller-controlled bit here; HAS_KEY is derived.
            let flags = if extra_flag { RecordFlags::COMPRESSED } else { RecordFlags::EMPTY };
            let rec = RecordView {
                seq: Seq::new(seq), timestamp_ms: ts, flags,
                key: &key, headers: &headers, payload: &payload,
            };
            let mut buf = Vec::new();
            let n = encode(&rec, &mut buf).unwrap();
            prop_assert_eq!(n, buf.len());
            let (got, consumed) = decode(&buf).unwrap();
            prop_assert_eq!(consumed, buf.len());
            prop_assert_eq!(got.seq, rec.seq);
            prop_assert_eq!(got.timestamp_ms, rec.timestamp_ms);
            prop_assert_eq!(got.key, &key[..]);
            prop_assert_eq!(got.headers, &headers[..]);
            prop_assert_eq!(got.payload, &payload[..]);
            prop_assert_eq!(got.flags.contains(RecordFlags::COMPRESSED), extra_flag);
            prop_assert_eq!(got.flags.contains(RecordFlags::HAS_KEY), !key.is_empty());
        }

        #[test]
        fn single_byte_flip_never_decodes_clean(
            seq in any::<u64>(),
            payload in proptest::collection::vec(any::<u8>(), 1..512),
            idx in any::<prop::sample::Index>(),
            bit in 0u8..8,
        ) {
            let rec = RecordView {
                seq: Seq::new(seq), timestamp_ms: 0, flags: RecordFlags::EMPTY,
                key: b"", headers: b"", payload: &payload,
            };
            let mut buf = Vec::new();
            encode(&rec, &mut buf).unwrap();
            let i = idx.index(buf.len());
            buf[i] ^= 1u8 << bit;
            // A single bit flip must never yield a clean decode with the same payload.
            match decode(&buf) {
                Err(_) => {}
                Ok((got, _)) => prop_assert!(got.payload != &payload[..],
                    "a corrupted frame decoded to the original payload"),
            }
        }
    }
}
