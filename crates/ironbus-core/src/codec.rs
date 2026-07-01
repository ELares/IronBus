// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encoding and decoding of the IronBus record frame, version 1.
//!
//! A frame is a fixed 36-byte header, a variable body (key, then headers, then
//! payload), and an 8-byte trailer, all little-endian. The `header_crc` (CRC32C)
//! protects header bytes `[0, 32)`; the `body_crc` (CRC32C) protects the body; and
//! `total_len` is the whole frame length, which lets a reader find the trailer and
//! scan forward or backward.
//!
//! A record whose stored body is at least [`XXH3_PAYLOAD_THRESHOLD`] bytes also carries
//! a second, independent xxh3-64 checksum (issue #8) over the same body byte range the
//! `body_crc` covers. It is an 8-byte little-endian field placed immediately before the
//! 8-byte trailer and counted in `total_len`, and its presence is flagged by the
//! [`RecordFlags::HAS_XXH3`] header bit. A record below the threshold has no field, no
//! flag, and the exact byte-for-byte layout it had before the field existed. CRC32C
//! stays the resync-gating checksum: it is verified first, and an xxh3-64 mismatch is a
//! distinct, typed corruption error.

use crate::format::{
    header_offsets as off, FORMAT_VERSION, MAX_RECORD_BYTES_CEILING, RECORD_HEADER_CRC_RANGE,
    RECORD_HEADER_LEN, RECORD_MAGIC, RECORD_TRAILER_LEN, RECORD_XXH3_LEN, XXH3_PAYLOAD_THRESHOLD,
};
use crate::raw::{read_u16, read_u32, read_u64};
use crate::types::{RecordFlags, Seq};
use xxhash_rust::xxh3::{xxh3_64, Xxh3};

/// Pre-computed per-record body checksums (issue #830), produced OFF the single-writer append
/// actor on the producing connection thread that already holds the body bytes, then trusted by
/// [`encode_precomputed`].
///
/// `body_crc` is the CRC32C over the contiguous stored body (`key ++ headers ++ payload`), the exact
/// byte range [`encode`] would checksum. `xxh3` is `Some` iff the stored body reaches
/// [`XXH3_PAYLOAD_THRESHOLD`] — the SAME condition [`encode`] uses to decide whether the second
/// xxh3-64 field is present — so a `BodyChecksums` computed by [`BodyChecksums::compute`] over the
/// same three slices always agrees with the frame [`encode`] emits.
///
/// This is safe to offload because the checksums are CORRUPTION-detection values RE-VALIDATED on
/// every read: a wrong value here is not a trust boundary — it only makes the record fail its own
/// CRC on read and surface as corrupt — so moving the COMPUTATION off the serialized actor cannot
/// weaken any integrity guarantee. The on-disk bytes are byte-identical to the actor-computed frame
/// whenever the precomputed values match the stored body (which [`encode_precomputed`] debug-asserts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyChecksums {
    /// CRC32C (Castagnoli) over the contiguous body `key ++ headers ++ payload`.
    pub body_crc: u32,
    /// xxh3-64 over the same body byte range, `Some` iff the stored body reaches
    /// [`XXH3_PAYLOAD_THRESHOLD`] (matching [`encode`]'s `HAS_XXH3` condition), else `None`.
    pub xxh3: Option<u64>,
}

impl BodyChecksums {
    /// Computes the body checksums over the contiguous body `key ++ headers ++ payload`
    /// INCREMENTALLY, with no intermediate concatenation buffer, producing exactly the values
    /// [`encode`] computes over the bytes it lays down. CRC32C is folded across the three slices
    /// (`crc32c(key)`, then `crc32c_append` over headers then payload — equal to a single pass over
    /// the concatenation), and the xxh3-64 streaming hasher is fed the same three slices in order.
    /// The xxh3-64 is present under the identical [`XXH3_PAYLOAD_THRESHOLD`] rule [`encode`] applies,
    /// measured on the STORED body length (the bytes actually written).
    #[must_use]
    pub fn compute(key: &[u8], headers: &[u8], payload: &[u8]) -> BodyChecksums {
        let body_len = key.len() + headers.len() + payload.len();
        let mut body_crc = crc32c::crc32c(key);
        body_crc = crc32c::crc32c_append(body_crc, headers);
        body_crc = crc32c::crc32c_append(body_crc, payload);
        let xxh3 = if body_len >= XXH3_PAYLOAD_THRESHOLD as usize {
            let mut hasher = Xxh3::new();
            hasher.update(key);
            hasher.update(headers);
            hasher.update(payload);
            Some(hasher.digest())
        } else {
            None
        };
        BodyChecksums { body_crc, xxh3 }
    }
}

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
    /// The body xxh3-64 did not match: the body is corrupt. Distinct from
    /// [`DecodeError::BadBodyCrc`] so a caller can tell which checksum caught it. CRC32C
    /// is verified first, so this is reached only when the body passed CRC32C but failed
    /// the independent xxh3-64 (or the xxh3-64 field itself was corrupted).
    BadXxh3,
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
            DecodeError::BadXxh3 => write!(f, "record body xxh3-64 mismatch"),
            DecodeError::BadLength => write!(f, "record frame has inconsistent length fields"),
            DecodeError::TooLarge => write!(f, "record frame exceeds the maximum size"),
        }
    }
}
impl std::error::Error for DecodeError {}

/// Encodes `rec` into a complete record frame appended to `out`.
///
/// Returns the number of bytes written. The `HAS_KEY` flag is set automatically
/// when the key is non-empty.
///
/// # Errors
/// Returns [`EncodeError::TooLarge`] if the total framed size would exceed the
/// 1 GiB format ceiling.
pub fn encode(rec: &RecordView<'_>, out: &mut Vec<u8>) -> Result<usize, EncodeError> {
    encode_impl(rec, None, out)
}

/// Encodes `rec` like [`encode`], but TRUSTS the caller-supplied `checksums` for the body instead of
/// computing them on this thread (issue #830). The body CRC32C (and, for a large body, the xxh3-64)
/// are lifted off the single-writer append actor and onto the producing connection thread, which
/// already holds the body bytes; the actor then only memcpys the body and writes the precomputed
/// trailer.
///
/// `checksums` MUST have been computed by [`BodyChecksums::compute`] over the SAME
/// `key`/`headers`/`payload` slices this `rec` carries, i.e. the exact stored body. When they match,
/// the emitted frame is byte-identical to [`encode`]'s. A mismatch is not a memory- or trust-safety
/// hazard — the checksum is re-validated on read, so a wrong value only makes the record fail its own
/// CRC on read (surfaced as corrupt) — but it would durably store an unreadable record, so this is a
/// caller contract a debug build asserts. Callers that re-inject or rewrite the body (compression,
/// DLQ redrive, replication apply) must use [`encode`], which recomputes.
///
/// # Errors
/// Returns [`EncodeError::TooLarge`] if the total framed size would exceed the 1 GiB format ceiling.
pub fn encode_precomputed(
    rec: &RecordView<'_>,
    checksums: BodyChecksums,
    out: &mut Vec<u8>,
) -> Result<usize, EncodeError> {
    encode_impl(rec, Some(checksums), out)
}

/// The shared framing core behind [`encode`] and [`encode_precomputed`]. When `precomputed` is
/// `Some`, the body checksums are trusted (computed off-actor, #830); when `None`, they are computed
/// here over the body bytes just laid down, exactly as before. Either way the emitted frame layout is
/// identical.
fn encode_impl(
    rec: &RecordView<'_>,
    precomputed: Option<BodyChecksums>,
    out: &mut Vec<u8>,
) -> Result<usize, EncodeError> {
    let key_len = u32::try_from(rec.key.len()).map_err(|_| EncodeError::TooLarge)?;
    let hdr_len = u32::try_from(rec.headers.len()).map_err(|_| EncodeError::TooLarge)?;
    let payload_len = u32::try_from(rec.payload.len()).map_err(|_| EncodeError::TooLarge)?;

    let body_len = rec.key.len() + rec.headers.len() + rec.payload.len();
    // The xxh3-64 field is added for a stored body at or above the threshold. `body_len`
    // is the stored size (the bytes actually written: key + headers + payload), so the
    // checksum protects exactly what lands on disk. See `XXH3_PAYLOAD_THRESHOLD`.
    let has_xxh3 = body_len >= XXH3_PAYLOAD_THRESHOLD as usize;
    let xxh3_field = if has_xxh3 { RECORD_XXH3_LEN } else { 0 };
    let total = RECORD_HEADER_LEN + body_len + xxh3_field + RECORD_TRAILER_LEN;
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
    // HAS_XXH3 is derived from the stored body size, never taken from the caller, so it
    // always agrees with whether the field is present (decode enforces that agreement).
    flags = if has_xxh3 {
        flags.with(RecordFlags::HAS_XXH3)
    } else {
        RecordFlags::from_bits(flags.bits() & !RecordFlags::HAS_XXH3.bits())
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
    let body = &out[body_start..body_start + body_len];
    // Trust the off-actor precomputed checksums when supplied (#830), else compute them here over the
    // body just laid down. A debug build re-derives them from the body to pin the caller contract that
    // the precomputed values describe the exact stored bytes; a mismatch would durably store a record
    // that fails its own CRC on read, so it is a bug, not a silent divergence.
    let checksums = match precomputed {
        Some(c) => {
            debug_assert_eq!(
                c,
                BodyChecksums::compute(rec.key, rec.headers, rec.payload),
                "precomputed body checksums must match the stored body (#830)"
            );
            c
        }
        None => BodyChecksums {
            body_crc: crc32c::crc32c(body),
            xxh3: if has_xxh3 { Some(xxh3_64(body)) } else { None },
        },
    };
    // The xxh3-64 covers the same body byte range as `body_crc`, and the field precedes
    // the trailer so the 8-byte trailer (`body_crc` then `total_len`) is unchanged. `has_xxh3` is
    // derived from the stored body length above and always agrees with `checksums.xxh3` for a
    // correctly-computed `BodyChecksums`; the `unwrap_or_else` recomputes rather than panic if a
    // caller passed an inconsistent value, keeping the frame well-formed.
    if has_xxh3 {
        let xxh3 = checksums.xxh3.unwrap_or_else(|| xxh3_64(body));
        out.extend_from_slice(&xxh3.to_le_bytes());
    }
    out.extend_from_slice(&checksums.body_crc.to_le_bytes());
    out.extend_from_slice(&total_u32.to_le_bytes());
    Ok(total)
}

/// Returns the total on-disk length of the record whose frame begins at the start of
/// `header`, validating the magic, version, and header CRC, WITHOUT needing the record
/// body. `header` need only contain the first [`RECORD_HEADER_LEN`] bytes of the frame.
///
/// Streaming recovery uses this to read exactly one record at a time: read the header,
/// learn the length, then read that many bytes and [`decode`] them, so peak memory is
/// one record rather than the whole segment (#156). The header validation here is the
/// same first half [`decode`] performs, so a header this rejects, `decode` rejects too;
/// a `codec` test pins that the returned length equals `decode`'s consumed length.
///
/// # Errors
/// Returns [`DecodeError::Truncated`] if `header` is shorter than a record header, and
/// the corrupt variants ([`DecodeError::BadMagic`], [`DecodeError::UnsupportedVersion`],
/// [`DecodeError::BadHeaderCrc`], [`DecodeError::TooLarge`]) for a bad or oversize header.
pub fn decoded_len(header: &[u8]) -> Result<usize, DecodeError> {
    if header.len() < RECORD_HEADER_LEN {
        return Err(DecodeError::Truncated);
    }
    if read_u16(header, off::MAGIC) != RECORD_MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = header[off::VERSION];
    if version != FORMAT_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let stored_header_crc = read_u32(header, off::HEADER_CRC);
    if crc32c::crc32c(&header[RECORD_HEADER_CRC_RANGE]) != stored_header_crc {
        return Err(DecodeError::BadHeaderCrc);
    }
    // The flags byte is inside the CRC-protected range, so HAS_XXH3 is trusted here and
    // its 8-byte field is counted in `total_len`, matching `decode`.
    let xxh3_field = if RecordFlags::from_bits(header[off::FLAGS]).contains(RecordFlags::HAS_XXH3) {
        RECORD_XXH3_LEN as u64
    } else {
        0
    };
    // Sum the three attacker-controlled u32 lengths in u64 so the total cannot overflow
    // usize on a 32-bit target before it is bounded by the 1 GiB ceiling (matches `decode`).
    let total64 = u64::from(read_u32(header, off::KEY_LEN))
        + u64::from(read_u32(header, off::HDR_LEN))
        + u64::from(read_u32(header, off::PAYLOAD_LEN))
        + RECORD_HEADER_LEN as u64
        + xxh3_field
        + RECORD_TRAILER_LEN as u64;
    if total64 > u64::from(MAX_RECORD_BYTES_CEILING) {
        return Err(DecodeError::TooLarge);
    }
    usize::try_from(total64).map_err(|_| DecodeError::TooLarge)
}

/// Decodes one record frame from the front of `input`.
///
/// On success returns the decoded [`RecordView`] (borrowing `input`) and the total
/// number of bytes the frame occupied, so the caller can advance to the next frame.
///
/// `decode` borrows sub-slices of `input` and allocates nothing; bounding the
/// per-record size further than the 1 GiB format ceiling (for example the 16 MiB
/// default) is the caller's responsibility.
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
    // Exact-match: a version-1 reader cannot parse a future layout, so it rejects
    // any other version loudly rather than guessing. Intentional; do not relax to
    // `>` without a versioned layout.
    let version = input[off::VERSION];
    if version != FORMAT_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let stored_header_crc = read_u32(input, off::HEADER_CRC);
    if crc32c::crc32c(&input[RECORD_HEADER_CRC_RANGE]) != stored_header_crc {
        return Err(DecodeError::BadHeaderCrc);
    }

    // The flags byte is inside the CRC-protected header range, so by here it is trusted:
    // HAS_XXH3 sizes the optional 8-byte checksum field that precedes the trailer.
    let flags = RecordFlags::from_bits(input[off::FLAGS]);
    let xxh3_field: usize = if flags.contains(RecordFlags::HAS_XXH3) {
        RECORD_XXH3_LEN
    } else {
        0
    };

    let key_len_u32 = read_u32(input, off::KEY_LEN);
    let hdr_len_u32 = read_u32(input, off::HDR_LEN);
    let payload_len_u32 = read_u32(input, off::PAYLOAD_LEN);
    // Sum the three attacker-controlled u32 lengths in u64 so the total cannot
    // overflow usize on a 32-bit target before it is bounded by the ceiling. The
    // optional xxh3 field is counted in `total_len`, so include it here too. The
    // `usize as u64` widening of the small fixed field sizes never truncates.
    let total64 = u64::from(key_len_u32)
        + u64::from(hdr_len_u32)
        + u64::from(payload_len_u32)
        + RECORD_HEADER_LEN as u64
        + xxh3_field as u64
        + RECORD_TRAILER_LEN as u64;
    if total64 > u64::from(MAX_RECORD_BYTES_CEILING) {
        return Err(DecodeError::TooLarge);
    }
    // total64 is now <= 1 GiB, so it and every length fit usize on all targets.
    let total = usize::try_from(total64).map_err(|_| DecodeError::TooLarge)?;
    if input.len() < total {
        return Err(DecodeError::Truncated);
    }
    let key_len = usize::try_from(key_len_u32).map_err(|_| DecodeError::TooLarge)?;
    let hdr_len = usize::try_from(hdr_len_u32).map_err(|_| DecodeError::TooLarge)?;
    let body_len = total - RECORD_HEADER_LEN - RECORD_TRAILER_LEN - xxh3_field;

    // HAS_KEY is a derived, frozen bit: it must agree with the key length. A frame
    // where they disagree was written by a buggy or hostile writer.
    if flags.contains(RecordFlags::HAS_KEY) != (key_len != 0) {
        return Err(DecodeError::BadLength);
    }
    // HAS_XXH3 is likewise derived: it must agree with the stored body reaching the
    // threshold. A mismatch is a malformed frame, not a recoverable corruption.
    if flags.contains(RecordFlags::HAS_XXH3) != (body_len >= XXH3_PAYLOAD_THRESHOLD as usize) {
        return Err(DecodeError::BadLength);
    }

    let body = &input[RECORD_HEADER_LEN..RECORD_HEADER_LEN + body_len];
    let xxh3_bytes =
        &input[RECORD_HEADER_LEN + body_len..RECORD_HEADER_LEN + body_len + xxh3_field];
    let trailer = &input[total - RECORD_TRAILER_LEN..total];
    let stored_body_crc = read_u32(trailer, 0);
    if u64::from(read_u32(trailer, 4)) != total64 {
        return Err(DecodeError::BadLength);
    }
    // CRC32C is the resync-gating checksum: verify it first. Only a body that passes
    // CRC32C is then checked against the independent xxh3-64, so a corruption the CRC
    // catches is always reported as BadBodyCrc, never BadXxh3.
    if crc32c::crc32c(body) != stored_body_crc {
        return Err(DecodeError::BadBodyCrc);
    }
    if flags.contains(RecordFlags::HAS_XXH3) {
        let stored_xxh3 = read_u64(xxh3_bytes, 0);
        if xxh3_64(body) != stored_xxh3 {
            return Err(DecodeError::BadXxh3);
        }
    }

    let view = RecordView {
        seq: Seq::new(read_u64(input, off::SEQ)),
        timestamp_ms: read_u64(input, off::TIMESTAMP),
        flags,
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

    // #830: the off-actor incremental body checksums must equal the one-shot checksums the actor path
    // computes over the contiguous stored body, at and around the xxh3 threshold and with empty
    // components. If this diverges, `encode_precomputed` would store an unreadable record.
    #[test]
    fn precomputed_body_checksums_match_one_shot() {
        let cases: &[(&[u8], &[u8], &[u8])] = &[
            (b"", b"", b""),
            (b"k", b"", b"payload"),
            (b"", b"headers", b""),
            (b"key", b"headers", b"payload"),
        ];
        for &(key, headers, payload) in cases {
            let mut body = Vec::new();
            body.extend_from_slice(key);
            body.extend_from_slice(headers);
            body.extend_from_slice(payload);
            let got = BodyChecksums::compute(key, headers, payload);
            assert_eq!(got.body_crc, crc32c::crc32c(&body), "crc {key:?}");
            assert_eq!(got.xxh3, None, "sub-threshold has no xxh3 {key:?}");
        }
        // A body at the threshold: the incremental xxh3-64 must equal the one-shot over the concat.
        let big_key = vec![0x11u8; 100];
        let big_hdr = vec![0x22u8; 100];
        let big_pay = vec![0x33u8; XXH3_PAYLOAD_THRESHOLD as usize];
        let mut body = Vec::new();
        body.extend_from_slice(&big_key);
        body.extend_from_slice(&big_hdr);
        body.extend_from_slice(&big_pay);
        let got = BodyChecksums::compute(&big_key, &big_hdr, &big_pay);
        assert_eq!(got.body_crc, crc32c::crc32c(&body));
        assert_eq!(got.xxh3, Some(xxh3_64(&body)));
    }

    // #830: `encode_precomputed` with the correct off-actor checksums must produce a frame BYTE-FOR-BYTE
    // identical to `encode`, both below and at/above the xxh3 threshold, and both must decode cleanly.
    #[test]
    fn encode_precomputed_is_byte_identical_to_encode() {
        for payload_len in [0usize, 5, XXH3_PAYLOAD_THRESHOLD as usize] {
            let payload = vec![0xA5u8; payload_len];
            let rec = RecordView {
                seq: Seq::new(9),
                timestamp_ms: 42,
                flags: RecordFlags::EMPTY,
                key: b"key",
                headers: b"hdr",
                payload: &payload,
            };
            let mut baseline = Vec::new();
            let n0 = encode(&rec, &mut baseline).unwrap();
            let checks = BodyChecksums::compute(rec.key, rec.headers, rec.payload);
            let mut offloaded = Vec::new();
            let n1 = encode_precomputed(&rec, checks, &mut offloaded).unwrap();
            assert_eq!(n0, n1, "len at payload_len={payload_len}");
            assert_eq!(baseline, offloaded, "bytes at payload_len={payload_len}");
            decode(&offloaded).expect("offloaded frame decodes");
        }
    }

    // #830: `encode_precomputed` TRUSTS the caller's value — a deliberately wrong body_crc lands
    // verbatim in the trailer (release build), and the record then fails its own CRC on read, i.e. a
    // wrong offloaded checksum degrades to detected corruption, never a silent accept. Guarded off
    // debug builds because the caller-contract debug_assert would (correctly) fire there.
    #[test]
    #[cfg(not(debug_assertions))]
    fn encode_precomputed_wrong_crc_is_caught_as_corrupt_on_read() {
        let rec = RecordView {
            seq: Seq::new(1),
            timestamp_ms: 1,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"body",
        };
        let bad = BodyChecksums {
            body_crc: 0xDEAD_BEEF,
            xxh3: None,
        };
        let mut buf = Vec::new();
        encode_precomputed(&rec, bad, &mut buf).unwrap();
        assert_eq!(decode(&buf), Err(DecodeError::BadBodyCrc));
    }

    #[test]
    fn decoded_len_matches_decode_consumed() {
        // The streaming-recovery length helper must return exactly the byte count
        // `decode` consumes for a valid frame, and reject the same bad headers `decode`
        // does, so a header it accepts is one `decode` can finish (#156).
        let buf = sample();
        let (_, consumed) = decode(&buf).unwrap();
        assert_eq!(decoded_len(&buf).unwrap(), consumed);
        // Only the header bytes are needed to learn the length.
        assert_eq!(decoded_len(&buf[..RECORD_HEADER_LEN]).unwrap(), consumed);

        // A header shorter than RECORD_HEADER_LEN is Truncated, not a wrong length.
        assert!(matches!(
            decoded_len(&buf[..RECORD_HEADER_LEN - 1]),
            Err(DecodeError::Truncated)
        ));
        // A flipped header byte inside the CRC-covered region (the seq, not the magic or
        // version) fails the header CRC in the helper exactly as in decode.
        let mut bad = buf.clone();
        bad[10] ^= 0xff;
        assert!(matches!(decoded_len(&bad), Err(DecodeError::BadHeaderCrc)));
        assert!(decode(&bad).is_err());
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

    #[test]
    fn sub_threshold_has_no_xxh3_field_or_flag() {
        // A stored body one byte below the threshold keeps the exact pre-xxh3 layout:
        // no HAS_XXH3 flag, and the frame is header + body + 8-byte trailer only.
        let payload = vec![0xABu8; XXH3_PAYLOAD_THRESHOLD as usize - 1];
        let rec = RecordView {
            seq: Seq::new(3),
            timestamp_ms: 9,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload,
        };
        let mut buf = Vec::new();
        let n = encode(&rec, &mut buf).unwrap();
        assert_eq!(n, RECORD_HEADER_LEN + payload.len() + RECORD_TRAILER_LEN);
        assert_eq!(buf.len(), n);
        let (got, consumed) = decode(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert!(!got.flags.contains(RecordFlags::HAS_XXH3));
        assert_eq!(got.payload, &payload[..]);
        // decoded_len agrees with decode for the no-flag path.
        assert_eq!(decoded_len(&buf).unwrap(), consumed);
    }

    #[test]
    fn at_threshold_emits_xxh3_field_and_verifies() {
        // A stored body exactly at the threshold sets the flag and adds the 8-byte field
        // before the unchanged 8-byte trailer; decode verifies both checksums.
        let payload = vec![0x5Au8; XXH3_PAYLOAD_THRESHOLD as usize];
        let rec = RecordView {
            seq: Seq::new(11),
            timestamp_ms: 22,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload,
        };
        let mut buf = Vec::new();
        let n = encode(&rec, &mut buf).unwrap();
        // header + body + xxh3(8) + trailer(8).
        assert_eq!(
            n,
            RECORD_HEADER_LEN + payload.len() + RECORD_XXH3_LEN + RECORD_TRAILER_LEN
        );
        let (got, consumed) = decode(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert!(got.flags.contains(RecordFlags::HAS_XXH3));
        assert_eq!(got.payload, &payload[..]);
        // The streaming-length helper must agree on the larger frame too.
        assert_eq!(decoded_len(&buf[..RECORD_HEADER_LEN]).unwrap(), consumed);
    }

    #[test]
    fn over_threshold_body_corruption_is_caught() {
        // Flip a body byte of an over-threshold record. CRC32C is verified first, so a
        // body flip is reported as BadBodyCrc (CRC32C stays the resync-gating checksum).
        let payload = vec![0x11u8; XXH3_PAYLOAD_THRESHOLD as usize + 64];
        let rec = RecordView {
            seq: Seq::new(1),
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload,
        };
        let mut buf = Vec::new();
        encode(&rec, &mut buf).unwrap();
        buf[RECORD_HEADER_LEN + 5] ^= 0x01;
        assert_eq!(decode(&buf), Err(DecodeError::BadBodyCrc));
    }

    #[test]
    fn over_threshold_xxh3_field_corruption_is_caught() {
        // Flip a byte inside the xxh3 field itself. The body still passes CRC32C, so the
        // failure surfaces as the distinct BadXxh3 error.
        let payload = vec![0x22u8; XXH3_PAYLOAD_THRESHOLD as usize];
        let rec = RecordView {
            seq: Seq::new(2),
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload,
        };
        let mut buf = Vec::new();
        encode(&rec, &mut buf).unwrap();
        // The xxh3 field sits immediately before the 8-byte trailer.
        let xxh3_at = buf.len() - RECORD_TRAILER_LEN - RECORD_XXH3_LEN;
        buf[xxh3_at] ^= 0xff;
        assert_eq!(decode(&buf), Err(DecodeError::BadXxh3));
    }

    #[test]
    fn xxh3_field_byte_flip_via_proptest_style_full_sweep() {
        // Flipping any single byte of the xxh3 field of an over-threshold record is caught
        // as BadXxh3 (the body CRC and total_len are untouched).
        let payload = vec![0x33u8; XXH3_PAYLOAD_THRESHOLD as usize];
        let rec = RecordView {
            seq: Seq::new(4),
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload,
        };
        let mut base = Vec::new();
        encode(&rec, &mut base).unwrap();
        let xxh3_at = base.len() - RECORD_TRAILER_LEN - RECORD_XXH3_LEN;
        for i in 0..RECORD_XXH3_LEN {
            let mut buf = base.clone();
            buf[xxh3_at + i] ^= 0x01;
            assert_eq!(decode(&buf), Err(DecodeError::BadXxh3), "byte {i}");
        }
    }

    /// Builds a 36-byte header with the given fields and a valid header CRC, so a
    /// test can craft frames that pass the header-CRC check.
    fn build_header(key_len: u32, hdr_len: u32, payload_len: u32, flags: u8) -> Vec<u8> {
        let mut h = vec![0u8; RECORD_HEADER_LEN];
        h[off::MAGIC..off::MAGIC + 2].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
        h[off::VERSION] = FORMAT_VERSION;
        h[off::FLAGS] = flags;
        h[off::KEY_LEN..off::KEY_LEN + 4].copy_from_slice(&key_len.to_le_bytes());
        h[off::HDR_LEN..off::HDR_LEN + 4].copy_from_slice(&hdr_len.to_le_bytes());
        h[off::PAYLOAD_LEN..off::PAYLOAD_LEN + 4].copy_from_slice(&payload_len.to_le_bytes());
        let crc = crc32c::crc32c(&h[RECORD_HEADER_CRC_RANGE]);
        h[off::HEADER_CRC..off::HEADER_CRC + 4].copy_from_slice(&crc.to_le_bytes());
        h
    }

    #[test]
    fn crafted_huge_lengths_are_rejected_not_panicked() {
        // key_len = hdr_len = u32::MAX with a valid header CRC must be TooLarge, never
        // a slice-out-of-bounds panic (regression for the 32-bit usize overflow).
        let h = build_header(u32::MAX, u32::MAX, 0, 0);
        assert_eq!(decode(&h), Err(DecodeError::TooLarge));
    }

    #[test]
    fn ceiling_boundary() {
        // 36 = RECORD_HEADER_LEN and 8 = RECORD_TRAILER_LEN (pinned by format::tests).
        let body_at = MAX_RECORD_BYTES_CEILING - 36 - 8;
        // A declared total of exactly the ceiling is not TooLarge; it is Truncated
        // here because we do not supply a 1 GiB buffer. One byte over is TooLarge.
        assert_eq!(
            decode(&build_header(body_at, 0, 0, 0)),
            Err(DecodeError::Truncated)
        );
        assert_eq!(
            decode(&build_header(body_at + 1, 0, 0, 0)),
            Err(DecodeError::TooLarge)
        );
    }

    #[test]
    fn has_key_inconsistency_is_rejected() {
        // key_len = 0 but HAS_KEY set, with valid header and body CRCs: malformed.
        let mut frame = build_header(0, 0, 1, RecordFlags::HAS_KEY.bits());
        frame.extend_from_slice(b"x");
        frame.extend_from_slice(&crc32c::crc32c(b"x").to_le_bytes());
        frame.extend_from_slice(&(36u32 + 1 + 8).to_le_bytes());
        assert_eq!(decode(&frame), Err(DecodeError::BadLength));
    }

    #[test]
    fn all_empty_record_roundtrips() {
        let rec = RecordView {
            seq: Seq::new(0),
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"",
        };
        let mut buf = Vec::new();
        let n = encode(&rec, &mut buf).unwrap();
        assert_eq!(n, RECORD_HEADER_LEN + RECORD_TRAILER_LEN);
        let (got, consumed) = decode(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert!(got.key.is_empty() && got.headers.is_empty() && got.payload.is_empty());
    }

    #[test]
    fn two_frames_decode_sequentially() {
        let r1 = RecordView {
            seq: Seq::new(1),
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"a",
            headers: b"",
            payload: b"one",
        };
        let r2 = RecordView {
            seq: Seq::new(2),
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"hh",
            payload: b"two!",
        };
        let mut buf = Vec::new();
        encode(&r1, &mut buf).unwrap();
        let first_len = buf.len();
        encode(&r2, &mut buf).unwrap();
        let (g1, c1) = decode(&buf).unwrap();
        assert_eq!(c1, first_len);
        assert_eq!(g1.payload, b"one");
        let (g2, c2) = decode(&buf[c1..]).unwrap();
        assert_eq!(c1 + c2, buf.len());
        assert_eq!(g2.seq, Seq::new(2));
        assert_eq!(g2.payload, b"two!");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // A payload length that straddles the xxh3 threshold: from a few bytes below it to a
    // few bytes above, so generated records land on both sides of the flag boundary.
    fn straddling_len() -> impl Strategy<Value = usize> {
        let lo = XXH3_PAYLOAD_THRESHOLD as usize - 8;
        let hi = XXH3_PAYLOAD_THRESHOLD as usize + 8;
        lo..=hi
    }

    proptest! {
        #[test]
        fn roundtrip(
            seq in any::<u64>(),
            ts in any::<u64>(),
            extra_flag in any::<bool>(),
            unknown_bit in any::<bool>(),
            key in proptest::collection::vec(any::<u8>(), 0..300),
            headers in proptest::collection::vec(any::<u8>(), 0..300),
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            // Only COMPRESSED is a caller-controlled bit here; HAS_KEY is derived.
            let mut flags = if extra_flag { RecordFlags::COMPRESSED } else { RecordFlags::EMPTY };
            if unknown_bit { flags = RecordFlags::from_bits(flags.bits() | 0b0100_0000); }
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
            prop_assert_eq!(got.flags.unknown_bits().bits(), if unknown_bit { 0b0100_0000 } else { 0 });
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
                Ok((got, consumed)) => {
                    prop_assert_eq!(consumed, buf.len());
                    prop_assert!(got.payload != &payload[..],
                        "a corrupted frame decoded to the original payload");
                }
            }
        }

        #[test]
        fn roundtrip_straddling_threshold(
            seq in any::<u64>(),
            ts in any::<u64>(),
            len in straddling_len(),
            byte in any::<u8>(),
        ) {
            // Records whose stored body straddles the threshold must round-trip, and the
            // HAS_XXH3 flag must agree exactly with body length >= threshold.
            let payload = vec![byte; len];
            let rec = RecordView {
                seq: Seq::new(seq), timestamp_ms: ts, flags: RecordFlags::EMPTY,
                key: b"", headers: b"", payload: &payload,
            };
            let mut buf = Vec::new();
            let n = encode(&rec, &mut buf).unwrap();
            prop_assert_eq!(n, buf.len());
            let want_xxh3 = len >= XXH3_PAYLOAD_THRESHOLD as usize;
            let (got, consumed) = decode(&buf).unwrap();
            prop_assert_eq!(consumed, buf.len());
            prop_assert_eq!(got.flags.contains(RecordFlags::HAS_XXH3), want_xxh3);
            prop_assert_eq!(got.payload, &payload[..]);
            prop_assert_eq!(decoded_len(&buf[..RECORD_HEADER_LEN]).unwrap(), consumed);
        }

        #[test]
        fn arbitrary_bytes_near_threshold_never_panic(
            data in proptest::collection::vec(any::<u8>(), 0..(XXH3_PAYLOAD_THRESHOLD as usize + 64)),
        ) {
            // The decoder must never panic on untrusted input, including buffers sized
            // around the xxh3 threshold; it returns a typed error or a valid view.
            let _ = decode(&data);
            let _ = decoded_len(&data);
        }
    }
}
