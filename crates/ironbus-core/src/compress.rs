// SPDX-License-Identifier: MIT OR Apache-2.0
//! The per-record compression runtime: a self-describing codec descriptor over the
//! record payload, the raw-store / never-expand write guard, and a decompression path
//! hardened against a corrupt or hostile compressed unit (issues #12, #75, #76).
//!
//! This module sits ABOVE [`crate::codec`] and never touches its frozen byte layout. A
//! record frame is still a 36-byte header, an opaque body, and an 8-byte trailer; the
//! `body_crc` (and the optional xxh3-64) still cover the STORED bytes exactly as before.
//! Compression only changes what those stored payload bytes ARE:
//!
//! - An UNCOMPRESSED record is byte-for-byte UNCHANGED. The compressor stores the raw
//!   payload, leaves the [`crate::types::RecordFlags::COMPRESSED`] bit CLEAR, and writes
//!   no descriptor. So every record written before this module existed, and every frozen
//!   conformance vector, decodes identically: a v1 reader needs this module only when the
//!   `COMPRESSED` bit is set, and that bit was never set on a v1 frame (see
//!   `docs/DICTIONARY_LIFECYCLE.md` §8).
//! - A COMPRESSED record sets the `COMPRESSED` bit and makes the payload a self-describing
//!   compressed object: a fixed [`DESCRIPTOR_LEN`]-byte descriptor (the codec id, the
//!   `dict_id`, and the `uncompressed_len`) followed by the codec stream. The descriptor
//!   lives INSIDE the payload, inside the checksum-covered body, so it consumes no new
//!   header bytes and shifts no existing field. `FORMAT_VERSION` stays 1 and the
//!   format-registry digest (`scripts/check-format-registry.sh`) is untouched, because no
//!   `pub const` layout declaration in `format.rs` changes.
//!
//! ## Ordering: CRC is verified BEFORE anything is decompressed
//!
//! The compressor produces the payload bytes that [`crate::codec::encode`] then frames and
//! checksums; the decompressor runs only on a payload that [`crate::codec::decode`] already
//! returned, which means the `body_crc` (and xxh3-64, when present) ALREADY passed. So a
//! caller's order is always: `decode` (verifies the CRC over the stored bytes) then
//! [`decompress_payload`] (interprets those verified bytes). Unverified bytes are never
//! decompressed.
//!
//! ## Decoder resilience (#76)
//!
//! The decompressor treats the compressed unit as fully untrusted even after the CRC
//! passes (the CRC proves the bytes are what was written, not that the writer was honest):
//!
//! - A per-unit DECOMPRESSED-size CAP ([`DEFAULT_MAX_DECOMPRESSED_BYTES`], 8 MiB by
//!   default) is checked against the descriptor's `uncompressed_len` BEFORE a single byte
//!   is allocated, so a decompression bomb that claims a huge output cannot drive an
//!   unbounded allocation.
//! - The output buffer is sized to EXACTLY `uncompressed_len` and lz4 decompresses INTO
//!   that bounded buffer, so a stream that tries to write past the claimed length is a
//!   typed error, never an over-allocation.
//! - A corrupt lz4 stream returns a typed [`DecompressError`] and NEVER panics.
//! - An UNKNOWN codec id (a future `zstd` on a build without it, or garbage) or an
//!   unresolved `dict_id` is classified as POISON ([`DecompressError::PoisonUnknownCodec`]
//!   / [`DecompressError::PoisonUnresolvedDict`]), the bounded-and-reported loss class that
//!   the recovery path routes to the #8 quarantine, never a crash (see
//!   `docs/compat/versions.md`).

use crate::types::RecordFlags;

/// The compression codec carried in a compressed record's descriptor.
///
/// The on-disk id byte is frozen per `docs/compat/versions.md`: `none` = 0 is the
/// no-compression sentinel and `lz4` = 1 is the pure-Rust default codec (ADR-0003). The
/// id space is APPEND-ONLY; a reader that meets an id it does not implement classifies the
/// record as POISON (a reported loss), it never guesses or crashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Codec {
    /// No compression: the stored payload is the raw payload. Frozen id `0`.
    None,
    /// LZ4 block compression via the pure-Rust `lz4_flex` codec (ADR-0003 default). Frozen
    /// id `1`.
    Lz4,
}

impl Codec {
    /// The frozen on-disk id byte for this codec.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Codec::None => CODEC_ID_NONE,
            Codec::Lz4 => CODEC_ID_LZ4,
        }
    }

    /// The codec for a frozen on-disk id byte, or `None` for an id this build does not
    /// implement (an UNKNOWN codec: a future `zstd` = 2, or garbage). An unknown id is
    /// POISON on the decode path, not an error this constructor decides.
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Codec> {
        match id {
            CODEC_ID_NONE => Some(Codec::None),
            CODEC_ID_LZ4 => Some(Codec::Lz4),
            _ => None,
        }
    }
}

/// Frozen codec id: no compression (the stored payload is raw).
pub const CODEC_ID_NONE: u8 = 0;
/// Frozen codec id: LZ4 block compression (`lz4_flex`, the ADR-0003 default).
pub const CODEC_ID_LZ4: u8 = 1;
/// Reserved codec id for the opt-in `zstd` codec (ADR-0003). NOT implemented on the
/// default build: a record carrying this id on a build without the `zstd` feature is
/// POISON, never a crash. Reserved here so the id space allocation is explicit and the
/// POISON-on-unknown test can name the exact future id it must reject.
pub const CODEC_ID_ZSTD_RESERVED: u8 = 2;

/// The no-dictionary sentinel `dict_id`. A `dict_id` of `0` means "decode without a
/// dictionary"; the trainer never emits it (see `docs/DICTIONARY_LIFECYCLE.md` §8).
pub const DICT_ID_NONE: u32 = 0;

/// The fixed length of a compressed record's descriptor: `codec_id (u8)` then
/// `dict_id (u32 LE)` then `uncompressed_len (u32 LE)`.
pub const DESCRIPTOR_LEN: usize = 1 + 4 + 4;

/// The default per-unit DECOMPRESSED-size cap: 8 MiB.
///
/// Derived from the `DEFAULT_MAX_RECORD_BYTES` (16 MiB) record bound: a single record's
/// decompressed payload is held bounded well under the max record so a decompression bomb
/// cannot allocate unbounded memory. The cap is checked against the descriptor's claimed
/// `uncompressed_len` BEFORE any allocation, then enforced again by decompressing into a
/// buffer sized to exactly that length.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: u32 = 8 * 1024 * 1024;

/// The default raw-store threshold: a payload smaller than this is stored RAW (codec
/// `none`), never compressed.
///
/// Below this size the descriptor overhead and the near-zero ratio on a tiny buffer make
/// compression a net loss, so the compressor does not even try. A record this small stays
/// byte-for-byte the uncompressed layout.
pub const DEFAULT_RAW_STORE_THRESHOLD: usize = 64;

/// An error returned by [`compress_payload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressError {
    /// The raw payload is larger than a `u32` can describe, so its `uncompressed_len`
    /// cannot be carried in the descriptor.
    PayloadTooLarge,
}

/// An error returned by [`decompress_payload`].
///
/// The POISON variants are the bounded-and-reported loss class (`docs/compat/versions.md`):
/// the frame is intact and its CRC passed, but the record names a decode input this reader
/// does not have. Recovery routes them to the #8 quarantine (reported loss, advance), never
/// a crash. The malformed variants mean the descriptor or stream is internally inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecompressError {
    /// The stored payload is shorter than the fixed [`DESCRIPTOR_LEN`]-byte descriptor.
    TruncatedDescriptor,
    /// POISON: the descriptor names a codec id this build does not implement (a future
    /// `zstd`, or garbage). Routed to the #8 quarantine as a reported loss, not a crash.
    PoisonUnknownCodec(u8),
    /// POISON: the descriptor references a non-zero `dict_id` the reader could resolve from
    /// neither the on-disk sidecar nor the embedded set. Routed to the #8 quarantine and
    /// surfaced as `ReasonCode::UnresolvedDictId` (see `docs/DICTIONARY_LIFECYCLE.md` §5).
    PoisonUnresolvedDict(u32),
    /// The descriptor's claimed `uncompressed_len` exceeds the per-unit decompressed cap, so
    /// the unit is rejected BEFORE any allocation (a decompression-bomb guard, #76).
    DecompressedTooLarge {
        /// The claimed uncompressed length from the descriptor.
        claimed: u32,
        /// The cap the claim exceeded.
        cap: u32,
    },
    /// The compressed stream is corrupt: it did not decode to exactly the claimed
    /// `uncompressed_len` bytes, or the lz4 block was internally invalid. A typed error, never
    /// a panic.
    CorruptStream,
    /// A `none`-codec descriptor's stored length did not match its claimed `uncompressed_len`.
    BadRawLength,
}

impl core::fmt::Display for CompressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CompressError::PayloadTooLarge => {
                write!(f, "payload is too large to compress (length exceeds u32)")
            }
        }
    }
}
impl std::error::Error for CompressError {}

impl core::fmt::Display for DecompressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecompressError::TruncatedDescriptor => {
                write!(f, "compressed payload is shorter than the codec descriptor")
            }
            DecompressError::PoisonUnknownCodec(id) => {
                write!(f, "unknown compression codec id {id} (poison)")
            }
            DecompressError::PoisonUnresolvedDict(dict) => {
                write!(f, "unresolved compression dictionary id {dict} (poison)")
            }
            DecompressError::DecompressedTooLarge { claimed, cap } => write!(
                f,
                "claimed uncompressed length {claimed} exceeds the decompressed cap {cap}"
            ),
            DecompressError::CorruptStream => {
                write!(f, "compressed stream is corrupt")
            }
            DecompressError::BadRawLength => {
                write!(f, "stored raw length disagrees with the descriptor")
            }
        }
    }
}
impl std::error::Error for DecompressError {}

impl DecompressError {
    /// `true` if this error is the bounded-and-reported POISON class (intact framing, valid
    /// CRC, but an absent decode input), as opposed to a malformed descriptor or a corrupt
    /// stream. The recovery path routes a POISON to the #8 quarantine with a reported-loss
    /// reason; a malformed/corrupt descriptor is a body-corruption skip.
    #[must_use]
    pub const fn is_poison(self) -> bool {
        matches!(
            self,
            DecompressError::PoisonUnknownCodec(_) | DecompressError::PoisonUnresolvedDict(_)
        )
    }
}

/// Knobs that govern how [`compress_payload`] decides to compress a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressConfig {
    /// The codec to compress NEW writes with. [`Codec::None`] disables compression (every
    /// record is stored raw, byte-for-byte the uncompressed layout).
    pub codec: Codec,
    /// A payload strictly smaller than this is stored RAW, never compressed (the descriptor
    /// overhead and near-zero ratio on a tiny buffer make compression a net loss).
    pub raw_store_threshold: usize,
    /// The `dict_id` to stamp on a compressed record (`0` = no dictionary). On the pure-Rust
    /// `lz4` path this is always `0`; a trained dictionary is a `zstd` feature
    /// (`docs/DICTIONARY_LIFECYCLE.md`).
    pub dict_id: u32,
}

impl Default for CompressConfig {
    fn default() -> CompressConfig {
        CompressConfig {
            codec: Codec::Lz4,
            raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD,
            dict_id: DICT_ID_NONE,
        }
    }
}

impl CompressConfig {
    /// A config that disables compression entirely: every record is stored raw.
    #[must_use]
    pub const fn disabled() -> CompressConfig {
        CompressConfig {
            codec: Codec::None,
            raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD,
            dict_id: DICT_ID_NONE,
        }
    }
}

/// The outcome of compressing one payload: the bytes to store and the record flag bit to
/// stamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compressed {
    /// The bytes to store as the record payload. When [`Compressed::compressed`] is true
    /// these are the descriptor + codec stream; when false they are the raw payload,
    /// byte-for-byte.
    pub stored: Vec<u8>,
    /// Whether the [`crate::types::RecordFlags::COMPRESSED`] bit must be set on the record.
    /// False means the payload was stored raw and the record is byte-identical to the
    /// uncompressed layout.
    pub compressed: bool,
}

impl Compressed {
    /// The record-flag delta to apply: [`RecordFlags::COMPRESSED`] when the payload was
    /// compressed, else [`RecordFlags::EMPTY`]. The caller `OR`s this onto its base flags.
    #[must_use]
    pub const fn flag(&self) -> RecordFlags {
        if self.compressed {
            RecordFlags::COMPRESSED
        } else {
            RecordFlags::EMPTY
        }
    }
}

/// Compresses `payload` per `config`, returning the bytes to store and whether the
/// `COMPRESSED` flag must be set.
///
/// The two write guards make compression always safe to apply to any payload:
///
/// - **Raw-store threshold.** A payload smaller than `config.raw_store_threshold`, or any
///   payload when `config.codec` is [`Codec::None`], is stored RAW (no descriptor, flag
///   clear), so the record is byte-for-byte the uncompressed layout.
/// - **Never-expand guard.** If the descriptor + compressed stream is NOT strictly smaller
///   than the raw payload, the payload is stored RAW instead, so compression can never
///   make a record larger.
///
/// A `compressed == false` result is therefore indistinguishable on disk from a record
/// written by a build that has no compression at all, which is what keeps every existing
/// record and conformance vector byte-identical.
///
/// # Errors
/// Returns [`CompressError::PayloadTooLarge`] if the payload length exceeds `u32::MAX`, so
/// its `uncompressed_len` cannot be carried in the descriptor.
pub fn compress_payload(
    payload: &[u8],
    config: &CompressConfig,
) -> Result<Compressed, CompressError> {
    let uncompressed_len =
        u32::try_from(payload.len()).map_err(|_| CompressError::PayloadTooLarge)?;

    // Store raw when compression is off or the payload is below the raw-store threshold.
    if config.codec == Codec::None || payload.len() < config.raw_store_threshold {
        return Ok(Compressed {
            stored: payload.to_vec(),
            compressed: false,
        });
    }

    let stream = match config.codec {
        // Unreachable: handled by the early-return above. Kept exhaustive without a panic.
        Codec::None => return Ok(store_raw(payload)),
        Codec::Lz4 => lz4_flex::block::compress(payload),
    };

    let mut descriptor = Vec::with_capacity(DESCRIPTOR_LEN + stream.len());
    descriptor.push(config.codec.id());
    descriptor.extend_from_slice(&config.dict_id.to_le_bytes());
    descriptor.extend_from_slice(&uncompressed_len.to_le_bytes());
    descriptor.extend_from_slice(&stream);

    // Never-expand guard: only keep the compressed form if it is STRICTLY smaller than the
    // raw payload (descriptor included). Otherwise store raw, so compression never expands.
    if descriptor.len() < payload.len() {
        Ok(Compressed {
            stored: descriptor,
            compressed: true,
        })
    } else {
        Ok(store_raw(payload))
    }
}

/// Stores a payload raw (no descriptor, flag clear).
fn store_raw(payload: &[u8]) -> Compressed {
    Compressed {
        stored: payload.to_vec(),
        compressed: false,
    }
}

/// Resolves a non-zero `dict_id` to its dictionary bytes, or signals it is unresolved.
///
/// This is the dictionary-lifecycle SEAM (#357, `docs/DICTIONARY_LIFECYCLE.md` §3-§4): a
/// real resolver looks up the on-disk `dicts/<dict_id>.zstd` sidecar first, then the
/// embedded active set, and validates the content hash. The IO-free core carries only the
/// seam; the sidecar IO and the embed live above it. `dict_id == 0` is never passed here
/// (it is the no-dictionary sentinel).
pub trait DictResolver {
    /// Returns the dictionary bytes for `dict_id`, or `None` if it cannot be resolved
    /// (absent sidecar and absent embedded copy), which makes the record POISON.
    fn resolve(&self, dict_id: u32) -> Option<&[u8]>;
}

/// A resolver that holds no dictionaries: every non-zero `dict_id` is unresolved.
///
/// This is the pure-Rust default-build resolver. On the `lz4` path a record is always
/// written with `dict_id == 0` (trained dictionaries are a `zstd` feature), so a non-zero
/// `dict_id` only ever arrives from a `zstd`-feature writer; on a build without it, that id
/// is correctly unresolved and the record is POISON, never a crash.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDictionaries;

impl DictResolver for NoDictionaries {
    fn resolve(&self, _dict_id: u32) -> Option<&[u8]> {
        None
    }
}

/// Reads the fixed descriptor at the front of a compressed payload WITHOUT decompressing,
/// so a fuzz target or an inspector can examine the header without running the codec.
///
/// Returns the codec id byte, the `dict_id`, the claimed `uncompressed_len`, and the
/// remaining stream slice.
///
/// # Errors
/// Returns [`DecompressError::TruncatedDescriptor`] if the payload is shorter than
/// [`DESCRIPTOR_LEN`].
pub fn read_descriptor(stored: &[u8]) -> Result<(u8, u32, u32, &[u8]), DecompressError> {
    if stored.len() < DESCRIPTOR_LEN {
        return Err(DecompressError::TruncatedDescriptor);
    }
    let codec_id = stored[0];
    let dict_id = u32::from_le_bytes([stored[1], stored[2], stored[3], stored[4]]);
    let uncompressed_len = u32::from_le_bytes([stored[5], stored[6], stored[7], stored[8]]);
    Ok((
        codec_id,
        dict_id,
        uncompressed_len,
        &stored[DESCRIPTOR_LEN..],
    ))
}

/// Decompresses a record's STORED payload back to the original payload.
///
/// `flags` are the decoded record's flags (whether the `COMPRESSED` bit is set), `stored`
/// is the payload [`crate::codec::decode`] returned (its CRC already verified), `resolver`
/// resolves any referenced `dict_id`, and `max_decompressed` is the per-unit decompressed
/// cap.
///
/// When the `COMPRESSED` bit is CLEAR the stored bytes ARE the payload and are returned
/// unchanged (a copy), so an uncompressed record needs nothing from this path. When the bit
/// is SET the descriptor is parsed, the cap is enforced BEFORE allocation, and the codec
/// stream is decompressed into a buffer sized to exactly the claimed length.
///
/// # Errors
/// Returns a typed [`DecompressError`]: a POISON variant for an unknown codec or unresolved
/// `dict_id` (routed to the #8 quarantine), [`DecompressError::DecompressedTooLarge`] for an
/// over-cap claim (a bomb), or [`DecompressError::CorruptStream`] for an invalid stream. It
/// NEVER panics on any input.
pub fn decompress_payload<R: DictResolver>(
    flags: RecordFlags,
    stored: &[u8],
    resolver: &R,
    max_decompressed: u32,
) -> Result<Vec<u8>, DecompressError> {
    if !flags.contains(RecordFlags::COMPRESSED) {
        // An uncompressed record: the stored bytes are the payload, byte-for-byte.
        return Ok(stored.to_vec());
    }

    let (codec_id, dict_id, uncompressed_len, stream) = read_descriptor(stored)?;

    // POISON: a codec id this build does not implement. Reported loss, never a crash.
    let codec = Codec::from_id(codec_id).ok_or(DecompressError::PoisonUnknownCodec(codec_id))?;

    // POISON: a non-zero dict_id the resolver cannot resolve (absent sidecar + embedded).
    if dict_id != DICT_ID_NONE && resolver.resolve(dict_id).is_none() {
        return Err(DecompressError::PoisonUnresolvedDict(dict_id));
    }

    // Decompression-bomb guard: reject an over-cap claim BEFORE allocating anything.
    if uncompressed_len > max_decompressed {
        return Err(DecompressError::DecompressedTooLarge {
            claimed: uncompressed_len,
            cap: max_decompressed,
        });
    }
    // The claim is now <= the cap (<= 8 MiB by default), so this length fits usize on every
    // target and the allocation it sizes is bounded.
    let out_len = uncompressed_len as usize;

    match codec {
        Codec::None => {
            // A `none`-codec descriptor stores the raw payload after the descriptor; the
            // stream length must equal the claimed length exactly.
            if stream.len() != out_len {
                return Err(DecompressError::BadRawLength);
            }
            Ok(stream.to_vec())
        }
        Codec::Lz4 => {
            // Allocate EXACTLY the claimed length and decompress into that bounded buffer, so
            // a stream that tries to write past the claim is a typed error, never an
            // over-allocation. A corrupt block returns a typed lz4 error here, never a panic.
            let mut out = vec![0u8; out_len];
            let written = lz4_flex::block::decompress_into(stream, &mut out)
                .map_err(|_| DecompressError::CorruptStream)?;
            if written != out_len {
                return Err(DecompressError::CorruptStream);
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lz4_config() -> CompressConfig {
        CompressConfig {
            codec: Codec::Lz4,
            raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD,
            dict_id: DICT_ID_NONE,
        }
    }

    /// A highly compressible payload, well over the raw-store threshold.
    fn compressible(len: usize) -> Vec<u8> {
        b"ironbus telemetry record sensor.telemetry.v1 "
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    #[test]
    fn codec_ids_are_frozen() {
        assert_eq!(Codec::None.id(), 0);
        assert_eq!(Codec::Lz4.id(), 1);
        assert_eq!(Codec::from_id(0), Some(Codec::None));
        assert_eq!(Codec::from_id(1), Some(Codec::Lz4));
        // The reserved zstd id and any garbage are UNKNOWN on this build.
        assert_eq!(Codec::from_id(CODEC_ID_ZSTD_RESERVED), None);
        assert_eq!(Codec::from_id(200), None);
        assert_eq!(DESCRIPTOR_LEN, 9);
    }

    #[test]
    fn compressed_record_round_trips() {
        let payload = compressible(4096);
        let out = compress_payload(&payload, &lz4_config()).unwrap();
        assert!(out.compressed, "a compressible 4 KiB payload compresses");
        assert!(
            out.stored.len() < payload.len(),
            "the stored form is smaller than the raw payload"
        );
        assert_eq!(out.flag(), RecordFlags::COMPRESSED);

        let back = decompress_payload(
            RecordFlags::COMPRESSED,
            &out.stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, payload, "decompress(compress(x)) == x");
    }

    #[test]
    fn below_threshold_stays_raw() {
        // A payload below the raw-store threshold is never compressed: stored raw, flag clear.
        let payload = compressible(DEFAULT_RAW_STORE_THRESHOLD - 1);
        let out = compress_payload(&payload, &lz4_config()).unwrap();
        assert!(!out.compressed, "sub-threshold payload stays raw");
        assert_eq!(out.stored, payload, "stored bytes are the raw payload");
        assert_eq!(out.flag(), RecordFlags::EMPTY);
    }

    /// A deterministic high-entropy byte stream (a SplitMix64-style mix), so the payload has
    /// no lz4-exploitable redundancy and the compressed form cannot beat the raw size.
    fn high_entropy(len: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        (0..len)
            .map(|_| {
                state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                ((z ^ (z >> 31)) & 0xFF) as u8
            })
            .collect()
    }

    #[test]
    fn incompressible_payload_stays_raw_never_expands() {
        // A high-entropy payload that lz4 cannot shrink below its raw size must be stored RAW,
        // so a record never grows. The never-expand guard falls back to raw storage.
        let payload = high_entropy(4096);
        let out = compress_payload(&payload, &lz4_config()).unwrap();
        assert!(!out.compressed, "an incompressible payload is stored raw");
        assert_eq!(out.stored, payload);
        assert_eq!(out.stored.len(), payload.len(), "never expands");
        // The round-trip still holds for the raw-stored outcome.
        let back = decompress_payload(
            out.flag(),
            &out.stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn disabled_codec_stores_raw() {
        let payload = compressible(4096);
        let out = compress_payload(&payload, &CompressConfig::disabled()).unwrap();
        assert!(!out.compressed);
        assert_eq!(out.stored, payload);
    }

    #[test]
    fn uncompressed_decompress_is_identity() {
        // With the COMPRESSED bit clear, decompress returns the stored bytes unchanged: an
        // uncompressed record needs nothing from the codec descriptor path.
        let payload = b"a small raw payload".to_vec();
        let back = decompress_payload(
            RecordFlags::EMPTY,
            &payload,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn unknown_codec_is_poison_not_a_crash() {
        // Hand-craft a descriptor with the reserved zstd id (a future codec this build lacks).
        let mut stored = Vec::new();
        stored.push(CODEC_ID_ZSTD_RESERVED);
        stored.extend_from_slice(&0u32.to_le_bytes()); // dict_id
        stored.extend_from_slice(&16u32.to_le_bytes()); // uncompressed_len
        stored.extend_from_slice(&[0xAB; 8]); // a stream we never reach
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DecompressError::PoisonUnknownCodec(CODEC_ID_ZSTD_RESERVED)
        );
        assert!(err.is_poison(), "unknown codec is the POISON class");
    }

    #[test]
    fn unresolved_dict_id_is_poison_not_a_crash() {
        // A valid lz4 stream but a non-zero dict_id the resolver does not hold.
        let payload = compressible(4096);
        let cfg = CompressConfig {
            codec: Codec::Lz4,
            raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD,
            dict_id: 0x1234_5678,
        };
        let out = compress_payload(&payload, &cfg).unwrap();
        assert!(out.compressed);
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &out.stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, DecompressError::PoisonUnresolvedDict(0x1234_5678));
        assert!(err.is_poison(), "unresolved dict id is the POISON class");
    }

    #[test]
    fn resolved_dict_id_is_not_poison() {
        // A resolver that holds the referenced dict_id clears the POISON gate (the descriptor
        // is then decoded; lz4 ignores the dict bytes since the stream was not dict-compressed,
        // but the gate behavior is what we pin here). Use dict_id resolution success only to
        // prove the POISON gate is keyed on resolution, not on the id being non-zero.
        struct OneDict;
        impl DictResolver for OneDict {
            fn resolve(&self, dict_id: u32) -> Option<&[u8]> {
                if dict_id == 0x1234_5678 {
                    Some(b"")
                } else {
                    None
                }
            }
        }
        let payload = compressible(4096);
        let cfg = CompressConfig {
            codec: Codec::Lz4,
            raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD,
            dict_id: 0x1234_5678,
        };
        let out = compress_payload(&payload, &cfg).unwrap();
        let back = decompress_payload(
            RecordFlags::COMPRESSED,
            &out.stored,
            &OneDict,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, payload, "a resolved dict_id decodes normally");
    }

    #[test]
    fn decompression_bomb_is_rejected_before_allocation() {
        // A descriptor that CLAIMS a huge uncompressed_len must be rejected by the cap before
        // any allocation, regardless of the (tiny) stream that follows.
        let mut stored = Vec::new();
        stored.push(CODEC_ID_LZ4);
        stored.extend_from_slice(&0u32.to_le_bytes()); // dict_id
        stored.extend_from_slice(&u32::MAX.to_le_bytes()); // claims ~4 GiB
        stored.extend_from_slice(&[0u8; 4]); // a trivial stream
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DecompressError::DecompressedTooLarge {
                claimed: u32::MAX,
                cap: DEFAULT_MAX_DECOMPRESSED_BYTES,
            }
        );
        assert!(
            !err.is_poison(),
            "an over-cap claim is a malformed-unit reject, not poison"
        );
    }

    #[test]
    fn corrupt_lz4_stream_is_a_typed_error_never_a_panic() {
        // A descriptor that claims a plausible length but whose stream is garbage decodes to a
        // typed CorruptStream, not a panic.
        let mut stored = Vec::new();
        stored.push(CODEC_ID_LZ4);
        stored.extend_from_slice(&0u32.to_le_bytes());
        stored.extend_from_slice(&64u32.to_le_bytes()); // claim 64 bytes
        stored.extend_from_slice(&[0xFF; 8]); // not a valid lz4 block for 64 bytes
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, DecompressError::CorruptStream);
    }

    #[test]
    fn a_stream_that_decodes_past_the_claimed_length_is_a_typed_error_never_a_panic() {
        // The claimed length and the stream are independently attacker-controlled (the body CRC
        // proves integrity, not honesty). A descriptor that claims a SMALL length but carries a
        // valid lz4 block decoding to a LARGER length must be a typed CorruptStream, never an
        // out-of-bounds panic on the claim-sized buffer. This is exactly the case the lz4_flex
        // `checked-decode` feature guards: without it, decompress_into indexes past the buffer.
        let real = vec![0x5Au8; 4096];
        let block = lz4_flex::block::compress(&real); // a valid lz4 block that decodes to 4096
        let mut stored = Vec::new();
        stored.push(CODEC_ID_LZ4);
        stored.extend_from_slice(&0u32.to_le_bytes()); // dict_id
        stored.extend_from_slice(&16u32.to_le_bytes()); // LIE: claim 16, well under the cap
        stored.extend_from_slice(&block);
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, DecompressError::CorruptStream);
    }

    #[test]
    fn truncated_descriptor_is_a_typed_error() {
        // A compressed-flagged payload shorter than the descriptor is a typed error.
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &[0u8; 3],
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, DecompressError::TruncatedDescriptor);
    }

    #[test]
    fn large_but_representable_payload_compresses() {
        // A 1 MiB payload (well within the u32 descriptor field) compresses cleanly and round
        // trips. The `PayloadTooLarge` guard fires only above u32::MAX, which is unrepresentable
        // in a test allocation; the `try_from` on `payload.len()` covers it structurally.
        let payload = compressible(1 << 20);
        let out = compress_payload(&payload, &lz4_config()).unwrap();
        assert!(out.compressed);
        let back = decompress_payload(
            out.flag(),
            &out.stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, payload);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Round-trip: decompress(compress(x)) == x for arbitrary payloads across the raw-store
        // boundary, with both raw-stored and compressed outcomes exercised.
        #[test]
        fn round_trip(payload in proptest::collection::vec(any::<u8>(), 0..8192)) {
            let cfg = CompressConfig::default();
            let out = compress_payload(&payload, &cfg).expect("in-cap payload compresses");
            // Never-expand: a compressed outcome is STRICTLY smaller than the raw payload; a
            // raw-stored outcome is byte-for-byte the payload. Either way the stored form is
            // never larger than the raw payload.
            if out.compressed {
                prop_assert!(out.stored.len() < payload.len(), "compressed form is strictly smaller");
            } else {
                prop_assert_eq!(&out.stored, &payload, "raw-stored form is byte-identical");
            }
            let flags = if out.compressed { RecordFlags::COMPRESSED } else { RecordFlags::EMPTY };
            let back = decompress_payload(flags, &out.stored, &NoDictionaries, DEFAULT_MAX_DECOMPRESSED_BYTES)
                .expect("round-trips");
            prop_assert_eq!(back, payload);
        }

        // The decompressor must NEVER panic on arbitrary compressed-flagged bytes: any input is
        // a typed error or a valid vec. This is the corrupt-stream fuzz leg in-process.
        #[test]
        fn arbitrary_compressed_bytes_never_panic(
            stored in proptest::collection::vec(any::<u8>(), 0..4096),
            cap in 0u32..(16 * 1024 * 1024),
        ) {
            let _ = decompress_payload(RecordFlags::COMPRESSED, &stored, &NoDictionaries, cap);
            let _ = read_descriptor(&stored);
        }

        // A bomb sweep: any claimed length over the cap is rejected before allocation, for any
        // cap and any short stream, with no allocation proportional to the claim.
        #[test]
        fn over_cap_claim_always_rejected(
            claim in any::<u32>(),
            cap in 0u32..(8 * 1024 * 1024),
            stream in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            prop_assume!(claim > cap);
            let mut stored = Vec::new();
            stored.push(CODEC_ID_LZ4);
            stored.extend_from_slice(&0u32.to_le_bytes());
            stored.extend_from_slice(&claim.to_le_bytes());
            stored.extend_from_slice(&stream);
            let err = decompress_payload(RecordFlags::COMPRESSED, &stored, &NoDictionaries, cap)
                .expect_err("over-cap claim is rejected");
            prop_assert_eq!(err, DecompressError::DecompressedTooLarge { claimed: claim, cap });
        }
    }
}
