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
//!   `COMPRESSED` bit is set, and that bit was never set on a v1 frame until #430 wired the
//!   write path (the broker now sets it on compressed stores under the default `lz4` codec;
//!   see `docs/DICTIONARY_LIFECYCLE.md` §8).
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
    /// Zstandard block compression via the OPT-IN, vendored-C `zstd` codec (ADR-0003, frozen
    /// id `2`). Present ONLY on a build with the `zstd` feature: on the DEFAULT pure-Rust
    /// build this variant does not exist, so [`Codec::from_id`] returns `None` for id `2` and
    /// a `zstd` record is correctly treated as an UNKNOWN-codec POISON (never a crash). The
    /// optional `dict_id` carried alongside it selects a trained dictionary
    /// (`docs/DICTIONARY_LIFECYCLE.md`).
    #[cfg(feature = "zstd")]
    Zstd,
}

impl Codec {
    /// The frozen on-disk id byte for this codec.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Codec::None => CODEC_ID_NONE,
            Codec::Lz4 => CODEC_ID_LZ4,
            #[cfg(feature = "zstd")]
            Codec::Zstd => CODEC_ID_ZSTD,
        }
    }

    /// The codec for a frozen on-disk id byte, or `None` for an id this build does not
    /// implement (an UNKNOWN codec). An unknown id is POISON on the decode path, not an error
    /// this constructor decides.
    ///
    /// Id `2` (`zstd`) resolves to [`Codec::Zstd`] ONLY on a build with the `zstd` feature; on
    /// the default pure-Rust build id `2` is UNKNOWN here, which is exactly what makes a `zstd`
    /// record poison rather than a crash on a default reader.
    #[must_use]
    pub const fn from_id(id: u8) -> Option<Codec> {
        match id {
            CODEC_ID_NONE => Some(Codec::None),
            CODEC_ID_LZ4 => Some(Codec::Lz4),
            #[cfg(feature = "zstd")]
            CODEC_ID_ZSTD => Some(Codec::Zstd),
            _ => None,
        }
    }
}

/// Frozen codec id: no compression (the stored payload is raw).
pub const CODEC_ID_NONE: u8 = 0;
/// Frozen codec id: LZ4 block compression (`lz4_flex`, the ADR-0003 default).
pub const CODEC_ID_LZ4: u8 = 1;
/// Frozen codec id for the OPT-IN `zstd` codec (ADR-0003). Implemented ONLY on a build with the
/// `zstd` feature; on the DEFAULT build a record carrying this id is UNKNOWN-codec POISON, never a
/// crash. The const is always defined (the id-space allocation is explicit and frozen regardless of
/// the build) so the POISON-on-unknown test can name the exact id a default build must reject.
pub const CODEC_ID_ZSTD: u8 = 2;
/// Deprecated alias for [`CODEC_ID_ZSTD`], kept so existing references to the pre-implementation
/// "reserved" name continue to resolve. New code should use [`CODEC_ID_ZSTD`].
pub const CODEC_ID_ZSTD_RESERVED: u8 = CODEC_ID_ZSTD;

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
    /// The configured codec is the OPT-IN `zstd` codec but its underlying C library returned an
    /// error while compressing this payload. A typed error, never a panic; the caller can fall
    /// back to a raw store or surface the failure. Only reachable on a `zstd`-feature build.
    #[cfg(feature = "zstd")]
    ZstdEncode,
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
            #[cfg(feature = "zstd")]
            CompressError::ZstdEncode => write!(f, "zstd compression failed"),
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

/// The default zstd compression level used when the OPT-IN `zstd` codec is selected. `3` is
/// zstd's own default: a balanced speed/ratio point appropriate for an edge node's compress
/// budget. Only consulted on a `zstd`-feature build.
#[cfg(feature = "zstd")]
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Knobs that govern how [`compress_payload`] decides to compress a record.
///
/// The optional dictionary bytes (`dict`) are a borrowed slice, so this carries a lifetime; the
/// IO-free core never owns the dictionary, it only borrows the bytes a higher layer resolved (the
/// sidecar/embedded set lives in storage/cli, `docs/DICTIONARY_LIFECYCLE.md` §3-§4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressConfig<'d> {
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
    /// The trained dictionary bytes to compress with, when `dict_id != 0` and the codec is
    /// `zstd`. `None` means no dictionary (the only case on the `lz4` path). The bytes are
    /// borrowed from whatever resolved them; the core does not own them.
    pub dict: Option<&'d [u8]>,
    /// The zstd compression level (consulted only by the `zstd` codec). Ignored by `lz4`/`none`.
    pub zstd_level: i32,
}

impl Default for CompressConfig<'_> {
    fn default() -> CompressConfig<'static> {
        CompressConfig {
            codec: Codec::Lz4,
            raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD,
            dict_id: DICT_ID_NONE,
            dict: None,
            #[cfg(feature = "zstd")]
            zstd_level: DEFAULT_ZSTD_LEVEL,
            #[cfg(not(feature = "zstd"))]
            zstd_level: 0,
        }
    }
}

impl CompressConfig<'_> {
    /// A config that disables compression entirely: every record is stored raw.
    #[must_use]
    pub const fn disabled() -> CompressConfig<'static> {
        CompressConfig {
            codec: Codec::None,
            raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD,
            dict_id: DICT_ID_NONE,
            dict: None,
            zstd_level: 0,
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
/// its `uncompressed_len` cannot be carried in the descriptor. On a `zstd`-feature build,
/// returns [`CompressError::ZstdEncode`] if the zstd C library fails to compress (a typed
/// error, never a panic).
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
        #[cfg(feature = "zstd")]
        Codec::Zstd => zstd_compress(payload, config)?,
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

/// Compresses `payload` with the OPT-IN `zstd` codec, optionally with the trained dictionary in
/// `config.dict`. Returns a typed [`CompressError::ZstdEncode`] on any zstd-library error, never a
/// panic. The FFI lives entirely inside the `zstd` crate, so this wrapper adds no `unsafe`.
#[cfg(feature = "zstd")]
fn zstd_compress(payload: &[u8], config: &CompressConfig) -> Result<Vec<u8>, CompressError> {
    match config.dict {
        // A trained-dictionary compress: prime the compressor with the dictionary bytes. An empty
        // dictionary is treated as no dictionary (the plain bulk-compress path), so a degenerate
        // dict never errors here.
        Some(dict) if !dict.is_empty() => {
            zstd::bulk::Compressor::with_dictionary(config.zstd_level, dict)
                .and_then(|mut c| c.compress(payload))
                .map_err(|_| CompressError::ZstdEncode)
        }
        _ => {
            zstd::bulk::compress(payload, config.zstd_level).map_err(|_| CompressError::ZstdEncode)
        }
    }
}

/// Decompresses a `zstd` stream into a buffer of EXACTLY `out_len` bytes, optionally with the
/// trained dictionary `dict`, returning [`DecompressError::CorruptStream`] on any zstd-library
/// error OR a length mismatch. The output is bounded to `out_len` (the cap-checked claimed
/// length): zstd's bulk decompressor will not write past the buffer it is handed, so a stream that
/// claims to decode larger fails as a typed error, never an over-allocation or a panic.
#[cfg(feature = "zstd")]
fn zstd_decompress(stream: &[u8], dict: &[u8], out_len: usize) -> Result<Vec<u8>, DecompressError> {
    let mut out = vec![0u8; out_len];
    let written = if dict.is_empty() {
        zstd::bulk::Decompressor::new().and_then(|mut d| d.decompress_to_buffer(stream, &mut out))
    } else {
        zstd::bulk::Decompressor::with_dictionary(dict)
            .and_then(|mut d| d.decompress_to_buffer(stream, &mut out))
    }
    .map_err(|_| DecompressError::CorruptStream)?;
    if written != out_len {
        return Err(DecompressError::CorruptStream);
    }
    Ok(out)
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

/// Validates the SHAPE of a compressed payload's descriptor WITHOUT decompressing (#438):
/// the produce-time gate for a wire PUB that carries the `COMPRESSED` bit.
///
/// The broker is store-and-forward, so a record it acks is decoded only by its CONSUMERS;
/// before this gate, nothing validated a producer-supplied descriptor at produce time, and
/// one undecodable record cost EVERY consumer group max-deliver visibility-timeout cycles
/// of typed decode failures before it dead-lettered (#438, post-#430). Each rule here is a
/// header-only check (a [`DESCRIPTOR_LEN`]-byte parse, NO decompression, so the produce hot
/// path pays no codec CPU) and rejects what the shipped read side
/// ([`decompress_payload`], for a codec the reader implements) can never decode, with ONE
/// deliberate, documented exception where the gate is STRICTER than the read side (the
/// empty-stream rule below):
///
/// - The payload must parse as a well-formed descriptor ([`read_descriptor`] succeeds):
///   shorter than [`DESCRIPTOR_LEN`] and no reader can even frame the header.
/// - The codec id must be one of the REGISTERED ids ([`CODEC_ID_NONE`], [`CODEC_ID_LZ4`],
///   [`CODEC_ID_ZSTD`]; the append-only registry in `docs/compat/versions.md`), regardless
///   of what THIS build implements: a `zstd` record produced through a default-build broker
///   is still decodable by a `zstd`-capable consumer, so the gate must not narrow the
///   registry to the broker's own feature set. An UNREGISTERED id (a typo'd future producer,
///   or garbage) fails fast at the source instead of poisoning every consumer.
/// - The claimed `uncompressed_len` must be within `max_decompressed` (callers pass
///   [`DEFAULT_MAX_DECOMPRESSED_BYTES`], the SAME constant every shipped reader and the
///   #437 write seam enforce): an over-cap claim would be durably acked and then refused by
///   every reader's bomb guard (#76) before allocation, on every delivery attempt.
/// - The stream must be plausibly decodable for the named codec: a `none`-codec stream's
///   length must equal the claimed `uncompressed_len` exactly (the read side's
///   [`DecompressError::BadRawLength`] check), and an `lz4`/`zstd` stream must be non-empty.
///   For lz4 the non-empty rule mirrors the read side exactly: an lz4 block needs at least
///   one token byte even for empty output (the canonical lz4 of `b""` is the single byte
///   `0x00`), so `lz4_flex` rejects an empty stream for ANY claimed length. For zstd the
///   rule is deliberately STRICTER than the read side on exactly one degenerate input, the
///   9-byte descriptor (codec `zstd`, any resolvable `dict_id`, claim 0) with an EMPTY
///   stream: the locked `zstd` decoder accepts it
///   (`Decompressor::decompress_to_buffer(&[], &mut [])` is `Ok` with 0 bytes written), but
///   the wire contract (`docs/CONTRACTS.md`) normatively requires a non-empty stream under a
///   compressing codec, and a genuine zstd encoder never emits an empty frame (an empty
///   payload still gets a frame header), so only hand-crafted bytes hit the gap. Pinned by
///   `zstd_empty_stream_claim_zero_is_the_documented_strictness_exception`.
///
/// The `dict_id` is deliberately NOT validated: dictionary resolution is a READER capability
/// (the on-disk sidecar plus the embedded set, `docs/DICTIONARY_LIFECYCLE.md` §5), so the
/// broker cannot know which ids a consumer resolves; an unresolvable id stays the read-side
/// POISON path it always was. Stream CONTENT is likewise not checked (that would require
/// decompressing): a syntactically corrupt stream behind a well-formed descriptor still
/// reaches consumers, exactly as a corrupt raw payload would.
///
/// # Errors
/// Returns the matching [`DecompressError`] variant (the existing taxonomy; no new error
/// vocabulary): [`DecompressError::TruncatedDescriptor`],
/// [`DecompressError::PoisonUnknownCodec`], [`DecompressError::DecompressedTooLarge`],
/// [`DecompressError::BadRawLength`], or [`DecompressError::CorruptStream`].
pub fn validate_descriptor_shape(
    stored: &[u8],
    max_decompressed: u32,
) -> Result<(), DecompressError> {
    // WHY: a payload shorter than the fixed descriptor has no header any reader can parse.
    let (codec_id, _dict_id, uncompressed_len, stream) = read_descriptor(stored)?;

    // WHY: the codec id space is the append-only registry (none/lz4/zstd per
    // docs/compat/versions.md). The check is against the REGISTERED ids, not Codec::from_id
    // (the build-implemented set), so a store-and-forward broker without the zstd feature
    // still accepts a zstd record its consumers may decode; an unregistered id can be
    // decoded by NO conforming reader, so it is rejected at the source.
    if !matches!(codec_id, CODEC_ID_NONE | CODEC_ID_LZ4 | CODEC_ID_ZSTD) {
        return Err(DecompressError::PoisonUnknownCodec(codec_id));
    }

    // WHY: every shipped reader enforces this cap against the CLAIM before allocating (the
    // #76 decompression-bomb guard), so an over-cap claim is undeliverable everywhere; the
    // same DEFAULT_MAX_DECOMPRESSED_BYTES constant keeps the write gate and the readers on
    // one number (the #437 seam's raw-store guard uses it too).
    if uncompressed_len > max_decompressed {
        return Err(DecompressError::DecompressedTooLarge {
            claimed: uncompressed_len,
            cap: max_decompressed,
        });
    }

    if codec_id == CODEC_ID_NONE {
        // WHY: a none-codec descriptor stores the raw payload after the header, and the read
        // side requires the stream length to equal the claim EXACTLY (BadRawLength); the
        // length is in the header, so the check is free here and a mismatch is undecodable.
        if stream.len() != uncompressed_len as usize {
            return Err(DecompressError::BadRawLength);
        }
    } else if stream.is_empty() {
        // WHY: the wire contract (docs/CONTRACTS.md) requires a NON-EMPTY stream under a
        // compressing codec, and no genuine encoder emits one: an lz4 block needs at least
        // one token byte even for empty output (lz4_flex returns ExpectedAnotherByte ->
        // CorruptStream on empty input), and a zstd encoder always emits a frame header.
        // For lz4 this mirrors the read side exactly. For zstd it is deliberately STRICTER
        // on one degenerate input (empty stream + claim 0, which the zstd decoder accepts
        // as a 0-byte output): the contract is normative, and only hand-crafted bytes,
        // never an encoder, produce that shape. See the rustdoc above and the pinning test
        // `zstd_empty_stream_claim_zero_is_the_documented_strictness_exception`.
        return Err(DecompressError::CorruptStream);
    }
    Ok(())
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

    // POISON: a non-zero dict_id the resolver cannot resolve (absent sidecar + embedded). Keep the
    // resolved bytes so the zstd path can actually prime its decompressor with them; the lz4/none
    // paths ignore them (they are dict-free), so resolution there is purely the poison gate. The
    // binding is consumed by the zstd arm; on a default (non-zstd) build it is the poison gate only,
    // so it is explicitly discarded to stay warning-clean under `-D warnings`.
    let dict_bytes: &[u8] = if dict_id == DICT_ID_NONE {
        &[]
    } else {
        resolver
            .resolve(dict_id)
            .ok_or(DecompressError::PoisonUnresolvedDict(dict_id))?
    };
    #[cfg(not(feature = "zstd"))]
    let _ = dict_bytes;

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
        // The OPT-IN zstd codec, with the SAME resilience as lz4: the cap is enforced above before
        // allocation, the output is sized to exactly the claimed length, a corrupt/hostile stream
        // is a typed `CorruptStream` (never a panic), and the dict (if any) was resolved or this
        // path was never reached (poison). `dict_bytes` is the resolved dictionary or empty.
        #[cfg(feature = "zstd")]
        Codec::Zstd => zstd_decompress(stream, dict_bytes, out_len),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lz4_config() -> CompressConfig<'static> {
        CompressConfig {
            codec: Codec::Lz4,
            raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD,
            dict_id: DICT_ID_NONE,
            ..CompressConfig::default()
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
        // The frozen zstd id is 2; the const is always defined regardless of the build.
        assert_eq!(CODEC_ID_ZSTD, 2);
        // On a build WITHOUT the zstd feature, id 2 is UNKNOWN (poison); with the feature it
        // resolves to the zstd codec. This is exactly what makes a default-build reader treat a
        // zstd record as unknown-codec poison rather than a crash.
        #[cfg(not(feature = "zstd"))]
        assert_eq!(Codec::from_id(CODEC_ID_ZSTD), None);
        #[cfg(feature = "zstd")]
        {
            assert_eq!(Codec::from_id(CODEC_ID_ZSTD), Some(Codec::Zstd));
            assert_eq!(Codec::Zstd.id(), 2);
        }
        // Garbage is UNKNOWN on every build.
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
        // Hand-craft a descriptor with a codec id this build does not implement. On a build WITHOUT
        // the zstd feature, the zstd id (2) is itself unknown and is the canonical case (a default
        // reader meeting a zstd record); on a build WITH the feature, id 2 is known, so use an id
        // (200) that is unknown on EVERY build to keep this assertion build-agnostic. The
        // zstd-on-default-build poison case is pinned by `zstd_record_is_unknown_codec_poison`.
        #[cfg(not(feature = "zstd"))]
        let unknown_id = CODEC_ID_ZSTD;
        #[cfg(feature = "zstd")]
        let unknown_id = 200u8;
        let mut stored = Vec::new();
        stored.push(unknown_id);
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
        assert_eq!(err, DecompressError::PoisonUnknownCodec(unknown_id));
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
            ..CompressConfig::default()
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
            ..CompressConfig::default()
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

    /// On a DEFAULT (non-zstd) build, a record written by a zstd-feature writer (codec id 2) is
    /// read as UNKNOWN-codec POISON, never a crash: the default reader cannot decode zstd, so it
    /// routes the record to the #8 quarantine as reported loss. This is the load-bearing
    /// cross-build property: a default binary never panics on a zstd record.
    #[cfg(not(feature = "zstd"))]
    #[test]
    fn zstd_record_is_unknown_codec_poison_on_a_default_build() {
        let mut stored = Vec::new();
        stored.push(CODEC_ID_ZSTD); // the zstd id this default build does not implement
        stored.extend_from_slice(&0u32.to_le_bytes()); // dict_id
        stored.extend_from_slice(&64u32.to_le_bytes()); // uncompressed_len
        stored.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]); // a (real) zstd magic-led stream
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, DecompressError::PoisonUnknownCodec(CODEC_ID_ZSTD));
        assert!(
            err.is_poison(),
            "a zstd record on a default build is poison"
        );
    }

    /// Builds a raw descriptor + stream payload for the shape-validation tests (#438).
    fn descriptor(codec_id: u8, dict_id: u32, uncompressed_len: u32, stream: &[u8]) -> Vec<u8> {
        let mut v = vec![codec_id];
        v.extend_from_slice(&dict_id.to_le_bytes());
        v.extend_from_slice(&uncompressed_len.to_le_bytes());
        v.extend_from_slice(stream);
        v
    }

    #[test]
    fn shape_validation_accepts_a_writer_produced_descriptor() {
        // The gate must accept exactly what an honest compressor emits: the broker's own
        // seam output and a producer-compressed publish are the same bytes.
        let out = compress_payload(&compressible(4096), &lz4_config()).unwrap();
        assert!(out.compressed, "the fixture genuinely compresses");
        validate_descriptor_shape(&out.stored, DEFAULT_MAX_DECOMPRESSED_BYTES)
            .expect("a well-formed compressed object passes the shape gate");
    }

    #[test]
    fn shape_validation_rejects_a_truncated_descriptor_like_the_read_side() {
        // Shorter than DESCRIPTOR_LEN: no reader can frame the header. Same typed error as
        // the read side, so the gate and the readers cannot drift.
        let garbage = b"garbage!"; // 8 bytes < DESCRIPTOR_LEN (9)
        assert_eq!(
            validate_descriptor_shape(garbage, DEFAULT_MAX_DECOMPRESSED_BYTES),
            Err(DecompressError::TruncatedDescriptor)
        );
        assert_eq!(
            decompress_payload(
                RecordFlags::COMPRESSED,
                garbage,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES
            )
            .unwrap_err(),
            DecompressError::TruncatedDescriptor
        );
    }

    #[test]
    fn shape_validation_rejects_an_unregistered_codec_id() {
        // Id 7 is outside the append-only registry (none/lz4/zstd): NO conforming reader
        // can ever decode it, so the produce gate fails it at the source.
        let stored = descriptor(7, DICT_ID_NONE, 4, b"abcd");
        assert_eq!(
            validate_descriptor_shape(&stored, DEFAULT_MAX_DECOMPRESSED_BYTES),
            Err(DecompressError::PoisonUnknownCodec(7))
        );
        assert_eq!(
            decompress_payload(
                RecordFlags::COMPRESSED,
                &stored,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES
            )
            .unwrap_err(),
            DecompressError::PoisonUnknownCodec(7)
        );
    }

    #[test]
    fn shape_validation_accepts_the_registered_zstd_id_on_every_build() {
        // The broker is store-and-forward: a zstd record produced through a default-build
        // broker is decodable by a zstd-capable CONSUMER, so the gate checks the REGISTERED
        // id space (docs/compat/versions.md), never the build-implemented set. The shape
        // passes on both the default and the zstd-feature build (content is not checked).
        let stored = descriptor(CODEC_ID_ZSTD, DICT_ID_NONE, 64, b"not a real zstd frame");
        validate_descriptor_shape(&stored, DEFAULT_MAX_DECOMPRESSED_BYTES)
            .expect("registered id 2 passes the shape gate regardless of the build");
    }

    #[test]
    fn shape_validation_does_not_judge_dict_ids() {
        // Dictionary resolution is a READER capability (sidecar + embedded set), unknowable
        // at the broker, so a non-zero dict_id passes the shape gate and stays the read-side
        // poison path it always was.
        let stored = descriptor(CODEC_ID_LZ4, 0xDEAD_BEEF, 64, b"stream");
        validate_descriptor_shape(&stored, DEFAULT_MAX_DECOMPRESSED_BYTES)
            .expect("a non-zero dict_id is a reader concern, not a shape fault");
    }

    #[test]
    fn shape_validation_rejects_an_over_cap_claim_like_the_readers_bomb_guard() {
        // The cap binds the CLAIM (#76): every shipped reader refuses it before allocating,
        // so an acked over-cap record would stall every consumer. Same constant, same error.
        let stored = descriptor(
            CODEC_ID_LZ4,
            DICT_ID_NONE,
            DEFAULT_MAX_DECOMPRESSED_BYTES + 1,
            b"x",
        );
        let expected = DecompressError::DecompressedTooLarge {
            claimed: DEFAULT_MAX_DECOMPRESSED_BYTES + 1,
            cap: DEFAULT_MAX_DECOMPRESSED_BYTES,
        };
        assert_eq!(
            validate_descriptor_shape(&stored, DEFAULT_MAX_DECOMPRESSED_BYTES),
            Err(expected)
        );
        assert_eq!(
            decompress_payload(
                RecordFlags::COMPRESSED,
                &stored,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES
            )
            .unwrap_err(),
            expected
        );
        // An AT-cap claim is the largest legal one (the readers reject only strictly above).
        let at_cap = descriptor(
            CODEC_ID_LZ4,
            DICT_ID_NONE,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
            b"x",
        );
        validate_descriptor_shape(&at_cap, DEFAULT_MAX_DECOMPRESSED_BYTES)
            .expect("an at-cap claim is shape-legal");
    }

    #[test]
    fn shape_validation_pins_the_none_codec_exact_length_rule() {
        // COMPRESSED + codec none IS wire-legal: the read side returns the stream verbatim
        // when its length equals the claim, and rejects a mismatch as BadRawLength. The gate
        // mirrors both halves exactly.
        let legal = descriptor(CODEC_ID_NONE, DICT_ID_NONE, 2, b"ab");
        validate_descriptor_shape(&legal, DEFAULT_MAX_DECOMPRESSED_BYTES)
            .expect("a length-consistent none-codec object is wire-legal");
        assert_eq!(
            decompress_payload(
                RecordFlags::COMPRESSED,
                &legal,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES
            )
            .unwrap(),
            b"ab",
            "the read side decodes it to the inner raw bytes"
        );
        let mismatched = descriptor(CODEC_ID_NONE, DICT_ID_NONE, 3, b"ab");
        assert_eq!(
            validate_descriptor_shape(&mismatched, DEFAULT_MAX_DECOMPRESSED_BYTES),
            Err(DecompressError::BadRawLength)
        );
        assert_eq!(
            decompress_payload(
                RecordFlags::COMPRESSED,
                &mismatched,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES
            )
            .unwrap_err(),
            DecompressError::BadRawLength
        );
    }

    /// Mutation teeth for the none-codec EXACTNESS rule (#438 review finding 3): the suite
    /// above only covers a stream SHORTER than its claim, so weakening either side's
    /// `stream.len() != claim` to `stream.len() < claim` survived every test. A stream
    /// LONGER than the claim is equally undecodable on the wire contract (which bytes are
    /// the payload?), so BOTH the produce gate and the read side must reject it as
    /// `BadRawLength`. Verified by applying the `<` mutant to each side in turn: this test
    /// fails, the rest of the suite cannot be relied on to.
    #[test]
    fn a_none_codec_stream_longer_than_its_claim_is_rejected_by_both_sides() {
        let longer = descriptor(CODEC_ID_NONE, DICT_ID_NONE, 2, b"abc");
        assert_eq!(
            validate_descriptor_shape(&longer, DEFAULT_MAX_DECOMPRESSED_BYTES),
            Err(DecompressError::BadRawLength),
            "the gate rejects a none-codec stream longer than its claim"
        );
        assert_eq!(
            decompress_payload(
                RecordFlags::COMPRESSED,
                &longer,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES
            )
            .unwrap_err(),
            DecompressError::BadRawLength,
            "the read side rejects it identically"
        );
    }

    #[test]
    fn shape_validation_rejects_an_empty_stream_under_a_compressing_codec() {
        // An empty LZ4 stream cannot be a valid lz4 block (lz4 needs at least one token
        // byte, even for empty output: the canonical lz4 of b"" is the single byte 0x00),
        // so for lz4 the gate and the read side agree for ANY claimed length, including 0.
        // The zstd half of the non-empty rule is NOT a read-side mirror on a claim of 0; it
        // is the gate's one documented strictness exception, pinned separately by
        // `zstd_empty_stream_claim_zero_is_the_documented_strictness_exception`.
        let empty = descriptor(CODEC_ID_LZ4, DICT_ID_NONE, 0, b"");
        assert_eq!(
            validate_descriptor_shape(&empty, DEFAULT_MAX_DECOMPRESSED_BYTES),
            Err(DecompressError::CorruptStream)
        );
        assert_eq!(
            decompress_payload(
                RecordFlags::COMPRESSED,
                &empty,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES
            )
            .unwrap_err(),
            DecompressError::CorruptStream,
            "the read side agrees: an empty lz4 stream is corrupt"
        );
    }

    /// The premise sanity for the #438 gate-contract property
    /// (`proptests::shape_gate_never_rejects_a_decodable_record_except_the_documented_exception`):
    /// a targeted, deterministic set of inputs the read side GENUINELY decodes, so the
    /// "decoder-accept implies gate-accept" direction is exercised by construction, not
    /// vacuously (a raw random stream decodes with probability ~0). The gate must accept
    /// every one of them; the ONE decodable input the gate rejects is pinned separately by
    /// the strictness-exception tests.
    #[test]
    fn the_shape_gate_accepts_every_genuinely_decodable_premise_case() {
        let mut cases: Vec<(&str, Vec<u8>, Vec<u8>)> = Vec::new(); // (name, stored, payload)

        // none-codec: the stream IS the payload and the claim matches exactly.
        cases.push((
            "none, exact length",
            descriptor(CODEC_ID_NONE, DICT_ID_NONE, 3, b"abc"),
            b"abc".to_vec(),
        ));
        // none-codec, empty payload: claim 0 over an empty stream is decodable AND
        // gate-legal (the non-empty-stream rule binds only the compressing codecs).
        cases.push((
            "none, empty payload",
            descriptor(CODEC_ID_NONE, DICT_ID_NONE, 0, b""),
            Vec::new(),
        ));
        // lz4: a genuine block (the same encode call compress_payload makes), claim == the
        // payload length.
        let payload = compressible(4096);
        let block = lz4_flex::block::compress(&payload);
        cases.push((
            "lz4, genuine block",
            descriptor(
                CODEC_ID_LZ4,
                DICT_ID_NONE,
                u32::try_from(payload.len()).unwrap(),
                &block,
            ),
            payload,
        ));
        // lz4 of the EMPTY payload: the canonical single token byte 0x00 with claim 0, a
        // NON-empty stream for a zero-length output (decodable and gate-legal, unlike the
        // empty-stream descriptor).
        let empty_block = lz4_flex::block::compress(b"");
        assert_eq!(empty_block, [0u8], "the canonical lz4 block of b\"\"");
        cases.push((
            "lz4, empty payload",
            descriptor(CODEC_ID_LZ4, DICT_ID_NONE, 0, &empty_block),
            Vec::new(),
        ));
        // zstd, on a feature build only (a default build poisons codec id 2 at decode, so
        // there is no decodable zstd premise case there).
        #[cfg(feature = "zstd")]
        {
            let payload = compressible(4096);
            let frame = zstd::bulk::compress(&payload, DEFAULT_ZSTD_LEVEL).unwrap();
            cases.push((
                "zstd, genuine frame",
                descriptor(
                    CODEC_ID_ZSTD,
                    DICT_ID_NONE,
                    u32::try_from(payload.len()).unwrap(),
                    &frame,
                ),
                payload,
            ));
            // The genuine zstd frame of the empty payload: a NON-empty stream (the frame
            // header) with claim 0, which is exactly why the strictness exception costs a
            // real producer nothing.
            let empty_frame = zstd::bulk::compress(b"", DEFAULT_ZSTD_LEVEL).unwrap();
            assert!(!empty_frame.is_empty());
            cases.push((
                "zstd, empty payload",
                descriptor(CODEC_ID_ZSTD, DICT_ID_NONE, 0, &empty_frame),
                Vec::new(),
            ));
        }

        for (name, stored, expected) in cases {
            let decoded = decompress_payload(
                RecordFlags::COMPRESSED,
                &stored,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES,
            )
            .unwrap_or_else(|e| panic!("premise case {name:?} must be decodable, got {e:?}"));
            assert_eq!(decoded, expected, "case {name:?}: the read side decodes it");
            validate_descriptor_shape(&stored, DEFAULT_MAX_DECOMPRESSED_BYTES)
                .unwrap_or_else(|e| panic!("the gate rejected decodable case {name:?}: {e:?}"));
        }
    }

    /// On a DEFAULT (non-zstd) build the degenerate zstd-empty-stream-claim-0 descriptor is
    /// rejected by BOTH sides (the gate as an empty stream, the read side as unknown-codec
    /// POISON since id 2 is unimplemented here), so the gate's strictness exception is
    /// observable only on a `zstd`-feature build; its read-side-ACCEPTS half is pinned in
    /// `zstd_tests::zstd_empty_stream_claim_zero_is_the_documented_strictness_exception`.
    #[cfg(not(feature = "zstd"))]
    #[test]
    fn zstd_empty_stream_claim_zero_is_rejected_by_both_sides_on_a_default_build() {
        let degenerate = descriptor(CODEC_ID_ZSTD, DICT_ID_NONE, 0, b"");
        assert_eq!(
            degenerate.len(),
            DESCRIPTOR_LEN,
            "the 9-byte degenerate descriptor"
        );
        assert_eq!(
            validate_descriptor_shape(&degenerate, DEFAULT_MAX_DECOMPRESSED_BYTES),
            Err(DecompressError::CorruptStream),
            "the gate rejects the empty stream"
        );
        assert_eq!(
            decompress_payload(
                RecordFlags::COMPRESSED,
                &degenerate,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES
            )
            .unwrap_err(),
            DecompressError::PoisonUnknownCodec(CODEC_ID_ZSTD),
            "a default build cannot decode codec id 2 at all"
        );
    }
}

/// Teeth for the OPT-IN zstd codec (id 2) and the trained-dictionary lifecycle. Compiled only on a
/// `zstd`-feature build; the default build's cross-build poison behaviour is pinned in `mod tests`.
#[cfg(all(test, feature = "zstd"))]
mod zstd_tests {
    use super::*;

    fn zstd_config(dict_id: u32, dict: Option<&[u8]>) -> CompressConfig<'_> {
        CompressConfig {
            codec: Codec::Zstd,
            raw_store_threshold: DEFAULT_RAW_STORE_THRESHOLD,
            dict_id,
            dict,
            zstd_level: DEFAULT_ZSTD_LEVEL,
        }
    }

    /// A resolver that holds exactly one dictionary, for the dict round-trip tests.
    struct OneDict<'a>(u32, &'a [u8]);
    impl DictResolver for OneDict<'_> {
        fn resolve(&self, id: u32) -> Option<&[u8]> {
            (id == self.0).then_some(self.1)
        }
    }

    fn compressible(len: usize) -> Vec<u8> {
        b"ironbus.sensor.telemetry.v1 {\"temp\":21.5,\"unit\":\"C\",\"seq\":42} "
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    #[test]
    fn zstd_round_trips_without_a_dictionary() {
        let payload = compressible(4096);
        let out = compress_payload(&payload, &zstd_config(DICT_ID_NONE, None)).unwrap();
        assert!(
            out.compressed,
            "a compressible payload compresses under zstd"
        );
        assert!(out.stored.len() < payload.len(), "zstd shrinks the payload");
        // The descriptor carries codec id 2.
        let (codec_id, dict_id, _, _) = read_descriptor(&out.stored).unwrap();
        assert_eq!(codec_id, CODEC_ID_ZSTD);
        assert_eq!(dict_id, DICT_ID_NONE);
        let back = decompress_payload(
            RecordFlags::COMPRESSED,
            &out.stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, payload, "zstd decompress(compress(x)) == x");
    }

    #[test]
    fn a_corrupt_zstd_stream_is_a_typed_error_never_a_panic() {
        // A descriptor that claims a plausible length but whose stream is not a valid zstd frame
        // must be a typed CorruptStream, never a panic.
        let mut stored = Vec::new();
        stored.push(CODEC_ID_ZSTD);
        stored.extend_from_slice(&0u32.to_le_bytes());
        stored.extend_from_slice(&64u32.to_le_bytes());
        stored.extend_from_slice(&[0xFF; 16]); // garbage, not a zstd frame
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, DecompressError::CorruptStream);
        assert!(
            !err.is_poison(),
            "a corrupt stream is a body-corruption reject, not poison"
        );
    }

    #[test]
    fn a_zstd_decompression_bomb_is_capped_before_allocation() {
        // A real zstd stream that decodes to a LARGE output, but a descriptor claim OVER the cap,
        // is rejected before any allocation by the same cap that guards lz4.
        let big = compressible(2 * 1024 * 1024);
        let stream = zstd::bulk::compress(&big, DEFAULT_ZSTD_LEVEL).unwrap();
        let mut stored = Vec::new();
        stored.push(CODEC_ID_ZSTD);
        stored.extend_from_slice(&0u32.to_le_bytes());
        stored.extend_from_slice(&u32::MAX.to_le_bytes()); // claim ~4 GiB, over the cap
        stored.extend_from_slice(&stream);
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
    }

    #[test]
    fn a_zstd_stream_that_decodes_past_the_claim_is_a_typed_error() {
        // The claim and the stream are independently attacker-controlled. A descriptor that claims
        // a SMALL length but carries a zstd frame decoding to a LARGER length must be a typed
        // CorruptStream (the bounded buffer rejects the overflow), never a panic.
        let real = vec![0x5Au8; 4096];
        let stream = zstd::bulk::compress(&real, DEFAULT_ZSTD_LEVEL).unwrap();
        let mut stored = Vec::new();
        stored.push(CODEC_ID_ZSTD);
        stored.extend_from_slice(&0u32.to_le_bytes());
        stored.extend_from_slice(&16u32.to_le_bytes()); // LIE: claim 16, well under the cap
        stored.extend_from_slice(&stream);
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, DecompressError::CorruptStream);
    }

    /// THE documented strictness exception of the #438 produce gate, pinned deterministically:
    /// the 9-byte descriptor (codec `zstd`, `dict_id` 0, claim 0) with an EMPTY stream is the
    /// ONE input the read side ACCEPTS but `validate_descriptor_shape` rejects. Empirically,
    /// the locked `zstd` 0.13.3 `Decompressor::decompress_to_buffer(&[], &mut [])` returns
    /// `Ok` with 0 bytes written, so `decompress_payload` yields an empty payload; the gate
    /// still rejects because the wire contract (`docs/CONTRACTS.md`) normatively requires a
    /// non-empty stream under a compressing codec, and a genuine zstd encoder never emits an
    /// empty frame (compressing an empty payload still emits a frame header), so only
    /// hand-crafted bytes reach this gap. Everywhere else the gate's rejection set is a
    /// subset of the read side's (the proptest
    /// `shape_gate_never_rejects_a_decodable_record_except_the_documented_exception`).
    #[test]
    fn zstd_empty_stream_claim_zero_is_the_documented_strictness_exception() {
        let mut degenerate = vec![CODEC_ID_ZSTD];
        degenerate.extend_from_slice(&DICT_ID_NONE.to_le_bytes());
        degenerate.extend_from_slice(&0u32.to_le_bytes()); // claim 0
        assert_eq!(
            degenerate.len(),
            DESCRIPTOR_LEN,
            "empty stream: descriptor only"
        );

        // The read side ACCEPTS: a zstd-build reader decodes it to the empty payload.
        let back = decompress_payload(
            RecordFlags::COMPRESSED,
            &degenerate,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .expect("zstd 0.13 accepts an empty stream for a claim of 0");
        assert!(back.is_empty(), "and the decoded payload is empty");

        // A genuine zstd encoder NEVER produces this shape: even the empty payload
        // compresses to a non-empty frame (the frame header), which is why the strictness
        // costs no real producer anything.
        let genuine_empty_frame = zstd::bulk::compress(b"", DEFAULT_ZSTD_LEVEL).unwrap();
        assert!(
            !genuine_empty_frame.is_empty(),
            "a real zstd frame for the empty payload is non-empty"
        );

        // The gate REJECTS: the wire contract requires a non-empty stream under a
        // compressing codec, deliberately stricter than the permissive zstd read side here.
        assert_eq!(
            validate_descriptor_shape(&degenerate, DEFAULT_MAX_DECOMPRESSED_BYTES),
            Err(DecompressError::CorruptStream),
            "the produce gate enforces the normative non-empty-stream contract"
        );
    }

    #[test]
    fn an_unresolved_zstd_dict_id_is_poison() {
        // A zstd record stamped with a non-zero dict_id the resolver does not hold is the distinct
        // POISON (intact frame, absent dictionary), not a crash. Compress WITHOUT a real dict so we
        // do not need the resolver at write time; the read-time gate is what is under test.
        let payload = compressible(4096);
        let cfg = zstd_config(0x0BAD_F00D, None);
        let out = compress_payload(&payload, &cfg).unwrap();
        let err = decompress_payload(
            RecordFlags::COMPRESSED,
            &out.stored,
            &NoDictionaries,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap_err();
        assert_eq!(err, DecompressError::PoisonUnresolvedDict(0x0BAD_F00D));
        assert!(err.is_poison());
    }

    #[test]
    #[allow(clippy::cast_precision_loss)] // a test ratio measurement; the byte counts are small
    fn a_trained_dictionary_round_trips_and_improves_the_ratio() {
        // Train a dictionary over a corpus of small, same-shaped records (the realistic per-type
        // case), then compress a held-out record of that type with and without the dictionary. The
        // dictionary must (a) beat the no-dictionary zstd ratio on a small record, which is the
        // whole point of a trained dictionary, and (b) round-trip through the full codec path.
        let dict = crate::dict::train_dictionary(&sample_corpus(), 16 * 1024)
            .expect("training over a representative corpus succeeds");
        assert!(!dict.bytes.is_empty(), "a non-empty dictionary was trained");
        assert_ne!(
            dict.dict_id, DICT_ID_NONE,
            "the dict_id is never the sentinel"
        );

        // The RATIO claim, measured over a held-out BATCH of small records of the same type (the
        // §7 per-batch unit) at the raw zstd-stream level, so the never-expand/raw-store guard does
        // not obscure the dictionary's win on a few-hundred-byte record (where an unprimed zstd
        // window finds nothing but a primed one does). Both arms compress the SAME corpus at the
        // SAME level; the ONLY variable is the dictionary (the §7 method).
        let held_out: Vec<Vec<u8>> = (9000..9200u32).map(record_for).collect();
        let mut no_dict_total = 0usize;
        let mut with_dict_total = 0usize;
        let mut raw_total = 0usize;
        let with_dict_compressor =
            zstd::bulk::Compressor::with_dictionary(DEFAULT_ZSTD_LEVEL, &dict.bytes).unwrap();
        let mut with_dict_compressor = with_dict_compressor;
        for rec in &held_out {
            raw_total += rec.len();
            no_dict_total += zstd::bulk::compress(rec, DEFAULT_ZSTD_LEVEL).unwrap().len();
            with_dict_total += with_dict_compressor.compress(rec).unwrap().len();
        }
        let ratio_no_dict = raw_total as f64 / no_dict_total as f64;
        let ratio_with_dict = raw_total as f64 / with_dict_total as f64;
        assert!(
            ratio_with_dict > ratio_no_dict,
            "the trained dictionary improves the per-batch ratio: {ratio_with_dict:.2}x with vs \
             {ratio_no_dict:.2}x without (raw {raw_total} B -> {with_dict_total} B with dict, \
             {no_dict_total} B without)"
        );

        // The dictionary-compressed record round-trips through the FULL codec path with a resolver
        // that holds the dict. Use a sub-threshold-immune record by lowering the raw-store
        // threshold so the descriptor path is exercised end to end.
        let record = record_for(9999);
        let cfg = CompressConfig {
            codec: Codec::Zstd,
            raw_store_threshold: 1, // force the compressed path for the round-trip check
            dict_id: dict.dict_id,
            dict: Some(&dict.bytes),
            zstd_level: DEFAULT_ZSTD_LEVEL,
        };
        let out = compress_payload(&record, &cfg).unwrap();
        assert!(out.compressed, "the descriptor path was exercised");
        let resolver = OneDict(dict.dict_id, &dict.bytes);
        let back = decompress_payload(
            RecordFlags::COMPRESSED,
            &out.stored,
            &resolver,
            DEFAULT_MAX_DECOMPRESSED_BYTES,
        )
        .unwrap();
        assert_eq!(back, record, "a dictionary-compressed record round-trips");
    }

    /// A representative per-type corpus: many small JSON-ish telemetry records that share keys,
    /// schema, and units, which is exactly the cross-record redundancy a trained dictionary
    /// captures.
    fn sample_corpus() -> Vec<Vec<u8>> {
        (0..2000u32).map(record_for).collect()
    }

    fn record_for(i: u32) -> Vec<u8> {
        format!(
            "{{\"type\":\"sensor.telemetry.v1\",\"device\":\"hive-{:04}\",\"temp\":{}.{},\"unit\":\"C\",\"rssi\":-{},\"seq\":{}}}",
            i % 64,
            18 + (i % 12),
            i % 10,
            40 + (i % 50),
            i
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// A STRUCTURED stream for the chaos arm of the #438 gate-contract case: empty,
    /// arbitrary bytes, or a GENUINE codec stream (the same `lz4_flex`/`zstd` encode calls
    /// `compress_payload` makes).
    fn structured_stream() -> proptest::strategy::BoxedStrategy<Vec<u8>> {
        let empty = Just(Vec::new());
        let arbitrary = proptest::collection::vec(any::<u8>(), 0..4096);
        let lz4 = proptest::collection::vec(any::<u8>(), 0..4096)
            .prop_map(|p| lz4_flex::block::compress(&p));
        #[cfg(feature = "zstd")]
        {
            let zstd_frame = proptest::collection::vec(any::<u8>(), 0..4096)
                .prop_map(|p| zstd::bulk::compress(&p, DEFAULT_ZSTD_LEVEL).expect("zstd encode"));
            prop_oneof![empty, arbitrary, lz4, zstd_frame].boxed()
        }
        #[cfg(not(feature = "zstd"))]
        {
            prop_oneof![empty, arbitrary, lz4].boxed()
        }
    }

    /// Genuinely encodes `payload` for `codec_id` with the SAME calls `compress_payload`
    /// makes. Only called with codec ids this build can encode.
    fn genuine_stream(codec_id: u8, payload: &[u8]) -> Vec<u8> {
        match codec_id {
            CODEC_ID_NONE => payload.to_vec(),
            CODEC_ID_LZ4 => lz4_flex::block::compress(payload),
            #[cfg(feature = "zstd")]
            CODEC_ID_ZSTD => {
                zstd::bulk::compress(payload, DEFAULT_ZSTD_LEVEL).expect("zstd encode")
            }
            other => unreachable!("codec id {other} is not encodable on this build"),
        }
    }

    /// One generated `(codec_id, dict_id, claim, stream)` case for the #438 gate-contract
    /// property, drawn from three arms so the decoder-accepts premise GENUINELY fires (the
    /// review proved a raw-random-bytes generator hits a decodable input with probability ~0,
    /// and measurement showed even structured streams stay vacuous while the claim is drawn
    /// INDEPENDENTLY, since decode requires claim == decoded length exactly):
    ///
    /// - CHAOS: every field independent (unregistered ids, arbitrary dicts, mismatched
    ///   claims, streams from `structured_stream`), probing the rejection sets.
    /// - HONEST: a genuine encode with claim == payload length and no dict, decodable by
    ///   construction on every build (`none`/`lz4`; plus `zstd` on a feature build).
    /// - CLAIM-0 BOUNDARY: compressing codecs with claim 0 over an empty stream or the
    ///   genuine codec stream of the EMPTY payload, the neighborhood of the documented
    ///   zstd-empty-stream strictness exception, so the exception branch itself is exercised
    ///   by random cases on a zstd build.
    fn gate_contract_case() -> proptest::strategy::BoxedStrategy<(u8, u32, u32, Vec<u8>)> {
        let chaos = (
            0u8..=3,
            prop_oneof![Just(DICT_ID_NONE), any::<u32>()],
            0u32..=DEFAULT_MAX_DECOMPRESSED_BYTES + 1024,
            structured_stream(),
        )
            .boxed();

        #[cfg(feature = "zstd")]
        let encodable_ids =
            prop_oneof![Just(CODEC_ID_NONE), Just(CODEC_ID_LZ4), Just(CODEC_ID_ZSTD)];
        #[cfg(not(feature = "zstd"))]
        let encodable_ids = prop_oneof![Just(CODEC_ID_NONE), Just(CODEC_ID_LZ4)];
        let honest = (
            encodable_ids,
            proptest::collection::vec(any::<u8>(), 0..4096),
        )
            .prop_map(|(codec_id, payload)| {
                let claim = u32::try_from(payload.len()).expect("payload < 4096");
                let stream = genuine_stream(codec_id, &payload);
                (codec_id, DICT_ID_NONE, claim, stream)
            })
            .boxed();

        let empty_payload_streams = {
            let empty = Just(Vec::new());
            let lz4_of_empty = Just(lz4_flex::block::compress(b""));
            #[cfg(feature = "zstd")]
            {
                let zstd_of_empty =
                    Just(zstd::bulk::compress(b"", DEFAULT_ZSTD_LEVEL).expect("zstd encode"));
                prop_oneof![empty, lz4_of_empty, zstd_of_empty].boxed()
            }
            #[cfg(not(feature = "zstd"))]
            {
                prop_oneof![empty, lz4_of_empty].boxed()
            }
        };
        let claim_zero_boundary = (
            prop_oneof![Just(CODEC_ID_LZ4), Just(CODEC_ID_ZSTD)],
            empty_payload_streams,
        )
            .prop_map(|(codec_id, stream)| (codec_id, DICT_ID_NONE, 0u32, stream))
            .boxed();

        prop_oneof![chaos, honest, claim_zero_boundary].boxed()
    }

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
            let _ = validate_descriptor_shape(&stored, cap);
        }

        // The #438 gate contract over STRUCTURED descriptors (see `gate_contract_case`:
        // a chaos arm, an honest-encode arm, and the claim-0 boundary arm): everything
        // the read side ACCEPTS, the gate also accepts, EXCEPT the single documented
        // degenerate input where the gate is deliberately stricter (codec zstd, EMPTY stream,
        // claim 0: a permissive zstd decoder yields the empty payload, the wire contract
        // demands a non-empty stream; pinned deterministically by the strictness-exception
        // tests). Equivalently: the gate's rejection set is a subset of the readers' rejection
        // set, modulo that one enumerated input. The converse (gate-accept implies
        // decoder-accept) does NOT hold by design and is not asserted: corrupt stream content,
        // a registered-but-unimplemented codec, and an unresolved dict_id all pass the shape
        // gate and stay read-side concerns. The decoder-accepts premise genuinely fires here:
        // the honest arm is decodable BY CONSTRUCTION (measured: the read side accepts ~42%
        // of generated cases on the default build and ~50% on a zstd build, where the
        // degenerate exception branch itself fired 555 times in 10000 cases), whereas
        // raw random bytes decode with probability ~0 and left the previous property vacuous;
        // the deterministic premise set in
        // `tests::the_shape_gate_accepts_every_genuinely_decodable_premise_case` additionally
        // guarantees the premise regardless of generator luck.
        #[test]
        fn shape_gate_never_rejects_a_decodable_record_except_the_documented_exception(
            (codec_id, dict_id, claim, stream) in gate_contract_case(),
        ) {
            let mut stored = vec![codec_id];
            stored.extend_from_slice(&dict_id.to_le_bytes());
            stored.extend_from_slice(&claim.to_le_bytes());
            stored.extend_from_slice(&stream);
            let validated = validate_descriptor_shape(&stored, DEFAULT_MAX_DECOMPRESSED_BYTES);
            let decoded = decompress_payload(
                RecordFlags::COMPRESSED,
                &stored,
                &NoDictionaries,
                DEFAULT_MAX_DECOMPRESSED_BYTES,
            );
            if decoded.is_ok() {
                if codec_id == CODEC_ID_ZSTD && stream.is_empty() && claim == 0 {
                    // The enumerated strictness exception, and nothing else: reachable only
                    // on a zstd-feature build (a default build poisons codec id 2 at decode).
                    prop_assert_eq!(
                        validated,
                        Err(DecompressError::CorruptStream),
                        "the gate rejects the degenerate zstd-empty-claim-0 descriptor"
                    );
                } else {
                    prop_assert!(
                        validated.is_ok(),
                        "the gate rejected a record the read side decodes: {:?}",
                        validated
                    );
                }
            }
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
