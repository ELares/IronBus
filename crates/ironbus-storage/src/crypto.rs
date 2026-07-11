// SPDX-License-Identifier: MIT OR Apache-2.0
//! Optional at-rest AEAD encryption of segment record payloads (#780, spec
//! `docs/AT_REST_ENCRYPTION.md`, design #108).
//!
//! This module is the CRYPTOGRAPHIC core. It is compiled only under the opt-in `encryption` feature.
//! It owns four things and nothing else:
//!
//! 1. **Suite selection** ([`AeadSuite::detect`]): AES-256-GCM where the runtime reports hardware AES
//!    (aarch64 crypto extensions / x86 AES-NI), ChaCha20-Poly1305 as the portable constant-time
//!    fallback. The choice is made ONCE at startup and RECORDED in the segment header, so a read is
//!    unambiguous regardless of the reading host's CPU.
//! 2. **The deterministic nonce** ([`nonce`]): `segment_id (64-bit) || record_counter (32-bit)`. This
//!    makes GCM/ChaCha nonce reuse STRUCTURALLY IMPOSSIBLE under a fixed key without trusting any RNG
//!    (segment-ids never recycle, ADR-0002; the per-segment record counter is monotonic and a u32, so
//!    a segment can never hold enough records to wrap it). See [`nonce`]'s docs for the no-reuse
//!    argument and the tests `nonce_is_injective_*` for the proof.
//! 3. **Encrypt / decrypt** ([`SegmentCrypto::encrypt`], [`KeyRing::decrypt_record`]): AEAD over the
//!    record body, DETACHED tag, using the `RustCrypto` pure-Rust primitives. A decrypt failure is a
//!    typed [`DecryptError`] (unknown key-id vs tag mismatch), NEVER a panic and NEVER garbage
//!    plaintext — `RustCrypto` zeroizes the output buffer and returns an error on a tag mismatch.
//! 4. **Key handling** ([`AeadKey`], [`KeyRing`], [`load_key_file`]): a 32-byte key that zeroizes on
//!    drop and is never logged; a key-id → key map for reads (rotation loads many keys); and a
//!    fail-closed raw-key-file loader (refuses a group/world-readable file, #109).
//!
//! The FRAMING of an encrypted record (the `ENCRYPTED` flag, the ciphertext + tag body layout, the
//! CRC over the ciphertext) lives in the always-linked `ironbus_core::codec`; this module never
//! touches the on-disk frame. That separation is why a DEFAULT build with no `encryption` feature
//! still detects an encrypted segment and fail-closes on it — it just cannot decrypt.

use crate::loss::ReasonCode;
use ironbus_core::format::{
    AEAD_SUITE_AES_256_GCM, AEAD_SUITE_CHACHA20_POLY1305, AEAD_SUITE_NONE, AEAD_TAG_LEN,
};
use std::collections::HashMap;
use zeroize::Zeroize;

/// The length of an at-rest key: 256 bits. Both suites use a 256-bit key.
pub const KEY_LEN: usize = 32;

/// The length of the deterministic AEAD nonce: 96 bits (`segment_id || record_counter`).
pub const NONCE_LEN: usize = 12;

/// The two AEAD suites (#780). Both are 256-bit-key, 96-bit-nonce, 128-bit-tag AEADs, so the key
/// material and the nonce construction are identical across them; only the primitive differs. The
/// suite is chosen once at startup by [`AeadSuite::detect`] and RECORDED in each sealed segment's
/// header, so a segment written under one suite is read back correctly on a host that would have
/// detected the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadSuite {
    /// AES-256-GCM. Selected only where the CPU exposes a constant-time hardware AES path (a software
    /// AES-GCM is both slow and a timing-side-channel risk on a small device).
    Aes256Gcm,
    /// ChaCha20-Poly1305, constant-time in portable software — the fallback everywhere hardware AES
    /// is not reported.
    ChaCha20Poly1305,
}

impl AeadSuite {
    /// The on-disk suite id recorded in the segment header (`segment_header_offsets::AEAD_SUITE`).
    #[must_use]
    pub fn id(self) -> u8 {
        match self {
            AeadSuite::Aes256Gcm => AEAD_SUITE_AES_256_GCM,
            AeadSuite::ChaCha20Poly1305 => AEAD_SUITE_CHACHA20_POLY1305,
        }
    }

    /// Maps an on-disk suite id back to a suite. Returns `None` for [`AEAD_SUITE_NONE`] (a plaintext
    /// segment) or any UNKNOWN value — the caller REFUSES an unknown suite fail-closed (the same
    /// refuse-on-unknown discipline as an unknown `checksum_algo`), never guessing a primitive.
    #[must_use]
    pub fn from_id(id: u8) -> Option<AeadSuite> {
        match id {
            AEAD_SUITE_AES_256_GCM => Some(AeadSuite::Aes256Gcm),
            AEAD_SUITE_CHACHA20_POLY1305 => Some(AeadSuite::ChaCha20Poly1305),
            _ => None, // AEAD_SUITE_NONE or an unknown future suite
        }
    }

    /// A stable, human-readable name (for logs and the config surface).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            AeadSuite::Aes256Gcm => "AES-256-GCM",
            AeadSuite::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }

    /// Selects the suite for THIS host, ONCE, by CPU feature detection: AES-256-GCM where a hardware
    /// AES implementation is reported (x86 AES-NI, aarch64 crypto extensions), else ChaCha20-Poly1305.
    /// The result is recorded in every sealed segment's header, so it is a per-writer choice, never
    /// re-evaluated per record and never assumed by a reader.
    #[must_use]
    pub fn detect() -> AeadSuite {
        #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
        {
            if std::arch::is_x86_feature_detected!("aes") {
                return AeadSuite::Aes256Gcm;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("aes") {
                return AeadSuite::Aes256Gcm;
            }
        }
        AeadSuite::ChaCha20Poly1305
    }
}

/// Builds the deterministic 96-bit AEAD nonce for a record: `segment_id (little-endian 64-bit) ||
/// record_counter (little-endian 32-bit)`.
///
/// # Why reuse is structurally impossible
///
/// GCM (and ChaCha20-Poly1305) nonce reuse under a fixed key is catastrophic. This construction
/// prevents it WITHOUT trusting any RNG:
///
/// 1. **Within a segment**, `record_counter` is the record's per-segment ordinal (0, 1, 2, …), which
///    is strictly increasing and never repeats, so two records in the same segment never share a
///    nonce.
/// 2. **Across segments**, `segment_id` is unique and NEVER recycled (ADR-0002; a fresh segment
///    always gets a higher id, even across restart/recovery), so the high 64 bits differ and no two
///    records in different segments share a nonce, even at the same `record_counter`.
/// 3. **Across a key** (rotation), each new segment gets a fresh, never-recycled `segment_id`, so the
///    `(segment_id, counter)` space under any one key is collision-free by construction.
///
/// The map `(segment_id, record_counter) -> nonce` is INJECTIVE (little-endian is a bijection on each
/// component and the two occupy disjoint byte ranges), so distinct `(segment_id, counter)` pairs
/// always yield distinct nonces. Because the writer's per-segment record ordinal is a `u32` and
/// `SegmentWriter::append` refuses (`SegmentFull`) at `record_count == u32::MAX`, a single segment can
/// never hold enough records to wrap the 32-bit counter — the cap is airtight regardless of the
/// configured `max_segment_bytes`. This needs NO randomness at all, so it cannot be defeated by a
/// low-entropy early-boot RNG on a freshly provisioned edge device.
#[must_use]
pub fn nonce(segment_id: u64, record_counter: u32) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..8].copy_from_slice(&segment_id.to_le_bytes());
    n[8..].copy_from_slice(&record_counter.to_le_bytes());
    n
}

/// A 256-bit at-rest key. Zeroized on drop so it does not linger in freed heap, and never printed
/// (its [`std::fmt::Debug`] is redacted): the key bytes never touch a log or the on-disk format — only
/// a `key_id` does.
#[derive(Clone)]
pub struct AeadKey([u8; KEY_LEN]);

impl AeadKey {
    /// Wraps 32 raw key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> AeadKey {
        AeadKey(bytes)
    }
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER print the key material.
        f.write_str("AeadKey(<redacted 32 bytes>)")
    }
}

/// A decrypt failure (#780), each a DISTINCT reported class routed through the #8 bounded-and-reported
/// recovery-loss path via [`DecryptError::reason_code`], never a silent skip, a crash, or garbage
/// plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// The segment's `key_id` matches NO loaded key: a key-management gap, not corruption. The bytes
    /// are fine; the key is absent.
    UnknownKeyId(u64),
    /// The CRC over the ciphertext passed but the AEAD tag FAILED under the named key: a wrong or
    /// rotated key, or a forgery. Deliberately distinct from bit-rot.
    TagMismatch,
    /// The segment header names an AEAD suite id this build does not understand (an unknown future
    /// suite). Refused fail-closed, like an unknown `checksum_algo`.
    UnsupportedSuite(u8),
}

impl DecryptError {
    /// The [`ReasonCode`] this failure routes to in the loss report. A missing key and an unknown
    /// suite are both "cannot decrypt, key/format problem" ([`ReasonCode::UnknownKeyId`]); a tag
    /// mismatch is the distinct authenticity failure ([`ReasonCode::AeadTagMismatch`]). Neither is
    /// ever reported as `CorruptRecordBody`, so a key problem can never masquerade as bit-rot.
    #[must_use]
    pub fn reason_code(self) -> ReasonCode {
        match self {
            DecryptError::UnknownKeyId(_) | DecryptError::UnsupportedSuite(_) => {
                ReasonCode::UnknownKeyId
            }
            DecryptError::TagMismatch => ReasonCode::AeadTagMismatch,
        }
    }
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::UnknownKeyId(id) => {
                write!(f, "no loaded at-rest key matches segment key_id {id}")
            }
            DecryptError::TagMismatch => write!(
                f,
                "AEAD tag mismatch: the ciphertext is intact (CRC passed) but does not authenticate \
                 under the named key (wrong/rotated key or forgery)"
            ),
            DecryptError::UnsupportedSuite(s) => {
                write!(f, "segment names an unsupported AEAD suite id {s}")
            }
        }
    }
}

impl std::error::Error for DecryptError {}

/// Encrypts `plaintext` in place under `suite`/`key` with the deterministic nonce for
/// `(segment_id, record_counter)`, returning the ciphertext (same length as the plaintext) and the
/// detached 16-byte tag. No associated data is bound (the nonce already binds the segment id and the
/// record ordinal). Encryption of a record bounded by the 1 GiB format ceiling can never fail on
/// length (far below the AEAD's own limit), so this does not return a `Result`.
#[must_use]
fn encrypt(
    suite: AeadSuite,
    key: &AeadKey,
    segment_id: u64,
    record_counter: u32,
    plaintext: &[u8],
) -> (Vec<u8>, [u8; AEAD_TAG_LEN]) {
    let nonce_bytes = nonce(segment_id, record_counter);
    let mut buf = plaintext.to_vec();
    let mut tag = [0u8; AEAD_TAG_LEN];
    match suite {
        AeadSuite::Aes256Gcm => {
            use aes_gcm::aead::{AeadInPlace, KeyInit};
            use aes_gcm::{Aes256Gcm, Nonce};
            let cipher =
                Aes256Gcm::new_from_slice(&key.0).expect("a 32-byte key is a valid AES-256 key");
            let t = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), b"", &mut buf)
                .expect("AEAD encryption of a bounded (<1 GiB) record cannot fail on length");
            tag.copy_from_slice(t.as_slice());
        }
        AeadSuite::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{AeadInPlace, KeyInit};
            use chacha20poly1305::{ChaCha20Poly1305, Nonce};
            let cipher = ChaCha20Poly1305::new_from_slice(&key.0)
                .expect("a 32-byte key is a valid ChaCha20-Poly1305 key");
            let t = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), b"", &mut buf)
                .expect("AEAD encryption of a bounded (<1 GiB) record cannot fail on length");
            tag.copy_from_slice(t.as_slice());
        }
    }
    (buf, tag)
}

/// Decrypts `ciphertext`+`tag` under `suite`/`key` with the deterministic nonce for
/// `(segment_id, record_counter)`. On a tag mismatch `RustCrypto` zeroizes the working buffer and this
/// returns [`DecryptError::TagMismatch`] — it NEVER returns garbage plaintext and NEVER panics.
fn decrypt(
    suite: AeadSuite,
    key: &AeadKey,
    segment_id: u64,
    record_counter: u32,
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    if tag.len() != AEAD_TAG_LEN {
        return Err(DecryptError::TagMismatch);
    }
    let nonce_bytes = nonce(segment_id, record_counter);
    let mut buf = ciphertext.to_vec();
    match suite {
        AeadSuite::Aes256Gcm => {
            use aes_gcm::aead::{AeadInPlace, KeyInit};
            use aes_gcm::{Aes256Gcm, Nonce, Tag};
            let cipher =
                Aes256Gcm::new_from_slice(&key.0).expect("a 32-byte key is a valid AES-256 key");
            cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce_bytes),
                    b"",
                    &mut buf,
                    Tag::from_slice(tag),
                )
                .map_err(|_| DecryptError::TagMismatch)?;
        }
        AeadSuite::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{AeadInPlace, KeyInit};
            use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
            let cipher = ChaCha20Poly1305::new_from_slice(&key.0)
                .expect("a 32-byte key is a valid ChaCha20-Poly1305 key");
            cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce_bytes),
                    b"",
                    &mut buf,
                    Tag::from_slice(tag),
                )
                .map_err(|_| DecryptError::TagMismatch)?;
        }
    }
    Ok(buf)
}

/// The active WRITE-side encryption context a [`crate::segment::SegmentWriter`] carries when at-rest
/// encryption is on: the startup-selected suite, the active write key, and its key-id. Exactly one is
/// active at a time; rotation swaps it and only affects NEW segments (history is never re-encrypted).
#[derive(Clone)]
pub struct SegmentCrypto {
    suite: AeadSuite,
    key_id: u64,
    key: AeadKey,
}

impl SegmentCrypto {
    /// Creates the write context. `key_id` must be non-zero (`0` is the [`AEAD_SUITE_NONE`] /
    /// no-key sentinel), so a real key is never confused with a plaintext segment.
    ///
    /// # Panics
    /// Panics if `key_id == 0` (a configuration error caught at construction, not at write time).
    #[must_use]
    pub fn new(suite: AeadSuite, key_id: u64, key: AeadKey) -> SegmentCrypto {
        assert!(
            key_id != 0,
            "at-rest key_id must be non-zero (0 is the no-key/plaintext sentinel)"
        );
        SegmentCrypto { suite, key_id, key }
    }

    /// The suite this writer records in the segment header.
    #[must_use]
    pub fn suite(&self) -> AeadSuite {
        self.suite
    }

    /// The key-id this writer records in the segment header (never the key).
    #[must_use]
    pub fn key_id(&self) -> u64 {
        self.key_id
    }

    /// Encrypts a record body for the segment `segment_id` at per-segment ordinal `record_counter`.
    /// The nonce is [`nonce`]`(segment_id, record_counter)`, which is unique for the life of the log
    /// under this key (see [`nonce`]). Returns the ciphertext and the detached 16-byte tag.
    #[must_use]
    pub fn encrypt(
        &self,
        segment_id: u64,
        record_counter: u32,
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; AEAD_TAG_LEN]) {
        encrypt(self.suite, &self.key, segment_id, record_counter, plaintext)
    }
}

impl std::fmt::Debug for SegmentCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentCrypto")
            .field("suite", &self.suite)
            .field("key_id", &self.key_id)
            .field("key", &self.key) // AeadKey redacts itself
            .finish()
    }
}

/// A set of loaded at-rest keys, indexed by key-id, for READS. Rotation is new-segments-only, so a
/// reader must keep EVERY key whose segments are still on disk loaded at once; a segment's header
/// `key_id` selects which one decrypts it. A key-id that matches no loaded key is a distinct reported
/// [`DecryptError::UnknownKeyId`], not corruption.
#[derive(Default)]
pub struct KeyRing {
    keys: HashMap<u64, AeadKey>,
}

impl KeyRing {
    /// An empty key ring.
    #[must_use]
    pub fn new() -> KeyRing {
        KeyRing {
            keys: HashMap::new(),
        }
    }

    /// Loads a key under `key_id` (replacing any existing key with that id). `key_id` `0` is the
    /// no-key sentinel and is rejected.
    ///
    /// # Panics
    /// Panics if `key_id == 0`.
    pub fn insert(&mut self, key_id: u64, key: AeadKey) {
        assert!(key_id != 0, "at-rest key_id must be non-zero");
        self.keys.insert(key_id, key);
    }

    /// Whether a key with this id is loaded.
    #[must_use]
    pub fn contains(&self, key_id: u64) -> bool {
        self.keys.contains_key(&key_id)
    }

    /// Decrypts one record's `ciphertext`+`tag` for segment `segment_id` at per-segment ordinal
    /// `record_counter`, selecting the key by `key_id` and the primitive by `suite`. A missing key is
    /// [`DecryptError::UnknownKeyId`]; a tag failure is [`DecryptError::TagMismatch`]; both map to
    /// distinct loss reason codes via [`DecryptError::reason_code`], never `CorruptRecordBody`.
    ///
    /// # Errors
    /// [`DecryptError::UnknownKeyId`] if `key_id` is not loaded, or [`DecryptError::TagMismatch`] on a
    /// tag failure.
    pub fn decrypt_record(
        &self,
        suite: AeadSuite,
        key_id: u64,
        segment_id: u64,
        record_counter: u32,
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let key = self
            .keys
            .get(&key_id)
            .ok_or(DecryptError::UnknownKeyId(key_id))?;
        decrypt(suite, key, segment_id, record_counter, ciphertext, tag)
    }
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print only the loaded key-ids, never the keys.
        let mut ids: Vec<u64> = self.keys.keys().copied().collect();
        ids.sort_unstable();
        f.debug_struct("KeyRing").field("key_ids", &ids).finish()
    }
}

/// An error loading a raw at-rest key file (#780, key-source phase 1).
#[derive(Debug)]
pub enum KeyFileError {
    /// The file is group- or world-accessible (fails the `mode & 0o077 == 0` check), so the broker
    /// refuses to load a secret from it (#109). The strongest local custody would be a TEE-sealed key
    /// (deferred); a raw key file must at least be owner-only.
    TooOpen {
        /// The offending file mode's permission bits.
        mode: u32,
    },
    /// The file is not exactly [`KEY_LEN`] (32) bytes.
    WrongLength {
        /// The actual byte length read.
        len: usize,
    },
    /// An IO error reading the file.
    Io(std::io::Error),
}

impl std::fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyFileError::TooOpen { mode } => write!(
                f,
                "at-rest key file is group/world-accessible (mode {mode:#o}); refusing to load a \
                 secret from a non-owner-only file"
            ),
            KeyFileError::WrongLength { len } => {
                write!(
                    f,
                    "at-rest key file must be exactly {KEY_LEN} bytes, found {len}"
                )
            }
            KeyFileError::Io(e) => write!(f, "reading at-rest key file: {e}"),
        }
    }
}

impl std::error::Error for KeyFileError {}

impl From<std::io::Error> for KeyFileError {
    fn from(e: std::io::Error) -> Self {
        KeyFileError::Io(e)
    }
}

/// Loads a 32-byte raw at-rest key from a file (#780, key-source phase 1: the raw-key-file source of
/// the #14 priority). FAIL-CLOSED: on Unix the file must be owner-only — a group- or world-accessible
/// file is refused ([`KeyFileError::TooOpen`]), mirroring the TLS private-key and cluster-secret
/// permission checks (#109). The file must contain EXACTLY 32 bytes.
///
/// Argon2id-from-passphrase and TEE-sealed key sources are documented follow-ups (the #14/#109
/// key-config schema owns them); this phase implements the raw-key-file source only.
///
/// # Errors
/// [`KeyFileError::TooOpen`] if the file is group/world-accessible, [`KeyFileError::WrongLength`] if
/// it is not 32 bytes, or [`KeyFileError::Io`] on an IO error.
pub fn load_key_file(path: &std::path::Path) -> Result<AeadKey, KeyFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        let mode = meta.mode();
        // The same fail-closed rule as every other secret-bearing file (#109): reject any group- or
        // world- read/write/execute bit. A raw key on disk is only as safe as its file permissions.
        if mode & 0o077 != 0 {
            return Err(KeyFileError::TooOpen {
                mode: mode & 0o7777,
            });
        }
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() != KEY_LEN {
        return Err(KeyFileError::WrongLength { len: bytes.len() });
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    let out = AeadKey::from_bytes(key);
    key.zeroize();
    Ok(out)
}

/// A tiny compile-time sanity anchor: the no-suite sentinel is zero, so a suite id from
/// [`AeadSuite::id`] (1 or 2) can never collide with "plaintext".
const _: () = assert!(AEAD_SUITE_NONE == 0);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn test_key(seed: u8) -> AeadKey {
        AeadKey::from_bytes([seed; KEY_LEN])
    }

    #[test]
    fn suite_id_round_trips_and_none_is_distinct() {
        assert_eq!(
            AeadSuite::from_id(AeadSuite::Aes256Gcm.id()),
            Some(AeadSuite::Aes256Gcm)
        );
        assert_eq!(
            AeadSuite::from_id(AeadSuite::ChaCha20Poly1305.id()),
            Some(AeadSuite::ChaCha20Poly1305)
        );
        // NONE and an unknown future id are refused (None), never guessed.
        assert_eq!(AeadSuite::from_id(AEAD_SUITE_NONE), None);
        assert_eq!(AeadSuite::from_id(200), None);
        assert_ne!(AeadSuite::Aes256Gcm.id(), AeadSuite::ChaCha20Poly1305.id());
    }

    #[test]
    fn detect_returns_a_supported_suite() {
        // Whatever the host, detection yields a suite this build can encode/decode.
        let s = AeadSuite::detect();
        assert!(matches!(
            s,
            AeadSuite::Aes256Gcm | AeadSuite::ChaCha20Poly1305
        ));
        assert_eq!(AeadSuite::from_id(s.id()), Some(s));
    }

    #[test]
    fn nonce_layout_is_segment_id_then_counter() {
        let n = nonce(0x0102_0304_0506_0708, 0x1112_1314);
        assert_eq!(&n[..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&n[8..], &0x1112_1314u32.to_le_bytes());
        assert_eq!(n.len(), NONCE_LEN);
    }

    #[test]
    fn nonce_is_injective_across_segments_and_counters() {
        // THE structural no-reuse proof: over a grid of segment-ids and per-segment counters, every
        // (segment_id, counter) pair yields a DISTINCT nonce — so no two encrypted records under a
        // fixed key ever share a nonce. This covers within-a-segment (same id, different counter),
        // across-segments (different id, same counter), and the diagonal.
        let mut seen: HashSet<[u8; NONCE_LEN]> = HashSet::new();
        let segment_ids = [
            0u64,
            1,
            2,
            7,
            1000,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::MAX,
        ];
        for &sid in &segment_ids {
            for counter in 0u32..2000 {
                assert!(
                    seen.insert(nonce(sid, counter)),
                    "nonce collision at segment_id={sid} counter={counter}"
                );
            }
        }
        // A hand-checked cross pair that a naive additive scheme would collide on:
        // (segment_id=0, counter=1<<8) vs (segment_id=1, counter=0) share no bytes here.
        assert_ne!(nonce(0, 256), nonce(1, 0));
    }

    #[test]
    fn round_trip_both_suites() {
        for suite in [AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305] {
            let key = test_key(0x42);
            let plaintext = b"the confidential record body: key||headers||payload".to_vec();
            let (ct, tag) = encrypt(suite, &key, 7, 3, &plaintext);
            // Ciphertext is the same length as the plaintext (stream-cipher AEAD) and NOT the
            // plaintext (it is actually encrypted).
            assert_eq!(ct.len(), plaintext.len(), "{}", suite.name());
            assert_ne!(ct, plaintext, "{}", suite.name());
            assert_eq!(tag.len(), AEAD_TAG_LEN);
            let got = decrypt(suite, &key, 7, 3, &ct, &tag).unwrap();
            assert_eq!(got, plaintext, "{} round-trip", suite.name());
        }
    }

    #[test]
    fn empty_body_round_trips() {
        for suite in [AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305] {
            let key = test_key(1);
            let (ct, tag) = encrypt(suite, &key, 0, 0, b"");
            assert_eq!(ct.len(), 0);
            assert_eq!(decrypt(suite, &key, 0, 0, &ct, &tag).unwrap(), b"");
        }
    }

    #[test]
    fn wrong_key_is_a_tag_mismatch_not_garbage() {
        for suite in [AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305] {
            let key = test_key(0x11);
            let wrong = test_key(0x22);
            let (ct, tag) = encrypt(suite, &key, 5, 9, b"secret");
            // A wrong key NEVER yields plaintext — it is a distinct, reported TagMismatch.
            assert_eq!(
                decrypt(suite, &wrong, 5, 9, &ct, &tag),
                Err(DecryptError::TagMismatch),
                "{}",
                suite.name()
            );
        }
    }

    #[test]
    fn wrong_nonce_position_is_a_tag_mismatch() {
        // Decrypting with the WRONG (segment_id, counter) — i.e. a nonce that does not match how it
        // was encrypted — fails the tag. This is what makes a mis-placed record (e.g. a
        // verbatim-copied frame under a different segment_id) fail LOUDLY rather than decrypt to
        // garbage: the anti-silent guarantee across positions.
        let suite = AeadSuite::Aes256Gcm;
        let key = test_key(3);
        let (ct, tag) = encrypt(suite, &key, 5, 9, b"payload");
        assert_eq!(
            decrypt(suite, &key, 6, 9, &ct, &tag),
            Err(DecryptError::TagMismatch)
        ); // wrong seg
        assert_eq!(
            decrypt(suite, &key, 5, 10, &ct, &tag),
            Err(DecryptError::TagMismatch)
        ); // wrong ctr
    }

    #[test]
    fn wrong_suite_does_not_decrypt() {
        // A ciphertext produced under one suite never authenticates under the other (belt-and-braces:
        // the header records the suite so this cannot happen in practice, but prove it fails loudly).
        let key = test_key(4);
        let (ct, tag) = encrypt(AeadSuite::Aes256Gcm, &key, 1, 1, b"data-in-flight");
        assert_eq!(
            decrypt(AeadSuite::ChaCha20Poly1305, &key, 1, 1, &ct, &tag),
            Err(DecryptError::TagMismatch)
        );
    }

    #[test]
    fn a_truncated_tag_is_a_tag_mismatch_not_a_panic() {
        let key = test_key(5);
        let (ct, _tag) = encrypt(AeadSuite::Aes256Gcm, &key, 1, 1, b"x");
        assert_eq!(
            decrypt(AeadSuite::Aes256Gcm, &key, 1, 1, &ct, &[0u8; 8]),
            Err(DecryptError::TagMismatch)
        );
    }

    #[test]
    fn keyring_selects_by_key_id_and_reports_unknown() {
        let mut ring = KeyRing::new();
        ring.insert(1, test_key(0xA1));
        ring.insert(2, test_key(0xB2));
        // Encrypt under key 2's material, decrypt via the ring naming key 2.
        let (ct, tag) = encrypt(
            AeadSuite::ChaCha20Poly1305,
            &test_key(0xB2),
            8,
            4,
            b"rotated",
        );
        assert_eq!(
            ring.decrypt_record(AeadSuite::ChaCha20Poly1305, 2, 8, 4, &ct, &tag)
                .unwrap(),
            b"rotated"
        );
        // A key-id no one loaded is a distinct UnknownKeyId, not corruption and not a crash.
        assert_eq!(
            ring.decrypt_record(AeadSuite::ChaCha20Poly1305, 99, 8, 4, &ct, &tag),
            Err(DecryptError::UnknownKeyId(99))
        );
        // The wrong loaded key (id 1) still fails as a tag mismatch.
        assert_eq!(
            ring.decrypt_record(AeadSuite::ChaCha20Poly1305, 1, 8, 4, &ct, &tag),
            Err(DecryptError::TagMismatch)
        );
    }

    #[test]
    fn decrypt_error_maps_to_distinct_reason_codes() {
        // The anti-silent-garbage routing: each failure is its OWN reason class, never CorruptRecordBody.
        assert_eq!(
            DecryptError::UnknownKeyId(7).reason_code(),
            ReasonCode::UnknownKeyId
        );
        assert_eq!(
            DecryptError::UnsupportedSuite(9).reason_code(),
            ReasonCode::UnknownKeyId
        );
        assert_eq!(
            DecryptError::TagMismatch.reason_code(),
            ReasonCode::AeadTagMismatch
        );
        assert_ne!(ReasonCode::UnknownKeyId, ReasonCode::CorruptRecordBody);
        assert_ne!(ReasonCode::AeadTagMismatch, ReasonCode::CorruptRecordBody);
    }

    #[test]
    fn segment_crypto_encrypts_and_the_key_is_redacted_in_debug() {
        let crypto = SegmentCrypto::new(AeadSuite::Aes256Gcm, 7, test_key(0xEE));
        assert_eq!(crypto.key_id(), 7);
        assert_eq!(crypto.suite(), AeadSuite::Aes256Gcm);
        let (ct, tag) = crypto.encrypt(3, 0, b"body");
        let got = decrypt(crypto.suite(), &test_key(0xEE), 3, 0, &ct, &tag).unwrap();
        assert_eq!(got, b"body");
        // Neither the key struct nor the crypto context leaks key bytes in Debug.
        assert!(format!("{:?}", test_key(0xEE)).contains("redacted"));
        let dbg = format!("{crypto:?}");
        assert!(dbg.contains("key_id: 7"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn segment_crypto_rejects_zero_key_id() {
        let _ = SegmentCrypto::new(AeadSuite::Aes256Gcm, 0, test_key(1));
    }

    #[cfg(unix)]
    #[test]
    fn key_file_loader_is_fail_closed_on_permissions_and_length() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();

        // A world-readable 32-byte file is REFUSED (fail-closed), even though the length is right.
        let open_path = dir.path().join("open.key");
        {
            let mut f = std::fs::File::create(&open_path).unwrap();
            f.write_all(&[7u8; KEY_LEN]).unwrap();
        }
        std::fs::set_permissions(&open_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_key_file(&open_path),
            Err(KeyFileError::TooOpen { .. })
        ));

        // An owner-only file of the WRONG length is refused with WrongLength.
        let short_path = dir.path().join("short.key");
        {
            let mut f = std::fs::File::create(&short_path).unwrap();
            f.write_all(&[7u8; 16]).unwrap();
        }
        std::fs::set_permissions(&short_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load_key_file(&short_path),
            Err(KeyFileError::WrongLength { len: 16 })
        ));

        // An owner-only 32-byte file LOADS and decrypts a round-trip.
        let good_path = dir.path().join("good.key");
        {
            let mut f = std::fs::File::create(&good_path).unwrap();
            f.write_all(&[0x5Au8; KEY_LEN]).unwrap();
        }
        std::fs::set_permissions(&good_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let key = load_key_file(&good_path).unwrap();
        let (ct, tag) = encrypt(AeadSuite::Aes256Gcm, &key, 1, 0, b"loaded");
        assert_eq!(
            decrypt(AeadSuite::Aes256Gcm, &key, 1, 0, &ct, &tag).unwrap(),
            b"loaded"
        );
    }
}
