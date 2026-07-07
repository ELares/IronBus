// SPDX-License-Identifier: MIT OR Apache-2.0
//! Interim shared-secret authentication for the cluster PEER wire (#1067, Increment 2).
//!
//! The raft metadata peer wire is plaintext and, before this module, authenticated a peer only by its
//! *claimed* node id ([`super::transport::PeerRegistry`]) — spoofable by anyone who can reach the port.
//! This module adds an HMAC-SHA256 origin-authentication + per-frame integrity envelope keyed by a
//! cluster-wide shared secret, so a peer frame is cryptographically authenticated as originating from a
//! holder of the cluster secret — defeating OUTSIDER spoofing of `from`. It is the INTERIM step before
//! mTLS on the peer wire (#766), which supersedes it with confidentiality, mutual identity, and
//! anti-replay.
//!
//! # Honest scope
//! This provides **origin authentication (cluster-MEMBERSHIP, not per-node identity) + per-frame
//! integrity ONLY**:
//!   * NOT per-node identity: the key is ONE cluster-wide symmetric secret, so the MAC proves "produced
//!     by a holder of the cluster secret," never "produced by the node named in `from`." A compromised
//!     secret-holder can still forge `from` — but raft already fully trusts every voter, so this grants
//!     an insider no new capability; per-node identity is mTLS #766.
//!   * NOT confidentiality: the raft protobuf still travels in cleartext.
//!   * NOT anti-replay: a captured valid frame can be re-injected; raft's own term/index/log-matching
//!     make stale appends/votes inert or idempotent, and the signed `from`/`to` blunt cross-node replay.
//!     A per-connection nonce/counter is deliberately out of scope; the `ver` byte in the frame layout
//!     leaves room for a future MAC version to add one.
//!   * METADATA wire only: this authenticates the raft metadata peer wire; the co-located data-plane
//!     replication wire (ISR / fetch) is a separate listener not covered by this increment.
//!
//! # Primitive
//! HMAC-SHA256 (RFC 2104) is hand-rolled over the already-vetted pure-Rust `sha2` crate already in the
//! tree (via `argon2`/`password-hash`) — ZERO new dependency, no `deny.toml` / MSRV churn — and tested
//! against the RFC 4231 vectors. The tag compare is constant-time via `subtle::ConstantTimeEq` (the same
//! primitive the #631 token-digest compare uses); a plain `==` would be a timing oracle. The key bytes
//! are zeroized on drop and never logged (redacting `Debug`).

use std::sync::Arc;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// The MAC layout version carried as the first body byte of a [`RaftAuth`](ironbus_proto::frame::FrameType::RaftAuth)
/// frame. Bumping it is how a future MAC scheme (e.g. one adding an anti-replay counter) is introduced
/// without silently reinterpreting the current bytes.
pub const MAC_VERSION: u8 = 1;

/// The fixed domain-separation label bound into every MAC (`HMAC(key, LABEL || ver || raft_pb)`), so a
/// key can never be cross-used to authenticate a different context, and so the `ver` is authenticated.
const DOMAIN_LABEL: &[u8] = b"ironbus.cluster.peer.raft.v1";

/// The SHA-256 / HMAC-SHA256 block size, in bytes.
const HMAC_BLOCK: usize = 64;

/// A 32-byte cluster peer-authentication key, derived from the operator's shared-secret file. Zeroized
/// on drop; its `Debug` redacts the bytes so a key is never logged. Cheap to share behind an `Arc`.
pub struct PeerKey([u8; 32]);

impl std::fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeerKey(<redacted>)")
    }
}

impl Drop for PeerKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PeerKey {
    /// Derive the key from the raw shared-secret file bytes with a SHA-256 KDF. Hashing maps an
    /// arbitrary-length secret to a fixed 32-byte key; the derived key is BYTE-SENSITIVE, so every node
    /// must hold the SAME secret file byte-identically — a trailing newline (or any byte difference)
    /// yields a different key and, under the default `Required` mode, silently breaks all peer auth (no
    /// quorum, only generic MAC-mismatch logs). Generate with `head -c 32 /dev/urandom > file` (no
    /// editor/echo-added newline) and copy that exact file to every node. The minimum-length floor is
    /// enforced by the caller (the CLI) before this is reached.
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        let mut digest = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        // Wipe the transient full-key copy the digest holds (PeerKey.0 is zeroized on Drop; this is the
        // second copy).
        digest.as_mut_slice().zeroize();
        Self(key)
    }
}

/// The per-node peer-authentication ROLLOUT rung (#1067), the `--cluster-peer-auth` ladder. Each rung is
/// a `(send, accept)` policy chosen so that a node's accept-set is a SUPERSET of any adjacent rung's
/// send format — so a cluster is migrated one node at a time up the ladder without a quorum split:
///
/// | rung        | sends  | accepts             |
/// |-------------|--------|---------------------|
/// | `Off`       | plain  | {plain}             |
/// | `Permissive`| plain  | {plain, signed✓}    |
/// | `Signed`    | signed | {plain, signed✓}    |
/// | `Required`  | signed | {signed✓}           |
///
/// `Off` is the default with no secret (byte-for-byte today's plaintext wire). With a secret configured,
/// `Required` is the secure-by-default end state (downgrade-proof); `Permissive`/`Signed` exist only to
/// migrate an already-running cluster up the ladder before flipping the whole fleet to `Required`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerAuthMode {
    /// No peer authentication: send + accept only plain `Raft` frames (today's behavior).
    Off,
    /// Verify a signed frame if one arrives, but do not require it and do not sign yet (migration entry).
    Permissive,
    /// Sign every outbound frame; still accept an un-upgraded peer's plain frame (migration middle).
    Signed,
    /// Sign every outbound frame AND reject any unsigned inbound frame (downgrade-proof end state).
    Required,
}

impl PeerAuthMode {
    /// Whether this node SIGNs its outbound peer frames (emits `RaftAuth`, tag 50).
    #[must_use]
    pub fn sends_authed(self) -> bool {
        matches!(self, PeerAuthMode::Signed | PeerAuthMode::Required)
    }

    /// Whether this node ACCEPTS a plain (unsigned) `Raft` frame (tag 27). `Required` does not.
    #[must_use]
    pub fn accepts_plain(self) -> bool {
        !matches!(self, PeerAuthMode::Required)
    }

    /// Whether this node ACCEPTS (and verifies) a signed `RaftAuth` frame (tag 50). `Off` does not.
    #[must_use]
    pub fn accepts_authed(self) -> bool {
        !matches!(self, PeerAuthMode::Off)
    }
}

/// The peer-wire security policy threaded from the CLI into the cluster runtime (#1067): the optional
/// shared key plus the rollout mode. Built once at serve and shared (behind `Arc`) into the per-peer
/// dialer (sign) and listener (verify) threads. Invariant (enforced by the CLI before construction): a
/// `key` is present iff `mode.accepts_authed()` (any mode above `Off`); `Off` carries no key.
#[derive(Clone, Debug)]
pub struct PeerSecurity {
    /// The shared key, present for any mode above `Off`; `None` for `Off` (plaintext, today's wire).
    pub key: Option<Arc<PeerKey>>,
    /// The rollout rung governing send/accept behavior.
    pub mode: PeerAuthMode,
}

impl PeerSecurity {
    /// The default (no cluster secret configured): plaintext peer wire, byte-for-byte today's behavior.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            key: None,
            mode: PeerAuthMode::Off,
        }
    }
}

impl Default for PeerSecurity {
    fn default() -> Self {
        Self::disabled()
    }
}

/// A peer-authentication verification failure (#1067). Distinct from a framing/decode error so the
/// caller can log the security-relevant reason (rate-limited, never carrying the secret).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerAuthError {
    /// The `RaftAuth` body was shorter than the `[ver: 1][mac: 32]` header — malformed.
    Truncated,
    /// The MAC layout version byte is not one this build understands.
    UnsupportedVersion(u8),
    /// The MAC did not verify: the frame was forged, tampered, or signed with a different secret.
    MacMismatch,
}

impl std::fmt::Display for PeerAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAuthError::Truncated => write!(f, "authenticated peer frame is truncated"),
            PeerAuthError::UnsupportedVersion(v) => {
                write!(f, "unsupported peer-auth MAC version {v}")
            }
            PeerAuthError::MacMismatch => write!(f, "peer frame MAC did not verify"),
        }
    }
}

impl std::error::Error for PeerAuthError {}

/// HMAC-SHA256 (RFC 2104) of the concatenation of `parts`, keyed by `key`. Handles any key length
/// (hash if longer than the block, zero-pad otherwise); the intermediate key-derived pads are zeroized.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block_key = [0u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let digest = hasher.finalize();
        block_key[..32].copy_from_slice(&digest);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; HMAC_BLOCK];
    let mut opad = [0x5cu8; HMAC_BLOCK];
    for i in 0..HMAC_BLOCK {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    for p in parts {
        inner.update(p);
    }
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let out = outer.finalize();
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&out);
    // The pads carry key-derived material; wipe them.
    block_key.zeroize();
    ipad.zeroize();
    opad.zeroize();
    mac
}

/// Produce the BODY of a [`RaftAuth`](ironbus_proto::frame::FrameType::RaftAuth) frame around a raw raft
/// protobuf: `[ver: u8][mac: 32][raft_pb: N]`, where `mac = HMAC-SHA256(key, DOMAIN_LABEL || ver ||
/// raft_pb)`. The caller wraps this body in the standard length/type frame envelope with tag 50.
#[must_use]
pub fn seal(key: &PeerKey, raft_pb: &[u8]) -> Vec<u8> {
    let mac = hmac_sha256(&key.0, &[DOMAIN_LABEL, &[MAC_VERSION], raft_pb]);
    let mut out = Vec::with_capacity(1 + 32 + raft_pb.len());
    out.push(MAC_VERSION);
    out.extend_from_slice(&mac);
    out.extend_from_slice(raft_pb);
    out
}

/// Verify a [`RaftAuth`](ironbus_proto::frame::FrameType::RaftAuth) frame BODY and, on success, return
/// the inner raft protobuf slice (byte-identical to a tag-27 body) for the normal bounded decode. The
/// MAC is recomputed and compared in constant time; verification happens BEFORE the protobuf decode, so
/// an unauthenticated peer never reaches the decoder.
///
/// # Errors
/// [`PeerAuthError`] if the body is truncated, the MAC version is unsupported, or the MAC does not verify.
pub fn open<'a>(key: &PeerKey, body: &'a [u8]) -> Result<&'a [u8], PeerAuthError> {
    if body.len() < 1 + 32 {
        return Err(PeerAuthError::Truncated);
    }
    let ver = body[0];
    if ver != MAC_VERSION {
        return Err(PeerAuthError::UnsupportedVersion(ver));
    }
    let mac = &body[1..33];
    let raft_pb = &body[33..];
    let expected = hmac_sha256(&key.0, &[DOMAIN_LABEL, &[ver], raft_pb]);
    if bool::from(mac.ct_eq(&expected)) {
        Ok(raft_pb)
    } else {
        Err(PeerAuthError::MacMismatch)
    }
}

// --- #1067 Increment 3: the DATA-plane peer wire ------------------------------------------------
//
// The metadata (raft) peer wire is authenticated above; the co-located cluster DATA-plane wire (the
// replication fetch / ISR-report / epoch / committed-HW verbs multiplexed on `DataPlaneLink`) is a
// SEPARATE listener. It reuses the SAME [`PeerKey`] / [`PeerSecurity`] / [`PeerAuthMode`] ladder and the
// SAME hand-rolled [`hmac_sha256`], differing only in (a) a DISTINCT domain label — so one shared cluster
// secret can never cross-authenticate a raft frame as a data frame or vice-versa — and (b) a
// STREAMING-MAC seam ([`data_seal_mac`]) that authenticates the up-to-~8 MiB zero-copy `FetchResponse`
// payload WITHOUT copying it, preserving the leader's single-copy egress fast path (#810/#825).

/// The fixed domain-separation label bound into every DATA-plane peer MAC (#1067 Increment 3),
/// DISTINCT from [`DOMAIN_LABEL`] (the raft-metadata label) so a key can never be cross-used to
/// authenticate a raft frame as a data-plane frame or vice-versa — the two co-located peer wires are
/// cryptographically separated even under one shared cluster secret.
const DATA_DOMAIN_LABEL: &[u8] = b"ironbus.cluster.peer.data.v1";

/// The fixed byte length of a data-plane authentication HEADER — the `[ver: u8][mac: 32]` that
/// [`data_seal`] prepends and [`data_open`] strips. The authenticated data-plane content follows it.
pub const DATA_AUTH_HEADER_LEN: usize = 1 + 32;

/// HMAC-SHA256 over the data-plane domain: `HMAC(key, DATA_DOMAIN_LABEL || [ver] || parts...)`. The
/// `parts` are STREAMED through the HMAC in order and NEVER copied (`sha2::Sha256::update` reads each
/// borrowed slice in place), so the up-to-~8 MiB zero-copy `FetchResponse` payload is authenticated by
/// passing its borrowed slice as a part — no extra payload copy on either seal or open. Because the parts
/// are streamed, a multi-part call is byte-identical to a single-part call over their concatenation (the
/// [`tests::multipart_hmac_equals_the_concatenated_single_part`] invariant), so a frame sealed part-wise
/// via [`data_seal_mac`] verifies against a single contiguous `content` in [`data_open`].
fn data_hmac(key: &PeerKey, ver: u8, parts: &[&[u8]]) -> [u8; 32] {
    let ver = [ver];
    let mut all: Vec<&[u8]> = Vec::with_capacity(2 + parts.len());
    all.push(DATA_DOMAIN_LABEL);
    all.push(&ver);
    all.extend_from_slice(parts);
    hmac_sha256(&key.0, &all)
}

/// Compute JUST the data-plane MAC over the authenticated content `parts` (streamed, no copy) — the seam
/// the zero-copy `FetchResponse` fast path uses. That path materializes the frame body itself (the ONE
/// payload copy, into the outbound buffer) and then calls this over the BORROWED body slice to fill in the
/// MAC in place, so the ~8 MiB run is copied exactly once (never for the MAC). The `content_parts` are the
/// authenticated content `[inner_type][partition][layer_body]`, in order.
#[must_use]
pub fn data_seal_mac(key: &PeerKey, content_parts: &[&[u8]]) -> [u8; 32] {
    data_hmac(key, MAC_VERSION, content_parts)
}

/// Produce a DATA-plane authentication BODY around already-materialized `content`:
/// `[ver: u8][mac: 32][content: N]`, where `mac = HMAC-SHA256(key, DATA_DOMAIN_LABEL || ver || content)`.
/// The generic (small-frame) data-plane encoder wraps its `[inner_type][partition][layer_body]` content
/// with this; the big `FetchResponse` uses [`data_seal_mac`] instead to avoid materializing `content`
/// twice. The caller frames this body with the [`DataPlaneAuth`](ironbus_proto::frame::FrameType::DataPlaneAuth)
/// (tag 51) envelope.
#[must_use]
pub fn data_seal(key: &PeerKey, content: &[u8]) -> Vec<u8> {
    let mac = data_hmac(key, MAC_VERSION, &[content]);
    let mut out = Vec::with_capacity(DATA_AUTH_HEADER_LEN + content.len());
    out.push(MAC_VERSION);
    out.extend_from_slice(&mac);
    out.extend_from_slice(content);
    out
}

/// Verify a DATA-plane authentication BODY and, on success, return the inner authenticated `content`
/// slice (`[inner_type][partition][layer_body]`) for the caller to parse + bounded-decode. The MAC is
/// recomputed over the BORROWED content (no copy — the up-to-~8 MiB payload is read in place) and compared
/// in constant time BEFORE any parse, so an unauthenticated peer never reaches the data-plane decoder.
///
/// # Errors
/// [`PeerAuthError`] if the body is truncated, the MAC version is unsupported, or the MAC does not verify.
pub fn data_open<'a>(key: &PeerKey, body: &'a [u8]) -> Result<&'a [u8], PeerAuthError> {
    if body.len() < DATA_AUTH_HEADER_LEN {
        return Err(PeerAuthError::Truncated);
    }
    let ver = body[0];
    if ver != MAC_VERSION {
        return Err(PeerAuthError::UnsupportedVersion(ver));
    }
    let mac = &body[1..DATA_AUTH_HEADER_LEN];
    let content = &body[DATA_AUTH_HEADER_LEN..];
    let expected = data_hmac(key, ver, &[content]);
    if bool::from(mac.ct_eq(&expected)) {
        Ok(content)
    } else {
        Err(PeerAuthError::MacMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_test_case_1() {
        // RFC 4231 §4.2: key = 0x0b × 20, data = "Hi There".
        let mac = hmac_sha256(&[0x0b; 20], &[b"Hi There"]);
        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_test_case_2() {
        // RFC 4231 §4.3: key = "Jefe", data = "what do ya want for nothing?".
        let mac = hmac_sha256(b"Jefe", &[b"what do ya want for nothing?"]);
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_test_case_6_with_a_key_longer_than_the_block() {
        // RFC 4231 §4.7 (Test Case 6): key = 0xaa × 131 (> 64-byte block, so it is hashed first),
        // data = "Test Using Larger Than Block-Size Key - Hash Key First".
        let mac = hmac_sha256(
            &[0xaa; 131],
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"],
        );
        assert_eq!(
            hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn multipart_hmac_equals_the_concatenated_single_part() {
        let key = PeerKey::from_secret_bytes(b"a-cluster-shared-secret");
        let whole = hmac_sha256(&key.0, &[b"ironbus.cluster.peer.raft.v1\x01hello world"]);
        let split = hmac_sha256(
            &key.0,
            &[b"ironbus.cluster.peer.raft.v1", &[1u8], b"hello world"],
        );
        assert_eq!(whole, split, "streaming the parts must equal one buffer");
    }

    #[test]
    fn seal_then_open_round_trips_and_returns_the_exact_body() {
        let key = PeerKey::from_secret_bytes(b"the-shared-cluster-secret-file-bytes");
        let raft_pb = b"\x08\x01\x10\x2a\x18\x07arbitrary raft protobuf bytes";
        let sealed = seal(&key, raft_pb);
        // Layout: [ver=1][mac:32][raft_pb].
        assert_eq!(sealed.len(), 1 + 32 + raft_pb.len());
        assert_eq!(sealed[0], MAC_VERSION);
        let opened = open(&key, &sealed).expect("a freshly sealed frame verifies");
        assert_eq!(opened, raft_pb, "open returns the exact inner raft body");
    }

    #[test]
    fn a_tampered_body_fails_verification() {
        let key = PeerKey::from_secret_bytes(b"secret");
        let mut sealed = seal(&key, b"payload");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01; // flip a bit in the raft_pb
        assert_eq!(open(&key, &sealed), Err(PeerAuthError::MacMismatch));
    }

    #[test]
    fn a_tampered_mac_fails_verification() {
        let key = PeerKey::from_secret_bytes(b"secret");
        let mut sealed = seal(&key, b"payload");
        sealed[1] ^= 0x80; // flip a bit in the MAC
        assert_eq!(open(&key, &sealed), Err(PeerAuthError::MacMismatch));
    }

    #[test]
    fn a_different_secret_fails_verification() {
        let a = PeerKey::from_secret_bytes(b"secret-a");
        let b = PeerKey::from_secret_bytes(b"secret-b");
        let sealed = seal(&a, b"payload");
        assert_eq!(open(&b, &sealed), Err(PeerAuthError::MacMismatch));
    }

    #[test]
    fn a_truncated_or_wrong_version_body_is_rejected() {
        let key = PeerKey::from_secret_bytes(b"secret");
        assert_eq!(open(&key, &[]), Err(PeerAuthError::Truncated));
        assert_eq!(open(&key, &[1u8; 10]), Err(PeerAuthError::Truncated));
        let mut sealed = seal(&key, b"payload");
        sealed[0] = 2; // an unknown MAC version
        assert_eq!(
            open(&key, &sealed),
            Err(PeerAuthError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn the_key_and_secret_are_never_in_debug() {
        let key = PeerKey::from_secret_bytes(b"top-secret-bytes");
        assert_eq!(format!("{key:?}"), "PeerKey(<redacted>)");
        let sec = PeerSecurity {
            key: Some(Arc::new(key)),
            mode: PeerAuthMode::Required,
        };
        let s = format!("{sec:?}");
        assert!(s.contains("Required") && s.contains("redacted"));
        assert!(!s.contains("top-secret"));
    }

    // --- #1067 Increment 3: the DATA-plane seal/open + streaming-MAC + domain separation. ---

    #[test]
    fn data_seal_then_open_round_trips_and_returns_the_exact_content() {
        let key = PeerKey::from_secret_bytes(b"the-shared-cluster-secret-file-bytes");
        // content = [inner_type][partition:8][layer body] — arbitrary bytes here.
        let content = b"\x21\x00\x00\x00\x00\x00\x00\x00\x00some data-plane layer body";
        let sealed = data_seal(&key, content);
        assert_eq!(sealed.len(), DATA_AUTH_HEADER_LEN + content.len());
        assert_eq!(sealed[0], MAC_VERSION);
        let opened = data_open(&key, &sealed).expect("a freshly sealed data frame verifies");
        assert_eq!(
            opened, content,
            "data_open returns the exact authenticated content"
        );
    }

    #[test]
    fn data_seal_mac_streamed_parts_equal_the_single_part_body_mac() {
        // The zero-copy fast path streams the content as multiple borrowed parts; it MUST produce the
        // exact MAC `data_seal`/`data_open` compute over the contiguous content, or a fast-path frame
        // would fail verification. This is the property that lets the 8 MiB payload be authenticated by
        // reference (no copy) while still verifying against the received contiguous body.
        let key = PeerKey::from_secret_bytes(b"cluster-secret");
        let inner_type = [33u8];
        let partition = 7u64.to_le_bytes();
        let header = b"\x10\x00header";
        let payload = b"verbatim frame bytes (stand-in for the zero-copy run)";
        let streamed = data_seal_mac(&key, &[&inner_type, &partition, header, payload]);
        let mut contiguous = Vec::new();
        contiguous.extend_from_slice(&inner_type);
        contiguous.extend_from_slice(&partition);
        contiguous.extend_from_slice(header);
        contiguous.extend_from_slice(payload);
        let via_seal = data_seal(&key, &contiguous);
        assert_eq!(
            &via_seal[1..DATA_AUTH_HEADER_LEN],
            &streamed[..],
            "the streamed multi-part MAC must equal the single-buffer body MAC"
        );
        // And a body assembled from the streamed MAC verifies through data_open.
        let mut body = Vec::new();
        body.push(MAC_VERSION);
        body.extend_from_slice(&streamed);
        body.extend_from_slice(&contiguous);
        assert_eq!(data_open(&key, &body).expect("verifies"), &contiguous[..]);
    }

    #[test]
    fn a_tampered_data_body_fails_verification() {
        let key = PeerKey::from_secret_bytes(b"secret");
        let mut sealed = data_seal(&key, b"payload-content");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(data_open(&key, &sealed), Err(PeerAuthError::MacMismatch));
    }

    #[test]
    fn a_data_frame_with_a_different_secret_is_rejected() {
        let a = PeerKey::from_secret_bytes(b"secret-a");
        let b = PeerKey::from_secret_bytes(b"secret-b");
        let sealed = data_seal(&a, b"payload-content");
        assert_eq!(data_open(&b, &sealed), Err(PeerAuthError::MacMismatch));
    }

    #[test]
    fn a_truncated_or_wrong_version_data_body_is_rejected() {
        let key = PeerKey::from_secret_bytes(b"secret");
        assert_eq!(data_open(&key, &[]), Err(PeerAuthError::Truncated));
        assert_eq!(data_open(&key, &[1u8; 10]), Err(PeerAuthError::Truncated));
        let mut sealed = data_seal(&key, b"payload");
        sealed[0] = 2;
        assert_eq!(
            data_open(&key, &sealed),
            Err(PeerAuthError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn the_raft_and_data_domains_do_not_cross_authenticate() {
        // The SAME key seals a raft body and a data body over the SAME bytes; the two MACs differ (the
        // domain label is bound in), so a raft-sealed frame can never be replayed as a data frame.
        let key = PeerKey::from_secret_bytes(b"one-cluster-secret");
        let bytes = b"identical inner bytes";
        let raft = seal(&key, bytes); // [ver][mac][bytes] under DOMAIN_LABEL
        let data = data_seal(&key, bytes); // [ver][mac][bytes] under DATA_DOMAIN_LABEL
        assert_eq!(raft.len(), data.len());
        assert_ne!(
            &raft[1..33],
            &data[1..33],
            "the raft and data-plane MACs of the same bytes under the same key must differ"
        );
        // Cross-open fails: a data body does not verify with the raft `open`, and vice-versa.
        assert_eq!(open(&key, &data), Err(PeerAuthError::MacMismatch));
        assert_eq!(data_open(&key, &raft), Err(PeerAuthError::MacMismatch));
    }

    #[test]
    fn the_rollout_ladder_send_accept_matrix_is_monotone() {
        use PeerAuthMode::{Off, Permissive, Required, Signed};
        // sends_authed: off/permissive send plain; signed/required sign.
        assert!(!Off.sends_authed() && !Permissive.sends_authed());
        assert!(Signed.sends_authed() && Required.sends_authed());
        // accepts_plain: everyone but Required.
        assert!(Off.accepts_plain() && Permissive.accepts_plain() && Signed.accepts_plain());
        assert!(!Required.accepts_plain());
        // accepts_authed: everyone but Off.
        assert!(!Off.accepts_authed());
        assert!(
            Permissive.accepts_authed() && Signed.accepts_authed() && Required.accepts_authed()
        );
    }
}
