// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded, fail-closed peer transport for the metadata Raft group (V2-C1 peer transport, #667).
//!
//! This module is the wire that carries `raft::eraftpb::Message`s between metadata-Raft cluster
//! nodes: a node serializes the outbound messages its [`MetadataRaftGroup::drive_ready`] surfaces
//! and sends them to the addressed peer, and a node decodes the bytes it receives from a peer back
//! into an `eraftpb::Message` and feeds them to [`MetadataRaftGroup::step`]. It is the FIRST place
//! in IronBus that parses UNTRUSTED PEER BYTES through the vendored protobuf-2 `eraftpb` codec, so
//! it is built around one rule: **treat every incoming byte as adversarial**.
//!
//! ## The security core: why this module exists separately (RUSTSEC-2024-0437)
//!
//! `raft` (tikv/raft-rs) parses Raft messages with the pure-Rust `protobuf` 2.x runtime. That
//! runtime is flagged by [RUSTSEC-2024-0437] (the advisory's `patched = ">= 3.7.2"` flags every
//! version below 3.7.2, so IronBus's pinned `protobuf 2.28.0` is in range): an uncontrolled
//! recursion `DoS` whose named affected function is `CodedInputStream::skip_group` — a hostile,
//! deeply-nested message overflows the stack while being parsed. Until this issue NO peer bytes were
//! ever parsed (the metadata group ran in-process, decoding only entries it itself proposed), so the
//! advisory was UNREACHABLE and `deny.toml` scoped-ignored it. This module makes the codec reachable
//! with attacker input, so it MUST bound the decode before the ignore can be removed. It does so on
//! two independent axes, BOTH enforced before/at decode, and FAILS CLOSED on any violation:
//!
//! 1. **A hard maximum incoming message SIZE** ([`MAX_RAFT_MSG_BYTES`]). The frame envelope's
//!    length prefix is checked against this cap BEFORE the body is read or the decoder is entered,
//!    so an oversized frame is rejected without allocating a large buffer or running the parser. A
//!    metadata Raft message is tiny (a few control fields plus, at most, a bounded run of small log
//!    entries); 1 MiB is already orders of magnitude of head-room, so a larger frame is hostile.
//!    This BOUNDS THE INPUT the parser ever sees: every nested level on the wire costs at least one
//!    tag byte, so the cap also bounds the maximum recursion any malformed body could request.
//!
//! 2. **A tight protobuf RECURSION-DEPTH bound** ([`RAFT_DECODE_RECURSION_LIMIT`]). The decode does
//!    NOT use protobuf's defaulted parse (which leaves the recursion limit at the library default of
//!    100 — still deep enough to overflow a small stack on the generic nested-message path). Instead
//!    it builds a `CodedInputStream` over the (already size-capped) body and calls
//!    `set_recursion_limit(16)` before merging: every descent into a nested message field calls the
//!    runtime's `incr_recursion`, which returns a typed `OverRecursionLimit` ERROR (never a panic)
//!    once the bound is crossed. An `eraftpb::Message` is SHALLOW — its deepest legitimate nesting
//!    is `Message -> Snapshot -> SnapshotMetadata -> ConfState` (four levels) — so 16 accepts every
//!    valid message with margin while bounding any nested-message recursion to a tiny, stack-safe
//!    depth.
//!
//! How the two together close RUSTSEC-2024-0437 on protobuf 2.28: the advisory's named
//! `skip_group` deep-recursion was introduced in protobuf's 3.x rewrite of group skipping; in the
//! pinned **2.28.0** runtime `skip_group` does NOT recurse into a nested start-group — it returns a
//! typed `UnexpectedWireType` error (verified directly: a 100k-deep nested-group body decodes to a
//! typed `Decode` error on a 256 KiB stack, no overflow — see
//! [`tests::deeply_nested_unknown_groups_are_rejected_not_a_stack_overflow`]). The only other
//! recursion path, generic nested KNOWN-message fields, is bounded by the explicit
//! `set_recursion_limit(16)` (verified in
//! [`tests::the_recursion_limit_is_actually_applied_to_the_decode_stream`]). So on 2.28.0 the decode
//! is genuinely size- and depth-bounded and the recursion `DoS` is defended in code and tested.
//!
//! On the `deny.toml` ignore: RUSTSEC-2024-0437 is a VERSION-MATCH advisory (`patched = ">= 3.7.2"`),
//! so `cargo deny` flags `protobuf 2.28.0` purely by its version and has no way to see this runtime
//! bound — and the dep cannot be upgraded under the 1.78 MSRV (raft 0.7's `protobuf-codec` is bound
//! to protobuf 2.x). So the ignore is RETAINED but its justification is now the residual version
//! match only, with the recursion `DoS` itself bounded + fuzzed here. It is dropped the moment raft-rs
//! can ride a fixed protobuf. See the `deny.toml` ignore comment for the full rationale.
//!
//! On ANY malformed / oversized / over-deep / trailing-garbage input the decoder returns a typed
//! [`PeerWireError`] and the caller drops the frame (and may drop the connection); it NEVER panics,
//! NEVER unbounded-allocates, and NEVER stack-overflows. A bad peer cannot OOM or crash the node.
//!
//! ## Peer identity (the C1-I4 peer-id validation, applied to the wire)
//!
//! IronBus is plaintext TCP today (mTLS is a separate roadmap item), so this transport cannot yet
//! cryptographically authenticate a peer. It does, however, bind every accepted message to a
//! KNOWN-MEMBERSHIP peer id: a decoded message's `from` field is validated against the set of node
//! ids the metadata group's current `ConfState` knows (voters + learners) via [`PeerRegistry`]. A
//! frame whose claimed sender is `0` (the raft `INVALID_ID`) or is not a known member is rejected
//! with [`PeerWireError::UnknownPeer`] and never reaches `step`. This is the wire-side companion of
//! the C1-I4 membership peer-id validation: an unexpected / phantom peer cannot inject Raft state.
//!
//! ## Scope (what this module is, and what is deferred)
//!
//! This is the TESTABLE transport LAYER: the bounded codec ([`encode_raft_message`] /
//! [`decode_raft_message`]), the frame helpers that reuse `ironbus-proto`'s `[len][type][body]`
//! envelope discipline, the peer-id registry, and a [`PeerLink`] over any `Read + Write` (a real
//! `TcpStream` in production, an in-memory pipe in tests) that reads bounded frames and feeds a
//! `step` sink, and serializes outbound messages to a peer. It is driven here by a loopback test
//! harness. The FULL `serve`-path wiring (a cluster listener/dialer bound to a multi-node config,
//! the running broker actually replicating) is the next step and is DEFERRED — see the module
//! note in [`crate::cluster`]; C2 replication, snapshot transfer, and TLS are out of scope.
//!
//! [RUSTSEC-2024-0437]: https://rustsec.org/advisories/RUSTSEC-2024-0437

use std::collections::BTreeSet;
use std::io::{self, Read, Write};

use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType,
};
use protobuf::{CodedInputStream, Message as _};
use raft::eraftpb::Message;

/// The hard maximum size, in bytes, of a single incoming peer Raft message body (the protobuf
/// encoding of one `eraftpb::Message`). Checked against the frame's length prefix BEFORE the body
/// is read or decoded, so an oversized frame is rejected without allocating or parsing.
///
/// A metadata Raft message is small: heartbeats / votes / appends carry a handful of `u64` control
/// fields and, at most, a bounded run of small metadata log entries (membership / placement /
/// config commands, not asset data — the metadata group is O(quorum), never O(assets)). 1 MiB is
/// already vast head-room; a peer message larger than this is treated as hostile and dropped. This
/// is the SIZE half of the RUSTSEC-2024-0437 bound (the cap that stops an unbounded allocation and
/// caps the bytes the recursion-bounded parser ever sees).
pub const MAX_RAFT_MSG_BYTES: u32 = 1024 * 1024;

/// The protobuf recursion-depth limit applied to peer Raft message decode — the DEPTH half of the
/// RUSTSEC-2024-0437 bound.
///
/// protobuf 2.x's `CodedInputStream` defaults its recursion limit to 100; that is still deep enough
/// to overflow a small thread stack with a crafted, deeply-nested message (the advisory). We set a
/// far tighter bound: a valid `eraftpb::Message` nests at most four levels
/// (`Message -> Snapshot -> SnapshotMetadata -> ConfState`), so 16 accepts every legitimate message
/// with comfortable margin while rejecting any deeper (hostile) nesting with a typed
/// `OverRecursionLimit` error — never a panic, never a stack overflow.
pub const RAFT_DECODE_RECURSION_LIMIT: u32 = 16;

/// A typed error from the peer wire: every failure mode of framing / decoding / authenticating an
/// untrusted peer message. The transport ALWAYS surfaces one of these rather than panicking,
/// over-allocating, or recursing without bound, so a hostile peer is contained to a dropped frame
/// (or, at the caller's discretion, a dropped connection).
#[derive(Debug)]
pub enum PeerWireError {
    /// The frame's length prefix exceeded the hard size cap ([`MAX_RAFT_MSG_BYTES`]) — rejected
    /// before the body was read or the decoder was entered (the SIZE bound). Carries the offending
    /// length so an operator can see how oversized the frame claimed to be.
    Oversized {
        /// The frame length the peer claimed.
        len: u64,
    },
    /// The frame envelope itself was malformed (an empty / zero-length frame). The body never
    /// reached the protobuf decoder.
    Frame(FrameError),
    /// The frame carried a type tag other than [`FrameType::Raft`] on the peer link. A peer link
    /// only ever carries Raft messages; anything else is rejected rather than misinterpreted.
    UnexpectedFrameType {
        /// The raw type tag seen.
        tag: u8,
    },
    /// The body was not a decodable `eraftpb::Message` under the size + recursion bounds: a
    /// malformed wire encoding, a too-deeply-nested message (the recursion bound fired —
    /// RUSTSEC-2024-0437 rejected here), or trailing garbage after the message. Fail-closed: the
    /// frame is dropped, nothing is fed to `step`.
    Decode(protobuf::ProtobufError),
    /// The decoded message's claimed sender (`from`) is the raft `INVALID_ID` (0) or is not a known
    /// member of the current `ConfState` (voters + learners) — the peer-id authentication check.
    /// The message is rejected and never reaches `step`.
    UnknownPeer {
        /// The unrecognized claimed sender id.
        from: u64,
    },
    /// An underlying IO error reading from / writing to the peer connection.
    Io(io::Error),
}

impl core::fmt::Display for PeerWireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PeerWireError::Oversized { len } => write!(
                f,
                "peer raft frame length {len} exceeds the {MAX_RAFT_MSG_BYTES}-byte cap; rejected pre-decode"
            ),
            PeerWireError::Frame(e) => write!(f, "peer raft frame envelope error: {e}"),
            PeerWireError::UnexpectedFrameType { tag } => {
                write!(f, "peer link carried unexpected frame type tag {tag} (expected Raft)")
            }
            PeerWireError::Decode(e) => {
                write!(f, "peer raft message decode error (size+depth bounded): {e}")
            }
            PeerWireError::UnknownPeer { from } => {
                write!(f, "peer raft message from unknown / invalid node id {from}; rejected")
            }
            PeerWireError::Io(e) => write!(f, "peer link IO error: {e}"),
        }
    }
}

impl std::error::Error for PeerWireError {}

impl From<io::Error> for PeerWireError {
    fn from(e: io::Error) -> Self {
        PeerWireError::Io(e)
    }
}

/// Encode an outbound Raft message to its on-wire frame bytes: the protobuf-2 encoding of the
/// `eraftpb::Message`, wrapped in IronBus's `[len][type=Raft][body]` envelope.
///
/// The encoded body is bounded the same way the decoder bounds an incoming one: if a (locally
/// produced) message somehow encodes larger than [`MAX_RAFT_MSG_BYTES`], framing rejects it rather
/// than emitting a frame a conforming peer would itself reject — keeping send and receive symmetric.
///
/// # Errors
///
/// Returns [`PeerWireError::Decode`] if protobuf serialization fails (it should not for a
/// well-formed local message), or [`PeerWireError::Frame`] / [`PeerWireError::Oversized`] if the
/// encoded body cannot be framed within the cap.
pub fn encode_raft_message(msg: &Message) -> Result<Vec<u8>, PeerWireError> {
    let body = msg.write_to_bytes().map_err(PeerWireError::Decode)?;
    if body.len() as u64 > u64::from(MAX_RAFT_MSG_BYTES) {
        return Err(PeerWireError::Oversized {
            len: body.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(body.len() + 5);
    encode_frame(FrameType::Raft, &body, &mut out).map_err(|e| match e {
        FrameError::FrameTooLarge { len } => PeerWireError::Oversized { len },
        e @ FrameError::EmptyFrame => PeerWireError::Frame(e),
    })?;
    Ok(out)
}

/// Decode an untrusted peer Raft message BODY (the protobuf bytes inside a frame) into an
/// `eraftpb::Message`, under the size + recursion bounds. This is the SECURITY CORE.
///
/// Preconditions enforced by the caller's framing: `body` is at most [`MAX_RAFT_MSG_BYTES`] long
/// (the frame length prefix was checked against the cap before the body was read). This function
/// then bounds the protobuf RECURSION depth to [`RAFT_DECODE_RECURSION_LIMIT`] and merges; a
/// deeper-than-bound nesting (RUSTSEC-2024-0437) returns a typed `OverRecursionLimit` error rather
/// than overflowing the stack. Trailing bytes after the message are rejected (`check_eof`).
///
/// This function NEVER panics, NEVER allocates beyond the size of the (already-capped) input, and
/// NEVER recurses past the depth bound.
///
/// # Errors
///
/// Returns [`PeerWireError::Decode`] on any malformed, over-deep, or trailing-garbage input.
pub fn decode_raft_message(body: &[u8]) -> Result<Message, PeerWireError> {
    // Belt-and-suspenders: even though the frame layer caps the length prefix, never decode a body
    // larger than the cap (a caller that bypassed framing cannot smuggle an oversized body in).
    if body.len() as u64 > u64::from(MAX_RAFT_MSG_BYTES) {
        return Err(PeerWireError::Oversized {
            len: body.len() as u64,
        });
    }
    let mut is = CodedInputStream::from_bytes(body);
    // THE DEPTH BOUND. protobuf 2.x defaults this to 100 (deep enough to overflow a small stack —
    // RUSTSEC-2024-0437); pin it tight. Every nested-message descent checks it and returns a typed
    // OverRecursionLimit error past the bound, so a deeply-nested hostile message is rejected, not
    // a panic / stack overflow.
    is.set_recursion_limit(RAFT_DECODE_RECURSION_LIMIT);
    let mut msg = Message::new();
    msg.merge_from(&mut is).map_err(PeerWireError::Decode)?;
    // Reject trailing garbage after a well-formed message (fail-closed, no silent acceptance).
    is.check_eof().map_err(PeerWireError::Decode)?;
    Ok(msg)
}

/// The set of node ids the local metadata group currently knows as members (voters + learners),
/// used to authenticate the claimed sender of an incoming peer message.
///
/// This is the wire-side application of the C1-I4 peer-id validation: a message is only fed to
/// `step` if its `from` is a known member. The registry is refreshed from the group's current
/// `ConfState` (which changes only through committed, peer-id-validated membership changes).
#[derive(Clone, Debug, Default)]
pub struct PeerRegistry {
    members: BTreeSet<u64>,
}

impl PeerRegistry {
    /// An empty registry (no peers known yet).
    #[must_use]
    pub fn new() -> Self {
        Self {
            members: BTreeSet::new(),
        }
    }

    /// Build a registry from the current voter + learner sets (e.g. a `ConfState`'s
    /// `get_voters()` and `get_learners()`). The local node id may be included or not; it is never
    /// a valid `from` on an inbound message in practice, but including it is harmless.
    #[must_use]
    pub fn from_members(voters: &[u64], learners: &[u64]) -> Self {
        let mut members = BTreeSet::new();
        for &v in voters {
            if v != raft::INVALID_ID {
                members.insert(v);
            }
        }
        for &l in learners {
            if l != raft::INVALID_ID {
                members.insert(l);
            }
        }
        Self { members }
    }

    /// Is `node` a known member (and not the invalid id)?
    #[must_use]
    pub fn is_known(&self, node: u64) -> bool {
        node != raft::INVALID_ID && self.members.contains(&node)
    }

    /// Validate a decoded message's claimed sender against the known membership.
    ///
    /// # Errors
    ///
    /// Returns [`PeerWireError::UnknownPeer`] if `msg.from` is the invalid id or is not a known
    /// member, so the caller drops the message before it reaches `step`.
    pub fn authenticate(&self, msg: &Message) -> Result<(), PeerWireError> {
        let from = msg.get_from();
        if self.is_known(from) {
            Ok(())
        } else {
            Err(PeerWireError::UnknownPeer { from })
        }
    }
}

/// Decode an UNTRUSTED peer FRAME (the full `[len][type][body]` envelope bytes for exactly one
/// frame) into an authenticated `eraftpb::Message`, applying every bound: the size cap (the frame
/// length prefix is checked against [`MAX_RAFT_MSG_BYTES`] before the body is taken), the frame
/// type check (must be [`FrameType::Raft`]), the recursion-bounded protobuf decode, and the
/// peer-id authentication against `registry`.
///
/// `input` must contain at least one complete frame; on success the message and the number of bytes
/// the frame consumed are returned, so a stream reader can advance. If `input` does not yet hold a
/// complete frame, `Ok(None)` is returned (the caller reads more bytes). Every failure is a typed
/// [`PeerWireError`]; this function never panics or over-allocates.
///
/// # Errors
///
/// See [`PeerWireError`] for every rejection mode (oversized, malformed frame, wrong type,
/// undecodable / over-deep body, unknown peer).
pub fn decode_peer_frame(
    input: &[u8],
    registry: &PeerRegistry,
) -> Result<Option<(Message, usize)>, PeerWireError> {
    // The SIZE bound is enforced HERE, by capping the frame length prefix at MAX_RAFT_MSG_BYTES
    // (plus the one type byte) BEFORE the body is sliced out or the decoder is entered. An
    // oversized frame is rejected without allocating its body.
    match decode_frame_with_cap(input, MAX_RAFT_MSG_BYTES + 1) {
        Ok(FrameDecode::Frame {
            type_tag,
            body,
            consumed,
        }) => {
            let Some(FrameType::Raft) = FrameType::from_u8(type_tag) else {
                return Err(PeerWireError::UnexpectedFrameType { tag: type_tag });
            };
            let msg = decode_raft_message(body)?;
            registry.authenticate(&msg)?;
            Ok(Some((msg, consumed)))
        }
        Ok(FrameDecode::Incomplete { .. }) => Ok(None),
        Err(FrameError::FrameTooLarge { len }) => Err(PeerWireError::Oversized { len }),
        Err(other) => Err(PeerWireError::Frame(other)),
    }
}

/// A bidirectional peer link over any byte stream (`Read + Write`): a real `TcpStream` in
/// production, an in-memory pipe in tests. It frames outbound Raft messages with [`send`] and
/// reads bounded, authenticated inbound messages with [`recv_into`], applying every bound in this
/// module on the receive path.
///
/// The link is deliberately TRANSPORT-AGNOSTIC and synchronous, matching the broker's blocking
/// `std::net` connection model: it carries no async runtime and no IronBus engine state, so it is
/// trivially driven by a loopback harness (the tests below) without a `serve` integration.
///
/// [`send`]: PeerLink::send
/// [`recv_into`]: PeerLink::recv_into
pub struct PeerLink<S> {
    stream: S,
    /// Accumulated, not-yet-consumed inbound bytes (a partial frame may straddle reads).
    inbuf: Vec<u8>,
}

impl<S: Read + Write> PeerLink<S> {
    /// Wrap a byte stream as a peer link.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            inbuf: Vec::new(),
        }
    }

    /// Serialize and send one outbound Raft message to the peer (the `drive_ready` -> wire path).
    ///
    /// # Errors
    ///
    /// Returns [`PeerWireError::Decode`] / [`PeerWireError::Oversized`] if the message cannot be
    /// framed within the cap, or [`PeerWireError::Io`] on a write failure.
    pub fn send(&mut self, msg: &Message) -> Result<(), PeerWireError> {
        let frame = encode_raft_message(msg)?;
        self.stream.write_all(&frame)?;
        Ok(())
    }

    /// Read exactly one inbound peer message, blocking until a full frame arrives (or the peer
    /// closes). Returns `Ok(None)` if the peer closed the connection cleanly with no partial frame
    /// pending. Every bound in this module is applied: oversized frames are rejected pre-allocation,
    /// the protobuf decode is recursion-bounded, and the sender is authenticated against `registry`.
    ///
    /// On a [`PeerWireError`] the caller should drop the frame and, for a framing/decode/auth
    /// error (a misbehaving or hostile peer), drop the connection — the link's buffer is left as-is
    /// so the caller can choose its policy.
    ///
    /// # Errors
    ///
    /// See [`PeerWireError`]. A decode/auth error means the peer sent something invalid or hostile;
    /// the node is never harmed (no panic, no OOM, no stack overflow).
    pub fn recv(&mut self, registry: &PeerRegistry) -> Result<Option<Message>, PeerWireError> {
        // A heap read buffer (not a large stack array): 64 KiB per read pass.
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            // Try to decode a complete frame from what we already have.
            if let Some((msg, consumed)) = decode_peer_frame(&self.inbuf, registry)? {
                self.inbuf.drain(..consumed);
                return Ok(Some(msg));
            }
            // Need more bytes; read from the peer.
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                // Peer closed. A clean close with no partial frame is end-of-stream;
                // a close mid-frame is a truncated frame error.
                if self.inbuf.is_empty() {
                    return Ok(None);
                }
                return Err(PeerWireError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed mid-frame",
                )));
            }
            self.inbuf.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use raft::eraftpb::{Entry, MessageType, Snapshot};

    /// A valid metadata Raft message (an AppendEntries-shaped one with a couple of small entries),
    /// the kind the transport carries in practice.
    fn sample_message(from: u64, to: u64) -> Message {
        let mut m = Message::new();
        m.set_msg_type(MessageType::MsgAppend);
        m.set_from(from);
        m.set_to(to);
        m.set_term(7);
        m.set_log_term(6);
        m.set_index(42);
        m.set_commit(40);
        let mut e1 = Entry::new();
        e1.set_term(6);
        e1.set_index(43);
        e1.set_data(b"membership-cmd".to_vec().into());
        let mut e2 = Entry::new();
        e2.set_term(6);
        e2.set_index(44);
        e2.set_data(b"placement-cmd".to_vec().into());
        m.set_entries(vec![e1, e2].into());
        m
    }

    fn registry_with(members: &[u64]) -> PeerRegistry {
        PeerRegistry::from_members(members, &[])
    }

    // --- Round-trip: a valid message encodes, frames, decodes, and authenticates back to itself. ---

    #[test]
    fn valid_message_round_trips_through_the_codec() {
        let original = sample_message(2, 1);
        let frame = encode_raft_message(&original).expect("encode");
        let registry = registry_with(&[1, 2, 3]);
        let (decoded, consumed) = decode_peer_frame(&frame, &registry)
            .expect("decode ok")
            .expect("a complete frame");
        assert_eq!(consumed, frame.len());
        assert_eq!(decoded, original, "round-trip must be byte-faithful");
    }

    #[test]
    fn round_trip_over_an_in_memory_peer_link() {
        // node B's link reading what node A's link wrote (a loopback pipe via a Vec cursor).
        let original = sample_message(3, 1);
        let mut wire = Vec::new();
        // "Send" by encoding into the shared wire buffer.
        wire.extend_from_slice(&encode_raft_message(&original).expect("encode"));
        let mut link = PeerLink::new(io::Cursor::new(wire));
        let registry = registry_with(&[1, 3]);
        let got = link.recv(&registry).expect("recv ok").expect("a message");
        assert_eq!(got, original);
    }

    // --- The SIZE bound: an oversized frame is rejected pre-allocation. ---

    #[test]
    fn an_oversized_frame_is_rejected_before_allocation() {
        // Hand-craft a frame whose length prefix claims more than the cap, with NO body present:
        // the decoder must reject on the prefix alone, never trying to allocate the claimed body.
        let mut frame = Vec::new();
        let claimed = MAX_RAFT_MSG_BYTES + 100; // type byte + body, over the cap
        frame.extend_from_slice(&claimed.to_le_bytes());
        frame.push(FrameType::Raft.as_u8());
        // Deliberately NO body bytes — proves rejection is pre-allocation, length-prefix-only.
        let registry = registry_with(&[1, 2]);
        match decode_peer_frame(&frame, &registry) {
            Err(PeerWireError::Oversized { len }) => {
                assert_eq!(len, u64::from(claimed));
            }
            other => panic!("expected Oversized, got {other:?}"),
        }
    }

    // --- Peer-id auth: a frame from an unknown peer id is rejected. ---

    #[test]
    fn a_frame_from_an_unknown_peer_id_is_rejected() {
        let msg = sample_message(99, 1); // 99 is not a member
        let frame = encode_raft_message(&msg).expect("encode");
        let registry = registry_with(&[1, 2, 3]);
        match decode_peer_frame(&frame, &registry) {
            Err(PeerWireError::UnknownPeer { from }) => assert_eq!(from, 99),
            other => panic!("expected UnknownPeer, got {other:?}"),
        }
    }

    #[test]
    fn a_frame_claiming_the_invalid_zero_id_is_rejected() {
        let msg = sample_message(0, 1); // INVALID_ID
        let frame = encode_raft_message(&msg).expect("encode");
        let registry = registry_with(&[1, 2, 3]);
        match decode_peer_frame(&frame, &registry) {
            Err(PeerWireError::UnknownPeer { from }) => assert_eq!(from, 0),
            other => panic!("expected UnknownPeer for invalid id, got {other:?}"),
        }
    }

    #[test]
    fn an_unexpected_frame_type_on_the_peer_link_is_rejected() {
        // A Ping frame (tag 3) does not belong on the peer link.
        let mut frame = Vec::new();
        encode_frame(FrameType::Ping, b"x", &mut frame).expect("frame");
        let registry = registry_with(&[1, 2]);
        match decode_peer_frame(&frame, &registry) {
            Err(PeerWireError::UnexpectedFrameType { tag }) => {
                assert_eq!(tag, FrameType::Ping.as_u8());
            }
            other => panic!("expected UnexpectedFrameType, got {other:?}"),
        }
    }

    // --- THE RUSTSEC-2024-0437 CASE: a deeply-nested hostile protobuf is rejected with a typed
    //     error, NEVER a panic / stack overflow. ---
    //
    // RUSTSEC-2024-0437 is the protobuf-2.x uncontrolled-recursion DoS; the advisory names
    // `CodedInputStream::skip_group` (the unknown-field START-GROUP skip path) as the affected
    // function. The two attack shapes a hostile peer can send are:
    //   (a) deeply-nested unknown START-GROUP fields (the named `skip_group` vector), and
    //   (b) deeply-nested KNOWN length-delimited message fields (the generic nested-message vector
    //       that `set_recursion_limit` exists to bound).
    // Our decoder must reject BOTH with a typed `Decode` error and never overflow the stack. We run
    // each on a deliberately SMALL (256 KiB) thread stack so a genuine unbounded recursion WOULD
    // overflow — proving the bound (the recursion limit and/or the runtime's wire-type rejection),
    // not luck or a large default stack, is what contains the attack.

    fn write_varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
    }

    /// Vector (a): `depth` nested unknown START-GROUP tags (`field 1, wire 3`) followed by the
    /// matching END-GROUP tags — the exact `skip_group` shape RUSTSEC-2024-0437 names.
    fn deeply_nested_group_bytes(depth: usize) -> Vec<u8> {
        let mut body = Vec::new();
        for _ in 0..depth {
            write_varint(&mut body, (1 << 3) | 3); // start group, field 1
        }
        for _ in 0..depth {
            write_varint(&mut body, (1 << 3) | 4); // end group, field 1
        }
        body
    }

    /// Decode a hostile body on a 256 KiB stack and assert it is a typed `Decode` error, never a
    /// panic / overflow.
    fn assert_rejected_on_small_stack(body: Vec<u8>) {
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let registry = registry_with(&[1, 2, 3]);
                let mut framed = Vec::new();
                encode_frame(FrameType::Raft, &body, &mut framed).expect("frame");
                // Must be a typed Decode error (an invalid nested wire type or over-recursion),
                // never a panic / stack overflow.
                matches!(
                    decode_peer_frame(&framed, &registry),
                    Err(PeerWireError::Decode(_))
                )
            })
            .expect("spawn");
        let rejected = handle
            .join()
            .expect("the decode thread must NOT overflow or panic on hostile deep nesting");
        assert!(
            rejected,
            "hostile deep nesting must be a typed Decode error"
        );
    }

    #[test]
    fn deeply_nested_unknown_groups_are_rejected_not_a_stack_overflow() {
        // The named RUSTSEC-2024-0437 `skip_group` vector (deeply-nested unknown START-GROUP
        // fields), an order of magnitude past any sane depth, run on a 256 KiB stack. protobuf
        // 2.28's `skip_group` rejects a nested start-group with a typed `UnexpectedWireType` error
        // rather than recursing — fail-closed, no overflow.
        assert_rejected_on_small_stack(deeply_nested_group_bytes(100_000));
    }

    #[test]
    fn the_recursion_limit_is_actually_applied_to_the_decode_stream() {
        // Prove the DEPTH bound is WIRED INTO the decode path (defense-in-depth for the generic
        // nested-known-message recursion). eraftpb's type graph is not self-referential (its deepest
        // real nesting is 4: Message -> Snapshot -> SnapshotMetadata -> ConfState), so no eraftpb
        // input can climb the recursion counter past ~4 — meaning on 2.28.0 the PRIMARY RUSTSEC
        // defense is the `skip_group` wire-type rejection plus the size cap, and the recursion limit
        // is a belt-and-suspenders bound. We still verify the limit is genuinely applied: a
        // recursion limit of 0 makes the FIRST nested-message descent fail with OverRecursionLimit,
        // proving `set_recursion_limit` is honored on this exact decode path (a message with a real
        // nested `snapshot` field).
        let mut m = sample_message(2, 1);
        let mut snap = Snapshot::new();
        snap.mut_metadata().set_index(10);
        m.set_snapshot(snap); // a real nested-message field, so decode descends once
        let body = m.write_to_bytes().expect("encode");

        // With a limit of 0, the very first nested-message descent must be rejected.
        let mut is0 = CodedInputStream::from_bytes(&body);
        is0.set_recursion_limit(0);
        let mut got0 = Message::new();
        let res0 = got0.merge_from(&mut is0);
        assert!(
            matches!(
                res0,
                Err(protobuf::ProtobufError::WireError(
                    protobuf::error::WireError::OverRecursionLimit
                ))
            ),
            "a 0 recursion limit must reject the first nested-message descent; got {res0:?}"
        );

        // With our real (tight) limit of 16, the same message decodes fine — the bound accepts
        // every legitimate, shallow eraftpb message.
        let got16 = decode_raft_message(&body).expect("decodes under the real limit");
        assert_eq!(got16, m);
    }

    #[test]
    fn the_decode_recursion_limit_is_tight() {
        // Pin the depth bound so a future loosening trips this test, not a deployed node. 16 is far
        // below protobuf's default of 100 (so it is tighter than the library default) and far above
        // eraftpb's real max nesting of 4.
        assert_eq!(RAFT_DECODE_RECURSION_LIMIT, 16);
    }

    #[test]
    fn a_message_nested_within_the_bound_still_decodes() {
        // A few real nested levels (snapshot present) must still succeed — the bound is not so tight
        // it rejects valid messages.
        let mut m = sample_message(2, 1);
        let mut snap = Snapshot::new();
        snap.mut_metadata().set_index(10);
        snap.mut_metadata().set_term(5);
        m.set_snapshot(snap);
        let frame = encode_raft_message(&m).expect("encode");
        let registry = registry_with(&[1, 2]);
        let (decoded, _) = decode_peer_frame(&frame, &registry)
            .expect("decode ok")
            .expect("complete");
        assert_eq!(decoded, m);
    }

    // --- FUZZ / PROPERTY: arbitrary, malformed, oversized, and deeply-nested bytes NEVER panic,
    //     over-allocate, or stack-overflow — the decoder always returns a typed error or a valid
    //     Message. This is the adversarial core: untrusted input can be ANYTHING. ---

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        /// Random bytes fed straight to the body decoder: must ALWAYS be a typed result, never a
        /// panic. (proptest catches a panic as a test failure.)
        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = decode_raft_message(&bytes);
        }

        /// Random bytes fed to the FULL frame path (envelope + decode + auth): must always be a
        /// typed result, never a panic / over-allocation.
        #[test]
        fn decoding_arbitrary_frames_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let registry = registry_with(&[1, 2, 3, 4, 5]);
            let _ = decode_peer_frame(&bytes, &registry);
        }

        /// Random bytes wrapped in a VALID Raft envelope (so the body always reaches the protobuf
        /// decoder): the body decoder must still always be a typed result, never a panic.
        #[test]
        fn decoding_arbitrary_raft_bodies_never_panics(body in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let registry = registry_with(&[1, 2, 3]);
            let mut framed = Vec::new();
            if encode_frame(FrameType::Raft, &body, &mut framed).is_ok() {
                let _ = decode_peer_frame(&framed, &registry);
            }
        }

        /// Arbitrarily DEEP nested unknown START-GROUP fields (random depths well past any sane
        /// bound — the named RUSTSEC-2024-0437 `skip_group` vector) are ALWAYS rejected with a typed
        /// Decode error and never overflow the stack, generalized over depth.
        #[test]
        fn arbitrarily_deep_group_nestings_are_always_typed_errors(depth in 17usize..4096) {
            prop_assert!(matches!(
                decode_raft_message(&deeply_nested_group_bytes(depth)),
                Err(PeerWireError::Decode(_))
            ));
        }

        /// A valid message with arbitrary control-field values always round-trips and authenticates
        /// (when its sender is a member), proving the bounds never corrupt a legitimate message.
        #[test]
        fn valid_messages_with_arbitrary_fields_round_trip(
            from in 1u64..=5,
            to in 1u64..=5,
            term in any::<u64>(),
            index in any::<u64>(),
            commit in any::<u64>(),
        ) {
            let mut m = Message::new();
            m.set_msg_type(MessageType::MsgHeartbeat);
            m.set_from(from);
            m.set_to(to);
            m.set_term(term);
            m.set_index(index);
            m.set_commit(commit);
            let frame = encode_raft_message(&m).expect("encode");
            let registry = registry_with(&[1, 2, 3, 4, 5]);
            let (decoded, consumed) = decode_peer_frame(&frame, &registry)
                .expect("decode ok")
                .expect("complete");
            prop_assert_eq!(consumed, frame.len());
            prop_assert_eq!(decoded, m);
        }
    }

    // --- INTEGRATION: the bounded transport carries REAL consensus traffic. A small mesh of actual
    //     `MetadataRaftGroup`s drives an election and a membership change, but EVERY raft message
    //     between nodes is serialized through the wire codec (`encode_raft_message`) and decoded +
    //     authenticated back through the bounded receive path (`decode_peer_frame`) before reaching
    //     `step` — proving the transport's `drive_ready -> wire -> decode -> step` seam works
    //     end-to-end, not just on synthetic messages. ---

    mod mesh {
        use super::*;
        use crate::cluster::metadata_group::MetadataRaftGroup;
        use ironbus_core::clock::ManualClock;
        use ironbus_storage::fs::InMemoryFs;
        use ironbus_storage::log::LogConfig;
        use std::collections::{BTreeMap, BTreeSet};

        type Group = MetadataRaftGroup<InMemoryFs, ManualClock>;

        fn log_config() -> LogConfig {
            LogConfig::default()
        }

        /// A mesh whose router serializes every raft message through the BOUNDED WIRE CODEC and
        /// authenticates the sender against the live membership before delivering to `step`.
        struct WireMesh {
            nodes: BTreeMap<u64, Group>,
        }

        impl WireMesh {
            fn new(voters: &[u64]) -> Self {
                let mut nodes = BTreeMap::new();
                for &id in voters {
                    let fs = InMemoryFs::new();
                    let g =
                        MetadataRaftGroup::open(id, voters, &fs, ManualClock::new(), log_config())
                            .expect("open node");
                    nodes.insert(id, g);
                }
                Self { nodes }
            }

            /// The current known membership across the mesh, as a peer registry (voters + learners
            /// from any node's conf state — they converge as consensus advances).
            fn registry(&self) -> PeerRegistry {
                let mut voters = BTreeSet::new();
                let mut learners = BTreeSet::new();
                for g in self.nodes.values() {
                    if let Ok(cs) = g.conf_state() {
                        voters.extend(cs.get_voters().iter().copied());
                        learners.extend(cs.get_learners().iter().copied());
                    }
                }
                let voters: Vec<u64> = voters.into_iter().collect();
                let learners: Vec<u64> = learners.into_iter().collect();
                PeerRegistry::from_members(&voters, &learners)
            }

            fn tick_all(&mut self) {
                for n in self.nodes.values_mut() {
                    n.tick();
                }
            }

            /// Drain every node's ready, but route each message THROUGH THE WIRE: encode -> frame
            /// -> decode -> authenticate -> step. Returns messages routed this round.
            fn pump_once(&mut self) -> usize {
                let registry = self.registry();
                // Phase 1: collect every outbound message as ON-WIRE FRAME BYTES (the send path).
                let mut wire: Vec<(u64, Vec<u8>)> = Vec::new();
                for n in self.nodes.values_mut() {
                    for msg in n.drive_ready().expect("drive ready") {
                        let to = msg.to;
                        let frame = encode_raft_message(&msg).expect("encode outbound");
                        wire.push((to, frame));
                    }
                }
                let routed = wire.len();
                // Phase 2: deliver by DECODING the untrusted bytes through the bounded receive path.
                for (to, frame) in wire {
                    // A message from a node mid-removal may fail auth against the converged
                    // membership, or be an incomplete frame; the mesh router is best-effort, exactly
                    // like the in-value one — skip anything that is not a complete, authenticated msg.
                    let Ok(Some((decoded, consumed))) = decode_peer_frame(&frame, &registry) else {
                        continue;
                    };
                    assert_eq!(consumed, frame.len(), "one frame per message");
                    if let Some(dst) = self.nodes.get_mut(&to) {
                        let _ = dst.step(decoded);
                    }
                }
                routed
            }

            fn run(&mut self) {
                for _ in 0..1024 {
                    self.tick_all();
                    // Drain-and-route to a local fixed point before the next tick.
                    for _ in 0..256 {
                        if self.pump_once() == 0 {
                            break;
                        }
                    }
                    if self.quiesced() {
                        break;
                    }
                }
            }

            fn quiesced(&self) -> bool {
                self.nodes.values().all(|n| !n.has_pending_ready())
            }

            fn leader(&self) -> Option<u64> {
                self.nodes
                    .iter()
                    .find(|(_, g)| g.is_leader())
                    .map(|(id, _)| *id)
            }
        }

        #[test]
        fn a_three_node_mesh_elects_a_leader_over_the_bounded_wire() {
            // Every vote / heartbeat / append between the three nodes crosses the bounded codec.
            let mut mesh = WireMesh::new(&[1, 2, 3]);
            // Kick an election on node 1, then run the mesh over the wire to a fixed point.
            mesh.nodes
                .get_mut(&1)
                .unwrap()
                .campaign()
                .expect("campaign");
            mesh.run();
            let leader = mesh.leader().expect("a leader must emerge over the wire");
            assert!([1, 2, 3].contains(&leader));
            // The leader's term is established and replicated — consensus happened entirely through
            // encode -> frame -> bounded-decode -> authenticate -> step.
            let term = mesh.nodes[&leader].term();
            assert!(term >= 1, "leader must have a real term");
        }

        #[test]
        fn a_membership_change_replicates_over_the_bounded_wire() {
            // Add node 4 as a learner, proposed on the leader and replicated to followers entirely
            // through the bounded transport. This exercises a conf-change entry crossing the wire.
            let mut mesh = WireMesh::new(&[1, 2, 3]);
            mesh.nodes
                .get_mut(&1)
                .unwrap()
                .campaign()
                .expect("campaign");
            mesh.run();
            let leader = mesh.leader().expect("leader");
            mesh.nodes
                .get_mut(&leader)
                .unwrap()
                .add_learner(4)
                .expect("propose learner");
            mesh.run();
            // The learner must now be in the leader's durable conf state — the conf-change entry
            // committed after crossing the bounded wire to a quorum.
            let cs = mesh.nodes[&leader].conf_state().expect("conf state");
            assert!(
                cs.get_learners().contains(&4),
                "node 4 must be a known learner after the change replicated over the wire"
            );
        }
    }
}
