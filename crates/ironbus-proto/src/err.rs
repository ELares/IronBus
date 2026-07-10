// SPDX-License-Identifier: MIT OR Apache-2.0
//! The wire `Err` frame body codec (#883): an OPTIONAL stable machine-readable code token in front
//! of the existing free-form human message, so a client can branch on a code instead of substring-
//! matching prose the broker is free to reword.
//!
//! # Backward-compatible layout
//! The historical `Err` body was the raw UTF-8 message with no structure. To stay byte-identical for
//! every UNCODED reply (the malformed-body literals, the uniform auth violation, and any error the
//! server chooses not to tag), a coded body is marked by a single leading `NUL` (`0x00`) sentinel.
//! A lone `0x00` is valid UTF-8 in general, but every uncoded `Err` message the server emits is
//! printable human text that never begins with `NUL`, so a leading `0x00` unambiguously flags a
//! coded body:
//!
//! - UNCODED: `[ message bytes … ]` (unchanged: byte-for-byte the pre-#883 body).
//! - CODED:   `[ 0x00 ][ code_len: u8 ][ code_token: code_len bytes ][ message bytes … ]`.
//!
//! A decoder that sees a leading `0x00` reads the fixed code field, then the message follows exactly
//! as before; a body that does NOT start with `0x00` is the raw message with NO code. The code token
//! is one of the frozen `ErrorCode` spellings (`ironbus-server`'s `codes` module), so the client maps
//! it to a typed [`ServerErrorCode`] and keeps the human string for display only.

use std::borrow::Cow;

/// The sentinel that marks a CODED `Err` body. No uncoded `Err` message the server emits begins with
/// `NUL` (a lone `0x00` is valid UTF-8, but the server's human messages are all printable text), so a
/// leading `0x00` unambiguously distinguishes a coded body from the historical raw-message body.
const CODED_SENTINEL: u8 = 0x00;

/// A stable, machine-readable server rejection code (#883, #35): the typed twin of the free-form `Err`
/// message a client can branch on (retry-vs-fail, backpressure-vs-permanent-reject) instead of parsing
/// prose. Each variant mirrors one frozen `ErrorCode` token the server places on the wire; an
/// unrecognized token (a newer server code this client build predates) decodes as ABSENT (`None`) with
/// the human message still intact, so a forward-incompatible code never masquerades as a wrong one.
///
/// The enum is `#[non_exhaustive]`: a future server code adds a variant without breaking a client that
/// matches with a wildcard arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServerErrorCode {
    /// `ERR_AT_CAPACITY`: the durable log is at its byte cap (the drop-new shed) — a benign,
    /// retryable backpressure signal, NOT a permanent reject.
    AtCapacity,
    /// `ERR_NOT_ENOUGH_ISR`: a clustered `C2-fsync` produce could not be quorum-committed because the
    /// partition's parked-ack backlog is at its cap (not enough in-sync replicas) — a RETRYABLE
    /// unavailable-over-unsafe signal, NOT a permanent reject: retry once the ISR recovers.
    NotEnoughIsr,
    /// `ERR_STORAGE`: a generic storage fault.
    Storage,
    /// `ERR_PRODUCER_FENCED`: a produce presented a stale producer epoch (a zombie session).
    ProducerFenced,
    /// `ERR_OUT_OF_ORDER_SEQUENCE`: a sequenced idempotent produce skipped past the next sequence.
    OutOfOrderSequence,
    /// `ERR_CUMULATIVE_ACK_NOT_ALLOWED`: a cumulative ack on a competing / non-broadcast work-group.
    CumulativeAckNotAllowed,
    /// `ERR_CUMULATIVE_ACK_OUT_OF_RANGE`: a broadcast cumulative ack outside the retained window.
    CumulativeAckOutOfRange,
    /// `ERR_BROADCAST_GROUP_BUSY`: a second subscriber (or an unsafe flip) broke group-of-one.
    BroadcastGroupBusy,
    /// `ERR_BROADCAST_GROUP_NOT_NAMED`: a flip to broadcast named the default/empty group.
    BroadcastGroupNotNamed,
    /// `ERR_TOO_MANY_GROUPS`: a new named work-group exceeded the per-engine group cap.
    TooManyGroups,
    /// `ERR_TOO_MANY_STREAMS`: a new named stream exceeded the per-engine resident-stream cap.
    TooManyStreams,
    /// `ERR_INVALID_GROUP_NAME`: a work-group name was empty, too long, or non-graphic ASCII.
    InvalidGroupName,
    /// `ERR_INVALID_STREAM_NAME`: a named stream name was empty, too long, or non-graphic ASCII.
    InvalidStreamName,
    /// `ERR_UNKNOWN_STREAM`: a verb targeted a named stream that was never declared.
    UnknownStream,
    /// `ERR_MIRROR_READ_ONLY`: a client produce targeted a read-only cross-cluster mirror stream.
    MirrorReadOnly,
    /// `ERR_INVALID_SUBJECT`: a subject or bind pattern was not valid grammar.
    InvalidSubject,
    /// `ERR_BIND_REJECTED`: a bind would exceed the routing trie's fork bound.
    BindRejected,
    /// `ERR_BINDING_TABLE_FULL`: a bind would make the binding table's durable snapshot exceed its
    /// checkpoint slot (#1106); the previous table stays installed.
    BindingTableFull,
    /// `ERR_NO_STREAM_FOR_SUBJECT`: a subject-addressed publish resolved to no bound stream.
    NoStreamForSubject,
    /// `ERR_AMBIGUOUS_SUBJECT`: a subject-addressed publish resolved to two-or-more bound streams.
    AmbiguousSubject,
    /// `ERR_GENERATION_EXHAUSTED`: the lease generation space is exhausted (unreachable in practice).
    GenerationExhausted,
    /// `ERR_MISSING_RECORD`: an internal invariant broke (a deliverable offset had no record).
    MissingRecord,
    /// `ERR_ZERO_MAX_IN_FLIGHT`: `max_in_flight` was zero, rejected at open.
    ZeroMaxInFlight,
    /// `ERR_TXN`: a transactional half-message verb was rejected by the lifecycle.
    Txn,
    /// `ERR_TXN_CHECK_UNAUTHORIZED`: a back-check answer was refused on ownership.
    TxnCheckUnauthorized,
}

impl ServerErrorCode {
    /// Maps a frozen `ErrorCode` token spelling to its typed code, or `None` for a token this build
    /// does not recognize (a newer server code). The spellings are the NORMATIVE `ironbus-server`
    /// `codes` constants; a drift is caught by the cross-crate test in that crate.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        let code = match token {
            "ERR_AT_CAPACITY" => Self::AtCapacity,
            "ERR_NOT_ENOUGH_ISR" => Self::NotEnoughIsr,
            "ERR_STORAGE" => Self::Storage,
            "ERR_PRODUCER_FENCED" => Self::ProducerFenced,
            "ERR_OUT_OF_ORDER_SEQUENCE" => Self::OutOfOrderSequence,
            "ERR_CUMULATIVE_ACK_NOT_ALLOWED" => Self::CumulativeAckNotAllowed,
            "ERR_CUMULATIVE_ACK_OUT_OF_RANGE" => Self::CumulativeAckOutOfRange,
            "ERR_BROADCAST_GROUP_BUSY" => Self::BroadcastGroupBusy,
            "ERR_BROADCAST_GROUP_NOT_NAMED" => Self::BroadcastGroupNotNamed,
            "ERR_TOO_MANY_GROUPS" => Self::TooManyGroups,
            "ERR_TOO_MANY_STREAMS" => Self::TooManyStreams,
            "ERR_INVALID_GROUP_NAME" => Self::InvalidGroupName,
            "ERR_INVALID_STREAM_NAME" => Self::InvalidStreamName,
            "ERR_UNKNOWN_STREAM" => Self::UnknownStream,
            "ERR_MIRROR_READ_ONLY" => Self::MirrorReadOnly,
            "ERR_INVALID_SUBJECT" => Self::InvalidSubject,
            "ERR_BIND_REJECTED" => Self::BindRejected,
            "ERR_BINDING_TABLE_FULL" => Self::BindingTableFull,
            "ERR_NO_STREAM_FOR_SUBJECT" => Self::NoStreamForSubject,
            "ERR_AMBIGUOUS_SUBJECT" => Self::AmbiguousSubject,
            "ERR_GENERATION_EXHAUSTED" => Self::GenerationExhausted,
            "ERR_MISSING_RECORD" => Self::MissingRecord,
            "ERR_ZERO_MAX_IN_FLIGHT" => Self::ZeroMaxInFlight,
            "ERR_TXN" => Self::Txn,
            "ERR_TXN_CHECK_UNAUTHORIZED" => Self::TxnCheckUnauthorized,
            _ => return None,
        };
        Some(code)
    }

    /// The frozen token spelling this code encodes to on the wire (the inverse of [`Self::from_token`]).
    #[must_use]
    pub fn as_token(self) -> &'static str {
        match self {
            Self::AtCapacity => "ERR_AT_CAPACITY",
            Self::NotEnoughIsr => "ERR_NOT_ENOUGH_ISR",
            Self::Storage => "ERR_STORAGE",
            Self::ProducerFenced => "ERR_PRODUCER_FENCED",
            Self::OutOfOrderSequence => "ERR_OUT_OF_ORDER_SEQUENCE",
            Self::CumulativeAckNotAllowed => "ERR_CUMULATIVE_ACK_NOT_ALLOWED",
            Self::CumulativeAckOutOfRange => "ERR_CUMULATIVE_ACK_OUT_OF_RANGE",
            Self::BroadcastGroupBusy => "ERR_BROADCAST_GROUP_BUSY",
            Self::BroadcastGroupNotNamed => "ERR_BROADCAST_GROUP_NOT_NAMED",
            Self::TooManyGroups => "ERR_TOO_MANY_GROUPS",
            Self::TooManyStreams => "ERR_TOO_MANY_STREAMS",
            Self::InvalidGroupName => "ERR_INVALID_GROUP_NAME",
            Self::InvalidStreamName => "ERR_INVALID_STREAM_NAME",
            Self::UnknownStream => "ERR_UNKNOWN_STREAM",
            Self::MirrorReadOnly => "ERR_MIRROR_READ_ONLY",
            Self::InvalidSubject => "ERR_INVALID_SUBJECT",
            Self::BindRejected => "ERR_BIND_REJECTED",
            Self::BindingTableFull => "ERR_BINDING_TABLE_FULL",
            Self::NoStreamForSubject => "ERR_NO_STREAM_FOR_SUBJECT",
            Self::AmbiguousSubject => "ERR_AMBIGUOUS_SUBJECT",
            Self::GenerationExhausted => "ERR_GENERATION_EXHAUSTED",
            Self::MissingRecord => "ERR_MISSING_RECORD",
            Self::ZeroMaxInFlight => "ERR_ZERO_MAX_IN_FLIGHT",
            Self::Txn => "ERR_TXN",
            Self::TxnCheckUnauthorized => "ERR_TXN_CHECK_UNAUTHORIZED",
        }
    }
}

/// The decoded parts of an `Err` frame body: the optional typed code and the human message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedErr<'a> {
    /// The typed rejection code the server tagged, or `None` for an uncoded (legacy-shape) body or a
    /// code token this build does not recognize.
    pub code: Option<ServerErrorCode>,
    /// The free-form human-readable message, for display.
    pub message: Cow<'a, str>,
}

/// Encodes an `Err` frame body: an optional frozen code `token` in front of the human `message`.
///
/// `token` is the NORMATIVE `ErrorCode` spelling (e.g. `"ERR_AT_CAPACITY"`). `None` writes the raw
/// message with NO code, byte-identical to the pre-#883 body. A token longer than 255 bytes (never
/// true of the frozen tokens) is written UNCODED as a defensive fallback so encode is infallible.
pub fn encode_err_body(token: Option<&str>, message: &str, out: &mut Vec<u8>) {
    match token.and_then(|tok| {
        (!tok.is_empty())
            .then_some(tok)
            .zip(u8::try_from(tok.len()).ok())
    }) {
        Some((tok, code_len)) => {
            out.push(CODED_SENTINEL);
            out.push(code_len);
            out.extend_from_slice(tok.as_bytes());
            out.extend_from_slice(message.as_bytes());
        }
        None => out.extend_from_slice(message.as_bytes()),
    }
}

/// Decodes an `Err` frame body written by [`encode_err_body`]. A body that does NOT begin with the
/// coded sentinel is the historical raw message with no code; a malformed coded body (a truncated code
/// field) falls back to treating the whole body as the message, so decode never errors.
#[must_use]
pub fn decode_err_body(body: &[u8]) -> DecodedErr<'_> {
    if let Some((&CODED_SENTINEL, rest)) = body.split_first() {
        if let Some((&code_len, after_len)) = rest.split_first() {
            let code_len = usize::from(code_len);
            if code_len <= after_len.len() {
                let (token_bytes, message_bytes) = after_len.split_at(code_len);
                let code = std::str::from_utf8(token_bytes)
                    .ok()
                    .and_then(ServerErrorCode::from_token);
                return DecodedErr {
                    code,
                    message: String::from_utf8_lossy(message_bytes),
                };
            }
        }
    }
    DecodedErr {
        code: None,
        message: String::from_utf8_lossy(body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncoded_body_is_byte_identical_to_the_raw_message() {
        // The pre-#883 shape: the raw UTF-8 message, no structure. Every UNCODED reply MUST stay
        // byte-for-byte identical so existing consumers (and the auth-violation exact bytes) are
        // untouched.
        let mut out = Vec::new();
        encode_err_body(None, "not connected", &mut out);
        assert_eq!(out, b"not connected");
    }

    #[test]
    fn coded_round_trips_the_code_and_keeps_the_message() {
        let mut out = Vec::new();
        encode_err_body(Some("ERR_AT_CAPACITY"), "at capacity", &mut out);
        // The sentinel guards the coded shape; the human message still trails so a `.contains` reader
        // on the whole body finds it.
        assert_eq!(out[0], CODED_SENTINEL);
        assert!(String::from_utf8_lossy(&out).contains("at capacity"));
        let decoded = decode_err_body(&out);
        assert_eq!(decoded.code, Some(ServerErrorCode::AtCapacity));
        assert_eq!(decoded.message, "at capacity");
    }

    #[test]
    fn a_raw_message_decodes_as_uncoded() {
        let decoded = decode_err_body(b"malformed pub body");
        assert_eq!(decoded.code, None);
        assert_eq!(decoded.message, "malformed pub body");
    }

    #[test]
    fn an_unrecognized_token_decodes_as_absent_but_keeps_the_message() {
        // A newer server code this build predates: the typed code is ABSENT (never a wrong one) but the
        // human message survives.
        let mut out = Vec::new();
        encode_err_body(Some("ERR_FROM_THE_FUTURE"), "some new reject", &mut out);
        let decoded = decode_err_body(&out);
        assert_eq!(decoded.code, None);
        assert_eq!(decoded.message, "some new reject");
    }

    #[test]
    fn a_truncated_coded_body_falls_back_to_the_whole_body_as_message() {
        // A coded sentinel with a code_len that overruns the body: decode must not panic and must not
        // invent a code.
        let decoded = decode_err_body(&[CODED_SENTINEL, 40, b'x']);
        assert_eq!(decoded.code, None);
    }

    #[test]
    fn every_variant_round_trips_through_its_token() {
        for code in [
            ServerErrorCode::AtCapacity,
            ServerErrorCode::NotEnoughIsr,
            ServerErrorCode::Storage,
            ServerErrorCode::ProducerFenced,
            ServerErrorCode::OutOfOrderSequence,
            ServerErrorCode::CumulativeAckNotAllowed,
            ServerErrorCode::CumulativeAckOutOfRange,
            ServerErrorCode::BroadcastGroupBusy,
            ServerErrorCode::BroadcastGroupNotNamed,
            ServerErrorCode::TooManyGroups,
            ServerErrorCode::TooManyStreams,
            ServerErrorCode::InvalidGroupName,
            ServerErrorCode::InvalidStreamName,
            ServerErrorCode::UnknownStream,
            ServerErrorCode::MirrorReadOnly,
            ServerErrorCode::InvalidSubject,
            ServerErrorCode::BindRejected,
            ServerErrorCode::BindingTableFull,
            ServerErrorCode::NoStreamForSubject,
            ServerErrorCode::AmbiguousSubject,
            ServerErrorCode::GenerationExhausted,
            ServerErrorCode::MissingRecord,
            ServerErrorCode::ZeroMaxInFlight,
            ServerErrorCode::Txn,
            ServerErrorCode::TxnCheckUnauthorized,
        ] {
            assert_eq!(ServerErrorCode::from_token(code.as_token()), Some(code));
        }
    }
}
