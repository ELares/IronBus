// SPDX-License-Identifier: MIT OR Apache-2.0
//! The connection session: it frames the wire protocol onto the engine.
//!
//! A session reads frames from a connection's input buffer, dispatches each to the
//! [`Engine`], and writes response frames back. It is synchronous and buffer-driven: it
//! consumes only the complete frames at the front of the input (a partial trailing frame
//! is left for the next read) and never blocks, so the async TCP server can drive it from
//! a byte stream without owning any IO here. Request/response verbs only: produce (`Pub`),
//! acknowledge (`Ack`), the handshake (`Connect`/`Info`), and keepalive (`Ping`/`Pong`).
//! The streaming consumer-fetch path and capability negotiation are follow-ups.
//!
//! Response body conventions: an `Ok` to a `Pub` carries the 8-byte little-endian assigned
//! offset; other `Ok`s have an empty body; an `Err` carries a UTF-8 message. A malformed
//! frame envelope is unrecoverable for a length-prefixed stream, so it ends the session.

use crate::engine::Engine;
use ironbus_core::clock::Clock;
use ironbus_core::types::RecordFlags;
use ironbus_proto::frame::{decode_frame, encode_frame, FrameDecode, FrameError, FrameType};
use ironbus_proto::message::{decode_ack, decode_pub, AckOp};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Append;

/// A session error that ends the connection (the frame boundary is lost and cannot be
/// resynced).
#[derive(Debug)]
pub enum SessionError {
    /// The frame envelope was malformed (a zero or over-cap length prefix).
    BadFrame(FrameError),
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SessionError::BadFrame(e) => write!(f, "malformed frame, closing session: {e}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Per-connection session state over a shared [`Engine`].
#[derive(Debug, Default)]
pub struct Session {
    connected: bool,
}

impl Session {
    /// A new, not-yet-handshaked session.
    #[must_use]
    pub fn new() -> Session {
        Session::default()
    }

    /// Processes the complete frames at the front of `input`, dispatching each to `engine`
    /// and appending response frames to `out`. Returns the number of input bytes consumed;
    /// a partial trailing frame is not consumed and should be retried once more bytes
    /// arrive.
    ///
    /// # Errors
    /// Returns [`SessionError::BadFrame`] if a frame envelope is malformed; the caller must
    /// then close the connection (a length-prefixed stream cannot resync).
    pub fn process<F: Filesystem, C: Clock>(
        &mut self,
        engine: &mut Engine<F, C>,
        input: &[u8],
        out: &mut Vec<u8>,
        now: u64,
    ) -> Result<usize, SessionError> {
        let mut consumed = 0;
        loop {
            match decode_frame(&input[consumed..]).map_err(SessionError::BadFrame)? {
                FrameDecode::Incomplete { .. } => return Ok(consumed),
                FrameDecode::Frame {
                    type_tag,
                    body,
                    consumed: n,
                } => {
                    self.dispatch(engine, type_tag, body, now, out);
                    consumed += n;
                }
            }
        }
    }

    fn dispatch<F: Filesystem, C: Clock>(
        &mut self,
        engine: &mut Engine<F, C>,
        type_tag: u8,
        body: &[u8],
        now: u64,
        out: &mut Vec<u8>,
    ) {
        match FrameType::from_u8(type_tag) {
            Some(FrameType::Connect) => {
                self.connected = true;
                reply(out, FrameType::Info, &[]);
            }
            Some(FrameType::Ping) => reply(out, FrameType::Pong, &[]),
            Some(FrameType::Pub) => self.handle_pub(engine, body, out),
            Some(FrameType::Ack) => self.handle_ack(engine, body, now, out),
            // Recognized but not yet wired (streaming consumer path), or response-only verbs
            // a client should not send.
            Some(_) => reply_err(out, "verb not supported on this connection"),
            // An unknown tag is forward-compatible at the envelope level but has no handler.
            None => reply_err(out, "unknown frame type"),
        }
    }

    fn handle_pub<F: Filesystem, C: Clock>(
        &mut self,
        engine: &mut Engine<F, C>,
        body: &[u8],
        out: &mut Vec<u8>,
    ) {
        if !self.connected {
            reply_err(out, "not connected");
            return;
        }
        let Ok(msg) = decode_pub(body) else {
            reply_err(out, "malformed pub body");
            return;
        };
        let append = Append {
            timestamp_ms: msg.timestamp_ms,
            flags: RecordFlags::from_bits(msg.flags),
            key: msg.key,
            headers: msg.headers,
            payload: msg.payload,
        };
        match engine.produce(&append) {
            Ok(offset) => reply(out, FrameType::Ok, &offset.get().to_le_bytes()),
            Err(_) => reply_err(out, "produce failed"),
        }
    }

    fn handle_ack<F: Filesystem, C: Clock>(
        &mut self,
        engine: &mut Engine<F, C>,
        body: &[u8],
        _now: u64,
        out: &mut Vec<u8>,
    ) {
        if !self.connected {
            reply_err(out, "not connected");
            return;
        }
        let Ok(ack) = decode_ack(body) else {
            reply_err(out, "malformed ack body");
            return;
        };
        // This PR wires the `ack` op (commit). nack/term/progress are the streaming path.
        if ack.op != AckOp::Ack {
            reply_err(out, "only ack is supported on this connection");
            return;
        }
        let token = ironbus_core::lease::LeaseToken {
            offset: ironbus_core::types::Offset::new(ack.offset),
            generation: ack.generation,
        };
        // ack is idempotent: a fenced (stale) ack is a no-op, still an Ok to the client.
        let _ = engine.ack(&token);
        reply(out, FrameType::Ok, &[]);
    }
}

/// Encodes a response frame (never fails: bodies here are tiny and well under the cap).
fn reply(out: &mut Vec<u8>, frame_type: FrameType, body: &[u8]) {
    // The body is at most 8 bytes here, so encoding cannot exceed MAX_FRAME_LEN.
    let _ = encode_frame(frame_type, body, out);
}

fn reply_err(out: &mut Vec<u8>, message: &str) {
    let _ = encode_frame(FrameType::Err, message.as_bytes(), out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Engine, EngineConfig, Poll};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_proto::message::{encode_ack, encode_pub, AckBody, PubBody};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;

    fn engine() -> Engine<InMemoryFs, ManualClock> {
        Engine::open(
            InMemoryFs::new(),
            ManualClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 10,
            },
        )
        .unwrap()
    }

    /// Decodes one response frame from the front of `out`.
    fn one_response(out: &[u8]) -> (FrameType, Vec<u8>) {
        match decode_frame(out).unwrap() {
            FrameDecode::Frame { type_tag, body, .. } => {
                (FrameType::from_u8(type_tag).unwrap(), body.to_vec())
            }
            FrameDecode::Incomplete { .. } => panic!("expected a complete response"),
        }
    }

    fn frame(ty: FrameType, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        encode_frame(ty, body, &mut v).unwrap();
        v
    }

    #[test]
    fn ping_is_answered_with_pong() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        let input = frame(FrameType::Ping, b"");
        let consumed = s.process(&mut e, &input, &mut out, 0).unwrap();
        assert_eq!(consumed, input.len());
        assert_eq!(one_response(&out).0, FrameType::Pong);
    }

    #[test]
    fn connect_is_answered_with_info() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out, 0)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Info);
    }

    #[test]
    fn pub_after_connect_appends_and_replies_ok_with_the_offset() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        let mut input = frame(FrameType::Connect, b"");
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 5,
                key: b"k",
                headers: b"",
                payload: b"hello",
            },
            &mut pub_body,
        )
        .unwrap();
        input.extend_from_slice(&frame(FrameType::Pub, &pub_body));

        let consumed = s.process(&mut e, &input, &mut out, 0).unwrap();
        assert_eq!(consumed, input.len());
        // Two responses: Info, then Ok with offset 0.
        let info = decode_frame(&out).unwrap();
        let FrameDecode::Frame { consumed: c0, .. } = info else {
            panic!("info incomplete");
        };
        let (ty, body) = one_response(&out[c0..]);
        assert_eq!(ty, FrameType::Ok);
        assert_eq!(body, 0u64.to_le_bytes());
        // The message is durable in the engine and deliverable.
        match e.poll(0).unwrap() {
            Poll::Message(d) => assert_eq!(d.record.payload, b"hello"),
            other => panic!("expected the produced message, got {other:?}"),
        }
    }

    #[test]
    fn pub_before_connect_is_rejected() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        let mut pub_body = Vec::new();
        encode_pub(
            &PubBody {
                flags: 0,
                timestamp_ms: 0,
                key: b"",
                headers: b"",
                payload: b"x",
            },
            &mut pub_body,
        )
        .unwrap();
        s.process(&mut e, &frame(FrameType::Pub, &pub_body), &mut out, 0)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }

    #[test]
    fn ack_commits_a_delivered_message() {
        let mut e = engine();
        let mut s = Session::new();
        // Connect + produce + deliver out of band, then ack via the session.
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out, 0)
            .unwrap();
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"m",
        })
        .unwrap();
        let token = match e.poll(0).unwrap() {
            Poll::Message(d) => d.token,
            other => panic!("expected a delivery, got {other:?}"),
        };
        let mut ack_body = Vec::new();
        encode_ack(
            &AckBody {
                op: AckOp::Ack,
                offset: token.offset.get(),
                generation: token.generation,
                delay_ms: 0,
            },
            &mut ack_body,
        );
        out.clear();
        s.process(&mut e, &frame(FrameType::Ack, &ack_body), &mut out, 0)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Ok);
        assert_eq!(e.committed_offset().get(), 1);
    }

    #[test]
    fn a_partial_trailing_frame_is_not_consumed() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        let ping = frame(FrameType::Ping, b"");
        let mut input = ping.clone();
        input.extend_from_slice(&frame(FrameType::Ping, b"")[..2]); // half of a second frame
        let consumed = s.process(&mut e, &input, &mut out, 0).unwrap();
        assert_eq!(consumed, ping.len(), "only the complete frame is consumed");
        assert_eq!(one_response(&out).0, FrameType::Pong);
    }

    #[test]
    fn a_malformed_frame_ends_the_session() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        let bad = [0u8, 0, 0, 0]; // zero-length prefix
        assert!(matches!(
            s.process(&mut e, &bad, &mut out, 0),
            Err(SessionError::BadFrame(_))
        ));
    }

    #[test]
    fn an_unsupported_verb_replies_err_without_closing() {
        let mut e = engine();
        let mut s = Session::new();
        let mut out = Vec::new();
        s.process(&mut e, &frame(FrameType::Connect, b""), &mut out, 0)
            .unwrap();
        out.clear();
        // Sub is recognized but not wired on this connection.
        s.process(&mut e, &frame(FrameType::Sub, b""), &mut out, 0)
            .unwrap();
        assert_eq!(one_response(&out).0, FrameType::Err);
    }
}
