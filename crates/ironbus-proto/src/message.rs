// SPDX-License-Identifier: MIT OR Apache-2.0
//! Codecs for the message frame bodies: PUB (a producer's message) and ACK (a consumer's
//! acknowledgement). These are the two bodies the at-least-once produce/consume path
//! rides in; they sit inside the [`crate::frame`] envelope, which owns the length prefix
//! and type tag, so these codecs only frame the body fields.
//!
//! Decoding is bounds-checked and never panics on a malformed body: a short or
//! inconsistent body is a typed [`BodyError`], not a slice out of range. The wire uses
//! little-endian fixed-width fields and explicit `u16` lengths for the variable parts, so
//! a body parses identically on every target. These are wire types: the server maps them
//! to the storage and consumer domain types.

/// An error decoding (or encoding) a message body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyError {
    /// The body ended before a field could be read.
    Truncated,
    /// A length-prefixed field claimed more bytes than the body held.
    BadLength,
    /// A variable field (key or headers) was longer than `u16::MAX`, the wire limit.
    FieldTooLarge,
    /// The acknowledgement op tag was not a known verb.
    BadAckOp {
        /// The unrecognized op byte.
        op: u8,
    },
    /// Trailing bytes remained after a fixed-layout body was fully read.
    TrailingBytes,
}

impl core::fmt::Display for BodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BodyError::Truncated => write!(f, "message body is truncated"),
            BodyError::BadLength => write!(f, "a length field exceeds the body"),
            BodyError::FieldTooLarge => write!(f, "a variable field exceeds the u16 wire limit"),
            BodyError::BadAckOp { op } => write!(f, "unknown ack op {op}"),
            BodyError::TrailingBytes => write!(f, "unexpected trailing bytes in the body"),
        }
    }
}

impl std::error::Error for BodyError {}

/// A bounds-checked, panic-free reader over a body slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], BodyError> {
        let end = self.pos.checked_add(n).ok_or(BodyError::BadLength)?;
        let slice = self.buf.get(self.pos..end).ok_or(BodyError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, BodyError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BodyError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Result<u64, BodyError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    /// Reads a `u16`-length-prefixed byte field.
    fn var(&mut self) -> Result<&'a [u8], BodyError> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    fn rest(self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn push_var(out: &mut Vec<u8>, field: &[u8]) -> Result<(), BodyError> {
    let len = u16::try_from(field.len()).map_err(|_| BodyError::FieldTooLarge)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// A producer's published message (the PUB frame body).
///
/// Layout: `flags: u8`, `timestamp_ms: u64`, `key: u16-len + bytes`,
/// `headers: u16-len + bytes`, then `payload` (the remainder of the body).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PubBody<'a> {
    /// Producer record flags (the codec/server derives storage flags such as `HAS_KEY`).
    pub flags: u8,
    /// Producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The routing or ordering key (empty if none).
    pub key: &'a [u8],
    /// The headers blob (empty if none).
    pub headers: &'a [u8],
    /// The message payload.
    pub payload: &'a [u8],
}

/// Encodes a PUB body onto the end of `out`.
///
/// # Errors
/// Returns [`BodyError::FieldTooLarge`] if the key or headers exceed `u16::MAX`.
pub fn encode_pub(msg: &PubBody<'_>, out: &mut Vec<u8>) -> Result<(), BodyError> {
    out.push(msg.flags);
    out.extend_from_slice(&msg.timestamp_ms.to_le_bytes());
    push_var(out, msg.key)?;
    push_var(out, msg.headers)?;
    out.extend_from_slice(msg.payload);
    Ok(())
}

/// Decodes a PUB body. The payload is whatever remains after the framed fields, so
/// `body` MUST be exactly one frame's body (as handed out by [`crate::frame::decode_frame`]):
/// any trailing bytes would be folded into the payload.
///
/// # Errors
/// Returns a [`BodyError`] on a short or inconsistent body.
pub fn decode_pub(body: &[u8]) -> Result<PubBody<'_>, BodyError> {
    let mut r = Reader::new(body);
    let flags = r.u8()?;
    let timestamp_ms = r.u64()?;
    let key = r.var()?;
    let headers = r.var()?;
    let payload = r.rest();
    Ok(PubBody {
        flags,
        timestamp_ms,
        key,
        headers,
        payload,
    })
}

/// A consumer acknowledgement op (the wire verb).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckOp {
    /// Done; commit the message.
    Ack,
    /// Failed; retry (optionally after `delay_ms`).
    Nack,
    /// Stop redelivering without dead-lettering.
    Term,
    /// Extend the lease (work in progress).
    Progress,
}

impl AckOp {
    /// The one-byte wire tag.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            AckOp::Ack => 0,
            AckOp::Nack => 1,
            AckOp::Term => 2,
            AckOp::Progress => 3,
        }
    }

    /// Parses a wire tag.
    fn from_u8(op: u8) -> Result<AckOp, BodyError> {
        Ok(match op {
            0 => AckOp::Ack,
            1 => AckOp::Nack,
            2 => AckOp::Term,
            3 => AckOp::Progress,
            other => return Err(BodyError::BadAckOp { op: other }),
        })
    }
}

/// A consumer acknowledgement (the ACK frame body).
///
/// Layout: `op: u8`, `offset: u64`, `generation: u64`, `delay_ms: u64`. The offset names
/// the message; the generation is the lease fencing token; `delay_ms` is meaningful only
/// for [`AckOp::Nack`] (zero otherwise).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckBody {
    /// The acknowledgement op.
    pub op: AckOp,
    /// The log offset of the message being acknowledged.
    pub offset: u64,
    /// The lease generation the message was delivered under (the fencing token).
    pub generation: u64,
    /// For a nack, how long to defer redelivery, in milliseconds; zero otherwise.
    pub delay_ms: u64,
}

/// Encodes an ACK body onto the end of `out`.
pub fn encode_ack(ack: &AckBody, out: &mut Vec<u8>) {
    out.push(ack.op.as_u8());
    out.extend_from_slice(&ack.offset.to_le_bytes());
    out.extend_from_slice(&ack.generation.to_le_bytes());
    out.extend_from_slice(&ack.delay_ms.to_le_bytes());
}

/// Decodes an ACK body (a fixed 25-byte layout; trailing bytes are rejected).
///
/// # Errors
/// Returns a [`BodyError`] on a short body, an unknown op, or trailing bytes.
pub fn decode_ack(body: &[u8]) -> Result<AckBody, BodyError> {
    let mut r = Reader::new(body);
    let op = AckOp::from_u8(r.u8()?)?;
    let offset = r.u64()?;
    let generation = r.u64()?;
    let delay_ms = r.u64()?;
    if !r.at_end() {
        return Err(BodyError::TrailingBytes);
    }
    Ok(AckBody {
        op,
        offset,
        generation,
        delay_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn pub_round_trips() {
        let msg = PubBody {
            flags: 0b0000_0010,
            timestamp_ms: 1_700_000_000_000,
            key: b"order-42",
            headers: b"h",
            payload: b"the payload bytes",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        assert_eq!(decode_pub(&buf).unwrap(), msg);
    }

    #[test]
    fn pub_with_empty_fields_round_trips() {
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: b"",
            headers: b"",
            payload: b"",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        let got = decode_pub(&buf).unwrap();
        assert_eq!(got, msg);
        assert!(got.key.is_empty() && got.headers.is_empty() && got.payload.is_empty());
    }

    #[test]
    fn pub_rejects_an_oversized_key() {
        let big = vec![0u8; usize::from(u16::MAX) + 1];
        let msg = PubBody {
            flags: 0,
            timestamp_ms: 0,
            key: &big,
            headers: b"",
            payload: b"",
        };
        let mut buf = Vec::new();
        assert_eq!(encode_pub(&msg, &mut buf), Err(BodyError::FieldTooLarge));
    }

    #[test]
    fn pub_decode_is_truncation_safe() {
        let mut buf = Vec::new();
        encode_pub(
            &PubBody {
                flags: 1,
                timestamp_ms: 9,
                key: b"abc",
                headers: b"de",
                payload: b"xyz",
            },
            &mut buf,
        )
        .unwrap();
        // Framed header = flags(1) + ts(8) + key_len(2) + key(3) + hdr_len(2) + hdr(2) = 18.
        let framed = 1 + 8 + 2 + 3 + 2 + 2;
        // Cutting inside the framed header errors (never panics).
        for cut in 0..framed {
            assert!(
                decode_pub(&buf[..cut]).is_err(),
                "header prefix {cut} should error"
            );
        }
        // The payload is the remainder, so cutting into it just yields a shorter payload.
        for cut in framed..=buf.len() {
            assert_eq!(decode_pub(&buf[..cut]).unwrap().payload.len(), cut - framed);
        }
    }

    #[test]
    fn pub_rejects_a_key_length_past_the_body() {
        // flags(1) + ts(8) + key_len(2)=0xffff but no key bytes.
        let mut buf = vec![0u8; 9];
        buf.extend_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(decode_pub(&buf), Err(BodyError::Truncated));
    }

    #[test]
    fn ack_round_trips_every_op() {
        for op in [AckOp::Ack, AckOp::Nack, AckOp::Term, AckOp::Progress] {
            let ack = AckBody {
                op,
                offset: 12_345,
                generation: 7,
                delay_ms: if op == AckOp::Nack { 250 } else { 0 },
            };
            let mut buf = Vec::new();
            encode_ack(&ack, &mut buf);
            assert_eq!(buf.len(), 25);
            assert_eq!(decode_ack(&buf).unwrap(), ack);
        }
    }

    #[test]
    fn ackop_tags_have_their_exact_frozen_wire_values() {
        // Pin the on-the-wire op numbers so a future reorder breaks a test here, not a
        // deployed peer. Part of the frozen wire contract.
        assert_eq!(AckOp::Ack.as_u8(), 0);
        assert_eq!(AckOp::Nack.as_u8(), 1);
        assert_eq!(AckOp::Term.as_u8(), 2);
        assert_eq!(AckOp::Progress.as_u8(), 3);
    }

    #[test]
    fn pub_round_trips_at_the_u16_field_boundary() {
        // key and headers each at exactly u16::MAX, the largest a length field can name.
        let big = vec![0xa5_u8; usize::from(u16::MAX)];
        let msg = PubBody {
            flags: 7,
            timestamp_ms: 1,
            key: &big,
            headers: &big,
            payload: b"tail",
        };
        let mut buf = Vec::new();
        encode_pub(&msg, &mut buf).unwrap();
        assert_eq!(decode_pub(&buf).unwrap(), msg);
    }

    #[test]
    fn ack_rejects_an_unknown_op() {
        let mut buf = vec![9u8]; // op 9 is unknown
        buf.extend_from_slice(&[0u8; 24]);
        assert_eq!(decode_ack(&buf), Err(BodyError::BadAckOp { op: 9 }));
    }

    #[test]
    fn ack_rejects_a_short_or_overlong_body() {
        assert_eq!(decode_ack(&[0u8; 24]), Err(BodyError::Truncated));
        assert_eq!(decode_ack(&[0u8; 26]), Err(BodyError::TrailingBytes));
    }

    proptest! {
        #[test]
        fn any_pub_round_trips(
            flags in any::<u8>(),
            timestamp_ms in any::<u64>(),
            key in prop::collection::vec(any::<u8>(), 0..300),
            headers in prop::collection::vec(any::<u8>(), 0..300),
            payload in prop::collection::vec(any::<u8>(), 0..1024),
        ) {
            let msg = PubBody { flags, timestamp_ms, key: &key, headers: &headers, payload: &payload };
            let mut buf = Vec::new();
            encode_pub(&msg, &mut buf).unwrap();
            prop_assert_eq!(decode_pub(&buf).unwrap(), msg);
        }

        #[test]
        fn any_ack_round_trips(op_idx in 0u8..4, offset in any::<u64>(), generation in any::<u64>(), delay_ms in any::<u64>()) {
            let op = AckOp::from_u8(op_idx).unwrap();
            let ack = AckBody { op, offset, generation, delay_ms };
            let mut buf = Vec::new();
            encode_ack(&ack, &mut buf);
            prop_assert_eq!(decode_ack(&buf).unwrap(), ack);
        }

        /// Decoding arbitrary bytes as a PUB or ACK never panics.
        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = decode_pub(&bytes);
            let _ = decode_ack(&bytes);
        }
    }
}
