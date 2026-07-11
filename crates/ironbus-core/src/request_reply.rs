// SPDX-License-Identifier: MIT OR Apache-2.0
//! Request/reply (RPC) correlation carried in the message-header blob (#764, V2-M4-I5).
//!
//! IronBus builds request/reply as a THIN pattern over the EXISTING substrate — subjects (#585),
//! competing work-groups (#588), and ephemeral consumer groups (#771/#1148) — NOT as a new
//! mechanism. It invents NO wire field and NO frame tag: exactly like the W3C `traceparent` carrier
//! (#770, [`crate::trace_context`]), the requester stamps a **reply-subject** and a **correlation
//! id** into the record's already-arbitrary, already-durable HEADER blob, and the responder echoes
//! the correlation id back on its reply. This module is the pure, dependency-free, IO-free codec for
//! those two header entries: it links no runtime, adds no dependency to `ironbus-core`, generates NO
//! randomness, and reads NO clock — the client supplies the random correlation id (and derives the
//! ephemeral inbox subject from it). Parsing is DEFENSIVE by construction: a malformed, truncated, or
//! absent value is "no value" (`None`), NEVER an error, so a bad header can never wedge a produce or
//! a delivery.
//!
//! ## Carrier convention
//! The header blob is opaque bytes IronBus otherwise never interprets. This codec adds (and reads)
//! two HTTP-header-like lines, newline-separated, case-insensitive on the name, exactly the shape the
//! `traceparent` reader already tolerates:
//!
//! ```text
//! ib-reply-to: _INBOX.7f3a...          <- the ephemeral reply subject (request only)
//! ib-corr-id: 7f3a9c1e...              <- 32 lowercase hex = the 16-byte correlation id
//! ```
//!
//! Existing header lines (e.g. a `traceparent`) are PRESERVED: the encoders append their lines to
//! whatever the caller already had, so request/reply composes with distributed tracing on the same
//! record.

/// The header name carrying the ephemeral reply subject the responder publishes its reply to. Case is
/// ignored on read; the encoder always emits this lowercase form.
pub const REPLY_TO_HEADER_NAME: &[u8] = b"ib-reply-to";

/// The header name carrying the 16-byte correlation id (as 32 lowercase hex digits). The requester
/// stamps it on the request; the responder echoes it verbatim on the reply so the requester can
/// demultiplex many in-flight requests over one connection.
pub const CORRELATION_ID_HEADER_NAME: &[u8] = b"ib-corr-id";

/// The reserved subject prefix for per-request ephemeral reply inboxes (mirrors the NATS `_INBOX.>`
/// convention). A reply subject is `_INBOX.<32 hex of the correlation id>`; the whole space is routed
/// by binding the [`INBOX_PATTERN`] to the [`INBOX_STREAM`].
pub const INBOX_PREFIX: &str = "_INBOX";

/// The reserved stream the inbox subject space binds to (declare-on-bind). All ephemeral reply
/// inboxes share this one durable log; each requester consumes it through its OWN ephemeral group and
/// filters by correlation id, so the log keeps no per-request durable state.
pub const INBOX_STREAM: &str = "_INBOX";

/// The wildcard bind pattern that routes every `_INBOX.<id>` reply subject to the [`INBOX_STREAM`]:
/// `_INBOX.>` (the `>` tail matches the one-token id). Bound once (idempotently) before the first
/// request; a responder's reply to `_INBOX.<id>` then resolves single-home to [`INBOX_STREAM`].
pub const INBOX_PATTERN: &str = "_INBOX.>";

/// The byte length of a correlation id: a 128-bit value, ample to make an accidental collision across
/// concurrent in-flight requests negligible.
pub const CORRELATION_ID_LEN: usize = 16;

/// A request/reply correlation id: 16 random bytes the requester allocates per request and the
/// responder echoes back. Serialized in a header as 32 lowercase hex digits.
pub type CorrelationId = [u8; CORRELATION_ID_LEN];

/// The request metadata a requester stamps and a responder reads back off a request's headers: the
/// ephemeral reply subject to publish the reply on, and the correlation id to echo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHeaders<'a> {
    /// The ephemeral reply subject (`_INBOX.<id>`) the responder publishes its reply on.
    pub reply_to: &'a [u8],
    /// The correlation id the responder must echo on the reply so the requester can match it.
    pub correlation_id: CorrelationId,
}

/// Serializes a correlation id to its canonical 32-lowercase-hex header value. The inverse of
/// [`parse_correlation_id`]; a value formatted here and re-parsed round-trips byte-for-byte.
#[must_use]
pub fn format_correlation_id(id: &CorrelationId) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(CORRELATION_ID_LEN * 2);
    for b in id {
        // `write!` to a String is infallible; the `let _` documents that.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parses a correlation id from exactly 32 ASCII hex digits (either case), returning `None` for any
/// wrong length or non-hex input — the defensive, never-erroring inverse of
/// [`format_correlation_id`].
#[must_use]
pub fn parse_correlation_id(hex: &[u8]) -> Option<CorrelationId> {
    hex_bytes::<CORRELATION_ID_LEN>(hex)
}

/// The ephemeral reply subject for a request, derived deterministically from its correlation id:
/// `_INBOX.<32 hex>`. Deriving the inbox from the correlation id keeps allocation to a SINGLE random
/// draw client-side while still giving every in-flight request a distinct reply subject.
#[must_use]
pub fn inbox_subject(id: &CorrelationId) -> String {
    let mut s = String::with_capacity(INBOX_PREFIX.len() + 1 + CORRELATION_ID_LEN * 2);
    s.push_str(INBOX_PREFIX);
    s.push('.');
    s.push_str(&format_correlation_id(id));
    s
}

/// Builds the header blob for a REQUEST: the caller's `existing` header lines (preserved verbatim, so
/// a `traceparent` survives) followed by the `ib-reply-to` and `ib-corr-id` lines. When `existing` is
/// empty the result is just the two lines; otherwise a single `\n` separates the caller's block from
/// the appended lines (a trailing newline on `existing` is not duplicated).
#[must_use]
pub fn encode_request_headers(
    reply_to: &[u8],
    correlation_id: &CorrelationId,
    existing: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    append_existing(&mut out, existing);
    push_line(&mut out, REPLY_TO_HEADER_NAME, reply_to);
    out.push(b'\n');
    push_line(
        &mut out,
        CORRELATION_ID_HEADER_NAME,
        format_correlation_id(correlation_id).as_bytes(),
    );
    out
}

/// Builds the header blob for a REPLY: the responder's `existing` header lines (preserved) followed
/// by the single `ib-corr-id` line echoing the request's correlation id. The requester matches a
/// delivered reply to its outstanding request by this id (an id it never issued is ignored).
#[must_use]
pub fn encode_reply_headers(correlation_id: &CorrelationId, existing: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    append_existing(&mut out, existing);
    push_line(
        &mut out,
        CORRELATION_ID_HEADER_NAME,
        format_correlation_id(correlation_id).as_bytes(),
    );
    out
}

/// Reads the `ib-reply-to` reply subject out of a header blob, or `None` when it is absent or empty.
/// The returned slice borrows the blob (the raw subject bytes, whitespace-trimmed).
#[must_use]
pub fn reply_to_from_headers(headers: &[u8]) -> Option<&[u8]> {
    let v = header_value(headers, REPLY_TO_HEADER_NAME)?;
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Reads and parses the `ib-corr-id` correlation id out of a header blob, or `None` when it is absent
/// or malformed (not exactly 32 hex digits). Defensive: a bad id is treated as absent, never an
/// error.
#[must_use]
pub fn correlation_id_from_headers(headers: &[u8]) -> Option<CorrelationId> {
    parse_correlation_id(header_value(headers, CORRELATION_ID_HEADER_NAME)?)
}

/// Reads BOTH request fields off a header blob, returning the [`RequestHeaders`] only when a
/// well-formed reply subject AND correlation id are both present — i.e. this record is a request a
/// responder can answer. A record missing either is not a request (`None`).
#[must_use]
pub fn request_headers_from(headers: &[u8]) -> Option<RequestHeaders<'_>> {
    let reply_to = reply_to_from_headers(headers)?;
    let correlation_id = correlation_id_from_headers(headers)?;
    Some(RequestHeaders {
        reply_to,
        correlation_id,
    })
}

// ---- internal helpers (pure; mirror `trace_context`'s style so the module is self-contained) ----

/// Appends `existing` header bytes to `out` for the encoders, followed by a single separating `\n`
/// (dropping any trailing newline `existing` already had, so lines never double-space). A no-op for
/// an empty `existing`, so the encoded blob is just the appended lines.
fn append_existing(out: &mut Vec<u8>, existing: &[u8]) {
    // Trim a trailing run of newlines so appending never produces a blank line, but keep interior
    // content byte-for-byte.
    let mut end = existing.len();
    while end > 0 && existing[end - 1] == b'\n' {
        end -= 1;
    }
    if end == 0 {
        return;
    }
    out.extend_from_slice(&existing[..end]);
    out.push(b'\n');
}

/// Writes one `name: value` header line (no trailing newline) onto `out`.
fn push_line(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
}

/// Locates the value of the header named `name` (case-insensitive) in an opaque, newline-separated
/// header blob, tolerating `name: value` or `name=value` and surrounding whitespace — the SAME carrier
/// convention [`crate::trace_context::TraceParent::from_headers`] reads. Returns the whitespace-trimmed
/// value bytes, or `None` when no line names `name`.
fn header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in headers.split(|&b| b == b'\n') {
        let line = trim_ascii(line);
        let Some(sep) = line.iter().position(|&b| b == b':' || b == b'=') else {
            continue;
        };
        let (lname, rest) = line.split_at(sep);
        if trim_ascii(lname).eq_ignore_ascii_case(name) {
            // `rest` begins with the separator byte; skip it before trimming the value.
            return Some(trim_ascii(&rest[1..]));
        }
    }
    None
}

/// Maps one ASCII hex digit to its 0..=15 value, in either case. `None` for a non-hex byte.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parses `2 * N` ASCII hex digits into `N` bytes; `None` unless the slice is exactly `2 * N` hex
/// digits (length-checked up front, so a short or long field is rejected as malformed).
fn hex_bytes<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (hex_val(s[i * 2])? << 4) | hex_val(s[i * 2 + 1])?;
        i += 1;
    }
    Some(out)
}

/// Trims leading and trailing ASCII whitespace from a byte slice. A local helper (not the standard
/// `<[u8]>::trim_ascii`, which stabilized after the 1.78 MSRV floor) so the parser stays buildable on
/// the pinned toolchain — matching [`crate::trace_context`].
fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: CorrelationId = [
        0x7f, 0x3a, 0x9c, 0x1e, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
        0xbb,
    ];

    #[test]
    fn correlation_id_hex_round_trips() {
        let hex = format_correlation_id(&ID);
        assert_eq!(hex, "7f3a9c1e00112233445566778899aabb");
        assert_eq!(parse_correlation_id(hex.as_bytes()), Some(ID));
        // Upper-case input parses to the same bytes (defensive, case-insensitive).
        assert_eq!(
            parse_correlation_id(b"7F3A9C1E00112233445566778899AABB"),
            Some(ID)
        );
    }

    #[test]
    fn malformed_correlation_id_is_none_not_error() {
        assert_eq!(parse_correlation_id(b""), None);
        assert_eq!(parse_correlation_id(b"7f3a"), None); // too short
        assert_eq!(
            parse_correlation_id(b"zz3a9c1e00112233445566778899aabb"),
            None
        ); // non-hex
        assert_eq!(
            parse_correlation_id(b"7f3a9c1e00112233445566778899aabbcc"),
            None
        ); // too long
    }

    #[test]
    fn inbox_subject_is_prefixed_and_carries_the_id() {
        let subj = inbox_subject(&ID);
        assert_eq!(subj, "_INBOX.7f3a9c1e00112233445566778899aabb");
        assert!(subj.starts_with(INBOX_PREFIX));
    }

    #[test]
    fn request_headers_round_trip_from_empty() {
        let reply = inbox_subject(&ID);
        let blob = encode_request_headers(reply.as_bytes(), &ID, b"");
        let parsed = request_headers_from(&blob).expect("a well-formed request");
        assert_eq!(parsed.reply_to, reply.as_bytes());
        assert_eq!(parsed.correlation_id, ID);
    }

    #[test]
    fn request_headers_preserve_an_existing_traceparent() {
        let existing = b"traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let reply = inbox_subject(&ID);
        let blob = encode_request_headers(reply.as_bytes(), &ID, existing);
        // Both the request fields and the pre-existing traceparent line survive.
        let parsed = request_headers_from(&blob).expect("a well-formed request");
        assert_eq!(parsed.reply_to, reply.as_bytes());
        assert_eq!(parsed.correlation_id, ID);
        assert_eq!(
            crate::trace_context::TraceParent::from_headers(&blob)
                .expect("the traceparent survives")
                .flags,
            0x01
        );
    }

    #[test]
    fn reply_headers_carry_only_the_correlation_id() {
        let blob = encode_reply_headers(&ID, b"");
        assert_eq!(correlation_id_from_headers(&blob), Some(ID));
        assert_eq!(reply_to_from_headers(&blob), None);
    }

    #[test]
    fn absent_fields_are_none() {
        assert_eq!(reply_to_from_headers(b""), None);
        assert_eq!(correlation_id_from_headers(b""), None);
        assert_eq!(request_headers_from(b"random: header"), None);
        // A reply subject but no id is not a request.
        let only_reply = {
            let mut v = Vec::new();
            push_line(&mut v, REPLY_TO_HEADER_NAME, b"_INBOX.abc");
            v
        };
        assert_eq!(request_headers_from(&only_reply), None);
        assert_eq!(reply_to_from_headers(&only_reply), Some(&b"_INBOX.abc"[..]));
    }

    #[test]
    fn header_name_match_is_case_insensitive() {
        let blob = b"IB-CORR-ID: 7f3a9c1e00112233445566778899aabb";
        assert_eq!(correlation_id_from_headers(blob), Some(ID));
    }
}
