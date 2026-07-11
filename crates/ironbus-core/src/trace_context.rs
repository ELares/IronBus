// SPDX-License-Identifier: MIT OR Apache-2.0
//! W3C Trace Context (`traceparent`) parse and format for distributed tracing (#770).
//!
//! IronBus does NOT invent a wire field for trace context: the client stamps a W3C `traceparent`
//! into the message HEADERS (the record's already-arbitrary, already-durable header blob), and the
//! broker reads it back off the stored record on delivery. This module is the pure, dependency-free
//! codec for that value — it links no `opentelemetry` crate, adds no dependency to the IO-free
//! `ironbus-core`, and is compiled into every build (the default and `edge-min` binaries pay only the
//! cost of this small plain-data parser, never the OTLP exporter, which stays behind the `otlp`
//! feature in `ironbus-server::obs`).
//!
//! The value format is the W3C Trace Context `traceparent` field
//! (`00-<32 hex trace-id>-<16 hex span-id>-<2 hex flags>`, the version-0 form): a 1-byte version, a
//! 16-byte trace id, an 8-byte parent (span) id, and a 1-byte flags field. Parsing is DEFENSIVE by
//! construction — a malformed, truncated, all-zero, or absent value is treated as "no context"
//! (`None`), NEVER an error, so a bad `traceparent` can never wedge or reject a produce. Formatting
//! always emits the canonical lowercase version-0 form, so a value parsed and re-formatted round-trips
//! byte-for-byte.

/// A parsed W3C `traceparent`: the distributed trace context a client hands the bus in the message
/// headers (#770). Carries the 16-byte trace id, the 8-byte parent (span) id, and the 1-byte trace
/// flags. Pure plain data with no `opentelemetry` dependency; `ironbus-server::obs` maps it onto an
/// exported span's parent (on produce) or link (on deliver) only when the `otlp` feature is compiled
/// in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceParent {
    /// The 16-byte trace id. Never all-zero for a parsed value (an all-zero trace id is the W3C
    /// "invalid" sentinel and is rejected as absent).
    pub trace_id: [u8; 16],
    /// The 8-byte parent (span) id — the id of the span that produced this message. Never all-zero
    /// for a parsed value (an all-zero id is invalid and is rejected as absent). On produce this
    /// becomes the produce span's parent; on deliver it becomes the linked span id.
    pub parent_id: [u8; 8],
    /// The 1-byte W3C trace flags (bit 0 = sampled). Carried verbatim so the sampled bit survives the
    /// hop; not otherwise interpreted here.
    pub flags: u8,
}

/// The canonical serialized length of a version-0 `traceparent` value: `2 + 1 + 32 + 1 + 16 + 1 + 2`.
pub const TRACEPARENT_LEN: usize = 55;

/// The ASCII header name a client uses to carry the trace context inside the message header blob, per
/// the W3C convention. [`TraceParent::from_headers`] also accepts a header blob that is nothing but a
/// bare `traceparent` value (no name), so both a single-value blob and an HTTP-header-like
/// `traceparent: <value>` line are recognized.
pub const TRACEPARENT_HEADER_NAME: &[u8] = b"traceparent";

impl TraceParent {
    /// Parses one W3C `traceparent` VALUE from `value` (`00-<trace>-<span>-<flags>`), returning `None`
    /// for anything malformed — wrong length, non-hex, an unknown-but-`ff` version, or an all-zero
    /// trace/parent id (the W3C invalid sentinels). Hex is accepted in either case on input; the
    /// caller gets the raw bytes. This is the defensive, never-erroring core the produce path relies
    /// on: a broken value is simply "no context".
    ///
    /// For the version-0 (`00`) form the value must be EXACTLY the four dash-separated fields; a
    /// trailing field is rejected. A higher (future) version is accepted so long as its first four
    /// fields parse, per the W3C forward-compatibility rule, with any trailing fields ignored. The
    /// reserved `ff` version is rejected.
    #[must_use]
    pub fn parse(value: &[u8]) -> Option<TraceParent> {
        let mut parts = value.split(|&b| b == b'-');
        let version_s = parts.next()?;
        let trace_s = parts.next()?;
        let parent_s = parts.next()?;
        let flags_s = parts.next()?;
        let version = hex_byte(version_s)?;
        // `ff` is the reserved "invalid" version; reject it outright.
        if version == 0xff {
            return None;
        }
        // Version 0 is EXACTLY four fields: a trailing field makes the value malformed. Future
        // versions may carry a suffix, which the W3C rule says to ignore.
        if version == 0x00 && parts.next().is_some() {
            return None;
        }
        let trace_id = hex_bytes::<16>(trace_s)?;
        let parent_id = hex_bytes::<8>(parent_s)?;
        let flags = hex_byte(flags_s)?;
        // All-zero trace or span id is the W3C invalid sentinel: treat as absent.
        if trace_id == [0u8; 16] || parent_id == [0u8; 8] {
            return None;
        }
        Some(TraceParent {
            trace_id,
            parent_id,
            flags,
        })
    }

    /// Locates a W3C `traceparent` in an opaque message-header blob and parses it, returning `None`
    /// when none is present or the one present is malformed (#770). Two carrier conventions are
    /// accepted, in order: (1) the WHOLE trimmed blob is a bare `traceparent` value; (2) an
    /// HTTP-header-like `traceparent: <value>` (or `traceparent=<value>`) entry among newline-separated
    /// lines, case-insensitive on the name and tolerant of surrounding whitespace. The broker treats
    /// the header blob as opaque bytes otherwise; this only READS a `traceparent` when the client put
    /// one there, and never mutates or injects.
    #[must_use]
    pub fn from_headers(headers: &[u8]) -> Option<TraceParent> {
        // (1) The whole blob is a bare value (the leanest carrier: a header blob that is just the
        // traceparent).
        if let Some(tp) = TraceParent::parse(trim_ascii(headers)) {
            return Some(tp);
        }
        // (2) An HTTP-header-like `traceparent: <value>` line among newline-separated entries.
        for line in headers.split(|&b| b == b'\n') {
            let line = trim_ascii(line);
            let Some(sep) = line.iter().position(|&b| b == b':' || b == b'=') else {
                continue;
            };
            let (name, rest) = line.split_at(sep);
            if trim_ascii(name).eq_ignore_ascii_case(TRACEPARENT_HEADER_NAME) {
                // `rest` includes the separator byte at index 0; skip it before trimming the value.
                if let Some(tp) = TraceParent::parse(trim_ascii(&rest[1..])) {
                    return Some(tp);
                }
            }
        }
        None
    }

    /// Serializes this context back to the canonical W3C version-0 `traceparent` value
    /// (`00-<trace>-<span>-<flags>`, lowercase hex), the exact form a client would put in the headers.
    /// A value parsed from a canonical lowercase input and re-formatted is byte-identical, so context
    /// round-trips across the bus without loss.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(TRACEPARENT_LEN);
        // Always emit version 0 (the only form IronBus produces); lowercase hex per the W3C spec.
        s.push_str("00-");
        for b in self.trace_id {
            let _ = write!(s, "{b:02x}");
        }
        s.push('-');
        for b in self.parent_id {
            let _ = write!(s, "{b:02x}");
        }
        let _ = write!(s, "-{:02x}", self.flags);
        s
    }
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

/// Parses exactly two ASCII hex digits into one byte; `None` unless the slice is exactly two hex
/// digits.
fn hex_byte(s: &[u8]) -> Option<u8> {
    if s.len() != 2 {
        return None;
    }
    Some((hex_val(s[0])? << 4) | hex_val(s[1])?)
}

/// Parses `2 * N` ASCII hex digits into `N` bytes; `None` unless the slice is exactly `2 * N` hex
/// digits. Length-checked up front so a short or long field is rejected as malformed.
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
/// the pinned toolchain.
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

    /// A known-good version-0 value round-trips byte-for-byte through parse then format.
    #[test]
    fn parse_then_format_round_trips_a_canonical_value() {
        let value = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tp = TraceParent::parse(value).expect("a canonical value parses");
        assert_eq!(
            tp.trace_id,
            [
                0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
                0x47, 0x36
            ]
        );
        assert_eq!(
            tp.parent_id,
            [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]
        );
        assert_eq!(tp.flags, 0x01);
        assert_eq!(
            tp.to_header_value().as_bytes(),
            value,
            "the re-serialized value is byte-identical to the input"
        );
        assert_eq!(tp.to_header_value().len(), TRACEPARENT_LEN);
    }

    /// Uppercase hex on input is tolerated (parsed to the same bytes) and normalized to lowercase on
    /// output — defensive leniency without breaking the canonical output contract.
    #[test]
    fn uppercase_hex_is_accepted_and_normalized() {
        let upper = b"00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01";
        let lower = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tp = TraceParent::parse(upper).expect("uppercase hex parses");
        assert_eq!(
            tp.to_header_value().as_bytes(),
            lower,
            "output is always canonical lowercase"
        );
    }

    /// Every malformed shape is treated as ABSENT (`None`), never an error: this is the property the
    /// produce path relies on so a broken `traceparent` can never reject a publish.
    #[test]
    fn malformed_values_are_absent_not_errors() {
        let cases: &[&[u8]] = &[
            b"",                                                              // empty
            b"garbage",                                                       // not dashed
            b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",          // missing flags
            b"00-4bf9-00f067aa0ba902b7-01",                                   // short trace id
            b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f0-01",                   // short span id
            b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",        // short flags
            b"zz-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",       // non-hex version
            b"00-zzf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",       // non-hex trace id
            b"00-00000000000000000000000000000000-00f067aa0ba902b7-01",       // all-zero trace id
            b"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",       // all-zero span id
            b"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",       // reserved ff version
            b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra", // v0 trailing field
        ];
        for &c in cases {
            assert!(
                TraceParent::parse(c).is_none(),
                "malformed value must parse as absent: {:?}",
                std::str::from_utf8(c).unwrap_or("<bytes>")
            );
        }
    }

    /// A future (non-`ff`) version with a trailing suffix still yields the first four fields, per the
    /// W3C forward-compatibility rule.
    #[test]
    fn a_future_version_with_a_suffix_still_parses_the_base_fields() {
        let value = b"cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-99";
        let tp = TraceParent::parse(value).expect("a future version parses its base fields");
        assert_eq!(
            tp.parent_id,
            [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]
        );
        assert_eq!(tp.flags, 0x01);
    }

    /// The header carrier: a blob that is nothing but a bare value is found.
    #[test]
    fn from_headers_finds_a_bare_value() {
        let headers = b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tp = TraceParent::from_headers(headers).expect("bare value found");
        assert_eq!(
            tp.parent_id,
            [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]
        );
    }

    /// The header carrier: an HTTP-header-like `traceparent: <value>` entry among other lines is
    /// found, case-insensitively, and other headers are ignored.
    #[test]
    fn from_headers_finds_a_named_line_among_others() {
        let headers = b"content-type: application/octet-stream\nTraceParent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\nx-other: 1";
        let tp = TraceParent::from_headers(headers).expect("named traceparent line found");
        assert_eq!(tp.flags, 0x01);
        assert_eq!(
            tp.parent_id,
            [0x00, 0xf0, 0x67, 0xaa, 0x0b, 0xa9, 0x02, 0xb7]
        );
    }

    /// The header carrier: a `traceparent=<value>` (equals separator) entry is also accepted.
    #[test]
    fn from_headers_accepts_an_equals_separator() {
        let headers = b"traceparent=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";
        let tp = TraceParent::from_headers(headers).expect("equals-separated value found");
        assert_eq!(tp.flags, 0x00);
    }

    /// The header carrier: no `traceparent` anywhere is simply absent (`None`), the common case for a
    /// client that does not participate in tracing.
    #[test]
    fn from_headers_is_absent_when_none_present() {
        assert!(TraceParent::from_headers(b"").is_none());
        assert!(TraceParent::from_headers(b"content-type: text/plain\nx-foo: bar").is_none());
        assert!(TraceParent::from_headers(b"traceparent: not-a-valid-value").is_none());
    }

    /// The flags byte survives verbatim (both the sampled and the un-sampled bit patterns).
    #[test]
    fn flags_byte_is_carried_verbatim() {
        for flags in [0x00u8, 0x01, 0xfe] {
            let tp = TraceParent {
                trace_id: [1u8; 16],
                parent_id: [2u8; 8],
                flags,
            };
            let reparsed = TraceParent::parse(tp.to_header_value().as_bytes())
                .expect("a formatted value re-parses");
            assert_eq!(reparsed.flags, flags);
        }
    }
}
