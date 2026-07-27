// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `ironbus admin` introspection client (#15, #99): fetch the broker's read-only `/admin` v1
//! JSON and render the operator views (segments, consumers with lag, and the last-skip-offset) FROM
//! THAT JSON ALONE.
//!
//! This is the consumer that proves the #99 contract: the human diagnostics are driven entirely by
//! the `/admin` document, NEVER by parsing a metric name. The HTTP fetch sends the version-pinning
//! `Accept: application/vnd.ironbus.admin.v1+json` header, so a future schema bump is detected by the
//! server (a `406`) rather than silently mis-rendered here. The JSON is parsed by a tiny, dependency-
//! free extractor (the workspace deliberately keeps no serde on the shipped rendering path, matching
//! the hand-rendered server side), tolerant of field order and whitespace and confined to the flat,
//! integer-and-string shape the `/admin` body uses.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// The media type that pins the `/admin` v1 schema (#99); sent in the `Accept` header so the server
/// serves v1 or rejects a version mismatch rather than letting this client misread a future shape.
pub const ADMIN_ACCEPT_V1: &str = "application/vnd.ironbus.admin.v1+json";

/// A read error from the admin client: a connection/transport failure (the broker or its health
/// server is unreachable) or a protocol failure (a non-200 status, an unparseable body, or a schema
/// the client does not understand). The caller maps these onto the CLI exit-code scheme.
#[derive(Debug)]
pub enum AdminError {
    /// The health server could not be reached or dropped the connection (exit: broker-unreachable).
    Unreachable(String),
    /// The server answered but the response was not a usable v1 admin body (exit: internal).
    Protocol(String),
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdminError::Unreachable(m) | AdminError::Protocol(m) => f.write_str(m),
        }
    }
}

/// Fetches the raw `/admin` JSON body from the health server at `health_addr` over plain HTTP,
/// sending the v1 Accept header. Bounded by a read/write/total timeout so a hung server cannot wedge
/// the CLI; the response body is bounded by [`MAX_ADMIN_BODY`].
///
/// # Errors
/// [`AdminError::Unreachable`] on a connect/IO failure; [`AdminError::Protocol`] on a non-200 status
/// or an over-long/truncated response.
pub fn fetch_admin(health_addr: &str) -> Result<String, AdminError> {
    let mut stream = TcpStream::connect(health_addr).map_err(|e| {
        AdminError::Unreachable(format!("cannot reach health server at {health_addr}: {e}"))
    })?;
    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(REQUEST_TIMEOUT)))
        .map_err(|e| AdminError::Unreachable(format!("cannot set socket timeout: {e}")))?;
    let request = format!(
        "GET /admin HTTP/1.1\r\n\
         Host: {health_addr}\r\n\
         Accept: {ADMIN_ACCEPT_V1}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| AdminError::Unreachable(format!("cannot send admin request: {e}")))?;
    let mut raw = Vec::new();
    // Read with a hard byte bound so a hostile or buggy server cannot stream without limit.
    let mut buf = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|e| AdminError::Unreachable(format!("cannot read admin response: {e}")))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_ADMIN_BODY {
            return Err(AdminError::Protocol(
                "admin response exceeded the size bound".to_string(),
            ));
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (status_line, body) = split_http_response(&text).ok_or_else(|| {
        AdminError::Protocol("malformed HTTP response from the admin endpoint".to_string())
    })?;
    if !status_line.contains(" 200 ") {
        // A 404 means admin is not enabled; a 406 means a schema-version mismatch; anything else is a
        // server-side problem. Surface the status so the operator knows which.
        if status_line.contains(" 404 ") {
            return Err(AdminError::Protocol(
                "the /admin endpoint is not enabled on this broker (start it with --enable-admin)"
                    .to_string(),
            ));
        }
        if status_line.contains(" 406 ") {
            return Err(AdminError::Protocol(
                "the broker does not serve the admin v1 schema this client understands".to_string(),
            ));
        }
        return Err(AdminError::Protocol(format!(
            "the admin endpoint returned an error status: {status_line}"
        )));
    }
    Ok(body.to_string())
}

/// Per-request read/write timeout for the admin fetch (slow-server defense).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// The hard bound on the admin response body. The `/admin` document is small (a bounded set of
/// counters and per-group rows), so a few hundred KiB is far above any real body and well below a
/// memory hazard.
const MAX_ADMIN_BODY: usize = 1 << 20; // 1 MiB

/// Splits a raw HTTP response into its (status line, body), or `None` if the header/body boundary is
/// absent. The status line is the first line; the body is everything after the blank line.
fn split_http_response(text: &str) -> Option<(&str, &str)> {
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))?;
    let status_line = head.lines().next().unwrap_or("");
    Some((status_line, body))
}

/// The fields the human admin views need, projected out of the `/admin` v1 JSON. Exactly the #99
/// set: the segment span, the per-consumer committed offset and lag, and the resilience
/// last-skip-offset (plus the frozen flag, which an operator always wants beside a skip). Parsed
/// from the JSON ALONE, so the CLI never reads a metric name to render these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminView {
    /// The `/admin` schema version (must be 1 for this client).
    pub schema_version: u64,
    /// Whether the writer is integrity-frozen (the resilience alarm).
    pub frozen: bool,
    /// The number of durable-log segments.
    pub segment_count: u64,
    /// The oldest retained offset (the low end of the segment span).
    pub earliest_retained_offset: u64,
    /// The durable head offset (the high end of the segment span).
    pub head_offset: u64,
    /// The highest offset any skip/loss event reached (the resilience watermark).
    pub last_skip_offset: u64,
    /// The durable recovery-loss record total.
    pub records_skipped: u64,
    /// One row per work-group consumer: name, committed offset, lag, in-flight depth.
    pub consumers: Vec<ConsumerRow>,
}

/// One per-consumer (work-group) row from the `/admin` `consumers` array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumerRow {
    /// The work-group name (the default group is the empty string).
    pub name: String,
    /// The group's committed offset.
    pub committed_offset: u64,
    /// The group's incremental lag (durable head minus committed).
    pub consumer_lag: u64,
    /// The group's current in-flight (un-acked) depth.
    pub in_flight: u64,
}

/// Parses the #99 view out of the `/admin` v1 JSON body, WITHOUT a JSON library and WITHOUT reading
/// a metric name. The parser is intentionally small and shape-specific: it pulls flat integer/bool
/// fields by key from the relevant object, and walks the `consumers` array by object. It tolerates
/// field order and surrounding whitespace.
///
/// # Errors
/// Returns the offending key in a message if a required field is missing or unparseable, or if the
/// schema version is not 1 (so a future shape is a clear error here, not a silent mis-render).
pub fn parse_admin_v1(body: &str) -> Result<AdminView, AdminError> {
    let schema_version = extract_u64(body, "schema_version")
        .ok_or_else(|| AdminError::Protocol("admin body missing schema_version".to_string()))?;
    if schema_version != 1 {
        return Err(AdminError::Protocol(format!(
            "unsupported admin schema_version {schema_version} (this client understands v1)"
        )));
    }
    // The segment span and resilience fields live in their named objects; we scan from each object's
    // opening brace so a same-named key in another object cannot be picked up by mistake.
    let segments = object_slice(body, "segments").ok_or_else(|| {
        AdminError::Protocol("admin body missing the segments object".to_string())
    })?;
    let resilience = object_slice(body, "resilience").ok_or_else(|| {
        AdminError::Protocol("admin body missing the resilience object".to_string())
    })?;

    let segment_count = extract_u64(segments, "count")
        .ok_or_else(|| AdminError::Protocol("segments.count missing".to_string()))?;
    let earliest_retained_offset =
        extract_u64(segments, "earliest_retained_offset").ok_or_else(|| {
            AdminError::Protocol("segments.earliest_retained_offset missing".to_string())
        })?;
    let head_offset = extract_u64(segments, "head_offset")
        .ok_or_else(|| AdminError::Protocol("segments.head_offset missing".to_string()))?;
    let frozen = extract_bool(resilience, "frozen")
        .ok_or_else(|| AdminError::Protocol("resilience.frozen missing".to_string()))?;
    let last_skip_offset = extract_u64(resilience, "last_skip_offset")
        .ok_or_else(|| AdminError::Protocol("resilience.last_skip_offset missing".to_string()))?;
    let records_skipped = extract_u64(resilience, "records_skipped")
        .ok_or_else(|| AdminError::Protocol("resilience.records_skipped missing".to_string()))?;

    let consumers = parse_consumers(body)?;

    Ok(AdminView {
        schema_version,
        frozen,
        segment_count,
        earliest_retained_offset,
        head_offset,
        last_skip_offset,
        records_skipped,
        consumers,
    })
}

/// Parses the `consumers` array into rows. Each element is a flat object
/// `{"name":"..","committed_offset":N,"consumer_lag":N,"in_flight":N}`; the walk is brace-counted so
/// a `}` inside a (future) nested value would not end an element early.
fn parse_consumers(body: &str) -> Result<Vec<ConsumerRow>, AdminError> {
    let array = array_slice(body, "consumers").ok_or_else(|| {
        AdminError::Protocol("admin body missing the consumers array".to_string())
    })?;
    let mut rows = Vec::new();
    let bytes = array.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            // Find the matching close brace (the rows are flat, but count to be safe).
            let start = i;
            let mut depth = 0i32;
            let mut in_string = false;
            let mut escaped = false;
            let mut end = None;
            while i < bytes.len() {
                let c = bytes[i];
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if c == b'\\' {
                        escaped = true;
                    } else if c == b'"' {
                        in_string = false;
                    }
                } else if c == b'"' {
                    in_string = true;
                } else if c == b'{' {
                    depth += 1;
                } else if c == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                i += 1;
            }
            let end = end.ok_or_else(|| {
                AdminError::Protocol("a consumers element is unterminated".to_string())
            })?;
            let element = &array[start..=end];
            rows.push(parse_consumer_row(element)?);
        }
        i += 1;
    }
    Ok(rows)
}

/// Parses one `{"name":..,"committed_offset":..,"consumer_lag":..,"in_flight":..}` object.
fn parse_consumer_row(element: &str) -> Result<ConsumerRow, AdminError> {
    let name = extract_string(element, "name")
        .ok_or_else(|| AdminError::Protocol("a consumer row missing name".to_string()))?;
    let committed_offset = extract_u64(element, "committed_offset").ok_or_else(|| {
        AdminError::Protocol("a consumer row missing committed_offset".to_string())
    })?;
    let consumer_lag = extract_u64(element, "consumer_lag")
        .ok_or_else(|| AdminError::Protocol("a consumer row missing consumer_lag".to_string()))?;
    let in_flight = extract_u64(element, "in_flight")
        .ok_or_else(|| AdminError::Protocol("a consumer row missing in_flight".to_string()))?;
    Ok(ConsumerRow {
        name,
        committed_offset,
        consumer_lag,
        in_flight,
    })
}

/// Renders the human admin view #15 prints, FROM the parsed `/admin` document ALONE. The layout is
/// stable and line-oriented so it is easy to read on a degraded box and easy to assert in a test.
#[must_use]
pub fn render_admin_view(view: &AdminView) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "admin (schema v{})", view.schema_version);
    let _ = writeln!(
        s,
        "segments: count={} span=[{}, {})",
        view.segment_count, view.earliest_retained_offset, view.head_offset
    );
    let _ = writeln!(
        s,
        "resilience: frozen={} last_skip_offset={} records_skipped={}",
        view.frozen, view.last_skip_offset, view.records_skipped
    );
    s.push_str("consumers:\n");
    if view.consumers.is_empty() {
        s.push_str("  (none)\n");
    } else {
        for c in &view.consumers {
            let name = if c.name.is_empty() {
                "(default)"
            } else {
                &c.name
            };
            let _ = writeln!(
                s,
                "  {name}: committed={} lag={} in_flight={}",
                c.committed_offset, c.consumer_lag, c.in_flight
            );
        }
    }
    s
}

// --- the tiny, shape-specific JSON extractors (dependency-free) ---

/// Returns the slice of `body` starting at the opening `{` of the object named `key` and running to
/// its matching close brace (inclusive), so a field lookup is confined to that object.
///
/// Exposed `pub(crate)` so the `top` view (#93) reuses the SAME dependency-free, shape-specific
/// `/admin` JSON extractors as the `admin` view rather than duplicating a second hand-rolled parser.
pub(crate) fn object_slice<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    bracketed_slice(body, key, b'{', b'}')
}

/// Returns the slice of `body` for the array named `key`, from its `[` to the matching `]`.
///
/// Exposed `pub(crate)` for the `top` view (#93); see [`object_slice`].
pub(crate) fn array_slice<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    bracketed_slice(body, key, b'[', b']')
}

/// Shared brace/bracket matcher: finds `"key":` then the next `open` and returns through its matching
/// `close`, counting nesting and skipping string contents so a delimiter inside a string value does
/// not throw off the match.
fn bracketed_slice<'a>(body: &'a str, key: &str, open: u8, close: u8) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let key_at = body.find(&needle)?;
    let bytes = body.as_bytes();
    let mut i = key_at + needle.len();
    // Skip whitespace to the opening delimiter.
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != open {
        return None;
    }
    let start = i;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else if c == b'"' {
            in_string = true;
        } else if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some(&body[start..=i]);
            }
        }
        i += 1;
    }
    None
}

/// Extracts the unsigned integer value of `"key":N` from `scope`. Returns `None` if the key is
/// absent or the value is not a bare unsigned integer.
///
/// Exposed `pub(crate)` for the `top` view (#93); see [`object_slice`].
pub(crate) fn extract_u64(scope: &str, key: &str) -> Option<u64> {
    let value = scalar_after_key(scope, key)?;
    let digits: String = value.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Extracts the boolean value of `"key":true|false` from `scope`.
///
/// Exposed `pub(crate)` for the `top` view (#93); see [`object_slice`].
pub(crate) fn extract_bool(scope: &str, key: &str) -> Option<bool> {
    let value = scalar_after_key(scope, key)?;
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Extracts the signed integer value of `"key":N` from `scope`, including a leading `-` (so a `-1`
/// sentinel such as `last_dead_lettered_offset` parses). Returns `None` if the key is absent or the
/// value is not a bare signed integer.
///
/// Exposed `pub(crate)` for the `top` view (#93); see [`object_slice`].
pub(crate) fn extract_i64(scope: &str, key: &str) -> Option<i64> {
    let value = scalar_after_key(scope, key)?;
    let mut chars = value.chars();
    let mut text = String::new();
    if let Some(first) = chars.clone().next() {
        if first == '-' {
            text.push('-');
            chars.next();
        }
    }
    for c in chars {
        if c.is_ascii_digit() {
            text.push(c);
        } else {
            break;
        }
    }
    if text.is_empty() || text == "-" {
        return None;
    }
    text.parse().ok()
}

/// Extracts the string value of `"key":"..."` from `scope`, undoing the two structural escapes the
/// server emits (`\"` and `\\`); other escapes (`\n` etc.) are left as-is since the admin string
/// fields (group names) are graphic ASCII.
///
/// Exposed `pub(crate)` for the `top` view (#93); see [`object_slice`].
pub(crate) fn extract_string(scope: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let at = scope.find(&needle)? + needle.len();
    let rest = scope[at..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let bytes = rest.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' {
            i += 1;
            match bytes.get(i) {
                Some(b'"') => out.push('"'),
                Some(b'\\') => out.push('\\'),
                Some(b'n') => out.push('\n'),
                Some(b'r') => out.push('\r'),
                Some(b't') => out.push('\t'),
                Some(other) => out.push(*other as char),
                None => break,
            }
        } else if c == b'"' {
            return Some(out);
        } else {
            // The admin names are ASCII; push the byte as a char (valid for graphic ASCII).
            out.push(c as char);
        }
        i += 1;
    }
    None
}

/// Returns the text immediately after `"key":` in `scope` (trimmed of leading whitespace), for the
/// scalar extractors to parse a number or bool from. Returns `None` if the key is absent.
fn scalar_after_key<'a>(scope: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let at = scope.find(&needle)? + needle.len();
    Some(scope[at..].trim_start())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative `/admin` v1 body in the exact shape the server renders (segments before
    /// consumers before resilience), used to prove the CLI renders the #99 views from the JSON
    /// alone.
    const SAMPLE: &str = "{\"schema_version\":1,\
        \"broker\":{\"healthy\":true,\"flushed_offset\":3,\"committed_offset\":0},\
        \"segments\":{\"count\":2,\"earliest_retained_offset\":1,\"head_offset\":7,\
            \"durable_record_count\":6,\"durable_record_bytes\":120},\
        \"consumers\":[\
            {\"name\":\"\",\"committed_offset\":0,\"consumer_lag\":7,\"in_flight\":0},\
            {\"name\":\"orders\",\"committed_offset\":5,\"consumer_lag\":2,\"in_flight\":1}],\
        \"groups\":[\
            {\"name\":\"\",\"committed_offset\":0,\"consumer_lag\":7,\"in_flight\":0},\
            {\"name\":\"orders\",\"committed_offset\":5,\"consumer_lag\":2,\"in_flight\":1}],\
        \"resilience\":{\"frozen\":false,\"last_skip_offset\":4,\"records_skipped\":3,\
            \"bytes_skipped\":48,\"recovery_truncated_bytes\":0,\"counter_checkpoint_repairs\":1},\
        \"dlq\":{\"records\":0,\"last_dead_lettered_offset\":-1},\
        \"config\":{\"max_total_bytes\":1000000}}";

    #[test]
    fn parses_segments_consumers_lag_and_last_skip_offset_from_json_alone() {
        // The #99 acceptance: every operator field comes from the /admin JSON, never a metric name.
        let view = parse_admin_v1(SAMPLE).expect("the sample parses");
        assert_eq!(view.schema_version, 1);
        assert_eq!(view.segment_count, 2);
        assert_eq!(view.earliest_retained_offset, 1);
        assert_eq!(view.head_offset, 7);
        assert!(!view.frozen);
        assert_eq!(
            view.last_skip_offset, 4,
            "last-skip-offset from /admin alone"
        );
        assert_eq!(view.records_skipped, 3);
        assert_eq!(view.consumers.len(), 2);
        assert_eq!(
            view.consumers[0],
            ConsumerRow {
                name: String::new(),
                committed_offset: 0,
                consumer_lag: 7,
                in_flight: 0
            }
        );
        assert_eq!(
            view.consumers[1],
            ConsumerRow {
                name: "orders".to_string(),
                committed_offset: 5,
                consumer_lag: 2,
                in_flight: 1
            }
        );
    }

    #[test]
    fn render_shows_segments_consumers_lag_and_last_skip_offset() {
        // The rendered human view carries exactly the #99 fields, derived from the parsed document.
        let view = parse_admin_v1(SAMPLE).unwrap();
        let text = render_admin_view(&view);
        assert!(text.contains("segments: count=2 span=[1, 7)"), "{text}");
        assert!(text.contains("last_skip_offset=4"), "{text}");
        assert!(
            text.contains("(default): committed=0 lag=7 in_flight=0"),
            "{text}"
        );
        assert!(
            text.contains("orders: committed=5 lag=2 in_flight=1"),
            "{text}"
        );
    }

    #[test]
    fn the_extractor_is_confined_to_the_named_object() {
        // `count` only exists in segments here; a naive global search would still find it, but the
        // object-scoped lookup must read the segments value specifically. Add a decoy `count` in
        // another object to prove the scoping.
        let body = "{\"schema_version\":1,\
            \"other\":{\"count\":999},\
            \"segments\":{\"count\":2,\"earliest_retained_offset\":0,\"head_offset\":2},\
            \"consumers\":[],\
            \"resilience\":{\"frozen\":false,\"last_skip_offset\":0,\"records_skipped\":0}}";
        let view = parse_admin_v1(body).unwrap();
        assert_eq!(
            view.segment_count, 2,
            "read the segments.count, not the decoy 999"
        );
    }

    #[test]
    fn a_non_v1_schema_is_a_clear_error_not_a_misrender() {
        let body = "{\"schema_version\":2,\"segments\":{},\"consumers\":[],\"resilience\":{}}";
        let err = parse_admin_v1(body).unwrap_err();
        match err {
            AdminError::Protocol(m) => assert!(m.contains("schema_version 2"), "{m}"),
            AdminError::Unreachable(m) => panic!("wrong variant: {m}"),
        }
    }

    #[test]
    fn a_frozen_broker_surfaces_in_the_view() {
        let body = "{\"schema_version\":1,\
            \"segments\":{\"count\":1,\"earliest_retained_offset\":0,\"head_offset\":1},\
            \"consumers\":[],\
            \"resilience\":{\"frozen\":true,\"last_skip_offset\":9,\"records_skipped\":2}}";
        let view = parse_admin_v1(body).unwrap();
        assert!(view.frozen);
        assert_eq!(view.last_skip_offset, 9);
        let text = render_admin_view(&view);
        assert!(text.contains("frozen=true"), "{text}");
    }

    #[test]
    fn a_group_name_with_escapes_round_trips() {
        // A group name carrying an escaped quote and backslash is decoded back to its literal form.
        let body = "{\"schema_version\":1,\
            \"segments\":{\"count\":1,\"earliest_retained_offset\":0,\"head_offset\":1},\
            \"consumers\":[{\"name\":\"a\\\"b\\\\c\",\"committed_offset\":0,\"consumer_lag\":1,\"in_flight\":0}],\
            \"resilience\":{\"frozen\":false,\"last_skip_offset\":0,\"records_skipped\":0}}";
        let view = parse_admin_v1(body).unwrap();
        assert_eq!(view.consumers[0].name, "a\"b\\c");
    }

    #[test]
    fn extract_i64_reads_a_negative_sentinel() {
        // The DLQ `last_dead_lettered_offset` is `-1` when nothing has been dead-lettered; the
        // signed extractor (shared with the `top` view, #93) must read it, where `extract_u64` cannot.
        let scope = "{\"records\":0,\"last_dead_lettered_offset\":-1}";
        assert_eq!(extract_i64(scope, "last_dead_lettered_offset"), Some(-1));
        assert_eq!(extract_i64(scope, "records"), Some(0));
        assert_eq!(extract_i64(scope, "absent"), None);
        // A lone `-` with no digits is not a number.
        assert_eq!(extract_i64("{\"x\":-}", "x"), None);
    }

    #[test]
    fn split_http_response_separates_status_and_body() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
        let (status, body) = split_http_response(resp).unwrap();
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(body, "{\"a\":1}");
    }

    #[test]
    fn a_missing_required_field_names_the_offender() {
        // Drop head_offset: the error must name it so an operator sees what the server failed to send.
        let body = "{\"schema_version\":1,\
            \"segments\":{\"count\":1,\"earliest_retained_offset\":0},\
            \"consumers\":[],\
            \"resilience\":{\"frozen\":false,\"last_skip_offset\":0,\"records_skipped\":0}}";
        let err = parse_admin_v1(body).unwrap_err();
        match err {
            AdminError::Protocol(m) => assert!(m.contains("head_offset"), "{m}"),
            AdminError::Unreachable(m) => panic!("wrong variant: {m}"),
        }
    }

    /// Builds a broker engine, produces `produce_count` records on it directly, then hands it to the
    /// real append actor and starts the `serve_health` server with `admin_enabled`. Returns the live
    /// loopback address plus the shutdown flag and join handles, so a test can drive the real client
    /// against the real server (the production `EngineHandle` path, not a test-only shim).
    fn start_admin_server(
        admin_enabled: bool,
        produce_count: usize,
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        use ironbus_core::delivery::DeliveryConfig;
        use ironbus_core::lease::LeaseConfig;
        use ironbus_core::types::RecordFlags;
        use ironbus_server::actor::{spawn_actor, DEFAULT_CHANNEL_BOUND};
        use ironbus_server::clock::SystemClock;
        use ironbus_server::engine::{DiskFullPolicy, Engine, EngineConfig};
        use ironbus_server::health::serve_health;
        use ironbus_storage::fs::InMemoryFs;
        use ironbus_storage::log::{Append, LogConfig};
        use std::net::TcpListener;
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let mut engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                consume_longpoll_ms: 0,
                min_splice_bytes: 0,
                storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
                log: LogConfig::default(),
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_acked_ahead_runs: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: 1024,
                max_streams: 0,
                max_open_streams: 0,
                max_metric_streams: 1024,
                group_idle_evict_ms: 0,
                ram_ceiling_bytes: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
                dedup: ironbus_core::dedup::DedupConfig::default(),
                durability_level: ironbus_server::engine::DurabilityLevel::Sync,
                flush_interval_ms: 0,
                flush_max_bytes: 0,
                // Backpressure controls (#68, #69) default to inert in this test EngineConfig.
                codel_target_ms: 0,
                codel_interval_ms: 0,
                retry_budget_ratio_per_million: 0,
                retry_budget_window_ms: 0,
                fire_and_forget_msg_rate: 0,
                fire_and_forget_byte_rate: 0,
                fire_and_forget_refill_ms: 0,
                egress_limit: 0,
                wal_fsync_headroom_bytes: 0,
                sync_max_dirty_bytes: 0,
                // Compression OFF (#430): the admin tests pin the historical byte-identical image.
                compression: ironbus_core::compress::Codec::None,
                // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
                // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
                default_message_ttl_ms: 0,
                max_delay_ms: 0,
                dead_letter_exchange: None,
                dead_letter_expired: false,
            },
        )
        .unwrap();
        // Produce on the engine directly BEFORE handing it to the actor, so the served snapshot has a
        // non-trivial head without needing the wire produce path.
        for _ in 0..produce_count {
            engine
                .produce(&Append {
                    timestamp_ms: 0,
                    flags: RecordFlags::EMPTY,
                    key: b"",
                    headers: b"",
                    payload: b"x",
                })
                .unwrap();
        }
        // The production path: own the engine in the append actor and reach it through the handle,
        // exactly as `serve` does.
        let (handle_engine, _actor) = spawn_actor(engine, DEFAULT_CHANNEL_BOUND);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || {
                // Watchdog disabled (window 0): this admin round-trip test does not exercise the #95
                // liveness watchdog, so /healthz keeps its static-200 contract.
                serve_health(
                    &listener,
                    &handle_engine,
                    &shutdown,
                    admin_enabled,
                    &ironbus_server::liveness::LivenessBeacon::new(0),
                    0,
                    &SystemClock::new(),
                )
                .unwrap();
            }
        });
        (addr, shutdown, server)
    }

    #[test]
    fn fetches_and_renders_against_a_live_admin_server() {
        // The END-TO-END HTTP round-trip (#15, #99): start the REAL `serve_health` admin server, then
        // drive `fetch_admin` -> `parse_admin_v1` -> `render_admin_view` against its live loopback
        // port. This proves the CLI renders the operator views from the wire `/admin` body alone (the
        // Accept header is sent, the body is parsed without serde, the views never touch a metric
        // name), the one piece the in-memory parser tests cannot cover.
        use std::sync::atomic::Ordering;

        let (addr, shutdown, server) = start_admin_server(true, 3);

        let body = fetch_admin(&addr.to_string()).expect("fetch the live /admin body");
        let view = parse_admin_v1(&body).expect("parse the live v1 body");
        assert_eq!(view.schema_version, 1);
        assert_eq!(
            view.head_offset, 3,
            "the segment head reflects the 3 produces"
        );
        assert_eq!(view.segment_count, 1);
        assert!(!view.frozen);
        // The default group is present with full lag (nothing consumed).
        assert!(view
            .consumers
            .iter()
            .any(|c| c.name.is_empty() && c.consumer_lag == 3));
        let text = render_admin_view(&view);
        assert!(text.contains("segments: count=1 span=[0, 3)"), "{text}");
        assert!(text.contains("last_skip_offset=0"), "{text}");

        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
    }

    #[test]
    fn a_disabled_admin_endpoint_is_a_clear_not_enabled_error() {
        // When the broker did NOT enable admin, /admin is a 404; the client must surface a clear
        // "not enabled" message (mapped to exit-internal), not a confusing parse error.
        use std::sync::atomic::Ordering;

        let (addr, shutdown, server) = start_admin_server(false, 0);

        let err = fetch_admin(&addr.to_string()).unwrap_err();
        match err {
            AdminError::Protocol(m) => assert!(m.contains("not enabled"), "{m}"),
            AdminError::Unreachable(m) => panic!("wrong variant: {m}"),
        }

        shutdown.store(true, Ordering::Release);
        server.join().unwrap();
    }
}
