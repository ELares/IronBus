// SPDX-License-Identifier: MIT OR Apache-2.0
//! A tiny, dependency-free HTTP GET for the broker's health-server text endpoints (V2-M6, #589,
//! #592): `GET /metrics` (Prometheus text exposition) and the Nagios-style health probes
//! (`/healthz`, `/readyz`). It mirrors the trust model and the bounded-read defenses of
//! [`crate::admin::fetch_admin`] (a per-request timeout and a hard body cap so a hung or hostile
//! server cannot wedge the CLI), but speaks the PLAIN-text endpoints rather than the `/admin` JSON.
//!
//! READ-ONLY: every call is a `GET` against the existing health server; this module NEVER mutates
//! the broker and NEVER changes `crates/ironbus-server/`. A missing or disabled endpoint, an
//! unreachable port, or a non-200 status is mapped to a typed error the caller projects onto the
//! frozen CLI exit-code scheme.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// A read failure from the health-server text endpoints. The caller maps each variant onto the
/// frozen CLI exit codes: [`HttpError::Unreachable`] → broker-unreachable (5),
/// [`HttpError::Status`] / [`HttpError::Protocol`] → internal (70). A 404/503 carries its status so
/// the probe verbs can classify it (e.g. `/readyz` 503 = not ready, NOT unreachable).
#[derive(Debug)]
pub(crate) enum HttpError {
    /// The health server could not be reached or dropped the connection mid-exchange.
    Unreachable(String),
    /// The server answered with a non-200 status. Carries the numeric `status` so a probe can
    /// distinguish a healthy 200 from a 503 (degraded) or 404 (endpoint absent) without re-parsing.
    Status { status: u16, body: String },
    /// The server answered but the response was not a usable HTTP response (no header/body split,
    /// an over-long body, or an unparseable status line).
    Protocol(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Unreachable(m) | HttpError::Protocol(m) => f.write_str(m),
            HttpError::Status { status, body } => {
                write!(f, "the endpoint returned HTTP {status}: {}", body.trim())
            }
        }
    }
}

/// Per-request read/write timeout for a health-endpoint fetch (slow-server defense). Matches the
/// `/admin` client's bound.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// The hard bound on a response body. A `/metrics` body is a bounded set of counters and a few
/// histograms; 1 MiB is far above any real body and well below a memory hazard.
const MAX_BODY: usize = 1 << 20; // 1 MiB

/// Fetches `path` from the health server at `addr` over plain HTTP. On a 200, returns the response
/// body. On any non-200, returns [`HttpError::Status`] carrying the status so the caller decides
/// whether it is degraded (503), absent (404), or a hard error. Bounded by [`REQUEST_TIMEOUT`] and
/// [`MAX_BODY`] so a hung or hostile server cannot wedge the CLI.
///
/// # Errors
/// [`HttpError::Unreachable`] on a connect/IO failure; [`HttpError::Status`] on a non-200;
/// [`HttpError::Protocol`] on an unparseable or over-long response.
pub(crate) fn fetch(addr: &str, path: &str) -> Result<String, HttpError> {
    let (status, body) = fetch_status(addr, path)?;
    if status == 200 {
        Ok(body)
    } else {
        Err(HttpError::Status { status, body })
    }
}

/// Like [`fetch`] but returns the `(status, body)` pair even for a non-200, so a probe verb that
/// MUST inspect a 503 (degraded) or 404 (endpoint absent) gets the status without it being folded
/// into an error. A transport failure is still [`HttpError::Unreachable`]; a malformed HTTP
/// response is still [`HttpError::Protocol`].
///
/// # Errors
/// [`HttpError::Unreachable`] on a connect/IO failure; [`HttpError::Protocol`] on a malformed or
/// over-long response.
pub(crate) fn fetch_status(addr: &str, path: &str) -> Result<(u16, String), HttpError> {
    let mut stream = TcpStream::connect(addr).map_err(|e| {
        HttpError::Unreachable(format!("cannot reach health server at {addr}: {e}"))
    })?;
    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(REQUEST_TIMEOUT)))
        .map_err(|e| HttpError::Unreachable(format!("cannot set socket timeout: {e}")))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| HttpError::Unreachable(format!("cannot send request: {e}")))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|e| HttpError::Unreachable(format!("cannot read response: {e}")))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_BODY {
            return Err(HttpError::Protocol(
                "response exceeded the size bound".to_string(),
            ));
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (status_line, body) = split_http_response(&text)
        .ok_or_else(|| HttpError::Protocol("malformed HTTP response".to_string()))?;
    let status = parse_status_code(status_line)
        .ok_or_else(|| HttpError::Protocol(format!("unparseable status line: {status_line}")))?;
    Ok((status, body.to_string()))
}

/// Splits a raw HTTP response into its (status line, body), or `None` if the header/body boundary is
/// absent. The status line is the first line; the body is everything after the blank line.
fn split_http_response(text: &str) -> Option<(&str, &str)> {
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))?;
    let status_line = head.lines().next().unwrap_or("");
    Some((status_line, body))
}

/// Parses the numeric status code out of an HTTP status line (`HTTP/1.1 200 OK` → `200`). Returns
/// `None` if the second whitespace-delimited token is not a 3-digit code.
fn parse_status_code(status_line: &str) -> Option<u16> {
    let code = status_line.split_whitespace().nth(1)?;
    code.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_http_response_separates_status_and_body() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody-here";
        let (status, body) = split_http_response(resp).unwrap();
        assert_eq!(status, "HTTP/1.1 200 OK");
        assert_eq!(body, "body-here");
    }

    #[test]
    fn parse_status_code_reads_the_numeric_code() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), Some(200));
        assert_eq!(
            parse_status_code("HTTP/1.1 503 Service Unavailable"),
            Some(503)
        );
        assert_eq!(parse_status_code("HTTP/1.1 404 Not Found"), Some(404));
        assert_eq!(parse_status_code("garbage"), None);
        assert_eq!(parse_status_code("HTTP/1.1 notacode OK"), None);
    }

    #[test]
    fn http_error_status_displays_status_and_trimmed_body() {
        let e = HttpError::Status {
            status: 503,
            body: "  writer frozen\n".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "the endpoint returned HTTP 503: writer frozen"
        );
    }
}
