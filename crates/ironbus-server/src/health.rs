// SPDX-License-Identifier: MIT OR Apache-2.0
//! A minimal HTTP health endpoint for an operator or an orchestrator probe.
//!
//! Two routes on a loopback HTTP port (#16): `GET /healthz` is liveness (this loop is
//! running, so the process is up) and `GET /readyz` is readiness (the broker's durable log
//! writer is not frozen, so it can still accept writes). Everything else is `404`, and a
//! non-`GET` is `405`. The parser reads only the bounded request line, sets read and write
//! timeouts, and closes after one response, so a slow or hostile client cannot wedge the
//! loop. This is the first slice of the observability surface; `OpenMetrics` `/metrics` and
//! structured introspection are follow-ups under #16.

use crate::server::SharedEngine;
use ironbus_core::clock::Clock;
use ironbus_storage::fs::Filesystem;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::PoisonError;
use std::time::Duration;

/// How long to wait between non-blocking accept polls.
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// Per-connection read/write timeout (slowloris defense).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// The request line is bounded; a client that sends no newline within this many bytes is
/// rejected rather than buffered without limit.
const MAX_REQUEST_LINE: usize = 8 * 1024;

/// Serves the health endpoints over `listener` until `shutdown` is set. Connections are
/// handled inline (health traffic is low and loopback), each bounded by [`REQUEST_TIMEOUT`].
///
/// # Errors
/// Returns an IO error only from configuring the listener; per-connection IO errors are
/// contained so one bad client never ends the loop.
pub fn serve_health<F, C>(
    listener: &TcpListener,
    engine: &SharedEngine<F, C>,
    shutdown: &AtomicBool,
) -> std::io::Result<()>
where
    F: Filesystem,
    C: Clock,
{
    listener.set_nonblocking(true)?;
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // One bad client must not end the loop; contain its IO error.
                let _ = handle(stream, engine);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            // A transient accept failure must not tear the listener down.
            Err(_) => std::thread::sleep(ACCEPT_POLL),
        }
    }
    Ok(())
}

fn handle<F, C>(mut stream: TcpStream, engine: &SharedEngine<F, C>) -> std::io::Result<()>
where
    F: Filesystem,
    C: Clock,
{
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;

    // Read the request line into a bounded buffer (chunked, so a dribble cannot run forever).
    let mut buf = vec![0u8; MAX_REQUEST_LINE];
    let mut len = 0;
    let newline = loop {
        if len == buf.len() {
            return respond(&mut stream, 414, "URI Too Long", "request line too long");
        }
        let n = stream.read(&mut buf[len..])?;
        if n == 0 {
            return Ok(()); // the client closed before sending a request line
        }
        len += n;
        if let Some(pos) = buf[..len].iter().position(|&b| b == b'\n') {
            break pos;
        }
    };

    // Parse "METHOD PATH VERSION" (a leading CR is trimmed by split_whitespace).
    let line = String::from_utf8_lossy(&buf[..newline]);
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_path = parts.next().unwrap_or("");
    if method != "GET" {
        return respond(
            &mut stream,
            405,
            "Method Not Allowed",
            "only GET is supported",
        );
    }
    // Drop any query string.
    let path = raw_path.split('?').next().unwrap_or(raw_path);

    match path {
        "/healthz" => respond(&mut stream, 200, "OK", "ok"),
        "/readyz" => {
            let healthy = engine
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_healthy();
            if healthy {
                respond(&mut stream, 200, "OK", "ready")
            } else {
                respond(&mut stream, 503, "Service Unavailable", "writer frozen")
            }
        }
        _ => respond(&mut stream, 404, "Not Found", "unknown endpoint"),
    }
}

fn respond(stream: &mut TcpStream, code: u16, reason: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::engine::{Engine, EngineConfig};
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;
    use std::sync::{Arc, Mutex};

    fn start() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, vec![]).unwrap(),
                max_in_flight: 16,
                checkpoint_interval: 1024,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve_health(&listener, &shared, &shutdown).unwrap()
        });
        (addr, shutdown, handle)
    }

    /// Sends one raw request and returns the full response text.
    fn request(addr: std::net::SocketAddr, raw: &str) -> String {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(raw.as_bytes()).unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn healthz_is_ok_and_readyz_is_ready_on_a_live_broker() {
        let (addr, shutdown, handle) = start();

        let h = request(addr, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(h.starts_with("HTTP/1.1 200 OK"), "{h}");
        assert!(h.ends_with("ok"), "{h}");

        let r = request(addr, "GET /readyz HTTP/1.1\r\n\r\n");
        assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(r.ends_with("ready"), "{r}");

        // A query string is stripped.
        let q = request(addr, "GET /healthz?probe=1 HTTP/1.1\r\n\r\n");
        assert!(q.starts_with("HTTP/1.1 200 OK"), "{q}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn unknown_path_is_404_and_non_get_is_405() {
        let (addr, shutdown, handle) = start();

        let nf = request(addr, "GET /nope HTTP/1.1\r\n\r\n");
        assert!(nf.starts_with("HTTP/1.1 404 Not Found"), "{nf}");

        let na = request(addr, "POST /healthz HTTP/1.1\r\n\r\n");
        assert!(na.starts_with("HTTP/1.1 405 Method Not Allowed"), "{na}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_bare_newline_request_line_does_not_panic() {
        let (addr, shutdown, handle) = start();
        // A malformed request (just a newline) yields 405 (empty method != GET), never a panic.
        let r = request(addr, "\r\n");
        assert!(r.starts_with("HTTP/1.1 405"), "{r}");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }
}
