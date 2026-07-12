// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tiered storage (#643, V2-M10, phase 2): the S3 backend (`S3ColdStore`) exercised against a MOCK
//! S3 HTTP server (a tiny in-process `std::net` server — no network, no real S3, no extra dependency).
//!
//! Two proofs:
//!   1. the `ColdStore` CONTRACT over the wire — put/get round-trip byte-exact, idempotent delete,
//!      `exists`, a 404 GET => typed `NotFound`, a 403 (bad auth) => a typed transport error (NOT
//!      masked as `NotFound`); and every request my client sends carries a well-formed `SigV4`
//!      `Authorization` (+ `x-amz-date` + `x-amz-content-sha256`) header (the mock 403s otherwise);
//!   2. the SAME `Log` offload/fetch/reap machinery drives the S3 backend byte-for-byte identically to
//!      `FsColdStore` (mirrors the `cold_tiering.rs` suite).
//!
//! Gated on the `s3` feature (the backend + its deps only exist there). The full-endpoint `SigV4`
//! correctness is proven separately, without network, by the AWS test-vector unit tests in `cold.rs`.
#![cfg(feature = "s3")]
// The mock filters `seg-*.log` files by suffix; the file-extension lint is not meaningful here.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ironbus_core::clock::ManualClock;
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_storage::cold::{
    cold_object_name, ColdStorageConfig, ColdStore, ColdStoreError, S3ColdStore, S3ColdStoreConfig,
};
use ironbus_storage::fs::{Filesystem, InMemoryFs};
use ironbus_storage::log::{Append, Log, LogConfig, RetentionBounds};

type TestLog = Log<InMemoryFs, ManualClock>;

/// A shared object map: request-path (`/bucket/key`) -> object bytes.
type Store = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// Starts a mock S3 server on an ephemeral port; returns `(endpoint_url, store)`. The server runs on a
/// detached thread and lives for the test process. It VALIDATES that every request carries a
/// well-formed `SigV4` `Authorization` header (else 403), then routes PUT/GET/DELETE/HEAD over the store.
fn start_mock_s3() -> (String, Store) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let store: Store = Arc::new(Mutex::new(HashMap::new()));
    let store_for_thread = Arc::clone(&store);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let store = Arc::clone(&store_for_thread);
            // One request per connection (the client opens a fresh connection per op).
            std::thread::spawn(move || handle_conn(stream, &store));
        }
    });
    (format!("http://{addr}"), store)
}

/// Handles ONE HTTP/1.1 request on `stream`, mutating/serving `store`, and writes the response.
fn handle_conn(mut stream: TcpStream, store: &Store) {
    // Read until the header terminator `\r\n\r\n`, then read any Content-Length body.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    // Parse headers (lowercased names).
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    // SigV4 header validation: every signed request must carry these.
    let auth_ok = headers
        .get("authorization")
        .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256 ") && a.contains("Signature="))
        && headers.contains_key("x-amz-date")
        && headers.contains_key("x-amz-content-sha256");
    if !auth_ok {
        write_response(&mut stream, 403, "Forbidden", b"missing/invalid SigV4 auth");
        return;
    }

    // Read the body (Content-Length).
    let content_length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
        }
    }
    body.truncate(content_length);

    match method.as_str() {
        "PUT" => {
            store.lock().unwrap().insert(path, body);
            write_response(&mut stream, 200, "OK", b"");
        }
        "GET" => match store.lock().unwrap().get(&path).cloned() {
            Some(bytes) => write_response(&mut stream, 200, "OK", &bytes),
            None => write_response(&mut stream, 404, "Not Found", b""),
        },
        "HEAD" => {
            let present = store.lock().unwrap().contains_key(&path);
            let (code, reason) = if present {
                (200, "OK")
            } else {
                (404, "Not Found")
            };
            // HEAD: headers only, no body.
            write_response(&mut stream, code, reason, b"");
        }
        "DELETE" => {
            // Idempotent: 204 whether or not it existed.
            store.lock().unwrap().remove(&path);
            write_response(&mut stream, 204, "No Content", b"");
        }
        _ => write_response(&mut stream, 405, "Method Not Allowed", b""),
    }
}

fn write_response(stream: &mut TcpStream, code: u16, reason: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// An `S3ColdStore` pointed at the mock, path-style, with dummy static credentials.
fn s3_store(endpoint: &str, bucket: &str, prefix: &str) -> S3ColdStore {
    S3ColdStore::new(S3ColdStoreConfig {
        bucket: bucket.to_string(),
        prefix: prefix.to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some(endpoint.to_string()),
        path_style: true,
        access_key_id: "AKIDEXAMPLE".to_string(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
        session_token: None,
        ca_pem: None,
        connect_timeout: None,
        request_timeout: None,
    })
    .expect("build S3ColdStore")
}

#[test]
fn s3_cold_store_contract_over_the_wire() {
    let (endpoint, _store) = start_mock_s3();
    let store = s3_store(&endpoint, "ironbus-cold", "log-0");
    let key = cold_object_name(7);

    assert!(!store.exists(&key).unwrap());
    assert!(matches!(
        store.get(&key).unwrap_err(),
        ColdStoreError::NotFound { .. }
    ));

    let bytes = b"a sealed segment's bytes".to_vec();
    store.put(&key, &bytes).unwrap();
    assert!(store.exists(&key).unwrap());
    assert_eq!(store.get(&key).unwrap(), bytes);

    // Idempotent overwrite.
    let replacement = b"shorter".to_vec();
    store.put(&key, &replacement).unwrap();
    assert_eq!(store.get(&key).unwrap(), replacement);

    // Idempotent delete: gone, and a second delete of the absent key is still Ok.
    store.delete(&key).unwrap();
    assert!(!store.exists(&key).unwrap());
    store.delete(&key).unwrap();
}

#[test]
fn s3_bad_auth_is_a_typed_error_not_not_found() {
    // A store whose SECRET differs from what the mock would accept still SENDS an Authorization header,
    // so the mock accepts the shape — to prove 403 mapping, point at a server that always 403s.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut s = stream;
            // Drain a bit then always 403 (simulate an auth/permission failure).
            let mut tmp = [0u8; 1024];
            let _ = s.read(&mut tmp);
            write_response(&mut s, 403, "Forbidden", b"AccessDenied");
        }
    });
    let store = s3_store(&format!("http://{addr}"), "b", "p");
    // A 403 must be a typed transport error, NOT NotFound (a permission failure must not look like a
    // completed reap or an absent object).
    let err = store.get(&cold_object_name(1)).unwrap_err();
    assert!(
        matches!(err, ColdStoreError::Io(_)),
        "403 must map to Io, not NotFound: {err:?}"
    );
    let del = store.delete(&cold_object_name(1));
    assert!(del.is_err(), "a 403 DELETE must surface, not be masked Ok");
}

// ---- Log-driven offload/fetch/reap through the S3 backend (mirrors cold_tiering.rs) ----

fn config() -> LogConfig {
    LogConfig {
        max_segment_bytes: 256,
        ..LogConfig::default()
    }
}

fn append_n(log: &mut TestLog, n: u64) {
    for i in 0..n {
        let payload = i.to_le_bytes();
        log.append(&Append {
            timestamp_ms: 1_700_000_000_000 + i,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: &payload,
        })
        .unwrap();
        log.sync().unwrap();
    }
}

fn read_all(log: &TestLog) -> Vec<(u64, Vec<u8>)> {
    log.read_from(Offset::ZERO, 100_000)
        .unwrap()
        .into_iter()
        .map(|r| (r.offset.get(), r.payload.to_vec()))
        .collect()
}

fn local_segment_count(fs: &InMemoryFs) -> usize {
    fs.list()
        .unwrap()
        .into_iter()
        .filter(|n| n.starts_with("seg-") && n.ends_with(".log"))
        .count()
}

#[test]
fn log_offloads_to_s3_and_reads_back_then_reaps() {
    let data_fs = InMemoryFs::new();
    let (endpoint, _store) = start_mock_s3();
    let cold: Arc<dyn ColdStore> = Arc::new(s3_store(&endpoint, "ironbus-cold", "default"));

    let mut log = Log::open(data_fs.clone(), ManualClock::new(), config()).unwrap();
    log.set_cold_store(Arc::clone(&cold), ColdStorageConfig::enabled(1));
    append_n(&mut log, 60);

    let baseline = read_all(&log);
    let local_before = local_segment_count(&data_fs);
    assert!(local_before >= 3, "workload should roll several segments");

    let offloaded = log.offload_cold_segments().unwrap();
    assert!(offloaded > 0, "at least one cold segment offloads");

    // Segment 0: local file gone, manifest REMOTE, and the OBJECT is durable in S3 (probed via HEAD).
    assert!(log.is_segment_remote(0));
    assert!(!data_fs.exists(&format!("seg-{:016x}.log", 0u64)).unwrap());
    assert!(
        cold.exists(&cold_object_name(0)).unwrap(),
        "the offloaded object must be durable in S3"
    );
    assert!(local_segment_count(&data_fs) < local_before);

    // A read spanning the offloaded prefix transparently GETs from S3 + serves it byte-exact.
    assert_eq!(
        read_all(&log),
        baseline,
        "offloaded records read back byte-exact"
    );

    // Retention reap of the offloaded segment DELETEs the S3 object (no orphan).
    let bounds = RetentionBounds {
        max_bytes: 128,
        max_age_ms: 0,
        max_messages: 0,
    };
    let protect = log.next_offset().get();
    log.reap(bounds, protect).unwrap();
    assert!(!log.is_segment_remote(0));
    assert!(
        !cold.exists(&cold_object_name(0)).unwrap(),
        "reaping an offloaded segment must DELETE the S3 object (no orphan)"
    );
}

#[test]
fn a_hung_endpoint_times_out_and_never_wedges_the_actor() {
    // A server that ACCEPTS the TCP connection but NEVER responds — a routine partition /
    // security-group / throttle blackhole. Without per-step timeouts this would wedge the single-writer
    // append actor forever (offload/reap/fetch-on-read all run on it). With them, each op must RETURN a
    // typed TIMEOUT error within ~the bound, never hang, and NEVER a false NotFound.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        // Accept every connection and hold it open, reading nothing, writing nothing (blackhole).
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });

    let store = S3ColdStore::new(S3ColdStoreConfig {
        bucket: "b".to_string(),
        prefix: "p".to_string(),
        region: "us-east-1".to_string(),
        endpoint: Some(format!("http://{addr}")),
        path_style: true,
        access_key_id: "AKIDEXAMPLE".to_string(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
        session_token: None,
        ca_pem: None,
        connect_timeout: Some(Duration::from_millis(500)),
        request_timeout: Some(Duration::from_millis(500)),
    })
    .unwrap();

    let key = cold_object_name(1);
    let start = Instant::now();
    let err = store.get(&key).unwrap_err();
    let elapsed = start.elapsed();
    // A timeout is a typed, RETRYABLE Io(TimedOut) — NOT NotFound (a hang is not "object absent").
    assert!(
        matches!(err, ColdStoreError::Io(ref e) if e.kind() == std::io::ErrorKind::TimedOut),
        "a hung endpoint must yield a typed timeout, got {err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the op must return promptly (it did not hang), took {elapsed:?}"
    );
    // put + exists likewise RETURN (do not hang).
    assert!(
        store.put(&key, b"x").is_err(),
        "put must time out, not hang"
    );
    assert!(
        store.exists(&key).is_err(),
        "exists must time out, not hang"
    );
}
