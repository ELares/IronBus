// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end integration test against a REAL broker subprocess.
//!
//! Gated on the `IRONBUS_BIN` env var pointing at a built `ironbus` binary (the broker lives in the
//! root workspace, which this excluded crate does not build). When unset the test is a no-op skip,
//! so a plain `cargo test` here stays green; the full proof sets `IRONBUS_BIN`. The test:
//!   1. boots a broker, produces N records,
//!   2. runs the sink (drain-and-exit) and asserts the table has exactly the N contiguous offsets,
//!   3. produces M more and runs the sink AGAIN (a fresh open = a restart), asserting the table now
//!      has N+M contiguous offsets with NO duplicates, and that a third run with no new data writes
//!      nothing.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use ironbus_client::Client;
use ironbus_iceberg_sink::{run, scan_offsets, RunMode, SinkConfig};
use ironbus_proto::message::PubBody;

/// Kills the broker child on drop so a failed assertion never leaks a process.
struct Broker {
    child: Child,
    addr: String,
    _data: tempfile::TempDir,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn boot_broker(bin: &str) -> Broker {
    let data = tempfile::tempdir().unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(bin)
        .args([
            "serve",
            "--data-dir",
            data.path().to_str().unwrap(),
            "--addr",
            &addr,
        ])
        .spawn()
        .expect("spawn ironbus serve");

    // Wait until the broker accepts connections.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Client::connect(&addr).is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "broker did not come up at {addr}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Broker {
        child,
        addr,
        _data: data,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Produces `count` records to the default stream, returning the last assigned offset + 1.
fn produce(addr: &str, start: usize, count: usize) {
    let mut client = Client::connect(addr).expect("connect producer");
    for i in start..start + count {
        let payload = format!("event-{i}");
        client
            .produce(&PubBody {
                flags: 0,
                timestamp_ms: now_ms(),
                key: format!("k{i}").as_bytes(),
                headers: b"",
                dedup: None,
                fire_and_forget: false,
                payload: payload.as_bytes(),
            })
            .expect("produce");
    }
}

fn sink_config(addr: &str, output: &str) -> SinkConfig {
    SinkConfig {
        addr: addr.to_string(),
        stream: String::new(),
        group: "iceberg-sink-it".to_string(),
        output: output.to_string(),
        batch_max_records: 3, // small so N records span multiple snapshots
        batch_max_bytes: 0,
        start_offset: 0,
        mode: RunMode::DrainAndExit,
        poll_interval_ms: 50,
    }
}

fn sorted_offsets(output: &str) -> Vec<i64> {
    let mut v = scan_offsets(output).expect("scan table");
    v.sort_unstable();
    v
}

#[test]
fn end_to_end_materialize_and_resume() {
    let Ok(bin) = std::env::var("IRONBUS_BIN") else {
        eprintln!(
            "SKIP: IRONBUS_BIN not set (no broker binary to run the end-to-end test against)"
        );
        return;
    };
    assert!(
        PathBuf::from(&bin).exists(),
        "IRONBUS_BIN {bin} does not exist"
    );

    let broker = boot_broker(&bin);
    let table_dir = tempfile::tempdir().unwrap();
    let output = table_dir.path().join("orders_table");
    let output = output.to_str().unwrap();

    // --- Phase 1: produce 10, sink, expect offsets 0..10 contiguous ---
    produce(&broker.addr, 0, 10);
    let stats = run(&sink_config(&broker.addr, output)).expect("sink run 1");
    assert_eq!(stats.records_written, 10, "run 1 should write all 10");
    assert!(
        stats.batches >= 2,
        "10 records / batch 3 spans multiple snapshots"
    );
    assert_eq!(
        sorted_offsets(output),
        (0..10).collect::<Vec<_>>(),
        "table must hold exactly offsets 0..10, contiguous, no dup/drop"
    );
    let watermark_after_1 = stats.final_next_offset;
    assert_eq!(watermark_after_1, 10);

    // --- Phase 2: produce 7 more, RESTART the sink, expect 0..17 with NO duplicates ---
    produce(&broker.addr, 10, 7);
    let stats2 = run(&sink_config(&broker.addr, output)).expect("sink run 2 (restart)");
    assert_eq!(
        stats2.records_written, 7,
        "run 2 should write only the 7 new records"
    );
    assert_eq!(
        sorted_offsets(output),
        (0..17).collect::<Vec<_>>(),
        "resume must add only new records — no duplicates across the restart boundary"
    );

    // --- Phase 3: run again with NO new data: a pure no-op, no empty snapshot ---
    let stats3 = run(&sink_config(&broker.addr, output)).expect("sink run 3 (idempotent)");
    assert_eq!(stats3.records_written, 0, "run 3 has nothing new to write");
    assert_eq!(sorted_offsets(output), (0..17).collect::<Vec<_>>());

    // Every offset appears exactly once (belt-and-suspenders dedup check).
    let all = scan_offsets(output).unwrap();
    let mut unique = all.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(all.len(), unique.len(), "no duplicate offsets in the table");
    assert_eq!(all.len(), 17);
}
