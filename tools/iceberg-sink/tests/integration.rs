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
use ironbus_iceberg_sink::{run, scan_offsets, IcebergTable, Record, RunMode, SinkConfig};
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
        // Threshold above the ~6 snapshots this test makes, so it does NOT compact: keeps the base
        // materialize/resume test exercising the plain append path unchanged.
        manifest_compaction_threshold: 16,
        snapshot_retention_count: 10,
    }
}

/// Like [`sink_config`] but with a small compaction threshold + retention window, so compaction fires
/// mid-run and the snapshot log stays bounded.
fn compacting_sink_config(addr: &str, output: &str) -> SinkConfig {
    SinkConfig {
        batch_max_records: 2, // 2 records/append => many manifests, so compaction triggers
        manifest_compaction_threshold: 6,
        snapshot_retention_count: 4,
        ..sink_config(addr, output)
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

/// End-to-end proof that compaction fires DURING a real sink run against a live broker, that the
/// table still reads back every row through the real Iceberg chain, that the snapshot log stays
/// bounded, and that a COLD RESTART after compaction resumes at the correct watermark with no dups.
#[test]
fn end_to_end_compaction_and_resume() {
    let Ok(bin) = std::env::var("IRONBUS_BIN") else {
        eprintln!("SKIP: IRONBUS_BIN not set");
        return;
    };
    assert!(
        PathBuf::from(&bin).exists(),
        "IRONBUS_BIN {bin} does not exist"
    );

    let broker = boot_broker(&bin);
    let table_dir = tempfile::tempdir().unwrap();
    let output = table_dir.path().join("compact_table");
    let output = output.to_str().unwrap();

    // --- Phase 1: produce 40, sink with compaction enabled -> it must compact mid-run ---
    produce(&broker.addr, 0, 40);
    let stats = run(&compacting_sink_config(&broker.addr, output)).expect("compacting sink run 1");
    assert_eq!(stats.records_written, 40, "run 1 writes all 40");
    assert!(
        stats.compactions >= 1,
        "40 records / batch 2 / threshold 6 must trigger at least one compaction (got {})",
        stats.compactions
    );
    assert!(
        stats.snapshots_expired >= 1,
        "compaction with retention 4 must expire snapshots"
    );
    assert_eq!(
        sorted_offsets(output),
        (0..40).collect::<Vec<_>>(),
        "every row survives compaction, contiguous, no dup/drop"
    );

    // The snapshot log is bounded (retention 4 + at most one threshold window of 6 accumulated since
    // the last compaction), NOT the 20 a no-compaction run would have left.
    let reopened = IcebergTable::open_or_create(output, 0).unwrap();
    assert_eq!(
        reopened.next_offset(),
        40,
        "watermark intact after compaction"
    );
    assert!(
        reopened.snapshot_count() <= 10,
        "snapshot log must be bounded by retention (got {})",
        reopened.snapshot_count()
    );
    // The manifest set stays bounded by the compaction threshold (each compaction resets it to 1 and
    // it grows by one per append), NOT the 20 a no-compaction run would accumulate.
    assert!(
        reopened.current_manifest_count().unwrap() <= 6,
        "manifest set must stay bounded by the compaction threshold (got {})",
        reopened.current_manifest_count().unwrap()
    );

    // --- Phase 2: produce 15 more, RESTART the sink (cold resume after compaction) ---
    produce(&broker.addr, 40, 15);
    let stats2 = run(&compacting_sink_config(&broker.addr, output))
        .expect("compacting sink run 2 (restart)");
    assert_eq!(
        stats2.records_written, 15,
        "resume after compaction writes only the 15 new records — no re-materialization"
    );
    assert_eq!(
        sorted_offsets(output),
        (0..55).collect::<Vec<_>>(),
        "no duplicates across the compaction + restart boundary"
    );

    // --- Phase 3: no new data -> a pure no-op ---
    let stats3 = run(&compacting_sink_config(&broker.addr, output)).expect("compacting sink run 3");
    assert_eq!(stats3.records_written, 0);
    assert_eq!(sorted_offsets(output), (0..55).collect::<Vec<_>>());

    // Belt-and-suspenders: no duplicate offsets anywhere.
    let all = scan_offsets(output).unwrap();
    let mut unique = all.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        all.len(),
        unique.len(),
        "no duplicate offsets after compaction"
    );
    assert_eq!(all.len(), 55);
}

/// Writes a COMPACTED table to `ICEBERG_SINK_PROOF_DIR` and leaves it on disk, so an EXTERNAL engine
/// (`DuckDB`, via `scripts/duckdb-verify.sh`) can prove the compacted table is queryable and its
/// offsets are contiguous with no dup/drop. Broker-free (drives the table API directly); a no-op skip
/// when the env var is unset, so a plain `cargo test` stays green.
#[test]
fn compaction_duckdb_external_query_proof() {
    let Ok(dir) = std::env::var("ICEBERG_SINK_PROOF_DIR") else {
        eprintln!("SKIP: ICEBERG_SINK_PROOF_DIR not set (no external-query proof requested)");
        return;
    };

    let mut t = IcebergTable::open_or_create(&dir, 0).unwrap();
    // 100 rows across 20 snapshots (5 rows each), then compact to a single manifest, retention 3.
    for b in 0..20i64 {
        let recs: Vec<Record> = (b * 5..b * 5 + 5)
            .map(|offset| Record {
                offset,
                timestamp_ms: 1_700_000_000_000 + offset,
                flags: 0,
                key: format!("k{offset}").into_bytes(),
                headers: Vec::new(),
                payload: format!("payload-{offset}").into_bytes(),
            })
            .collect();
        t.append(&recs).unwrap();
    }
    let stats = t.compact_and_expire(3).unwrap();
    assert!(
        stats.manifests_before >= 2,
        "table must have accumulated manifests"
    );
    assert_eq!(
        t.current_manifest_count().unwrap(),
        1,
        "compacted to one manifest"
    );
    assert_eq!(t.snapshot_count(), 3, "snapshot log trimmed to retention");

    let mut got = scan_offsets(&dir).unwrap();
    got.sort_unstable();
    assert_eq!(
        got,
        (0..100).collect::<Vec<_>>(),
        "all 100 rows survive compaction"
    );
    eprintln!(
        "PROOF TABLE WRITTEN: {dir} (100 rows 0..100, compacted {} manifests -> 1, {} snapshots expired, {} stale files reclaimed)",
        stats.manifests_before, stats.snapshots_expired, stats.files_deleted
    );
}
