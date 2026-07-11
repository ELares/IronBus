// SPDX-License-Identifier: MIT OR Apache-2.0
//! `ironbus-iceberg-sink`: consume an IronBus topic and materialize it as an Apache Iceberg table
//! (Parquet data + Iceberg v2 metadata) in a local directory (#793, phase 1).

// The docs name products (IronBus, DuckDB, ...) that trip the CamelCase doc-markdown heuristic.
#![allow(clippy::doc_markdown)]

use anyhow::Result;
use clap::Parser;
use ironbus_iceberg_sink::{run, RunMode, SinkConfig};

/// Materialize an IronBus topic as an Apache Iceberg/Parquet table in object storage.
///
/// The broker is untouched: this is a standalone consumer that writes an open, analytics-queryable
/// table (DuckDB / Spark / Trino / Snowflake) entirely outside the broker. Phase 1 targets a local
/// directory object store; S3/GCS + a REST catalog are follow-ups.
#[derive(Parser, Debug)]
#[command(name = "ironbus-iceberg-sink", version, about)]
struct Cli {
    /// Broker address, host:port.
    #[arg(long, default_value = "127.0.0.1:7777")]
    addr: String,

    /// Stream to consume (empty = the default stream).
    #[arg(long, default_value = "")]
    stream: String,

    /// Durable consumer group name.
    #[arg(long, default_value = "iceberg-sink")]
    group: String,

    /// Output table location (a local directory).
    #[arg(long)]
    output: String,

    /// Records per fetch/append window.
    #[arg(long, default_value_t = 10_000)]
    batch_max_records: u32,

    /// Byte budget per fetch window (0 = unbounded by bytes).
    #[arg(long, default_value_t = 0)]
    batch_max_bytes: u64,

    /// Offset a BRAND-NEW table starts materializing from (ignored once the table exists).
    #[arg(long, default_value_t = 0)]
    start_offset: i64,

    /// Keep following the topic forever (default: drain to the head and exit).
    #[arg(long, default_value_t = false)]
    follow: bool,

    /// Poll interval in follow mode, milliseconds.
    #[arg(long, default_value_t = 500)]
    poll_interval_ms: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = SinkConfig {
        addr: cli.addr,
        stream: cli.stream,
        group: cli.group,
        output: cli.output,
        batch_max_records: cli.batch_max_records,
        batch_max_bytes: cli.batch_max_bytes,
        start_offset: cli.start_offset,
        mode: if cli.follow {
            RunMode::Follow
        } else {
            RunMode::DrainAndExit
        },
        poll_interval_ms: cli.poll_interval_ms,
    };

    eprintln!(
        "ironbus-iceberg-sink: broker={} stream={:?} group={} -> {} (mode={:?})",
        cfg.addr, cfg.stream, cfg.group, cfg.output, cfg.mode
    );
    let stats = run(&cfg)?;
    println!(
        "done: wrote {} records in {} snapshot(s); table watermark = offset {} (broker cursor committed to {})",
        stats.records_written, stats.batches, stats.final_next_offset, stats.last_committed_offset
    );
    Ok(())
}
