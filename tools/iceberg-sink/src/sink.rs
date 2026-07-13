// SPDX-License-Identifier: MIT OR Apache-2.0
//! The consume loop: connect to a live broker, stream a topic in windows, and materialize each
//! window as an Iceberg append.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use ironbus_client::{Client, ClientConfig, Message};
use ironbus_proto::message::ConsumeTier;

use crate::config::{RunMode, SinkConfig};
use crate::table::{IcebergTable, Record};

/// What a [`run`] accomplished.
#[derive(Clone, Debug, Default)]
pub struct SinkStats {
    /// The number of records newly written to the table (post-dedup).
    pub records_written: u64,
    /// The number of non-empty windows committed as snapshots.
    pub batches: u64,
    /// The highest offset the broker cursor was committed to.
    pub last_committed_offset: i64,
    /// The table's resume watermark when the run ended.
    pub final_next_offset: i64,
    /// The number of manifest-compaction / expire-snapshots passes performed.
    pub compactions: u64,
    /// The number of snapshots expired from `metadata.json` across those passes.
    pub snapshots_expired: u64,
    /// The number of stale manifest / manifest-list files reclaimed (delete-after-commit).
    pub files_reclaimed: u64,
}

fn message_to_record(m: &Message) -> Record {
    Record {
        offset: m.offset as i64,
        timestamp_ms: m.timestamp_ms as i64,
        flags: i32::from(m.flags),
        key: m.key.clone(),
        headers: m.headers.clone(),
        payload: m.payload.clone(),
    }
}

/// Connects to the broker, negotiating the streaming tier (and stream addressing for a named
/// stream), and subscribes the durable consumer group.
fn connect(cfg: &SinkConfig) -> Result<Client> {
    let client_cfg = ClientConfig {
        understands_streaming: true,
        default_consume_tier: Some(ConsumeTier::Streaming),
        understands_streams: !cfg.stream.is_empty(),
        understands_deliver_batch: true,
        ..ClientConfig::default()
    };
    let mut client = Client::connect_with(&cfg.addr, &client_cfg)
        .with_context(|| format!("connecting to broker {}", cfg.addr))?;
    if !client.streaming_enabled() {
        bail!("broker did not negotiate the streaming tier (Tier-S); cannot sink");
    }
    if cfg.stream.is_empty() {
        client
            .subscribe(&cfg.group)
            .context("subscribing the streaming group on the default stream")?;
    } else {
        if !client.streams_enabled() {
            bail!("broker did not negotiate stream addressing; cannot sink a named stream");
        }
        client
            .subscribe_to(&cfg.stream, &cfg.group)
            .with_context(|| format!("subscribing group {} on stream {}", cfg.group, cfg.stream))?;
    }
    Ok(client)
}

/// Opens (or creates) the table, connects to the broker, and materializes the topic.
///
/// In [`RunMode::DrainAndExit`] this returns once the log is drained to its durable head; in
/// [`RunMode::Follow`] it loops forever, sleeping `poll_interval_ms` when caught up.
///
/// The resume watermark is the TABLE's own `ironbus.next-offset` (read on open), so a restart
/// resumes exactly where the last durable Iceberg commit left off — never re-materializing a
/// committed offset, even if the broker cursor lagged. After each Iceberg commit the broker cursor
/// is advanced too (so retention can progress), but the table watermark is the dedup authority.
pub fn run(cfg: &SinkConfig) -> Result<SinkStats> {
    let mut table = IcebergTable::open_or_create(&cfg.output, cfg.start_offset)
        .with_context(|| format!("opening the Iceberg table at {}", cfg.output))?;
    let mut client = connect(cfg)?;

    let mut stats = SinkStats::default();
    loop {
        let watermark = table.next_offset();
        let fetch = client
            .stream_fetch(watermark as u64, cfg.batch_max_records, cfg.batch_max_bytes)
            .context("fetching a window from the broker")?;

        if fetch.messages.is_empty() {
            match cfg.mode {
                RunMode::DrainAndExit => break,
                RunMode::Follow => {
                    std::thread::sleep(Duration::from_millis(cfg.poll_interval_ms));
                    continue;
                }
            }
        }

        let records: Vec<Record> = fetch.messages.iter().map(message_to_record).collect();
        // Durable Iceberg commit FIRST (data file + manifests + metadata + atomic version-hint swap).
        let written = table
            .append(&records)
            .context("appending the window to the Iceberg table")?;
        if written > 0 {
            stats.records_written += written as u64;
            stats.batches += 1;
        }
        // Guard against a spin: a non-empty fetch that advances nothing means the broker delivered a
        // window entirely at/below the requested start offset (a protocol violation — `stream_fetch`
        // honors `start_offset`). Re-fetching would loop forever, so fail loudly instead.
        let committed = table.next_offset();
        if committed <= watermark {
            bail!(
                "broker delivered {} record(s) but none advanced the table past offset {watermark} \
                 (over-delivery below the requested start offset); refusing to spin",
                fetch.messages.len()
            );
        }
        // Then advance the broker cursor so retention can progress. The table watermark (already
        // durable) is the dedup authority, so a crash here just redelivers a batch the table drops.
        client
            .stream_commit(&cfg.group, committed as u64)
            .context("committing the broker consumer cursor")?;
        stats.last_committed_offset = committed;

        // Bound long-lived-table metadata growth: once the current snapshot has accumulated enough
        // manifests, rewrite them into one and expire snapshots beyond the retention window. This is a
        // correctness-preserving metadata rewrite (same crash-safe commit discipline as the append
        // above, and delete-after-commit), so a failure leaves the table valid at the pre-compaction
        // version — the watermark (read back on the next loop) is unaffected.
        if cfg.manifest_compaction_threshold > 0 {
            let manifests = table
                .current_manifest_count()
                .context("counting the current snapshot's manifests")?;
            if manifests >= cfg.manifest_compaction_threshold as usize {
                let c = table
                    .compact_and_expire(cfg.snapshot_retention_count as usize)
                    .context("compacting manifests / expiring snapshots")?;
                stats.compactions += 1;
                stats.snapshots_expired += c.snapshots_expired as u64;
                stats.files_reclaimed += c.files_deleted as u64;
            }
        }
    }

    stats.final_next_offset = table.next_offset();
    Ok(stats)
}
