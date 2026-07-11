// SPDX-License-Identifier: MIT OR Apache-2.0
//! The sink's runtime configuration.

/// Whether the sink drains the log to its durable head and exits, or follows it forever.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Consume everything available now, commit it, and return (the one-shot / test / batch mode).
    DrainAndExit,
    /// Keep polling for new records forever, sleeping `poll_interval_ms` when caught up.
    Follow,
}

/// Everything the sink needs to run: where the broker is, what to consume, and where to write the
/// Iceberg table.
#[derive(Clone, Debug)]
pub struct SinkConfig {
    /// The broker address, `host:port`.
    pub addr: String,
    /// The stream to consume. Empty = the default stream.
    pub stream: String,
    /// The durable consumer group (its committed cursor pins retention; the table's own watermark is
    /// the authoritative resume/dedup point).
    pub group: String,
    /// The table location: a local directory that becomes the Iceberg table tree.
    pub output: String,
    /// The fetch window's record cap per batch.
    pub batch_max_records: u32,
    /// The fetch window's byte budget per batch (`0` = unbounded by bytes).
    pub batch_max_bytes: u64,
    /// The offset a BRAND-NEW table starts materializing from (ignored once the table exists).
    pub start_offset: i64,
    /// Drain-and-exit vs follow.
    pub mode: RunMode,
    /// The poll interval when following and caught up, in milliseconds.
    pub poll_interval_ms: u64,
}

impl Default for SinkConfig {
    fn default() -> Self {
        SinkConfig {
            addr: "127.0.0.1:7777".to_string(),
            stream: String::new(),
            group: "iceberg-sink".to_string(),
            output: "./iceberg-table".to_string(),
            batch_max_records: 10_000,
            batch_max_bytes: 0,
            start_offset: 0,
            mode: RunMode::DrainAndExit,
            poll_interval_ms: 500,
        }
    }
}
