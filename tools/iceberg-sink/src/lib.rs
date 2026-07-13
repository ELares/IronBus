// SPDX-License-Identifier: MIT OR Apache-2.0
//! IronBus -> Apache Iceberg/Parquet sink connector (#793, phase 1).
//!
//! A STANDALONE companion binary that consumes a topic from a live IronBus broker over the wire and
//! materializes it as an Apache Iceberg v2 table (Parquet data files + Iceberg manifest/metadata) in
//! a local-directory object store, so Snowflake / Databricks / Spark / Trino / DuckDB can query the
//! bus's data as an open table. The broker is a PURE message bus and is never linked against this
//! stack: this crate is its own, separate, root-EXCLUDED Cargo workspace (see Cargo.toml).
//!
//! Correctness model (the whole point — a table nothing can query, or one that drops/duplicates
//! records, is worthless):
//!
//! * The table's OWN durable state is the source of truth for resume + dedup. Each snapshot records
//!   `ironbus.next-offset` in its summary; on startup the sink reads it back and consumes strictly
//!   from there. It never re-materializes an offset already in the table, so a crash between the
//!   Iceberg commit and the broker cursor commit cannot duplicate rows.
//! * The Iceberg commit is an ATOMIC pointer swap: data file -> manifest -> manifest-list ->
//!   `v{N}.metadata.json` are all written and fsynced, THEN `version-hint.text` is renamed over
//!   atomically. A crash before the rename leaves the new files orphaned (invisible) and the table
//!   valid at the previous version; the batch simply re-materializes on resume. A crash after it
//!   advances the watermark, so the broker cursor (committed last) redelivering the batch is
//!   dropped by the dedup filter. At-least-once in, exactly-once in the table.
//!
//! See [`table::IcebergTable`] for the Iceberg-metadata approach (and why it uses the `iceberg`
//! crate's spec writers rather than hand-rolling Avro) and [`sink`] for the consume loop.

// A data-plumbing connector converts between the bus's `u64` offsets/timestamps and Iceberg/Parquet's
// `i64` columns constantly; the pedantic cast lints add no safety here (offsets never exceed i64::MAX
// in any real log). Documenting errors on a binary's internal helpers is noise.
#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    // The docs name products (IronBus, DuckDB, Databricks, ...) that trip the CamelCase heuristic.
    clippy::doc_markdown
)]

pub mod config;
pub mod sink;
pub mod table;

pub use config::{RunMode, SinkConfig};
pub use sink::{run, SinkStats};
pub use table::{scan_offsets, CompactionStats, IcebergTable, Record};
