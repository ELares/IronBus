// SPDX-License-Identifier: MIT OR Apache-2.0
//! Storage engine for IronBus: segmented log, durability, recovery.
#![warn(missing_docs)]

pub mod admin;
pub mod checkpoint;
pub mod compaction;
/// The on-disk trained-dictionary sidecar store and resolver (`dicts/<dict_id>.zstd`), behind the
/// OPT-IN `zstd` feature (#357, `docs/DICTIONARY_LIFECYCLE.md` §3-§4). Absent from the default build.
#[cfg(feature = "zstd")]
pub mod dict_store;
pub mod dlq;
pub mod fault;
pub mod fs;
pub mod invariants;
pub mod io;
/// The data-directory LAYOUT version marker (#562): a small, durable, CRC32C'd `layout.meta` at the
/// data-dir root that versions the on-disk DIRECTORY structure (where streams/cursors/DLQ live),
/// distinct from the per-segment `FORMAT_VERSION`. Version 1 is today's layout (root log = default
/// stream, `dlq/` subdir), and it reserves the `streams/` subtree for per-stream logs (M2-I2).
pub mod layout;
pub mod log;
pub mod loss;
pub mod naming;
pub mod offline;
/// A [`PartitionedStream`](partitioned::PartitionedStream): ONE stream optionally subdivided into `P`
/// independent sub-logs (partitions) — the parallel-consume scaling lever (#591, V2-M2 M2-I11).
/// `P = 1` (the default) is the stream's single log at its root (byte-identical to a non-partitioned
/// stream); `P > 1` is `P` independent [`log::Log`]s under `p-<08x>/` (the StreamSet subdir pattern,
/// at the partition granularity). A keyed record routes by a stable `xxh3_64(key) % P` hash
/// (per-key order preserved within a partition); a keyless record round-robins. Each partition
/// recovers independently (I1–I4 isolation), has its own cursor/poll/lease (P-way parallel consume),
/// and folds into a cross-partition group-commit.
pub mod partitioned;
pub mod quarantine;
/// The lock-free, off-actor consume READ plane (#539): an atomic flushed frontier plus an
/// arc-swapped immutable snapshot of the sealed segments + their seek indexes, so a consumer read
/// takes a wait-free snapshot and reads the durable prefix with NO lock and NO append-actor
/// round-trip. The single append actor remains the only writer (it publishes the frontier + swaps
/// the snapshot after each commit/seal).
pub mod read_plane;
pub mod segment;
pub mod sim;
/// A [`StreamSet`](streamset::StreamSet): N independently-opened, independently-recovered IronBus
/// logs over one filesystem (#563, V2-M2). The DEFAULT stream `""` is today's root log (byte
/// identical), and each named stream is an independent [`log::Log`] under `streams/<name>/`
/// (generalizing the `dlq/` subdir pattern). Each stream recovers independently — a torn stream
/// recovers to its own valid prefix + loss report without touching a sibling — and per-record cost
/// stays flat as streams grow (no per-record structure is added).
pub mod streamset;
