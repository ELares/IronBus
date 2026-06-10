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
pub mod log;
pub mod loss;
pub mod naming;
pub mod offline;
pub mod quarantine;
pub mod segment;
pub mod sim;
