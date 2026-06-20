// SPDX-License-Identifier: MIT OR Apache-2.0
//! Core types and IO-free logic for IronBus.
//!
//! This crate performs no input or output: it must not touch the filesystem or
//! the network, spawn processes, or pull in an async runtime. A CI lint enforces
//! this, so the engine logic stays pure and deterministic.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub(crate) mod raw;

pub mod attempt;
pub mod backpressure;
pub mod binding;
pub mod clock;
pub mod codec;
pub mod compress;
pub mod config;
pub mod confirm;
pub mod cursor;
pub mod dedup;
pub mod delivery;
/// The trained-dictionary lifecycle compute (ZDICT training, content-addressed `dict_id`), behind
/// the OPT-IN `zstd` feature. IO-free: the on-disk sidecar IO and the embedded set live above this
/// in storage/cli (`docs/DICTIONARY_LIFECYCLE.md`). Absent entirely from the default build.
#[cfg(feature = "zstd")]
pub mod dict;
pub mod epoch_cache;
pub mod format;
pub mod keyshared;
pub mod leader_lease;
pub mod lease;
pub mod partition;
pub mod resolve_cache;
pub mod segment;
pub mod subject;
pub mod sublist;
pub mod types;
