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
pub mod clock;
pub mod codec;
pub mod compress;
pub mod cursor;
pub mod dedup;
pub mod delivery;
pub mod format;
pub mod keyshared;
pub mod lease;
pub mod segment;
pub mod types;
