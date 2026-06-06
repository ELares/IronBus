//! Core types and IO-free logic for IronBus.
//!
//! This crate is intentionally IO-free: it must not depend on tokio, an async
//! runtime, `std::fs`, or `std::net`. A CI lint enforces this.
#![forbid(unsafe_code)]
