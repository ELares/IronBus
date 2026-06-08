// SPDX-License-Identifier: MIT OR Apache-2.0
//! Dev-only home for the scoped `loom` concurrency models (#122).
//!
//! This crate carries NO production logic: the loom models live in `tests/loom_concurrency.rs`
//! (gated `#![cfg(loom)]`) and are faithful standalone replicas of three IronBus cross-thread hot
//! paths, cross-referenced to the real symbols they mirror. The crate exists only to OWN the
//! `cfg(loom)` `loom` dev-dependency in isolation, so loom (and its transitive `tracing-subscriber`
//! `env-filter` tree) can never unify into a shipped crate's dependency graph. The library is
//! intentionally empty.
