// SPDX-License-Identifier: MIT OR Apache-2.0
//! IronBus broker server.

pub mod actor;
pub mod audit;
pub mod auth;
pub mod clock;
pub mod cluster;
pub mod codes;
pub mod commit_notify;
pub mod connz;
pub mod engine;
pub(crate) mod flusher;
pub mod health;
pub mod liveness;
pub mod metrics;
pub mod obs;
pub mod preauth;
pub mod produce_gate;
pub mod registry;
pub mod rss;
pub mod server;
pub mod session;
// Multi-tenant account isolation + per-tenant quotas (#765, V2-M7, phase 1).
pub mod tenant;
// TLS 1.3 transport config (ADR-0004, #766) — compiled only under `--features tls`; the default and
// edge-min builds carry no TLS code and no new C (deny.toml's aws-lc-sys allowance is feature-scoped).
#[cfg(feature = "tls")]
pub mod tls;
