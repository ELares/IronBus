// SPDX-License-Identifier: MIT OR Apache-2.0
//! IronBus macro-bench harness (#111): an OPEN-LOOP load generator that drives the SHIPPING
//! `ironbus` binary over real sockets and measures end-to-end throughput and tail latency WITHOUT
//! coordinated omission. This is the honest SLO instrument the parent (#19) depends on.
//!
//! # The instrument, in one paragraph
//!
//! A SENDER produces on a schedule fixed before the run (constant target arrival rate, Poisson
//! inter-arrival jitter), stamping each payload with its INTENDED send time. A separate RECEIVER
//! fetches + acks continuously and records each message's end-to-end latency from that intended
//! time (wrk2 style), against a single monotonic-raw clock. Latencies land in an `HdrHistogram` (1 us
//! to 60 s, 3 significant figures), archived RAW per run so percentiles recompute and runs merge.
//! Every run also reports msg/s, MB/s, p50/p99/p99.9, steady-state broker RSS, and write
//! amplification, and emits a versioned provenance JSON (git SHA, build, host, config, raw
//! histogram, reproduce command). Both ends drive the broker through the REAL #11 client.
//!
//! # Why this exists and what guards it
//!
//! A closed-loop generator silently erases the tail under overload (coordinated omission), which is
//! precisely the failure mode an edge queue's p99.9 SLO must rule out. The
//! [`injected_stall`](crate::injected_stall) self-test SIGSTOPs the broker mid-run and asserts the
//! stall shows up in the recorded tail; it FAILS if the tail does not move, so every change to this
//! harness is gated against re-introducing coordinated omission. That self-test is the only part of
//! the harness that runs in `cargo test`; the generator itself runs ON DEMAND via the binary and is
//! deliberately OFF the per-PR CI critical path (like the criterion micro-benches, #112).

pub mod broker;
pub mod clock;
pub mod harness;
pub mod injected_stall;
pub mod probe;
pub mod provenance;

pub use broker::{Broker, BrokerError};
pub use harness::{run_open_loop, Percentiles, RunConfig, RunError, RunReport};
pub use provenance::Provenance;
