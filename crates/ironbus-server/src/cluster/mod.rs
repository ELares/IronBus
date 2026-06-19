// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cluster control plane: the embedded metadata Raft group (V2-C1).
//!
//! This module is the home of IronBus's single metadata consensus group — one Raft group
//! for the whole cluster's membership / partition placement / leader epoch / config, not
//! one group per replicated asset (the group-explosion ceiling the design indicts NATS
//! for). Consensus is the production tikv/raft-rs core, wired in here in `ironbus-server`
//! ONLY (never `ironbus-core`, which stays IO-free and async-free).
//!
//! ## Status: C1-I1 (#578) — dependency integration + standalone group
//!
//! This is the FOUNDATION PR. It proves the vendored-codec raft-rs builds clean under
//! every IronBus gate and gives a constructible, in-memory metadata group:
//!
//! * [`metadata_group::MetadataRaftGroup`] — a `RawNode<MemStorage>` for a 1/3/5-voter
//!   group, driven by the synchronous `tick` / `step` / `propose` / `ready` loop;
//! * [`state_machine::MetadataStateMachine`] — the deterministic applied control plane
//!   (membership, placement, leader epoch, config) with a small, zero-dependency,
//!   hand-rolled command codec.
//!
//! ## Deliberately deferred (later C1 issues)
//!
//! * **C1-I2** — replace `MemStorage` with a durable `Storage` impl over the
//!   `ironbus-storage` CRC-framed log (the metadata log becomes an IronBus log).
//! * **C1-I3** — expose the Raft term as the per-partition leader epoch and pair it with
//!   the `ironbus-core` lease/clock fencing.
//! * **C1-I4** — joint-consensus membership changes, learners, and peer-id validation in
//!   the transport/step seam.
//!
//! This module is NOT yet referenced by the running broker (no `serve`-path wiring), so its
//! presence does not change the single-node binary's behavior or on-disk layout — the n=1
//! zero-config path is unaffected.

pub mod metadata_group;
pub mod state_machine;

pub use metadata_group::{GroupError, MetadataRaftGroup};
pub use state_machine::{DecodeError, MetadataCommand, MetadataStateMachine, NodeRole, Placement};
