// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cluster control plane: the embedded metadata Raft group (V2-C1).
//!
//! This module is the home of IronBus's single metadata consensus group — one Raft group
//! for the whole cluster's membership / partition placement / leader epoch / config, not
//! one group per replicated asset (the group-explosion ceiling the design indicts NATS
//! for). Consensus is the production tikv/raft-rs core, wired in here in `ironbus-server`
//! ONLY (never `ironbus-core`, which stays IO-free and async-free).
//!
//! ## Status: C1-I3 (#582) — leader epoch (fencing token) + monotonic leadership lease
//!
//! C1-I1 (#578) integrated the vendored-codec raft-rs and gave a constructible, in-memory
//! metadata group; C1-I2 (#580) made the group's storage DURABLE; C1-I3 (this) surfaces the
//! Raft term as a cluster-wide leader epoch and bounds leadership with a monotonic-clock lease:
//!
//! * [`metadata_group::MetadataRaftGroup`] — a `RawNode<MetadataLogStorage>` for a 1/3/5-voter
//!   group, driven by the synchronous `tick` / `step` / `propose` / `ready` loop, persisting
//!   to an IronBus CRC-framed log and fsyncing before it advances. It now exposes
//!   [`leader_epoch`](metadata_group::MetadataRaftGroup::leader_epoch) (the monotonic fencing
//!   token), a [`leader_lease`](metadata_group::MetadataRaftGroup::leader_lease), and the
//!   [`fences`](metadata_group::MetadataRaftGroup::fences) /
//!   [`can_act_as_leader`](metadata_group::MetadataRaftGroup::can_act_as_leader) predicates;
//! * [`metadata_storage::MetadataLogStorage`] — the durable raft-rs `Storage` over an IronBus
//!   [`Log`](ironbus_storage::log::Log), so the metadata log IS an IronBus log (its own
//!   `metaraft/` subdirectory, the dead-letter-sink shape) and inherits I1–I4 (longest-valid-
//!   prefix recovery, CRC validation, bounded + reported loss / quarantine); the epoch is the
//!   persisted term, so it survives a restart;
//! * [`state_machine::MetadataStateMachine`] — the deterministic applied control plane
//!   (membership, placement, leader epoch, config) with a small, zero-dependency,
//!   hand-rolled command codec.
//!
//! The epoch + lease primitive themselves live IO-free in
//! [`ironbus_core::leader_lease`](ironbus_core::leader_lease) — the cluster-wide generalization
//! of [`lease.rs`](ironbus_core::lease)'s per-consumer generation fencing — so the metadata
//! group only WIRES the raft term + the I6 monotonic clock into it.
//!
//! ## Deliberately deferred (later C1 issues)
//!
//! * **PEER TRANSPORT + RUSTSEC-2024-0437** — the wire that parses untrusted peer Raft bytes
//!   (and the bounding of incoming message size / recursion + removing the deny.toml ignore)
//!   is a SEPARATE, security-sensitive follow-up; C1-I3 parses NO peer bytes, so the advisory
//!   stays unreachable and its scoped ignore is unchanged here.
//! * **C1-I4** — joint-consensus membership changes, learners, and peer-id validation in
//!   the transport/step seam.
//! * log COMPACTION / snapshot DATA — physically reclaiming the applied metadata-log prefix
//!   (a focused follow-up; the durable append + recover + truncate core ships here).
//!
//! This module is NOT yet referenced by the running broker (no `serve`-path wiring), so its
//! presence does not change the single-node binary's behavior or on-disk layout — the n=1
//! zero-config path is unaffected (a 1-member group's epoch/lease is trivial / degenerate).

pub mod metadata_group;
pub mod metadata_storage;
pub mod state_machine;

pub use metadata_group::{GroupError, MetadataRaftGroup};
pub use metadata_storage::{MetadataLogStorage, MetadataStorageError, METADATA_SUBDIR};
pub use state_machine::{DecodeError, MetadataCommand, MetadataStateMachine, NodeRole, Placement};
