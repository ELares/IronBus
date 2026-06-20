// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cluster control plane: the embedded metadata Raft group (V2-C1).
//!
//! This module is the home of IronBus's single metadata consensus group — one Raft group
//! for the whole cluster's membership / partition placement / leader epoch / config, not
//! one group per replicated asset (the group-explosion ceiling the design indicts NATS
//! for). Consensus is the production tikv/raft-rs core, wired in here in `ironbus-server`
//! ONLY (never `ironbus-core`, which stays IO-free and async-free).
//!
//! ## Status: C1-I4 (#584) — joint-consensus membership + learners + peer-id validation
//!
//! C1-I1 (#578) integrated the vendored-codec raft-rs and gave a constructible, in-memory
//! metadata group; C1-I2 (#580) made the group's storage DURABLE; C1-I3 (#582) surfaced the
//! Raft term as a cluster-wide leader epoch and bounds leadership with a monotonic-clock lease;
//! C1-I4 (this) makes the membership CHANGEABLE — add / remove a voter via raft-rs joint
//! consensus (overlapping old+new majorities, Raft §6), a new node joins as a non-voting
//! learner and is promoted to a voter, and every membership change is peer-id-validated before
//! it can enter the metadata log (the #6403-class fix: a mangled / duplicate / phantom peer is
//! rejected, so a bad peer-id can never freeze quorum):
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
//!   hand-rolled command codec; committed conf-change entries now fold the new membership
//!   (voters / learners) into it so the state machine's view tracks the durable `ConfState`;
//! * [`membership`] — the C1-I4 membership API: [`MembershipChange`](membership::MembershipChange)
//!   (add/remove voters, add learners, promote learners) encoded to a raft-rs `ConfChangeV2`
//!   (joint consensus), and [`validate_change`](membership::validate_change) — the peer-id
//!   validation that rejects a mangled / duplicate / phantom peer BEFORE it can be proposed.
//!
//! The epoch + lease primitive themselves live IO-free in
//! [`ironbus_core::leader_lease`](ironbus_core::leader_lease) — the cluster-wide generalization
//! of [`lease.rs`](ironbus_core::lease)'s per-consumer generation fencing — so the metadata
//! group only WIRES the raft term + the I6 monotonic clock into it.
//!
//! ## C1 peer transport (#667) — the BOUNDED, FAIL-CLOSED wire (this issue's addition)
//!
//! [`transport`] adds the wire that carries `eraftpb::Message`s between cluster nodes: it
//! serializes the outbound messages [`metadata_group::MetadataRaftGroup::drive_ready`] surfaces and
//! sends them to the addressed peer, and it decodes the bytes a peer sends back into an
//! `eraftpb::Message` to feed [`metadata_group::MetadataRaftGroup::step`]. This is the FIRST place
//! IronBus parses UNTRUSTED PEER BYTES through the vendored protobuf-2 `eraftpb` codec, so it is
//! built to treat every incoming byte as adversarial: a hard incoming-message SIZE cap
//! ([`transport::MAX_RAFT_MSG_BYTES`], enforced on the frame length prefix BEFORE any allocation)
//! and a tight protobuf RECURSION-DEPTH bound ([`transport::RAFT_DECODE_RECURSION_LIMIT`], set on
//! the `CodedInputStream` before merge) together make RUSTSEC-2024-0437 (the protobuf-2.x
//! deep-nesting stack overflow) UNREACHABLE — a hostile message is rejected with a typed error,
//! never a panic / OOM / stack overflow. The decoded message's `from` is also authenticated against
//! the known membership (the wire-side application of C1-I4 peer-id validation). With the bound in
//! place the `deny.toml` `RUSTSEC-2024-0437` ignore is REMOVED.
//!
//! [`transport`] is the testable transport LAYER (the bounded codec + frame helpers + peer-id
//! registry + a [`transport::PeerLink`] over any `Read + Write`, driven by a loopback harness). The
//! full `serve`-path wiring (a cluster listener/dialer on a multi-node config, the broker actually
//! replicating) is the next step and is DEFERRED below.
//!
//! ## Status: C2-I1 (#590) — follower-fetch per-partition data replication
//!
//! [`replication`] adds the FIRST real multi-node DATA fault-tolerance: per-partition leader + ISR
//! PULL replication of the existing CRC-framed log. A follower sends a
//! [`replication::FetchRecordsBody`] to the leader; the leader serves a contiguous CRC-framed byte
//! range from its own log ([`replication::ReplicationLeader`], reusing the zero-copy `raw_byte_range`
//! / `read_range_raw` of #657) plus its high-watermark; the follower
//! ([`replication::Follower`]) RE-VALIDATES every frame's CRC with the existing intact-record
//! predicate ([`ironbus_core::codec::decode`]) and appends only validated frames — fail-closed, it
//! never blind-trusts the leader's bytes. The follower's high-watermark = `min(its durable prefix,
//! the leader's committed prefix)`, so only committed-and-replicated data is visible. Like the C1
//! peer transport, it is a TESTABLE layer (a [`replication::ReplicationLink`] over any `Read + Write`,
//! driven by an in-process leader↔follower loopback) — the `serve`-path wiring is deferred.
//! Divergence self-heal (C4) and multi-partition fan-out are deferred to those issues.
//!
//! ## Status: C2-I4 (#599) — leader-epoch truncation on follower divergence (KIP-101)
//!
//! [`replication`] now makes replication SAFE under a LEADER CHANGE: where C2-I1 fails closed on any
//! gap/overlap (it assumed the follower shared the leader's lineage), a follower that replicated from
//! an OLD leader may hold an uncommitted suffix from an old epoch the NEW leader never had (or has
//! different records at the same offsets). Truncating to the high-watermark is INSUFFICIENT — it can
//! leave divergent committed-looking data or over-truncate. KIP-101 tracks the LEADER EPOCH per
//! offset-range in a reconstructible, IO-free [`ironbus_core::epoch_cache::EpochCache`] (an
//! epoch->start-offset map, NEVER stamped into the on-disk frames — the segment format is unchanged
//! and old logs stay readable), and on a leader change the follower
//! ([`replication::EpochAwareFollower`]) QUERIES the leader's epoch history (the new
//! [`ironbus_proto::frame::FrameType::OffsetForLeaderEpoch`] wire tag 38, request+response sharing the
//! tag), finds the DIVERGENCE POINT (the first offset its epoch lineage disagrees with the leader's),
//! and TRUNCATES exactly there via the new bounded, REPORTED [`ironbus_storage::log::Log::truncate_to`]
//! (keep the longest common prefix, drop only the divergent suffix), then re-fetches and converges
//! BYTE-IDENTICAL to the new leader. The truncation is bounded + reported (a typed
//! [`replication::DivergenceTruncation`] event, never a silent drop — the beat over NATS #5576) and
//! NEVER drops committed data (the divergence point is clamped at or above the quorum-commit HW of
//! #691). Single-node is unaffected: with no cluster a follower / epoch cache is never built, so no
//! truncation ever runs and the on-disk layout is byte-for-byte unchanged. Footer/CRC cross-replica
//! divergence DETECTION + self-heal is a DIFFERENT mechanism (silent corruption/drift) deferred to C4
//! (#611/#612); this issue is leader-change LOG divergence only.
//!
//! ## Status: C2-I2 (#593) — ISR set + min-in-sync-replicas + quorum-FSYNC ack release
//!
//! [`isr`] turns C2-I1's follower-fetch into a DURABILITY GUARANTEE: the leader tracks the in-sync
//! replica set ([`isr::IsrTracker`]) from each follower's reported FSYNC'd offset
//! ([`isr::AckReplicatedBody`], the new wire tag 37 — the follower reports what it has `fdatasync`'d,
//! NOT merely received), evicts a follower that lags past a bound, computes the QUORUM-COMMIT offset
//! (the highest offset `min_isr` in-sync replicas have all fsync'd), and releases a `C2-fsync`
//! `PubAck` ([`isr::QuorumAckGate`]) ONLY once the produce's offset is quorum-committed — so an
//! IronBus R-ack means fsync'd-on-a-quorum BY CONSTRUCTION (the win over NATS R3's quorum page-cache).
//! Below `min_isr` the gate releases NOTHING (the no-false-ack property: unavailable over unsafe). The
//! explicit cluster ack-level enum / opt-in page-cache level + per-level metrics are C3 (#605/#608);
//! this ships the C2-fsync quorum gate + the ISR. Like the rest of C1/C2 it is a TESTABLE layer; the
//! `serve`-path wiring of the gate into the produce-ack release is the follow-up.
//!
//! ## Deliberately deferred (later C1 / C2 issues)
//!
//! * **`serve`-path wiring + over-the-wire learner CATCH-UP + C2 replication** — wiring the
//!   transport into the running broker (a cluster listener/dialer bound to a multi-node config) and
//!   the actual back-fill of a joining learner / replication is the follow-up. This issue ships the
//!   bounded, fail-closed transport layer + closes the RUSTSEC advisory; it does NOT make the broker
//!   run multi-node by default.
//! * **metadata snapshot DATA + log COMPACTION (#660, C1-I2b)** — physically reclaiming the
//!   applied metadata-log prefix and filling in snapshot data.
//! * **mTLS peer authentication** — IronBus is plaintext TCP today; the transport binds a message
//!   to a known-membership peer id but does not yet cryptographically authenticate the peer.
//!
//! This module is NOT yet referenced by the running broker (no `serve`-path wiring), so its
//! presence does not change the single-node binary's behavior or on-disk layout — the n=1
//! zero-config path is unaffected (a 1-member group opens NO peer listener; the transport only
//! activates in a multi-node config).

pub mod isr;
pub mod membership;
pub mod metadata_group;
pub mod metadata_storage;
pub mod replication;
pub mod runtime;
pub mod state_machine;
pub mod transport;

pub use isr::{AckReplicatedBody, IsrConfig, IsrMembership, IsrTracker, PendingAck, QuorumAckGate};
pub use membership::{MemberOp, MembershipChange, PeerIdError};
pub use metadata_group::{GroupError, MetadataRaftGroup};
pub use metadata_storage::{MetadataLogStorage, MetadataStorageError, METADATA_SUBDIR};
pub use replication::{
    ApplyOutcome, DivergenceTruncation, EpochAwareFollower, FetchRecordsBody, FetchResponseBody,
    Follower, OffsetForLeaderEpochBody, OffsetForLeaderEpochResponse, ReplicationError,
    ReplicationFrame, ReplicationLeader, ReplicationLink, MAX_REPL_FETCH_BYTES,
};
pub use runtime::{ClusterConfig, ClusterRuntime, ClusterStatus, RuntimeError};
pub use state_machine::{DecodeError, MetadataCommand, MetadataStateMachine, NodeRole, Placement};
pub use transport::{
    decode_peer_frame, decode_raft_message, encode_raft_message, PeerLink, PeerRegistry,
    PeerWireError, MAX_RAFT_MSG_BYTES, RAFT_DECODE_RECURSION_LIMIT,
};
