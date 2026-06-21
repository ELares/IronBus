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
//! explicit cluster ack-level enum / opt-in page-cache level + per-level metrics are C3 (#605/#609/#610,
//! [`ack_level`]); this ships the C2-fsync quorum gate + the ISR. Like the rest of C1/C2 it is a
//! TESTABLE layer; the `serve`-path wiring of the gate into the produce-ack release is the follow-up.
//!
//! ## Status: C3-I1/I3/I4 (#605/#609/#610) — the cluster ack-level enum + metrics
//!
//! [`ack_level`] adds the EXPLICIT, CONFIGURABLE, OBSERVABLE cluster durability level on top of the
//! quorum-fsync MECHANISM above. [`ack_level::ClusterAckLevel`] extends the single-node `0/1/2` ack
//! spectrum into the cluster cross-product — `C0` (no-ack) / `C1` (leader local-fsync = today's I2) /
//! `C2-pagecache` (quorum page-cache, NATS-R3-parity, weaker) / `C2-fsync` (quorum `fdatasync`, the
//! #691 [`isr::QuorumAckGate`]) — and makes `C2-fsync` the `R >= 3` DEFAULT (the honest beat over NATS's
//! weaker default). `C2-pagecache` is an EXPLICIT, LOUD opt-in
//! ([`ack_level::ClusterAckLevel::requires_explicit_opt_in`] +
//! [`ack_level::ClusterAckLevel::cluster_worst_case_loss_description`]), never the silent default; without
//! the opt-in [`ack_level::ClusterAckLevel::resolve`] falls back to the safe `C2-fsync`.
//! [`ack_level::ClusterAckLevelMetrics`] is a COUNTER PER LEVEL + a cluster `power_loss_unsafe` gauge —
//! the `ironbus_cluster_ack_*` series in the FROZEN metric taxonomy (`docs/METRICS.md`). The enum SELECTS
//! the #691 gate; it does NOT re-implement it. Self-heal is C4; multi-partition + the `serve`-path
//! wiring of a per-produce selected level are follow-ups. Single-node is byte-identical: with no cluster
//! the level degenerates to `C1` (the leader local-fsync I2 ack), the counters render at `0`, and the
//! cluster `power_loss_unsafe` gauge renders `0`.
//!
//! ## Status: C4-I1/I2/I3 (#611/#612/#613) — cross-replica divergence detection + self-heal
//!
//! [`divergence`] is the RECOVERY DIFFERENTIATOR: it extends the single-node I3 contract (bounded,
//! reported, fail-closed recovery) CLUSTER-WIDE, fixing the two NATS failures that have no fix today.
//! Replicas advertise a per-SEALED-segment FINGERPRINT — the footer triple `(record_count, last_seq,
//! footer_CRC)` plus an xxh3-64 `content_hash` over the segment's verbatim on-disk record bytes — over
//! the bounded, validated [`ironbus_proto::frame::FrameType::SegmentFingerprints`] wire (tag 39).
//! [`divergence::compare_fingerprints`] DETECTS divergence in O(segments) (a clean cluster detects
//! NOTHING — no false positive), emitting a typed [`divergence::DivergenceReport`]; this is the signal
//! NATS computes (`errFirstSequenceMismatch`) but never acts on (#5576). On a detected divergence
//! [`divergence::plan_resync`] + [`divergence::execute_resync`] TRUNCATE the divergent suffix (clamped
//! at or above the committed high-watermark of #691, so committed data is NEVER dropped) and RE-FETCH
//! the clean CRC-validated bytes from the quorum (the C2 [`replication::Follower`] path), converging
//! BYTE-IDENTICAL — bounded by the I3 caps ([`divergence::ResyncBounds`]) and REPORTED as a
//! [`divergence::ResyncReport`] (fail-closed over the cap). When a divergent segment on a MINORITY is
//! locally corrupt, [`divergence::quarantine_and_resync`] COPY-THEN-DROPS it into the existing capped
//! forensic [`ironbus_storage::quarantine::QuarantineStore`] (the corrupt bytes are PRESERVED, NEVER
//! deleted) and re-syncs from the clean majority — the partition stays available; a minority fault can
//! neither delete data nor lose quorum (the direct beat over NATS #7556's minority-corruption-deletes-
//! stream). Single-node is byte-identical: with no cluster a broker never advertises, compares, or
//! resyncs, and the single-node quarantine/recovery path is unchanged.
//!
//! ## Status: C4-I4/I5 (#614/#615) — leader-completeness election restriction + CI1-CI4 checkers
//!
//! [`eligibility`] completes the cluster SAFETY story: it makes a stale/corrupt replica INELIGIBLE for
//! partition leadership, the construction that prevents the Jepsen NATS 2.12.1 failure (a corrupt node
//! "managed to become the leader … despite its corrupt state" and then DELETED the stream, losing
//! ~49.7% of acked writes). When a partition leader is (re)assigned, eligibility =
//! `(in ISR) AND (durable prefix >= committed HW) AND (no detected divergence)` — reusing the #668
//! epoch, the #691 ISR + quorum HW ([`isr::IsrTracker`]), and the #697 divergence detection
//! ([`divergence::DivergenceReport`]). A replica BEHIND the committed HW (stale), or one whose log
//! DIVERGES from the committed lineage (corrupt), is excluded BY CONSTRUCTION — it can never win, the
//! Kafka ELR "Leader Candidate Completeness" / KIP-966 restriction. The pure predicate lives IO-free in
//! [`ironbus_core::cluster_invariants::LeaderEligibility`]; [`eligibility::eligible_leaders`] is the
//! function the metadata-plane PLACEMENT consults (the placement/rebalance itself — WHICH eligible
//! replica to designate, and when — is C5, #616+). Alongside it,
//! [`ironbus_core::cluster_invariants`] ratifies CI1-CI4 as pure-function checkers mirroring the
//! single-node I1-I4 (`ironbus-storage/src/invariants.rs`): CI1 (in-sync replicas share the committed
//! prefix), CI2 (a C2-fsync ack implies a quorum fsync — #691), CI3 (divergence is bounded + reported +
//! repaired, never silently served / deleted — #697), CI4 (epoch monotonic, no stale-leader-commit —
//! #668 + #614), each falsifiable against a constructed bad state. The cluster recovery contract is
//! documented in `docs/CLUSTER_INVARIANTS.md`. Single-node is byte-identical: the lone replica is its
//! own ISR, is complete to its own HW, and cannot diverge from itself, so it is trivially eligible; the
//! eligibility / CI layer never constructs in a standalone broker. The `serve`-path wiring of the
//! eligibility check into the running metadata placement is the follow-up.
//!
//! ## Status: C2-I6 — data-plane serve-wiring (the controller that RUNS the layers)
//!
//! [`dataplane`] is the piece that finally WIRES the DATA-plane layers above into a serving cluster.
//! [`dataplane::DataPlaneController`] reads the committed placements
//! ([`state_machine::Placement`], #616) and, per LOCAL partition replica
//! ([`dataplane::role_for_placement`]), runs the right role: a LEADER serves
//! [`replication::FetchRecordsBody`] pulls to its followers ([`replication::ReplicationLeader`]) AND
//! gates a `C2-fsync` produce's `PubAck` through the partition's [`isr::IsrTracker`] +
//! [`isr::QuorumAckGate`] (#593) — the ack releases only once `min_isr` replicas have each
//! `fdatasync`'d the record, and below `min_isr` it releases NOTHING (the no-false-ack property); a
//! FOLLOWER runs the [`replication::Follower`] fetch loop, applies only CRC-revalidated bytes, reports
//! its fsync'd offset back ([`isr::AckReplicatedBody`]), and on a detected divergence self-heals via
//! the leader-epoch truncation (#599, [`replication::EpochAwareFollower`]). The controller is
//! TRANSPORT-AGNOSTIC: it returns a [`dataplane::DataPlaneAction`] describing what to send and is
//! routed inbound via [`dataplane::decode_dataplane_frame`] + [`dataplane::DataPlaneController::handle_frame`],
//! so the same logic is the serve-path driver AND the unit under the in-process 3-node test (a produce
//! to the leader REPLICATES byte-identical to two followers, the `C2-fsync` ack releases only after the
//! ISR quorum fsync'd, below `min_isr` the produce blocks, a divergent follower self-heals, a single
//! replica acks on its own fsync, and a restart re-establishes the role from the committed placement).
//! Single-node is byte-identical: with no cluster config NO controller is constructed and the produce
//! path is the existing local-fsync (I2) ack. FLAGGED remaining hookup: threading the parked-reply
//! token through `engine.rs` / `session.rs` so a real produce on a leader partition parks its wire
//! `PubAck` in the gate (the exact seam is documented on [`dataplane::DataPlaneController::park_produce_ack`]);
//! rebalance on a placement CHANGE is C5-I2/I3; the real `TcpStream` peer reader/dialer carrying the
//! data frames is the transport wiring.
//!
//! ## Status: C2-I7 (#713) — LIVE data-plane serve wiring (the clustering capstone)
//!
//! [`serve`] is the piece that finally RUNS the proven data-plane layers over REAL connections. Where
//! C2-I6 ([`dataplane`]) built the transport-agnostic [`DataPlaneController`] + [`ProduceAckSeam`] and
//! proved them in-process, this issue carries the DATA frames over the wire and drives the controller
//! per the committed placement in a serving cluster:
//!
//! * [`serve::DataPlaneLink`] — the DATA-plane twin of the C1 [`PeerLink`](transport): it frames each
//!   [`DataPlaneFrame`](dataplane::DataPlaneFrame) (prefixed with its partition id) over the SAME
//!   bounded `[len][type][body]` envelope and reads it back through the SAME bounded, fail-closed layer
//!   codecs, so an untrusted data-frame's bytes stay size-capped ([`serve::MAX_DATAPLANE_FRAME_BYTES`])
//!   + CRC-revalidated by the follower (a hostile peer is contained to a dropped frame);
//! * [`serve::DataPlaneServer`] — the per-node runnable that holds the [`ProduceAckSeam`] (the
//!   controller + every local partition role + the parked-ack side table), routes one inbound
//!   data-plane frame at a time, and runs the per-role loops: a LEADER serves `FetchRecords` /
//!   `OffsetForLeaderEpoch` and records `AckReplicated` reports (driving the quorum-ack gate); a
//!   FOLLOWER pulls the leader's CRC-revalidated bytes, applies them to its own replica log, and reports
//!   its fsync'd offset back;
//! * [`serve::DataPlaneServer::from_placements`] — the serve-path constructor: per local partition,
//!   [`role_for_placement`](dataplane::role_for_placement) decides the role from the committed
//!   placement and registers it (a restart re-derives every role from the same committed placement +
//!   the durable replica log).
//!
//! Proven by a 3-node SERVE cluster over REAL loopback sockets: a produce to the leader REPLICATES
//! byte-identical to its followers, a `C2-fsync` produce's wire `PubAck` is released ONLY after
//! quorum-fsync (not leader-only), below `min_isr` the ack stays parked (no false ack), a follower that
//! falls behind catches up, and a restarted node re-establishes its role + resumes replication.
//! Single-node / no-cluster is byte-identical: [`serve::DataPlaneServer`] constructs ONLY on a
//! clustered serve, so a no-cluster broker never builds it — the produce/consume path + the immediate
//! local-fsync (I2) ack are byte-for-byte today's broker.
//!
//! FLAGGED (precise, not landed here): the live produce-ack [`session`](crate::session)`::drain_parked`
//! hot-path wiring (it needs two engine/actor ownership changes — exposing the engine's leader
//! `&Log<F, C>` to the leader role, and holding the [`ProduceAckSeam`] in shared broker state a session
//! can consult — both deliberately deferred so the single-node hot path stays untouched); cooperative
//! REBALANCE on a placement change (C5-I2); leaderless FAILOVER (C5-I3); follower READS (C6);
//! multi-partition fan-out + geo (later). See the [`serve`] module docs for the exact remaining wiring.
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

pub mod ack_level;
pub mod client_ack;
pub mod dataplane;
pub mod divergence;
pub mod eligibility;
pub mod isr;
pub mod membership;
pub mod metadata_group;
pub mod metadata_storage;
pub mod placement;
pub mod replication;
pub mod runtime;
pub mod serve;
pub mod state_machine;
pub mod transport;

pub use ack_level::{ClusterAckLevel, ClusterAckLevelMetrics};
pub use client_ack::ClientAckGate;
pub use dataplane::{
    decode_dataplane_frame, role_for_placement, AckDisposition, AckToken, DataPlaneAction,
    DataPlaneController, DataPlaneError, DataPlaneFrame, PlacementRole, ProduceAckSeam,
};
pub use divergence::{
    compare_fingerprints, execute_resync, fingerprint_log, plan_resync, quarantine_and_resync,
    DivergenceDetected, DivergenceError, DivergenceField, DivergenceReport, ResyncBounds,
    ResyncPlan, ResyncReport, SegmentFingerprint, SegmentFingerprints, MAX_FINGERPRINTS,
};
pub use eligibility::{
    eligible_leaders, evaluate_eligibility, is_eligible_leader, replica_state_from,
    IneligibleReason, ReplicaState,
};
pub use isr::{AckReplicatedBody, IsrConfig, IsrMembership, IsrTracker, PendingAck, QuorumAckGate};
pub use membership::{MemberOp, MembershipChange, PeerIdError};
pub use metadata_group::{GroupError, MetadataRaftGroup};
pub use metadata_storage::{MetadataLogStorage, MetadataStorageError, METADATA_SUBDIR};
pub use placement::{decide_placement, placement_command, placement_node_from, PlacementOutcome};
pub use replication::{
    ApplyOutcome, DivergenceTruncation, EpochAwareFollower, FetchRecordsBody, FetchResponseBody,
    Follower, OffsetForLeaderEpochBody, OffsetForLeaderEpochResponse, ReadPlaneLeader,
    ReplicationError, ReplicationFrame, ReplicationLeader, ReplicationLink, MAX_REPL_FETCH_BYTES,
};
pub use runtime::{
    dataplane_addr, ClusterConfig, ClusterRuntime, ClusterStatus, MetadataProposer, RuntimeError,
    DATAPLANE_PORT_OFFSET,
};
pub use serve::{
    decode_dataplane_peer_frame, encode_dataplane_peer_frame, DataPlaneLink, DataPlaneRuntime,
    DataPlaneServer, DataPlaneWireError, ReplicaLogFactory, MAX_DATAPLANE_FRAME_BYTES,
};
pub use state_machine::{DecodeError, MetadataCommand, MetadataStateMachine, NodeRole, Placement};
pub use transport::{
    decode_peer_frame, decode_raft_message, encode_raft_message, PeerLink, PeerRegistry,
    PeerWireError, MAX_RAFT_MSG_BYTES, RAFT_DECODE_RECURSION_LIMIT,
};
