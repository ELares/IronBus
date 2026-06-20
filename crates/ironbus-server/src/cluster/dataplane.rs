// SPDX-License-Identifier: MIT OR Apache-2.0
//! Data-plane serve-wiring: run replication + quorum-ack in a serving cluster broker (V2-C2-I6).
//!
//! Every cluster DATA-plane layer already exists as a TESTABLE LAYER but UN-WIRED into a serving
//! broker: per-partition leader-serve + follower-fetch ([`replication`](super::replication), #590),
//! the ISR tracker + quorum-fsync-ack gate ([`isr`](super::isr), #593), leader-epoch truncation on
//! divergence (#599), divergence detection + self-heal ([`divergence`](super::divergence), C4), and
//! the metadata plane that decides PLACEMENT — which eligible node leads / holds each partition
//! ([`state_machine::Placement`](super::state_machine::Placement), #616) — and is CLI-startable
//! ([`runtime::ClusterRuntime`](super::runtime::ClusterRuntime), #684). What was missing is the piece
//! that READS the committed placement and, per partition, actually RUNS the right role in a serving
//! cluster. This module is that piece.
//!
//! ## The data-plane controller (what this module wires)
//!
//! [`DataPlaneController`] is the per-node DATA-plane driver. On a clustered serve it is built from
//! the committed placements: for each placement, [`role_for_placement`] decides this node's role and
//! [`DataPlaneController::start_leader`] / [`DataPlaneController::start_follower`] register it. For
//! each LOCAL partition replica (a placement whose replica set contains this node) it starts the right
//! role:
//!
//! * **[`PartitionRole::Leader`]** — the node leads the partition. It holds a
//!   [`ReplicationLeader`](super::replication::ReplicationLeader) over the partition log so it serves
//!   [`FetchRecordsBody`](super::replication::FetchRecordsBody) pulls to its followers
//!   ([`DataPlaneController::serve_fetch`]); it owns the partition's [`IsrTracker`] + [`QuorumAckGate`]
//!   so a `C2-fsync` produce's `PubAck` is GATED through the quorum (the durability win): the ack is
//!   released only once `min_isr` replicas — the leader plus a quorum of in-sync followers — have each
//!   `fdatasync`'d the record ([`DataPlaneController::park_produce_ack`] +
//!   [`DataPlaneController::release_quorum_acked`]). Below `min_isr` the gate releases NOTHING — the
//!   produce blocks, never a false ack (#593).
//! * **[`PartitionRole::Follower`]** — the node holds a replica but does not lead. It runs the
//!   follower fetch loop ([`DataPlaneController::make_fetch_request`] /
//!   [`DataPlaneController::apply_fetch_response`]) pulling the leader's CRC-framed bytes, applying
//!   only CRC-revalidated frames to its local replica log, and reporting its fsync'd offset back to
//!   the leader ([`DataPlaneController::follower_report`], an [`AckReplicatedBody`]). On a detected
//!   divergence it self-heals: [`DataPlaneController::reconcile_follower`] runs the leader-epoch
//!   truncation (#599) to the divergence point and re-fetches the clean lineage forward (C4).
//! * **[`PartitionRole::None`]** — the partition is not placed on this node: no leader serve, no
//!   follower fetch, no role state. (This node simply does not participate in that partition.)
//!
//! ## The data-plane frame and the peer transport
//!
//! The C1 peer transport ([`transport`](super::transport)) carries the metadata Raft messages. The
//! DATA-plane frames ride the SAME bounded `[len][type][body]` envelope but are a distinct,
//! peer-only set: [`DataPlaneFrame`] unifies the replication-fetch verbs
//! ([`ReplicationFrame`](super::replication::ReplicationFrame)) and the
//! [`AckReplicatedBody`](super::isr::AckReplicatedBody) ISR report. [`decode_dataplane_frame`] is the
//! bounded router a peer reader calls to turn an inbound data-plane frame's `(type_tag, body)` into a
//! [`DataPlaneFrame`] for [`DataPlaneController::handle_frame`]; the codecs are the SAME
//! already-bounded, fail-closed decoders the layer crates ship (a follower never trusts a leader's
//! bytes; the leader authenticates a follower's report against the partition replica set). The
//! divergence-advertisement frame (`SegmentFingerprints`, #611) is a future hookup — see SCOPE below.
//!
//! ## Single-node / no-cluster = byte-identical (the critical guarantee)
//!
//! This controller is constructed ONLY on a clustered serve (a [`ClusterConfig`](super::ClusterConfig)
//! present). With no cluster config NOTHING here is constructed: no controller, no role state, no
//! data-plane frame ever decoded, and the produce/consume path is the existing single-node path with
//! the existing local-fsync (I2) ack — byte-for-byte today's broker. A single-replica placement
//! (`replicas == [this_node]`, `min_isr == 1`) is the degenerate leader-only shape: the
//! [`QuorumAckGate`] reduces to the local-fsync ack and no follower is required, so even the
//! 1-node-clustered path matches the single-node ack semantics.
//!
//! ## SCOPE — the coherent slice this module ships, and what is flagged
//!
//! SHIPPED (the static-placement data-plane run loop):
//! * the controller reading committed placements and assigning per-partition leader / follower /
//!   none roles;
//! * the LEADER serving `FetchRecords` to its followers over the (transport-agnostic) link;
//! * the FOLLOWER fetch loop applying CRC-revalidated bytes + reporting its fsync'd offset;
//! * the `C2-fsync` produce-ack GATED through the [`QuorumAckGate`] (no false ack below `min_isr`);
//! * the divergence self-heal hookup (leader-epoch truncation, #599) on the follower.
//!
//! FLAGGED / DEFERRED (out of this slice — each its own issue):
//! * **The exact `engine.rs` produce-ack hot-path integration.** This module makes the quorum-ack a
//!   CONTROLLABLE LAYER ([`park_produce_ack`](DataPlaneController::park_produce_ack) /
//!   [`release_quorum_acked`](DataPlaneController::release_quorum_acked) over a caller-opaque ack
//!   token) driven here by the in-process 3-node test. Threading the token through the actor's parked
//!   reply path in `engine.rs` / `session.rs` (so a real produce on a leader partition parks its wire
//!   `PubAck` in this gate instead of replying after the local fsync) is the remaining hookup,
//!   FLAGGED precisely so the single-node hot path stays byte-identical until it lands. The seam is:
//!   `session::drain_parked` writes the `PubAck` after `submission.wait()` returns
//!   `ProduceOutcome::Appended(offset)`; on a clustered LEADER partition it must instead call
//!   [`park_produce_ack`](DataPlaneController::park_produce_ack) with that offset + the parked-reply
//!   token, and a later [`release_quorum_acked`](DataPlaneController::release_quorum_acked) (driven by
//!   follower reports) hands back the tokens to finally write the replies.
//! * **Rebalance on a placement CHANGE** is C5-I2/I3 (this slice is STATIC placement: roles are
//!   assigned from the committed placement at start via [`role_for_placement`] +
//!   [`DataPlaneController::start_leader`] / [`DataPlaneController::start_follower`] and re-derived on a
//!   restart, but a live leader hand-off / replica move is later work).
//! * **The peer reader / dialer SPAWN** in [`runtime`](super::runtime) that carries the data-plane
//!   frames over real `TcpStream`s alongside the metadata Raft messages is the transport wiring; this
//!   module provides [`decode_dataplane_frame`] + [`handle_frame`](DataPlaneController::handle_frame)
//!   so that wiring is a routing change, not a logic change.
//! * **Snapshot / compaction** (#660), **multi-partition fan-out optimization**, and the
//!   **cross-cluster geo** plane (C7) are separate.

use std::collections::BTreeMap;

use ironbus_core::clock::Clock;
use ironbus_core::epoch_cache::{EpochCache, LeaderEpochEndOffset};
use ironbus_core::leader_lease::LeaderEpoch;
use ironbus_core::types::Offset;
use ironbus_proto::frame::FrameType;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Log;

use super::isr::{AckReplicatedBody, IsrConfig, IsrTracker, QuorumAckGate};
use super::replication::{
    DivergenceTruncation, EpochAwareFollower, FetchRecordsBody, FetchResponseBody, Follower,
    OffsetForLeaderEpochBody, OffsetForLeaderEpochResponse, ReplicationError, ReplicationLeader,
};
use super::state_machine::Placement;

/// A typed error from the data-plane controller. Every fault is surfaced as one of these — the
/// controller NEVER panics on a serve-path call (a misrouted frame, an unknown partition, a wrong
/// role for the requested operation, or an underlying replication / storage fault).
#[derive(Debug)]
pub enum DataPlaneError {
    /// An operation was requested for a partition this node does not hold a data-plane role for (the
    /// partition is not in the committed placements that name this node, or has not been started).
    UnknownPartition {
        /// The partition id that has no local role.
        partition: u64,
    },
    /// An operation valid only for a LEADER (e.g. [`DataPlaneController::serve_fetch`],
    /// [`DataPlaneController::park_produce_ack`]) was requested for a partition this node FOLLOWS, or
    /// vice-versa (e.g. [`DataPlaneController::apply_fetch_response`] on a leader partition).
    WrongRole {
        /// The partition id whose local role did not match the requested operation.
        partition: u64,
        /// What the operation needed ("leader" or "follower").
        needed: &'static str,
    },
    /// An underlying replication / codec / storage fault (a corrupt fetch response, a malformed
    /// report, a truncation failure). The replication layer's typed error, surfaced verbatim.
    Replication(ReplicationError),
}

impl core::fmt::Display for DataPlaneError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DataPlaneError::UnknownPartition { partition } => {
                write!(
                    f,
                    "partition {partition} has no local data-plane role on this node"
                )
            }
            DataPlaneError::WrongRole { partition, needed } => write!(
                f,
                "partition {partition} operation needs the {needed} role on this node"
            ),
            DataPlaneError::Replication(e) => write!(f, "replication fault: {e}"),
        }
    }
}

impl std::error::Error for DataPlaneError {}

impl From<ReplicationError> for DataPlaneError {
    fn from(e: ReplicationError) -> Self {
        DataPlaneError::Replication(e)
    }
}

/// One decoded DATA-plane peer frame: the replication-fetch verbs plus the ISR report. These ride the
/// SAME bounded `[len][type][body]` envelope as the C1 metadata transport, but are a distinct,
/// peer-only set a client never sends. The leader receives `FetchRequest` + `AckReplicated` +
/// `EpochQuery`; a follower receives `FetchResponse` + `EpochResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataPlaneFrame {
    /// A follower → leader fetch request (received on the leader side).
    FetchRequest(FetchRecordsBody),
    /// A leader → follower fetch response (received on the follower side).
    FetchResponse(FetchResponseBody),
    /// A follower → leader durably-replicated-offset report (received on the leader side, #593).
    AckReplicated(AckReplicatedBody),
    /// A follower → leader leader-epoch offset query (received on the leader side, #599).
    EpochQuery(OffsetForLeaderEpochBody),
    /// A leader → follower leader-epoch offset response (received on the follower side, #599).
    EpochResponse(OffsetForLeaderEpochResponse),
}

/// The leading byte of an [`OffsetForLeaderEpochBody`] encoding — the kind discriminant that
/// distinguishes a query from a response on the shared `OffsetForLeaderEpoch` (tag 38) wire type.
/// Kept in lock-step with the replication codec; a body whose first byte is neither is rejected.
const EPOCH_KIND_REQUEST: u8 = 0;
const EPOCH_KIND_RESPONSE: u8 = 1;

/// Route a single inbound DATA-plane frame's `(type_tag, body)` into a [`DataPlaneFrame`], reusing the
/// SAME bounded, fail-closed decoders the layer crates ship. The caller (a peer reader) has already
/// length-bounded the frame via the `[len][type][body]` envelope; this only DECODES the body and
/// rejects an unexpected type tag or a malformed body with a typed error — never a panic.
///
/// # Errors
/// Returns [`DataPlaneError::Replication`] if `type_tag` is not a data-plane verb or the body does not
/// decode (a corrupt / truncated / mistyped frame is rejected, never guessed at).
pub fn decode_dataplane_frame(type_tag: u8, body: &[u8]) -> Result<DataPlaneFrame, DataPlaneError> {
    match FrameType::from_u8(type_tag) {
        Some(FrameType::FetchRecords) => Ok(DataPlaneFrame::FetchRequest(
            FetchRecordsBody::decode(body)?,
        )),
        Some(FrameType::FetchResponse) => Ok(DataPlaneFrame::FetchResponse(
            FetchResponseBody::decode(body)?,
        )),
        Some(FrameType::AckReplicated) => Ok(DataPlaneFrame::AckReplicated(
            AckReplicatedBody::decode(body)?,
        )),
        Some(FrameType::OffsetForLeaderEpoch) => match body.first().copied() {
            Some(EPOCH_KIND_REQUEST) => Ok(DataPlaneFrame::EpochQuery(
                OffsetForLeaderEpochBody::decode(body)?,
            )),
            Some(EPOCH_KIND_RESPONSE) => Ok(DataPlaneFrame::EpochResponse(
                OffsetForLeaderEpochResponse::decode(body)?,
            )),
            _ => Err(DataPlaneError::Replication(ReplicationError::Frame {
                what: "malformed OffsetForLeaderEpoch kind byte on a data-plane frame".to_string(),
            })),
        },
        _ => Err(DataPlaneError::Replication(ReplicationError::Frame {
            what: format!("unexpected frame type tag {type_tag} on a data-plane link"),
        })),
    }
}

/// An action the controller asks the caller to take after [`DataPlaneController::handle_frame`] — the
/// transport-agnostic OUTPUT of routing one inbound data-plane frame. The caller (the serve-path peer
/// router, or the in-process test harness) performs the send; the controller itself holds no
/// transport, so it never blocks on the wire and stays unit-testable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataPlaneAction {
    /// Nothing to send (the frame was absorbed: a report recorded, a response applied).
    None,
    /// Reply to the requesting follower with this fetch response (the leader served a `FetchRecords`).
    SendFetchResponse {
        /// The partition the response is for.
        partition: u64,
        /// The leader's served response.
        response: FetchResponseBody,
    },
    /// Reply to the querying follower with this epoch end-offset (the leader served an `EpochQuery`).
    SendEpochResponse {
        /// The partition the response is for.
        partition: u64,
        /// The leader's epoch end-offset answer.
        response: OffsetForLeaderEpochResponse,
    },
    /// Acks released by a follower's report reaching quorum: the caller maps each opaque token back to
    /// its parked producer reply and writes the wire `PubAck`. Empty unless this report advanced the
    /// quorum-commit past one or more parked offsets.
    ReleaseAcks {
        /// The partition the acks are for.
        partition: u64,
        /// The released opaque ack tokens, in offset order.
        tokens: Vec<AckToken>,
    },
}

/// The caller-opaque token the [`QuorumAckGate`] returns verbatim when an offset's `C2-fsync` ack is
/// released. In a real serve this is the parked-reply key the actor / session uses to find the
/// awaiting producer connection; in the in-process test it is a synthetic id. The controller never
/// interprets it.
pub type AckToken = u64;

/// The per-partition DATA-plane role this node runs, derived from the committed placement.
///
/// `'a` borrows the partition's [`Log`] for the LEADER role (the leader serves bytes from the same log
/// the engine appends to — it never copies). The FOLLOWER role OWNS its replica log (it appends the
/// leader's bytes to its own copy). `None` holds no state.
enum PartitionRole<'a, F: Filesystem, C: Clock> {
    /// This node LEADS the partition: it serves fetches from the leader log + gates produces through
    /// the ISR quorum.
    Leader {
        /// A read-only replication view over the leader's partition log (serves `FetchRecords`).
        log: &'a Log<F, C>,
        /// The leader's epoch cache (answers `OffsetForLeaderEpoch` queries; the leader-epoch fence).
        epochs: EpochCache,
        /// The ISR tracker: the leader's own fsync'd frontier + every follower's reported frontier.
        isr: IsrTracker,
        /// The quorum-ack gate: holds `C2-fsync` acks (keyed by an [`AckToken`]) until quorum-fsync'd.
        gate: QuorumAckGate<AckToken>,
    },
    /// This node FOLLOWS the partition: it pulls the leader's bytes + self-heals on divergence.
    Follower {
        /// The epoch-aware follower over this node's OWN replica log (fetch + apply + reconcile).
        /// Boxed so the `Follower` variant (which owns a whole replica `Log` + epoch cache) does not
        /// bloat every `Leader` slot — the enum is held one-per-partition in a `BTreeMap`.
        follower: Box<EpochAwareFollower<F, C>>,
    },
}

/// The per-node DATA-plane controller: the serve-wiring that reads committed placement and, per local
/// partition, runs the leader-serve / follower-fetch / quorum-ack-gate run loop.
///
/// Transport-agnostic by construction: it holds the role state and the ISR / gate logic, and returns
/// [`DataPlaneAction`]s describing what to send — the caller owns the wire. This is what makes it both
/// the serve-path driver AND the unit under the in-process 3-node test (the test plays the transport).
pub struct DataPlaneController<'a, F: Filesystem, C: Clock> {
    /// This node's cluster id (the same `u64` node-id space the metadata group / runtime use).
    node_id: u64,
    /// The per-partition role this node runs, keyed by partition id.
    roles: BTreeMap<u64, PartitionRole<'a, F, C>>,
}

impl<'a, F: Filesystem, C: Clock> DataPlaneController<'a, F, C> {
    /// A fresh controller for `node_id` with no roles yet. Roles are added by
    /// [`start_leader`](Self::start_leader) / [`start_follower`](Self::start_follower) or, in one shot
    /// from the committed metadata, by [`apply_placement`](Self::apply_placement) /
    /// [`from_placements`](Self::from_placements).
    #[must_use]
    pub fn new(node_id: u64) -> Self {
        Self {
            node_id,
            roles: BTreeMap::new(),
        }
    }

    /// This node's cluster id.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// The number of partitions this node holds a (leader or follower) role for.
    #[must_use]
    pub fn partition_count(&self) -> usize {
        self.roles.len()
    }

    /// Whether this node currently LEADS `partition`.
    #[must_use]
    pub fn is_leader(&self, partition: u64) -> bool {
        matches!(
            self.roles.get(&partition),
            Some(PartitionRole::Leader { .. })
        )
    }

    /// Whether this node currently FOLLOWS `partition`.
    #[must_use]
    pub fn is_follower(&self, partition: u64) -> bool {
        matches!(
            self.roles.get(&partition),
            Some(PartitionRole::Follower { .. })
        )
    }

    /// Register this node as the LEADER of `partition`, serving fetches from `log` and gating produces
    /// through an [`IsrTracker`] / [`QuorumAckGate`] sized by `isr_config` over `replica_ids` (the full
    /// committed replica set; the leader is implicit and need not appear). The leader's `epochs` cache
    /// answers divergence queries; pass an [`EpochCache`] seeded with the partition's leader-epoch
    /// history (or a fresh one for a fresh partition).
    pub fn start_leader(
        &mut self,
        partition: u64,
        log: &'a Log<F, C>,
        epochs: EpochCache,
        replica_ids: &[u64],
        isr_config: IsrConfig,
    ) {
        let mut isr = IsrTracker::new(self.node_id, replica_ids, isr_config);
        // Seed the ISR tracker's own-frontier with the log's current durable head so the leader's
        // quorum-commit starts from the truth (a recovered log may already hold records).
        isr.observe_leader_fsync(log.flushed_offset().get());
        self.roles.insert(
            partition,
            PartitionRole::Leader {
                log,
                epochs,
                isr,
                gate: QuorumAckGate::new(),
            },
        );
    }

    /// Register this node as a FOLLOWER of `partition` over its OWN replica `log` (freshly opened or
    /// recovered; it starts wherever recovery left it). The follower pulls the leader's bytes and
    /// self-heals on divergence.
    pub fn start_follower(&mut self, partition: u64, log: Log<F, C>) {
        self.roles.insert(
            partition,
            PartitionRole::Follower {
                follower: Box::new(EpochAwareFollower::new(Follower::new(log))),
            },
        );
    }

    /// Remove this node's role for `partition` (it no longer holds a replica). Returns `true` if a role
    /// was held and removed, `false` if this node held no role for the partition. A follower's replica
    /// log is dropped with the role (closing its files); a leader's log is borrowed (owned by the
    /// engine) and merely un-referenced here.
    pub fn stop_partition(&mut self, partition: u64) -> bool {
        self.roles.remove(&partition).is_some()
    }

    // ---- LEADER role: serve fetches + gate produces ----------------------------------------------

    /// Serve a follower's `FetchRecords` for `partition` from the leader log (zero-copy CRC-framed
    /// bytes + the leader's high-watermark). Leader-only.
    ///
    /// # Errors
    /// [`DataPlaneError::UnknownPartition`] if this node holds no role for `partition`;
    /// [`DataPlaneError::WrongRole`] if it is a follower, not a leader;
    /// [`DataPlaneError::Replication`] on a serve fault.
    pub fn serve_fetch(
        &self,
        partition: u64,
        req: &FetchRecordsBody,
    ) -> Result<FetchResponseBody, DataPlaneError> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Leader { log, .. }) => {
                Ok(ReplicationLeader::new(log).serve_fetch(req)?)
            }
            Some(PartitionRole::Follower { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "leader",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// Serve a follower's `OffsetForLeaderEpoch` query for `partition` from the leader's epoch cache.
    /// Leader-only; the follower uses the answer to find the divergence point on reconcile (#599).
    ///
    /// # Errors
    /// As [`serve_fetch`](Self::serve_fetch).
    pub fn serve_epoch_query(
        &self,
        partition: u64,
        req: &OffsetForLeaderEpochBody,
    ) -> Result<OffsetForLeaderEpochResponse, DataPlaneError> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Leader { log, epochs, .. }) => {
                Ok(ReplicationLeader::new(log).serve_epoch_query(epochs, req))
            }
            Some(PartitionRole::Follower { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "leader",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// Tell the leader's ISR tracker that its OWN log has fsync'd up to `flushed_offset` (called after
    /// a local group-commit `fdatasync`). The leader is always an ISR member; this is the I2 local
    /// frontier the quorum builds on. No-op for a follower / absent partition.
    pub fn observe_leader_fsync(&mut self, partition: u64, flushed_offset: u64) {
        if let Some(PartitionRole::Leader { isr, .. }) = self.roles.get_mut(&partition) {
            isr.observe_leader_fsync(flushed_offset);
        }
    }

    /// PARK a `C2-fsync` produce's `PubAck` for `partition` at `offset`, withholding it until the
    /// offset is quorum-fsync'd. `token` is the caller's opaque routing key (the parked-reply key in a
    /// real serve). Leader-only. The leader has ALREADY locally fsync'd (the I2 ack-after-its-own-fsync
    /// holds); this gate adds the cluster condition.
    ///
    /// # Errors
    /// As [`serve_fetch`](Self::serve_fetch) (a produce only lands on a leader partition).
    pub fn park_produce_ack(
        &mut self,
        partition: u64,
        offset: u64,
        token: AckToken,
    ) -> Result<(), DataPlaneError> {
        match self.roles.get_mut(&partition) {
            Some(PartitionRole::Leader { gate, .. }) => {
                gate.park(offset, token);
                Ok(())
            }
            Some(PartitionRole::Follower { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "leader",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// Record a follower's [`AckReplicatedBody`] report for `partition` and RELEASE any produce acks
    /// that the report just pushed past the quorum-commit. Leader-only.
    ///
    /// Returns the released opaque ack tokens, in offset order (empty if the report did not advance the
    /// quorum past a parked offset — including the no-quorum / below-`min_isr` case, where the gate
    /// releases NOTHING: the no-false-ack property). An unknown follower id (not in the partition's
    /// replica set) is ignored and releases nothing.
    ///
    /// # Errors
    /// As [`serve_fetch`](Self::serve_fetch).
    pub fn apply_follower_report(
        &mut self,
        partition: u64,
        report: &AckReplicatedBody,
    ) -> Result<Vec<AckToken>, DataPlaneError> {
        match self.roles.get_mut(&partition) {
            Some(PartitionRole::Leader { isr, gate, .. }) => {
                isr.observe_follower_report(report);
                Ok(gate.release_up_to(isr.quorum_commit()))
            }
            Some(PartitionRole::Follower { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "leader",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// Re-drive the quorum-ack release for `partition` against the CURRENT ISR state without a new
    /// report (e.g. after a local-fsync advance, or to re-check after a follower rejoins the ISR).
    /// Releases any now-quorum-committed parked acks. Leader-only; no-op tokens otherwise.
    ///
    /// # Errors
    /// As [`serve_fetch`](Self::serve_fetch).
    pub fn release_quorum_acked(
        &mut self,
        partition: u64,
    ) -> Result<Vec<AckToken>, DataPlaneError> {
        match self.roles.get_mut(&partition) {
            Some(PartitionRole::Leader { isr, gate, .. }) => {
                Ok(gate.release_up_to(isr.quorum_commit()))
            }
            Some(PartitionRole::Follower { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "leader",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// The leader's current quorum-commit offset for `partition`: the highest offset `min_isr` replicas
    /// have all fsync'd, or `None` if the ISR is below `min_isr` (no quorum — the no-false-ack signal).
    /// Leader-only; `None` for a follower / absent partition.
    #[must_use]
    pub fn quorum_commit(&self, partition: u64) -> Option<u64> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Leader { isr, .. }) => isr.quorum_commit(),
            _ => None,
        }
    }

    /// The number of produce acks currently WITHHELD for `partition` (parked behind the quorum gate).
    /// Leader-only; 0 otherwise.
    #[must_use]
    pub fn pending_ack_count(&self, partition: u64) -> usize {
        match self.roles.get(&partition) {
            Some(PartitionRole::Leader { gate, .. }) => gate.pending_len(),
            _ => 0,
        }
    }

    // ---- FOLLOWER role: fetch + apply + report + self-heal ---------------------------------------

    /// Build the next `FetchRecords` request for `partition` (the follower's `next_offset` + the given
    /// budgets). Follower-only.
    ///
    /// # Errors
    /// [`DataPlaneError::UnknownPartition`] if no role; [`DataPlaneError::WrongRole`] if a leader.
    pub fn make_fetch_request(
        &self,
        partition: u64,
        max_records: u32,
        max_bytes: u32,
    ) -> Result<FetchRecordsBody, DataPlaneError> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                Ok(follower.follower().fetch_request(max_records, max_bytes))
            }
            Some(PartitionRole::Leader { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "follower",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// Apply a leader's `FetchResponse` to the follower's replica log for `partition`: re-validate
    /// every frame's CRC, append only validated frames, fsync, advance the follower's high-watermark.
    /// Follower-only. Returns the follower's new fsync'd frontier (its `next_offset` after the synced
    /// apply) — exactly what [`follower_report`](Self::follower_report) reports to the leader.
    ///
    /// # Errors
    /// [`DataPlaneError::WrongRole`] on a leader partition; [`DataPlaneError::Replication`] (fail
    /// closed) on a corrupt / tampered / truncated frame — nothing from the bad frame onward is
    /// appended.
    pub fn apply_fetch_response(
        &mut self,
        partition: u64,
        resp: &FetchResponseBody,
    ) -> Result<u64, DataPlaneError> {
        match self.roles.get_mut(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                let outcome = follower.follower_mut().apply_fetch_response(resp)?;
                Ok(outcome.next_offset)
            }
            Some(PartitionRole::Leader { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "follower",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// Build the follower's [`AckReplicatedBody`] report for `partition`: "I have fsync'd every record
    /// below my `next_offset`." The leader records this to advance its quorum-commit (#593). Reporting
    /// the FSYNC'd (not merely received) frontier is what makes the leader's quorum-commit a
    /// quorum-FSYNC. Follower-only.
    ///
    /// # Errors
    /// As [`make_fetch_request`](Self::make_fetch_request).
    pub fn follower_report(&self, partition: u64) -> Result<AckReplicatedBody, DataPlaneError> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => Ok(AckReplicatedBody {
                follower_id: self.node_id,
                fsynced_offset: follower.follower().next_fetch_offset().get(),
            }),
            Some(PartitionRole::Leader { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "follower",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// Inform the follower of `partition`'s leader-epoch boundary `(epoch, start_offset)` — the epoch
    /// the records it is about to fetch were minted under. The follower folds it into its epoch cache
    /// so a later [`reconcile_follower`](Self::reconcile_follower) can find the divergence point.
    /// Follower-only.
    ///
    /// # Errors
    /// [`DataPlaneError::WrongRole`] on a leader; [`DataPlaneError::Replication`] if the epoch boundary
    /// is out of order (the epoch cache rejects a non-monotonic assignment).
    pub fn assign_follower_epoch(
        &mut self,
        partition: u64,
        epoch: LeaderEpoch,
        start_offset: Offset,
    ) -> Result<(), DataPlaneError> {
        match self.roles.get_mut(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                follower.assign_epoch(epoch, start_offset)?;
                Ok(())
            }
            Some(PartitionRole::Leader { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "follower",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// SELF-HEAL a divergent follower of `partition`: run the leader-epoch truncation (#599) to the
    /// divergence point against the leader's epoch answers (`leader_end_offset`), keeping the committed
    /// prefix (`committed_hw`, fsync'd on a quorum — NEVER truncated) and dropping only the
    /// uncommitted-divergent suffix. After this returns the follower re-fetches the clean lineage
    /// forward via the ordinary [`apply_fetch_response`](Self::apply_fetch_response) (C4 self-heal).
    /// Follower-only.
    ///
    /// `leader_end_offset` answers, for a queried leader epoch, the leader's end-offset for it — in a
    /// real serve this issues an `OffsetForLeaderEpoch` query to the leader and waits for the response;
    /// in the in-process test it calls the leader controller's
    /// [`serve_epoch_query`](Self::serve_epoch_query) directly.
    ///
    /// # Errors
    /// [`DataPlaneError::WrongRole`] on a leader; [`DataPlaneError::Replication`] on a truncation /
    /// epoch-cache fault.
    pub fn reconcile_follower<L>(
        &mut self,
        partition: u64,
        committed_hw: Offset,
        leader_end_offset: L,
    ) -> Result<DivergenceTruncation, DataPlaneError>
    where
        L: FnMut(LeaderEpoch) -> LeaderEpochEndOffset,
    {
        match self.roles.get_mut(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                Ok(follower.reconcile_with_leader(committed_hw, leader_end_offset)?)
            }
            Some(PartitionRole::Leader { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "follower",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// The follower's current visible high-watermark for `partition` (`min(its durable prefix, the
    /// leader's last-observed HW)`) — only committed-and-replicated data is visible below it.
    /// Follower-only; `None` otherwise.
    #[must_use]
    pub fn follower_high_watermark(&self, partition: u64) -> Option<u64> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                Some(follower.follower().high_watermark().get())
            }
            _ => None,
        }
    }

    /// Borrow the follower's replica [`Log`] for `partition` (e.g. to assert byte-identity against the
    /// leader, or to serve a follower read). `None` for a leader / absent partition.
    #[must_use]
    pub fn follower_log(&self, partition: u64) -> Option<&Log<F, C>> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => Some(follower.follower().log()),
            _ => None,
        }
    }

    // ---- Inbound-frame routing (the serve-path peer reader's entry point) ------------------------

    /// Route ONE inbound data-plane frame for `partition` into the right role and return the action the
    /// caller should take (send a response, release acks, or nothing). This is the single entry point a
    /// serve-path peer reader (or the in-process test) calls per decoded [`DataPlaneFrame`]; the
    /// controller holds no transport, so it never blocks on the wire.
    ///
    /// # Errors
    /// [`DataPlaneError::UnknownPartition`] / [`DataPlaneError::WrongRole`] if the frame's role does not
    /// match this node's role for the partition; [`DataPlaneError::Replication`] on a serve / apply
    /// fault. A frame for a partition / role this node does not hold is a typed error the caller drops.
    pub fn handle_frame(
        &mut self,
        partition: u64,
        frame: DataPlaneFrame,
    ) -> Result<DataPlaneAction, DataPlaneError> {
        match frame {
            DataPlaneFrame::FetchRequest(req) => {
                let response = self.serve_fetch(partition, &req)?;
                Ok(DataPlaneAction::SendFetchResponse {
                    partition,
                    response,
                })
            }
            DataPlaneFrame::EpochQuery(req) => {
                let response = self.serve_epoch_query(partition, &req)?;
                Ok(DataPlaneAction::SendEpochResponse {
                    partition,
                    response,
                })
            }
            DataPlaneFrame::AckReplicated(report) => {
                let tokens = self.apply_follower_report(partition, &report)?;
                Ok(DataPlaneAction::ReleaseAcks { partition, tokens })
            }
            DataPlaneFrame::FetchResponse(resp) => {
                self.apply_fetch_response(partition, &resp)?;
                Ok(DataPlaneAction::None)
            }
            DataPlaneFrame::EpochResponse(_) => {
                // An epoch response is consumed by an in-flight reconcile (the `leader_end_offset`
                // closure of `reconcile_follower`), not by the steady-state frame router. A stray one
                // is absorbed.
                Ok(DataPlaneAction::None)
            }
        }
    }
}

/// Decide this node's ROLE for a committed `placement`: [`PlacementRole::Leader`] if
/// `node_id == placement.leader`, [`PlacementRole::Follower`] if it is a non-leader replica, and
/// [`PlacementRole::None`] if it does not hold the partition. This is the pure placement→role policy
/// at the heart of the controller's start path — IO-free and unit-testable, so a clustered serve can
/// decide every partition's role from the committed metadata before opening a single replica log.
#[must_use]
pub fn role_for_placement(node_id: u64, placement: &Placement) -> PlacementRole {
    if placement.leader == node_id {
        PlacementRole::Leader
    } else if placement.replicas.contains(&node_id) {
        PlacementRole::Follower
    } else {
        PlacementRole::None
    }
}

/// The role this node should run for a committed placement (the pure output of [`role_for_placement`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementRole {
    /// This node leads the partition.
    Leader,
    /// This node holds a replica but does not lead.
    Follower,
    /// This node does not hold the partition.
    None,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::io::RandomAccessFile;
    use ironbus_storage::log::{Append, LogConfig};

    // ---- test scaffolding ------------------------------------------------------------------------

    /// A small segment cap so a handful of records rolls to multiple segments — the replicated logs
    /// cross segment boundaries, proving byte-identity is not a single-active-segment artifact.
    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn open_log(fs: InMemoryFs, config: LogConfig) -> Log<InMemoryFs, ManualClock> {
        Log::open(fs, ManualClock::new(), config).expect("log opens")
    }

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    /// The full on-disk bytes of every segment file of a log, keyed by file name — the ground truth
    /// for byte-identity (two logs are byte-identical iff they hold the same files with the same bytes).
    fn dump_segments(log: &Log<InMemoryFs, ManualClock>) -> Vec<(String, Vec<u8>)> {
        let fs = log.filesystem();
        let mut out = Vec::new();
        for name in fs.list().expect("list segments") {
            let file = fs.open(&name).expect("open segment");
            let len = usize::try_from(file.len().expect("len")).expect("len fits usize");
            let mut buf = vec![0u8; len];
            file.read_exact_at(&mut buf, 0).expect("read segment bytes");
            out.push((name, buf));
        }
        out
    }

    /// The R=3 / `min_isr=2` quorum config (the design default for `R>=3`), no lag eviction.
    fn quorum3() -> IsrConfig {
        IsrConfig {
            min_isr: 2,
            max_lag_records: 0,
        }
    }

    /// Drive ONE fetch round from the leader controller to a follower controller over the
    /// transport-agnostic in-process path: the follower builds a request, the leader SERVES it (the
    /// `handle_frame` -> `SendFetchResponse` action), the follower APPLIES the response, then the
    /// follower reports its fsync'd frontier back and the leader records it (the `handle_frame` ->
    /// `ReleaseAcks` action). Returns the acks the leader released on this round.
    fn fetch_round(
        leader: &mut DataPlaneController<'_, InMemoryFs, ManualClock>,
        follower: &mut DataPlaneController<'_, InMemoryFs, ManualClock>,
        partition: u64,
    ) -> Vec<AckToken> {
        // follower -> leader: fetch request
        let req = follower
            .make_fetch_request(partition, 8, 4096)
            .expect("follower builds a fetch request");
        let action = leader
            .handle_frame(partition, DataPlaneFrame::FetchRequest(req))
            .expect("leader serves the fetch");
        let resp = match action {
            DataPlaneAction::SendFetchResponse { response, .. } => response,
            other => panic!("leader expected to send a fetch response, got {other:?}"),
        };
        // leader -> follower: fetch response
        follower
            .handle_frame(partition, DataPlaneFrame::FetchResponse(resp))
            .expect("follower applies the fetch response");
        // follower -> leader: AckReplicated report
        let report = follower
            .follower_report(partition)
            .expect("follower builds its report");
        let action = leader
            .handle_frame(partition, DataPlaneFrame::AckReplicated(report))
            .expect("leader records the follower report");
        match action {
            DataPlaneAction::ReleaseAcks { tokens, .. } => tokens,
            other => panic!("leader expected to release acks, got {other:?}"),
        }
    }

    // ---- placement -> role policy ----------------------------------------------------------------

    #[test]
    fn placement_assigns_leader_follower_and_none_roles() {
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 5,
        };
        assert_eq!(role_for_placement(1, &placement), PlacementRole::Leader);
        assert_eq!(role_for_placement(2, &placement), PlacementRole::Follower);
        assert_eq!(role_for_placement(3, &placement), PlacementRole::Follower);
        // A node not in the replica set holds NO role for the partition.
        assert_eq!(role_for_placement(4, &placement), PlacementRole::None);
    }

    // ---- THE headline test: a 3-node serving cluster REPLICATES byte-identical + quorum-acks -------

    #[test]
    fn a_produce_to_the_leader_replicates_to_two_followers_byte_identical_and_quorum_acks() {
        const P: u64 = 0;
        // Leader (node 1) log with 25 records across multiple segments.
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..25u32 {
            leader_log
                .append(&rec(format!("rep-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let leader_hw = leader_log.flushed_offset().get();
        assert_eq!(leader_hw, 25);

        // Node 1 leads P over replicas {1,2,3}, min_isr=2 (a 2-of-3 quorum).
        let mut leader = DataPlaneController::new(1);
        leader.start_leader(P, &leader_log, EpochCache::new(), &[1, 2, 3], quorum3());
        // The leader's own log is already fsync'd to 25; the ISR tracker was seeded with that on start.

        // Nodes 2 and 3 each follow P with a fresh replica log.
        let mut follower2 = DataPlaneController::new(2);
        follower2.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        let mut follower3 = DataPlaneController::new(3);
        follower3.start_follower(P, open_log(InMemoryFs::new(), small_config()));

        // PARK all 25 produce acks behind the quorum gate (a real serve parks each produce's PubAck;
        // here token == offset). The leader has locally fsync'd, but no follower has the data yet.
        for off in 0..leader_hw {
            leader.park_produce_ack(P, off, off).unwrap();
        }
        assert_eq!(leader.pending_ack_count(P), 25);

        // No follower has fsync'd => the 2-of-3 quorum-commit is 0 (only the leader is at 25) => NO ack
        // releases. This is the no-false-ack property: leader-only is NOT a quorum.
        let released = leader.release_quorum_acked(P).unwrap();
        assert!(
            released.is_empty(),
            "no ack may release on the leader alone (no quorum)"
        );
        assert_eq!(leader.quorum_commit(P), Some(0));

        // Replicate to follower 2 to catch-up. Each round: follower fetches, leader serves, follower
        // applies + reports, leader records the report and releases the now-quorum-committed acks.
        let mut released_to_f2: Vec<AckToken> = Vec::new();
        for _ in 0..(leader_hw + 2) {
            if follower2.follower_high_watermark(P).unwrap() >= leader_hw {
                break;
            }
            released_to_f2.extend(fetch_round(&mut leader, &mut follower2, P));
        }
        // With follower 2 caught up the 2-of-3 quorum (leader + follower2) is met at 25, so ALL 25 acks
        // released — and ONLY after the quorum fsync'd (not on the leader alone above).
        let mut all = released_to_f2;
        all.sort_unstable();
        assert_eq!(all, (0..leader_hw).collect::<Vec<_>>());
        assert_eq!(leader.pending_ack_count(P), 0, "every ack released");
        assert_eq!(leader.quorum_commit(P), Some(25));

        // Follower 2's replica log is BYTE-IDENTICAL to the leader's.
        assert_eq!(
            dump_segments(follower2.follower_log(P).unwrap()),
            dump_segments(&leader_log),
            "follower 2 replica is byte-identical to the leader"
        );

        // Catch follower 3 up too (its reports release nothing new — the acks already released).
        for _ in 0..(leader_hw + 2) {
            if follower3.follower_high_watermark(P).unwrap() >= leader_hw {
                break;
            }
            let none_new = fetch_round(&mut leader, &mut follower3, P);
            assert!(
                none_new.is_empty(),
                "acks already released, none re-release"
            );
        }
        assert_eq!(
            dump_segments(follower3.follower_log(P).unwrap()),
            dump_segments(&leader_log),
            "follower 3 replica is byte-identical to the leader"
        );
    }

    // ---- below min_isr a produce BLOCKS (no false ack) -------------------------------------------

    #[test]
    fn below_min_isr_a_produce_blocks_rather_than_falsely_acking() {
        const P: u64 = 0;
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..10u32 {
            leader_log
                .append(&rec(format!("blk-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let leader_hw = leader_log.flushed_offset().get();

        // Node 1 leads, replicas {1,2,3}, min_isr=2, with lag eviction at 3 records. NO follower ever
        // reports, so both sit at offset 0 — lagging the leader's frontier (10) by far more than the
        // bound. Both are EVICTED for lag, dropping the ISR to the leader alone (size 1 < min_isr 2):
        // there is genuinely no quorum.
        let mut leader = DataPlaneController::new(1);
        leader.start_leader(
            P,
            &leader_log,
            EpochCache::new(),
            &[1, 2, 3],
            IsrConfig {
                min_isr: 2,
                max_lag_records: 3,
            },
        );
        for off in 0..leader_hw {
            leader.park_produce_ack(P, off, off).unwrap();
        }

        // No quorum => quorum_commit is None => the gate releases NOTHING. The produce BLOCKS: its ack
        // is withheld, never falsely emitted on the leader's local fsync alone.
        assert_eq!(leader.quorum_commit(P), None, "no quorum below min_isr");
        let released = leader.release_quorum_acked(P).unwrap();
        assert!(
            released.is_empty(),
            "below min_isr a produce ack is WITHHELD (no false ack)"
        );
        assert_eq!(
            leader.pending_ack_count(P),
            usize::try_from(leader_hw).unwrap(),
            "every ack still parked, awaiting a quorum"
        );

        // The moment ONE follower catches up and reports, the quorum (2-of-3) is met and the acks
        // release — proving the block was on the missing quorum, not a stuck gate.
        let mut follower2 = DataPlaneController::new(2);
        follower2.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        let mut released: Vec<AckToken> = Vec::new();
        for _ in 0..(leader_hw + 2) {
            if follower2.follower_high_watermark(P).unwrap() >= leader_hw {
                break;
            }
            released.extend(fetch_round(&mut leader, &mut follower2, P));
        }
        released.sort_unstable();
        assert_eq!(released, (0..leader_hw).collect::<Vec<_>>());
        assert_eq!(leader.pending_ack_count(P), 0);
    }

    // ---- a divergent follower self-heals ---------------------------------------------------------

    #[test]
    fn a_divergent_follower_self_heals_then_converges_byte_identical() {
        use ironbus_core::epoch_cache::LeaderEpochEndOffset;

        const P: u64 = 0;

        // An OLD leader's lineage: epoch 1 from offset 0, epoch 5 from offset 10 (18 records total).
        let mut old_leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..18u32 {
            old_leader_log
                .append(&rec(format!("old-{i:02}").as_bytes()))
                .unwrap();
        }
        old_leader_log.sync().unwrap();
        let mut old_epochs = EpochCache::new();
        old_epochs
            .assign(LeaderEpoch::new(1), Offset::new(0))
            .unwrap();
        old_epochs
            .assign(LeaderEpoch::new(5), Offset::new(10))
            .unwrap();

        // A follower replicates the OLD leader fully (all 18 records, its epoch cache mirrors the old
        // lineage). It is now DIVERGENT from the new lineage past offset 14.
        let mut follower = DataPlaneController::new(2);
        follower.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        follower
            .assign_follower_epoch(P, LeaderEpoch::new(1), Offset::new(0))
            .unwrap();
        // Catch the follower up to the old leader.
        {
            let mut old_leader = DataPlaneController::new(1);
            old_leader.start_leader(P, &old_leader_log, old_epochs.clone(), &[1, 2], {
                IsrConfig {
                    min_isr: 1,
                    max_lag_records: 0,
                }
            });
            for _ in 0..20 {
                if follower.follower_high_watermark(P).unwrap() >= 18 {
                    break;
                }
                let req = follower.make_fetch_request(P, 8, 4096).unwrap();
                let resp = old_leader.serve_fetch(P, &req).unwrap();
                follower.apply_fetch_response(P, &resp).unwrap();
            }
            follower
                .assign_follower_epoch(P, LeaderEpoch::new(5), Offset::new(10))
                .unwrap();
        }
        assert_eq!(follower.follower_high_watermark(P).unwrap(), 18);

        // A NEW leader takes over with a DIFFERENT lineage: epoch 1 from 0, epoch 6 from 14. Only the
        // epoch-1 prefix [0,10) and the epoch-5 segment up to 14 are the common committed lineage; the
        // follower's records [14,18) under epoch 5 diverge from the new leader's epoch 6.
        let new_leader_log = {
            let mut log = open_log(InMemoryFs::new(), small_config());
            for i in 0..14u32 {
                log.append(&rec(format!("old-{i:02}").as_bytes())).unwrap();
            }
            // New lineage diverges from offset 14 onward.
            for i in 14..22u32 {
                log.append(&rec(format!("new-{i:02}").as_bytes())).unwrap();
            }
            log.sync().unwrap();
            log
        };
        let mut new_epochs = EpochCache::new();
        new_epochs
            .assign(LeaderEpoch::new(1), Offset::new(0))
            .unwrap();
        new_epochs
            .assign(LeaderEpoch::new(5), Offset::new(10))
            .unwrap();
        new_epochs
            .assign(LeaderEpoch::new(6), Offset::new(14))
            .unwrap();
        let mut new_leader = DataPlaneController::new(1);
        new_leader.start_leader(P, &new_leader_log, new_epochs, &[1, 2], {
            IsrConfig {
                min_isr: 1,
                max_lag_records: 0,
            }
        });

        // SELF-HEAL: reconcile the follower against the new leader's epoch answers. Committed HW is 10
        // (only epoch 1 was committed on a quorum), so the follower truncates its divergent suffix down
        // to the divergence point (14, where the new leader's epoch 5 ends) — committed data is never
        // dropped.
        let leader_end = |epoch: LeaderEpoch| -> LeaderEpochEndOffset {
            let req = OffsetForLeaderEpochBody { epoch };
            new_leader.serve_epoch_query(P, &req).unwrap().end_offset
        };
        let healed = follower
            .reconcile_follower(P, Offset::new(10), leader_end)
            .expect("the follower self-heals to the divergence point");
        assert!(!healed.is_no_op(), "the divergent suffix was truncated");

        // Re-fetch the clean lineage forward from the new leader; the follower converges byte-identical.
        for _ in 0..30 {
            if follower.follower_high_watermark(P).unwrap() >= new_leader_log.flushed_offset().get()
            {
                break;
            }
            let req = follower.make_fetch_request(P, 8, 4096).unwrap();
            let resp = new_leader.serve_fetch(P, &req).unwrap();
            follower.apply_fetch_response(P, &resp).unwrap();
        }
        assert_eq!(
            dump_segments(follower.follower_log(P).unwrap()),
            dump_segments(&new_leader_log),
            "after self-heal the follower is byte-identical to the new leader's lineage"
        );
    }

    // ---- single-node / single-replica = the local-fsync ack, byte-identical ----------------------

    #[test]
    fn single_replica_leader_acks_on_local_fsync_no_quorum_wait() {
        const P: u64 = 0;
        let mut log = open_log(InMemoryFs::new(), small_config());
        for i in 0..6u32 {
            log.append(&rec(format!("one-{i}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        let hw = log.flushed_offset().get();

        // A single-replica placement (replicas == [this node], min_isr == 1) is the degenerate
        // leader-only shape: the quorum-commit is the leader's own fsync'd frontier and the gate
        // releases on the local fsync alone — exactly the single-node I2 ack, no follower required.
        let mut node = DataPlaneController::new(1);
        node.start_leader(
            P,
            &log,
            EpochCache::new(),
            &[1],
            IsrConfig {
                min_isr: 1,
                max_lag_records: 0,
            },
        );
        for off in 0..hw {
            node.park_produce_ack(P, off, off).unwrap();
        }
        // min_isr=1: the quorum is the leader alone, already fsync'd to `hw` => every ack releases now.
        assert_eq!(node.quorum_commit(P), Some(hw));
        let mut released = node.release_quorum_acked(P).unwrap();
        released.sort_unstable();
        assert_eq!(
            released,
            (0..hw).collect::<Vec<_>>(),
            "a single replica acks on its own local fsync (the single-node I2 ack)"
        );
        assert_eq!(node.pending_ack_count(P), 0);
    }

    // ---- recovery after a restart re-establishes the role from the committed placement -----------

    #[test]
    fn a_restart_re_establishes_the_role_from_the_committed_placement() {
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 9,
        };

        // A leader log that already holds recovered records (as after a restart). The role is rebuilt
        // PURELY from the committed placement + this node's id: node 1 -> leader, the ISR tracker
        // seeded from the recovered log's durable head.
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..12u32 {
            leader_log
                .append(&rec(format!("rec-{i}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();

        assert_eq!(role_for_placement(1, &placement), PlacementRole::Leader);
        let mut leader = DataPlaneController::new(1);
        leader.start_leader(
            P,
            &leader_log,
            EpochCache::new(),
            &placement.replicas,
            quorum3(),
        );
        // The leader re-establishes its quorum-commit from the recovered durable head (no follower yet
        // => the 2-of-3 quorum is 0; a newly-parked ack waits for a follower, the no-false-ack rule).
        assert!(leader.is_leader(P));
        assert_eq!(leader.quorum_commit(P), Some(0));

        // A node that follows the same placement rebuilds the follower role and resumes fetching from
        // wherever its recovered replica log left off (here a fresh log => from 0).
        assert_eq!(role_for_placement(2, &placement), PlacementRole::Follower);
        let mut follower = DataPlaneController::new(2);
        follower.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        assert!(follower.is_follower(P));
        let req = follower.make_fetch_request(P, 8, 4096).unwrap();
        assert_eq!(
            req.from_offset, 0,
            "the follower resumes from its recovered head"
        );
    }
}
