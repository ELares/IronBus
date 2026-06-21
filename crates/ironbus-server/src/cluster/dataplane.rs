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
//! THE PRODUCE-ACK SEAM (#704 — now SHIPPED as [`ProduceAckSeam`]):
//! * [`ProduceAckSeam`] threads a REAL produce's wire `PubAck` FRAME BYTES (exactly what
//!   `session::reply_pub_ack` would write) through the [`QuorumAckGate`] via the controller's
//!   [`park_produce_ack`](DataPlaneController::park_produce_ack) /
//!   [`apply_follower_report`](DataPlaneController::apply_follower_report) /
//!   [`release_quorum_acked`](DataPlaneController::release_quorum_acked). Its single decision point,
//!   [`ProduceAckSeam::on_local_fsynced_ack`], is called AFTER the produce's local fsync returned
//!   `Appended(offset)` (the leader's I2 holds) and PARKS the wire reply — withholding it from the wire
//!   — ONLY for a clustered `C2-fsync` produce to a partition this node LEADS; in EVERY other case
//!   (single-node — no seam built at all; no-cluster; `C0`/`C1`/`C2-pagecache`; non-led partition) it
//!   returns the reply bytes verbatim to write NOW, so the single-node hot path is byte-identical BY
//!   CONSTRUCTION. [`ProduceAckSeam::on_follower_report`], driven by the ISR follower reports, hands
//!   back the parked real bytes once `min_isr` replicas have fsync'd the offset; below `min_isr` it
//!   releases nothing — no false ack, now on the REAL wire.
//!
//! FLAGGED / DEFERRED (out of this slice — each its own issue):
//! * **The live `serve`-path DATA-frame transport routing.** [`ProduceAckSeam`] is the produce-ack
//!   logic seam and is proven END-TO-END through the REAL wire-`PubAck` bytes by a leader↔follower
//!   loopback test (the `AckReplicatedBody` follower reports drive the gate; the released bytes ARE the
//!   reply the producer connection receives). What remains is purely TRANSPORT: spawning the real
//!   `TcpStream` peer reader/dialer in [`runtime`](super::runtime) that carries the `DataPlaneFrame`s
//!   (including the [`AckReplicatedBody`] reports that feed
//!   [`ProduceAckSeam::on_follower_report`]) between live nodes, and holding the [`ProduceAckSeam`]
//!   alongside the engine on the clustered serve path so `session::drain_parked` consults it. The seam
//!   provides [`decode_dataplane_frame`] + [`handle_frame`](DataPlaneController::handle_frame) +
//!   [`ProduceAckSeam::on_follower_report`] so that wiring is a routing change, not a logic change.
//!   The broker is single-partition-per-engine today; multi-partition produce fan-out is later.
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
use std::sync::Arc;

use ironbus_core::clock::Clock;
use ironbus_core::epoch_cache::{EpochCache, LeaderEpochEndOffset};
use ironbus_core::leader_lease::LeaderEpoch;
use ironbus_core::types::Offset;
use ironbus_proto::frame::FrameType;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Log;
use ironbus_storage::read_plane::ReadPlane;

use super::ack_level::ClusterAckLevel;
use super::isr::{AckReplicatedBody, IsrConfig, IsrTracker, QuorumAckGate};
use super::replication::{
    DivergenceTruncation, EpochAwareFollower, FetchRecordsBody, FetchResponseBody, Follower,
    OffsetForLeaderEpochBody, OffsetForLeaderEpochResponse, ReadPlaneLeader, ReplicationError,
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
/// The LEADER role holds an `Arc`-shared, off-actor [`ReadPlane`] of the partition's log (#654, #715),
/// NOT a `&Log` borrow: the leader serves committed bytes from the same log the engine appends to, but
/// it READS them through the lock-free read plane and NEVER writes (or borrows) the log. The engine's
/// single append actor stays the ONLY writer — the data plane is never a second writer. Holding an
/// `Arc` (rather than a borrow) is exactly what makes the controller `Send`, so the data plane can run
/// on a peer-I/O thread alongside the append actor. The FOLLOWER role OWNS its replica log (it appends
/// the leader's bytes to its OWN copy, via its OWN single writer). `None` holds no state.
enum PartitionRole<F: Filesystem, C: Clock> {
    /// This node LEADS the partition: it serves fetches from the leader's read plane + gates produces
    /// through the ISR quorum.
    Leader {
        /// The leader's `Arc`-shared, off-actor [`ReadPlane`] (#654): the lock-free view of the SEALED,
        /// flushed prefix the leader serves `FetchRecords` from. NOT a `&Log` borrow — the leader never
        /// writes (or borrows) its log here; the append actor remains the sole writer. This `Arc` is
        /// what makes the role (and the whole controller) `Send`.
        plane: Arc<ReadPlane<F>>,
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
pub struct DataPlaneController<F: Filesystem, C: Clock> {
    /// This node's cluster id (the same `u64` node-id space the metadata group / runtime use).
    node_id: u64,
    /// The per-partition role this node runs, keyed by partition id.
    roles: BTreeMap<u64, PartitionRole<F, C>>,
}

impl<F: Filesystem, C: Clock> DataPlaneController<F, C> {
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

    /// Register this node as the LEADER of `partition`, serving fetches from the `Arc`-shared, off-actor
    /// read `plane` (#654, #715) — NOT a `&Log` borrow, so the leader never writes (or borrows) its log
    /// and the controller stays `Send`. Gates produces through an [`IsrTracker`] / [`QuorumAckGate`]
    /// sized by `isr_config` over `replica_ids` (the full committed replica set; the leader is implicit
    /// and need not appear). The leader's `epochs` cache answers divergence queries; pass an
    /// [`EpochCache`] seeded with the partition's leader-epoch history (or a fresh one for a fresh
    /// partition).
    pub fn start_leader(
        &mut self,
        partition: u64,
        plane: Arc<ReadPlane<F>>,
        epochs: EpochCache,
        replica_ids: &[u64],
        isr_config: IsrConfig,
    ) {
        let mut isr = IsrTracker::new(self.node_id, replica_ids, isr_config);
        // Seed the ISR tracker's own-frontier with the read plane's current flushed frontier (the same
        // committed head Log::flushed_offset publishes), so the leader's quorum-commit starts from the
        // truth (a recovered log may already hold records).
        isr.observe_leader_fsync(plane.flushed());
        self.roles.insert(
            partition,
            PartitionRole::Leader {
                plane,
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
    /// log is dropped with the role (closing its files); a leader's read plane is an `Arc` (the engine
    /// owns the log) and merely un-referenced here.
    pub fn stop_partition(&mut self, partition: u64) -> bool {
        self.roles.remove(&partition).is_some()
    }

    // ---- LEADER role: serve fetches + gate produces ----------------------------------------------

    /// Serve a follower's `FetchRecords` for `partition` from the leader's off-actor read plane (#654,
    /// #715): zero-copy CRC-framed bytes of the SEALED, flushed prefix + the leader's high-watermark
    /// (the read plane's flushed frontier). Leader-only. The leader NEVER writes its log here — it only
    /// reads the immutable sealed bytes through the `Arc`-shared plane (the single-writer invariant).
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
            Some(PartitionRole::Leader { plane, .. }) => {
                Ok(ReadPlaneLeader::new(plane).serve_fetch(req)?)
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
            Some(PartitionRole::Leader { plane, epochs, .. }) => {
                Ok(ReadPlaneLeader::new(plane).serve_epoch_query(epochs, req))
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

/// The disposition of a produce's wire `PubAck` after the seam looks at the cluster ack level + role
/// (the output of [`ProduceAckSeam::on_local_fsynced_ack`]).
///
/// The single-node / no-cluster / non-`C2-fsync` / non-led case returns [`AckDisposition::WriteNow`]
/// carrying back the SAME reply bytes verbatim — the caller writes them immediately, exactly as it does
/// today. Only the clustered `C2-fsync` led-partition case returns [`AckDisposition::Parked`]: the
/// reply bytes are WITHHELD inside the [`QuorumAckGate`] and handed back later by
/// [`ProduceAckSeam::on_follower_report`] once the ISR quorum has fsync'd the offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AckDisposition {
    /// Write the wire reply NOW (the existing immediate local-fsync ack): single-node, no-cluster,
    /// `C0`/`C1`/`C2-pagecache`, or a partition this node does not LEAD. The bytes are the produce's
    /// own reply, returned verbatim — the caller's write path is byte-for-byte unchanged.
    WriteNow(Vec<u8>),
    /// Write these wire replies NOW, in offset order: the clustered `C2-fsync` produce was parked, but
    /// the quorum had ALREADY fsync'd the offset (a follower reported past it before this produce's
    /// local fsync completed), so the gate released its real reply (and any co-released earlier ones)
    /// straight back. The common clustered case is [`AckDisposition::Parked`]; this is the
    /// already-committed fast release. Never empty (the parked produce's own reply is always present).
    WriteNowBatch(Vec<Vec<u8>>),
    /// The wire reply is PARKED behind the quorum-fsync gate (clustered `C2-fsync` to a led partition):
    /// nothing goes on the wire until [`ProduceAckSeam::on_follower_report`] releases it on quorum
    /// fsync. Below `min_isr` it stays parked — no false ack on the wire (#593).
    Parked,
}

/// The produce-ack SEAM: the one hot-path hookup that threads a REAL produce's wire `PubAck` through
/// the [`QuorumAckGate`] (#691) via the [`DataPlaneController`] (#703), so a SERVING clustered broker's
/// `C2-fsync` produce waits for quorum-fsync end-to-end (V2-C2, #704).
///
/// # What it threads (the real wire, not an opaque id)
///
/// [`DataPlaneController::park_produce_ack`] takes a caller-opaque [`AckToken`] (a `u64`); the
/// in-process #703 test used a synthetic id. This seam parks the produce's ACTUAL wire-`PubAck` FRAME
/// BYTES (exactly what `session::reply_pub_ack` would have written) keyed by a per-park token, drives
/// the controller's gate over that token, and on release hands back the very bytes to flush. So the
/// thing released on quorum-fsync IS the real reply, not a stand-in.
///
/// # When it engages (single-node stays byte-identical BY CONSTRUCTION)
///
/// [`ProduceAckSeam::on_local_fsynced_ack`] is the single decision point. It returns
/// [`AckDisposition::Parked`] — withholding the wire reply — ONLY when ALL hold:
/// * a [`DataPlaneController`] exists (this seam is constructed; a no-cluster serve never builds it);
/// * the produce's resolved [`ClusterAckLevel`] is [`ClusterAckLevel::C2Fsync`]
///   ([`ClusterAckLevel::ack_implies_quorum_fsync`]); and
/// * this node currently LEADS the produce's partition.
///
/// In EVERY other case — single-node (no seam), no-cluster, `C0`/`C1`/`C2-pagecache`, or a non-led
/// partition — it returns [`AckDisposition::WriteNow`] with the reply bytes verbatim: the existing
/// immediate ack-after-local-fsync path, unchanged. The leader's local I2 still holds: the produce is
/// already locally fsync'd before this is called (the caller invokes it AFTER `submission.wait()`
/// returned `Appended`), so the gate only ADDS the quorum wait.
///
/// # How it releases (driven by the ISR follower reports)
///
/// [`ProduceAckSeam::on_follower_report`] feeds a follower's [`AckReplicatedBody`] into
/// [`DataPlaneController::apply_follower_report`]; whenever that advances the quorum-commit past a
/// parked offset the controller returns the parked tokens (in offset order), which the seam maps back
/// to the parked wire-`PubAck` bytes and returns for the caller to flush. Below `min_isr` the gate
/// releases NOTHING (the no-false-ack property), so a parked ack stays withheld — on the REAL wire.
///
/// `F`/`C` are the broker's filesystem / clock seams (the same the engine uses), so the seam is held
/// alongside the engine on a clustered serve. There is NO lifetime: the controller it owns serves
/// leader fetches through the `Arc`-shared off-actor read plane (#654, #715), not a `&Log` borrow, so
/// the whole seam is `Send` and can be held in shared broker state and driven on a peer-I/O thread.
pub struct ProduceAckSeam<F: Filesystem, C: Clock> {
    /// The data-plane controller (#703) this seam drives. Present ONLY on a clustered serve; a
    /// single-node / no-cluster broker never constructs a [`ProduceAckSeam`] at all, so the parking
    /// path is unreachable by construction (the single-node guarantee).
    controller: DataPlaneController<F, C>,
    /// The next per-park token. Monotonic; keys [`Self::parked`] and is what the controller's gate
    /// holds + hands back on release. Wraps only after `u64::MAX` parks, which is unreachable.
    next_token: u64,
    /// The parked wire-`PubAck` frame bytes, keyed by the token the controller's gate holds, each
    /// tagged with the OPAQUE OWNER id (the producer connection's [`MemberId`](ironbus_core::keyshared::MemberId)
    /// `u64`) that parked it, so a real serve can route the released reply back to the RIGHT producer
    /// connection. The REAL reply each parked produce will get; removed and returned in offset order on
    /// quorum-fsync release. Empty whenever nothing is withheld (single-node / no-cluster never inserts).
    /// The owner is opaque here (the in-process #703 test and the existing un-owned API tag it `0`; the
    /// client-ack path #719 tags it with the connection's member id), exactly like [`AckToken`].
    parked: BTreeMap<AckToken, (u64, Vec<u8>)>,
}

impl<F: Filesystem, C: Clock> ProduceAckSeam<F, C> {
    /// Build the seam around a clustered serve's [`DataPlaneController`]. Called ONLY on a clustered
    /// serve (a [`ClusterConfig`](super::ClusterConfig) present); a no-cluster broker never reaches
    /// here, so the parking path is never constructed (the single-node byte-identical guarantee).
    #[must_use]
    pub fn new(controller: DataPlaneController<F, C>) -> Self {
        Self {
            controller,
            next_token: 0,
            parked: BTreeMap::new(),
        }
    }

    /// The underlying controller (for role queries / serve-path frame routing). The seam owns it so the
    /// gate's parked state and the parked-bytes side-table can never drift apart.
    #[must_use]
    pub fn controller(&self) -> &DataPlaneController<F, C> {
        &self.controller
    }

    /// Mutable access to the underlying controller (the serve-path peer reader routes follower fetches /
    /// epoch queries through it). The produce-ack release path goes through
    /// [`Self::on_follower_report`], which keeps the side-table consistent.
    pub fn controller_mut(&mut self) -> &mut DataPlaneController<F, C> {
        &mut self.controller
    }

    /// The number of wire `PubAck`s currently WITHHELD across all led partitions (parked behind the
    /// quorum gate). Zero on single-node / no-cluster and whenever nothing is awaiting quorum-fsync.
    #[must_use]
    pub fn parked_len(&self) -> usize {
        self.parked.len()
    }

    /// The ONE produce-ack decision point: called AFTER the produce's local group-commit fsync returned
    /// `Appended(offset)` (the leader's I2 holds), with the produce's resolved cluster `ack_level`, the
    /// `partition` it landed on, the appended `offset`, and the EXACT wire-`PubAck` frame bytes the
    /// caller would otherwise write now.
    ///
    /// Returns [`AckDisposition::Parked`] — withholding `reply_bytes` inside the quorum gate — ONLY for
    /// a clustered `C2-fsync` produce to a partition THIS node leads. In every other case it returns
    /// [`AckDisposition::WriteNow(reply_bytes)`](AckDisposition::WriteNow) verbatim: the caller writes
    /// the reply immediately, byte-for-byte the existing path. The gate's release re-checks the current
    /// quorum-commit in case it is already satisfied (a fast follower that reported before this park),
    /// so a just-parked ack that is ALREADY quorum-committed is handed straight back to write now.
    ///
    /// # Errors
    /// [`DataPlaneError`] only if the controller rejects the park (it never does for a led partition —
    /// the `Parked` branch is taken only when [`DataPlaneController::is_leader`] is already true).
    pub fn on_local_fsynced_ack(
        &mut self,
        ack_level: ClusterAckLevel,
        partition: u64,
        offset: u64,
        reply_bytes: Vec<u8>,
    ) -> Result<AckDisposition, DataPlaneError> {
        // The un-owned API (the in-process #703 test + the serve-path observability callers) tags the
        // park with owner `0`; routing the released bytes back to a specific producer connection is the
        // #719 client-ack path, which calls `on_local_fsynced_ack_owned`. The decision logic is shared.
        self.on_local_fsynced_ack_owned(0, ack_level, partition, offset, reply_bytes)
    }

    /// The OWNER-tagged produce-ack decision (#719): identical to [`Self::on_local_fsynced_ack`] but
    /// records the OPAQUE `owner` id (a producer connection's [`MemberId`](ironbus_core::keyshared::MemberId))
    /// alongside the parked reply, so the release path ([`Self::on_follower_report_owned`]) can route the
    /// released wire `PubAck` back to the RIGHT producer connection. The seam never interprets `owner`.
    ///
    /// Single-node byte-identical is unchanged: the seam is never CONSTRUCTED off-cluster, and this
    /// returns [`AckDisposition::WriteNow`] verbatim for every non-`C2-fsync` / non-led case (no park,
    /// no owner recorded).
    ///
    /// # Errors
    /// [`DataPlaneError`] only if the controller rejects the park (never for a led partition — the
    /// `Parked` branch is taken only when [`DataPlaneController::is_leader`] is already true).
    pub fn on_local_fsynced_ack_owned(
        &mut self,
        owner: u64,
        ack_level: ClusterAckLevel,
        partition: u64,
        offset: u64,
        reply_bytes: Vec<u8>,
    ) -> Result<AckDisposition, DataPlaneError> {
        // The seam engages ONLY for a clustered C2-fsync produce to a LED partition. Anything else is
        // the existing immediate ack: returned verbatim, no parking state constructed.
        if !ack_level.ack_implies_quorum_fsync() || !self.controller.is_leader(partition) {
            return Ok(AckDisposition::WriteNow(reply_bytes));
        }
        // Park the REAL wire bytes keyed by a fresh token (tagged with the owner), then thread that token
        // through the controller's gate at the appended offset. The leader has ALREADY locally fsync'd
        // (the I2 ack-after-its-own-fsync); the gate adds the quorum-fsync condition.
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        self.parked.insert(token, (owner, reply_bytes));
        self.controller.park_produce_ack(partition, offset, token)?;
        // Re-check the CURRENT quorum-commit: a follower may already have reported past this offset
        // (its report arrived before this produce's local fsync completed), in which case the ack is
        // immediately quorum-committed and we hand the real bytes straight back to write now. Below
        // min_isr this releases nothing and the ack stays parked (no false ack on the wire).
        let released = self.take_released_owned(partition)?;
        if released.is_empty() {
            Ok(AckDisposition::Parked)
        } else {
            // The quorum had already fsync'd this offset (a follower reported past it before this
            // produce's local fsync completed), so the gate released the real reply (and any
            // co-released earlier ones, in offset order) straight back to write now. The un-owned
            // disposition drops the owner tags (the caller of the un-owned path holds one connection).
            Ok(AckDisposition::WriteNowBatch(
                released.into_iter().map(|(_owner, bytes)| bytes).collect(),
            ))
        }
    }

    /// Feed a follower's [`AckReplicatedBody`] for `partition` into the gate and return the REAL wire
    /// `PubAck` byte-frames that the report just pushed past the quorum-commit, in offset order, for the
    /// caller to flush onto the producer connections. Empty unless this report advanced the
    /// quorum-commit past a parked offset (including the no-quorum / below-`min_isr` case, where the
    /// gate releases NOTHING — the no-false-ack property, now on the real wire).
    ///
    /// # Errors
    /// [`DataPlaneError`] if the controller rejects the report (an unknown / non-led partition).
    pub fn on_follower_report(
        &mut self,
        partition: u64,
        report: &AckReplicatedBody,
    ) -> Result<Vec<Vec<u8>>, DataPlaneError> {
        Ok(self
            .on_follower_report_owned(partition, report)?
            .into_iter()
            .map(|(_owner, bytes)| bytes)
            .collect())
    }

    /// The OWNER-tagged release (#719): like [`Self::on_follower_report`] but returns each released wire
    /// `PubAck` paired with the OPAQUE owner id ([`Self::on_local_fsynced_ack_owned`]'s `owner`) that
    /// parked it, so a real serve routes each reply back to the RIGHT producer connection. Below
    /// `min_isr` releases nothing (the no-false-ack property, on the real wire).
    ///
    /// # Errors
    /// [`DataPlaneError`] if the controller rejects the report (an unknown / non-led partition).
    pub fn on_follower_report_owned(
        &mut self,
        partition: u64,
        report: &AckReplicatedBody,
    ) -> Result<Vec<(u64, Vec<u8>)>, DataPlaneError> {
        let tokens = self.controller.apply_follower_report(partition, report)?;
        Ok(self.owned_bytes_for_tokens(&tokens))
    }

    /// Re-drive the quorum-ack release for `partition` against the CURRENT ISR state (e.g. after the
    /// leader's own local fsync advanced, or a follower rejoined the ISR) and return any newly-released
    /// owner-tagged wire `PubAck` byte-frames in offset order. Below `min_isr` releases nothing.
    fn take_released_owned(
        &mut self,
        partition: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, DataPlaneError> {
        let tokens = self.controller.release_quorum_acked(partition)?;
        Ok(self.owned_bytes_for_tokens(&tokens))
    }

    /// Map released gate tokens (in offset order) back to their parked `(owner, wire-PubAck bytes)`,
    /// removing them from the side-table. A token with no entry is skipped defensively (it can only
    /// happen if a token was released twice, which the gate's `released_through` prevents).
    fn owned_bytes_for_tokens(&mut self, tokens: &[AckToken]) -> Vec<(u64, Vec<u8>)> {
        tokens
            .iter()
            .filter_map(|t| self.parked.remove(t))
            .collect()
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

    /// The engine's `Arc`-shared, off-actor read plane over a leader log (#654, #715) — what the leader
    /// role serves fetches from after the #715 refactor (NO `&Log` borrow). The test owns the log; the
    /// plane keeps observing it (the append actor would keep publishing in a real serve).
    fn leader_plane(log: &Log<InMemoryFs, ManualClock>) -> Arc<ReadPlane<InMemoryFs>> {
        Arc::new(log.read_plane().expect("read plane builds"))
    }

    /// The first offset the leader's read plane does NOT serve off-actor (the sealed-served end): chain
    /// `read_range_raw` from 0 until it reports no more sealed bytes below the flushed frontier. The
    /// read plane serves the SEALED prefix; this is the offset a follower converges to over the live
    /// transport before the active (flushed-but-unsealed) tail seals. Used so byte-identity asserts over
    /// exactly the replicated range.
    fn plane_served_end(plane: &ReadPlane<InMemoryFs>) -> u64 {
        let flushed = plane.flushed();
        let mut next = 0u64;
        let mut guard = 0u32;
        while next < flushed {
            guard += 1;
            assert!(guard < 100_000, "read-plane chain failed to terminate");
            let raw = plane
                .read_range_raw(Offset::new(next), 1_000, None)
                .expect("read plane serves");
            let advanced = raw.run.next_offset.get();
            if advanced > next {
                next = advanced;
            } else {
                // Nothing more is served off-actor from here (the active tail): stop at the sealed end.
                break;
            }
        }
        next
    }

    /// Assert a follower replica is BYTE-IDENTICAL to the leader over the range the read plane served.
    ///
    /// A follower replicates frames VERBATIM and seals at the same cap, so a SEALED follower segment is
    /// byte-for-byte the leader's same-named file (footer included). The follower's LAST (still-active)
    /// segment holds the same RECORDS but has not sealed yet (it seals on its next roll), so it equals
    /// the leader's same-named SEALED file MINUS the trailing seal footer — i.e. the leader's file is a
    /// byte-identical PREFIX-superset. So: every follower file is a byte-identical prefix of the leader's
    /// same-named file, at least one matches EXACTLY (proving real sealed replication), and the follower
    /// covered the whole sealed-served prefix. This is the exact invariant the read-plane leader serve
    /// guarantees; the active flushed tail (and the follower's own trailing seal) close on the next roll
    /// (FLAGGED).
    fn assert_replicated_byte_identical(
        follower_log: &Log<InMemoryFs, ManualClock>,
        leader_log: &Log<InMemoryFs, ManualClock>,
        served_end: u64,
    ) {
        let leader: std::collections::BTreeMap<String, Vec<u8>> =
            dump_segments(leader_log).into_iter().collect();
        let follower = dump_segments(follower_log);
        assert!(
            follower.iter().any(|(_, b)| !b.is_empty()),
            "follower replicated at least one segment file"
        );
        let mut any_exact = false;
        for (name, bytes) in &follower {
            let leader_bytes = leader
                .get(name)
                .unwrap_or_else(|| panic!("leader missing replicated segment file {name}"));
            assert!(
                leader_bytes.starts_with(bytes),
                "follower segment {name} is not a byte-identical prefix of the leader's"
            );
            any_exact |= bytes == leader_bytes;
        }
        assert!(
            any_exact,
            "no fully-sealed follower segment is byte-identical to the leader's (no real replication)"
        );
        assert!(
            follower_log.next_offset().get() >= served_end,
            "follower ({}) did not cover the read plane's sealed-served prefix ({served_end})",
            follower_log.next_offset().get()
        );
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
        leader: &mut DataPlaneController<InMemoryFs, ManualClock>,
        follower: &mut DataPlaneController<InMemoryFs, ManualClock>,
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

        // Node 1 leads P over replicas {1,2,3}, min_isr=2 (a 2-of-3 quorum). The leader serves through
        // the engine's OFF-ACTOR read plane (#654, #715), NOT a &Log borrow — it never writes its log.
        let plane = leader_plane(&leader_log);
        // The read plane serves the SEALED prefix; the active flushed tail seals later (FLAGGED). The
        // multi-segment small cap leaves a healthy sealed prefix to replicate + quorum-ack here.
        let served_end = plane_served_end(&plane);
        assert!(
            served_end > 0 && served_end <= leader_hw,
            "the read plane serves a non-empty sealed prefix (served_end={served_end})"
        );
        let mut leader = DataPlaneController::new(1);
        leader.start_leader(
            P,
            Arc::clone(&plane),
            EpochCache::new(),
            &[1, 2, 3],
            quorum3(),
        );

        // Nodes 2 and 3 each follow P with a fresh replica log.
        let mut follower2 = DataPlaneController::new(2);
        follower2.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        let mut follower3 = DataPlaneController::new(3);
        follower3.start_follower(P, open_log(InMemoryFs::new(), small_config()));

        // PARK a produce ack for each sealed-served offset behind the quorum gate (a real serve parks
        // each produce's PubAck; here token == offset). The leader has locally fsync'd, but no follower
        // has the data yet.
        for off in 0..served_end {
            leader.park_produce_ack(P, off, off).unwrap();
        }
        assert_eq!(
            leader.pending_ack_count(P),
            usize::try_from(served_end).unwrap()
        );

        // No follower has fsync'd => the 2-of-3 quorum-commit is 0 (only the leader) => NO ack releases.
        // This is the no-false-ack property: leader-only is NOT a quorum.
        let released = leader.release_quorum_acked(P).unwrap();
        assert!(
            released.is_empty(),
            "no ack may release on the leader alone (no quorum)"
        );
        assert_eq!(leader.quorum_commit(P), Some(0));

        // Replicate to follower 2 to catch-up over the read-plane-served prefix. Each round: follower
        // fetches, leader serves (via the read plane), follower applies + reports, leader records the
        // report and releases the now-quorum-committed acks.
        let mut released_to_f2: Vec<AckToken> = Vec::new();
        for _ in 0..(leader_hw + 4) {
            if follower2.follower_high_watermark(P).unwrap() >= served_end {
                break;
            }
            released_to_f2.extend(fetch_round(&mut leader, &mut follower2, P));
        }
        // With follower 2 caught up to the sealed-served prefix the 2-of-3 quorum (leader + follower2)
        // is met at served_end, so ALL parked acks released — and ONLY after the quorum fsync'd.
        let mut all = released_to_f2;
        all.sort_unstable();
        assert_eq!(all, (0..served_end).collect::<Vec<_>>());
        assert_eq!(leader.pending_ack_count(P), 0, "every parked ack released");
        assert_eq!(leader.quorum_commit(P), Some(served_end));

        // Follower 2's replica is BYTE-IDENTICAL to the leader over the read-plane-served prefix (every
        // replicated segment file matches the leader's same-named file).
        assert_replicated_byte_identical(
            follower2.follower_log(P).unwrap(),
            &leader_log,
            served_end,
        );

        // Catch follower 3 up too (its reports release nothing new — the acks already released).
        for _ in 0..(leader_hw + 4) {
            if follower3.follower_high_watermark(P).unwrap() >= served_end {
                break;
            }
            let none_new = fetch_round(&mut leader, &mut follower3, P);
            assert!(
                none_new.is_empty(),
                "acks already released, none re-release"
            );
        }
        assert_replicated_byte_identical(
            follower3.follower_log(P).unwrap(),
            &leader_log,
            served_end,
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
        let plane = leader_plane(&leader_log);
        let served_end = plane_served_end(&plane);
        assert!(
            served_end > 0,
            "the read plane serves a non-empty sealed prefix"
        );
        let mut leader = DataPlaneController::new(1);
        leader.start_leader(
            P,
            Arc::clone(&plane),
            EpochCache::new(),
            &[1, 2, 3],
            IsrConfig {
                min_isr: 2,
                max_lag_records: 3,
            },
        );
        for off in 0..served_end {
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
            usize::try_from(served_end).unwrap(),
            "every ack still parked, awaiting a quorum"
        );

        // The moment ONE follower catches up and reports, the quorum (2-of-3) is met and the acks
        // release — proving the block was on the missing quorum, not a stuck gate.
        let mut follower2 = DataPlaneController::new(2);
        follower2.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        let mut released: Vec<AckToken> = Vec::new();
        for _ in 0..(leader_hw + 4) {
            if follower2.follower_high_watermark(P).unwrap() >= served_end {
                break;
            }
            released.extend(fetch_round(&mut leader, &mut follower2, P));
        }
        released.sort_unstable();
        assert_eq!(released, (0..served_end).collect::<Vec<_>>());
        assert_eq!(leader.pending_ack_count(P), 0);
    }

    // ---- a divergent follower self-heals ---------------------------------------------------------

    #[test]
    #[allow(clippy::too_many_lines)] // one coherent self-heal scenario (build lineages, diverge, heal)
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
        // Catch the follower up to the old leader's read-plane-served prefix (the leader serves through
        // the off-actor read plane #654/#715, the SEALED prefix). The small cap leaves an 18-record log
        // with a sealed prefix that covers the divergence region [10,14) and the divergent suffix.
        let old_served = {
            let old_plane = leader_plane(&old_leader_log);
            let old_served = plane_served_end(&old_plane);
            assert!(
                old_served >= 14,
                "the old leader's sealed prefix must cover the divergent suffix (got {old_served})"
            );
            let mut old_leader = DataPlaneController::<InMemoryFs, ManualClock>::new(1);
            old_leader.start_leader(P, Arc::clone(&old_plane), old_epochs.clone(), &[1, 2], {
                IsrConfig {
                    min_isr: 1,
                    max_lag_records: 0,
                }
            });
            for _ in 0..24 {
                if follower.follower_high_watermark(P).unwrap() >= old_served {
                    break;
                }
                let req = follower.make_fetch_request(P, 8, 4096).unwrap();
                let resp = old_leader.serve_fetch(P, &req).unwrap();
                follower.apply_fetch_response(P, &resp).unwrap();
            }
            follower
                .assign_follower_epoch(P, LeaderEpoch::new(5), Offset::new(10))
                .unwrap();
            old_served
        };
        assert_eq!(follower.follower_high_watermark(P).unwrap(), old_served);

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
        let new_plane = leader_plane(&new_leader_log);
        let new_served = plane_served_end(&new_plane);
        assert!(
            new_served >= 14,
            "the new leader's sealed prefix must cover the clean lineage past divergence (got {new_served})"
        );
        let mut new_leader = DataPlaneController::<InMemoryFs, ManualClock>::new(1);
        new_leader.start_leader(P, Arc::clone(&new_plane), new_epochs, &[1, 2], {
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

        // Re-fetch the clean lineage forward from the new leader's read-plane-served prefix; the
        // follower converges byte-identical over the replicated range.
        for _ in 0..30 {
            if follower.follower_high_watermark(P).unwrap() >= new_served {
                break;
            }
            let req = follower.make_fetch_request(P, 8, 4096).unwrap();
            let resp = new_leader.serve_fetch(P, &req).unwrap();
            follower.apply_fetch_response(P, &resp).unwrap();
        }
        assert_replicated_byte_identical(
            follower.follower_log(P).unwrap(),
            &new_leader_log,
            new_served,
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
        // leader-only shape: the quorum-commit is the leader's own fsync'd frontier (seeded from the
        // read plane's flushed frontier = the full committed prefix) and the gate releases on the local
        // fsync alone — exactly the single-node I2 ack, no follower required.
        let plane = leader_plane(&log);
        let mut node = DataPlaneController::<InMemoryFs, ManualClock>::new(1);
        node.start_leader(
            P,
            Arc::clone(&plane),
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
        let plane = leader_plane(&leader_log);
        let mut leader = DataPlaneController::<InMemoryFs, ManualClock>::new(1);
        leader.start_leader(
            P,
            Arc::clone(&plane),
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

    // ---- THE produce-ack SEAM (#704): a REAL wire PubAck threaded through the QuorumAckGate ---------

    use ironbus_proto::frame::encode_frame;
    use ironbus_proto::message::{decode_pub_ack, encode_pub_ack, PubAckBody};

    /// Build the EXACT wire `PubAck` frame bytes the session would write for `offset` — the real
    /// reply the producer connection receives. This mirrors `session::reply_pub_ack`
    /// (`encode_pub_ack` body inside an `encode_frame(FrameType::PubAck, ..)` envelope), so the bytes
    /// the seam parks + releases are the genuine wire reply, not a synthetic token.
    fn wire_pub_ack(offset: u64) -> Vec<u8> {
        let mut body = Vec::with_capacity(8);
        encode_pub_ack(&PubAckBody { offset }, &mut body);
        let mut frame = Vec::new();
        encode_frame(FrameType::PubAck, &body, &mut frame).expect("PubAck frame encodes");
        frame
    }

    /// Decode a wire `PubAck` frame's offset (skip the `[len][type]` envelope header, then decode the
    /// body) — to assert a RELEASED frame is the real reply for the expected offset, on the real wire.
    fn pub_ack_offset(frame: &[u8]) -> u64 {
        // The frame is `[u32 len][u8 type][body]`; the offset body is the last 8 bytes.
        let body = &frame[frame.len() - 8..];
        decode_pub_ack(body).expect("PubAck body decodes").offset
    }

    /// Stand up a leader controller for partition `P` over a fresh `replica_ids` / `config`, with a
    /// log already fsync'd to `n` records (the leader's local I2 done), plus a follower controller per
    /// non-leader replica. The leader serves through the OFF-ACTOR read plane (#654, #715), NOT a &Log
    /// borrow. Returns `(seam_around_leader, followers, served_end)` — `served_end` is the read plane's
    /// sealed-served prefix end, the offset a follower converges to before the active tail seals, so a
    /// seam test parks within the range that actually replicates over the wire.
    fn led_cluster(
        partition: u64,
        leader_id: u64,
        replica_ids: &[u64],
        config: IsrConfig,
        n: u32,
    ) -> (
        ProduceAckSeam<InMemoryFs, ManualClock>,
        Vec<DataPlaneController<InMemoryFs, ManualClock>>,
        u64,
    ) {
        // Leak the leader log so the read plane keeps observing it for the test's lifetime (the append
        // actor would keep publishing in a real serve); the test owns the process. The leader role
        // holds only an Arc<ReadPlane> (Send), never the log.
        let leader_log: &'static Log<InMemoryFs, ManualClock> = {
            let mut log = open_log(InMemoryFs::new(), small_config());
            for i in 0..n {
                log.append(&rec(format!("rep-{i:02}").as_bytes())).unwrap();
            }
            log.sync().unwrap();
            Box::leak(Box::new(log))
        };
        let plane = leader_plane(leader_log);
        let served_end = plane_served_end(&plane);
        let mut leader = DataPlaneController::new(leader_id);
        leader.start_leader(
            partition,
            Arc::clone(&plane),
            EpochCache::new(),
            replica_ids,
            config,
        );
        let followers = replica_ids
            .iter()
            .filter(|&&id| id != leader_id)
            .map(|&id| {
                let mut f = DataPlaneController::new(id);
                f.start_follower(partition, open_log(InMemoryFs::new(), small_config()));
                f
            })
            .collect();
        (ProduceAckSeam::new(leader), followers, served_end)
    }

    #[test]
    fn clustered_c2_fsync_led_produce_parks_the_wire_puback_until_quorum_fsync_then_sends_it() {
        const P: u64 = 0;
        // Node 1 leads P over {1,2,3}, min_isr=2 — a real serving leader with a local fsync done.
        let (mut seam, mut followers, served_end) = led_cluster(P, 1, &[1, 2, 3], quorum3(), 25);
        assert!(seam.controller().is_leader(P));
        assert!(
            served_end > 0,
            "the read plane serves a non-empty sealed prefix"
        );

        // A real C2-fsync produce to the LED partition: thread its REAL wire PubAck through the seam.
        // The leader has locally fsync'd (I2); the gate must now WITHHOLD the wire ack until quorum.
        // Park the LAST sealed-served offset (it replicates over the wire; the active tail seals later).
        let offset = served_end - 1;
        let reply = wire_pub_ack(offset);
        let disposition = seam
            .on_local_fsynced_ack(ClusterAckLevel::C2Fsync, P, offset, reply.clone())
            .unwrap();

        // LEADER-ONLY: the ack is PARKED — NOT sent on the wire (no quorum yet).
        assert_eq!(
            disposition,
            AckDisposition::Parked,
            "a clustered C2-fsync led produce parks its wire PubAck (no quorum yet)"
        );
        assert_eq!(seam.parked_len(), 1, "exactly one wire PubAck is withheld");

        // The 2nd replica catches up but its report does NOT yet cover the offset until it has fsync'd
        // through it; drive fetch rounds until follower 2 is caught up, collecting released wire frames.
        let mut released: Vec<Vec<u8>> = Vec::new();
        for _ in 0..40 {
            if seam.controller().is_leader(P) {
                // follower 2 fetches from the leader, applies, and reports its fsync'd frontier
                let req = followers[0].make_fetch_request(P, 8, 4096).unwrap();
                let action = seam
                    .controller_mut()
                    .handle_frame(P, DataPlaneFrame::FetchRequest(req))
                    .unwrap();
                let resp = match action {
                    DataPlaneAction::SendFetchResponse { response, .. } => response,
                    other => panic!("expected a fetch response, got {other:?}"),
                };
                followers[0]
                    .handle_frame(P, DataPlaneFrame::FetchResponse(resp))
                    .unwrap();
                let report = followers[0].follower_report(P).unwrap();
                // THE RELEASE PATH: the follower's fsync report drives the gate; released bytes are the
                // REAL wire PubAck frames to flush to the producer connection.
                released.extend(seam.on_follower_report(P, &report).unwrap());
            }
            if followers[0].follower_high_watermark(P).unwrap() >= served_end {
                break;
            }
        }

        // The wire PubAck was SENT (released) only after the 2nd replica reported fsync of the offset —
        // and it is the REAL reply: it decodes to the produce's offset, and the released bytes are
        // byte-identical to the reply the session would have written immediately on single-node.
        assert_eq!(
            released.len(),
            1,
            "exactly one wire PubAck released after the quorum fsync'd"
        );
        assert_eq!(
            pub_ack_offset(&released[0]),
            offset,
            "the released frame is the real PubAck for the produced offset"
        );
        assert_eq!(
            released[0], reply,
            "the released bytes ARE the original wire PubAck (the real reply, not a token)"
        );
        assert_eq!(
            seam.parked_len(),
            0,
            "nothing remains withheld after release"
        );
    }

    #[test]
    fn below_min_isr_the_wire_puback_stays_parked_no_false_ack_on_the_wire() {
        const P: u64 = 0;
        // Node 1 leads P over {1,2,3}, min_isr=2. Only the leader exists in the ISR's eyes until a
        // follower reports; with NO follower report the ISR is below min_isr (no quorum).
        let (mut seam, mut followers, served_end) = led_cluster(P, 1, &[1, 2, 3], quorum3(), 10);
        assert!(
            served_end > 0,
            "the read plane serves a non-empty sealed prefix"
        );

        let offset = served_end - 1;
        let reply = wire_pub_ack(offset);
        let disposition = seam
            .on_local_fsynced_ack(ClusterAckLevel::C2Fsync, P, offset, reply)
            .unwrap();
        assert_eq!(disposition, AckDisposition::Parked);

        // Re-drive the release with NO follower report at all: the ISR is below min_isr (leader alone),
        // so the gate releases NOTHING — the no-false-ack property, now on the REAL wire.
        let released = seam.on_follower_report(P, &followers[0].follower_report(P).unwrap());
        // follower 0 has fsync'd nothing yet (fresh log => fsynced_offset 0), so still no quorum at 9.
        assert!(
            released.unwrap().is_empty(),
            "below min_isr the wire PubAck is NEVER sent (no false ack)"
        );
        assert_eq!(
            seam.parked_len(),
            1,
            "the wire PubAck stays withheld below min_isr"
        );
        // Silence the unused-mut on `followers` if the loop above ever changes.
        let _ = &mut followers;
    }

    #[test]
    fn single_node_and_c1_and_c2_pagecache_acks_are_byte_identical_immediate_no_parking() {
        const P: u64 = 0;
        // A 1-node cluster (replicas == [1], min_isr == 1) is the degenerate leader-only shape — the
        // closest a cluster gets to single-node. Even here, C1 / C2-pagecache must ack IMMEDIATELY with
        // the verbatim reply bytes and NEVER park (the single-node-shaped guarantee).
        let mut single = DataPlaneController::<InMemoryFs, ManualClock>::new(1);
        let single_log: &'static Log<InMemoryFs, ManualClock> = {
            let mut log = open_log(InMemoryFs::new(), small_config());
            log.append(&rec(b"only")).unwrap();
            log.sync().unwrap();
            Box::leak(Box::new(log))
        };
        single.start_leader(
            P,
            leader_plane(single_log),
            EpochCache::new(),
            &[1],
            IsrConfig {
                min_isr: 1,
                max_lag_records: 0,
            },
        );
        let mut seam = ProduceAckSeam::new(single);

        let reply = wire_pub_ack(0);
        // C1 (leader local-fsync = today's I2 ack): WRITE NOW, verbatim, never parked.
        assert_eq!(
            seam.on_local_fsynced_ack(ClusterAckLevel::C1, P, 0, reply.clone())
                .unwrap(),
            AckDisposition::WriteNow(reply.clone()),
            "C1 returns the verbatim reply to write now — byte-identical to single-node"
        );
        // C2-pagecache (the weaker opt-in): WRITE NOW, verbatim, never parked (it does NOT imply
        // quorum-fsync, so the quorum gate never engages).
        assert_eq!(
            seam.on_local_fsynced_ack(ClusterAckLevel::C2Pagecache, P, 0, reply.clone())
                .unwrap(),
            AckDisposition::WriteNow(reply.clone()),
            "C2-pagecache returns the verbatim reply to write now (no quorum-fsync gate)"
        );
        // C0 (no-ack): also WRITE NOW (the caller suppresses the frame for L0 upstream; the seam never
        // parks it — fire-and-forget is not at-least-once).
        assert_eq!(
            seam.on_local_fsynced_ack(ClusterAckLevel::C0, P, 0, reply.clone())
                .unwrap(),
            AckDisposition::WriteNow(reply.clone()),
            "C0 returns the verbatim reply to write now"
        );
        // The CRITICAL by-construction check: across every non-C2-fsync level NOTHING was ever parked.
        assert_eq!(
            seam.parked_len(),
            0,
            "the parking path is NEVER constructed for C0/C1/C2-pagecache"
        );
    }

    #[test]
    fn a_non_led_partition_uses_the_existing_immediate_ack_even_at_c2_fsync() {
        const P: u64 = 7;
        // This node (node 2) FOLLOWS P — it does not lead it. A produce can only land on a leader, but
        // assert defensively that even a C2-fsync ack for a partition this node does NOT lead returns
        // the verbatim immediate reply and never parks (the seam engages ONLY on a led partition).
        let mut follower = DataPlaneController::new(2);
        follower.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        let mut seam = ProduceAckSeam::new(follower);
        assert!(!seam.controller().is_leader(P));

        let reply = wire_pub_ack(3);
        assert_eq!(
            seam.on_local_fsynced_ack(ClusterAckLevel::C2Fsync, P, 3, reply.clone())
                .unwrap(),
            AckDisposition::WriteNow(reply),
            "a C2-fsync ack for a NON-led partition uses the existing immediate ack — never parked"
        );
        assert_eq!(
            seam.parked_len(),
            0,
            "no parking for a partition this node does not lead"
        );
    }

    #[test]
    fn an_already_quorum_committed_offset_releases_the_real_reply_straight_back() {
        const P: u64 = 0;
        // Node 1 leads {1,2,3}, min_isr=2, log fsync'd to 5. The follower reports fsync of the WHOLE
        // range BEFORE the produce's ack is threaded — so when the produce parks, the offset is already
        // quorum-committed and the seam hands the REAL reply straight back to write now.
        let (mut seam, mut followers, served_end) = led_cluster(P, 1, &[1, 2, 3], quorum3(), 5);
        assert!(
            served_end > 0,
            "the read plane serves a non-empty sealed prefix"
        );
        // Catch follower 2 fully up so its reported fsync'd frontier is the sealed-served end.
        for _ in 0..20 {
            let req = followers[0].make_fetch_request(P, 8, 4096).unwrap();
            let action = seam
                .controller_mut()
                .handle_frame(P, DataPlaneFrame::FetchRequest(req))
                .unwrap();
            if let DataPlaneAction::SendFetchResponse { response, .. } = action {
                followers[0]
                    .handle_frame(P, DataPlaneFrame::FetchResponse(response))
                    .unwrap();
            }
            let report = followers[0].follower_report(P).unwrap();
            let _ = seam.on_follower_report(P, &report).unwrap();
            if followers[0].follower_high_watermark(P).unwrap() >= served_end {
                break;
            }
        }
        // quorum_commit is now served_end (leader + follower2 both fsync'd through served_end-1). A
        // produce at served_end-1 is already quorum-committed: parking it releases the real reply now.
        let offset = served_end - 1;
        let reply = wire_pub_ack(offset);
        let disposition = seam
            .on_local_fsynced_ack(ClusterAckLevel::C2Fsync, P, offset, reply.clone())
            .unwrap();
        match disposition {
            AckDisposition::WriteNowBatch(frames) => {
                assert_eq!(frames.len(), 1);
                assert_eq!(frames[0], reply, "the real reply releases straight back");
                assert_eq!(pub_ack_offset(&frames[0]), offset);
            }
            other => panic!("expected an already-committed fast release, got {other:?}"),
        }
        assert_eq!(seam.parked_len(), 0, "nothing remains withheld");
    }
}
