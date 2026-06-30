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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use ironbus_core::clock::Clock;
use ironbus_core::epoch_cache::{EpochCache, LeaderEpochEndOffset};
use ironbus_core::leader_lease::LeaderEpoch;
use ironbus_core::types::Offset;
use ironbus_proto::frame::FrameType;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Log;
use ironbus_storage::read_plane::{RawSealedRead, ReadPlane};
use ironbus_storage::segment::RawByteRun;

use super::ack_level::ClusterAckLevel;
use super::isr::{AckReplicatedBody, IsrConfig, IsrTracker, QuorumAckGate};
use super::read_consistency::{
    classify_follower_read, classify_leader_local_read, follower_safe_watermark,
    FollowerReadDecision, LeaderReadDecision, ReadTier,
};
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
    /// The apply-time committed-completeness self-verify FAILED (#618b): a failover named THIS node the
    /// new leader, but its own durable log does NOT cover the committed-HW bar carried with the
    /// promotion — promoting it would lose committed data. The promotion is ABORTED fail-closed (no false
    /// leader is created; the partition stays leaderless / recoverable). This is the defense-in-depth net
    /// that makes committed-data loss impossible even from an optimistic / buggy proposal.
    FailoverIncomplete {
        /// The partition whose failover was aborted.
        partition: u64,
        /// THIS node's durable frontier (the first offset it has NOT durably appended).
        durable_frontier: u64,
        /// The committed-HW bar the successor had to hold (and did not).
        committed_hw: u64,
    },
    /// A LEADER-LEASE LINEARIZABLE LOCAL read (#620, [`DataPlaneController::serve_leader_local_read`])
    /// was requested but the leaseholder's lease is in DOUBT (expired, or this node is on a stale epoch /
    /// is not the current leaseholder). The read is REFUSED fail-closed rather than risk a stale local
    /// read — the caller falls back to a read-index/quorum confirm or returns unavailable. This is the
    /// #694/#722 soundness fence: no serving-as-leader on a stale epoch.
    LeaseNotValid {
        /// The partition whose lease was in doubt.
        partition: u64,
    },
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
            DataPlaneError::FailoverIncomplete {
                partition,
                durable_frontier,
                committed_hw,
            } => write!(
                f,
                "partition {partition} failover aborted (fail-closed): this node's durable frontier \
                 {durable_frontier} is behind the committed-HW bar {committed_hw}; it is missing \
                 committed data and must not become leader"
            ),
            DataPlaneError::LeaseNotValid { partition } => write!(
                f,
                "partition {partition} leader-lease local read refused (fail-closed): the leader lease \
                 is in doubt (expired / stale epoch); not serving a stale local read"
            ),
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
    /// A follower → leader DIRTY-TIER committed-HW QUERY (received on the leader side, #739): the tiny
    /// HW-version confirm a follower sends when a "latest" follower-read reaches above its safe
    /// watermark. The partition is carried by the data-plane envelope's partition prefix.
    CommittedHwQuery(CommittedHwQueryBody),
    /// A leader → follower committed-HW RESPONSE (received on the follower side, #739): the leader's
    /// CURRENT committed HW, which the follower uses to raise its servable bound before re-serving the
    /// confirmed prefix locally — never an offset above this.
    CommittedHwResponse(CommittedHwResponseBody),
}

/// The per-partition cap on parked (quorum-withheld) `C2-fsync` produce acks (#864). A `C2-fsync`
/// produce to a led partition whose ISR is below `min_isr` (a follower down) cannot be quorum-committed,
/// so its `PubAck` is withheld; below `min_isr` NOTHING drains. Without a cap a pipelining producer that
/// does not wait for acks grows the gate's `pending` list AND the seam's `parked` reply-bytes map without
/// bound — driving a bounded-RAM node to OOM (and, under `panic = "abort"`, an allocation failure aborts
/// the whole broker). At the cap the produce is FAILED with an explicit not-enough-replicas error (the
/// honest unavailable-over-unsafe signal the producer can back off on) rather than buffered unboundedly.
/// `8192` per partition bounds the worst-case parked footprint to a few hundred KiB per led partition
/// while tolerating a transient follower blip (the backlog drains the moment the quorum advances). A
/// configurable cap is a tracked follow-up.
const MAX_PARKED_ACKS_PER_PARTITION: usize = 8192;

/// The `kind` discriminant byte leading a [`FrameType::CommittedHwQuery`] body (#739), so the request
/// and the response (which SHARE the wire tag 43, like `OffsetForLeaderEpoch`) are never confused.
const HW_KIND_REQUEST: u8 = 0;
const HW_KIND_RESPONSE: u8 = 1;

/// The fixed little-endian byte length of an encoded [`CommittedHwQueryBody`]: just the `kind: u8`
/// (the partition rides the data-plane envelope's partition prefix).
const HW_QUERY_REQUEST_LEN: usize = 1;

/// The fixed little-endian byte length of an encoded [`CommittedHwResponseBody`]: `kind: u8` +
/// `committed_hw: u64`.
const HW_QUERY_RESPONSE_LEN: usize = 1 + 8;

/// A follower → leader DIRTY-TIER committed-HW QUERY (#739, the #723 `ConfirmWithLeader` over the
/// wire): "what is YOUR current committed high-watermark for this partition?" — a tiny HW-VERSION query,
/// NOT a data fetch. The follower asks this when a "latest" follower-read reaches ABOVE its known safe
/// watermark, so it can serve the now-confirmed prefix locally and NEVER an unconfirmed offset. Rides
/// the [`FrameType::CommittedHwQuery`] envelope (tag 43) with a leading `kind = 0` byte; the partition
/// is the data-plane envelope's partition prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedHwQueryBody;

impl CommittedHwQueryBody {
    /// Encode this query to its fixed-layout body bytes (just the request `kind` byte).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        vec![HW_KIND_REQUEST]
    }

    /// Decode a query from its body bytes.
    ///
    /// # Errors
    /// Returns [`ReplicationError::Frame`] if `body` is not exactly the request length or its `kind`
    /// byte is not the request discriminant — fail-closed, never guessed at.
    pub fn decode(body: &[u8]) -> Result<CommittedHwQueryBody, ReplicationError> {
        if body.len() != HW_QUERY_REQUEST_LEN || body[0] != HW_KIND_REQUEST {
            return Err(ReplicationError::Frame {
                what: format!("malformed CommittedHwQuery request (len {})", body.len()),
            });
        }
        Ok(CommittedHwQueryBody)
    }
}

/// A leader → follower committed-HW RESPONSE (#739): the leader's CURRENT committed HW for the
/// partition (its read plane's flushed frontier — the SAME committed offset
/// [`DataPlaneController::leader_committed_hw`] answers). The follower raises its servable bound to (at
/// most) this and re-serves the confirmed prefix locally. Rides the [`FrameType::CommittedHwQuery`]
/// envelope (tag 43) with a leading `kind = 1` byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedHwResponseBody {
    /// The leader's current committed high-watermark for the partition.
    pub committed_hw: u64,
}

impl CommittedHwResponseBody {
    /// Encode this response to its fixed-layout little-endian body bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HW_QUERY_RESPONSE_LEN);
        out.push(HW_KIND_RESPONSE);
        out.extend_from_slice(&self.committed_hw.to_le_bytes());
        out
    }

    /// Decode a response from its body bytes.
    ///
    /// # Errors
    /// Returns [`ReplicationError::Frame`] if `body` is not exactly the response length or its `kind`
    /// byte is not the response discriminant.
    pub fn decode(body: &[u8]) -> Result<CommittedHwResponseBody, ReplicationError> {
        if body.len() != HW_QUERY_RESPONSE_LEN || body[0] != HW_KIND_RESPONSE {
            return Err(ReplicationError::Frame {
                what: format!("malformed CommittedHwQuery response (len {})", body.len()),
            });
        }
        let mut hw = [0u8; 8];
        hw.copy_from_slice(&body[1..9]);
        Ok(CommittedHwResponseBody {
            committed_hw: u64::from_le_bytes(hw),
        })
    }
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
        Some(FrameType::CommittedHwQuery) => match body.first().copied() {
            Some(HW_KIND_REQUEST) => Ok(DataPlaneFrame::CommittedHwQuery(
                CommittedHwQueryBody::decode(body)?,
            )),
            Some(HW_KIND_RESPONSE) => Ok(DataPlaneFrame::CommittedHwResponse(
                CommittedHwResponseBody::decode(body)?,
            )),
            _ => Err(DataPlaneError::Replication(ReplicationError::Frame {
                what: "malformed CommittedHwQuery kind byte on a data-plane frame".to_string(),
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
    /// Reply to the querying follower with this committed-HW answer (#739): the leader served a
    /// dirty-tier [`DataPlaneFrame::CommittedHwQuery`] from its current committed HW. The follower uses
    /// it to raise its servable bound (never above it) before re-serving the confirmed prefix locally.
    SendCommittedHwResponse {
        /// The partition the response is for.
        partition: u64,
        /// The leader's current committed-HW answer.
        response: CommittedHwResponseBody,
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
/// The per-partition follower handle (#809): an `Arc<Mutex<EpochAwareFollower>>` the follower fetch
/// thread clones once and applies under, off the node-global server `Mutex`. A poisoned lock is
/// recovered with `into_inner` everywhere (a follower-apply panic must not wedge the whole data plane).
pub(crate) type FollowerHandle<F, C> = Arc<Mutex<EpochAwareFollower<F, C>>>;

/// Lock a follower handle, recovering from a poisoned lock (`into_inner`) so a panic in ONE partition's
/// apply never wedges the whole data plane (#809).
///
/// This is a deliberate scope change from the pre-#809 global lock, which failed CLOSED on a poison (the
/// fetch loop's `let Ok(..) = server.lock() else return` tore down on a poisoned global). Recovering a
/// poisoned PER-PARTITION follower is sound here: `apply_fetch_response` returns a typed `Err` for every
/// EXPECTED fault (corrupt / non-contiguous / storage) — a panic is therefore a latent bug, not
/// adversarial input — and the follower's durable state is never left half-applied in a way a later read
/// could serve as committed: `next_offset` advances only AFTER `Log::append` returns `Ok` (a torn append
/// errors rather than advancing), and follower reads clamp to `follower_safe_watermark(plane.flushed(),
/// known_committed_hw)`, so any torn UNCOMMITTED tail is never served below the committed bar. (If a
/// poison ever needs stricter handling, fail closed by dropping the follower and forcing a clean
/// re-fetch — tracked as a #809 follow-up.)
fn lock_follower<F: Filesystem, C: Clock>(
    handle: &FollowerHandle<F, C>,
) -> std::sync::MutexGuard<'_, EpochAwareFollower<F, C>> {
    handle
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Apply a leader's `FetchResponse` to a follower HANDLE — decode + CRC-revalidate + append + `log.sync()`
/// — under the handle's PER-PARTITION lock (#809), returning the follower's new fsync'd frontier. The
/// follower fetch thread calls this OFF the node-global server `Mutex` (it holds only this handle's lock
/// across the fsync), so partition A's apply no longer blocks partition B's serve/apply.
///
/// # Errors
/// [`DataPlaneError::Replication`] (fail-closed) on a corrupt / tampered / truncated frame — nothing from
/// the bad frame onward is appended.
pub fn apply_on_follower<F: Filesystem, C: Clock>(
    handle: &FollowerHandle<F, C>,
    resp: &FetchResponseBody,
) -> Result<u64, DataPlaneError> {
    let outcome = lock_follower(handle)
        .follower_mut()
        .apply_fetch_response(resp)?;
    Ok(outcome.next_offset)
}

/// Build a follower HANDLE's [`AckReplicatedBody`] report ("I have fsync'd every record below my
/// `next_offset`") under its per-partition lock (#809) — the off-global-lock twin of
/// [`DataPlaneController::follower_report`], called by the follower fetch thread after `apply_on_follower`.
#[must_use]
pub fn report_from_follower<F: Filesystem, C: Clock>(
    handle: &FollowerHandle<F, C>,
    node_id: u64,
) -> AckReplicatedBody {
    AckReplicatedBody {
        follower_id: node_id,
        fsynced_offset: lock_follower(handle).follower().next_fetch_offset().get(),
    }
}

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
        /// The epoch-aware follower over this node's OWN replica log (fetch + apply + reconcile), held
        /// behind a PER-PARTITION `Arc<Mutex>` (#809): the follower fetch thread clones the handle once
        /// and applies (decode + append + fsync) under THIS lock, NOT the node-global server `Mutex`, so
        /// partition A's apply/fsync no longer blocks partition B's serve/apply. The controller's
        /// follower-routing methods lock the same handle; the lock order is always global-server →
        /// follower-handle (the fetch thread holds the follower handle WITHOUT the global lock), so no
        /// deadlock. Promotion builds the leader plane from the locked `&log` without consuming the
        /// `Arc`, so a still-running fetch thread's clone never blocks failover.
        follower: FollowerHandle<F, C>,
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

    /// The leader's `Arc`-shared read plane for `partition`, or `None` if this node is not its leader
    /// (#809). The reader thread clones this under the server lock and then serves the `FetchRecords`
    /// OFF the lock: `ReadPlaneLeader::serve_fetch` is a pure read (`&self`) over the wait-free
    /// [`ReadPlane`] (its own `ArcSwap`/Acquire ordering, independent of the server `Mutex`), so K
    /// followers' fetch-serves to different partitions run in PARALLEL instead of serializing on the one
    /// global lock across each `read_range_raw`.
    #[must_use]
    pub fn leader_read_plane(&self, partition: u64) -> Option<Arc<ReadPlane<F>>> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Leader { plane, .. }) => Some(Arc::clone(plane)),
            _ => None,
        }
    }

    /// The per-partition follower handle for `partition`, or `None` if this node is not its follower
    /// (#809). The follower fetch thread clones this ONCE (under a brief server lock) and then drives
    /// fetch/apply/report on it via [`apply_on_follower`] / [`report_from_follower`] OFF the global server
    /// `Mutex`, so partition A's apply (incl. its `log.sync()` fsync) no longer blocks partition B's
    /// serve/apply. The handle stays valid across a role change: promotion does not consume the `Arc`, so
    /// a still-running fetch thread's clone is harmless (its next `make_fetch_request` reports the role is
    /// gone and it exits).
    #[must_use]
    pub fn follower_handle(&self, partition: u64) -> Option<FollowerHandle<F, C>> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => Some(Arc::clone(follower)),
            _ => None,
        }
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
                // The per-partition parked-ack backlog cap (#864): under an unsatisfiable ISR (a follower
                // down, below `min_isr`) nothing drains, so without a cap a pipelining producer grows the
                // gate's `pending` + the seam's `parked` map without bound — OOM/abort on a bounded-RAM
                // node. At the cap the gate refuses and the produce is failed with an explicit
                // not-enough-replicas error rather than buffered unboundedly.
                gate: QuorumAckGate::with_cap(MAX_PARKED_ACKS_PER_PARTITION),
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
                follower: Arc::new(Mutex::new(EpochAwareFollower::new(Follower::new(log)))),
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

    // ---- C6 reads: leader-lease linearizable local read + the HW-version query the dirty tier needs --

    /// The leader's CURRENT committed high-watermark for `partition` — the read plane's flushed frontier,
    /// the SAME committed offset [`ReadPlaneLeader::high_watermark`] advertises (#654/#715). This is the
    /// answer to a follower's "latest/dirty" HW-VERSION query (#621, [`ReadTier::FollowerLatest`]): a
    /// follower wanting data above its known safe watermark asks the leader for this offset (NOT the
    /// data), then serves the confirmed prefix locally. Leader-only; `None` for a follower / absent
    /// partition (a follower never answers an authoritative committed-HW query).
    #[must_use]
    pub fn leader_committed_hw(&self, partition: u64) -> Option<u64> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Leader { plane, .. }) => Some(plane.flushed()),
            _ => None,
        }
    }

    /// Serve a LEADER-LEASE LINEARIZABLE LOCAL read of `[from, from + max_records)` for `partition` from
    /// the leader's OWN off-actor read plane — a 0-RTT linearizable read with NO quorum round (#620).
    /// Leader-only.
    ///
    /// `lease_valid` is the leaseholder's lease-validity bit at the CURRENT monotonic time and epoch —
    /// exactly [`MetadataRaftGroup::can_act_as_leader`](super::metadata_group::MetadataRaftGroup::can_act_as_leader)
    /// (a held, unexpired lease under the current epoch). The serve path is SOUND by the #694/#722 fence:
    /// if the lease is in doubt the leader REFUSES the local read ([`DataPlaneError::LeaseNotValid`])
    /// rather than risk a stale read — the caller falls back to a read-index/quorum confirm or returns
    /// unavailable. No serving-as-leader on a stale epoch.
    ///
    /// On a valid lease the read is served zero-copy from the leader's read plane via
    /// [`ReadPlane::read_range_raw`] (the SAME machinery the leader serves fetches from), bounded by the
    /// leader's flushed frontier (the linearizable committed prefix), `max_records`, and the optional
    /// `max_bytes`.
    ///
    /// # Errors
    /// [`DataPlaneError::UnknownPartition`] if this node holds no role for `partition`;
    /// [`DataPlaneError::WrongRole`] if it is a follower; [`DataPlaneError::LeaseNotValid`] if the lease
    /// is in doubt (the soundness fence — never a stale local read);
    /// [`DataPlaneError::Replication`] on a serve fault.
    pub fn serve_leader_local_read(
        &self,
        partition: u64,
        lease_valid: bool,
        from: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<RawSealedRead, DataPlaneError> {
        let plane = match self.roles.get(&partition) {
            Some(PartitionRole::Leader { plane, .. }) => plane,
            Some(PartitionRole::Follower { .. }) => {
                return Err(DataPlaneError::WrongRole {
                    partition,
                    needed: "leader",
                })
            }
            None => return Err(DataPlaneError::UnknownPartition { partition }),
        };
        let leader_flushed = plane.flushed();
        // The wanted exclusive end: `from + max_records`, saturated. `usize::MAX` records means "as much
        // as is linearizable", clamped to the flushed frontier by the classifier.
        let wanted_end = Offset::new(from.get().saturating_add(max_records as u64));
        match classify_leader_local_read(lease_valid, from, wanted_end, leader_flushed) {
            // The SOUNDNESS FENCE: an in-doubt lease refuses the local read (never a stale read).
            LeaderReadDecision::Refuse => Err(DataPlaneError::LeaseNotValid { partition }),
            LeaderReadDecision::Nothing => Ok(empty_raw_read(from)),
            LeaderReadDecision::ServeLocal { from, .. } => {
                // The classifier already clamped to the flushed frontier; the read plane re-applies the
                // SAME flushed bound internally (its frontier is the hard exclusive bound), so a record
                // at/past the linearizable prefix is never returned. Zero-copy raw serve.
                plane
                    .read_range_raw(from, max_records, max_bytes)
                    .map_err(|e| DataPlaneError::Replication(ReplicationError::Storage(e)))
            }
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
    /// Returns `Ok(true)` if the ack was parked, or `Ok(false)` if the partition's gate is at its
    /// backlog cap (#864) — an unsatisfiable ISR is withholding the cap's worth of acks and nothing is
    /// draining. On `Ok(false)` the caller MUST NOT treat the produce as parked: it fails the produce
    /// with an explicit not-enough-replicas error rather than buffering the reply unboundedly.
    ///
    /// # Errors
    /// As [`serve_fetch`](Self::serve_fetch) (a produce only lands on a leader partition).
    pub fn park_produce_ack(
        &mut self,
        partition: u64,
        offset: u64,
        token: AckToken,
    ) -> Result<bool, DataPlaneError> {
        match self.roles.get_mut(&partition) {
            Some(PartitionRole::Leader { gate, .. }) => Ok(gate.park(offset, token)),
            Some(PartitionRole::Follower { .. }) => Err(DataPlaneError::WrongRole {
                partition,
                needed: "leader",
            }),
            None => Err(DataPlaneError::UnknownPartition { partition }),
        }
    }

    /// Remove `tokens` from EVERY led partition's quorum-ack gate (#869, #871): a disconnected
    /// producer's still-parked acks are dropped from the gate `pending` so their backlog-cap slots are
    /// freed and they never release. Returns the total removed across all partitions. A token is parked
    /// in exactly one gate, so the cross-partition sweep removes each at most once; an empty `tokens` is
    /// a cheap no-op (the common disconnect, which parked nothing).
    pub fn purge_parked_tokens(&mut self, tokens: &BTreeSet<AckToken>) -> usize {
        if tokens.is_empty() {
            return 0;
        }
        let mut removed = 0;
        for role in self.roles.values_mut() {
            if let PartitionRole::Leader { gate, .. } = role {
                removed += gate.purge_where(|t| tokens.contains(t));
            }
        }
        removed
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
            Some(PartitionRole::Follower { follower }) => Ok(lock_follower(follower)
                .follower()
                .fetch_request(max_records, max_bytes)),
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
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                let outcome = lock_follower(follower)
                    .follower_mut()
                    .apply_fetch_response(resp)?;
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
                fsynced_offset: lock_follower(follower).follower().next_fetch_offset().get(),
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
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                lock_follower(follower).assign_epoch(epoch, start_offset)?;
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
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                Ok(lock_follower(follower)
                    .reconcile_with_leader(committed_hw, leader_end_offset)?)
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
                Some(lock_follower(follower).follower().high_watermark().get())
            }
            _ => None,
        }
    }

    /// Run `f` against the follower's replica [`Log`] for `partition` under the per-partition follower
    /// lock (#809) — e.g. to assert byte-identity against the leader, or to read its frontier. Returns
    /// `Some(f(&log))` for a follower, `None` for a leader / absent partition. (The follower log is now
    /// behind an `Arc<Mutex>`, so it cannot be borrowed out across the lock; a closure scopes the borrow.)
    pub fn with_follower_log<R>(
        &self,
        partition: u64,
        f: impl FnOnce(&Log<F, C>) -> R,
    ) -> Option<R> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                Some(f(lock_follower(follower).follower().log()))
            }
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
            DataPlaneFrame::CommittedHwQuery(_) => {
                // The DIRTY-TIER committed-HW confirm (#739): a follower asks the leader for its current
                // committed HW. Answer it from the leader's read plane (the SAME committed offset
                // `leader_committed_hw` advertises). A query landing on a node that does NOT lead the
                // partition is a wrong-role error the caller drops — only the LEADER is an authoritative
                // committed-HW source, so the follower never trusts a non-leader's answer and falls back
                // to the clean tier. NEVER an over-claimed HW: the leader's flushed frontier is its
                // proven-committed prefix.
                let committed_hw =
                    self.leader_committed_hw(partition)
                        .ok_or(DataPlaneError::WrongRole {
                            partition,
                            needed: "leader",
                        })?;
                Ok(DataPlaneAction::SendCommittedHwResponse {
                    partition,
                    response: CommittedHwResponseBody { committed_hw },
                })
            }
            DataPlaneFrame::CommittedHwResponse(_) => {
                // A committed-HW response is consumed by the in-flight dirty-tier confirm on the
                // requesting (follower) side (a short-lived query link reads it directly), not by the
                // steady-state frame router. A stray one is absorbed.
                Ok(DataPlaneAction::None)
            }
        }
    }
}

// The #618 leaderless-FAILOVER promotion needs `F: Clone` (it builds a [`ReadPlane`] over the
// follower's owned log via [`Log::read_plane`], which clones the filesystem handle behind an `Arc` so
// the plane outlives the log). It is a SEPARATE impl block so the rest of the controller — and the
// no-cluster path — keeps the looser `F: Filesystem` bound; nothing on the single-node path links this.
impl<F: Filesystem + Clone, C: Clock> DataPlaneController<F, C> {
    /// PROMOTE this node from FOLLOWER to LEADER of `partition` on a leaderless-node FAILOVER (#618),
    /// serving the SAME committed log it already holds as a follower — NO data copy. This is the
    /// data-plane half of the failover: the metadata plane committed a
    /// [`PlacePartition`](super::state_machine::MetadataCommand::PlacePartition) naming THIS node the new
    /// leader at a strictly-higher `new_epoch` (the #618
    /// [`reassign_leadership`](super::placement::reassign_leadership)); this applies it locally.
    ///
    /// It takes the follower's OWNED replica [`Log`] out of the role (so its writer is dropped — the
    /// single-writer invariant), builds the leader's read plane over THAT log (the leader serves the
    /// records it already holds, zero byte copy), seeds the leader's epoch cache with the follower's
    /// learned epoch history PLUS the new boundary `(new_epoch, current_frontier)` — the KIP-101 FENCE:
    /// a stale/returning old leader at a lower epoch is rejected — and registers the leader role over
    /// `replica_ids` / `isr_config`.
    ///
    /// `new_epoch` MUST strictly exceed the dead leader's epoch (the failover re-placement guarantees
    /// this via [`reassign_leadership`](super::placement::reassign_leadership)); the epoch-cache `assign`
    /// enforces strict monotonicity and fails closed if it does not.
    ///
    /// ## Apply-time committed-completeness self-verify (defense in depth, #618b)
    ///
    /// `committed_hw_bar` is the SAFE bar carried with the failover (the persisted committed-HW
    /// checkpoint the metadata plane proved this node holds before proposing the promotion). Even though
    /// the proposer already gated on it, this method RE-CHECKS it against THIS node's OWN durable log
    /// before it becomes leader: if its durable frontier does NOT cover the bar it ABORTS the promotion
    /// (fail-closed — the partition stays leaderless; no false leader is created), so even an
    /// optimistic / buggy / hand-built proposal can never make a leader that is missing committed data.
    /// Pass `0` to skip the check (the n=1 / no-bar degenerate, where there is no committed data to lose).
    ///
    /// # Errors
    /// - [`DataPlaneError::WrongRole`] if this node is already the leader (idempotent re-promotion is a
    ///   no-op caller-side; a double-promote is a logic error surfaced here);
    /// - [`DataPlaneError::UnknownPartition`] if this node holds no role for `partition`;
    /// - [`DataPlaneError::FailoverIncomplete`] if this node's durable log does not cover
    ///   `committed_hw_bar` (the apply-time self-verify fails closed — no false leader is created);
    /// - [`DataPlaneError::Replication`] if the read plane cannot be built or the epoch boundary cannot
    ///   be assigned (a backward epoch — fail-closed).
    pub fn promote_follower_to_leader(
        &mut self,
        partition: u64,
        new_epoch: LeaderEpoch,
        replica_ids: &[u64],
        isr_config: IsrConfig,
        committed_hw_bar: u64,
    ) -> Result<(), DataPlaneError> {
        // Take the role out so we can consume the follower (or restore it on a wrong-role error).
        let role = self
            .roles
            .remove(&partition)
            .ok_or(DataPlaneError::UnknownPartition { partition })?;
        let follower = match role {
            PartitionRole::Follower { follower } => follower,
            // Already a leader: not a follower to promote. Put it back and report the wrong role.
            leader @ PartitionRole::Leader { .. } => {
                self.roles.insert(partition, leader);
                return Err(DataPlaneError::WrongRole {
                    partition,
                    needed: "follower",
                });
            }
        };
        // Build the leader's plane + seeded epoch cache from the follower's log UNDER its per-partition
        // lock (#809), WITHOUT consuming the `Arc` — the leader role needs only the read plane (built
        // from `&log`) and the learned epoch history (cloned), never ownership of the log. On a verify
        // failure the follower role is restored unchanged. The `Arc` then drops here; the follower's
        // replica-log writer is released once the last clone (an exiting fetch thread's) drops — the same
        // "serve through the read plane only" outcome as the old `into_log()`+`drop(log)`, only the writer
        // release is deferred to the thread's exit instead of being immediate.
        //
        // SAFETY of the deferred release: only ONE writer ever touches this replica log (the leader's
        // append actor is not yet wired, so nothing else writes it), and the follower lock serializes a
        // racing post-promotion apply against this promotion. Such an apply CAN still advance the leader's
        // served frontier (`plane.flushed()`), but it only appends a byte-identical, CRC-revalidated,
        // CONTIGUOUS continuation of the same authoritative old-leader lineage ABOVE the promotion
        // frontier — adopting more of the uncommitted tail under the new epoch, never overwriting
        // committed data and keeping the epoch fence at `frontier` consistent. When the append actor IS
        // wired to write this log, add an explicit single-writer handoff (wait for the fetch thread to
        // exit / the `Arc` to drop before opening the writer) — tracked as a #809 follow-up.
        let plane_epochs = {
            let guard = lock_follower(&follower);
            let log = guard.follower().log();
            // APPLY-TIME COMMITTED-COMPLETENESS SELF-VERIFY (defense in depth, #618b): the node's OWN
            // durable frontier (`next_offset`) must cover the committed-HW bar, else ABORT fail-closed so
            // no leader missing committed data is ever created. `Err(frontier)` carries the offending value.
            let frontier = log.next_offset();
            if frontier.get() < committed_hw_bar {
                Err(frontier.get())
            } else {
                let plane = Arc::new(
                    log.read_plane()
                        .map_err(|e| DataPlaneError::Replication(ReplicationError::Storage(e)))?,
                );
                // SEED THE FENCE on a CLONE of the learned epoch history (strictly-higher new epoch at the
                // current frontier; `assign` fails closed on a regression). The follower keeps its copy.
                let mut epochs = guard.epochs().clone();
                epochs
                    .assign(new_epoch, frontier)
                    .map_err(|e| DataPlaneError::Replication(ReplicationError::EpochCache(e)))?;
                Ok((plane, epochs))
            }
        };
        let (plane, epochs) = match plane_epochs {
            Ok(pe) => pe,
            Err(durable_frontier) => {
                // Restore the follower role UNCHANGED — we did not consume it; this node keeps following.
                self.roles
                    .insert(partition, PartitionRole::Follower { follower });
                return Err(DataPlaneError::FailoverIncomplete {
                    partition,
                    durable_frontier,
                    committed_hw: committed_hw_bar,
                });
            }
        };
        drop(follower);
        self.start_leader(partition, plane, epochs, replica_ids, isr_config);
        Ok(())
    }

    // ---- C6 FOLLOWER reads (#621/#622): CRAQ committed-local + the dirty-tier leader confirm --------

    /// The SAFE committed watermark a FOLLOWER of `partition` may serve reads up to (#621): `min(its own
    /// read-plane flushed frontier, the KNOWN committed HW)` — the bar BOTH durably-held-here AND
    /// committed-on-a-quorum (see [`crate::cluster::read_consistency::follower_safe_watermark`]). A
    /// follower NEVER serves a record at or past this. Follower-only; `None` for a leader / absent
    /// partition.
    ///
    /// `known_committed_hw` is the last [`CheckpointCommittedHw`](super::state_machine::MetadataCommand::CheckpointCommittedHw)
    /// bar this node has applied from the replicated metadata (#722) — read by the caller from
    /// [`committed_hw`](super::state_machine::MetadataStateMachine::committed_hw); pass `None` when no
    /// checkpoint has committed yet (the safe bar is then 0 — fail closed).
    ///
    /// # Errors
    /// [`DataPlaneError::Replication`] if the follower's read plane cannot be built (an IO fault).
    pub fn follower_safe_read_watermark(
        &self,
        partition: u64,
        known_committed_hw: Option<u64>,
    ) -> Result<Option<u64>, DataPlaneError> {
        match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => {
                // The follower's OWN durably-replicated, CRC-revalidated flushed prefix.
                let own_flushed = lock_follower(follower).follower().read_plane()?.flushed();
                Ok(Some(follower_safe_watermark(
                    own_flushed,
                    known_committed_hw,
                )))
            }
            _ => Ok(None),
        }
    }

    /// Serve a CRAQ-style FOLLOWER read of `[from, from + max_records)` for `partition` at `tier`,
    /// LOCALLY from the follower's OWN off-actor read plane (#621/#622) — zero-copy, no leader data
    /// round-trip. Follower-only.
    ///
    /// `known_committed_hw` is the committed-HW bar this node has applied from the replicated metadata
    /// (#722). The serve is fail-closed by the safe watermark (`min(own_flushed, known_committed_hw)`):
    ///
    /// * [`ReadTier::FollowerCommitted`] (clean): serves the committed prefix `<=` the safe watermark
    ///   locally; a read starting in the uncommitted tail serves an empty run.
    /// * [`ReadTier::FollowerLatest`] (dirty): if the wanted range is already provably committed-and-held
    ///   it serves locally; if it reaches ABOVE the safe watermark it returns
    ///   [`FollowerReadOutcome::ConfirmWithLeader`] (the caller does the HW-version query via
    ///   [`leader_committed_hw`](Self::leader_committed_hw), updates `known_committed_hw`, and re-serves)
    ///   — NEVER speculatively serving unconfirmed bytes.
    /// * [`ReadTier::LeaderLocal`] on a follower escalates to the dirty-tier confirm (never a stale local
    ///   serve).
    ///
    /// The served bytes are the SAME zero-copy [`RawByteRun`] the read plane hands a leader fetch (#542):
    /// arc-swapped sealed-segment byte ranges, no user-space copy. The read plane re-applies its own
    /// flushed bound internally, and the safe-watermark clamp bounds it further to the committed prefix,
    /// so a record at/past the safe watermark is never returned.
    ///
    /// # Errors
    /// [`DataPlaneError::UnknownPartition`] if this node holds no role; [`DataPlaneError::WrongRole`] if
    /// it is a leader; [`DataPlaneError::Replication`] on a serve fault.
    pub fn serve_follower_read(
        &self,
        partition: u64,
        tier: ReadTier,
        known_committed_hw: Option<u64>,
        from: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Result<FollowerReadOutcome, DataPlaneError> {
        let follower = match self.roles.get(&partition) {
            Some(PartitionRole::Follower { follower }) => follower,
            Some(PartitionRole::Leader { .. }) => {
                return Err(DataPlaneError::WrongRole {
                    partition,
                    needed: "follower",
                })
            }
            None => return Err(DataPlaneError::UnknownPartition { partition }),
        };
        // `read_plane()` returns an OWNED plane (built fresh over the follower's `Arc<Filesystem>`), so it
        // outlives the brief per-partition lock taken here (#809).
        let plane = lock_follower(follower).follower().read_plane()?;
        let safe = follower_safe_watermark(plane.flushed(), known_committed_hw);
        let wanted_end = Offset::new(from.get().saturating_add(max_records as u64));
        match classify_follower_read(tier, from, wanted_end, safe) {
            FollowerReadDecision::Nothing => Ok(FollowerReadOutcome::Served(empty_raw_read(from))),
            FollowerReadDecision::ConfirmWithLeader { current_safe } => {
                Ok(FollowerReadOutcome::ConfirmWithLeader { current_safe })
            }
            FollowerReadDecision::ServeLocal { from, serve_up_to } => {
                // The classifier clamped `serve_up_to` to the safe watermark. Bound the read-plane read
                // by `serve_up_to - from` records so it never serves past the committed bar. The read
                // plane ALSO clamps to its own flushed frontier (the hard exclusive bound), so the two
                // bounds together never return a record at/past `min(own_flushed, known_committed_hw)`.
                let safe_records = usize::try_from(serve_up_to.get().saturating_sub(from.get()))
                    .unwrap_or(usize::MAX)
                    .min(max_records);
                if safe_records == 0 {
                    return Ok(FollowerReadOutcome::Served(empty_raw_read(from)));
                }
                let run = plane
                    .read_range_raw(from, safe_records, max_bytes)
                    .map_err(|e| DataPlaneError::Replication(ReplicationError::Storage(e)))?;
                Ok(FollowerReadOutcome::Served(run))
            }
        }
    }
}

/// The outcome of [`DataPlaneController::serve_follower_read`] (#621): either the zero-copy bytes served
/// locally, or a signal that the "latest/dirty" read must CONFIRM the leader's current committed HW
/// before it can serve above the follower's known safe watermark.
#[derive(Debug)]
pub enum FollowerReadOutcome {
    /// The follower served `[from, ...)` LOCALLY from its read plane (committed-and-held bytes,
    /// zero-copy). May be an empty run (nothing safe to serve at this position/tier yet).
    Served(RawSealedRead),
    /// The read reaches ABOVE the follower's known safe watermark: the caller must query the leader's
    /// current committed HW (a tiny HW-version query, [`DataPlaneController::leader_committed_hw`] in the
    /// in-process test, an `OffsetForLeaderEpoch`-style HW frame over the wire in a real serve), update
    /// `known_committed_hw`, and re-serve. NEVER serve unconfirmed bytes speculatively.
    ConfirmWithLeader {
        /// The follower's CURRENT safe watermark (the clean prefix it could serve right now without
        /// confirmation).
        current_safe: Offset,
    },
}

/// An empty zero-copy [`RawSealedRead`] anchored at `from` — what a read serves when nothing is safe to
/// return at this position/tier (the request is empty, the start is past the safe watermark, or a
/// leader-lease read has an exhausted range). Mirrors the read plane's own empty-run shape.
fn empty_raw_read(from: Offset) -> RawSealedRead {
    RawSealedRead {
        run: RawByteRun {
            bytes: bytes::Bytes::new(),
            first_offset: from,
            record_count: 0,
            next_offset: from,
        },
        fallback_from: None,
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
    /// The produce was REFUSED because the partition's parked-ack backlog is at its cap (#864): an
    /// unsatisfiable ISR (below `min_isr`) is already withholding [`MAX_PARKED_ACKS_PER_PARTITION`] acks
    /// and nothing is draining, so parking another would grow memory unboundedly toward OOM. The caller
    /// writes an explicit not-enough-replicas error to the producer (the honest unavailable-over-unsafe
    /// signal it can back off on) — NOT a `PubAck` (the record is durable on the leader but is not
    /// quorum-fsync'd, so it must not be acked) and NOT a silent withhold.
    Rejected,
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
        // Thread a fresh token through the controller's gate at the appended offset FIRST (it is
        // cap-checked), THEN — only on a successful park — store the REAL wire bytes keyed by that token.
        // The leader has ALREADY locally fsync'd (the I2 ack-after-its-own-fsync); the gate adds the
        // quorum-fsync condition. On a FULL backlog (#864) the gate refuses (`Ok(false)`): REJECT this
        // produce so the caller writes an explicit not-enough-replicas error, and store NOTHING — never
        // buffer the reply bytes unboundedly while the ISR is below `min_isr`. The `?` still propagates
        // the (unreachable for a led partition) `WrongRole` / `UnknownPartition` errors unchanged.
        let token = self.next_token;
        if !self.controller.park_produce_ack(partition, offset, token)? {
            return Ok(AckDisposition::Rejected);
        }
        self.next_token = self.next_token.wrapping_add(1);
        self.parked.insert(token, (owner, reply_bytes));
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

    /// Purge every still-PARKED ack owned by `owner` from BOTH the seam's reply side-table AND the
    /// controller's quorum-ack gates (#869, #871). Called when a producer connection disconnects: its
    /// withheld `C2-fsync` acks can never be delivered (no connection is left to write them), so leaving
    /// them parked leaks the reply bytes + the gate's backlog-cap slots an unsatisfiable quorum (a
    /// follower partitioned below `min_isr`) may never drain. Returns the number of parked acks dropped.
    ///
    /// Because the entries are removed from the seam here, a LATER follower report can never release
    /// them — so it can never re-deposit them into the dead owner's outbox either (#871's second leak).
    pub fn purge_owner(&mut self, owner: u64) -> usize {
        let dead: BTreeSet<AckToken> = self
            .parked
            .iter()
            .filter(|(_, (o, _))| *o == owner)
            .map(|(t, _)| *t)
            .collect();
        if dead.is_empty() {
            return 0;
        }
        for t in &dead {
            self.parked.remove(t);
        }
        // Free the gate-cap slots too, so the cap is not permanently consumed by dead-owner entries.
        self.controller.purge_parked_tokens(&dead);
        dead.len()
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
        follower2
            .with_follower_log(P, |log| {
                assert_replicated_byte_identical(log, &leader_log, served_end);
            })
            .unwrap();

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
        follower3
            .with_follower_log(P, |log| {
                assert_replicated_byte_identical(log, &leader_log, served_end);
            })
            .unwrap();
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
        follower
            .with_follower_log(P, |log| {
                assert_replicated_byte_identical(log, &new_leader_log, new_served);
            })
            .unwrap();
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

    // ---- #618b apply-time committed-completeness self-verify (defense in depth) -------------------

    #[test]
    fn promote_aborts_fail_closed_when_the_node_is_behind_the_committed_hw_bar() {
        // Build a follower caught up to a known durable frontier, then attempt to promote it with a
        // committed-HW bar ABOVE that frontier (modeling an optimistic/buggy proposal that names an
        // incomplete node leader). The apply-time self-verify MUST abort fail-closed: it returns
        // FailoverIncomplete, the node STAYS a follower (no false leader is created), and no committed
        // data is exposed under a leader missing it.
        const P: u64 = 0;
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..12u32 {
            leader_log
                .append(&rec(format!("rec-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let plane = leader_plane(&leader_log);
        let served_end = plane_served_end(&plane);
        assert!(
            served_end > 0,
            "the leader serves a non-empty sealed prefix"
        );

        let mut leader = DataPlaneController::<InMemoryFs, ManualClock>::new(1);
        leader.start_leader(P, Arc::clone(&plane), EpochCache::new(), &[1, 2], quorum3());

        let mut follower = DataPlaneController::new(2);
        follower.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        // Catch the follower up to the served prefix.
        for _ in 0..24 {
            if follower.follower_high_watermark(P).unwrap() >= served_end {
                break;
            }
            let req = follower.make_fetch_request(P, 8, 4096).unwrap();
            let resp = leader.serve_fetch(P, &req).unwrap();
            follower.apply_fetch_response(P, &resp).unwrap();
        }
        let durable = follower
            .with_follower_log(P, |log| log.next_offset().get())
            .expect("follower log");
        assert!(durable > 0, "the follower durably holds some records");

        // A bar ABOVE the follower's durable frontier => the self-verify aborts fail-closed.
        let bar_above = durable + 1;
        let err = follower
            .promote_follower_to_leader(P, LeaderEpoch::new(6), &[2], quorum3(), bar_above)
            .expect_err("promotion with a bar above the durable frontier must fail closed");
        match err {
            DataPlaneError::FailoverIncomplete {
                partition,
                durable_frontier,
                committed_hw,
            } => {
                assert_eq!(partition, P);
                assert_eq!(durable_frontier, durable);
                assert_eq!(committed_hw, bar_above);
            }
            other => panic!("expected FailoverIncomplete, got {other:?}"),
        }
        // CRITICAL: the node is STILL a follower (no false leader was created) and is NOT a leader.
        assert!(
            follower.is_follower(P),
            "the aborted promotion left the node a follower (no false leader)"
        );
        assert!(!follower.is_leader(P), "the node did not become leader");

        // A bar AT the follower's durable frontier (it really holds the committed prefix) => the
        // promotion SUCCEEDS — the safe path is not over-zealous.
        follower
            .promote_follower_to_leader(P, LeaderEpoch::new(6), &[2], quorum3(), durable)
            .expect("promotion with a bar the node holds succeeds");
        assert!(
            follower.is_leader(P),
            "a complete node (durable frontier >= bar) is promoted to leader"
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
    fn a_clustered_c2_fsync_produce_is_rejected_when_the_parked_backlog_hits_the_cap() {
        // #864: under an unsatisfiable ISR (a follower down, below `min_isr`) NOTHING drains, so a
        // pipelining producer's parked acks accumulate. The gate caps the per-partition backlog at
        // `MAX_PARKED_ACKS_PER_PARTITION`; past it the produce is REJECTED (an explicit
        // not-enough-replicas signal) instead of buffered unboundedly toward OOM. Lead P over {1,2,3}
        // (min_isr=2) with NO follower reports — the ISR is {leader} < min_isr, so every park stays
        // withheld and the backlog only grows.
        const P: u64 = 0;
        let (mut seam, _followers, _served_end) = led_cluster(P, 1, &[1, 2, 3], quorum3(), 4);
        assert!(seam.controller().is_leader(P));

        // Park exactly the cap's worth of C2-fsync produces: each is withheld (no quorum to release it).
        for off in 0..MAX_PARKED_ACKS_PER_PARTITION as u64 {
            let disposition = seam
                .on_local_fsynced_ack(ClusterAckLevel::C2Fsync, P, off, wire_pub_ack(off))
                .unwrap();
            assert_eq!(
                disposition,
                AckDisposition::Parked,
                "below the cap a clustered C2-fsync produce parks"
            );
        }
        assert_eq!(
            seam.parked_len(),
            MAX_PARKED_ACKS_PER_PARTITION,
            "the backlog filled to exactly the cap"
        );

        // The NEXT produce overflows the cap: REJECTED, not parked, and it buffers NOTHING — so a
        // sustained unsatisfiable-ISR flood is bounded at the cap, never unbounded toward OOM.
        let over = MAX_PARKED_ACKS_PER_PARTITION as u64;
        let disposition = seam
            .on_local_fsynced_ack(ClusterAckLevel::C2Fsync, P, over, wire_pub_ack(over))
            .unwrap();
        assert_eq!(
            disposition,
            AckDisposition::Rejected,
            "past the cap the produce is rejected (not-enough-replicas), never buffered"
        );
        assert_eq!(
            seam.parked_len(),
            MAX_PARKED_ACKS_PER_PARTITION,
            "the rejected produce buffered NOTHING — the backlog stays bounded at the cap"
        );
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
    fn purge_owner_drops_a_disconnected_producers_parked_acks_and_frees_gate_slots() {
        // #869/#871: a producer that parks C2-fsync acks below min_isr (no quorum, never released) then
        // DISCONNECTS must have its parked acks purged from BOTH the seam side-table AND the gate's
        // backlog, so its reply bytes and (#864) cap slots are not leaked until the partition heals. The
        // purge is owner-selective: a still-connected producer's acks survive.
        const P: u64 = 0;
        const M: u64 = 7; // the disconnecting producer
        const N: u64 = 9; // a different, still-connected producer
        let (mut seam, _followers, served_end) = led_cluster(P, 1, &[1, 2, 3], quorum3(), 10);
        assert!(
            served_end >= 4,
            "need at least 4 served offsets for this fixture"
        );

        // Park (below min_isr → all stay parked) in monotone offset order: M owns 0,1,2; N owns 3.
        for (owner, off) in [(M, 0u64), (M, 1), (M, 2), (N, 3)] {
            let d = seam
                .on_local_fsynced_ack_owned(
                    owner,
                    ClusterAckLevel::C2Fsync,
                    P,
                    off,
                    wire_pub_ack(off),
                )
                .unwrap();
            assert_eq!(d, AckDisposition::Parked, "owner {owner} offset {off}");
        }
        assert_eq!(seam.parked_len(), 4);
        assert_eq!(seam.controller().pending_ack_count(P), 4);

        // M disconnects: purge drops its 3 parked acks from the seam AND frees its 3 gate-cap slots.
        assert_eq!(seam.purge_owner(M), 3, "M's three parked acks were dropped");
        assert_eq!(seam.parked_len(), 1, "only N's ack remains in the seam");
        assert_eq!(
            seam.controller().pending_ack_count(P),
            1,
            "M's gate-cap slots were freed too (not just the seam side-table)"
        );

        // Purging an owner that parked nothing is a cheap no-op.
        assert_eq!(seam.purge_owner(12345), 0);
        assert_eq!(seam.parked_len(), 1);
    }

    #[test]
    fn a_quorum_report_after_purge_releases_nothing_for_a_dead_owner() {
        // #871 second leak: once a disconnected owner's acks are purged, a LATER follower report that
        // reaches quorum must release NOTHING for it — so its bytes can never be re-deposited into a
        // dead-owner outbox nobody drains.
        const P: u64 = 0;
        const M: u64 = 7;
        let (mut seam, mut followers, served_end) = led_cluster(P, 1, &[1, 2, 3], quorum3(), 25);
        let offset = served_end - 1;
        let d = seam
            .on_local_fsynced_ack_owned(
                M,
                ClusterAckLevel::C2Fsync,
                P,
                offset,
                wire_pub_ack(offset),
            )
            .unwrap();
        assert_eq!(d, AckDisposition::Parked);
        assert_eq!(seam.parked_len(), 1);

        // M disconnects BEFORE quorum catches up.
        assert_eq!(seam.purge_owner(M), 1);
        assert_eq!(seam.parked_len(), 0);

        // Drive the 2nd replica to quorum-fsync past `offset`. With M's ack purged, the report releases
        // nothing — so nothing is ever re-deposited for the dead owner.
        let mut released: Vec<Vec<u8>> = Vec::new();
        for _ in 0..40 {
            if seam.controller().is_leader(P) {
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
                released.extend(seam.on_follower_report(P, &report).unwrap());
            }
            if followers[0].follower_high_watermark(P).unwrap() >= served_end {
                break;
            }
        }
        assert!(
            released.is_empty(),
            "a purged owner's ack is never released, so it is never re-deposited"
        );
        assert_eq!(seam.parked_len(), 0);
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

    // ---- C6 reads (#620/#621/#622): leader-lease local + CRAQ follower committed reads -------------

    use super::{FollowerReadOutcome, ReadTier};

    /// Decode a zero-copy raw run into `(offset, payload)` pairs the way a consumer that received the
    /// run would — full `codec::decode` (header + body CRC), so a served run is integrity-checkable
    /// end-to-end (the C6 zero-copy delivery, #622, reuses the read-plane raw run verbatim).
    fn decode_run(run: &ironbus_storage::segment::RawByteRun) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        let mut offset = run.first_offset.get();
        while cursor < run.bytes.len() {
            let (view, consumed) = ironbus_core::codec::decode(&run.bytes[cursor..])
                .expect("every shipped C6 follower-read frame passes header AND body CRC");
            out.push((offset, view.payload.to_vec()));
            offset += 1;
            cursor += consumed;
        }
        assert_eq!(out.len() as u64, run.record_count);
        out
    }

    /// Catch `follower` up to the leader's read-plane-served prefix over the in-process fetch path, then
    /// return that served end (the offset the follower durably holds up to).
    fn catch_follower_up(
        leader: &mut DataPlaneController<InMemoryFs, ManualClock>,
        follower: &mut DataPlaneController<InMemoryFs, ManualClock>,
        partition: u64,
        served_end: u64,
        rounds: u64,
    ) {
        for _ in 0..rounds {
            if follower.follower_high_watermark(partition).unwrap() >= served_end {
                break;
            }
            let req = follower.make_fetch_request(partition, 8, 4096).unwrap();
            let resp = leader.serve_fetch(partition, &req).unwrap();
            follower.apply_fetch_response(partition, &resp).unwrap();
        }
    }

    /// THE C6 follower-read SAFETY test (#621 non-negotiable 1): a follower whose FLUSHED prefix is
    /// BEYOND the known committed HW serves only `<= committed HW`, NEVER the uncommitted tail. The
    /// follower replicates a leader's whole sealed prefix (its own flushed frontier is the served end),
    /// but we hand it a committed-HW bar STRICTLY BELOW that — the safe watermark is the bar, and the
    /// clean read serves nothing past it.
    #[test]
    #[allow(clippy::too_many_lines)] // one coherent safety scenario (replicate, set a low bar, chain-read)
    fn a_follower_serves_only_up_to_the_committed_hw_never_the_uncommitted_tail() {
        const P: u64 = 0;
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..30u32 {
            leader_log
                .append(&rec(format!("c6-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let plane = leader_plane(&leader_log);
        let served_end = plane_served_end(&plane);
        assert!(
            served_end >= 10,
            "need a healthy sealed prefix (got {served_end})"
        );

        let mut leader = DataPlaneController::new(1);
        leader.start_leader(P, Arc::clone(&plane), EpochCache::new(), &[1, 2], quorum3());
        let mut follower = DataPlaneController::new(2);
        follower.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        catch_follower_up(&mut leader, &mut follower, P, served_end, served_end + 8);
        let own_flushed = follower.follower_high_watermark(P).unwrap();
        assert!(
            own_flushed >= served_end,
            "the follower durably holds the served prefix (own_flushed={own_flushed})"
        );

        // The committed HW is STRICTLY BELOW the follower's flushed prefix: [committed_hw, own_flushed)
        // is an uncommitted (still epoch-truncatable) tail the follower happens to hold.
        let committed_hw = served_end / 2;
        assert!(committed_hw > 0 && committed_hw < own_flushed);

        // The SAFE watermark is the committed HW (the MIN), so a CLEAN read for everything serves only
        // [0, committed_hw) — never a record at/past committed_hw.
        assert_eq!(
            follower
                .follower_safe_read_watermark(P, Some(committed_hw))
                .unwrap(),
            Some(committed_hw),
        );
        // CHAIN clean reads across the whole prefix (the read plane serves one sealed segment per raw
        // read). EVERY served record must be strictly BELOW the committed HW — never the uncommitted tail
        // [committed_hw, own_flushed). The chain must serve SOMETHING (not vacuously empty) and stop
        // exactly at the bar, never crossing it.
        let mut from = Offset::ZERO;
        let mut served_any = false;
        let mut guard = 0u32;
        loop {
            guard += 1;
            assert!(guard < 10_000, "follower-read chain failed to terminate");
            let outcome = follower
                .serve_follower_read(
                    P,
                    ReadTier::FollowerCommitted,
                    Some(committed_hw),
                    from,
                    usize::MAX,
                    None,
                )
                .unwrap();
            let run = match outcome {
                FollowerReadOutcome::Served(r) => r,
                FollowerReadOutcome::ConfirmWithLeader { .. } => {
                    panic!("expected a local serve, not a confirm")
                }
            };
            let records = decode_run(&run.run);
            for (off, _payload) in &records {
                assert!(
                    *off < committed_hw,
                    "served offset {off} at/past the committed HW {committed_hw} (the uncommitted tail!)"
                );
            }
            if records.is_empty() {
                break;
            }
            served_any = true;
            let next = run.run.next_offset.get();
            assert!(
                next <= committed_hw,
                "the served run crossed the committed HW (next={next} > {committed_hw})"
            );
            if next <= from.get() {
                break;
            }
            from = Offset::new(next);
        }
        assert!(
            served_any,
            "the follower served the committed prefix locally (not vacuously empty)"
        );
        // The clean chain stopped exactly at the committed bar: a read STARTING at the bar serves nothing.
        let at_bar = follower
            .serve_follower_read(
                P,
                ReadTier::FollowerCommitted,
                Some(committed_hw),
                Offset::new(committed_hw),
                usize::MAX,
                None,
            )
            .unwrap();
        match at_bar {
            FollowerReadOutcome::Served(r) => {
                assert_eq!(
                    r.run.record_count, 0,
                    "a clean read at the committed bar serves nothing"
                );
            }
            FollowerReadOutcome::ConfirmWithLeader { .. } => {
                panic!("a clean read at the committed bar serves an empty run, not a confirm")
            }
        }
    }

    /// THE C6 follower-read CORRECTNESS test (#621/#622): a follower serves COMMITTED records LOCALLY,
    /// BYTE-IDENTICAL to the leader's, with NO leader round-trip — the CRAQ clean tier + zero-copy
    /// delivery. The committed HW covers the whole served prefix here (the steady state once a checkpoint
    /// caught up), so the clean read serves the full committed prefix from the follower's own read plane.
    #[test]
    fn a_follower_serves_committed_records_locally_byte_identical_to_the_leader() {
        const P: u64 = 0;
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..30u32 {
            leader_log
                .append(&rec(format!("c6-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let plane = leader_plane(&leader_log);
        let served_end = plane_served_end(&plane);

        let mut leader = DataPlaneController::new(1);
        leader.start_leader(P, Arc::clone(&plane), EpochCache::new(), &[1, 2], quorum3());
        let mut follower = DataPlaneController::new(2);
        follower.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        catch_follower_up(&mut leader, &mut follower, P, served_end, served_end + 8);

        // The committed HW covers the whole served prefix (a checkpoint has caught up). CHAIN the clean
        // read across the whole committed prefix off the FOLLOWER's own read plane (one sealed segment
        // per raw read), collecting (offset, payload).
        let collect_committed =
            |c: &DataPlaneController<InMemoryFs, ManualClock>| -> Vec<(u64, Vec<u8>)> {
                let mut out = Vec::new();
                let mut from = Offset::ZERO;
                let mut guard = 0u32;
                loop {
                    guard += 1;
                    assert!(guard < 10_000, "chain failed to terminate");
                    let outcome = c
                        .serve_follower_read(
                            P,
                            ReadTier::FollowerCommitted,
                            Some(served_end),
                            from,
                            usize::MAX,
                            None,
                        )
                        .unwrap();
                    let run = match outcome {
                        FollowerReadOutcome::Served(r) => r,
                        FollowerReadOutcome::ConfirmWithLeader { .. } => {
                            panic!("expected a local serve, not a confirm")
                        }
                    };
                    let recs = decode_run(&run.run);
                    if recs.is_empty() {
                        break;
                    }
                    let next = run.run.next_offset.get();
                    out.extend(recs);
                    if next <= from.get() {
                        break;
                    }
                    from = Offset::new(next);
                }
                out
            };
        let follower_records = collect_committed(&follower);
        assert!(
            !follower_records.is_empty(),
            "the follower served committed records locally"
        );

        // BYTE-IDENTICAL to the leader: chain the LEADER's read plane over the same prefix and compare
        // every (offset, payload). The follower's bytes are its OWN replica's page cache (zero-copy), and
        // they decode to the same records as the leader's — real CRAQ committed reads off a replica.
        let mut leader_records: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut from = Offset::ZERO;
        while from.get() < served_end {
            let leader_run = plane
                .read_range_raw(from, usize::MAX, None)
                .expect("leader read plane serves");
            let recs = decode_run(&leader_run.run);
            if recs.is_empty() {
                break;
            }
            let next = leader_run.run.next_offset.get();
            leader_records.extend(recs);
            if next <= from.get() {
                break;
            }
            from = Offset::new(next);
        }
        // The follower serves its OWN SEALED page-cache prefix, which is a byte-identical PREFIX of the
        // leader's committed prefix (the follower's last replicated segment may not have sealed yet — its
        // read plane, like the leader's, serves only the sealed prefix). So the follower's served records
        // are byte-identical to the leader's at the same offsets, and the follower covers a non-trivial
        // chunk (real committed reads off the replica), but it need not cover the leader's still-active
        // tail (FLAGGED, the same active-tail lag the leader-fetch path has).
        assert!(
            follower_records.len() <= leader_records.len(),
            "the follower never serves MORE than the leader's committed prefix"
        );
        assert!(
            follower_records.len() * 2 >= leader_records.len(),
            "the follower served a healthy committed prefix off its own read plane (got {}, leader {})",
            follower_records.len(),
            leader_records.len()
        );
        for (f, l) in follower_records.iter().zip(leader_records.iter()) {
            assert_eq!(f.0, l.0, "offset mismatch leader vs follower");
            assert_eq!(
                f.1, l.1,
                "payload byte mismatch leader vs follower at offset {}",
                f.0
            );
        }
    }

    /// THE C6 dirty-tier test (#621): a "latest" read ABOVE the follower's known safe watermark CONFIRMS
    /// the leader's current committed HW (a HW-version query) before serving — never speculatively
    /// serving unconfirmed bytes — and after the confirm it serves the now-confirmed prefix locally.
    #[test]
    fn a_latest_follower_read_above_the_safe_watermark_confirms_with_the_leader_then_serves() {
        const P: u64 = 0;
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..30u32 {
            leader_log
                .append(&rec(format!("c6-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let plane = leader_plane(&leader_log);
        let served_end = plane_served_end(&plane);

        let mut leader = DataPlaneController::new(1);
        leader.start_leader(P, Arc::clone(&plane), EpochCache::new(), &[1, 2], quorum3());
        let mut follower = DataPlaneController::new(2);
        follower.start_follower(P, open_log(InMemoryFs::new(), small_config()));
        catch_follower_up(&mut leader, &mut follower, P, served_end, served_end + 8);

        // The follower KNOWS only a low committed HW (a stale checkpoint). A "latest" read STARTING AT
        // that known-safe bar has nothing committed to serve from there with current knowledge, so it
        // must CONFIRM the leader's current HW first — never speculatively serving the unconfirmed tail.
        let stale_known = served_end / 3;
        assert!(stale_known > 0 && stale_known < served_end);
        let outcome = follower
            .serve_follower_read(
                P,
                ReadTier::FollowerLatest,
                Some(stale_known),
                Offset::new(stale_known),
                usize::MAX,
                None,
            )
            .unwrap();
        let current_safe = match outcome {
            FollowerReadOutcome::ConfirmWithLeader { current_safe } => current_safe,
            FollowerReadOutcome::Served(_) => {
                panic!("a latest read at/above the known bar must confirm, not serve")
            }
        };
        assert_eq!(
            current_safe.get(),
            stale_known,
            "the clean prefix is the known-safe bar"
        );

        // The caller does the tiny HW-VERSION query to the leader (NOT the data) — the leader's current
        // committed HW. The follower updates its known HW and re-serves: now the previously-unconfirmed
        // prefix is confirmed-committed, so it serves locally.
        let leader_hw = leader
            .leader_committed_hw(P)
            .expect("leader answers the HW query");
        assert!(
            leader_hw >= served_end,
            "the leader's committed HW covers the served prefix"
        );
        let reserved = follower
            .serve_follower_read(
                P,
                ReadTier::FollowerLatest,
                Some(leader_hw),
                Offset::new(stale_known),
                usize::MAX,
                None,
            )
            .unwrap();
        let run = match reserved {
            FollowerReadOutcome::Served(r) => r,
            FollowerReadOutcome::ConfirmWithLeader { .. } => {
                panic!("after the confirm the follower serves locally, not another confirm")
            }
        };
        assert!(
            run.run.record_count > 0,
            "the confirmed prefix is served locally after the HW confirm"
        );
        // Every served record is at/above where we resumed and strictly below the confirmed HW.
        for (off, _) in decode_run(&run.run) {
            assert!(off >= stale_known && off < leader_hw);
        }
    }

    /// THE #739 wire-routing test: a [`DataPlaneFrame::CommittedHwQuery`] routed through the LEADER's
    /// `handle_frame` is answered with a [`DataPlaneAction::SendCommittedHwResponse`] carrying the leader's
    /// current committed HW; the SAME query routed through a FOLLOWER is a wrong-role error (a follower is
    /// never an authoritative committed-HW source, so the follower never trusts a non-leader's answer).
    #[test]
    fn committed_hw_query_is_answered_by_the_leader_and_rejected_by_a_follower() {
        use super::{CommittedHwQueryBody, DataPlaneAction, DataPlaneFrame};
        const P: u64 = 0;
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..20u32 {
            leader_log
                .append(&rec(format!("hw-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let plane = leader_plane(&leader_log);
        let mut leader = DataPlaneController::<InMemoryFs, ManualClock>::new(1);
        leader.start_leader(P, Arc::clone(&plane), EpochCache::new(), &[1, 2], quorum3());
        let mut follower = DataPlaneController::new(2);
        follower.start_follower(P, open_log(InMemoryFs::new(), small_config()));

        // The leader answers the HW query from its current committed HW (its read plane's flushed frontier).
        let action = leader
            .handle_frame(P, DataPlaneFrame::CommittedHwQuery(CommittedHwQueryBody))
            .expect("the leader answers a committed-HW query");
        match action {
            DataPlaneAction::SendCommittedHwResponse {
                partition,
                response,
            } => {
                assert_eq!(partition, P);
                assert_eq!(
                    response.committed_hw,
                    leader.leader_committed_hw(P).unwrap(),
                    "the answer is the leader's current committed HW"
                );
            }
            other => panic!("expected a committed-HW response, got {other:?}"),
        }
        // A query routed to a FOLLOWER is a wrong-role error (only the leader answers authoritatively).
        assert!(matches!(
            follower.handle_frame(P, DataPlaneFrame::CommittedHwQuery(CommittedHwQueryBody)),
            Err(DataPlaneError::WrongRole {
                needed: "leader",
                ..
            })
        ));
        // A query for a partition no role is held for is an unknown-partition error.
        assert!(matches!(
            leader.handle_frame(99, DataPlaneFrame::CommittedHwQuery(CommittedHwQueryBody)),
            Err(DataPlaneError::WrongRole { .. } | DataPlaneError::UnknownPartition { .. })
        ));
    }

    /// The #739 committed-HW body codec round-trips and is fail-closed on a bad kind byte / length.
    #[test]
    fn committed_hw_bodies_round_trip_and_reject_malformed() {
        use super::{CommittedHwQueryBody, CommittedHwResponseBody};
        let q = CommittedHwQueryBody;
        assert_eq!(CommittedHwQueryBody::decode(&q.encode()).unwrap(), q);
        let r = CommittedHwResponseBody {
            committed_hw: 1_234_567,
        };
        assert_eq!(CommittedHwResponseBody::decode(&r.encode()).unwrap(), r);
        // A response decoded as a query (wrong kind byte) is rejected, and vice-versa.
        assert!(CommittedHwQueryBody::decode(&r.encode()).is_err());
        assert!(CommittedHwResponseBody::decode(&q.encode()).is_err());
        // A truncated / empty body is rejected.
        assert!(CommittedHwQueryBody::decode(&[]).is_err());
        assert!(CommittedHwResponseBody::decode(&[1, 2, 3]).is_err());
    }

    /// A follower is NOT an authoritative committed-HW source: `leader_committed_hw` returns `None` on a
    /// follower (only the leader answers the dirty-tier HW-version query), and `serve_leader_local_read`
    /// / `serve_follower_read` reject the wrong role.
    #[test]
    fn role_gating_for_the_c6_read_apis() {
        const P: u64 = 0;
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..10u32 {
            leader_log
                .append(&rec(format!("g-{i}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let plane = leader_plane(&leader_log);
        let mut leader = DataPlaneController::<InMemoryFs, ManualClock>::new(1);
        leader.start_leader(P, Arc::clone(&plane), EpochCache::new(), &[1, 2], quorum3());
        let mut follower = DataPlaneController::new(2);
        follower.start_follower(P, open_log(InMemoryFs::new(), small_config()));

        // A follower never answers an authoritative committed-HW query.
        assert_eq!(follower.leader_committed_hw(P), None);
        assert!(leader.leader_committed_hw(P).is_some());
        // A follower-read on a LEADER is a wrong-role error.
        assert!(matches!(
            leader.serve_follower_read(
                P,
                ReadTier::FollowerCommitted,
                Some(5),
                Offset::ZERO,
                8,
                None
            ),
            Err(DataPlaneError::WrongRole {
                needed: "follower",
                ..
            })
        ));
        // A leader-local read on a FOLLOWER is a wrong-role error.
        assert!(matches!(
            follower.serve_leader_local_read(P, true, Offset::ZERO, 8, None),
            Err(DataPlaneError::WrongRole {
                needed: "leader",
                ..
            })
        ));
        // An unknown partition is a typed error on both.
        assert!(matches!(
            leader.serve_leader_local_read(99, true, Offset::ZERO, 8, None),
            Err(DataPlaneError::UnknownPartition { partition: 99 })
        ));
    }

    /// THE C6 leader-lease LOCAL-read test (#620): a VALID leaseholder serves a 0-RTT linearizable read
    /// LOCALLY from its own read plane; an EXPIRED/INVALID lease does NOT serve a stale local read — it
    /// REFUSES fail-closed (the #694/#722 soundness fence).
    #[test]
    fn a_valid_leaseholder_serves_a_local_linearizable_read_an_invalid_lease_refuses() {
        const P: u64 = 0;
        let mut leader_log = open_log(InMemoryFs::new(), small_config());
        for i in 0..20u32 {
            leader_log
                .append(&rec(format!("ll-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let plane = leader_plane(&leader_log);
        let served_end = plane_served_end(&plane);
        assert!(served_end > 0);
        let mut leader = DataPlaneController::<InMemoryFs, ManualClock>::new(1);
        leader.start_leader(P, Arc::clone(&plane), EpochCache::new(), &[1], {
            IsrConfig {
                min_isr: 1,
                max_lag_records: 0,
            }
        });

        // VALID lease: serve a linearizable read LOCALLY from the leader's own read plane (no quorum
        // round). The served bytes decode to the leader's committed records, byte-identical.
        let outcome = leader
            .serve_leader_local_read(P, true, Offset::ZERO, usize::MAX, None)
            .expect("a valid leaseholder serves locally");
        let local = decode_run(&outcome.run);
        assert!(
            !local.is_empty(),
            "the leaseholder served records locally with no quorum round"
        );
        let plane_run = plane
            .read_range_raw(Offset::ZERO, usize::MAX, None)
            .unwrap();
        let plane_records = decode_run(&plane_run.run);
        for (a, b) in local.iter().zip(plane_records.iter()) {
            assert_eq!(
                a, b,
                "the local linearizable read is byte-identical to the leader's read plane"
            );
        }

        // INVALID lease (in doubt — expired / stale epoch): REFUSE, never a stale local read.
        let refused = leader.serve_leader_local_read(P, false, Offset::ZERO, usize::MAX, None);
        assert!(
            matches!(refused, Err(DataPlaneError::LeaseNotValid { partition: P })),
            "an in-doubt lease refuses the local read (the #694/#722 soundness fence), got {refused:?}"
        );
    }
}
