// SPDX-License-Identifier: MIT OR Apache-2.0
//! Live data-plane SERVE wiring: run the proven data-plane layers over real connections (V2-C2-I7,
//! #713 — the clustering capstone).
//!
//! Every data-plane LAYER is built + proven IN-PROCESS — per-partition leader-serve + follower-fetch
//! ([`replication`](super::replication), #686), the ISR + quorum-fsync-ack gate
//! ([`isr`](super::isr), #691), leader-epoch truncation on divergence (#694), the
//! [`DataPlaneController`](super::dataplane::DataPlaneController) + [`ProduceAckSeam`] that drive them
//! (#703/#712), and the committed [`Placement`](super::state_machine::Placement) that decides which
//! node leads / holds each partition (#701). The C1 peer transport
//! ([`transport`](super::transport)) + [`ClusterRuntime`](super::runtime) already start the
//! METADATA-plane listener/dialer/driver over real `TcpStream`s (#683). What was missing — and what
//! this module ships — is the piece that carries the DATA frames over real connections and RUNS the
//! controller per the committed placement, so a serving multi-node cluster actually replicates
//! produced data + quorum-gates `C2-fsync` produces over the wire.
//!
//! ## What this module wires
//!
//! 1. **The data-plane peer transport** ([`DataPlaneLink`]). The C1 [`PeerLink`](super::transport)
//!    carries the metadata Raft messages; this is its DATA-plane twin: it frames each
//!    [`DataPlaneFrame`] (the replication-fetch verbs + the ISR report) PREFIXED with the partition id
//!    it routes to, over the SAME bounded `[len][type][body]` envelope, and reads them back through the
//!    SAME bounded, fail-closed decoders the layer crates ship (a follower never trusts a leader's
//!    bytes; the leader authenticates a follower's report against the partition replica set). Built
//!    around the same rule as the C1 transport: **treat every incoming byte as adversarial** — the
//!    frame size is capped before allocation ([`MAX_DATAPLANE_FRAME_BYTES`]) and every body is decoded
//!    by the bounded codec, so a hostile peer is contained to a dropped frame.
//! 2. **The data-plane SERVER** ([`DataPlaneServer`]). A per-node runnable that holds the
//!    [`ProduceAckSeam`] (which owns the [`DataPlaneController`] + every local partition role), binds a
//!    data-plane peer listener, dials its peers, and runs the per-role loops: a LEADER serves inbound
//!    `FetchRecords` / `OffsetForLeaderEpoch` and records inbound `AckReplicated` reports (driving the
//!    quorum-ack gate); a FOLLOWER pulls the leader's CRC-revalidated bytes on a fetch loop, applies
//!    them to its own replica log, and reports its fsync'd offset back.
//! 3. **Construction from the committed placement** ([`DataPlaneServer::from_placements`]). Per local
//!    partition, [`role_for_placement`](super::dataplane::role_for_placement) decides the role and the
//!    server registers it: the LEADER role serves from a borrowed leader log; the FOLLOWER role owns a
//!    freshly-opened / recovered replica log under the data dir. A restart re-derives every role from
//!    the same committed placement + the durable replica log, so the role + replication resume.
//!
//! ## Single-node / no-cluster = byte-identical (the critical guarantee)
//!
//! This server is constructed ONLY on a clustered serve (a [`ClusterConfig`](super::ClusterConfig)
//! present). With no cluster config NOTHING here is constructed: no [`DataPlaneServer`], no listener,
//! no role, no data-plane frame ever decoded — and (the load-bearing half) the broker's produce path
//! is untouched, so the produce/consume hot path + the immediate local-fsync (I2) ack are byte-for-byte
//! today's broker. The construction is gated in the CLI serve hook on the SAME `Option<ClusterConfig>`
//! the metadata runtime is gated on; with `None` the server is never built.
//!
//! ## SCOPE — the coherent slice this module ships, and what is FLAGGED
//!
//! SHIPPED (the live, runnable static-placement data plane):
//! * the data-plane peer transport carrying the data frames over real `TcpStream`s;
//! * the [`DataPlaneServer`] constructed from the committed placement, running per-partition
//!   leader-serve / follower-fetch over the live transport;
//! * a 3-node serve cluster (over real loopback sockets) where a produce to the leader REPLICATES
//!   byte-identical to its followers, a `C2-fsync` produce's wire `PubAck` is released ONLY after
//!   quorum-fsync (not leader-only), below `min_isr` the ack stays parked (no false ack), a lagging
//!   follower catches up, and a restarted node re-establishes its role + resumes replication.
//!
//! FLAGGED / DEFERRED (precise — each its own follow-up, none landed here):
//! * **The live produce-ack `session::drain_parked` hot-path wiring.** The [`ProduceAckSeam`] (#712)
//!   is driven END-TO-END here: a parked wire-`PubAck` is released ONLY once the ISR follower reports
//!   over the REAL wire bring quorum-fsync (proven by [`tests`]). What is NOT landed is threading that
//!   seam into the BROKER's `engine.rs` / `session.rs` produce path so a real client produce on a led
//!   partition parks its connection's wire `PubAck`. That requires two ownership changes the data
//!   plane cannot make from the side: (a) the [`DataPlaneController`] LEADER role needs `&Log<F, C>`,
//!   but the engine owns its partition log PRIVATELY behind the append actor (no borrow path, no
//!   `Arc`); and (b) a session reaches the engine only through the per-call `EngineAccess` trait
//!   object — there is no broker-wide shared state a session could consult the seam through. Wiring
//!   that is a focused engine/actor change (expose the leader log + hold the seam in shared broker
//!   state so `drain_parked` consults it), NOT a logic change — the seam, the gate, and the release
//!   path are all proven here.
//! * **Cooperative REBALANCE on a placement change** is C5-I2 (this slice is STATIC placement: roles
//!   are derived from the committed placement at start + re-derived on a restart; a live leader
//!   hand-off / replica move is later).
//! * **Leaderless FAILOVER** (a new leader election on a leader loss) is C5-I3.
//! * **Follower READS** (serving consume traffic from a follower replica) are C6.
//! * **Multi-partition fan-out optimization** (one shared fetch loop across many partitions) +
//!   **snapshot / compaction** (#660) + the **geo** plane (C7) are separate.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use ironbus_core::clock::Clock;
use ironbus_core::epoch_cache::EpochCache;
use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType, MAX_FRAME_LEN,
};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Log;

use super::dataplane::{
    decode_dataplane_frame, role_for_placement, DataPlaneAction, DataPlaneController,
    DataPlaneError, DataPlaneFrame, PlacementRole, ProduceAckSeam,
};
use super::isr::IsrConfig;
use super::state_machine::Placement;

/// The hard maximum size, in bytes, of a single inbound DATA-plane peer frame (the partition prefix
/// plus the encoded [`DataPlaneFrame`] body). Checked against the frame's length prefix BEFORE the
/// body is read or decoded, so an oversized frame is rejected without allocating or parsing — the
/// SIZE half of the same fail-closed discipline the C1 transport applies to Raft messages.
///
/// A data-plane fetch RESPONSE is the largest legitimate frame and is itself already bounded by
/// [`MAX_REPL_FETCH_BYTES`](super::replication::MAX_REPL_FETCH_BYTES) (8 MiB); this cap sits above
/// that (plus the small partition prefix + verb headers) and below the absolute envelope
/// [`MAX_FRAME_LEN`], so every valid frame fits and a larger one is treated as hostile and dropped.
pub const MAX_DATAPLANE_FRAME_BYTES: u32 = 12 * 1024 * 1024;

/// The fixed little-endian width of the partition-id prefix that precedes every data-plane frame body
/// on the wire, so one peer link can multiplex the data frames of every partition this node holds.
const PARTITION_PREFIX_LEN: usize = 8;

/// A typed error from the data-plane peer wire: every failure mode of framing / decoding an untrusted
/// data-plane frame. Like [`PeerWireError`](super::transport::PeerWireError) the transport ALWAYS
/// surfaces one of these rather than panicking or over-allocating, so a hostile peer is contained to a
/// dropped frame (or, at the caller's discretion, a dropped connection).
#[derive(Debug)]
pub enum DataPlaneWireError {
    /// The frame's length prefix exceeded the hard size cap ([`MAX_DATAPLANE_FRAME_BYTES`]) — rejected
    /// before the body was read or decoded (the SIZE bound).
    Oversized {
        /// The frame length the peer claimed.
        len: u64,
    },
    /// The frame envelope itself was malformed (empty / zero-length).
    Frame(FrameError),
    /// The frame body was shorter than the mandatory partition-id prefix — a truncated/garbage frame.
    MissingPartitionPrefix,
    /// The frame body did not decode to a valid [`DataPlaneFrame`] under the bounded layer codecs (a
    /// corrupt / truncated / mistyped data verb). Fail-closed: the frame is dropped.
    Decode(DataPlaneError),
    /// An underlying IO error reading from / writing to the peer connection.
    Io(io::Error),
}

impl core::fmt::Display for DataPlaneWireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DataPlaneWireError::Oversized { len } => write!(
                f,
                "data-plane frame length {len} exceeds the {MAX_DATAPLANE_FRAME_BYTES}-byte cap; rejected pre-decode"
            ),
            DataPlaneWireError::Frame(e) => write!(f, "data-plane frame envelope error: {e}"),
            DataPlaneWireError::MissingPartitionPrefix => {
                write!(f, "data-plane frame body is shorter than the partition-id prefix")
            }
            DataPlaneWireError::Decode(e) => write!(f, "data-plane frame decode error: {e}"),
            DataPlaneWireError::Io(e) => write!(f, "data-plane link IO error: {e}"),
        }
    }
}

impl std::error::Error for DataPlaneWireError {}

impl From<io::Error> for DataPlaneWireError {
    fn from(e: io::Error) -> Self {
        DataPlaneWireError::Io(e)
    }
}

/// The wire type tag carried in the `[len][type][body]` envelope for the inner data-plane frame.
/// The data-plane frames reuse the layer crates' own [`FrameType`]s ([`FrameType::FetchRecords`] /
/// `FetchResponse` / `AckReplicated` / `OffsetForLeaderEpoch`), so the outer envelope's type tag IS
/// the inner frame's type tag; the body is `[partition: u64-le][encoded layer body]`.
fn frame_type_for(frame: &DataPlaneFrame) -> FrameType {
    match frame {
        DataPlaneFrame::FetchRequest(_) => FrameType::FetchRecords,
        DataPlaneFrame::FetchResponse(_) => FrameType::FetchResponse,
        DataPlaneFrame::AckReplicated(_) => FrameType::AckReplicated,
        DataPlaneFrame::EpochQuery(_) | DataPlaneFrame::EpochResponse(_) => {
            FrameType::OffsetForLeaderEpoch
        }
    }
}

/// The encoded layer body for one data-plane frame (NOT including the partition prefix or the
/// `[len][type]` envelope) — exactly the bytes [`decode_dataplane_frame`] expects after the envelope.
fn encode_dataplane_body(frame: &DataPlaneFrame) -> Vec<u8> {
    match frame {
        DataPlaneFrame::FetchRequest(b) => b.encode(),
        DataPlaneFrame::FetchResponse(b) => b.encode(),
        DataPlaneFrame::AckReplicated(b) => b.encode(),
        DataPlaneFrame::EpochQuery(b) => b.encode(),
        DataPlaneFrame::EpochResponse(b) => b.encode(),
    }
}

/// Encode one `(partition, frame)` to its on-wire bytes: the `[len][type][partition-le][layer body]`
/// envelope, bounded the same way the decoder bounds an incoming one.
///
/// # Errors
/// Returns [`DataPlaneWireError::Oversized`] / [`DataPlaneWireError::Frame`] if the encoded body cannot
/// be framed within the cap (it never should for a layer-produced frame).
pub fn encode_dataplane_peer_frame(
    partition: u64,
    frame: &DataPlaneFrame,
) -> Result<Vec<u8>, DataPlaneWireError> {
    let layer_body = encode_dataplane_body(frame);
    let mut body = Vec::with_capacity(PARTITION_PREFIX_LEN + layer_body.len());
    body.extend_from_slice(&partition.to_le_bytes());
    body.extend_from_slice(&layer_body);
    if body.len() as u64 > u64::from(MAX_DATAPLANE_FRAME_BYTES) {
        return Err(DataPlaneWireError::Oversized {
            len: body.len() as u64,
        });
    }
    let mut out = Vec::with_capacity(body.len() + 5);
    encode_frame(frame_type_for(frame), &body, &mut out).map_err(|e| match e {
        FrameError::FrameTooLarge { len } => DataPlaneWireError::Oversized { len },
        e @ FrameError::EmptyFrame => DataPlaneWireError::Frame(e),
    })?;
    Ok(out)
}

/// Decode ONE untrusted data-plane peer FRAME (the full `[len][type][partition-le][body]` envelope for
/// exactly one frame) into a `(partition, DataPlaneFrame)`, applying every bound: the size cap (the
/// length prefix is checked against [`MAX_DATAPLANE_FRAME_BYTES`] before the body is taken), the
/// partition-prefix presence check, and the bounded layer-codec decode (which also rejects an
/// unexpected type tag for a data verb).
///
/// `input` must contain at least one complete frame; on success the `(partition, frame)` and the bytes
/// the frame consumed are returned. If `input` does not yet hold a complete frame, `Ok(None)` is
/// returned (the caller reads more bytes). Every failure is a typed [`DataPlaneWireError`]; this never
/// panics or over-allocates.
///
/// # Errors
/// See [`DataPlaneWireError`] for every rejection mode (oversized, malformed frame, missing prefix,
/// undecodable body).
pub fn decode_dataplane_peer_frame(
    input: &[u8],
) -> Result<Option<(u64, DataPlaneFrame, usize)>, DataPlaneWireError> {
    let cap = MAX_DATAPLANE_FRAME_BYTES.min(MAX_FRAME_LEN);
    match decode_frame_with_cap(input, cap) {
        Ok(FrameDecode::Frame {
            type_tag,
            body,
            consumed,
        }) => {
            if body.len() < PARTITION_PREFIX_LEN {
                return Err(DataPlaneWireError::MissingPartitionPrefix);
            }
            let mut p = [0u8; PARTITION_PREFIX_LEN];
            p.copy_from_slice(&body[..PARTITION_PREFIX_LEN]);
            let partition = u64::from_le_bytes(p);
            let layer_body = &body[PARTITION_PREFIX_LEN..];
            let frame =
                decode_dataplane_frame(type_tag, layer_body).map_err(DataPlaneWireError::Decode)?;
            Ok(Some((partition, frame, consumed)))
        }
        Ok(FrameDecode::Incomplete { .. }) => Ok(None),
        Err(FrameError::FrameTooLarge { len }) => Err(DataPlaneWireError::Oversized { len }),
        Err(other) => Err(DataPlaneWireError::Frame(other)),
    }
}

/// A bidirectional DATA-plane peer link over any byte stream (`Read + Write`): a real `TcpStream` in
/// production, an in-memory pipe in tests. Frames outbound `(partition, frame)` with [`send`] and
/// reads bounded inbound ones with [`recv`], applying every bound in this module on the receive path.
///
/// Deliberately TRANSPORT-AGNOSTIC + synchronous, matching the broker's blocking `std::net` model and
/// the C1 [`PeerLink`](super::transport): it carries no controller state, so it is trivially driven by
/// a loopback harness.
///
/// [`send`]: DataPlaneLink::send
pub struct DataPlaneLink<S> {
    stream: S,
    /// Accumulated, not-yet-consumed inbound bytes (a partial frame may straddle reads).
    inbuf: Vec<u8>,
}

impl<S: Read + Write> DataPlaneLink<S> {
    /// Wrap a byte stream as a data-plane peer link.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            inbuf: Vec::new(),
        }
    }

    /// Serialize and send one outbound `(partition, frame)` to the peer.
    ///
    /// # Errors
    /// Returns [`DataPlaneWireError::Oversized`] / [`DataPlaneWireError::Frame`] if the frame cannot be
    /// framed within the cap, or [`DataPlaneWireError::Io`] on a write failure.
    pub fn send(
        &mut self,
        partition: u64,
        frame: &DataPlaneFrame,
    ) -> Result<(), DataPlaneWireError> {
        let bytes = encode_dataplane_peer_frame(partition, frame)?;
        self.stream.write_all(&bytes)?;
        Ok(())
    }

    /// Read exactly one inbound `(partition, frame)`, blocking until a full frame arrives (or the peer
    /// closes). Returns `Ok(None)` if the peer closed cleanly with no partial frame pending. Every
    /// bound in this module is applied: oversized frames are rejected pre-allocation and every body is
    /// decoded by the bounded layer codec.
    ///
    /// # Errors
    /// See [`DataPlaneWireError`]. A decode error means the peer sent something invalid or hostile; the
    /// node is never harmed (no panic, no OOM).
    pub fn recv(&mut self) -> Result<Option<(u64, DataPlaneFrame)>, DataPlaneWireError> {
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            if let Some((partition, frame, consumed)) = decode_dataplane_peer_frame(&self.inbuf)? {
                self.inbuf.drain(..consumed);
                return Ok(Some((partition, frame)));
            }
            let n = self.stream.read(&mut chunk)?;
            if n == 0 {
                if self.inbuf.is_empty() {
                    return Ok(None);
                }
                return Err(DataPlaneWireError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed mid-frame",
                )));
            }
            self.inbuf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// How a [`DataPlaneServer`] opens a FOLLOWER's replica log for a partition — the seam that lets the
/// serve path root a real on-disk `StdFs` replica log under the data dir while a test uses an in-memory
/// log. Given the partition id, returns the freshly-opened (or recovered) replica [`Log`] the follower
/// role owns.
pub trait ReplicaLogFactory<F: Filesystem, C: Clock> {
    /// Open (or recover) the replica log for `partition`. The follower role takes ownership of it.
    ///
    /// # Errors
    /// Any error opening the log is surfaced as a [`String`] (the caller maps it to its own error).
    fn open_replica_log(&self, partition: u64) -> Result<Log<F, C>, String>;
}

/// A per-node LIVE data-plane server: it holds the [`ProduceAckSeam`] (the
/// [`DataPlaneController`](super::dataplane::DataPlaneController) + every local partition role + the
/// parked-ack side table) and drives ONE inbound data-plane frame at a time, returning the bytes to
/// send back. It is transport-agnostic by construction (it holds no socket), so the SAME server is the
/// serve-path driver AND the unit under the real-socket 3-node test (the test/driver plays the
/// transport).
///
/// The `'a` lifetime is the controller's borrow of each LEADER partition log (the leader serves bytes
/// from the same log it leads); FOLLOWER replica logs are OWNED by the controller.
pub struct DataPlaneServer<'a, F: Filesystem, C: Clock> {
    /// This node's cluster id.
    node_id: u64,
    /// The produce-ack seam: owns the controller (roles) + the parked wire-`PubAck` side table. The
    /// release path goes through it so the gate's parked state + the parked bytes never drift apart.
    seam: ProduceAckSeam<'a, F, C>,
    /// The partitions this node FOLLOWS, with the leader node id to fetch from — the follower fetch
    /// loop targets the leader's address (resolved by the caller from the peer map).
    follower_targets: BTreeMap<u64, u64>,
}

impl<'a, F: Filesystem, C: Clock> DataPlaneServer<'a, F, C> {
    /// Build a server for `node_id` around an already-constructed [`ProduceAckSeam`] (its controller's
    /// roles already registered). Lower-level than [`from_placements`](Self::from_placements); the
    /// latter is the serve-path constructor that derives the roles from the committed metadata.
    #[must_use]
    pub fn new(node_id: u64, seam: ProduceAckSeam<'a, F, C>) -> Self {
        Self {
            node_id,
            seam,
            follower_targets: BTreeMap::new(),
        }
    }

    /// This node's cluster id.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// The seam (and through it the controller) this server drives.
    #[must_use]
    pub fn seam(&self) -> &ProduceAckSeam<'a, F, C> {
        &self.seam
    }

    /// Mutable access to the seam (the produce path threads a real wire `PubAck` through
    /// [`ProduceAckSeam::on_local_fsynced_ack`]; the serve loop drives the controller / release path).
    pub fn seam_mut(&mut self) -> &mut ProduceAckSeam<'a, F, C> {
        &mut self.seam
    }

    /// The leader node id this server FOLLOWS for `partition`, if it holds a follower role for it (the
    /// follower fetch loop sends its `FetchRecords` to that leader's address).
    #[must_use]
    pub fn follower_leader(&self, partition: u64) -> Option<u64> {
        self.follower_targets.get(&partition).copied()
    }

    /// The partitions this node FOLLOWS, with the leader id to fetch from.
    #[must_use]
    pub fn follower_partitions(&self) -> Vec<(u64, u64)> {
        self.follower_targets
            .iter()
            .map(|(&p, &l)| (p, l))
            .collect()
    }

    /// Register a follower target (used by [`from_placements`](Self::from_placements); exposed for a
    /// caller that builds the seam directly).
    pub fn set_follower_target(&mut self, partition: u64, leader: u64) {
        self.follower_targets.insert(partition, leader);
    }

    /// Route ONE inbound data-plane frame into the controller and return the action the caller must
    /// take on the wire (send a response / release acks / nothing). The single entry point a serve-path
    /// peer reader calls per decoded `(partition, frame)`.
    ///
    /// For an `AckReplicated` report this drives the quorum-ack gate; the released wire-`PubAck` BYTES
    /// (the real producer replies) are returned via [`Self::on_follower_report_bytes`] when the caller
    /// needs the bytes rather than the controller action. Here the action carries the released tokens
    /// for callers that route opaque tokens; the produce path uses [`Self::on_follower_report_bytes`].
    ///
    /// # Errors
    /// [`DataPlaneError`] if the frame's role does not match this node's role for the partition or a
    /// serve/apply fault — the caller drops the offending frame.
    pub fn handle_frame(
        &mut self,
        partition: u64,
        frame: DataPlaneFrame,
    ) -> Result<DataPlaneAction, DataPlaneError> {
        self.seam.controller_mut().handle_frame(partition, frame)
    }

    /// Record an inbound follower [`AckReplicatedBody`](super::isr::AckReplicatedBody) report for
    /// `partition` and return the REAL wire-`PubAck` byte-frames the report just released past the
    /// quorum-commit (in offset order), for the caller to flush onto the parked producer connections.
    /// Empty below `min_isr` (the no-false-ack property, now on the real wire).
    ///
    /// # Errors
    /// [`DataPlaneError`] if the controller rejects the report (unknown / non-led partition).
    pub fn on_follower_report_bytes(
        &mut self,
        partition: u64,
        report: &super::isr::AckReplicatedBody,
    ) -> Result<Vec<Vec<u8>>, DataPlaneError> {
        self.seam.on_follower_report(partition, report)
    }
}

impl<F: Filesystem, C: Clock> DataPlaneServer<'static, F, C> {
    /// Build a server from the committed placements (#701): per local partition,
    /// [`role_for_placement`] decides the role and the server registers it.
    ///
    /// * a LEADER role serves from `leader_log_for(partition)` — a `&'static Log` the caller supplies
    ///   for each partition this node leads (in a real serve this is the engine's partition log; the
    ///   `'static` borrow is documented in [`tests`] / the FLAGGED engine wiring above);
    /// * a FOLLOWER role OWNS a replica log opened via `replica_logs`.
    ///
    /// `isr_config` sizes the ISR / quorum gate for each led partition (the design `R=2f+1` /
    /// `min_isr=f+1`). The `epoch_for` closure supplies each leader's epoch cache (for the divergence
    /// handshake); pass a fresh [`EpochCache`] for a fresh partition.
    ///
    /// # Errors
    /// A [`String`] if a follower replica log cannot be opened (the caller maps it to its error type).
    pub fn from_placements<L, R, E>(
        node_id: u64,
        placements: &BTreeMap<u64, Placement>,
        isr_config: IsrConfig,
        mut leader_log_for: L,
        replica_logs: &R,
        mut epoch_for: E,
    ) -> Result<Self, String>
    where
        L: FnMut(u64) -> Option<&'static Log<F, C>>,
        R: ReplicaLogFactory<F, C>,
        E: FnMut(u64) -> EpochCache,
    {
        let mut controller = DataPlaneController::new(node_id);
        let mut follower_targets = BTreeMap::new();
        for (&partition, placement) in placements {
            match role_for_placement(node_id, placement) {
                PlacementRole::Leader => {
                    let log = leader_log_for(partition).ok_or_else(|| {
                        format!("no leader log supplied for led partition {partition}")
                    })?;
                    controller.start_leader(
                        partition,
                        log,
                        epoch_for(partition),
                        &placement.replicas,
                        isr_config,
                    );
                }
                PlacementRole::Follower => {
                    let log = replica_logs.open_replica_log(partition)?;
                    controller.start_follower(partition, log);
                    follower_targets.insert(partition, placement.leader);
                }
                PlacementRole::None => {}
            }
        }
        Ok(Self {
            node_id,
            seam: ProduceAckSeam::new(controller),
            follower_targets,
        })
    }
}

#[cfg(test)]
#[allow(
    // Test-only ergonomics: `server` / `served` etc. read clearly in context, and the capstone
    // 3-node serve test is a single coherent scenario whose length is intrinsic, not accidental.
    clippy::similar_names,
    clippy::too_many_lines
)]
mod tests {
    use super::*;
    use crate::cluster::ack_level::ClusterAckLevel;
    use crate::cluster::dataplane::AckDisposition;
    use crate::cluster::isr::AckReplicatedBody;
    use crate::cluster::state_machine::Placement;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use ironbus_proto::frame::encode_frame as proto_encode_frame;
    use ironbus_proto::message::{decode_pub_ack, encode_pub_ack, PubAckBody};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::io::RandomAccessFile;
    use ironbus_storage::log::{Append, Log, LogConfig};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    // ---- log scaffolding -------------------------------------------------------------------------

    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn open_log() -> Log<InMemoryFs, ManualClock> {
        Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).expect("log opens")
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

    fn quorum3() -> IsrConfig {
        IsrConfig {
            min_isr: 2,
            max_lag_records: 0,
        }
    }

    fn wire_pub_ack(offset: u64) -> Vec<u8> {
        let mut body = Vec::with_capacity(8);
        encode_pub_ack(&PubAckBody { offset }, &mut body);
        let mut frame = Vec::new();
        proto_encode_frame(FrameType::PubAck, &body, &mut frame).expect("PubAck frame encodes");
        frame
    }

    fn pub_ack_offset(frame: &[u8]) -> u64 {
        let body = &frame[frame.len() - 8..];
        decode_pub_ack(body).expect("PubAck body decodes").offset
    }

    /// A leader log leaked to `'static` (the leader role borrows it for the test; the process owns the
    /// leak). Mirrors the FLAGGED engine wiring: in a real serve this is the engine's partition log.
    fn leaked_leader_log(n: u32) -> &'static Log<InMemoryFs, ManualClock> {
        let mut log = open_log();
        for i in 0..n {
            log.append(&rec(format!("rep-{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        Box::leak(Box::new(log))
    }

    /// A replica-log factory that hands each follower a fresh in-memory log.
    struct InMemReplicaLogs;
    impl ReplicaLogFactory<InMemoryFs, ManualClock> for InMemReplicaLogs {
        fn open_replica_log(
            &self,
            _partition: u64,
        ) -> Result<Log<InMemoryFs, ManualClock>, String> {
            Ok(open_log())
        }
    }

    // ============================================================================================
    //  Codec tests: the data-plane peer codec round-trips + stays bounded on untrusted input.
    // ============================================================================================

    #[test]
    fn every_dataplane_frame_round_trips_over_the_peer_codec() {
        use crate::cluster::replication::{
            FetchRecordsBody, FetchResponseBody, OffsetForLeaderEpochBody,
            OffsetForLeaderEpochResponse,
        };
        use ironbus_core::epoch_cache::LeaderEpochEndOffset;
        use ironbus_core::leader_lease::LeaderEpoch;
        use ironbus_core::types::Offset;

        let frames = [
            DataPlaneFrame::FetchRequest(FetchRecordsBody {
                from_offset: 7,
                max_records: 8,
                max_bytes: 4096,
            }),
            DataPlaneFrame::FetchResponse(FetchResponseBody {
                high_watermark: 25,
                first_offset: 7,
                record_count: 3,
                frame_bytes: vec![1, 2, 3, 4, 5],
            }),
            DataPlaneFrame::AckReplicated(AckReplicatedBody {
                follower_id: 2,
                fsynced_offset: 19,
            }),
            DataPlaneFrame::EpochQuery(OffsetForLeaderEpochBody {
                epoch: LeaderEpoch::new(4),
            }),
            DataPlaneFrame::EpochResponse(OffsetForLeaderEpochResponse {
                end_offset: LeaderEpochEndOffset {
                    requested_epoch: LeaderEpoch::new(4),
                    answered_epoch: LeaderEpoch::new(4),
                    end_offset: Offset::new(14),
                },
            }),
        ];
        for (partition, frame) in frames.iter().enumerate() {
            let p = partition as u64 + 1;
            let bytes = encode_dataplane_peer_frame(p, frame).expect("encode");
            let (got_p, got_frame, consumed) = decode_dataplane_peer_frame(&bytes)
                .expect("decode ok")
                .expect("a complete frame");
            assert_eq!(consumed, bytes.len(), "exactly one frame consumed");
            assert_eq!(got_p, p, "partition prefix round-trips");
            assert_eq!(&got_frame, frame, "frame round-trips byte-faithful");
        }
    }

    #[test]
    fn an_oversized_dataplane_frame_is_rejected_before_allocation() {
        // A length prefix beyond the cap, with no body present: rejected on the prefix alone.
        let mut frame = Vec::new();
        let claimed = MAX_DATAPLANE_FRAME_BYTES + 100;
        frame.extend_from_slice(&claimed.to_le_bytes());
        frame.push(FrameType::FetchResponse.as_u8());
        match decode_dataplane_peer_frame(&frame) {
            Err(DataPlaneWireError::Oversized { len }) => assert_eq!(len, u64::from(claimed)),
            other => panic!("expected Oversized, got {other:?}"),
        }
    }

    #[test]
    fn a_dataplane_frame_missing_its_partition_prefix_is_rejected() {
        // A well-framed FetchRecords frame whose body is shorter than the 8-byte partition prefix.
        let mut framed = Vec::new();
        proto_encode_frame(FrameType::FetchRecords, &[1, 2, 3], &mut framed).expect("frame");
        match decode_dataplane_peer_frame(&framed) {
            Err(DataPlaneWireError::MissingPartitionPrefix) => {}
            other => panic!("expected MissingPartitionPrefix, got {other:?}"),
        }
    }

    #[test]
    fn a_non_dataplane_type_tag_is_rejected_by_the_codec() {
        // A Ping frame (a client verb) with a valid partition prefix does not belong on the data link.
        let mut body = 1u64.to_le_bytes().to_vec();
        body.push(0xff);
        let mut framed = Vec::new();
        proto_encode_frame(FrameType::Ping, &body, &mut framed).expect("frame");
        match decode_dataplane_peer_frame(&framed) {
            Err(DataPlaneWireError::Decode(_)) => {}
            other => panic!("expected a Decode rejection, got {other:?}"),
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_dataplane_codec() {
        // Adversarial: random-ish prefixes + bodies must always be a typed result, never a panic.
        for seed in 0u32..2000 {
            let mut buf = Vec::new();
            let len = seed % 64;
            buf.extend_from_slice(&len.to_le_bytes());
            for i in 0..len {
                buf.push(u8::try_from(seed.wrapping_mul(31).wrapping_add(i) % 256).unwrap());
            }
            let _ = decode_dataplane_peer_frame(&buf);
        }
    }

    // ============================================================================================
    //  THE CAPSTONE: a 3-node SERVE cluster over REAL loopback sockets replicates produced data +
    //  quorum-gates a C2-fsync produce. The leader log is shared with the leader's DataPlaneServer;
    //  the two follower DataPlaneServers run real follower-fetch loops over TcpStreams, applying
    //  CRC-revalidated bytes, until their logs are BYTE-IDENTICAL to the leader's — and a parked
    //  wire PubAck releases ONLY after the ISR quorum reported fsync over the wire.
    // ============================================================================================

    /// Service one accept + one read pass on the leader serve loop on the MAIN thread (the leader role
    /// borrows a `&Log` which is not `Send`, so it stays on the test thread). Accepts any new follower
    /// link (non-blocking), then services each link once: a `FetchRecords` / `OffsetForLeaderEpoch` is
    /// answered with a response frame; an `AckReplicated` report drives the quorum-ack gate and any
    /// released wire-`PubAck` bytes are pushed onto `released`.
    fn pump_leader_once(
        server: &mut DataPlaneServer<'static, InMemoryFs, ManualClock>,
        listener: &TcpListener,
        links: &mut Vec<DataPlaneLink<TcpStream>>,
        released: &mut Vec<Vec<u8>>,
    ) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .unwrap();
                links.push(DataPlaneLink::new(stream));
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
        for link in links.iter_mut() {
            match link.recv() {
                Ok(Some((partition, DataPlaneFrame::AckReplicated(report)))) => {
                    // The produce-ack release path: a follower's fsync report drives the gate; the
                    // released bytes are the REAL wire PubAck frames to flush to the producer.
                    if let Ok(bytes) = server.on_follower_report_bytes(partition, &report) {
                        released.extend(bytes);
                    }
                }
                Ok(Some((partition, frame))) => match server.handle_frame(partition, frame) {
                    Ok(DataPlaneAction::SendFetchResponse {
                        partition,
                        response,
                    }) => {
                        let _ = link.send(partition, &DataPlaneFrame::FetchResponse(response));
                    }
                    Ok(DataPlaneAction::SendEpochResponse {
                        partition,
                        response,
                    }) => {
                        let _ = link.send(partition, &DataPlaneFrame::EpochResponse(response));
                    }
                    Ok(_) | Err(_) => {}
                },
                // A clean close, a read-timeout (the SO_RCVTIMEO surfaces WouldBlock/TimedOut), or a
                // dropped/decoded-bad link: nothing to serve this pass. The bounded codec already
                // contained any hostile frame to this typed error; just move on.
                Ok(None) | Err(_) => {}
            }
        }
    }

    /// A follower driven over a REAL non-blocking loopback socket to the leader. It owns its
    /// `DataPlaneServer` (its replica log) and a [`DataPlaneLink`] to the leader's listener. One
    /// [`Self::step`] sends a fetch, then (driven by the caller pumping the leader between steps) reads
    /// the response, applies it, and reports its fsync'd frontier — so the data crosses a genuine
    /// `TcpStream`. Because the controller holds a `&Log` type and is not `Send`, the whole cluster runs
    /// COOPERATIVELY on one thread over real sockets (the transport is real; only the driving is
    /// single-threaded, which keeps the test deterministic).
    struct LiveFollower {
        server: DataPlaneServer<'static, InMemoryFs, ManualClock>,
        link: DataPlaneLink<TcpStream>,
        partition: u64,
    }

    impl LiveFollower {
        fn connect(
            server: DataPlaneServer<'static, InMemoryFs, ManualClock>,
            partition: u64,
            leader_addr: SocketAddr,
        ) -> Self {
            let stream = TcpStream::connect(leader_addr).expect("follower connects to the leader");
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .expect("read timeout");
            Self {
                server,
                link: DataPlaneLink::new(stream),
                partition,
            }
        }

        /// Send one fetch request from the follower's current position (the leader is pumped after this
        /// to serve it).
        fn send_fetch(&mut self) {
            let req = self
                .server
                .seam()
                .controller()
                .make_fetch_request(self.partition, 8, 4096)
                .expect("follower builds a fetch request");
            self.link
                .send(self.partition, &DataPlaneFrame::FetchRequest(req))
                .expect("send fetch");
        }

        /// Read + apply the leader's response (if one has arrived), then report the follower's fsync'd
        /// frontier back to the leader (driving the quorum-ack gate on the next leader pump).
        fn recv_apply_and_report(&mut self) {
            if let Ok(Some((p, DataPlaneFrame::FetchResponse(resp)))) = self.link.recv() {
                assert_eq!(p, self.partition);
                self.server
                    .seam_mut()
                    .controller_mut()
                    .handle_frame(self.partition, DataPlaneFrame::FetchResponse(resp))
                    .expect("follower applies the response");
            }
            let report = self
                .server
                .seam()
                .controller()
                .follower_report(self.partition)
                .expect("follower builds its report");
            self.link
                .send(self.partition, &DataPlaneFrame::AckReplicated(report))
                .expect("send report");
        }

        fn high_watermark(&self) -> u64 {
            self.server
                .seam()
                .controller()
                .follower_high_watermark(self.partition)
                .unwrap()
        }

        fn replica_dump(&self) -> Vec<(String, Vec<u8>)> {
            dump_segments(
                self.server
                    .seam()
                    .controller()
                    .follower_log(self.partition)
                    .unwrap(),
            )
        }
    }

    #[test]
    fn three_node_serve_cluster_replicates_byte_identical_and_quorum_gates_a_c2_fsync_produce() {
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 5,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement.clone())].into_iter().collect();

        // The leader (node 1) holds a log of 25 records, fsync'd. The leader DataPlaneServer borrows it.
        let leader_log = leaked_leader_log(25);
        let leader_hw = leader_log.flushed_offset().get();
        assert_eq!(leader_hw, 25);

        let mut leader_server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| if p == P { Some(leader_log) } else { None },
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .expect("leader server builds from placement");
        assert!(leader_server.seam().controller().is_leader(P));

        // PARK a real C2-fsync produce's wire PubAck for the last record (offset 24): the leader has
        // locally fsync'd (I2) but NO follower has the data, so the 2-of-3 quorum is not met yet.
        let offset = leader_hw - 1;
        let reply = wire_pub_ack(offset);
        let disposition = leader_server
            .seam_mut()
            .on_local_fsynced_ack(ClusterAckLevel::C2Fsync, P, offset, reply.clone())
            .unwrap();
        assert_eq!(
            disposition,
            AckDisposition::Parked,
            "a clustered C2-fsync led produce parks its wire PubAck (no quorum yet)"
        );
        assert_eq!(leader_server.seam().parked_len(), 1);

        // Bind the leader's data-plane listener on a real loopback port.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind leader listener");
        listener.set_nonblocking(true).unwrap();
        let leader_addr = listener.local_addr().unwrap();

        // The two follower servers (nodes 2 + 3), built from the SAME committed placement, each opening
        // its own replica log and targeting the leader, each over a REAL loopback TcpStream.
        let follower2 = DataPlaneServer::from_placements(
            2,
            &placements,
            quorum3(),
            |_| None,
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .expect("follower2 builds");
        let follower3 = DataPlaneServer::from_placements(
            3,
            &placements,
            quorum3(),
            |_| None,
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .expect("follower3 builds");
        assert!(follower2.seam().controller().is_follower(P));
        assert_eq!(follower2.follower_leader(P), Some(1));
        assert!(follower3.seam().controller().is_follower(P));

        let mut f2 = LiveFollower::connect(follower2, P, leader_addr);
        let mut f3 = LiveFollower::connect(follower3, P, leader_addr);

        // Cooperatively drive the live cluster: each round both followers fetch, the leader serves +
        // records reports + releases the quorum-fsync'd ack, and the followers apply + report. All over
        // real sockets; the loop just keeps the single test thread fair.
        let mut links: Vec<DataPlaneLink<TcpStream>> = Vec::new();
        let mut released: Vec<Vec<u8>> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            f2.send_fetch();
            f3.send_fetch();
            // Pump the leader enough to accept the links + serve both fetches + record both reports.
            for _ in 0..8 {
                pump_leader_once(&mut leader_server, &listener, &mut links, &mut released);
            }
            f2.recv_apply_and_report();
            f3.recv_apply_and_report();
            for _ in 0..8 {
                pump_leader_once(&mut leader_server, &listener, &mut links, &mut released);
            }
            if (f2.high_watermark() >= leader_hw && f3.high_watermark() >= leader_hw)
                || Instant::now() > deadline
            {
                break;
            }
        }

        assert_eq!(
            f2.high_watermark(),
            leader_hw,
            "follower 2 caught up to the leader over the live transport"
        );
        assert_eq!(
            f3.high_watermark(),
            leader_hw,
            "follower 3 (which started behind) caught up over the live transport"
        );

        // The wire PubAck was RELEASED by the leader once a 2-of-3 quorum reported fsync of the offset
        // over the wire — and it is the REAL reply (decodes to the produced offset, byte-identical).
        let matching: Vec<&Vec<u8>> = released
            .iter()
            .filter(|f| pub_ack_offset(f) == offset)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "exactly one wire PubAck for the produced offset released after the quorum fsync'd"
        );
        assert_eq!(
            *matching[0], reply,
            "the released bytes ARE the original wire PubAck (the real reply, not a token)"
        );

        // Each follower's replica log is BYTE-IDENTICAL to the leader's, over the live transport.
        let leader_dump = dump_segments(leader_log);
        assert_eq!(
            f2.replica_dump(),
            leader_dump,
            "follower 2 replica is byte-identical to the leader over the live transport"
        );
        assert_eq!(
            f3.replica_dump(),
            leader_dump,
            "follower 3 replica is byte-identical to the leader over the live transport"
        );
    }

    #[test]
    fn below_min_isr_the_wire_puback_stays_parked_no_false_ack() {
        // Node 1 leads {1,2,3}, min_isr=2. With NO follower ever reporting, the ISR is the leader alone
        // (size 1 < min_isr 2): no quorum, so a parked C2-fsync produce ack is NEVER released.
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 1,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        let leader_log = leaked_leader_log(10);
        let mut server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| if p == P { Some(leader_log) } else { None },
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .unwrap();

        let offset = 9;
        let reply = wire_pub_ack(offset);
        assert_eq!(
            server
                .seam_mut()
                .on_local_fsynced_ack(ClusterAckLevel::C2Fsync, P, offset, reply)
                .unwrap(),
            AckDisposition::Parked
        );
        // A follower report from a fresh (fsynced_offset 0) follower does not bring quorum at 9.
        let report = AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 0,
        };
        let released = server.on_follower_report_bytes(P, &report).unwrap();
        assert!(
            released.is_empty(),
            "below min_isr the wire PubAck is NEVER sent (no false ack on the real wire)"
        );
        assert_eq!(server.seam().parked_len(), 1, "the ack stays withheld");
    }

    #[test]
    fn a_restart_re_establishes_roles_from_the_committed_placement() {
        // The serve constructor is deterministic from the committed placement: rebuilding the servers
        // from the SAME placement (as after a process restart) re-derives every role + the follower
        // targets, and a follower resumes fetching from its recovered replica-log head.
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 9,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        let leader_log = leaked_leader_log(12);

        // Rebuild the leader server (as on a restart): leader role re-established, ISR seeded from the
        // recovered durable head, no follower yet => the 2-of-3 quorum is 0 (the no-false-ack rule).
        let leader = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| if p == P { Some(leader_log) } else { None },
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .unwrap();
        assert!(leader.seam().controller().is_leader(P));
        assert_eq!(leader.seam().controller().quorum_commit(P), Some(0));

        // Rebuild a follower server: follower role re-established, targeting the committed leader, and
        // resuming from its (fresh, here) recovered replica-log head.
        let follower = DataPlaneServer::from_placements(
            2,
            &placements,
            quorum3(),
            |_| None,
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .unwrap();
        assert!(follower.seam().controller().is_follower(P));
        assert_eq!(follower.follower_leader(P), Some(1));
        let req = follower
            .seam()
            .controller()
            .make_fetch_request(P, 8, 4096)
            .unwrap();
        assert_eq!(
            req.from_offset, 0,
            "the follower resumes from its recovered head"
        );
    }

    #[test]
    fn a_node_not_in_the_placement_holds_no_role_and_no_data_plane() {
        // A node not in the replica set builds a server with NO roles — no leader serve, no follower
        // fetch, nothing on the data plane for that partition (the PlacementRole::None path).
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 1,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        let server = DataPlaneServer::from_placements(
            9, // not a replica
            &placements,
            quorum3(),
            |_| None,
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .unwrap();
        assert_eq!(server.seam().controller().partition_count(), 0);
        assert!(!server.seam().controller().is_leader(P));
        assert!(!server.seam().controller().is_follower(P));
        assert!(server.follower_partitions().is_empty());
    }

    /// The wired reader rejects a hostile oversized data-plane frame over a REAL socket without
    /// crashing the leader serve loop — the bounded codec on the live path. The leader serve loop runs
    /// on this thread (it borrows a non-`Send` `&Log`); a hostile probe + a well-behaved fetch arrive
    /// from a worker thread, and the leader must keep serving the valid fetch.
    #[test]
    fn the_wired_data_reader_rejects_hostile_frames_without_crashing() {
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 1,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        let leader_log = leaked_leader_log(8);
        let mut server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| if p == P { Some(leader_log) } else { None },
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .unwrap();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();

        // A worker plays the hostile peer, then a well-behaved follower; it reports the served response
        // back so the main thread can assert the node survived and still serves a valid fetch.
        let (got_tx, got_rx) = mpsc::channel::<bool>();
        let probe = std::thread::Builder::new()
            .spawn(move || {
                // Hostile: an oversized length prefix on its own connection (dropped by the reader).
                if let Ok(mut s) = TcpStream::connect(addr) {
                    let bogus = u64::from(MAX_DATAPLANE_FRAME_BYTES) + 1_000_000;
                    let _ = s.write_all(&bogus.to_le_bytes());
                    let _ = s.write_all(b"garbage");
                    drop(s);
                }
                // Well-behaved: a fresh link sends a valid fetch and must get a FetchResponse back.
                let stream = TcpStream::connect(addr).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let mut link = DataPlaneLink::new(stream);
                let req = crate::cluster::replication::FetchRecordsBody {
                    from_offset: 0,
                    max_records: 8,
                    max_bytes: 4096,
                };
                link.send(P, &DataPlaneFrame::FetchRequest(req)).unwrap();
                let served = matches!(link.recv(), Ok(Some((_, DataPlaneFrame::FetchResponse(_)))));
                let _ = got_tx.send(served);
            })
            .unwrap();

        // Drive the leader serve loop here until the probe reports its result (or a deadline).
        let mut links: Vec<DataPlaneLink<TcpStream>> = Vec::new();
        let mut released: Vec<Vec<u8>> = Vec::new();
        let mut served: Option<bool> = None;
        let deadline = Instant::now() + Duration::from_secs(15);
        while served.is_none() && Instant::now() < deadline {
            pump_leader_once(&mut server, &listener, &mut links, &mut released);
            if let Ok(s) = got_rx.try_recv() {
                served = Some(s);
            }
        }
        let _ = probe.join();
        assert_eq!(
            served,
            Some(true),
            "the leader serve loop survives a hostile frame and still serves a valid fetch"
        );
    }
}
