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
//!    server registers it: the LEADER role serves from the engine's `Arc`-shared, off-actor
//!    [`ReadPlane`](ironbus_storage::read_plane::ReadPlane) (#654, #715) — NOT a `&Log` borrow, so the
//!    leader never writes (or borrows) its log (the single append actor stays the sole writer) and the
//!    whole server is `Send`; the FOLLOWER role owns a freshly-opened / recovered replica log under the
//!    data dir. A restart re-derives every role from the same committed placement + the durable replica
//!    log, so the role + replication resume.
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
//! ## #715: the data plane now RUNS in the live broker via the read plane
//!
//! The #715 engine-ownership refactor lands the `Send` half of the above: the LEADER role serves
//! fetches through the engine's `Arc`-shared, off-actor [`ReadPlane`](ironbus_storage::read_plane::ReadPlane)
//! (#654) instead of a `&Log` borrow, so the [`DataPlaneController`] / [`ProduceAckSeam`] /
//! [`DataPlaneServer`] are all `Send` and the broker constructs + runs the data plane in cluster serve
//! over the live peer transport, on a dedicated peer-I/O thread alongside the engine's single append
//! actor. The leader NEVER writes its log here — it READS the immutable sealed bytes via the plane; the
//! append actor remains the ONLY writer (the single-writer invariant). The CLI `run_broker` obtains
//! each led partition's [`ReadPlane`](ironbus_storage::read_plane::ReadPlane) from
//! [`Engine::read_plane`](crate::engine::Engine::read_plane) BEFORE moving the engine into the actor,
//! builds the server from the committed placement, and spawns the serve loop — gated entirely on a
//! [`ClusterConfig`](super::ClusterConfig) being present (single-node constructs none of it).
//!
//! FLAGGED / DEFERRED (precise — each its own follow-up, none landed here):
//! * **The live produce-ack `session::drain_parked` hot-path wiring.** The [`ProduceAckSeam`] (#712)
//!   is driven END-TO-END here: a parked wire-`PubAck` is released ONLY once the ISR follower reports
//!   over the REAL wire bring quorum-fsync (proven by [`tests`]). The seam is now `Send` and reachable
//!   from shared broker state, but threading it through `session.rs`'s per-connection `drain_parked` so
//!   a real CLIENT produce on a led partition parks ITS connection's wire `PubAck` (rather than the
//!   broker driving the seam from the serve loop) is the remaining focused session change. It is gated
//!   entirely on the cluster being configured; the single-node produce hot path is untouched.
//! * **The active (flushed-but-unsealed) tail.** The read plane serves the SEALED prefix; a leader's
//!   flushed frontier can sit ahead of the sealed end. A follower converges to the sealed end
//!   byte-identically and replicates the active tail once it seals (a roll). This is correct by
//!   construction (no false ack, no false visibility) but a follower can LAG by up to the active-segment
//!   size until it seals; closing that liveness window (an actor-fallback active-tail read on the peer
//!   thread, or an active-segment read-plane extension) is FLAGGED.
//! * **Cooperative REBALANCE on a placement change** is C5-I2 (this slice is STATIC placement: roles
//!   are derived from the committed placement at start + re-derived on a restart; a live leader
//!   hand-off / replica move is later).
//! * **Leaderless FAILOVER** (a new leader election on a leader loss) is C5-I3.
//! * **Follower READS** (serving consume traffic from a follower replica) are C6.
//! * **Multi-partition fan-out optimization** (one shared fetch loop across many partitions) +
//!   **snapshot / compaction** (#660) + the **geo** plane (C7) are separate.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ironbus_core::clock::Clock;
use ironbus_core::epoch_cache::EpochCache;
use ironbus_proto::frame::{
    decode_frame_with_cap, encode_frame, FrameDecode, FrameError, FrameType, MAX_FRAME_LEN,
};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::Log;
use ironbus_storage::read_plane::ReadPlane;

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
/// There is NO lifetime: each LEADER role serves bytes through the engine's `Arc`-shared, off-actor
/// [`ReadPlane`](ironbus_storage::read_plane::ReadPlane) (#654, #715), NOT a `&Log` borrow, so the
/// whole server is `Send` and can run on a dedicated peer-I/O thread alongside the engine's single
/// append actor. FOLLOWER replica logs are OWNED by the controller.
pub struct DataPlaneServer<F: Filesystem, C: Clock> {
    /// This node's cluster id.
    node_id: u64,
    /// The produce-ack seam: owns the controller (roles) + the parked wire-`PubAck` side table. The
    /// release path goes through it so the gate's parked state + the parked bytes never drift apart.
    seam: ProduceAckSeam<F, C>,
    /// The partitions this node FOLLOWS, with the leader node id to fetch from — the follower fetch
    /// loop targets the leader's address (resolved by the caller from the peer map).
    follower_targets: BTreeMap<u64, u64>,
}

impl<F: Filesystem, C: Clock> DataPlaneServer<F, C> {
    /// Build a server for `node_id` around an already-constructed [`ProduceAckSeam`] (its controller's
    /// roles already registered). Lower-level than [`from_placements`](Self::from_placements); the
    /// latter is the serve-path constructor that derives the roles from the committed metadata.
    #[must_use]
    pub fn new(node_id: u64, seam: ProduceAckSeam<F, C>) -> Self {
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
    pub fn seam(&self) -> &ProduceAckSeam<F, C> {
        &self.seam
    }

    /// Mutable access to the seam (the produce path threads a real wire `PubAck` through
    /// [`ProduceAckSeam::on_local_fsynced_ack`]; the serve loop drives the controller / release path).
    pub fn seam_mut(&mut self) -> &mut ProduceAckSeam<F, C> {
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

impl<F: Filesystem, C: Clock> DataPlaneServer<F, C> {
    /// Build a server from the committed placements (#701): per local partition,
    /// [`role_for_placement`] decides the role and the server registers it.
    ///
    /// * a LEADER role serves from `leader_plane_for(partition)` — the engine's `Arc`-shared, off-actor
    ///   [`ReadPlane`](ironbus_storage::read_plane::ReadPlane) (#654, #715) for each partition this node
    ///   leads, obtained from [`Engine::read_plane`](crate::engine::Engine::read_plane). The leader
    ///   serves committed bytes through it and NEVER writes (or borrows) the engine's log — the single
    ///   append actor stays the sole writer — and the `Arc` (not a borrow) is what makes the server
    ///   `Send`;
    /// * a FOLLOWER role OWNS a replica log opened via `replica_logs`.
    ///
    /// `isr_config` sizes the ISR / quorum gate for each led partition (the design `R=2f+1` /
    /// `min_isr=f+1`). The `epoch_for` closure supplies each leader's epoch cache (for the divergence
    /// handshake); pass a fresh [`EpochCache`] for a fresh partition.
    ///
    /// # Errors
    /// A [`String`] if a leader read plane is not supplied for a led partition, or a follower replica
    /// log cannot be opened (the caller maps it to its error type).
    pub fn from_placements<L, R, E>(
        node_id: u64,
        placements: &BTreeMap<u64, Placement>,
        isr_config: IsrConfig,
        mut leader_plane_for: L,
        replica_logs: &R,
        mut epoch_for: E,
    ) -> Result<Self, String>
    where
        L: FnMut(u64) -> Option<Arc<ReadPlane<F>>>,
        R: ReplicaLogFactory<F, C>,
        E: FnMut(u64) -> EpochCache,
    {
        let mut controller = DataPlaneController::new(node_id);
        let mut follower_targets = BTreeMap::new();
        for (&partition, placement) in placements {
            match role_for_placement(node_id, placement) {
                PlacementRole::Leader => {
                    let plane = leader_plane_for(partition).ok_or_else(|| {
                        format!("no leader read plane supplied for led partition {partition}")
                    })?;
                    controller.start_leader(
                        partition,
                        plane,
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

/// How long a data-plane peer thread (the leader accept loop, a per-connection reader, a follower
/// fetch loop) sleeps / blocks between shutdown re-checks, so a `stop` is prompt and an idle loop never
/// busy-spins. The same cadence the metadata [`ClusterRuntime`](super::runtime::ClusterRuntime) uses.
const DATAPLANE_POLL: Duration = Duration::from_millis(100);

/// The follower fetch budgets: how many records / bytes a follower asks for per `FetchRecords`. The
/// leader's read plane already bounds a response to a single sealed segment run, so a catch-up is
/// several rounds; these are generous upper bounds, themselves under
/// [`MAX_REPL_FETCH_BYTES`](super::replication::MAX_REPL_FETCH_BYTES).
const FETCH_MAX_RECORDS: u32 = 1024;
const FETCH_MAX_BYTES: u32 = 1024 * 1024;

/// A LIVE, running data-plane server: the piece that finally CONSTRUCTS, SPAWNS, and DRIVES the proven
/// [`DataPlaneServer`] over real `TcpStream`s in a serving cluster (V2-C2-I9, #717). Where
/// [`DataPlaneServer::from_placements`] builds the (transport-agnostic) per-partition roles and the
/// 3-node capstone test (#713) drove them cooperatively on one thread, this owns the SHARED server and
/// runs it on its own threads alongside the engine's single append actor:
///
/// 1. a **data-plane LISTENER** thread (the LEADER side): it binds the node's data-plane peer address
///    ([`dataplane_addr`](super::runtime::dataplane_addr) of the configured metadata address) and, per
///    accepted connection, a reader thread that pulls bounded, CRC-revalidated data frames off the wire
///    ([`DataPlaneLink::recv`]) and routes each through the shared server — a `FetchRecords` /
///    `OffsetForLeaderEpoch` is answered with a response frame from the off-actor read plane (#654, the
///    leader NEVER writes its log), an `AckReplicated` report drives the quorum-ack gate;
/// 2. one **follower FETCH** thread per partition this node FOLLOWS: it dials the leader's data-plane
///    address (reconnecting on a drop), and on a cadence sends a `FetchRecords`, applies the
///    CRC-revalidated response to its OWN replica log (its own writer — the single-writer invariant),
///    and reports its fsync'd frontier back ([`AckReplicatedBody`](super::isr::AckReplicatedBody)),
///    self-healing on a detected divergence via the leader-epoch truncation (#599).
///
/// The [`DataPlaneServer`] is held in an `Arc<Mutex<..>>` so every data-plane thread (and, when the
/// produce-ack seam is threaded, the produce path) takes the SAME server under a short lock per frame —
/// the gate's parked state + the parked-reply side-table never drift apart. The server is `Send` (#715:
/// the leader serves through the `Arc`-shared off-actor read plane, not a `&Log` borrow), so this all
/// runs off the append actor.
///
/// ## Single-node / no-cluster: never constructed (the byte-identical guarantee)
///
/// [`DataPlaneRuntime::start`] is called ONLY on a clustered serve (a
/// [`ClusterConfig`](super::ClusterConfig) present, surfaced by the metadata
/// [`ClusterRuntime`](super::runtime::ClusterRuntime)). With no cluster config NOTHING here is
/// constructed — no server, no listener, no thread, no data frame — and the broker's produce/consume
/// hot path is byte-for-byte today's.
pub struct DataPlaneRuntime<F: Filesystem, C: Clock> {
    /// The shared, `Send` data-plane server every peer thread drives under a short per-frame lock.
    server: Arc<Mutex<DataPlaneServer<F, C>>>,
    /// The CLIENT produce-ack gate (#719) the leader-side readers release quorum-fsync'd acks through,
    /// when this runtime was started with one ([`DataPlaneRuntime::start_with_client_gate`]). It wraps
    /// the SAME `server` Arc, so the one seam is the single source of truth. `None` for a runtime
    /// started without a client gate (the in-process tests / the observability serve).
    client_gate: Option<Arc<super::client_ack::ClientAckGate<F, C>>>,
    /// The shutdown flag the runtime OWNS; `stop` sets it and joins every thread.
    shutdown: Arc<AtomicBool>,
    /// The data-plane peer LISTENER thread (leader side: accepts inbound links, spawns readers).
    listener: Option<JoinHandle<()>>,
    /// One FOLLOWER fetch thread per followed partition (dials the leader, fetch + apply + report).
    followers: Vec<JoinHandle<()>>,
}

/// How a leader-side data-plane reader RELEASES a quorum-fsync'd produce ack from a follower's
/// [`AckReplicatedBody`](super::isr::AckReplicatedBody) report (#719): either the CLIENT produce-ack
/// gate (which deposits each released wire `PubAck` into its owner connection's outbox to flush) or, in
/// the no-client-gate case, the server-only path that drives the gate and drops the bytes (the ISR /
/// parked state is still advanced — observability / a self-driven test).
enum AckRelease<F: Filesystem, C: Clock> {
    /// The clustered client serve (#719): route the report through the shared
    /// [`ClientAckGate`](super::client_ack::ClientAckGate), depositing each released wire `PubAck` into
    /// its owner connection's outbox.
    Gate(Arc<super::client_ack::ClientAckGate<F, C>>),
    /// No client gate (a runtime started without one): drive the seam directly and drop the released
    /// bytes (the gate's parked / ISR state is still correctly advanced).
    ServerOnly,
}

// Hand-written (a derive would demand `F: Clone` / `C: Clone`): each variant is just an `Arc` clone or
// a unit, so cloning is cheap and `F`/`C`-free.
impl<F: Filesystem, C: Clock> Clone for AckRelease<F, C> {
    fn clone(&self) -> Self {
        match self {
            AckRelease::Gate(g) => AckRelease::Gate(Arc::clone(g)),
            AckRelease::ServerOnly => AckRelease::ServerOnly,
        }
    }
}

impl<F, C> DataPlaneRuntime<F, C>
where
    F: Filesystem + Send + Sync + 'static,
    C: Clock + Send + 'static,
{
    /// Construct, spawn, and drive the data plane for a serving cluster (#717). `server` is the
    /// [`DataPlaneServer`] already built from the committed placement (see
    /// [`DataPlaneServer::from_placements`]); `self_data_addr` is THIS node's data-plane listener
    /// address ([`dataplane_addr`](super::runtime::dataplane_addr) of its metadata address);
    /// `peer_data_addrs` resolves every peer id to its data-plane address (the follower fetch loop dials
    /// its leader's). Binds the listener synchronously (so a bind failure is reported before any thread
    /// spawns) and spawns the listener + one follower fetch thread per followed partition.
    ///
    /// # Errors
    /// An [`io::Error`] if the data-plane peer listener cannot bind its address. On an error NO threads
    /// are left running.
    ///
    /// # Panics
    /// Panics only if the OS refuses to spawn a runtime thread (the listener or a follower fetch
    /// thread) — an unrecoverable resource-exhaustion condition at start, treated like a failed
    /// allocation. Once `start` returns `Ok`, the runtime never panics on the serve path.
    pub fn start(
        server: DataPlaneServer<F, C>,
        self_data_addr: SocketAddr,
        peer_data_addrs: &BTreeMap<u64, SocketAddr>,
    ) -> io::Result<Self> {
        Self::start_inner(server, self_data_addr, peer_data_addrs, None)
    }

    /// Like [`Self::start`], but BUILDS a shared CLIENT produce-ack
    /// [`ClientAckGate`](super::client_ack::ClientAckGate) (#719) at `configured_level` around the SAME
    /// `Arc<Mutex<DataPlaneServer>>` this runtime drives (so the one seam is the single source of truth),
    /// and routes the leader-side quorum-ack release THROUGH it: a follower's `AckReplicated` report that
    /// brings quorum-fsync past a parked offset deposits the released wire `PubAck` into its owner
    /// connection's outbox, for that connection to flush on its own pass. The built gate is returned by
    /// [`Self::client_gate`] so the caller can publish it to its per-connection produce paths. Below
    /// `min_isr` nothing releases (no false ack on the real client wire).
    ///
    /// # Errors
    /// As [`Self::start`].
    ///
    /// # Panics
    /// As [`Self::start`].
    pub fn start_with_client_gate(
        server: DataPlaneServer<F, C>,
        self_data_addr: SocketAddr,
        peer_data_addrs: &BTreeMap<u64, SocketAddr>,
        configured_level: super::ack_level::ClusterAckLevel,
    ) -> io::Result<Self> {
        Self::start_inner(
            server,
            self_data_addr,
            peer_data_addrs,
            Some(configured_level),
        )
    }

    /// The shared work of [`Self::start`] / [`Self::start_with_client_gate`]: when `client_level` is
    /// `Some`, a [`ClientAckGate`](super::client_ack::ClientAckGate) is built around the wrapped server
    /// Arc and the leader-side readers release through it (`AckRelease::Gate`); when `None`, the readers
    /// drive the seam directly and drop the released bytes (`AckRelease::ServerOnly`).
    fn start_inner(
        server: DataPlaneServer<F, C>,
        self_data_addr: SocketAddr,
        peer_data_addrs: &BTreeMap<u64, SocketAddr>,
        client_level: Option<super::ack_level::ClusterAckLevel>,
    ) -> io::Result<Self> {
        // Bind the data-plane peer listener BEFORE spawning anything, so a bind failure is synchronous
        // (no half-started runtime). Non-blocking so the accept loop polls the shutdown flag.
        let listener = TcpListener::bind(self_data_addr)?;
        listener.set_nonblocking(true)?;

        let follower_partitions = server.follower_partitions();
        let server = Arc::new(Mutex::new(server));
        let shutdown = Arc::new(AtomicBool::new(false));
        // Build the client produce-ack gate around the SAME server Arc when a configured level was given
        // (#719). The gate and every leader-side reader share this one Arc, so the seam's parked state is
        // one source of truth.
        let client_gate = client_level.map(|level| {
            Arc::new(super::client_ack::ClientAckGate::new(
                Arc::clone(&server),
                level,
            ))
        });
        let release = match &client_gate {
            Some(g) => AckRelease::Gate(Arc::clone(g)),
            None => AckRelease::ServerOnly,
        };

        // The LEADER side: accept inbound peer links and serve fetches / record reports.
        let shutdown_l = Arc::clone(&shutdown);
        let server_l = Arc::clone(&server);
        let release_l = release.clone();
        let listener_handle = std::thread::Builder::new()
            .name("ib-dataplane-listen".to_string())
            .spawn(move || run_dataplane_listener(listener, server_l, release_l, shutdown_l))
            .expect("spawn data-plane listener thread");

        // The FOLLOWER side: one fetch loop per followed partition, dialing the leader's data address.
        let mut followers = Vec::with_capacity(follower_partitions.len());
        for (partition, leader_id) in follower_partitions {
            let Some(&leader_addr) = peer_data_addrs.get(&leader_id) else {
                // A followed partition whose leader has no resolvable data address: skip its fetch loop
                // (it will simply not replicate that partition) rather than fail the whole runtime — a
                // misconfigured single peer must not take down the data plane. Logged for the operator.
                tracing::warn!(
                    partition,
                    leader = leader_id,
                    "data plane: no peer data address for the partition leader; not following it"
                );
                continue;
            };
            let shutdown_f = Arc::clone(&shutdown);
            let server_f = Arc::clone(&server);
            let handle = std::thread::Builder::new()
                .name(format!("ib-dataplane-fetch-{partition}"))
                .spawn(move || {
                    run_follower_fetch(partition, leader_addr, server_f, &shutdown_f);
                })
                .expect("spawn data-plane follower fetch thread");
            followers.push(handle);
        }

        Ok(Self {
            server,
            client_gate,
            shutdown,
            listener: Some(listener_handle),
            followers,
        })
    }

    /// The shared server, for the produce path (when the seam is threaded) or for observability /
    /// tests: lock it briefly to consult roles or drive the seam.
    #[must_use]
    pub fn server(&self) -> &Arc<Mutex<DataPlaneServer<F, C>>> {
        &self.server
    }

    /// The CLIENT produce-ack gate (#719) this runtime drives, when it was started with
    /// [`Self::start_with_client_gate`]; `None` otherwise. The caller publishes it to its per-connection
    /// produce paths so a clustered `C2-fsync` led produce gets its wire `PubAck` only on quorum-fsync.
    #[must_use]
    pub fn client_gate(&self) -> Option<&Arc<super::client_ack::ClientAckGate<F, C>>> {
        self.client_gate.as_ref()
    }

    /// Signal shutdown and join every data-plane thread. Idempotent. Called by the broker's serve teardown
    /// alongside [`ClusterRuntime::stop`](super::runtime::ClusterRuntime::stop).
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.listener.take() {
            let _ = h.join();
        }
        for h in self.followers.drain(..) {
            let _ = h.join();
        }
    }
}

impl<F: Filesystem, C: Clock> Drop for DataPlaneRuntime<F, C> {
    fn drop(&mut self) {
        // Best-effort: a caller that forgets `stop` (or a panic on the serve path) still signals the
        // threads to wind down rather than leaking them. The deterministic join is `stop`.
        self.shutdown.store(true, Ordering::Release);
    }
}

/// The data-plane LISTENER thread: accept inbound peer connections and spawn a reader per connection.
/// Reader threads are detached; they exit on a closed/broken link or shutdown. The accept loop is
/// non-blocking and polls the shutdown flag so a stop is prompt.
// A thread entry point: it OWNS the listener, the shared server, and the shutdown flag (cloned into
// each per-connection reader it spawns) for the thread's lifetime; a borrow would fight the 'static
// spawn bound and prevent cloning into the spawned readers.
#[allow(clippy::needless_pass_by_value)]
fn run_dataplane_listener<F, C>(
    listener: TcpListener,
    server: Arc<Mutex<DataPlaneServer<F, C>>>,
    release: AckRelease<F, C>,
    shutdown: Arc<AtomicBool>,
) where
    F: Filesystem + Send + Sync + 'static,
    C: Clock + Send + 'static,
{
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // A short read timeout so a reader's blocking `recv` re-checks shutdown promptly and an
                // idle inbound link never wedges a stop.
                let _ = stream.set_read_timeout(Some(DATAPLANE_POLL));
                let server = Arc::clone(&server);
                let release = release.clone();
                let sd = Arc::clone(&shutdown);
                let _ = std::thread::Builder::new()
                    .name("ib-dataplane-read".to_string())
                    .spawn(move || {
                        run_dataplane_reader(DataPlaneLink::new(stream), &server, &release, &sd);
                    });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                sleep_interruptible(DATAPLANE_POLL, &shutdown);
            }
            Err(_) => sleep_interruptible(DATAPLANE_POLL, &shutdown),
        }
    }
}

/// A per-connection data-plane reader (the LEADER side of one follower's link): pull bounded,
/// CRC-revalidated frames off the wire and route each through the shared server, writing any response
/// back on the SAME link. A `FetchRecords` / `OffsetForLeaderEpoch` is answered with a response frame
/// served from the off-actor read plane; an `AckReplicated` report drives the quorum-ack gate (#719):
/// with a [`ClientAckGate`](super::client_ack::ClientAckGate) (`release = Gate`) each released wire
/// `PubAck` is deposited into its OWNER producer connection's outbox, for that connection to flush on
/// its own pass; without one (`release = ServerOnly`) the seam is driven and the bytes are dropped (the
/// ISR / parked state is still advanced). Below `min_isr` nothing releases (no false ack on the real
/// client wire).
///
/// Every bound in [`DataPlaneLink::recv`] is applied: a hostile / oversized / corrupt frame is a typed
/// error that drops the link, never a panic or an over-allocation (the fail-closed bounded codec).
fn run_dataplane_reader<F, C>(
    mut link: DataPlaneLink<TcpStream>,
    server: &Arc<Mutex<DataPlaneServer<F, C>>>,
    release: &AckRelease<F, C>,
    shutdown: &AtomicBool,
) where
    F: Filesystem + Send + Sync + 'static,
    C: Clock + Send + 'static,
{
    while !shutdown.load(Ordering::Acquire) {
        match link.recv() {
            // An `AckReplicated` report drives the quorum-ack gate (#719). Route it through the CLIENT
            // produce-ack gate when present (it deposits each released wire `PubAck` into its owner
            // connection's outbox, for that connection to flush on its own pass); without a gate, drive
            // the seam directly and drop the bytes (the ISR / parked state is still advanced). Handled
            // OUTSIDE the server lock — the gate takes its own server lock — so no re-entrant lock.
            Ok(Some((partition, DataPlaneFrame::AckReplicated(report)))) => {
                match release {
                    AckRelease::Gate(gate) => {
                        // Deposits each released reply into its owner connection's outbox; below min_isr
                        // releases nothing (no false ack on the real client wire).
                        let _ = gate.on_follower_report(partition, &report);
                    }
                    AckRelease::ServerOnly => {
                        let Ok(mut srv) = server.lock() else {
                            return; // poisoned: the runtime is tearing down
                        };
                        let _ = srv.on_follower_report_bytes(partition, &report);
                    }
                }
            }
            Ok(Some((partition, frame))) => {
                // Route one frame under a short lock, computing the outbound action, then RELEASE the
                // lock before writing it to the wire (never hold the server lock across a socket write).
                let action = {
                    let Ok(mut srv) = server.lock() else {
                        return; // poisoned: the runtime is tearing down
                    };
                    srv.handle_frame(partition, frame).ok()
                };
                match action {
                    Some(DataPlaneAction::SendFetchResponse {
                        partition,
                        response,
                    }) => {
                        if link
                            .send(partition, &DataPlaneFrame::FetchResponse(response))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Some(DataPlaneAction::SendEpochResponse {
                        partition,
                        response,
                    }) => {
                        if link
                            .send(partition, &DataPlaneFrame::EpochResponse(response))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Some(DataPlaneAction::ReleaseAcks { .. } | DataPlaneAction::None) | None => {}
                }
            }
            Ok(None) => return, // peer closed cleanly
            Err(DataPlaneWireError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // The read timeout elapsed with no full frame; the link buffers any partial frame, so
                // loop and re-check shutdown.
            }
            Err(e) => {
                // A framing / decode error from a misbehaving or hostile peer: drop the link. The
                // bounded codec already contained it to this typed error (no panic, no OOM).
                tracing::debug!(error = %e, "data plane: peer read error; dropping link");
                return;
            }
        }
    }
}

/// A FOLLOWER fetch loop for one partition: dial the leader's data-plane address (reconnecting on a
/// drop) and, on a cadence, send a `FetchRecords` from the follower's current frontier, apply the
/// CRC-revalidated response to its OWN replica log, and report its fsync'd frontier back. The follower
/// writes its OWN replica log via its OWN writer (the single-writer invariant: the leader is read-only
/// via the read plane; a follower owns its replica log). On a divergence the apply fails closed and the
/// loop reconnects/refetches; the leader-epoch self-heal (#599) is driven by the controller's
/// `reconcile_follower` when a future epoch-aware fetch path engages it (FLAGGED for the lineage-change
/// case; the steady-state same-lineage fetch+apply+report runs here end-to-end).
// A thread entry point: it OWNS the shared server `Arc` for the thread's lifetime; a borrow would
// fight the 'static spawn bound.
#[allow(clippy::needless_pass_by_value)]
fn run_follower_fetch<F, C>(
    partition: u64,
    leader_addr: SocketAddr,
    server: Arc<Mutex<DataPlaneServer<F, C>>>,
    shutdown: &AtomicBool,
) where
    F: Filesystem + Send + Sync + 'static,
    C: Clock + Send + 'static,
{
    while !shutdown.load(Ordering::Acquire) {
        match TcpStream::connect_timeout(&leader_addr, DATAPLANE_POLL) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(DATAPLANE_POLL));
                let _ = stream.set_write_timeout(Some(DATAPLANE_POLL));
                let mut link = DataPlaneLink::new(stream);
                follower_fetch_loop(partition, &mut link, &server, shutdown);
            }
            Err(_) => {
                // Leader not reachable yet (it may still be binding / electing); back off and retry.
                sleep_interruptible(DATAPLANE_POLL, shutdown);
            }
        }
    }
}

/// Drive one connected follower link: fetch → apply → report, on a cadence, until shutdown or the link
/// breaks (then [`run_follower_fetch`] reconnects). Each round takes the server lock only to BUILD the
/// fetch request and to APPLY the response + build the report — never across a socket read/write.
fn follower_fetch_loop<F, C>(
    partition: u64,
    link: &mut DataPlaneLink<TcpStream>,
    server: &Arc<Mutex<DataPlaneServer<F, C>>>,
    shutdown: &AtomicBool,
) where
    F: Filesystem + Send + Sync + 'static,
    C: Clock + Send + 'static,
{
    while !shutdown.load(Ordering::Acquire) {
        // Build the next fetch request under a short lock (the follower's current frontier + budgets).
        let req = {
            let Ok(srv) = server.lock() else {
                return;
            };
            match srv.seam().controller().make_fetch_request(
                partition,
                FETCH_MAX_RECORDS,
                FETCH_MAX_BYTES,
            ) {
                Ok(req) => req,
                // No longer a follower of this partition (a future rebalance): stop fetching.
                Err(_) => return,
            }
        };
        if link
            .send(partition, &DataPlaneFrame::FetchRequest(req))
            .is_err()
        {
            return; // link broke; reconnect
        }
        // Read the response (blocking up to the read timeout). On a timeout, loop and re-fetch.
        match link.recv() {
            Ok(Some((p, DataPlaneFrame::FetchResponse(resp)))) if p == partition => {
                // Apply + build the report under a short lock, then send the report off-lock.
                let report = {
                    let Ok(mut srv) = server.lock() else {
                        return;
                    };
                    if resp.record_count > 0 {
                        // Apply the CRC-revalidated bytes to the follower's own replica log. A
                        // divergence / corrupt frame fails closed (nothing from the bad frame is
                        // appended); drop this response and re-fetch from the current frontier.
                        if srv
                            .seam_mut()
                            .controller_mut()
                            .apply_fetch_response(partition, &resp)
                            .is_err()
                        {
                            // Fail-closed: reconnect + refetch from the recovered frontier.
                            return;
                        }
                    }
                    srv.seam().controller().follower_report(partition).ok()
                };
                if let Some(report) = report {
                    if link
                        .send(partition, &DataPlaneFrame::AckReplicated(report))
                        .is_err()
                    {
                        return;
                    }
                }
                // If the leader served a non-empty run there may be more to pull; loop promptly.
                // Otherwise pace the next poll so a caught-up follower does not hot-loop.
                if resp.record_count == 0 {
                    sleep_interruptible(DATAPLANE_POLL, shutdown);
                }
            }
            Ok(Some(_)) => {
                // A frame for another partition / an unexpected verb on this link: ignore + re-poll.
                sleep_interruptible(DATAPLANE_POLL, shutdown);
            }
            Err(DataPlaneWireError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // No response within the read window; re-fetch on the next loop.
            }
            // The leader closed, or a decode / link error: drop the link and reconnect.
            Ok(None) | Err(_) => return,
        }
    }
}

/// Sleep for `dur` but wake early if shutdown is set, in small slices, so a stop is never delayed by a
/// full sleep. Used by the accept poll, the dialer backoff, and the caught-up follower pacing.
fn sleep_interruptible(dur: Duration, shutdown: &AtomicBool) {
    let slice = Duration::from_millis(20);
    let mut left = dur;
    while left > Duration::ZERO && !shutdown.load(Ordering::Acquire) {
        let this = slice.min(left);
        std::thread::sleep(this);
        left = left.checked_sub(this).unwrap_or(Duration::ZERO);
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

    /// Assert a follower replica dump is BYTE-IDENTICAL to the leader over the read-plane-served range.
    ///
    /// A follower replicates frames VERBATIM + seals at the same cap, so a SEALED follower segment is the
    /// leader's same-named file byte-for-byte. The follower's LAST (still-active) segment holds the same
    /// records but seals only on its next roll, so it equals the leader's same-named SEALED file MINUS
    /// the trailing seal footer (the leader's file is a byte-identical prefix-superset). So: every
    /// follower file is a byte-identical PREFIX of the leader's same-named file, and at least one matches
    /// EXACTLY (proving real sealed replication over the live transport). The active flushed tail (and
    /// the follower's own trailing seal) close on the next roll (FLAGGED).
    fn assert_replicated_byte_identical(
        follower_dump: &[(String, Vec<u8>)],
        leader_log: &Log<InMemoryFs, ManualClock>,
    ) {
        let leader: BTreeMap<String, Vec<u8>> = dump_segments(leader_log).into_iter().collect();
        assert!(
            follower_dump.iter().any(|(_, b)| !b.is_empty()),
            "follower replicated at least one segment file"
        );
        let mut any_exact = false;
        for (name, bytes) in follower_dump {
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
            "no fully-sealed follower segment is byte-identical to the leader's over the live transport"
        );
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

    /// A leader log leaked to `'static` so the read plane keeps observing it for the test's lifetime
    /// (the engine's append actor would keep publishing in a real serve). In a real serve this is the
    /// engine's partition log; the leader role holds only an `Arc<ReadPlane>` (Send) over it, never the
    /// log — the single append actor stays the sole writer (#715).
    fn leaked_leader_log(n: u32) -> &'static Log<InMemoryFs, ManualClock> {
        let mut log = open_log();
        for i in 0..n {
            log.append(&rec(format!("rep-{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        Box::leak(Box::new(log))
    }

    /// The engine's `Arc`-shared, off-actor read plane over a leader log (#654, #715) — what the leader
    /// role serves fetches from (NO `&Log` borrow). This is what makes the `DataPlaneServer` `Send`.
    fn leader_plane(log: &Log<InMemoryFs, ManualClock>) -> Arc<ReadPlane<InMemoryFs>> {
        Arc::new(log.read_plane().expect("read plane builds"))
    }

    /// The first offset the leader's read plane does NOT serve off-actor (its sealed-served end): chain
    /// `read_range_raw` from 0 until no more sealed bytes remain below the flushed frontier. The read
    /// plane serves the SEALED prefix; this is the offset a follower converges to over the live
    /// transport before the active (flushed-but-unsealed) tail seals.
    fn plane_served_end(plane: &ReadPlane<InMemoryFs>) -> u64 {
        let flushed = plane.flushed();
        let mut next = 0u64;
        let mut guard = 0u32;
        while next < flushed {
            guard += 1;
            assert!(guard < 100_000, "read-plane chain failed to terminate");
            let raw = plane
                .read_range_raw(ironbus_core::types::Offset::new(next), 1_000, None)
                .expect("read plane serves");
            let advanced = raw.run.next_offset.get();
            if advanced > next {
                next = advanced;
            } else {
                break;
            }
        }
        next
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

    /// Service one accept + one read pass on the leader serve loop. The leader serve loop is now `Send`
    /// (it serves through the `Arc`-shared read plane #654/#715, no `&Log` borrow — see the
    /// `the_send_data_plane_server_runs_on_its_own_thread` test); this cooperative single-thread driver
    /// is kept for the deterministic capstone scenario. Accepts any new follower link (non-blocking),
    /// then services each link once: a `FetchRecords` / `OffsetForLeaderEpoch` is answered with a
    /// response frame; an `AckReplicated` report drives the quorum-ack gate and any
    /// released wire-`PubAck` bytes are pushed onto `released`.
    fn pump_leader_once(
        server: &mut DataPlaneServer<InMemoryFs, ManualClock>,
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
    /// `TcpStream`. The whole cluster runs COOPERATIVELY on one thread over real sockets (the transport
    /// is real; only the driving is single-threaded, which keeps the capstone test deterministic). The
    /// server is now `Send` (#715) and CAN run on its own thread — the
    /// `the_send_data_plane_server_runs_on_its_own_thread` test asserts exactly that.
    struct LiveFollower {
        server: DataPlaneServer<InMemoryFs, ManualClock>,
        link: DataPlaneLink<TcpStream>,
        partition: u64,
    }

    impl LiveFollower {
        fn connect(
            server: DataPlaneServer<InMemoryFs, ManualClock>,
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

        /// DRAIN every response that has arrived (the read-plane leader serves SINGLE-SEGMENT runs, so a
        /// catch-up needs several round-trips and several responses can be in flight on the socket at
        /// once), applying each CONTIGUOUS one in order and DROPPING any stale/duplicate response whose
        /// `first_offset` no longer matches the follower's current head (a perfectly valid pull-model
        /// outcome: the follower simply re-fetches from where it is). Then report the follower's fsync'd
        /// frontier back to the leader (driving the quorum-ack gate on the next leader pump).
        fn recv_apply_and_report(&mut self) {
            while let Ok(Some((p, DataPlaneFrame::FetchResponse(resp)))) = self.link.recv() {
                assert_eq!(p, self.partition);
                // The follower's current head (the offset its next contiguous response must start at).
                let want = self
                    .server
                    .seam()
                    .controller()
                    .make_fetch_request(self.partition, 1, 0)
                    .expect("follower head")
                    .from_offset;
                // Drop a stale/duplicate or already-applied response (a non-contiguous one): the pull
                // model just re-fetches. An empty run (caught up) is contiguous and applies as a no-op.
                if resp.record_count > 0 && resp.first_offset != want {
                    continue;
                }
                self.server
                    .seam_mut()
                    .controller_mut()
                    .handle_frame(self.partition, DataPlaneFrame::FetchResponse(resp))
                    .expect("follower applies the contiguous response");
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

        // The leader (node 1) holds a log of 25 records, fsync'd. The leader DataPlaneServer serves it
        // through the engine's OFF-ACTOR read plane (#654, #715) — NOT a &Log borrow; the leader never
        // writes (or borrows) its log. The read plane serves the SEALED prefix; `served_end` is the
        // offset a follower converges to over the live transport before the active tail seals (FLAGGED).
        let leader_log = leaked_leader_log(25);
        let leader_hw = leader_log.flushed_offset().get();
        assert_eq!(leader_hw, 25);
        let leader_pl = leader_plane(leader_log);
        let served_end = plane_served_end(&leader_pl);
        assert!(
            served_end > 0 && served_end <= leader_hw,
            "the read plane serves a non-empty sealed prefix (served_end={served_end})"
        );

        let mut leader_server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| {
                if p == P {
                    Some(Arc::clone(&leader_pl))
                } else {
                    None
                }
            },
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .expect("leader server builds from placement");
        assert!(leader_server.seam().controller().is_leader(P));

        // PARK a real C2-fsync produce's wire PubAck for the last SEALED-served record: the leader has
        // locally fsync'd (I2) but NO follower has the data, so the 2-of-3 quorum is not met yet.
        let offset = served_end - 1;
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
            if (f2.high_watermark() >= served_end && f3.high_watermark() >= served_end)
                || Instant::now() > deadline
            {
                break;
            }
        }

        assert_eq!(
            f2.high_watermark(),
            served_end,
            "follower 2 caught up to the leader's sealed-served prefix over the live transport"
        );
        assert_eq!(
            f3.high_watermark(),
            served_end,
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

        // Each follower's replica is BYTE-IDENTICAL to the leader over the read-plane-served prefix,
        // over the live transport: every replicated segment FILE matches the leader's same-named file.
        assert_replicated_byte_identical(&f2.replica_dump(), leader_log);
        assert_replicated_byte_identical(&f3.replica_dump(), leader_log);
    }

    /// THE #715 `Send` PROOF: a leader [`DataPlaneServer`] built from the committed placement (serving
    /// through the off-actor read plane #654, NOT a `&Log` borrow) is `Send` and actually RUNS its
    /// leader serve loop on ITS OWN dedicated peer-I/O thread — exactly the engine-ownership change #715
    /// lands. A real follower over a loopback `TcpStream` (on the main thread) replicates the leader's
    /// sealed prefix byte-identically, with the leader serving from the OTHER thread. Before #715 the
    /// controller held a `&Log` and was NOT `Send`, so this `thread::spawn(move || ...)` would not even
    /// compile. The leader thread never writes the leader's log — it READS via the `Arc`-shared read
    /// plane; the single append actor (here, the test owning the leaked log) remains the sole writer.
    #[test]
    fn the_send_data_plane_server_runs_on_its_own_thread() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;

        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 7,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();

        let leader_log = leaked_leader_log(25);
        let leader_pl = leader_plane(leader_log);
        let served_end = plane_served_end(&leader_pl);
        assert!(served_end > 0);

        let mut leader_server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| {
                if p == P {
                    Some(Arc::clone(&leader_pl))
                } else {
                    None
                }
            },
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .expect("leader server builds");

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind leader listener");
        listener.set_nonblocking(true).unwrap();
        let leader_addr = listener.local_addr().unwrap();

        // MOVE the (now `Send`) leader server onto its OWN thread and serve from there. This is the
        // whole point of #715: the data plane runs alongside the append actor, not on it.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let leader_handle = std::thread::spawn(move || {
            let mut links: Vec<DataPlaneLink<TcpStream>> = Vec::new();
            let mut released: Vec<Vec<u8>> = Vec::new();
            ready_tx.send(()).ok();
            while !stop_thread.load(Ordering::Acquire) {
                pump_leader_once(&mut leader_server, &listener, &mut links, &mut released);
            }
            // Return the server back so its replica/leader state can be inspected (it stays Send).
            leader_server
        });
        ready_rx.recv().expect("leader thread started");

        // A real follower on THIS thread fetches over a loopback socket from the leader's OWN thread.
        let follower = DataPlaneServer::from_placements(
            2,
            &[(
                P,
                Placement {
                    replicas: vec![1, 2, 3],
                    leader: 1,
                    epoch: 7,
                },
            )]
            .into_iter()
            .collect(),
            quorum3(),
            |_| None,
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .expect("follower builds");
        let mut f = LiveFollower::connect(follower, P, leader_addr);

        let deadline = Instant::now() + Duration::from_secs(25);
        while f.high_watermark() < served_end && Instant::now() < deadline {
            f.send_fetch();
            std::thread::sleep(Duration::from_millis(2));
            f.recv_apply_and_report();
        }
        assert_eq!(
            f.high_watermark(),
            served_end,
            "the follower caught up to the leader's sealed prefix with the leader serving on ITS OWN thread"
        );
        // The leader served byte-identical replicated bytes from the other thread.
        assert_replicated_byte_identical(&f.replica_dump(), leader_log);

        stop.store(true, Ordering::Release);
        let _server = leader_handle.join().expect("leader thread joins cleanly");
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
        let leader_pl = leader_plane(leader_log);
        let mut server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| {
                if p == P {
                    Some(Arc::clone(&leader_pl))
                } else {
                    None
                }
            },
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .unwrap();

        // The seam parks a C2-fsync ack for a led partition regardless of the read-plane content (the
        // gate's no-quorum release is what is under test); offset 9 is a valid produced offset.
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
        let leader_pl = leader_plane(leader_log);

        // Rebuild the leader server (as on a restart): leader role re-established (serving through the
        // read plane #654/#715), ISR seeded from the recovered durable head (the read plane's flushed
        // frontier), no follower yet => the 2-of-3 quorum is 0 (the no-false-ack rule).
        let leader = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| {
                if p == P {
                    Some(Arc::clone(&leader_pl))
                } else {
                    None
                }
            },
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
    /// crashing the leader serve loop — the bounded codec on the live path. The leader serve loop is now
    /// `Send` (it serves through the `Arc`-shared read plane #654/#715, no `&Log` borrow); the test
    /// keeps it on this thread for determinism. A hostile probe + a well-behaved fetch arrive from a
    /// worker thread, and the leader must keep serving the valid fetch.
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
        let leader_pl = leader_plane(leader_log);
        let mut server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| {
                if p == P {
                    Some(Arc::clone(&leader_pl))
                } else {
                    None
                }
            },
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

// ===================================================================================================
//  #717 INTEGRATION TESTS: the LIVE DataPlaneRuntime — construct + spawn + DRIVE the data plane over
//  real sockets, exactly as `run_broker` does. A real 3-node serve cluster (1 leader runtime + 2
//  follower runtimes, each on its OWN threads over real loopback TcpStreams) replicates produced data
//  byte-identical + a C2-fsync produce's parked ack is released ONLY on quorum-fsync driven by REAL
//  wire reports; below min_isr it stays parked; a node restart resumes. Real on-disk StdFs (Unix-only,
//  like serve) so the runtime's `Send + Sync` bounds are exercised on production filesystem types, with
//  a deterministic ManualClock so the on-disk segment-header bytes are byte-identical leader<->follower.
// ===================================================================================================
#[cfg(all(test, unix))]
#[allow(clippy::similar_names, clippy::too_many_lines)]
mod live_runtime_tests {
    use super::*;
    use crate::cluster::isr::IsrConfig;
    use crate::cluster::state_machine::Placement;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::RecordFlags;
    use ironbus_proto::frame::encode_frame as proto_encode_frame;
    use ironbus_proto::message::{encode_pub_ack, PubAckBody};
    use ironbus_storage::fs::StdFs;
    use ironbus_storage::io::RandomAccessFile;
    use ironbus_storage::log::{Append, Log, LogConfig};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::time::{Duration, Instant};

    // A real on-disk StdFs backend (real sockets + real files), but a deterministic ManualClock at
    // zero so the SEGMENT HEADER timestamps (stamped from the clock seam) are byte-identical between the
    // leader and the follower — exactly the discipline the in-memory capstone test uses. The data plane
    // is generic over the clock; production wires the broker's SystemClock, but byte-identity of frames
    // (the property under test) is what makes ManualClock the right choice here.

    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
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

    /// A real on-disk leader log with `n` records, fsync'd, leaked to `'static` so its read plane keeps
    /// observing it for the test's lifetime (in a real serve the engine's append actor owns it).
    fn leaked_disk_leader(dir: &std::path::Path, n: u32) -> &'static Log<StdFs, ManualClock> {
        let fs = StdFs::new(dir.to_path_buf());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).expect("leader log opens");
        for i in 0..n {
            log.append(&rec(format!("rep-{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        Box::leak(Box::new(log))
    }

    /// The off-actor read plane over a leader log — what the leader role serves fetches from (no &Log).
    fn disk_leader_plane(log: &Log<StdFs, ManualClock>) -> Arc<ReadPlane<StdFs>> {
        Arc::new(log.read_plane().expect("read plane builds"))
    }

    /// The first offset the read plane does NOT serve off-actor (its sealed-served end): a follower
    /// converges to this over the live transport before the active (flushed-but-unsealed) tail seals.
    fn plane_served_end(plane: &ReadPlane<StdFs>) -> u64 {
        let flushed = plane.flushed();
        let mut next = 0u64;
        let mut guard = 0u32;
        while next < flushed {
            guard += 1;
            assert!(guard < 100_000, "read-plane chain failed to terminate");
            let raw = plane
                .read_range_raw(ironbus_core::types::Offset::new(next), 1_000, None)
                .expect("read plane serves");
            let advanced = raw.run.next_offset.get();
            if advanced > next {
                next = advanced;
            } else {
                break;
            }
        }
        next
    }

    /// A replica-log factory that opens each follower's replica as a real on-disk `StdFs` log under a
    /// per-node temp dir (the same shape the CLI `DiskReplicaLogs` uses under `<data_dir>/replicas/`).
    struct DiskReplicaLogs {
        root: std::path::PathBuf,
    }
    impl ReplicaLogFactory<StdFs, ManualClock> for DiskReplicaLogs {
        fn open_replica_log(&self, partition: u64) -> Result<Log<StdFs, ManualClock>, String> {
            let dir = self.root.join("replicas").join(partition.to_string());
            std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
            Log::open(StdFs::new(dir), ManualClock::new(), small_config())
                .map_err(|e| format!("open replica {partition}: {e}"))
        }
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

    /// Bind an ephemeral loopback port, read it, drop the listener (the runtime rebinds it). A small
    /// TOCTOU window, fine for a quiet in-process loopback test.
    fn free_port() -> u16 {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        pred()
    }

    fn dump_segments(log: &Log<StdFs, ManualClock>) -> Vec<(String, Vec<u8>)> {
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

    /// Assert a follower replica dump is a byte-identical prefix of the leader, with at least one fully
    /// sealed segment byte-for-byte equal (real sealed replication over the live transport).
    fn assert_replicated_byte_identical(
        follower_dump: &[(String, Vec<u8>)],
        leader_log: &Log<StdFs, ManualClock>,
    ) {
        let leader: BTreeMap<String, Vec<u8>> = dump_segments(leader_log).into_iter().collect();
        assert!(
            follower_dump.iter().any(|(_, b)| !b.is_empty()),
            "follower replicated at least one segment file"
        );
        let mut any_exact = false;
        for (name, bytes) in follower_dump {
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
            "no fully-sealed follower segment is byte-identical to the leader's over the live runtime"
        );
    }

    /// THE #717 CAPSTONE: a real 3-node serve cluster driven by the actual [`DataPlaneRuntime`] (the
    /// SAME construct `run_broker` spawns) over real loopback sockets replicates produced data
    /// byte-identical, and a parked C2-fsync produce's wire ack is released ONLY once the ISR quorum
    /// reports fsync over the REAL wire. Each follower runs its OWN `DataPlaneRuntime` on its OWN threads
    /// (listener + fetch loop); the leader runs its own. Nothing is hand-driven — the runtimes' threads
    /// do the fetch / apply / report / serve / gate over the sockets.
    #[test]
    fn live_three_node_runtime_replicates_and_quorum_gates_a_c2_fsync_produce() {
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 5,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();

        // Allocate one DATA-plane port per node (the runtime binds these directly here; in the CLI they
        // are derived from the metadata addr via `dataplane_addr`).
        let data_addrs: BTreeMap<u64, SocketAddr> = [1u64, 2, 3]
            .into_iter()
            .map(|id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
            .collect();

        let leader_dir = tempfile::tempdir().expect("leader dir");
        let leader_log = leaked_disk_leader(leader_dir.path(), 25);
        let leader_pl = disk_leader_plane(leader_log);
        let served_end = plane_served_end(&leader_pl);
        assert!(served_end > 0, "the read plane serves a non-empty prefix");

        // The LEADER runtime (node 1): leader role over the read plane, listening on its data port.
        let leader_server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| (p == P).then(|| Arc::clone(&leader_pl)),
            &DiskReplicaLogs {
                root: leader_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .expect("leader server builds");
        assert!(leader_server.seam().controller().is_leader(P));

        // PARK a real C2-fsync produce's wire PubAck for the last sealed-served record, BEFORE the
        // followers come up: the leader has locally fsync'd (I2) but no follower has the data, so the
        // 2-of-3 quorum is not met — the ack parks (no false ack).
        let offset = served_end - 1;
        let reply = wire_pub_ack(offset);
        let leader_rt = {
            let mut server = leader_server;
            let disposition = server
                .seam_mut()
                .on_local_fsynced_ack(
                    crate::cluster::ack_level::ClusterAckLevel::C2Fsync,
                    P,
                    offset,
                    reply,
                )
                .expect("park");
            assert_eq!(
                disposition,
                crate::cluster::dataplane::AckDisposition::Parked,
                "a clustered C2-fsync led produce parks its wire PubAck (no quorum yet)"
            );
            assert_eq!(server.seam().parked_len(), 1, "the ack is withheld");
            DataPlaneRuntime::start(server, data_addrs[&1], &data_addrs).expect("leader runtime")
        };

        // The two FOLLOWER runtimes (nodes 2 + 3), each from the SAME committed placement, each with its
        // own on-disk replica log + its own threads dialing the leader's data port.
        let f2_dir = tempfile::tempdir().expect("f2 dir");
        let f3_dir = tempfile::tempdir().expect("f3 dir");
        let follower2 = DataPlaneServer::from_placements(
            2,
            &placements,
            quorum3(),
            |_| None,
            &DiskReplicaLogs {
                root: f2_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .expect("f2 server");
        let follower3 = DataPlaneServer::from_placements(
            3,
            &placements,
            quorum3(),
            |_| None,
            &DiskReplicaLogs {
                root: f3_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .expect("f3 server");
        assert!(follower2.seam().controller().is_follower(P));
        assert_eq!(follower2.follower_leader(P), Some(1));

        let f2_rt = DataPlaneRuntime::start(follower2, data_addrs[&2], &data_addrs).expect("f2 rt");
        let f3_rt = DataPlaneRuntime::start(follower3, data_addrs[&3], &data_addrs).expect("f3 rt");

        // The runtimes' own threads drive everything. Wait until BOTH followers have caught up to the
        // leader's sealed-served prefix over the live transport.
        let f2_hw = || {
            f2_rt
                .server()
                .lock()
                .unwrap()
                .seam()
                .controller()
                .follower_high_watermark(P)
                .unwrap_or(0)
        };
        let f3_hw = || {
            f3_rt
                .server()
                .lock()
                .unwrap()
                .seam()
                .controller()
                .follower_high_watermark(P)
                .unwrap_or(0)
        };
        let caught_up = wait_until(Duration::from_secs(30), || {
            f2_hw() >= served_end && f3_hw() >= served_end
        });
        assert!(
            caught_up,
            "both followers caught up over the live runtime (f2={}, f3={}, served_end={served_end})",
            f2_hw(),
            f3_hw()
        );

        // The parked C2-fsync ack is RELEASED once a 2-of-3 quorum reported fsync over the wire: the
        // leader's gate no longer withholds it (the real follower reports drove the quorum-commit past
        // the offset). This proves the wire ack WAITED for quorum-fsync end-to-end via the live runtime.
        let released = wait_until(Duration::from_secs(15), || {
            leader_rt.server().lock().unwrap().seam().parked_len() == 0
        });
        assert!(
            released,
            "the parked C2-fsync wire ack is released ONLY after the ISR quorum fsync'd over the wire"
        );
        assert_eq!(
            leader_rt
                .server()
                .lock()
                .unwrap()
                .seam()
                .controller()
                .pending_ack_count(P),
            0,
            "no produce ack remains withheld once quorum-fsync'd"
        );

        // Each follower's replica is BYTE-IDENTICAL to the leader over the served prefix, over the live
        // runtime: lock the server and dump the follower's own replica log.
        {
            let f2 = f2_rt.server().lock().unwrap();
            let dump = dump_segments(f2.seam().controller().follower_log(P).unwrap());
            assert_replicated_byte_identical(&dump, leader_log);
        }
        {
            let f3 = f3_rt.server().lock().unwrap();
            let dump = dump_segments(f3.seam().controller().follower_log(P).unwrap());
            assert_replicated_byte_identical(&dump, leader_log);
        }

        let mut leader_rt = leader_rt;
        let mut f2_rt = f2_rt;
        let mut f3_rt = f3_rt;
        leader_rt.stop();
        f2_rt.stop();
        f3_rt.stop();
    }

    /// Below `min_isr` a parked C2-fsync ack is NEVER released over the live runtime: node 1 leads
    /// `{1,2,3}` with `min_isr=2`, but NO follower ever comes up, so the ISR is the leader alone (size
    /// 1 < 2). The leader runtime runs (its listener accepts nothing useful), and the parked ack stays
    /// withheld — no false ack on the real wire.
    #[test]
    fn live_runtime_below_min_isr_keeps_the_wire_ack_parked() {
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 1,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        let data_addrs: BTreeMap<u64, SocketAddr> = (1u64..=3)
            .map(|id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
            .collect();

        let dir = tempfile::tempdir().expect("dir");
        let leader_log = leaked_disk_leader(dir.path(), 10);
        let leader_pl = disk_leader_plane(leader_log);
        let mut server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| (p == P).then(|| Arc::clone(&leader_pl)),
            &DiskReplicaLogs {
                root: dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .unwrap();
        let offset = 9;
        assert_eq!(
            server
                .seam_mut()
                .on_local_fsynced_ack(
                    crate::cluster::ack_level::ClusterAckLevel::C2Fsync,
                    P,
                    offset,
                    wire_pub_ack(offset),
                )
                .unwrap(),
            crate::cluster::dataplane::AckDisposition::Parked
        );
        let mut rt = DataPlaneRuntime::start(server, data_addrs[&1], &data_addrs).expect("rt");

        // Give the runtime ample time; with no follower ever reporting, the ack must stay parked.
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            rt.server().lock().unwrap().seam().parked_len(),
            1,
            "below min_isr the wire ack is NEVER released (no false ack on the real wire)"
        );
        rt.stop();
    }

    /// A node RESTART resumes replication over the live runtime: a follower runtime replicates, is
    /// stopped, then a FRESH runtime is started over the SAME replica-log dir (as on a process restart).
    /// It recovers its replica log and resumes fetching from its recovered head, catching back up to the
    /// leader's served prefix.
    #[test]
    fn live_runtime_follower_restart_resumes_replication() {
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2],
            leader: 1,
            epoch: 3,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        // R=2, min_isr=1: a single in-sync follower (or the leader alone) is a quorum here — this test
        // is about replication resuming on restart, not the quorum-ack gate.
        let isr = IsrConfig {
            min_isr: 1,
            max_lag_records: 0,
        };
        let data_addrs: BTreeMap<u64, SocketAddr> = (1u64..=2)
            .map(|id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
            .collect();

        let leader_dir = tempfile::tempdir().expect("leader dir");
        let leader_log = leaked_disk_leader(leader_dir.path(), 20);
        let leader_pl = disk_leader_plane(leader_log);
        let served_end = plane_served_end(&leader_pl);

        let leader_server = DataPlaneServer::from_placements(
            1,
            &placements,
            isr,
            |p| (p == P).then(|| Arc::clone(&leader_pl)),
            &DiskReplicaLogs {
                root: leader_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .unwrap();
        let mut leader_rt =
            DataPlaneRuntime::start(leader_server, data_addrs[&1], &data_addrs).expect("leader rt");

        // The follower's replica dir is STABLE across the restart (a real on-disk recovery).
        let f_dir = tempfile::tempdir().expect("f dir");
        let mk_follower = || {
            DataPlaneServer::from_placements(
                2,
                &placements,
                isr,
                |_| None,
                &DiskReplicaLogs {
                    root: f_dir.path().to_path_buf(),
                },
                |_| EpochCache::new(),
            )
            .expect("follower server")
        };

        // First incarnation: catch up.
        let mut f_rt =
            DataPlaneRuntime::start(mk_follower(), data_addrs[&2], &data_addrs).expect("f rt");
        let hw = |rt: &DataPlaneRuntime<StdFs, ManualClock>| {
            rt.server()
                .lock()
                .unwrap()
                .seam()
                .controller()
                .follower_high_watermark(P)
                .unwrap_or(0)
        };
        assert!(
            wait_until(Duration::from_secs(30), || hw(&f_rt) >= served_end),
            "the follower caught up before the restart"
        );
        f_rt.stop();

        // Restart over the SAME replica dir: the fresh runtime recovers the replica log and resumes from
        // its recovered head (already caught up), staying at the served prefix.
        let mut f_rt2 =
            DataPlaneRuntime::start(mk_follower(), data_addrs[&2], &data_addrs).expect("f rt2");
        assert!(
            wait_until(Duration::from_secs(30), || hw(&f_rt2) >= served_end),
            "the restarted follower recovered its replica log and resumed at the served prefix (hw={})",
            hw(&f_rt2)
        );
        // Its recovered replica is byte-identical to the leader.
        {
            let f = f_rt2.server().lock().unwrap();
            let dump = dump_segments(f.seam().controller().follower_log(P).unwrap());
            assert_replicated_byte_identical(&dump, leader_log);
        }
        f_rt2.stop();
        leader_rt.stop();
    }
}
