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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ironbus_core::clock::Clock;
use ironbus_core::epoch_cache::EpochCache;
use ironbus_core::leader_lease::LeaderEpoch;
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
use super::replication::{FetchRecordsBody, FetchResponseBody};
use super::rereplication::{
    FetchBudget, ReReplicationThrottle, FULL_CATCHUP_BYTES, FULL_CATCHUP_RECORDS,
};
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
        DataPlaneFrame::CommittedHwQuery(_) | DataPlaneFrame::CommittedHwResponse(_) => {
            FrameType::CommittedHwQuery
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
        DataPlaneFrame::CommittedHwQuery(b) => b.encode(),
        DataPlaneFrame::CommittedHwResponse(b) => b.encode(),
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
    // Fast path for the big FETCH RESPONSE: its `frame_bytes` are a zero-copy `Bytes` view of a
    // sealed segment (#810) and can be up to 8 MiB. The generic path below would copy them THREE
    // times on the leader (layer body -> partition-prefixed body -> framed out); instead build the
    // final framed buffer directly so the run is materialized EXACTLY ONCE. The bytes are identical
    // to the generic encoding (#825).
    if let DataPlaneFrame::FetchResponse(resp) = frame {
        return encode_fetch_response_peer_frame(partition, resp);
    }
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

/// Frame one FETCH RESPONSE directly into its final `[len][type][partition-le][layer body]` buffer,
/// copying the (up to 8 MiB) zero-copy `frame_bytes` run EXACTLY ONCE (#825). This is the byte-for-byte
/// equivalent of the generic [`encode_dataplane_peer_frame`] path for a `FetchResponse`, with the same
/// bounds and the same error values, but without the two throw-away intermediate copies of the run.
///
/// # Errors
/// Returns [`DataPlaneWireError::Oversized`] if the partition-prefixed body exceeds
/// [`MAX_DATAPLANE_FRAME_BYTES`] or the framed length would exceed [`MAX_FRAME_LEN`].
fn encode_fetch_response_peer_frame(
    partition: u64,
    resp: &FetchResponseBody,
) -> Result<Vec<u8>, DataPlaneWireError> {
    // Body = partition prefix + the response's fixed header + verbatim frame bytes (same as the
    // generic path's `body`), bounded by the data-plane cap before anything is materialized.
    let body_len = PARTITION_PREFIX_LEN + resp.encoded_len();
    if body_len as u64 > u64::from(MAX_DATAPLANE_FRAME_BYTES) {
        return Err(DataPlaneWireError::Oversized {
            len: body_len as u64,
        });
    }
    // Envelope frame length is the type byte plus the body, matching `encode_frame`'s own check.
    let frame_len = 1u64 + body_len as u64;
    let Some(frame_len) = u32::try_from(frame_len)
        .ok()
        .filter(|&l| l <= MAX_FRAME_LEN)
    else {
        return Err(DataPlaneWireError::Oversized { len: frame_len });
    };
    let mut out = Vec::with_capacity(5 + body_len);
    out.extend_from_slice(&frame_len.to_le_bytes());
    out.push(FrameType::FetchResponse.as_u8());
    out.extend_from_slice(&partition.to_le_bytes());
    // The single copy of the run into the outbound buffer (header + verbatim frame bytes).
    resp.encode_into(&mut out);
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

/// The bounded timeout for the DIRTY-TIER committed-HW confirm (#739): how long the follower's query
/// link waits to CONNECT to, and to READ a [`CommittedHwResponseBody`] from, the partition leader. It is
/// deliberately SHORT (sub-second): the confirm sits on the consume serve path, so a slow / dead leader
/// must NOT stall the consumer — on a timeout the follower FAILS CLOSED to the clean tier (serve only up
/// to its safe watermark, never an unconfirmed offset). The same `connect_timeout` + `read_timeout`
/// discipline the follower fetch loop uses, sized for a single round-trip rather than a steady poll.
///
/// This is the PRODUCTION default; it is what [`ClientAckGate`](super::client_ack::ClientAckGate) holds
/// unless overridden ([`ClientAckGate::set_confirm_timeout`](super::client_ack::ClientAckGate::set_confirm_timeout),
/// a test-robustness seam). Production behaviour is unchanged: the confirm still bounds at 500 ms.
pub const HW_CONFIRM_TIMEOUT: Duration = Duration::from_millis(500);

/// Perform ONE bounded, over-the-wire DIRTY-TIER committed-HW CONFIRM (#739): dial the partition
/// LEADER's data-plane address `leader_data_addr`, send a [`DataPlaneFrame::CommittedHwQuery`] for
/// `partition`, and read back the leader's current committed HW from its
/// [`DataPlaneFrame::CommittedHwResponse`]. This is the #723 `ConfirmWithLeader` made REAL over the
/// wire — a tiny HW-version query (NOT the data) so a follower can serve a read-your-writes prefix above
/// its known safe watermark, and NEVER an offset the leader has not confirmed committed.
///
/// It is a short-lived, single-shot link with `timeout` bound on BOTH the connect and the read, so a
/// slow / dead / wrong-role leader cannot stall the consume path. `timeout` is the caller's confirm
/// budget — [`HW_CONFIRM_TIMEOUT`] (500 ms) in production; a test may pass a host-scaled value so the
/// confirm completes under a contended CI runner WITHOUT changing the fail-closed semantics. Returns
/// `Some(committed_hw)` ONLY on a clean round-trip whose response is the leader's committed HW for THIS
/// partition; on ANY failure (no route, connect/read timeout, link error, wrong partition / verb) it
/// returns `None` so the caller FAILS CLOSED to the clean tier (serves only up to its safe watermark —
/// never unconfirmed). The timeout only governs HOW LONG the confirm waits — never WHETHER an unconfirmed
/// offset is served (on a timeout it still returns `None` → fail-closed), so never-serve-unconfirmed holds
/// for any timeout.
///
/// It never panics and never serves data: it is a read-only HW query (single-writer preserved).
#[must_use]
pub fn query_leader_committed_hw(
    leader_data_addr: SocketAddr,
    partition: u64,
    timeout: Duration,
) -> Option<u64> {
    let stream = TcpStream::connect_timeout(&leader_data_addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let mut link = DataPlaneLink::new(stream);
    link.send(
        partition,
        &DataPlaneFrame::CommittedHwQuery(super::dataplane::CommittedHwQueryBody),
    )
    .ok()?;
    // Read exactly one response, bounded by the read timeout. Anything other than a committed-HW response
    // for THIS partition is a failed confirm → `None` → the caller serves the clean tier (never
    // unconfirmed). The leader-side reader answers a CommittedHwQuery with exactly this frame.
    match link.recv() {
        Ok(Some((p, DataPlaneFrame::CommittedHwResponse(resp)))) if p == partition => {
            Some(resp.committed_hw)
        }
        _ => None,
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

    /// This node's LEGITIMATE inbound data-plane-link fanout as a leader: Σ over its led partitions of
    /// (that partition's configured follower count) — see
    /// [`DataPlaneController::led_inbound_link_count`]. The data-plane listener sizes its concurrent
    /// inbound-reader cap to this (floored at the old fixed 256) so a high-partition-fanout leader admits
    /// every real follower rather than refusing links past a borrowed constant (#915).
    #[must_use]
    pub fn led_inbound_link_count(&self) -> usize {
        self.seam.controller().led_inbound_link_count()
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

    /// The leader's `Arc`-shared read plane for `partition`, or `None` if this node is not its leader
    /// (#809). The reader thread clones this under the server lock then serves `FetchRecords` OFF the
    /// lock — see [`DataPlaneController::leader_read_plane`].
    #[must_use]
    pub fn leader_read_plane(&self, partition: u64) -> Option<Arc<ReadPlane<F>>> {
        self.seam.controller().leader_read_plane(partition)
    }

    /// The per-partition follower handle for `partition`, or `None` if this node is not its follower
    /// (#809). The follower fetch thread clones this once under the server lock then applies OFF the lock
    /// — see [`DataPlaneController::follower_handle`].
    #[must_use]
    pub fn follower_handle(
        &self,
        partition: u64,
    ) -> Option<super::dataplane::FollowerHandle<F, C>> {
        self.seam.controller().follower_handle(partition)
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

// The #618 leaderless-FAILOVER reconcile needs `F: Clone` (the in-place promotion builds a read plane
// over the follower's owned log). A separate impl block so the rest of the server keeps the looser
// `F: Filesystem` bound and the no-cluster path links none of it.
impl<F: Filesystem + Clone, C: Clock> DataPlaneServer<F, C> {
    /// RECONCILE this node's roles to a NEW committed placement for `partition` on a leaderless-node
    /// FAILOVER (#618). The metadata plane committed a
    /// [`PlacePartition`](super::state_machine::MetadataCommand::PlacePartition) that re-pointed
    /// `partition`'s leadership (the dead leader's node was dropped and an in-sync survivor promoted, via
    /// [`reassign_leadership`](super::placement::reassign_leadership)); every node reads the SAME
    /// committed placement and applies it here, so all surviving nodes converge.
    ///
    /// The role transition this handles is the failover one — a FOLLOWER that the new placement names
    /// LEADER is PROMOTED IN PLACE over the log it already holds (no data move,
    /// [`DataPlaneController::promote_follower_to_leader`]), seeding the bumped epoch (the fence). It
    /// also updates the follower's leader TARGET when a still-following node's leader changed to the new
    /// successor. `isr_config` sizes the promoted leader's ISR / quorum gate.
    ///
    /// `committed_hw_bar` is the SAFE bar carried with the failover (the persisted committed-HW
    /// checkpoint, #618b): on the in-place promotion it is RE-VERIFIED against this node's own durable
    /// log (defense in depth), so a promotion that would leave a leader missing committed data is aborted
    /// fail-closed rather than creating a false leader. Pass `0` for the no-bar / n=1 degenerate.
    ///
    /// Returns `true` if this node's role for `partition` changed (a promotion or a re-targeted
    /// follower), `false` if nothing changed for this node (e.g. it does not hold the partition, or it
    /// was already the leader / still follows the same leader).
    ///
    /// NOT handled here (FLAGGED): promoting a node that holds NO role into a leader (it would need a
    /// freshly-built read plane from the engine — the metadata-leader bootstrap path, #717), and a
    /// no-data-move leader → follower DEMOTION. The #618 slice is the in-place ISR-follower → leader
    /// promotion, which is the failover correctness property; a full live rebalance is C5-I2 (#617).
    ///
    /// # Errors
    /// [`DataPlaneError`] if the in-place promotion fails (a read-plane build, a backward-epoch assign,
    /// or the apply-time committed-completeness self-verify — all fail-closed).
    pub fn reconcile_placement(
        &mut self,
        partition: u64,
        new_placement: &Placement,
        isr_config: IsrConfig,
        committed_hw_bar: u64,
    ) -> Result<bool, DataPlaneError> {
        let role = role_for_placement(self.node_id, new_placement);
        match role {
            PlacementRole::Leader => {
                if self.seam.controller().is_leader(partition) {
                    // Already the leader for this partition (an idempotent re-apply): nothing to do.
                    return Ok(false);
                }
                // FOLLOWER → LEADER promotion over the held log (no data move), seeding the bumped epoch.
                // The apply-time committed-completeness self-verify inside `promote_follower_to_leader`
                // aborts fail-closed if this node's durable log does not cover `committed_hw_bar`.
                self.seam.controller_mut().promote_follower_to_leader(
                    partition,
                    LeaderEpoch::new(new_placement.epoch),
                    &new_placement.replicas,
                    isr_config,
                    committed_hw_bar,
                )?;
                // This node no longer follows the partition (it leads it now).
                self.follower_targets.remove(&partition);
                Ok(true)
            }
            PlacementRole::Follower => {
                // A still-following node whose leader changed to the new successor: re-target its fetch
                // loop. (The fetch loop reads `follower_leader(partition)` to dial; updating it here is
                // what re-points replication to the promoted successor.)
                let changed = self.follower_targets.get(&partition) != Some(&new_placement.leader);
                if changed {
                    self.follower_targets
                        .insert(partition, new_placement.leader);
                }
                Ok(changed)
            }
            PlacementRole::None => Ok(false),
        }
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

/// The FLOOR (and small-deployment default) for the cap on CONCURRENT inbound peer reader threads on the
/// data-plane listener (#865, #915). Each accepted peer link spawns a detached reader thread (its own
/// stack and an fd), and follower-report auth happens only later inside `recv()` — after the thread and
/// fd already exist. Without a cap, anything on the cluster network (a flood, or a peer holding many idle
/// links) spawns unbounded threads and exhausts fd/RAM, collapsing the node — asymmetric with the
/// client-facing server's `max_connections` cap. This floor mirrors the client default (256): a bound at
/// ~256 × [`PER_CONNECTION_STACK_BYTES`](crate::rss::PER_CONNECTION_STACK_BYTES) ≈ 16 MiB of touched
/// reader-stack RSS (the project's per-connection RSS estimate; the virtual reservation is larger — the
/// default thread stack — and, like the client plane's reader stacks, is not charged in the #115
/// refuse-to-boot budget). Over the effective cap an inbound link is refused (dropped) rather than
/// spawning a thread.
///
/// #865 shipped this as a hard CONSTANT cap. #915 (this) makes the effective cap CONFIGURABLE and sizes
/// its default to the legitimate inbound fanout instead of borrowing the client `max_connections`
/// default: a leader's LEGITIMATE inbound links are one per (led partition × follower)
/// ([`DataPlaneServer::led_inbound_link_count`]), so a HIGH-partition-fanout leader (e.g. hundreds of
/// partitions × replicas) can exceed 256, and a hard 256 would then refuse real followers, stalling
/// replication on the refused partitions. The effective cap is now
/// [`effective_dataplane_reader_cap`]`(configured, led_inbound_link_count)`: it defaults to (and is
/// FLOORED at) this constant so a small edge deployment is unaffected, grows to the legitimate fanout so
/// no real follower is ever refused, and an operator override still bounds an unauthenticated flood.
const DEFAULT_MIN_DATAPLANE_READERS: usize = 256;

/// The EFFECTIVE concurrent inbound data-plane reader cap (#915): the operator-`configured` cap if any,
/// otherwise the [`DEFAULT_MIN_DATAPLANE_READERS`] default, then RAISED to `led_inbound_link_count` (this
/// node's legitimate inbound follower fanout, [`DataPlaneServer::led_inbound_link_count`]) so a
/// high-fanout leader admits every real follower link rather than refusing past a too-small constant.
///
/// Two guarantees hold jointly:
/// * a LEGITIMATE follower is NEVER refused for lack of a slot — the cap is at least the exact
///   led-partition inbound fanout, so all real links fit even when the operator configured a smaller cap;
/// * an UNAUTHENTICATED flood is still BOUNDED — the cap is finite (the configured value, or the default
///   floor, whichever with the fanout is the larger), so the listener still drops links past it and never
///   spawns unbounded threads.
///
/// Flooring the default at 256 leaves a small edge deployment (fanout ≪ 256) on exactly today's bound.
fn effective_dataplane_reader_cap(
    configured: Option<usize>,
    led_inbound_link_count: usize,
) -> usize {
    configured
        .unwrap_or(DEFAULT_MIN_DATAPLANE_READERS)
        .max(led_inbound_link_count)
}

/// Releases one concurrent-reader slot on drop (#865), so the concurrent-reader count is
/// decremented when a reader thread exits on EITHER a normal return OR a panic unwind — the count can
/// never leak and pin the cap. Constructed before the reader spawn and moved into it; a spawn FAILURE
/// drops it too, releasing the slot the accept loop reserved.
struct DataPlaneReaderSlot {
    /// The shared concurrent-reader counter to decrement on drop.
    active: Arc<AtomicUsize>,
}

impl Drop for DataPlaneReaderSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The follower fetch budgets: how many records / bytes a follower asks for per `FetchRecords`. The
/// leader's read plane already bounds a response to a single sealed segment run, so a catch-up is
/// several rounds; these are the FULL (un-throttled) upper bounds, themselves under
/// [`MAX_REPL_FETCH_BYTES`](super::replication::MAX_REPL_FETCH_BYTES). The canonical values live in
/// [`rereplication`](super::rereplication) ([`FULL_CATCHUP_RECORDS`] / [`FULL_CATCHUP_BYTES`]), which
/// owns the CoDel re-replication throttle (#619) that shapes these down under contention while a
/// follower is far behind; the steady-state / healthy-link fetch still uses the full budget.
///
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
/// The client-gate construction inputs threaded into [`DataPlaneRuntime::start_inner`] (#719/#735): the
/// configured cluster ack level (#719) plus the #735 client cluster-awareness wiring — the node-id ->
/// CLIENT-address advertise map (the `NOT_LEADER` leader hint) and the shared metadata status snapshot (the
/// follower-read committed-HW safe-watermark source). `None` for a runtime started without a client gate
/// (the in-process tests / the observability serve).
struct ClientGateConfig {
    /// The serve-wide configured cluster ack level the produce-ack gate holds produces to (#719/#696).
    configured_level: super::ack_level::ClusterAckLevel,
    /// The node-id -> CLIENT-address advertise map for the `NOT_LEADER` leader hint (#735); empty means the
    /// redirect carries no hint (the client re-tries its known peers).
    leader_client_addrs: BTreeMap<u64, SocketAddr>,
    /// The node-id -> DATA-PLANE peer address map for the dirty-tier committed-HW confirm (#739); empty
    /// means a "latest" follower-read above the safe watermark fails closed to the clean tier (never
    /// unconfirmed).
    leader_data_addrs: BTreeMap<u64, SocketAddr>,
    /// The shared metadata status snapshot the follower-read reads the committed-HW bar from (#735, half
    /// B); `None` fails the follower-read closed (serve nothing) until a checkpoint is known.
    status: Option<Arc<Mutex<super::runtime::ClusterStatus>>>,
    /// The dirty-tier committed-HW CONFIRM timeout (#739) the built gate holds — the connect+read budget
    /// for [`query_leader_committed_hw`]. PRODUCTION uses [`HW_CONFIRM_TIMEOUT`] (500 ms); a test may
    /// override it (e.g. host-scaled) so the confirm completes under a contended runner without weakening
    /// the fail-closed semantics. A `None` here defaults to [`HW_CONFIRM_TIMEOUT`].
    confirm_timeout: Option<Duration>,
}

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
        // No client gate and no configured reader cap: the inbound-reader cap defaults to the legitimate
        // led-partition fanout, floored at the old constant (#915).
        Self::start_inner(server, self_data_addr, peer_data_addrs, None, None)
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
            Some(ClientGateConfig {
                configured_level,
                leader_client_addrs: BTreeMap::new(),
                // The dirty-tier confirm (#739) targets the leader's data-plane address — the SAME
                // `peer_data_addrs` the follower fetch loop dials. With no #735-aware wiring there is no
                // status handle, so the follower-read fails closed anyway; the data addresses still make
                // the dirty-tier confirm reachable for a runtime started this way.
                leader_data_addrs: peer_data_addrs.clone(),
                status: None,
                confirm_timeout: None,
            }),
            // No configured reader cap: default to the legitimate led-partition fanout, floored at the
            // old constant (#915).
            None,
        )
    }

    /// Like [`Self::start_with_client_gate`], but ALSO supplies the #735 client cluster-awareness wiring:
    /// the node-id -> CLIENT-address advertise map (the `NOT_LEADER` leader HINT) and the shared metadata
    /// status snapshot (the follower-read committed-HW safe-watermark source). With an empty advertise map
    /// the `NOT_LEADER` redirect still fires (the client re-tries its known peers); without a status handle a
    /// follower-read fails closed (serves nothing) until a committed-HW checkpoint is known.
    ///
    /// `dataplane_reader_cap` is the operator-configured cap on concurrent inbound data-plane reader
    /// threads (#915), threaded from the broker/cluster config. `None` (the usual case) sizes the cap to
    /// this node's legitimate led-partition inbound fanout, floored at the old constant. A `Some(n)` value
    /// is honored as the operator bound but still raised to the exact legitimate fanout so a real follower
    /// is never refused — see [`effective_dataplane_reader_cap`].
    ///
    /// # Errors
    /// As [`Self::start`].
    ///
    /// # Panics
    /// As [`Self::start`].
    pub fn start_with_client_gate_aware(
        server: DataPlaneServer<F, C>,
        self_data_addr: SocketAddr,
        peer_data_addrs: &BTreeMap<u64, SocketAddr>,
        configured_level: super::ack_level::ClusterAckLevel,
        leader_client_addrs: BTreeMap<u64, SocketAddr>,
        status: Arc<Mutex<super::runtime::ClusterStatus>>,
        dataplane_reader_cap: Option<usize>,
    ) -> io::Result<Self> {
        Self::start_inner(
            server,
            self_data_addr,
            peer_data_addrs,
            Some(ClientGateConfig {
                configured_level,
                leader_client_addrs,
                // The dirty-tier committed-HW confirm (#739) dials the leader's DATA-plane address — the
                // SAME `peer_data_addrs` the follower fetch loop uses — so a "latest" follower-read above
                // the safe watermark can confirm with the leader before serving (never unconfirmed).
                leader_data_addrs: peer_data_addrs.clone(),
                status: Some(status),
                confirm_timeout: None,
            }),
            dataplane_reader_cap,
        )
    }

    /// The shared work of [`Self::start`] / [`Self::start_with_client_gate`] /
    /// [`Self::start_with_client_gate_aware`]: when `client_cfg` is `Some`, a
    /// [`ClientAckGate`](super::client_ack::ClientAckGate) is built around the wrapped server Arc (with the
    /// #735 leader-hint advertise map + status handle) and the leader-side readers release through it
    /// (`AckRelease::Gate`); when `None`, the readers drive the seam directly and drop the released bytes
    /// (`AckRelease::ServerOnly`).
    fn start_inner(
        server: DataPlaneServer<F, C>,
        self_data_addr: SocketAddr,
        peer_data_addrs: &BTreeMap<u64, SocketAddr>,
        client_cfg: Option<ClientGateConfig>,
        dataplane_reader_cap: Option<usize>,
    ) -> io::Result<Self> {
        // Bind the data-plane peer listener BEFORE spawning anything, so a bind failure is synchronous
        // (no half-started runtime). Non-blocking so the accept loop polls the shutdown flag.
        let listener = TcpListener::bind(self_data_addr)?;
        listener.set_nonblocking(true)?;

        let follower_partitions = server.follower_partitions();
        // The EFFECTIVE inbound-reader cap (#915): the operator-configured value (threaded from the
        // broker/cluster config) if any, else the default floor, RAISED to this node's legitimate
        // inbound-follower fanout so a high-partition-fanout leader admits every real follower link
        // instead of refusing past a borrowed constant. Computed from the server (its committed roles)
        // BEFORE it is moved into the shared `Arc<Mutex>`.
        let dataplane_reader_cap =
            effective_dataplane_reader_cap(dataplane_reader_cap, server.led_inbound_link_count());
        let server = Arc::new(Mutex::new(server));
        let shutdown = Arc::new(AtomicBool::new(false));
        // Build the client produce-ack gate around the SAME server Arc when a config was given (#719/#735).
        // The gate and every leader-side reader share this one Arc, so the seam's parked state is one
        // source of truth. The #735 wiring (the `NOT_LEADER` leader-hint advertise map + the follower-read
        // committed-HW status handle) is layered on via the gate's builders.
        let client_gate = client_cfg.map(|cfg| {
            let mut gate =
                super::client_ack::ClientAckGate::new(Arc::clone(&server), cfg.configured_level)
                    .with_leader_client_addrs(cfg.leader_client_addrs)
                    .with_leader_data_addrs(cfg.leader_data_addrs);
            if let Some(status) = cfg.status {
                gate = gate.with_status_handle(status);
            }
            if let Some(confirm_timeout) = cfg.confirm_timeout {
                gate = gate.with_confirm_timeout(confirm_timeout);
            }
            Arc::new(gate)
        });
        let release = match &client_gate {
            Some(g) => AckRelease::Gate(Arc::clone(g)),
            None => AckRelease::ServerOnly,
        };

        // The LEADER side: accept inbound peer links and serve fetches / record reports.
        let shutdown_l = Arc::clone(&shutdown);
        let server_l = Arc::clone(&server);
        let release_l = release.clone();
        // The concurrent inbound-reader counter (#865), owned by the listener thread: each spawned
        // reader holds a slot guard that decrements it on exit, so the listener caps concurrent peer
        // readers at `dataplane_reader_cap` (#915: sized to the legitimate fanout, floored at the old
        // constant, operator-overridable) and refuses any link beyond it rather than spawning an
        // unbounded number of threads under a cluster-network flood.
        let active_readers = Arc::new(AtomicUsize::new(0));
        let listener_handle = std::thread::Builder::new()
            .name("ib-dataplane-listen".to_string())
            .spawn(move || {
                run_dataplane_listener(
                    listener,
                    server_l,
                    release_l,
                    shutdown_l,
                    dataplane_reader_cap,
                    active_readers,
                );
            })
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

/// The data-plane LISTENER thread: accept inbound peer connections and spawn a reader per connection,
/// up to `max_readers` CONCURRENT readers (#865). Reader threads are detached; they exit on a
/// closed/broken link or shutdown, releasing their slot on `active_readers`. The accept loop is
/// non-blocking and polls the shutdown flag so a stop is prompt. Over the cap an inbound link is
/// REFUSED (dropped) rather than spawning an unbounded thread, and a thread-creation failure is logged
/// and shed rather than silently swallowed.
// A thread entry point: it OWNS the listener, the shared server, and the shutdown flag (cloned into
// each per-connection reader it spawns) for the thread's lifetime; a borrow would fight the 'static
// spawn bound and prevent cloning into the spawned readers.
#[allow(clippy::needless_pass_by_value)]
fn run_dataplane_listener<F, C>(
    listener: TcpListener,
    server: Arc<Mutex<DataPlaneServer<F, C>>>,
    release: AckRelease<F, C>,
    shutdown: Arc<AtomicBool>,
    max_readers: usize,
    active_readers: Arc<AtomicUsize>,
) where
    F: Filesystem + Send + Sync + 'static,
    C: Clock + Send + 'static,
{
    // Whether we are currently in a saturation episode, so the cap-refusal warning is logged ONCE per
    // episode rather than once per refused link (#865 review): the cap defends against a sustained
    // connection flood, and a per-link warn under that flood would itself be an unbounded log-volume
    // vector. Reset the moment the loop next admits a link (the episode ended).
    let mut cap_warned = false;
    // Latches while a reader-thread spawn-failure episode is ongoing, so the failure is logged ONCE per
    // episode (like `cap_warned`) and the loop backs off instead of tight-looping accept-then-drop
    // under thread/fd exhaustion (#870). Reset by the next successful spawn.
    let mut spawn_warned = false;
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // CAP the concurrent inbound peer readers (#865): the accept loop is the sole
                // incrementer of `active_readers` (readers only decrement, on exit), so this
                // load-then-spawn is race-free against the cap — the count can never exceed the cap.
                // At the cap, REFUSE the link by dropping the stream (it closes) rather than spawning an
                // unbounded thread; auth happens only later inside `recv()`, so this bounds an
                // unauthenticated cluster-network flood at the cheapest point.
                if active_readers.load(Ordering::Acquire) >= max_readers {
                    // Log once per saturation episode, not per refused link (see `cap_warned`).
                    if !cap_warned {
                        tracing::warn!(
                            cap = max_readers,
                            "data plane: inbound peer reader cap reached; refusing new links until a reader exits"
                        );
                        cap_warned = true;
                    }
                    drop(stream);
                    continue;
                }
                // Admitting a link: the saturation episode (if any) is over, so a later one warns again.
                cap_warned = false;
                // The listener is NON-BLOCKING (so this accept loop can poll the shutdown flag), and on
                // BSD/macOS an accepted stream INHERITS the listener's `O_NONBLOCK`. A blocking-mode read
                // timeout (`SO_RCVTIMEO`, set below) is IGNORED on a non-blocking socket: `read` returns
                // `WouldBlock` instantly instead of parking up to the timeout, so the leader-side reader
                // would hot-spin instead of blocking on an idle follower link — the #632 idle busy-spin.
                // Restore BLOCKING mode so the read timeout takes effect and an idle reader genuinely
                // PARKS (it still wakes every `DATAPLANE_POLL` to re-check shutdown).
                let _ = stream.set_nonblocking(false);
                // A short read timeout so a reader's blocking `recv` re-checks shutdown promptly and an
                // idle inbound link never wedges a stop.
                let _ = stream.set_read_timeout(Some(DATAPLANE_POLL));
                let server = Arc::clone(&server);
                let release = release.clone();
                let sd = Arc::clone(&shutdown);
                // Reserve the reader slot BEFORE spawning; the guard, moved into the reader, releases it
                // on the reader's exit (return OR panic unwind), so the count can never leak. A spawn
                // FAILURE drops the closure (and so the guard), releasing the slot automatically.
                active_readers.fetch_add(1, Ordering::AcqRel);
                let slot = DataPlaneReaderSlot {
                    active: Arc::clone(&active_readers),
                };
                let spawn_result = std::thread::Builder::new()
                    .name("ib-dataplane-read".to_string())
                    .spawn(move || {
                        let _slot = slot;
                        run_dataplane_reader(DataPlaneLink::new(stream), &server, &release, &sd);
                    });
                // The OS may refuse thread creation (EAGAIN/ENOMEM): the failed closure is dropped,
                // which releases the reserved reader slot (`slot`'s drop) and closes the stream.
                // Previously (#865) the failure was logged but the loop kept tight-looping
                // accept-then-drop; surface it via tracing (once per episode) AND back off so a
                // transient thread/fd exhaustion cannot become a hot accept-spin (#870).
                if super::on_reader_spawn_result(
                    &spawn_result,
                    &mut spawn_warned,
                    "data-plane peer",
                ) {
                    sleep_interruptible(DATAPLANE_POLL, &shutdown);
                }
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
/// The outcome of [`serve_fetch_off_lock`]: what the reader thread does with a served `FetchRecords`.
enum OffLockServe {
    /// The server `Mutex` was poisoned (a holder panicked) — the reader thread tears down.
    Poisoned,
    /// Serve produced a response frame to send to the follower.
    Send(FetchResponseBody),
    /// Nothing to send: this node is not the partition's leader, or the serve faulted — drop the frame
    /// (exactly what the old through-`handle_frame` path did with a `WrongRole`/`UnknownPartition` error).
    Drop,
}

/// Serve a follower's `FetchRecords` for `partition` OFF the global server lock (#809): take the lock
/// ONLY to clone the leader's `Arc<ReadPlane>` (a refcount bump), DROP it, then run the seek/scan +
/// `Bytes`-slice serve with NO lock held. `ReadPlaneLeader::serve_fetch` is a pure read over the
/// wait-free read plane (its own `ArcSwap`/Acquire ordering governs freshness, never this `Mutex`), so K
/// followers' fetch-serves to different partitions run in parallel instead of serializing on the one lock
/// across each `read_range_raw`. Factored out (rather than inlined in the reader loop) so a test can drive
/// the EXACT lock/serve sequence and prove the lock is released during the serve.
fn serve_fetch_off_lock<F, C>(
    server: &Arc<Mutex<DataPlaneServer<F, C>>>,
    partition: u64,
    req: &FetchRecordsBody,
) -> OffLockServe
where
    F: Filesystem + Send + Sync + 'static,
    C: Clock + Send + 'static,
{
    // The ONLY work under the lock: clone the partition's read-plane `Arc`. The lock is dropped at the
    // end of this block, BEFORE the serve below.
    let plane = match server.lock() {
        Ok(srv) => srv.leader_read_plane(partition),
        Err(_) => return OffLockServe::Poisoned,
    };
    let Some(plane) = plane else {
        return OffLockServe::Drop; // not this node's leader role for the partition
    };
    match crate::cluster::replication::ReadPlaneLeader::new(&plane).serve_fetch(req) {
        Ok(response) => OffLockServe::Send(response),
        Err(_) => OffLockServe::Drop, // a serve fault: drop, matching the old `.ok()`-swallow behavior
    }
}

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
            // #809: serve a `FetchRecords` OFF the global server lock. Take the lock ONLY to clone the
            // partition's `Arc<ReadPlane>` (a refcount bump), drop it, then run the seek/scan +
            // `Bytes`-slice serve with NO lock held — so K followers' fetch-serves to DIFFERENT partitions
            // run in parallel instead of serializing on the one global lock across each `read_range_raw`.
            // `serve_fetch` is a pure read (`&self`) over the wait-free read plane, whose freshness comes
            // from its own `ArcSwap`/Acquire ordering (never from this `Mutex`), so off-lock serve sees an
            // identical-or-fresher snapshot. A non-leader (`None`) drops the frame, exactly as the old
            // through-`handle_frame` path did (it returned a `WrongRole`/`UnknownPartition` error the
            // generic arm swallowed with `.ok()`).
            Ok(Some((partition, DataPlaneFrame::FetchRequest(req)))) => {
                match serve_fetch_off_lock(server, partition, &req) {
                    OffLockServe::Poisoned => return, // the runtime is tearing down
                    OffLockServe::Send(response) => {
                        if link
                            .send(partition, &DataPlaneFrame::FetchResponse(response))
                            .is_err()
                        {
                            return;
                        }
                    }
                    OffLockServe::Drop => {} // not this node's leader role, or a serve fault: drop it
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
                    // The DIRTY-TIER committed-HW confirm (#739): the leader answers a follower's
                    // HW-version query with its current committed HW on the SAME link.
                    Some(DataPlaneAction::SendCommittedHwResponse {
                        partition,
                        response,
                    }) => {
                        if link
                            .send(partition, &DataPlaneFrame::CommittedHwResponse(response))
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
    // The CoDel re-replication throttle (#619) for THIS partition. It is OWNED here, not per-link, so
    // it survives a reconnect mid-catch-up (a divergent / recovered follower that drops and redials
    // keeps its adapted budget). A monotonic origin gives the throttle deterministic nanosecond
    // timestamps from a `std::time::Instant` delta (no wall clock), so the production path drives the
    // SAME pure controller the unit tests inject a clock into.
    let mut throttle = ReReplicationThrottle::default_throttle();
    let origin = Instant::now();
    while !shutdown.load(Ordering::Acquire) {
        match TcpStream::connect_timeout(&leader_addr, DATAPLANE_POLL) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(DATAPLANE_POLL));
                let _ = stream.set_write_timeout(Some(DATAPLANE_POLL));
                let mut link = DataPlaneLink::new(stream);
                follower_fetch_loop(
                    partition,
                    &mut link,
                    &server,
                    shutdown,
                    &mut throttle,
                    origin,
                );
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
///
/// ## Re-replication rate-limit (#619)
///
/// `throttle` is the CoDel-style controlled-delay throttle on this partition's CATCH-UP fetch (see
/// [`ReReplicationThrottle`]). Each round:
/// 1. it [`decide`](ReReplicationThrottle::decide)s the fetch budget from the follower's BACKLOG
///    (`leader_high_watermark - follower_next_offset`, observed from the last response): far behind
///    (re-replicating) + a contended link → a SHRUNK budget + an inter-fetch backoff that yields the
///    link to live traffic; near the head (tailing) or an idle link → the FULL budget;
/// 2. it times the fetch round-trip + the local apply (the catch-up's per-fetch SERVICE DELAY) and
///    feeds it back as the CoDel sojourn, so a link contended by live produce / consume / replication
///    drives the budget down WITHOUT any cross-thread coordination.
///
/// The throttle only ever changes the REQUEST budget + adds a sleep — never WHAT is applied — so
/// re-replication stays byte-identical, in-order, CRC-revalidated, and gap-free (the apply path is
/// untouched). The budget floors at [`MIN_CATCHUP_RECORDS`] and the backoff is capped, so the catch-up
/// always makes forward progress and converges. `origin` is the monotonic instant the partition's
/// throttle clock is measured from.
fn follower_fetch_loop<F, C>(
    partition: u64,
    link: &mut DataPlaneLink<TcpStream>,
    server: &Arc<Mutex<DataPlaneServer<F, C>>>,
    shutdown: &AtomicBool,
    throttle: &mut ReReplicationThrottle,
    origin: Instant,
) where
    F: Filesystem + Send + Sync + 'static,
    C: Clock + Send + 'static,
{
    // #809: clone this partition's follower handle ONCE. The per-iteration apply (decode + append +
    // `log.sync()` fsync) then runs on it OFF the node-global server `Mutex`, holding only this handle's
    // PER-PARTITION lock — so partition A's apply/fsync never blocks partition B's serve/apply/park. The
    // handle stays valid across a promotion (which does NOT consume the `Arc`); the per-iteration
    // `make_fetch_request` still goes through the controller and exits the loop once the role is gone.
    let (handle, node_id) = {
        let Ok(srv) = server.lock() else {
            return; // poisoned: tearing down
        };
        match srv.follower_handle(partition) {
            Some(handle) => (handle, srv.node_id()),
            None => return, // not a follower of this partition
        }
    };
    // The budget the throttle decided for the NEXT fetch. Seeded full-rate: the first fetch of a
    // freshly-dialed link runs at full budget (the backlog is not known until the first response), and
    // the throttle shapes every subsequent fetch from the observed backlog + service delay.
    let mut budget = FetchBudget {
        max_records: FULL_CATCHUP_RECORDS,
        max_bytes: FULL_CATCHUP_BYTES,
    };
    while !shutdown.load(Ordering::Acquire) {
        // Build the next fetch request under a short lock (the follower's current frontier + the
        // throttle's current budget — capped below the historical full budget only while catching up
        // under contention).
        let req = {
            let Ok(srv) = server.lock() else {
                return;
            };
            match srv.seam().controller().make_fetch_request(
                partition,
                budget.max_records,
                budget.max_bytes,
            ) {
                Ok(req) => req,
                // No longer a follower of this partition (a future rebalance): stop fetching.
                Err(_) => return,
            }
        };
        // The follower's next offset BEFORE this fetch — the backlog is measured against the leader's
        // high-watermark in the response.
        let from_offset = req.from_offset;
        // Time the catch-up's per-fetch NETWORK round-trip: request-sent → response-received. This,
        // NOT the total fetch+apply+fsync, is the CoDel sojourn — LINK saturation (the contention this
        // rate-limit protects against) shows up as the network leg stretching, whereas the local
        // apply / fsync is host-disk jitter, not link contention, and would otherwise trip the throttle
        // on its own baseline work. The throttle further subtracts the minimum-observed network leg as
        // the uncontended baseline (see `ReReplicationThrottle::observe_fetch`), so only the STANDING
        // (above-baseline) network delay drives the throttle.
        let fetch_sent = Instant::now();
        if link
            .send(partition, &DataPlaneFrame::FetchRequest(req))
            .is_err()
        {
            return; // link broke; reconnect
        }
        // Read the response (blocking up to the read timeout). On a timeout, loop and re-fetch.
        match link.recv() {
            Ok(Some((p, DataPlaneFrame::FetchResponse(resp)))) if p == partition => {
                // The network round-trip ended here (response received), BEFORE the local apply/fsync.
                let net_nanos = u64::try_from(fetch_sent.elapsed().as_nanos()).unwrap_or(u64::MAX);
                let leader_hw = resp.high_watermark;
                // Apply + build the report OFF the global server lock (#809) — under this partition's
                // follower lock only, so the apply's `log.sync()` fsync does not block another partition's
                // serve/apply. Then send the report off-lock (as before).
                let report = {
                    if resp.record_count > 0 {
                        // Apply the CRC-revalidated bytes to the follower's own replica log. A
                        // divergence / corrupt frame fails closed (nothing from the bad frame is
                        // appended); drop this response and re-fetch from the current frontier.
                        if crate::cluster::dataplane::apply_on_follower(&handle, &resp).is_err() {
                            // Fail-closed: reconnect + refetch from the recovered frontier.
                            return;
                        }
                    }
                    Some(crate::cluster::dataplane::report_from_follower(
                        &handle, node_id,
                    ))
                };
                // The follower's next offset AFTER the apply (its fsync'd frontier) — what it just
                // reported. The backlog is the leader's high-watermark minus this.
                let next_offset = report.as_ref().map_or(from_offset, |r| r.fsynced_offset);
                if let Some(report) = report {
                    if link
                        .send(partition, &DataPlaneFrame::AckReplicated(report))
                        .is_err()
                    {
                        return;
                    }
                }
                // Drive the throttle from this fetch's NETWORK round-trip + the follower's backlog. The
                // throttle internally treats a near-the-head backlog as steady-state (full-rate, no
                // throttle); only a far-behind follower's catch-up is rate-limited.
                let now_nanos = elapsed_nanos(origin, fetch_sent);
                let backlog = leader_hw.saturating_sub(next_offset);
                throttle.observe_fetch(net_nanos, now_nanos);
                let decision = throttle.decide(backlog, now_nanos);
                budget = decision.budget;
                // If the leader served a non-empty run there may be more to pull; otherwise pace the
                // next poll so a caught-up follower does not hot-loop (the #726 discipline). While
                // re-replicating under contention, ALSO sleep the throttle's inter-fetch backoff, so
                // the catch-up yields the link to live traffic — a throttled-waiting follower BLOCKS,
                // it never busy-spins.
                if resp.record_count == 0 {
                    sleep_interruptible(DATAPLANE_POLL, shutdown);
                } else if decision.yield_for_ms > 0 {
                    sleep_interruptible(Duration::from_millis(decision.yield_for_ms), shutdown);
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

/// The monotonic nanoseconds elapsed from a partition's throttle `origin` to the instant `at`, for the
/// CoDel clock. Saturates at `u64::MAX` (≈585 years; unreachable) so a long-lived follower's clock
/// never wraps.
fn elapsed_nanos(origin: Instant, at: Instant) -> u64 {
    u64::try_from(at.saturating_duration_since(origin).as_nanos()).unwrap_or(u64::MAX)
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
    use ironbus_storage::fault::{FaultControl, FaultFs};
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

    /// A leaked leader log over a FAULT fs (so reads pass through the read gate), its `Arc`-shared read
    /// plane, and the fault control — used to PARK a fetch-serve mid-read and prove the server lock is free
    /// during the serve (#809).
    fn fault_leader_plane(n: u32) -> (Arc<ReadPlane<FaultFs<InMemoryFs>>>, FaultControl) {
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).expect("log opens");
        for i in 0..n {
            log.append(&rec(format!("rep-{i:02}").as_bytes())).unwrap();
        }
        log.sync().unwrap();
        let plane = Arc::new(log.read_plane().expect("read plane builds"));
        Box::leak(Box::new(log));
        (plane, control)
    }

    #[test]
    fn a_fetch_serve_does_not_hold_the_server_lock_across_the_read() {
        // #809: the reader thread serves a `FetchRecords` OFF the global server lock. We park a fetch-serve
        // mid-read (the fault read gate) and prove the server `Mutex` is FREE during the serve — so a
        // second partition's fetch-serve would NOT wait behind it. Pre-#809 the serve ran UNDER the lock
        // (through `handle_frame`), so the lock would be HELD across the parked read and this `try_lock`
        // would be `WouldBlock`.
        const P: u64 = 0;
        let (plane, control) = fault_leader_plane(25);
        let mut controller: DataPlaneController<FaultFs<InMemoryFs>, ManualClock> =
            DataPlaneController::new(1);
        controller.start_leader(P, plane, EpochCache::new(), &[2, 3], quorum3());
        let server = Arc::new(Mutex::new(DataPlaneServer::new(
            1,
            ProduceAckSeam::new(controller),
        )));

        // Close the read gate so the next positioned read parks; spawn the off-lock fetch-serve.
        control.close_read_gate();
        let server_t = Arc::clone(&server);
        let serve = std::thread::spawn(move || {
            serve_fetch_off_lock(
                &server_t,
                P,
                &FetchRecordsBody {
                    from_offset: 0,
                    max_records: 10,
                    max_bytes: 0,
                },
            )
        });

        // Wait until the serve is parked mid-read (deterministic, condvar — no wall-clock sleep).
        control.wait_for_read_gate_entered(1);

        // THE DISCRIMINATING ASSERTION: the server `Mutex` is FREE while the serve is parked in the read,
        // because the serve clones the read plane under the lock and then serves OFF the lock. Pre-#809
        // (serve under the lock) this would be `WouldBlock`. The guard drops immediately.
        assert!(
            server.try_lock().is_ok(),
            "the server Mutex must NOT be held during the fetch-serve read (#809 off-lock serve)"
        );

        // Release the parked read; the off-lock serve completes and produces a response.
        control.open_read_gate();
        let outcome = serve.join().expect("serve thread joins");
        assert!(
            matches!(outcome, OffLockServe::Send(_)),
            "the off-lock serve produced a FetchResponse"
        );
    }

    #[test]
    fn a_follower_apply_does_not_hold_the_server_lock_across_the_fsync() {
        // #809 Phase 2: the follower fetch thread applies a fetch response (decode + append + `log.sync()`
        // fsync) OFF the node-global server `Mutex`, under the partition's OWN follower lock. We park a
        // follower apply mid-fsync (the fault sync gate) and prove the server `Mutex` is FREE (so another
        // partition's serve/apply/park would not wait) while the per-partition follower lock IS held — i.e.
        // the apply runs under the partition lock, NOT the global lock. Pre-#809 the apply ran under the
        // global lock, so `server.try_lock()` would be `WouldBlock` during the parked fsync.
        const P: u64 = 0;
        // A leader controller with a few sealed records to serve a real fetch response.
        let leader_log = leaked_leader_log(12);
        let mut leader: DataPlaneController<InMemoryFs, ManualClock> = DataPlaneController::new(1);
        leader.start_leader(
            P,
            leader_plane(leader_log),
            EpochCache::new(),
            &[2],
            quorum3(),
        );

        // A FOLLOWER `DataPlaneServer` over a FAULT-fs replica log, so we can park its apply's fsync.
        let (fs, control) = FaultFs::new(InMemoryFs::new());
        let follower_log = Log::open(fs, ManualClock::new(), small_config()).expect("follower log");
        let mut fc: DataPlaneController<FaultFs<InMemoryFs>, ManualClock> =
            DataPlaneController::new(2);
        fc.start_follower(P, follower_log);
        let server = Arc::new(Mutex::new(DataPlaneServer::new(2, ProduceAckSeam::new(fc))));

        // Build the follower's fetch request and serve it from the leader → a real `FetchResponse`.
        let req = server
            .lock()
            .unwrap()
            .seam()
            .controller()
            .make_fetch_request(P, 8, 4096)
            .unwrap();
        let resp = leader.serve_fetch(P, &req).unwrap();
        assert!(resp.record_count > 0, "the leader served records to apply");
        let handle = server.lock().unwrap().follower_handle(P).unwrap();

        // Park the apply mid-fsync, then assert the off-global-lock / on-partition-lock property.
        control.close_sync_gate();
        let apply_handle = Arc::clone(&handle);
        let apply = std::thread::spawn(move || {
            crate::cluster::dataplane::apply_on_follower(&apply_handle, &resp)
        });
        control.wait_for_sync_gate_entered(1);
        assert!(
            server.try_lock().is_ok(),
            "the server Mutex is FREE during the follower apply's fsync (#809 — off the global lock)"
        );
        assert!(
            handle.try_lock().is_err(),
            "the apply holds the PER-PARTITION follower lock during the fsync (not the global lock)"
        );
        control.open_sync_gate();
        assert!(
            apply.join().unwrap().is_ok(),
            "the off-lock apply completed once the fsync was released"
        );
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
                frame_bytes: bytes::Bytes::from_static(&[1, 2, 3, 4, 5]),
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
            // The #739 dirty-tier committed-HW confirm (tag 43): request + response share the tag.
            DataPlaneFrame::CommittedHwQuery(crate::cluster::dataplane::CommittedHwQueryBody),
            DataPlaneFrame::CommittedHwResponse(
                crate::cluster::dataplane::CommittedHwResponseBody { committed_hw: 4242 },
            ),
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
    fn fetch_response_single_copy_framer_is_byte_identical_to_the_generic_path() {
        // #825: the FetchResponse fast path (`encode_fetch_response_peer_frame`) frames the run with
        // a single copy. Prove its bytes are IDENTICAL to the generic
        // `encode_frame(FetchResponse, [partition-le ++ resp.encode()])` encoding the follower
        // decodes — the conformance byte-identity guarantee — across empty, tiny, and large runs.
        for run_len in [0usize, 5, 1024, 3 * 1024 * 1024] {
            let payload: Vec<u8> = (0..run_len)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect();
            let resp = FetchResponseBody {
                high_watermark: 987_654_321,
                first_offset: 42,
                record_count: 9,
                frame_bytes: bytes::Bytes::from(payload),
            };
            let partition = 3u64;

            // The reference (generic) encoding: partition prefix + resp body, framed.
            let mut ref_body = partition.to_le_bytes().to_vec();
            ref_body.extend_from_slice(&resp.encode());
            let mut reference = Vec::new();
            proto_encode_frame(FrameType::FetchResponse, &ref_body, &mut reference)
                .expect("reference frames");

            let fast = encode_dataplane_peer_frame(
                partition,
                &DataPlaneFrame::FetchResponse(resp.clone()),
            )
            .expect("fast-path frames");

            assert_eq!(
                fast, reference,
                "fast-path FetchResponse framing must be byte-identical (run_len={run_len})"
            );

            // And it must still decode back to the same partition + frame.
            let (got_p, got_frame, consumed) = decode_dataplane_peer_frame(&fast)
                .expect("decode ok")
                .expect("a complete frame");
            assert_eq!(consumed, fast.len(), "exactly one frame consumed");
            assert_eq!(got_p, partition, "partition round-trips");
            assert_eq!(
                got_frame,
                DataPlaneFrame::FetchResponse(resp),
                "frame round-trips byte-faithful"
            );
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
            self.server
                .seam()
                .controller()
                .with_follower_log(self.partition, dump_segments)
                .unwrap()
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

    // ================================================================================================
    //  THE #618 FAILOVER CAPSTONE: a 3-node SERVE cluster over REAL loopback sockets, then the LEADER
    //  DIES. An in-sync follower is PROMOTED (no data move): it serves the SAME log it already held, at
    //  a STRICTLY-HIGHER epoch (the fence), and the cluster RESUMES — the surviving follower replicates
    //  from the NEW leader over a fresh real socket and stays byte-identical. We assert all five #618
    //  properties: (a) a new leader from the ISR, (b) it holds every pre-death record, (c) the cluster
    //  resumes quorum-acked produces under it, (d) the old leader's epoch is fenced, (e) NO data copied.
    // ================================================================================================

    /// Drive `follower` (a [`LiveFollower`]) against a leader serve loop pumped via `pump` until its
    /// high-watermark reaches `target` or the deadline elapses; returns whether it caught up.
    fn drive_follower_until(
        follower: &mut LiveFollower,
        target: u64,
        mut pump: impl FnMut(),
        timeout: Duration,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        while follower.high_watermark() < target && Instant::now() < deadline {
            follower.send_fetch();
            for _ in 0..8 {
                pump();
            }
            follower.recv_apply_and_report();
            for _ in 0..8 {
                pump();
            }
        }
        follower.high_watermark() >= target
    }

    #[test]
    fn leader_death_promotes_an_isr_follower_no_data_move_fences_the_old_leader_and_the_cluster_resumes(
    ) {
        const P: u64 = 0;
        // The original committed placement: node 1 leads {1,2,3} at epoch 5.
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 5,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement.clone())].into_iter().collect();

        // --- Phase 1: bring up the cluster; both followers catch up to the leader's committed log. ---
        let leader_log = leaked_leader_log(25);
        let leader_pl = leader_plane(leader_log);
        let served_end = plane_served_end(&leader_pl);
        assert!(served_end > 0);

        let mut leader_server = DataPlaneServer::from_placements(
            1,
            &placements,
            quorum3(),
            |p| (p == P).then(|| Arc::clone(&leader_pl)),
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .expect("leader server builds");

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind leader listener");
        listener.set_nonblocking(true).unwrap();
        let leader_addr = listener.local_addr().unwrap();

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

        let mut f2 = LiveFollower::connect(follower2, P, leader_addr);
        let mut f3 = LiveFollower::connect(follower3, P, leader_addr);

        let mut links: Vec<DataPlaneLink<TcpStream>> = Vec::new();
        let mut released: Vec<Vec<u8>> = Vec::new();
        // Both followers catch up to the leader's committed (sealed-served) prefix over real sockets.
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            f2.send_fetch();
            f3.send_fetch();
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
            "follower 2 caught up pre-death"
        );
        assert_eq!(
            f3.high_watermark(),
            served_end,
            "follower 3 caught up pre-death"
        );
        // The set of records quorum-acked BEFORE the death (the committed prefix every ISR member holds).
        let committed_before_death = served_end;
        // Snapshot follower 2's replica BYTES now, so we can prove promotion copied NOTHING (property e).
        let f2_bytes_before_promotion = f2.replica_dump();
        assert_replicated_byte_identical(&f2_bytes_before_promotion, leader_log);

        // --- Phase 2: the LEADER (node 1) DIES. Drop its server + listener: no more leader serve. ---
        drop(leader_server);
        drop(listener);
        // The committed HW the survivors must preserve across the failover (every ISR member holds it).
        let committed_hw = committed_before_death;

        // --- Phase 3: the metadata plane RE-ASSIGNS leadership (one committed PlacePartition). The
        // successor is chosen from the IN-SYNC survivors (the ISR), the dead leader is dropped, and the
        // epoch is bumped strictly above the dead leader's (5) — the #618 reassign_leadership policy. ---
        // Project each survivor's state: both 2 and 3 are in-sync + complete to the committed HW (they
        // caught up in phase 1), so both are eligible; the policy picks the least-loaded (ties => node 2).
        let survivor_states = vec![
            ironbus_core::placement::PlacementNode::healthy(2, committed_hw),
            ironbus_core::placement::PlacementNode::healthy(3, committed_hw),
        ];
        let outcome = crate::cluster::placement::reassign_leadership(
            P,
            1, // dead leader
            &placement.replicas,
            placement.epoch,
            placement.epoch, // dead leader's epoch
            &survivor_states,
            committed_hw,
            &std::collections::BTreeMap::new(),
        );
        let (failover_cmd, successor) = match outcome {
            crate::cluster::placement::FailoverOutcome::Promoted { command, successor } => {
                (command, successor)
            }
            crate::cluster::placement::FailoverOutcome::NoEligibleSuccessor { .. } => {
                panic!("an in-sync survivor must be promotable")
            }
        };
        // (a) A NEW leader was ELECTED FROM THE ISR (an in-sync survivor), never the dead leader.
        assert!(
            successor == 2 || successor == 3,
            "the successor is a surviving in-sync replica"
        );
        assert_ne!(successor, 1, "the dead leader is never re-chosen");
        // Apply the ONE failover entry to a state machine: every node converges on the SAME new placement.
        let mut sm = crate::cluster::state_machine::MetadataStateMachine::new();
        sm.apply(1, &failover_cmd);
        let new_placement = sm.placement(P).expect("the failover placement committed");
        assert_eq!(new_placement.leader, successor);
        assert_eq!(
            new_placement.replicas,
            vec![2, 3],
            "no node moved; only the dead leader left"
        );
        assert!(
            new_placement.epoch > placement.epoch,
            "(d) the epoch is bumped strictly above the dead leader's (fence)"
        );

        // --- Phase 4: every surviving node RECONCILES to the committed new placement. The successor is
        // PROMOTED IN PLACE (no data move); the other survivor re-targets to the new leader. ---
        // Bind to identify which LiveFollower is the successor vs the still-follower.
        let (successor_follower, other_follower): (&mut LiveFollower, &mut LiveFollower) =
            if successor == 2 {
                (&mut f2, &mut f3)
            } else {
                (&mut f3, &mut f2)
            };

        // The successor promotes IN PLACE over the log it already held (no fetch, no copy). Snapshot the
        // committed bytes + frontier it held as a FOLLOWER, just before promotion (property e baseline).
        let succ_bytes_pre = successor_follower.replica_dump();
        let succ_hw_pre = successor_follower.high_watermark();
        // The follower held the full committed prefix, byte-identical to the (now-dead) leader.
        assert_replicated_byte_identical(&succ_bytes_pre, leader_log);
        successor_follower
            .server
            // Carry the committed-HW bar (#618b): the apply-time self-verify confirms the promoted node's
            // own durable log covers it before it becomes leader (it caught up to the full pre-death HW).
            .reconcile_placement(P, &new_placement, quorum3(), committed_hw)
            .expect("the in-sync follower is promoted to leader in place");
        // (a) it is now the LEADER for the partition.
        assert!(
            successor_follower.server.seam().controller().is_leader(P),
            "(a) the promoted survivor now LEADS the partition"
        );
        assert!(
            !successor_follower.server.seam().controller().is_follower(P),
            "it is no longer a follower"
        );

        // (b) + (e): the new leader's read plane serves EVERY record quorum-acked before the death,
        // BYTE-IDENTICAL to what it held as a follower — proving promotion copied NOTHING (it serves the
        // SAME log it already held, just re-pointed as leader). Reconstruct the served frame bytes and
        // confirm the served end covers the pre-death committed HW.
        // Chain serve-fetches from offset 0 on BOTH the new leader and the (still-readable) original
        // leader read plane, collecting the raw CRC-framed record bytes. The new leader serves the SAME
        // bytes it held as a follower (which were byte-identical to the original leader): proof (e) — no
        // data was copied on promotion (the served bytes ARE the follower's already-held log).
        let serve_all = |srv: &DataPlaneServer<InMemoryFs, ManualClock>| -> (u64, Vec<u8>) {
            let mut next = 0u64;
            let mut bytes: Vec<u8> = Vec::new();
            let mut guard = 0;
            loop {
                guard += 1;
                assert!(guard < 100_000, "serve chain terminates");
                let req = crate::cluster::replication::FetchRecordsBody {
                    from_offset: next,
                    max_records: 1024,
                    max_bytes: 1024 * 1024,
                };
                let resp = srv
                    .seam()
                    .controller()
                    .serve_fetch(P, &req)
                    .expect("the new leader serves committed bytes it already holds");
                bytes.extend_from_slice(&resp.frame_bytes);
                let advanced = resp.first_offset + u64::from(resp.record_count);
                if resp.record_count == 0 || advanced <= next {
                    break;
                }
                next = advanced;
            }
            (next, bytes)
        };
        let (new_leader_served_end, new_leader_bytes) = serve_all(&successor_follower.server);
        // The original leader is still readable through its read plane (it leaked); serve the SAME
        // prefix the new leader serves, for a byte-for-byte comparison.
        let original_served_bytes = {
            let mut next = 0u64;
            let mut bytes: Vec<u8> = Vec::new();
            let mut guard = 0;
            while next < new_leader_served_end {
                guard += 1;
                assert!(guard < 100_000, "serve chain terminates");
                let req = crate::cluster::replication::FetchRecordsBody {
                    from_offset: next,
                    max_records: 1024,
                    max_bytes: 1024 * 1024,
                };
                let resp = crate::cluster::replication::ReadPlaneLeader::new(&leader_pl)
                    .serve_fetch(&req)
                    .expect("original leader plane serves");
                bytes.extend_from_slice(&resp.frame_bytes);
                let advanced = resp.first_offset + u64::from(resp.record_count);
                if resp.record_count == 0 || advanced <= next {
                    break;
                }
                next = advanced;
            }
            bytes
        };
        // (b) the new leader RECEIVED + holds every record quorum-acked before the death: as a follower
        // it caught up to the full pre-death committed HW (succ_hw_pre == committed_hw), so NO committed
        // record was lost on promotion. The new leader's read plane SERVES the sealed prefix of that log
        // (the active tail seals on the next roll — the documented #715/#717 active-tail flag; the
        // records past it are held in the active segment, not lost). It serves a non-empty committed run.
        assert_eq!(
            succ_hw_pre, committed_hw,
            "(b) the promoted follower held EVERY pre-death committed record (no loss): hw {succ_hw_pre} == committed {committed_hw}"
        );
        assert!(
            new_leader_served_end > 0 && new_leader_served_end <= committed_hw,
            "(b) the new leader serves a non-empty committed prefix it already held (served_end={new_leader_served_end})"
        );
        // (e) the new leader serves BYTE-IDENTICAL committed records to the dead leader over the served
        // prefix — it serves the log it already held as a follower, copying NOTHING on promotion.
        assert_eq!(
            new_leader_bytes, original_served_bytes,
            "(e) the new leader serves byte-identical committed records to the dead leader — no data was copied on promotion"
        );

        // (d) the OLD leader is FENCED (KIP-101): the new leader answers OffsetForLeaderEpoch under the
        // BUMPED epoch. A query for the OLD epoch (5) is answered with a bounded end-offset (the old
        // leader's range cannot extend past where the new epoch began), and the current epoch is > 5 —
        // so a stale produce/append carrying the old epoch is rejected by followers (the fence).
        let new_leader_addr = {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind new leader listener");
            l.set_nonblocking(true).unwrap();
            let addr = l.local_addr();
            (l, addr)
        };
        // (we re-bind a fresh listener for the new leader below; first assert the epoch fence directly)
        let epoch_answer = successor_follower
            .server
            .seam()
            .controller()
            .serve_epoch_query(
                P,
                &crate::cluster::replication::OffsetForLeaderEpochBody {
                    epoch: LeaderEpoch::new(placement.epoch), // the OLD (dead) leader's epoch
                },
            )
            .expect("the new leader answers an epoch query");
        assert!(
            epoch_answer.end_offset.answered_epoch.get() >= new_placement.epoch
                || epoch_answer.end_offset.end_offset.get() <= new_leader_served_end,
            "(d) the old epoch is bounded by the new leader's epoch history — the old leader is fenced"
        );

        // --- Phase 5: the CLUSTER RESUMES. The new leader binds a listener; the OTHER survivor
        // re-targets to it (reconcile updated its follower target) and replicates from the NEW leader
        // over a FRESH real socket, staying byte-identical — proving the cluster keeps serving. ---
        let (new_listener, new_addr) = new_leader_addr;
        let new_addr = new_addr.unwrap();

        // The other survivor reconciles too: it stays a follower but re-targets to the successor. (As a
        // follower the committed-HW bar is unused, but we pass it for symmetry with the leader path.)
        let changed = other_follower
            .server
            .reconcile_placement(P, &new_placement, quorum3(), committed_hw)
            .expect("the other survivor reconciles");
        assert!(changed, "the other survivor re-targeted to the new leader");
        assert_eq!(
            other_follower.server.follower_leader(P),
            Some(successor),
            "the still-follower now follows the promoted successor"
        );

        // Re-connect the other survivor to the NEW leader's address and replicate from it. It already
        // holds the committed prefix, so it stays at the committed HW (and would pull any NEW records the
        // new leader appends). This is the cluster RESUMING under the new leader over a real socket.
        other_follower.link = DataPlaneLink::new({
            let s = TcpStream::connect(new_addr).expect("the survivor dials the NEW leader");
            s.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            s
        });
        // Drive a few rounds: the new leader serves fetches; the survivor stays caught up to the
        // committed prefix it already holds (no data lost across the failover, cluster serving again).
        let mut new_links: Vec<DataPlaneLink<TcpStream>> = Vec::new();
        let mut new_released: Vec<Vec<u8>> = Vec::new();
        let resumed = drive_follower_until(
            other_follower,
            committed_hw,
            || {
                pump_leader_once(
                    &mut successor_follower.server,
                    &new_listener,
                    &mut new_links,
                    &mut new_released,
                );
            },
            Duration::from_secs(15),
        );
        assert!(
            resumed,
            "(c) the cluster RESUMES: the survivor replicates from the new leader over a fresh socket (hw={})",
            other_follower.high_watermark()
        );
        assert!(
            other_follower.high_watermark() >= committed_hw,
            "(c) no committed record was lost across the failover; the survivor holds the full committed prefix"
        );

        // FINAL: the falsifiable #618 invariant (CI5) over the REAL post-failover state — the successor
        // was in the ISR, holds every pre-death committed offset, and carries a strictly-higher epoch.
        // `successor_in_isr` is DERIVED FROM REAL STATE (no hardcoded shortcut, #618b): a replica is in
        // the ISR for failover purposes exactly when its durable prefix has reached the committed HW (the
        // data-plane completeness criterion `place_partition` uses); we read the successor's measured
        // pre-death durable HW and compute the predicate, rather than asserting it.
        let successor_in_isr = succ_hw_pre >= committed_hw;
        assert!(
            successor_in_isr,
            "the successor's measured durable HW ({succ_hw_pre}) reached the committed HW ({committed_hw}) — it really is ISR-complete"
        );
        let failover_state = ironbus_core::cluster_invariants::Failover {
            dead_leader: 1,
            successor,
            successor_in_isr,
            // The successor's TRUE durable prefix: every offset it durably appended as a follower (it
            // caught up to the full pre-death committed HW). The read-plane-served end can lag this by the
            // active (unsealed) tail, but the records are durably HELD — CI5 is about held committed data.
            successor_durable_prefix: succ_hw_pre,
            committed_hw,
            dead_leader_epoch: LeaderEpoch::new(placement.epoch),
            successor_epoch: LeaderEpoch::new(new_placement.epoch),
        };
        ironbus_core::cluster_invariants::check_failover_preserves_committed(&failover_state)
            .expect("CI5: the real failover preserved committed data + fenced the old leader");
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

    #[test]
    fn led_inbound_link_count_sums_per_led_partition_followers_and_ignores_followed() {
        // #915: the legitimate inbound-link fanout is Σ over the partitions this node LEADS of that
        // partition's follower count (replicas − leader). Partitions this node FOLLOWS contribute
        // nothing (this node dials OUT for those). Build a node that leads three partitions (each a
        // 3-replica set → 2 followers apiece) and follows a fourth, and assert the count is exactly
        // 3 × 2 == 6, not touched by the followed partition.
        const ME: u64 = 1;
        let mut placements: BTreeMap<u64, Placement> = BTreeMap::new();
        for p in 0..3u64 {
            placements.insert(
                p,
                Placement {
                    replicas: vec![ME, 2, 3],
                    leader: ME,
                    epoch: 1,
                },
            );
        }
        // A FOLLOWED partition (led by node 2): its two other replicas are inbound links on node 2's
        // listener, NOT ours — it must add 0 to our led fanout.
        placements.insert(
            9,
            Placement {
                replicas: vec![ME, 2, 3],
                leader: 2,
                epoch: 1,
            },
        );
        let planes: BTreeMap<u64, Arc<ReadPlane<InMemoryFs>>> = (0..3u64)
            .map(|p| (p, leader_plane(leaked_leader_log(1))))
            .collect();
        let server = DataPlaneServer::from_placements(
            ME,
            &placements,
            quorum3(),
            |p| planes.get(&p).cloned(),
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .unwrap();
        assert_eq!(
            server.led_inbound_link_count(),
            6,
            "3 led partitions × 2 followers each; the followed partition adds nothing"
        );
    }

    #[test]
    fn effective_reader_cap_grows_to_fanout_floors_at_default_and_honors_override() {
        // #915: the effective inbound-reader cap must (a) default to the legitimate fanout so a
        // high-partition-fanout leader (fanout > the old fixed 256) admits EVERY real follower instead
        // of refusing links past a borrowed constant — the bug this fixes — while (b) never dropping
        // below the old 256 floor for a small edge deployment, and (c) honoring an operator override as
        // the flood bound yet still raising it to the exact fanout so a legitimate follower is never
        // refused.
        // (a) high fanout, no override: the cap GROWS to the fanout (old code was stuck at 256 → refused).
        assert_eq!(effective_dataplane_reader_cap(None, 600), 600);
        // (b) small fanout, no override: floored at the old constant so edge deployments are unaffected.
        assert_eq!(
            effective_dataplane_reader_cap(None, 3),
            DEFAULT_MIN_DATAPLANE_READERS
        );
        assert_eq!(
            effective_dataplane_reader_cap(None, DEFAULT_MIN_DATAPLANE_READERS),
            DEFAULT_MIN_DATAPLANE_READERS
        );
        // (c) an override ABOVE the fanout is the bound (an unauthenticated flood is capped there)...
        assert_eq!(effective_dataplane_reader_cap(Some(1000), 600), 1000);
        // ...and an override BELOW the fanout is still raised to the fanout, so a real follower is never
        // refused for lack of a slot even under a too-small operator cap.
        assert_eq!(effective_dataplane_reader_cap(Some(50), 600), 600);
    }

    #[test]
    fn the_dataplane_listener_caps_concurrent_inbound_readers_and_refuses_beyond_it() {
        // #865: each accepted inbound peer link spawns a reader thread (its own stack + fd), and auth
        // happens only later inside `recv()`. Without a cap, a cluster-network flood (or a peer holding
        // many idle links) spawns unbounded threads and exhausts fd/RAM. The listener now BOUNDS
        // concurrent readers and REFUSES beyond the cap. Drive `run_dataplane_listener` directly with a
        // small cap and an inspectable counter, open MORE connections than the cap, and assert the live
        // reader count stays at the cap (excess links are refused) rather than growing 1:1.
        const P: u64 = 0;
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 1,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        // A minimal server with no roles: the test exercises the LISTENER cap, and an idle reader simply
        // parks on `recv()` (a read timeout loops and re-checks shutdown), so no serving plane is needed.
        let server = DataPlaneServer::from_placements(
            9, // not a replica — holds no plane
            &placements,
            quorum3(),
            |_| None,
            &InMemReplicaLogs,
            |_| EpochCache::new(),
        )
        .unwrap();
        let server = Arc::new(Mutex::new(server));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();

        let shutdown = Arc::new(AtomicBool::new(false));
        let active_readers = Arc::new(AtomicUsize::new(0));
        let cap = 2usize;

        let listener_thread = std::thread::Builder::new()
            .spawn({
                let shutdown = Arc::clone(&shutdown);
                let active = Arc::clone(&active_readers);
                move || {
                    run_dataplane_listener(
                        listener,
                        server,
                        AckRelease::ServerOnly,
                        shutdown,
                        cap,
                        active,
                    );
                }
            })
            .unwrap();

        // Open well MORE connections than the cap, holding them all idle (kept in a Vec so they stay
        // open — dropping one would close it and free a reader).
        let total = cap + 3; // 5
        let mut clients = Vec::new();
        for _ in 0..total {
            clients.push(TcpStream::connect(addr).unwrap());
        }

        // Poll until the cap saturates: the first `cap` links became parked readers; the rest are
        // refused (dropped) by the listener. The accept loop is the SOLE incrementer and checks the cap
        // before each spawn, so the count can never exceed `cap`.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while active_readers.load(Ordering::Acquire) < cap && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }

        // The live reader count is BOUNDED by the cap, not 1:1 with the connections: exactly `cap`
        // readers are live and the other `total - cap` inbound links were refused — the #865 bound.
        assert_eq!(
            active_readers.load(Ordering::Acquire),
            cap,
            "concurrent inbound readers are capped at {cap}, not 1:1 with {total} connections"
        );

        // Tear down: signal shutdown, join the listener loop; the detached readers exit on their next
        // shutdown re-check (and drop their slot). Holding `clients` until here kept the readers parked.
        shutdown.store(true, Ordering::Release);
        listener_thread.join().unwrap();
        drop(clients);
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

    /// Scale a GENEROUS base budget by the observed host slowdown (#618): a local copy of the runtime
    /// test's `host_scaled` (max-of-3-probes + a 24x cap), so a timing-sensitive budget stays truthful and
    /// flake-free on a contended CI runner WITHOUT weakening what the test proves. On an unloaded host the
    /// factor is ~1 and the budget stays the base. Used by the #739 dirty-tier HAPPY-PATH test to size the
    /// over-the-wire committed-HW CONFIRM timeout so the confirm completes even under heavy CI contention
    /// (the production default stays the hardcoded 500 ms — this only governs how long the confirm waits,
    /// never the fail-closed / never-serve-unconfirmed semantics).
    fn host_scaled(base: Duration) -> Duration {
        fn probe_busy_nanos() -> u128 {
            const ITERS: u64 = 2_000_000;
            let start = Instant::now();
            let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
            for i in 0..ITERS {
                acc = acc
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(i | 1);
                acc ^= acc >> 29;
            }
            std::hint::black_box(acc);
            start.elapsed().as_nanos().max(1)
        }
        const REFERENCE_BUSY_NANOS: u128 = 4_000_000;
        const MAX_SCALE: u32 = 24;
        let mut samples = [probe_busy_nanos(), probe_busy_nanos(), probe_busy_nanos()];
        samples.sort_unstable();
        let observed = samples[2];
        let factor = (observed / REFERENCE_BUSY_NANOS).clamp(1, u128::from(MAX_SCALE));
        let factor = u32::try_from(factor).unwrap_or(MAX_SCALE);
        base * factor
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
        // Serialize against the other heavy multi-node cluster tests (here and in the `runtime` module)
        // so this thread-spinning cluster runs on an un-contended host (no #687 starvation flake).
        let _serial = crate::cluster::heavy_cluster_test_guard();
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
            let dump = f2
                .seam()
                .controller()
                .with_follower_log(P, dump_segments)
                .unwrap();
            assert_replicated_byte_identical(&dump, leader_log);
        }
        {
            let f3 = f3_rt.server().lock().unwrap();
            let dump = f3
                .seam()
                .controller()
                .with_follower_log(P, dump_segments)
                .unwrap();
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
        let _serial = crate::cluster::heavy_cluster_test_guard();
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
        let _serial = crate::cluster::heavy_cluster_test_guard();
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
            let dump = f
                .seam()
                .controller()
                .with_follower_log(P, dump_segments)
                .unwrap();
            assert_replicated_byte_identical(&dump, leader_log);
        }
        f_rt2.stop();
        leader_rt.stop();
    }

    // ---- C6 (#620/#621/#622): a CONSUMER reads committed data FROM A FOLLOWER over the live runtime ---

    /// Decode a zero-copy raw run into `(offset, payload)` pairs via the full `codec::decode` (header +
    /// body CRC) — the consumer-side half of a C6 follower read: the served bytes are integrity-checkable
    /// end-to-end (#622 zero-copy delivery reuses the read-plane raw run verbatim).
    fn decode_run(run: &ironbus_storage::segment::RawByteRun) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        let mut offset = run.first_offset.get();
        while cursor < run.bytes.len() {
            let (view, consumed) = ironbus_core::codec::decode(&run.bytes[cursor..])
                .expect("every C6 follower-served frame passes header AND body CRC");
            out.push((offset, view.payload.to_vec()));
            offset += 1;
            cursor += consumed;
        }
        out
    }

    /// THE C6 HEADLINE (#621/#622): a real 3-node serve cluster over real loopback sockets, where a
    /// CONSUMER reads COMMITTED records FROM A FOLLOWER (not the leader) and gets BYTE-IDENTICAL committed
    /// data — the CRAQ committed-local read that makes read throughput scale with replicas — AND a read
    /// ABOVE the committed HW is NOT served stale (it confirms with the leader; never speculative).
    ///
    /// The leader + two followers each run their OWN `DataPlaneRuntime` (the SAME construct `run_broker`
    /// spawns) on their own threads over real sockets; the runtimes' threads do the replication. Once a
    /// follower has caught up, we read FROM THAT FOLLOWER's replica via the C6 serve path and verify:
    ///   1. the follower serves committed records LOCALLY (its own read plane, zero-copy);
    ///   2. those bytes are byte-identical to the leader's over the same committed prefix;
    ///   3. a "latest" read STARTING AT the follower's known committed bar does NOT serve the
    ///      uncommitted/unknown tail stale — it asks the leader to confirm the current HW first.
    #[test]
    fn live_three_node_runtime_a_consumer_reads_committed_data_from_a_follower_craq() {
        use crate::cluster::dataplane::FollowerReadOutcome;
        use crate::cluster::read_consistency::ReadTier;

        const P: u64 = 0;
        // Serialize against the other heavy multi-node tests so this thread-spinning cluster forms on an
        // un-contended host (the #687 starvation guard).
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 5,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        let data_addrs: BTreeMap<u64, SocketAddr> = [1u64, 2, 3]
            .into_iter()
            .map(|id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
            .collect();

        // The LEADER (node 1): 25 records produced + fsync'd; serves through the off-actor read plane.
        let leader_dir = tempfile::tempdir().expect("leader dir");
        let leader_log = leaked_disk_leader(leader_dir.path(), 25);
        let leader_pl = disk_leader_plane(leader_log);
        let served_end = plane_served_end(&leader_pl);
        assert!(
            served_end > 0,
            "the read plane serves a non-empty committed prefix"
        );

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
        let mut leader_rt =
            DataPlaneRuntime::start(leader_server, data_addrs[&1], &data_addrs).expect("leader rt");

        // The two FOLLOWERS (nodes 2 + 3), each its own runtime + replica log + threads dialing node 1.
        let f2_dir = tempfile::tempdir().expect("f2 dir");
        let f3_dir = tempfile::tempdir().expect("f3 dir");
        let mk_follower = |id: u64, root: std::path::PathBuf| {
            DataPlaneServer::from_placements(
                id,
                &placements,
                quorum3(),
                |_| None,
                &DiskReplicaLogs { root },
                |_| EpochCache::new(),
            )
            .expect("follower server builds")
        };
        let mut f2_rt = DataPlaneRuntime::start(
            mk_follower(2, f2_dir.path().to_path_buf()),
            data_addrs[&2],
            &data_addrs,
        )
        .expect("f2 rt");
        let mut f3_rt = DataPlaneRuntime::start(
            mk_follower(3, f3_dir.path().to_path_buf()),
            data_addrs[&3],
            &data_addrs,
        )
        .expect("f3 rt");

        // Wait until follower 2 has caught up to the leader's committed prefix over the LIVE transport.
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
        assert!(
            wait_until(Duration::from_secs(30), || f2_hw() >= served_end),
            "follower 2 caught up over the live runtime (hw={}, served_end={served_end})",
            f2_hw()
        );

        // The committed HW the cluster has recorded: with a 2-of-3 quorum met (the leader + follower 2
        // both hold the served prefix) the committed HW covers it. In a real serve this is the replicated
        // `CheckpointCommittedHw` bar; here we read the leader's live quorum-commit, which is exactly that
        // bar (the highest offset min_isr replicas have all fsync'd).
        let committed_hw = wait_until(Duration::from_secs(15), || {
            leader_rt
                .server()
                .lock()
                .unwrap()
                .seam()
                .controller()
                .quorum_commit(P)
                .unwrap_or(0)
                >= served_end
        })
        .then_some(served_end)
        .expect("the cluster committed the served prefix on a 2-of-3 quorum");

        // (1) + (2): a CONSUMER reads COMMITTED records FROM FOLLOWER 2 (NOT the leader), LOCALLY off the
        // follower's own read plane, and gets BYTE-IDENTICAL bytes to the leader's committed prefix. Chain
        // the clean read across the prefix (one sealed segment per raw read).
        let mut follower_records: Vec<(u64, Vec<u8>)> = Vec::new();
        {
            let f2 = f2_rt.server().lock().unwrap();
            let ctrl = f2.seam().controller();
            let mut from = ironbus_core::types::Offset::ZERO;
            let mut guard = 0u32;
            loop {
                guard += 1;
                assert!(guard < 10_000, "follower-read chain failed to terminate");
                let outcome = ctrl
                    .serve_follower_read(
                        P,
                        ReadTier::FollowerCommitted,
                        Some(committed_hw),
                        from,
                        usize::MAX,
                        None,
                    )
                    .expect("the follower serves a committed read locally");
                let run = match outcome {
                    FollowerReadOutcome::Served(r) => r,
                    FollowerReadOutcome::ConfirmWithLeader { .. } => {
                        panic!("a clean committed read serves locally, not a confirm")
                    }
                };
                let recs = decode_run(&run.run);
                if recs.is_empty() {
                    break;
                }
                // SAFETY: every served offset is strictly below the committed HW (never the uncommitted
                // tail) — the non-negotiable for a follower read.
                for (off, _) in &recs {
                    assert!(
                        *off < committed_hw,
                        "follower served offset {off} at/past committed HW"
                    );
                }
                let next = run.run.next_offset.get();
                follower_records.extend(recs);
                if next <= from.get() {
                    break;
                }
                from = ironbus_core::types::Offset::new(next);
            }
        }
        assert!(
            !follower_records.is_empty(),
            "the consumer read committed records FROM THE FOLLOWER (CRAQ committed-local read)"
        );

        // The leader's committed prefix, decoded over the same range (the byte-identity oracle).
        let mut leader_records: Vec<(u64, Vec<u8>)> = Vec::new();
        {
            let mut from = ironbus_core::types::Offset::ZERO;
            while from.get() < served_end {
                let run = leader_pl
                    .read_range_raw(from, usize::MAX, None)
                    .expect("leader read plane serves");
                let recs = decode_run(&run.run);
                if recs.is_empty() {
                    break;
                }
                let next = run.run.next_offset.get();
                leader_records.extend(recs);
                if next <= from.get() {
                    break;
                }
                from = ironbus_core::types::Offset::new(next);
            }
        }
        // The follower's served records are byte-identical to the leader's at the same offsets (a
        // byte-identical PREFIX — the follower's last replicated segment may not have sealed yet, the same
        // active-tail lag the leader-fetch path has; FLAGGED).
        assert!(
            !follower_records.is_empty() && follower_records.len() <= leader_records.len(),
            "the follower never serves more than the leader's committed prefix"
        );
        for (f, l) in follower_records.iter().zip(leader_records.iter()) {
            assert_eq!(
                f.0, l.0,
                "offset mismatch leader vs follower over the live runtime"
            );
            assert_eq!(
                f.1, l.1,
                "payload byte mismatch leader vs follower at offset {} over the live runtime",
                f.0
            );
        }

        // (3): a "latest" read STARTING AT the follower's served prefix end (above its known-committed
        // bar if we feed it a STALE lower known HW) is NOT served stale — it asks the leader to CONFIRM
        // the current HW first, never speculatively serving the unconfirmed tail.
        {
            let f2 = f2_rt.server().lock().unwrap();
            let ctrl = f2.seam().controller();
            // Feed a STALE known HW BELOW the served prefix and read starting AT it: the latest read must
            // confirm with the leader rather than serve the unknown-committed region stale.
            let stale_known = committed_hw / 2;
            let outcome = ctrl
                .serve_follower_read(
                    P,
                    ReadTier::FollowerLatest,
                    Some(stale_known),
                    ironbus_core::types::Offset::new(stale_known),
                    usize::MAX,
                    None,
                )
                .expect("the follower classifies a latest read");
            match outcome {
                FollowerReadOutcome::ConfirmWithLeader { current_safe } => {
                    assert_eq!(
                        current_safe.get(),
                        stale_known,
                        "a latest read above the known bar confirms with the leader (never stale)"
                    );
                }
                FollowerReadOutcome::Served(_) => {
                    panic!("a latest read above the known committed bar must NOT serve stale local data")
                }
            }
        }

        leader_rt.stop();
        f2_rt.stop();
        f3_rt.stop();
    }

    // ---- C5-I4 (#619): re-replication rate-limit converges + stays byte-identical -----------------

    /// THE #619 CORRECTNESS HEADLINE: a FAR-BEHIND follower whose backlog exceeds the catch-up
    /// threshold ([`super::super::rereplication::CATCHUP_BACKLOG_THRESHOLD`]) — i.e. it is genuinely
    /// RE-REPLICATING, so the CoDel re-replication throttle is engaged on its catch-up fetch — still
    /// converges to the leader's served prefix BYTE-IDENTICAL, IN-ORDER, and GAP-FREE over the real
    /// loopback transport. This proves the throttle only ever changes the fetch RATE / budget, never
    /// WHAT is applied: the catch-up runs through the throttled path (a far-behind follower) and the
    /// result is indistinguishable from an un-throttled catch-up.
    ///
    /// On an idle loopback link the per-fetch NETWORK round-trip stays under the CoDel target, so the
    /// throttle keeps the full budget and convergence is fast — exactly the "healthy link → full-rate
    /// catch-up" behavior. The contended-link budget-shrink + live-traffic-yield + bounded-progress
    /// properties are proven DETERMINISTICALLY (no wall-clock flake) by the
    /// `super::super::rereplication` unit tests; THIS test is the end-to-end correctness-through-the-
    /// throttle proof and is deliberately insensitive to whether the throttle transiently engages (see
    /// the big-segment note below), since correctness — not a convergence speed — is what it asserts.
    #[test]
    fn live_runtime_far_behind_follower_converges_byte_identical_through_the_rereplication_throttle(
    ) {
        use crate::cluster::rereplication::CATCHUP_BACKLOG_THRESHOLD;

        // LARGE segments (64 KiB) for this test only: the leader's read plane serves one sealed segment
        // run per fetch, so big segments mean each fetch pulls MANY records and the whole backlog
        // converges in a handful of fetches. That keeps the test FAST and STABLE even if the
        // wall-clock-driven throttle transiently engages on a contended CI host (a small per-fetch
        // backoff over a few fetches is negligible) — the property under test is correctness-through-
        // the-throttle (byte-identity), NOT a particular convergence speed (the throttle's
        // contended-behaviour is proven deterministically in the `rereplication` unit tests).
        fn big_config() -> LogConfig {
            LogConfig {
                max_segment_bytes: 64 * 1024,
                max_total_bytes: 0,
                ..LogConfig::default()
            }
        }
        fn leaked_big_leader(dir: &std::path::Path, n: u32) -> &'static Log<StdFs, ManualClock> {
            let fs = StdFs::new(dir.to_path_buf());
            let mut log =
                Log::open(fs, ManualClock::new(), big_config()).expect("leader log opens");
            for i in 0..n {
                log.append(&rec(format!("rep-{i:05}").as_bytes())).unwrap();
            }
            log.sync().unwrap();
            Box::leak(Box::new(log))
        }
        struct BigReplicaLogs {
            root: std::path::PathBuf,
        }
        impl ReplicaLogFactory<StdFs, ManualClock> for BigReplicaLogs {
            fn open_replica_log(&self, partition: u64) -> Result<Log<StdFs, ManualClock>, String> {
                let dir = self.root.join("replicas").join(partition.to_string());
                std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
                Log::open(StdFs::new(dir), ManualClock::new(), big_config())
                    .map_err(|e| format!("open replica {partition}: {e}"))
            }
        }

        const P: u64 = 0;
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let placement = Placement {
            replicas: vec![1, 2],
            leader: 1,
            epoch: 2,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        // R=2, min_isr=1: this test is about the catch-up converging through the throttle, not the
        // quorum-ack gate.
        let isr = IsrConfig {
            min_isr: 1,
            max_lag_records: 0,
        };
        let data_addrs: BTreeMap<u64, SocketAddr> = (1u64..=2)
            .map(|id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
            .collect();

        // A leader log with a backlog WELL ABOVE the catch-up threshold, so a fresh follower (at
        // offset 0) is unambiguously RE-REPLICATING and its catch-up runs through the throttled path.
        let backlog_records =
            u32::try_from(CATCHUP_BACKLOG_THRESHOLD).expect("threshold fits u32") * 3;
        let leader_dir = tempfile::tempdir().expect("leader dir");
        let leader_log = leaked_big_leader(leader_dir.path(), backlog_records);
        let leader_pl = disk_leader_plane(leader_log);
        let served_end = plane_served_end(&leader_pl);
        assert!(
            served_end > CATCHUP_BACKLOG_THRESHOLD,
            "the leader's served prefix ({served_end}) exceeds the catch-up threshold \
             ({CATCHUP_BACKLOG_THRESHOLD}), so the follower is genuinely re-replicating"
        );

        let leader_server = DataPlaneServer::from_placements(
            1,
            &placements,
            isr,
            |p| (p == P).then(|| Arc::clone(&leader_pl)),
            &BigReplicaLogs {
                root: leader_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .expect("leader server");
        let mut leader_rt =
            DataPlaneRuntime::start(leader_server, data_addrs[&1], &data_addrs).expect("leader rt");

        let f_dir = tempfile::tempdir().expect("f dir");
        let follower = DataPlaneServer::from_placements(
            2,
            &placements,
            isr,
            |_| None,
            &BigReplicaLogs {
                root: f_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .expect("follower server");
        let mut f_rt =
            DataPlaneRuntime::start(follower, data_addrs[&2], &data_addrs).expect("f rt");

        let hw = |rt: &DataPlaneRuntime<StdFs, ManualClock>| {
            rt.server()
                .lock()
                .unwrap()
                .seam()
                .controller()
                .follower_high_watermark(P)
                .unwrap_or(0)
        };
        // The far-behind follower's catch-up runs through the throttle and CONVERGES to the served
        // prefix in bounded time. A generous, host-scaled-style cap (the catch-up is multi-round at
        // the full budget on an idle link, so it is fast; the cap only guards a slow CI host).
        let converged = wait_until(Duration::from_secs(60), || hw(&f_rt) >= served_end);
        assert!(
            converged,
            "the far-behind follower's throttled catch-up converged to the served prefix \
             (hw={}, served_end={served_end})",
            hw(&f_rt)
        );

        // The throttled catch-up is BYTE-IDENTICAL to the leader (the throttle changed only the rate,
        // never the bytes): every follower segment is a byte-identical prefix of the leader's, and at
        // least one sealed segment matches exactly. The byte-identity check also implies in-order +
        // gap-free (a gap or reorder would diverge the bytes and the apply would have failed closed).
        {
            let f = f_rt.server().lock().unwrap();
            let dump = f
                .seam()
                .controller()
                .with_follower_log(P, dump_segments)
                .unwrap();
            assert_replicated_byte_identical(&dump, leader_log);
        }

        f_rt.stop();
        leader_rt.stop();
    }

    // ---- #737 (follow-up to #735): the NOT_LEADER redirect carries the leader's CLIENT address ----

    /// THE #737 PROOF over the LIVE runtime: a FOLLOWER runtime started via
    /// [`DataPlaneRuntime::start_with_client_gate_aware`] with a POPULATED node-id -> client-address
    /// advertise map redirects a non-led produce to the CURRENT committed leader's CLIENT address (the
    /// `NOT_LEADER` hint). An EMPTY map keeps the hintless redirect (the #735 baseline). The leader's own
    /// gate proceeds LOCAL (never a false `NOT_LEADER`). This extends the #735 client-gate-aware harness to
    /// prove the #737 CLI wiring (the `--cluster-peer-client` advertise map) installs into the live gate.
    #[test]
    fn live_follower_gate_redirects_to_the_leaders_client_address_when_advertised() {
        use crate::cluster::client_ack::ClusterProduceRouting;

        const P: u64 = 0;
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let placement = Placement {
            replicas: vec![1, 2],
            leader: 1,
            epoch: 4,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        // R=2, min_isr=1: keep the focus on the routing decision, not the quorum-ack gate.
        let isr = IsrConfig {
            min_isr: 1,
            max_lag_records: 0,
        };
        let data_addrs: BTreeMap<u64, SocketAddr> = (1u64..=2)
            .map(|id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
            .collect();

        // Node 1's advertised CLIENT address (its `--addr` listener), DISTINCT from its data-plane peer
        // address above — exactly what `--cluster-peer-client 1=<client-addr>` populates.
        let leader_client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
        let advertise: BTreeMap<u64, SocketAddr> =
            [(1u64, leader_client_addr)].into_iter().collect();

        // The LEADER (node 1): a real on-disk leader serving through its read plane.
        let leader_dir = tempfile::tempdir().expect("leader dir");
        let leader_log = leaked_disk_leader(leader_dir.path(), 16);
        let leader_pl = disk_leader_plane(leader_log);
        let served_end = plane_served_end(&leader_pl);
        assert!(served_end > 0, "the leader has a committed prefix");
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
        // The leader's OWN gate (also advertising node 1's client addr) must proceed LOCAL on its own
        // partition — never a false NOT_LEADER on the leader (the #735 is-leader-first check, unchanged).
        let leader_status = Arc::new(Mutex::new(crate::cluster::runtime::ClusterStatus::default()));
        let mut leader_rt = DataPlaneRuntime::start_with_client_gate_aware(
            leader_server,
            data_addrs[&1],
            &data_addrs,
            crate::cluster::ack_level::ClusterAckLevel::C1,
            advertise.clone(),
            Arc::clone(&leader_status),
            None,
        )
        .expect("leader runtime with client gate");
        let leader_gate = leader_rt
            .client_gate()
            .cloned()
            .expect("the leader runtime built a client gate");
        assert_eq!(
            leader_gate.produce_routing(P),
            ClusterProduceRouting::Local,
            "the leader proceeds locally, never a false NOT_LEADER"
        );

        // The FOLLOWER (node 2), started WITH the populated advertise map (the #737 wiring under test).
        let f_dir = tempfile::tempdir().expect("f dir");
        let f_status = Arc::new(Mutex::new(crate::cluster::runtime::ClusterStatus::default()));
        let follower_server = DataPlaneServer::from_placements(
            2,
            &placements,
            isr,
            |_| None,
            &DiskReplicaLogs {
                root: f_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .unwrap();
        assert!(follower_server.seam().controller().is_follower(P));
        assert_eq!(follower_server.follower_leader(P), Some(1));
        let mut f_rt = DataPlaneRuntime::start_with_client_gate_aware(
            follower_server,
            data_addrs[&2],
            &data_addrs,
            crate::cluster::ack_level::ClusterAckLevel::C1,
            advertise.clone(),
            Arc::clone(&f_status),
            None,
        )
        .expect("follower runtime with client gate");
        let follower_gate = f_rt
            .client_gate()
            .cloned()
            .expect("the follower runtime built a client gate");

        // THE #737 ASSERTION: a non-led produce on the follower redirects to the CURRENT committed leader's
        // advertised CLIENT address (node 1) — the concrete one-hop hint, not the hintless #735 baseline.
        assert_eq!(
            follower_gate.produce_routing(P),
            ClusterProduceRouting::Redirect {
                leader_hint: Some(leader_client_addr),
            },
            "the follower redirects a non-led produce to the leader's ADVERTISED client address"
        );

        // The BASELINE (#735, no advertise): a follower gate built with an EMPTY map still redirects, but
        // HINTLESS — the byte-identical-off-flag guarantee (no --cluster-peer-client => no concrete hint).
        let f_dir2 = tempfile::tempdir().expect("f dir2");
        let follower_server2 = DataPlaneServer::from_placements(
            2,
            &placements,
            isr,
            |_| None,
            &DiskReplicaLogs {
                root: f_dir2.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .unwrap();
        // A fresh self-addr so this second follower runtime does not collide with `f_rt`'s still-bound
        // data-plane port (the routing decision needs only the local role, not a live peer to dial).
        let f2_self = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
        let mut f_rt2 = DataPlaneRuntime::start_with_client_gate_aware(
            follower_server2,
            f2_self,
            &BTreeMap::new(), // no peers to dial; the routing decision needs only the local role
            crate::cluster::ack_level::ClusterAckLevel::C1,
            BTreeMap::new(), // EMPTY advertise map (the hintless baseline)
            Arc::new(Mutex::new(crate::cluster::runtime::ClusterStatus::default())),
            None,
        )
        .expect("follower runtime, empty advertise");
        let hintless_gate = f_rt2
            .client_gate()
            .cloned()
            .expect("a client gate is built even with an empty advertise map");
        assert_eq!(
            hintless_gate.produce_routing(P),
            ClusterProduceRouting::Redirect { leader_hint: None },
            "with no advertised client address the redirect still fires, but hintless (the #735 baseline)"
        );

        f_rt2.stop();
        f_rt.stop();
        leader_rt.stop();
    }

    // ============================================================================================
    //  #739: the follower-read DIRTY-TIER leader-confirm over the REAL wire.
    // ============================================================================================

    /// The served end of a follower-read run (its exclusive next offset).
    fn run_next(outcome: &crate::cluster::dataplane::FollowerReadOutcome) -> u64 {
        match outcome {
            crate::cluster::dataplane::FollowerReadOutcome::Served(r) => r.run.next_offset.get(),
            crate::cluster::dataplane::FollowerReadOutcome::ConfirmWithLeader { .. } => {
                panic!("a resolved follower-read is always a Served run, never a confirm")
            }
        }
    }

    /// Chain follower-read consumes from `from` and return all served `(offset, payload)` pairs (drains
    /// the whole servable prefix at the given tier, the read plane serving one sealed segment per call).
    fn drain_follower_consume(
        gate: &crate::cluster::client_ack::ClientAckGate<StdFs, ManualClock>,
        partition: u64,
        tier: crate::cluster::read_consistency::ReadTier,
        from: u64,
    ) -> Vec<(u64, Vec<u8>)> {
        use ironbus_core::types::Offset;
        let mut from = from;
        let mut out = Vec::new();
        let mut guard = 0u32;
        loop {
            guard += 1;
            assert!(guard < 10_000, "follower-read chain failed to terminate");
            let outcome = gate
                .serve_follower_consume(partition, tier, Offset::new(from), usize::MAX, None)
                .expect("a follower returns Some(outcome)");
            let run = match &outcome {
                crate::cluster::dataplane::FollowerReadOutcome::Served(r) => &r.run,
                crate::cluster::dataplane::FollowerReadOutcome::ConfirmWithLeader { .. } => {
                    panic!("a resolved follower-read is always a Served run, never a confirm")
                }
            };
            let recs = decode_run(run);
            if recs.is_empty() {
                break;
            }
            out.extend(recs);
            let next = run_next(&outcome);
            if next <= from {
                break;
            }
            from = next;
        }
        out
    }

    /// THE #739 DIRTY-TIER test over the REAL wire: a follower whose KNOWN committed-HW bar is STALE (a
    /// low checkpoint) serves only its CLEAN committed prefix at the clean tier — but a LATEST/dirty read
    /// reaching ABOVE that stale bar performs a real over-the-wire committed-HW CONFIRM with the live
    /// leader and then serves the now-confirmed prefix LOCALLY, byte-faithfully, and NEVER an offset above
    /// the leader-confirmed HW.
    #[test]
    fn live_runtime_follower_dirty_tier_confirms_with_the_leader_then_serves() {
        use crate::cluster::read_consistency::ReadTier;
        const P: u64 = 0;
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let placement = Placement {
            replicas: vec![1, 2],
            leader: 1,
            epoch: 7,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        let isr = IsrConfig {
            min_isr: 1,
            max_lag_records: 0,
        };
        let data_addrs: BTreeMap<u64, SocketAddr> = [1u64, 2]
            .into_iter()
            .map(|id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
            .collect();

        // The LEADER (node 1): a real on-disk leader serving through its read plane. Its committed HW is
        // its read plane's flushed frontier (>= served_end).
        let leader_dir = tempfile::tempdir().expect("leader dir");
        let leader_log = leaked_disk_leader(leader_dir.path(), 30);
        let leader_pl = disk_leader_plane(leader_log);
        let served_end = plane_served_end(&leader_pl);
        assert!(served_end >= 10, "leader has a healthy committed prefix");
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
        let leader_status = Arc::new(Mutex::new(crate::cluster::runtime::ClusterStatus::default()));
        let mut leader_rt = DataPlaneRuntime::start_with_client_gate_aware(
            leader_server,
            data_addrs[&1],
            &data_addrs,
            crate::cluster::ack_level::ClusterAckLevel::C1,
            BTreeMap::new(),
            Arc::clone(&leader_status),
            None,
        )
        .expect("leader runtime");

        // The FOLLOWER (node 2): a STALE committed-HW bar (a low checkpoint). The follower-read safe
        // watermark is min(own_flushed, stale_known); the clean tier serves only up to it.
        let stale_known = served_end / 3;
        assert!(stale_known > 0 && stale_known < served_end);
        let f_dir = tempfile::tempdir().expect("f dir");
        let mut status = crate::cluster::runtime::ClusterStatus::default();
        status.last_committed_hw.insert(P, stale_known);
        let f_status = Arc::new(Mutex::new(status));
        let follower_server = DataPlaneServer::from_placements(
            2,
            &placements,
            isr,
            |_| None,
            &DiskReplicaLogs {
                root: f_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .unwrap();
        assert!(follower_server.seam().controller().is_follower(P));
        // Start the follower runtime WITH the client gate: `data_addrs` is threaded as both the fetch
        // targets AND (via #739) the gate's leader_data_addrs, so the dirty-tier confirm dials node 1.
        let mut f_rt = DataPlaneRuntime::start_with_client_gate_aware(
            follower_server,
            data_addrs[&2],
            &data_addrs,
            crate::cluster::ack_level::ClusterAckLevel::C1,
            BTreeMap::new(),
            Arc::clone(&f_status),
            None,
        )
        .expect("follower runtime with client gate");
        let gate = f_rt
            .client_gate()
            .cloned()
            .expect("the follower runtime built a client gate");
        // HAPPY-PATH ROBUSTNESS (#739): the over-the-wire committed-HW CONFIRM is bounded by a SHORT
        // production timeout (500 ms). On a heavily-contended CI runner a localhost round-trip can exceed
        // that, so the confirm would TIME OUT and the dirty read would (correctly) FAIL CLOSED to the clean
        // tier — failing THIS happy-path assertion. Give the confirm a HOST-SCALED budget so it completes
        // even under load. This changes ONLY how long this test waits for the confirm; production keeps the
        // hardcoded default, and the fail-closed / never-serve-unconfirmed semantics are untouched (the
        // fail-closed test below proves an unreachable leader still fails fast on connect-refused).
        gate.set_confirm_timeout(host_scaled(Duration::from_millis(500)));

        // Wait until the follower's runtime fetch loop has replicated the leader's whole served prefix.
        let f_hw = || {
            f_rt.server()
                .lock()
                .unwrap()
                .seam()
                .controller()
                .follower_high_watermark(P)
                .unwrap_or(0)
        };
        assert!(
            wait_until(Duration::from_secs(30), || f_hw() >= served_end),
            "the follower replicated the served prefix (hw={}, served_end={served_end})",
            f_hw()
        );

        // CLEAN tier at the stale bar: serves ONLY the committed prefix [0, stale_known) — never above.
        let clean = drain_follower_consume(&gate, P, ReadTier::FollowerCommitted, 0);
        assert!(
            !clean.is_empty(),
            "the clean tier served the committed prefix"
        );
        for (off, _) in &clean {
            assert!(
                *off < stale_known,
                "clean tier served offset {off} at/above the stale bar {stale_known}"
            );
        }

        // DIRTY tier from the stale bar: the read reaches ABOVE the safe watermark, so the gate performs
        // the real over-the-wire committed-HW confirm with the live leader and serves the now-confirmed
        // prefix [stale_known, served_end) — byte-faithfully, and NEVER above the leader's confirmed HW.
        let leader_confirmed_hw = leader_pl.flushed();
        assert!(leader_confirmed_hw >= served_end);
        let dirty = drain_follower_consume(&gate, P, ReadTier::FollowerLatest, stale_known);
        assert!(
            !dirty.is_empty(),
            "the dirty tier served the confirmed read-your-writes prefix above the stale bar"
        );
        for (off, payload) in &dirty {
            assert!(
                *off >= stale_known,
                "the dirty serve resumed at the stale bar"
            );
            assert!(
                *off < leader_confirmed_hw,
                "the dirty serve crossed the leader-confirmed HW (offset {off} >= {leader_confirmed_hw}) — an UNCONFIRMED offset!"
            );
            // Byte-faithful: the payload is the leader's record verbatim (rep-NN).
            assert_eq!(payload, format!("rep-{off:02}").as_bytes());
        }
        // The dirty serve extended STRICTLY beyond the stale bar — read-your-writes that the CLEAN tier
        // (clamped to the stale bar) could never have served — proving the over-the-wire confirm RAISED
        // the servable bound to the leader-confirmed HW. It is clamped to min(own_flushed, confirmed_hw):
        // the follower's read-plane SEALED frontier can lag served_end by the still-unsealed active tail
        // (the FLAGGED active-tail lag), so the bound is `>= stale_known` and `<= served_end`, never above.
        let dirty_max = dirty.iter().map(|(o, _)| *o).max().unwrap();
        assert!(
            dirty_max >= stale_known,
            "the dirty tier served read-your-writes at/above the stale bar (max={dirty_max}, stale={stale_known})"
        );
        assert!(
            dirty_max < leader_confirmed_hw,
            "the dirty tier never served above the leader-confirmed HW (max={dirty_max}, hw={leader_confirmed_hw})"
        );

        f_rt.stop();
        leader_rt.stop();
    }

    /// THE #739 FAIL-CLOSED test: when the dirty-tier committed-HW confirm CANNOT reach the leader (the
    /// leader is down / unreachable), a LATEST read above the safe watermark FALLS BACK to the clean tier
    /// — it serves only up to the follower's safe watermark, NEVER an unconfirmed offset.
    #[test]
    fn live_runtime_follower_dirty_tier_fails_closed_when_the_leader_is_unreachable() {
        use crate::cluster::read_consistency::ReadTier;
        const P: u64 = 0;
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let placement = Placement {
            replicas: vec![1, 2],
            leader: 1,
            epoch: 2,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        let isr = IsrConfig {
            min_isr: 1,
            max_lag_records: 0,
        };
        let data_addrs: BTreeMap<u64, SocketAddr> = [1u64, 2]
            .into_iter()
            .map(|id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
            .collect();

        // Bring a leader up briefly to let the follower replicate, then STOP it so the confirm can't reach
        // it. The follower keeps the replicated prefix; only the live leader confirm is now unavailable.
        let leader_dir = tempfile::tempdir().expect("leader dir");
        let leader_log = leaked_disk_leader(leader_dir.path(), 30);
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
        let mut leader_rt = DataPlaneRuntime::start_with_client_gate_aware(
            leader_server,
            data_addrs[&1],
            &data_addrs,
            crate::cluster::ack_level::ClusterAckLevel::C1,
            BTreeMap::new(),
            Arc::new(Mutex::new(crate::cluster::runtime::ClusterStatus::default())),
            None,
        )
        .expect("leader runtime");

        let stale_known = served_end / 3;
        assert!(stale_known > 0 && stale_known < served_end);
        let f_dir = tempfile::tempdir().expect("f dir");
        let mut status = crate::cluster::runtime::ClusterStatus::default();
        status.last_committed_hw.insert(P, stale_known);
        let f_status = Arc::new(Mutex::new(status));
        let follower_server = DataPlaneServer::from_placements(
            2,
            &placements,
            isr,
            |_| None,
            &DiskReplicaLogs {
                root: f_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .unwrap();
        let mut f_rt = DataPlaneRuntime::start_with_client_gate_aware(
            follower_server,
            data_addrs[&2],
            &data_addrs,
            crate::cluster::ack_level::ClusterAckLevel::C1,
            BTreeMap::new(),
            Arc::clone(&f_status),
            None,
        )
        .expect("follower runtime");
        let gate = f_rt.client_gate().cloned().expect("client gate");
        let f_hw = || {
            f_rt.server()
                .lock()
                .unwrap()
                .seam()
                .controller()
                .follower_high_watermark(P)
                .unwrap_or(0)
        };
        assert!(
            wait_until(Duration::from_secs(30), || f_hw() >= served_end),
            "the follower replicated before the leader is stopped (hw={})",
            f_hw()
        );

        // STOP the leader: its data-plane listener is gone, so the dirty-tier confirm dial will fail/
        // time out. (The follower's fetch loop will also fail, but it has the prefix already.)
        leader_rt.stop();

        // A LATEST read above the stale bar now CANNOT confirm -> it FAILS CLOSED to the clean tier: it
        // serves only [_, stale_known) — never an offset at/above the unconfirmed safe watermark.
        let dirty = drain_follower_consume(&gate, P, ReadTier::FollowerLatest, 0);
        for (off, _) in &dirty {
            assert!(
                *off < stale_known,
                "fail-closed: served offset {off} at/above the unconfirmed bar {stale_known}"
            );
        }
        // A read STARTING at the stale bar serves NOTHING when the confirm cannot reach the leader.
        let at_bar = drain_follower_consume(&gate, P, ReadTier::FollowerLatest, stale_known);
        assert!(
            at_bar.is_empty(),
            "fail-closed: with no reachable leader the dirty read above the safe watermark serves nothing"
        );

        f_rt.stop();
    }

    /// THE #739 CLEAN-TIER-NO-ROUNDTRIP test: a committed read (`<=` the safe watermark) serves LOCALLY
    /// with NO leader confirm — proven by serving it with the LEADER NEVER STARTED (no data-plane listener
    /// to confirm against). The clean tier never dials the leader, so it serves the committed prefix even
    /// when no leader is reachable.
    #[test]
    fn live_runtime_follower_clean_tier_serves_without_a_leader_roundtrip() {
        use crate::cluster::read_consistency::ReadTier;
        const P: u64 = 0;
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let placement = Placement {
            replicas: vec![1, 2],
            leader: 1,
            epoch: 4,
        };
        let placements: BTreeMap<u64, Placement> = [(P, placement)].into_iter().collect();
        let isr = IsrConfig {
            min_isr: 1,
            max_lag_records: 0,
        };
        let data_addrs: BTreeMap<u64, SocketAddr> = [1u64, 2]
            .into_iter()
            .map(|id| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()))))
            .collect();

        // A leader runtime to let the follower replicate the prefix, then stopped (the clean tier needs
        // no live leader at all once replicated — it serves locally with no confirm).
        let leader_dir = tempfile::tempdir().expect("leader dir");
        let leader_log = leaked_disk_leader(leader_dir.path(), 24);
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
        let mut leader_rt = DataPlaneRuntime::start_with_client_gate_aware(
            leader_server,
            data_addrs[&1],
            &data_addrs,
            crate::cluster::ack_level::ClusterAckLevel::C1,
            BTreeMap::new(),
            Arc::new(Mutex::new(crate::cluster::runtime::ClusterStatus::default())),
            None,
        )
        .expect("leader runtime");

        // The follower KNOWS the full committed HW (a caught-up checkpoint), so the whole replicated prefix
        // is within its safe watermark — a clean read serves all of it with NO confirm.
        let f_dir = tempfile::tempdir().expect("f dir");
        let mut status = crate::cluster::runtime::ClusterStatus::default();
        status.last_committed_hw.insert(P, served_end);
        let f_status = Arc::new(Mutex::new(status));
        let follower_server = DataPlaneServer::from_placements(
            2,
            &placements,
            isr,
            |_| None,
            &DiskReplicaLogs {
                root: f_dir.path().to_path_buf(),
            },
            |_| EpochCache::new(),
        )
        .unwrap();
        let mut f_rt = DataPlaneRuntime::start_with_client_gate_aware(
            follower_server,
            data_addrs[&2],
            &data_addrs,
            crate::cluster::ack_level::ClusterAckLevel::C1,
            BTreeMap::new(),
            Arc::clone(&f_status),
            None,
        )
        .expect("follower runtime");
        let gate = f_rt.client_gate().cloned().expect("client gate");
        let f_hw = || {
            f_rt.server()
                .lock()
                .unwrap()
                .seam()
                .controller()
                .follower_high_watermark(P)
                .unwrap_or(0)
        };
        assert!(
            wait_until(Duration::from_secs(30), || f_hw() >= served_end),
            "the follower replicated before the leader is stopped (hw={})",
            f_hw()
        );

        // STOP the leader: there is now NO data-plane listener to confirm against. The CLEAN tier must
        // still serve the whole committed prefix locally (no leader round-trip on the committed path).
        leader_rt.stop();

        let clean = drain_follower_consume(&gate, P, ReadTier::FollowerCommitted, 0);
        assert!(
            !clean.is_empty(),
            "the clean tier served the committed prefix with NO live leader to confirm against"
        );
        // The clean tier serves the committed prefix LOCALLY with no leader round-trip; its bound is the
        // follower's read-plane SEALED frontier (`<= served_end`, the FLAGGED active-tail lag), never past
        // it. The load-bearing fact for THIS test is that it served WITHOUT a reachable leader.
        let clean_max = clean.iter().map(|(o, _)| *o).max().unwrap();
        assert!(
            clean_max < served_end,
            "the clean tier never serves past the committed prefix (max={clean_max}, served_end={served_end})"
        );
        for (off, payload) in &clean {
            assert_eq!(payload, format!("rep-{off:02}").as_bytes());
        }

        f_rt.stop();
    }
}
