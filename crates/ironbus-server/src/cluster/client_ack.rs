// SPDX-License-Identifier: MIT OR Apache-2.0
//! The CLIENT produce-ack gate (#719, V2-C2): the one shared handle that makes the (`Send`)
//! [`ProduceAckSeam`](super::dataplane::ProduceAckSeam) reachable from a real producer connection's
//! per-connection produce-ack path, so a clustered `C2-fsync` produce to a LED partition gets its wire
//! `PubAck` only AFTER quorum-fsync — not the immediate local-fsync ack.
//!
//! # The problem it closes
//!
//! After #718 the data plane RUNS: the [`DataPlaneRuntime`](super::serve::DataPlaneRuntime) replicates
//! over real TCP and DRIVES the seam's park/release end-to-end from the live follower reports — but a
//! real EXTERNAL CLIENT's wire `PubAck` was still sent on the immediate local-fsync ack, because the
//! seam lives inside the runtime's peer-I/O thread and the per-connection produce path (`session.rs`)
//! could not reach it: sessions touch the engine only via the per-call
//! [`EngineAccess`](crate::actor::EngineAccess) trait, with no shared mutable seam state, and a
//! released ack arrives on the RUNTIME's thread while only the owning connection's OWN thread may write
//! its socket.
//!
//! # The shape (mirrors the #497 Level-2 confirm registry)
//!
//! [`ClientAckGate`] is an `Arc`-shared, `Send + Sync` bundle of:
//! * the SAME [`Arc<Mutex<DataPlaneServer>>`](super::serve::DataPlaneServer) the
//!   [`DataPlaneRuntime`](super::serve::DataPlaneRuntime) drives (ONE seam — one source of truth for the
//!   parked state); and
//! * a per-producer-connection OUTBOX of RELEASED-but-not-yet-flushed wire `PubAck` bytes, keyed by the
//!   producer's [`MemberId`](ironbus_core::keyshared::MemberId).
//!
//! The produce path, on `Appended(offset)` for a clustered `C2-fsync` led produce, calls
//! [`ClientAckGate::on_local_fsynced_ack`] tagging the park with the connection's member id; if the
//! ack is PARKED it withholds the wire `PubAck`. The runtime's follower-report path calls
//! [`ClientAckGate::on_follower_report`], which drives the gate and DEPOSITS each released reply into
//! its owner's outbox. The owning connection then DRAINS its outbox on its OWN next pass
//! ([`ClientAckGate::drain_released`]) — exactly the cross-thread hand-off the #497 `ProduceConfirm`
//! registry uses (a terminal produced on another thread, drained on the producer's own pass).
//!
//! # Single-node byte-identical (BY CONSTRUCTION)
//!
//! A non-clustered broker NEVER constructs a [`ClientAckGate`] (it is created only on the clustered
//! disk serve path), so the produce-ack hot path never consults it: the
//! [`EngineAccess`](crate::actor::EngineAccess) handle carries `None`, the produce path's
//! cluster-gated branch is skipped, and the immediate ack-after-local-fsync path is byte-for-byte
//! today's, with ZERO added work, latency, or allocation. The gate is a no-op without a cluster.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ironbus_core::clock::Clock;
use ironbus_core::keyshared::MemberId;
use ironbus_core::types::Offset;
use ironbus_storage::fs::Filesystem;

use super::ack_level::ClusterAckLevel;
use super::dataplane::{AckDisposition, FollowerReadOutcome};
use super::isr::AckReplicatedBody;
use super::read_consistency::ReadTier;
use super::serve::DataPlaneServer;

/// The fixed partition the broker's DEFAULT-stream log maps to in a clustered serve (#717/#719).
/// Today's broker is single-stream; the data plane replicates that one log as partition `0` and the
/// client produce-ack gate routes every produce to it. Multi-partition routing (a produce to the right
/// partition leader's seam) is the #693 multi-partition engine — FLAGGED, out of scope here.
pub const DEFAULT_PARTITION: u64 = 0;

/// How a clustered produce to `partition` should be ROUTED at the wire level (#735, the `NOT_LEADER`
/// redirect, half A). The output of [`ClientAckGate::produce_routing`]: the produce path consults it
/// BEFORE any local append/ack and either proceeds locally (as today) or short-circuits with a typed
/// `NOT_LEADER` redirect carrying the current leader's CLIENT address.
///
/// A NON-cluster broker never builds a [`ClientAckGate`], so the produce path never calls this and the
/// single-node hot path is byte-for-byte unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterProduceRouting {
    /// PROCEED with the local produce exactly as today: this node either LEADS the partition (the #720
    /// quorum gate then applies), or holds no clustered role for it (the brief bootstrap window, or a
    /// partition that is not clustered) — in which case the local engine is authoritative and a redirect
    /// would be a FALSE `NOT_LEADER`. The fail-safe default: never redirect unless this node provably holds
    /// a clustered replica role it does not lead.
    Local,
    /// REDIRECT: this node holds a clustered REPLICA role for the partition but is NOT its current leader,
    /// so the produce must go to the leader. The produce path writes a `NOT_LEADER` frame carrying
    /// `leader_hint` (the current committed leader's CLIENT address, or `None` when this node does not yet
    /// know it — mid-failover, or no advertised client address) and does NOT append/ack locally. The
    /// client reconnects/retries to the leader (or, with no hint, re-tries its known peers).
    Redirect {
        /// The current leader's CLIENT-facing address, or `None` when unknown (the client falls back to
        /// re-discovering the leader from its own configured peer set).
        leader_hint: Option<SocketAddr>,
    },
}

/// The shared client produce-ack gate (#719): the seam (via the shared
/// [`DataPlaneServer`](super::serve::DataPlaneServer)) plus the per-connection released-ack outbox.
/// Held in an `Arc` and shared between every producer connection (via the
/// [`EngineAccess`](crate::actor::EngineAccess) handle) and the
/// [`DataPlaneRuntime`](super::serve::DataPlaneRuntime). Created ONLY on a clustered serve.
pub struct ClientAckGate<F: Filesystem, C: Clock> {
    /// The SAME shared data-plane server the runtime drives — the one [`ProduceAckSeam`] and its parked
    /// state. Locked briefly per produce-ack decision / per follower report; the lock is NEVER held
    /// across a socket write.
    ///
    /// [`ProduceAckSeam`]: super::dataplane::ProduceAckSeam
    server: Arc<Mutex<DataPlaneServer<F, C>>>,
    /// The serve-wide CONFIGURED cluster ack level (#696): the durability contract a produce to a led
    /// partition is held to. Only [`ClusterAckLevel::C2Fsync`] gates a produce on quorum-fsync; every
    /// other level acks immediately. Resolved at serve time (today from the replication factor via
    /// [`ClusterAckLevel::default_for_replication_factor`]); a per-publish wire override is later.
    configured_level: ClusterAckLevel,
    /// Per-producer-connection released wire `PubAck` byte-frames, keyed by the producer's member id,
    /// in release (offset) order. The runtime deposits here on quorum-fsync; the owning connection
    /// drains here on its own pass. Empty for any connection with nothing released-pending.
    outbox: Mutex<HashMap<u64, Vec<Vec<u8>>>>,
    /// The node-id -> CLIENT-facing address advertise map (#735), the source of the `NOT_LEADER` leader
    /// HINT. When this node holds a non-leader replica role for a partition, the produce path looks up the
    /// current leader's node id (via the shared server's follower target) and maps it here to the address
    /// the client should reconnect to. EMPTY when no client addresses are advertised (the redirect still
    /// fires, but with no hint — the client re-tries its own known peers). Immutable after construction
    /// (the committed placement is static this phase; #693 dynamic re-placement is the flagged follow-up).
    leader_client_addrs: BTreeMap<u64, SocketAddr>,
    /// The node-id -> DATA-PLANE peer address map (#739): the destination of the dirty-tier committed-HW
    /// CONFIRM. When a "latest/dirty" follower-read reaches ABOVE the follower's safe watermark, the gate
    /// dials the partition leader's data-plane address (mapped here from the follower's committed
    /// leader-target node id) and asks for the leader's current committed HW before serving (#723's
    /// `ConfirmWithLeader` over the wire). EMPTY when no data addresses are wired (the in-process tests
    /// drive the confirm directly, and a no-addr confirm FAILS CLOSED to the clean tier — serve only up to
    /// the safe watermark, never unconfirmed). Immutable after construction (static placement this phase;
    /// #693 dynamic re-placement is the flagged follow-up).
    leader_data_addrs: BTreeMap<u64, SocketAddr>,
    /// The shared metadata-plane status snapshot (#722/#735, half B): the source of the per-partition
    /// committed-HW bar (`last_committed_hw`) the follower-read safe watermark `min(own_flushed,
    /// known_committed_hw)` clamps to. `None` when no status handle was installed (the in-process tests
    /// that drive the follower-read directly pass the HW explicitly): the follower-read then fails CLOSED
    /// to a `0` committed bar (serve nothing) rather than risk a stale read. Read under a brief lock, never
    /// across a socket write.
    status: Option<Arc<Mutex<super::runtime::ClusterStatus>>>,
}

impl<F: Filesystem, C: Clock> ClientAckGate<F, C> {
    /// Build the gate around the SAME shared server the runtime drives, held to `configured_level`.
    /// Called ONLY on a clustered serve.
    #[must_use]
    pub fn new(
        server: Arc<Mutex<DataPlaneServer<F, C>>>,
        configured_level: ClusterAckLevel,
    ) -> Self {
        Self {
            server,
            configured_level,
            outbox: Mutex::new(HashMap::new()),
            leader_client_addrs: BTreeMap::new(),
            leader_data_addrs: BTreeMap::new(),
            status: None,
        }
    }

    /// Install the node-id -> CLIENT-address advertise map (#735) used to fill the `NOT_LEADER` leader
    /// HINT, returning the gate. Each entry maps a cluster node id to the address a CLIENT should dial to
    /// reach that node's broker (its `--addr` listener). The redirect mechanism works with an EMPTY map
    /// (the client re-tries its known peers); a populated map lets the redirect carry a concrete hint so
    /// the client reconnects straight to the leader. Builder-style so the runtime can supply it at
    /// construction (a non-cluster broker never builds the gate, so this never runs off-cluster).
    #[must_use]
    pub fn with_leader_client_addrs(mut self, addrs: BTreeMap<u64, SocketAddr>) -> Self {
        self.leader_client_addrs = addrs;
        self
    }

    /// Install the node-id -> DATA-PLANE peer address map (#739) used to DIAL the partition leader for the
    /// dirty-tier committed-HW CONFIRM, returning the gate. Each entry maps a cluster node id to the
    /// address of that node's data-plane peer listener (its [`dataplane_addr`](super::runtime::dataplane_addr)).
    /// The dirty-tier confirm works only with a populated map; with an EMPTY map a "latest" follower-read
    /// above the safe watermark FAILS CLOSED to the clean tier (serve only up to the safe watermark, never
    /// unconfirmed) rather than risk a stale read. Builder-style so the runtime can supply it at
    /// construction (a non-cluster broker never builds the gate, so this never runs off-cluster).
    #[must_use]
    pub fn with_leader_data_addrs(mut self, addrs: BTreeMap<u64, SocketAddr>) -> Self {
        self.leader_data_addrs = addrs;
        self
    }

    /// Install the shared metadata-plane status snapshot (#735, half B), returning the gate. The
    /// follower-read consume reads the per-partition committed-HW bar (`last_committed_hw`) from it for the
    /// SAFE watermark `min(own_flushed, known_committed_hw)`. Without it the follower-read fails CLOSED
    /// (a `0` committed bar — serve nothing — until a checkpoint is known), so installing it is what makes
    /// a follower actually serve committed records. Builder-style; a non-cluster broker never builds the
    /// gate, so this never runs off-cluster.
    #[must_use]
    pub fn with_status_handle(mut self, status: Arc<Mutex<super::runtime::ClusterStatus>>) -> Self {
        self.status = Some(status);
        self
    }

    /// The per-partition committed-HW bar this node has applied from the replicated metadata (#722) — the
    /// `known_committed_hw` the follower-read safe watermark clamps to. Reads the shared status snapshot
    /// (a brief lock); `None` when no status handle is installed or no checkpoint has committed for the
    /// partition yet (the follower-read then fails closed to a `0` safe bar — serve nothing).
    fn known_committed_hw(&self, partition: u64) -> Option<u64> {
        let status = self.status.as_ref()?;
        let snapshot = status.lock().ok()?;
        snapshot.last_committed_hw.get(&partition).copied()
    }

    /// The serve-wide configured cluster ack level this gate holds produces to (#696).
    #[must_use]
    pub fn configured_level(&self) -> ClusterAckLevel {
        self.configured_level
    }

    /// The shared data-plane server, for the runtime to drive (the runtime is built around the SAME
    /// `Arc<Mutex<DataPlaneServer>>` so the seam's parked state is one source of truth).
    #[must_use]
    pub fn server(&self) -> &Arc<Mutex<DataPlaneServer<F, C>>> {
        &self.server
    }

    /// The PRODUCE-ACK decision for one produce on connection `member` (#719): called AFTER the local
    /// group-commit fsync returned `Appended(offset)` (the leader's I2 holds), with the `partition` it
    /// landed on, the appended `offset`, and the EXACT wire-`PubAck` frame bytes the caller would
    /// otherwise write now. The produce is held to the gate's serve-wide [`Self::configured_level`].
    ///
    /// Returns [`AckDisposition::Parked`] — the caller WITHHOLDS the wire reply, and the runtime
    /// releases it into this connection's outbox on quorum-fsync — ONLY for a `C2-fsync` configured
    /// level AND a partition THIS node leads, below or at quorum. In every other case (not `C2-fsync`,
    /// not the leader) it returns [`AckDisposition::WriteNow`] with the bytes verbatim and the caller
    /// writes them immediately, byte-for-byte the existing path. A just-parked ack whose quorum was
    /// ALREADY met (a fast follower reported first) comes back as [`AckDisposition::WriteNowBatch`].
    ///
    /// Locks the shared server briefly (never across a socket write).
    ///
    /// A poisoned server lock yields [`AckDisposition::WriteNow`] (fail to the immediate ack rather than
    /// withhold a reply that nothing will ever release).
    pub fn on_local_fsynced_ack(
        &self,
        member: MemberId,
        partition: u64,
        offset: u64,
        reply_bytes: Vec<u8>,
    ) -> AckDisposition {
        // FAST NON-CLUSTER-LEVEL GATE: only a C2-fsync configured serve ever locks the server / parks.
        // Any other configured level (C0/C1/C2-pagecache) is the immediate ack, decided WITHOUT taking
        // the shared lock — so a clustered serve at C1 pays no per-produce lock either.
        if !self.configured_level.ack_implies_quorum_fsync() {
            return AckDisposition::WriteNow(reply_bytes);
        }
        let Ok(mut srv) = self.server.lock() else {
            // A poisoned lock means the runtime is tearing down; fall back to the immediate ack rather
            // than withhold a reply that nothing will ever release. Correctness-safe: the immediate ack
            // is the leader's already-durable I2 ack (it never over-claims durability — only the
            // quorum-wait is dropped on this teardown edge).
            return AckDisposition::WriteNow(reply_bytes);
        };
        // NOT THE LEADER of this partition (the #693 multi-partition routing concern, or a stale role on
        // a teardown/rebalance edge): ack IMMEDIATELY with the REAL bytes — never quorum-withhold a
        // produce this node does not lead, and never lose the reply. Checked HERE (before the seam call
        // that would move `reply_bytes`) so a non-led produce keeps its real wire PubAck. The seam's own
        // `on_local_fsynced_ack_owned` makes the same non-led decision (`WriteNow(reply_bytes)`); this
        // mirror just keeps the bytes recoverable in the gate.
        if !srv.seam().controller().is_leader(partition) {
            return AckDisposition::WriteNow(reply_bytes);
        }
        // ADVANCE the leader's OWN fsync'd frontier in the seam's ISR tracker to past this offset (#719):
        // the leader has ALREADY locally fsync'd through `offset` (the I2 that just returned `Appended`),
        // so its frontier is `offset + 1`. The ISR seeds the leader frontier ONCE at start (#718), so
        // without this the quorum-commit would be capped at the stale start frontier and a real produce
        // would never release. The leader is one of the `min_isr` quorum members, so its frontier is
        // load-bearing. Saturating so `u64::MAX` cannot overflow (unreachable in practice).
        srv.seam_mut()
            .controller_mut()
            .observe_leader_fsync(partition, offset.saturating_add(1));
        // Park (or fast-release) the REAL wire bytes. The leader role is confirmed above, so the seam
        // never errors here (its only error is a non-led / unknown partition). The fallback is purely
        // defensive (NO panic on the serve path, #11): on the unreachable error it acks immediately with
        // the real bytes (cloned cheaply only on this rare clustered C2-fsync path, never on the
        // single-node hot path), so a produce can never silently lose its reply.
        let fallback = reply_bytes.clone();
        match srv.seam_mut().on_local_fsynced_ack_owned(
            member.get(),
            self.configured_level,
            partition,
            offset,
            reply_bytes,
        ) {
            Ok(disposition) => disposition,
            Err(_) => AckDisposition::WriteNow(fallback),
        }
    }

    /// The cluster PRODUCE-ROUTING decision for `partition` (#735, the `NOT_LEADER` redirect, half A):
    /// called by the produce path BEFORE any local append or ack. Returns:
    ///
    /// * [`ClusterProduceRouting::Local`] — PROCEED locally (byte-for-byte today's path) when this node
    ///   LEADS the partition (the #720 quorum gate then applies on the local produce), OR holds NO
    ///   clustered role for it (the brief bootstrap window before the placement commits here, or a
    ///   non-clustered partition). The fail-safe default — NEVER a false `NOT_LEADER` on the leader, and
    ///   never a redirect on a partition this node is authoritative for.
    /// * [`ClusterProduceRouting::Redirect`] — this node holds a clustered REPLICA (follower) role for the
    ///   partition but is NOT the leader, so the produce must be redirected to the current leader. The
    ///   hint is the leader's CLIENT address from [`Self::with_leader_client_addrs`] (mapped from the
    ///   follower's committed leader-target node id), or `None` when unknown.
    ///
    /// Locks the shared server briefly (the SAME `Arc<Mutex<DataPlaneServer>>` the runtime drives), never
    /// across a socket write. A poisoned lock fails SAFE to [`ClusterProduceRouting::Local`] (proceed
    /// locally rather than wrongly redirect a produce on a teardown edge — the local engine's own append
    /// stays authoritative and no false `NOT_LEADER` is emitted).
    #[must_use]
    pub fn produce_routing(&self, partition: u64) -> ClusterProduceRouting {
        let Ok(srv) = self.server.lock() else {
            // Teardown edge (poisoned lock): proceed locally. The local engine append is authoritative;
            // we never emit a false `NOT_LEADER` here.
            return ClusterProduceRouting::Local;
        };
        // LEADER of this partition: proceed locally exactly as today (the #720 quorum gate applies on the
        // produce). This is checked FIRST so a leader NEVER gets a false `NOT_LEADER`.
        if srv.seam().controller().is_leader(partition) {
            return ClusterProduceRouting::Local;
        }
        // NOT the leader. Only REDIRECT when this node provably holds a clustered FOLLOWER role for the
        // partition (it is a replica that does not lead). If it holds no role at all — the bootstrap
        // window, or a partition that is not clustered here — proceed LOCALLY (the local engine is
        // authoritative; a redirect would be a false `NOT_LEADER`). `follower_leader` is `Some` exactly when
        // this node follows the partition, and it names the current committed leader to redirect to.
        match srv.follower_leader(partition) {
            Some(leader_id) => {
                let leader_hint = self.leader_client_addrs.get(&leader_id).copied();
                ClusterProduceRouting::Redirect { leader_hint }
            }
            // No clustered role for this partition (bootstrap / non-clustered): proceed locally.
            None => ClusterProduceRouting::Local,
        }
    }

    /// Feed a follower's [`AckReplicatedBody`] for `partition` into the gate (driven by the runtime's
    /// follower-report path) and DEPOSIT each released wire `PubAck` into its OWNER connection's outbox,
    /// in offset order, for that connection to flush on its own pass. Below `min_isr` releases NOTHING
    /// (the no-false-ack property, on the real client wire). Returns the number of replies released.
    ///
    /// Locks the shared server, then the outbox — both briefly, NEVER across a socket write (the
    /// release just moves bytes into the outbox; the owning connection's thread does the actual write).
    pub fn on_follower_report(&self, partition: u64, report: &AckReplicatedBody) -> usize {
        let released = {
            let Ok(mut srv) = self.server.lock() else {
                return 0;
            };
            match srv.seam_mut().on_follower_report_owned(partition, report) {
                Ok(r) => r,
                Err(_) => return 0,
            }
        };
        if released.is_empty() {
            return 0;
        }
        let count = released.len();
        let mut outbox = self
            .outbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (owner, bytes) in released {
            outbox.entry(owner).or_default().push(bytes);
        }
        count
    }

    /// Drain (and remove) every RELEASED wire `PubAck` for producer connection `member`, in release
    /// (offset) order, for the connection to flush on its OWN pass. Empty for a connection with nothing
    /// released-pending (the common case), so a connection that never parked a clustered `C2-fsync`
    /// produce pays only a brief lock + miss.
    #[must_use]
    pub fn drain_released(&self, member: MemberId) -> Vec<Vec<u8>> {
        let mut outbox = self
            .outbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        outbox.remove(&member.get()).unwrap_or_default()
    }

    /// Drop any released-but-undrained acks for a producer connection that DISCONNECTED (#719): nobody
    /// is left to flush them, so the outbox entry is removed rather than leaked. Called from the
    /// connection-cleanup path, like the #497 `drop_l2_confirms`. (A still-PARKED ack — withheld inside
    /// the seam, not yet released — is left to the seam's bounded gate; this only clears the outbox.)
    pub fn drop_connection(&self, member: MemberId) {
        let mut outbox = self
            .outbox
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        outbox.remove(&member.get());
    }
}

// The FOLLOWER-READ consume serve (#735, half B) needs `F: Clone`: the follower read plane is built over
// the follower's owned replica log (the #621 `DataPlaneController::serve_follower_read` lives in the
// `F: Filesystem + Clone` impl block). A SEPARATE impl block keeps the rest of the gate — and the
// no-cluster path — on the looser `F: Filesystem` bound; nothing on the single-node path links this.
impl<F: Filesystem + Clone, C: Clock> ClientAckGate<F, C> {
    /// Serve a CLUSTER FOLLOWER-READ consume of `[from, from + max_records)` for `partition` at `tier`
    /// (#735, half B), LOCALLY from this node's follower read plane via the #723 read-consistency tiers
    /// ([`DataPlaneController::serve_follower_read`](super::dataplane::DataPlaneController::serve_follower_read)).
    /// The committed-HW bar is read from the installed status snapshot ([`Self::with_status_handle`]); the
    /// serve is fail-closed by the SAFE watermark `min(own_flushed, known_committed_hw)` (a `0` bar when no
    /// checkpoint is known), so a follower NEVER serves a record past the committed bar.
    ///
    /// Returns `None` when this node holds NO follower role for the partition (it is the leader, or holds
    /// no role): the caller then serves the consume through the normal (leader/local-engine) path. Returns
    /// `Some(outcome)` when this node follows the partition: the served zero-copy bytes
    /// ([`FollowerReadOutcome::Served`]). A [`FollowerReadOutcome::ConfirmWithLeader`] is surfaced ONLY
    /// when the dirty-tier leader confirm could not be performed AND was not needed (see below); a
    /// `FollowerLatest` read that reaches above the safe watermark is RESOLVED in-place by the #739
    /// dirty-tier confirm.
    ///
    /// ## The DIRTY tier (#739): read-your-writes from a follower, never unconfirmed
    ///
    /// For a [`ReadTier::FollowerLatest`] (or a [`ReadTier::LeaderLocal`] degraded onto a follower) read
    /// that reaches ABOVE the follower's safe watermark `min(own_flushed, known_committed_hw)`, the #723
    /// classifier returns `ConfirmWithLeader` — it WON'T serve the unconfirmed tail speculatively. This
    /// method then performs the real, bounded, over-the-wire committed-HW CONFIRM
    /// ([`query_leader_committed_hw`](super::serve::query_leader_committed_hw)): it dials the partition
    /// leader's data-plane address and asks for the leader's CURRENT committed HW (a tiny HW-version
    /// query, NOT the data). On a successful confirm it RE-SERVES at the CLEAN tier with the bar RAISED to
    /// `max(known_committed_hw, confirmed_hw)`, so it serves up to `min(own_flushed, confirmed_hw)` —
    /// every served offset is one the LEADER confirmed committed AND the follower durably holds, never an
    /// unconfirmed/divergent offset. On ANY confirm failure (no data address for the leader, a
    /// connect/read timeout, a link error) it FAILS CLOSED: it re-serves at the CLEAN tier with the
    /// ORIGINAL (un-raised) bar — serving only up to the safe watermark, never unconfirmed.
    ///
    /// The CLEAN tier ([`ReadTier::FollowerCommitted`], the common case) is UNCHANGED: a committed read
    /// `<=` the safe watermark serves locally with NO leader round-trip — the confirm only ever runs for a
    /// dirty read above the safe watermark.
    ///
    /// Locks the shared server briefly, NEVER across a socket write or the confirm round-trip (the confirm
    /// is performed entirely off-lock). A poisoned lock fails SAFE to `None` (the caller serves through the
    /// normal path rather than risk a stale follower read).
    #[must_use]
    pub fn serve_follower_consume(
        &self,
        partition: u64,
        tier: ReadTier,
        from: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Option<FollowerReadOutcome> {
        // The committed-HW bar from the replicated metadata (#722): the SAFE watermark clamps to it.
        // Read BEFORE the server lock (its own brief lock), and `None` when unknown -> the serve fails
        // closed to a `0` safe bar (serve nothing) rather than risk a stale read.
        let known_committed_hw = self.known_committed_hw(partition);
        // FIRST serve attempt under a SHORT lock (released before any network round-trip). The CLEAN tier
        // resolves here with no round-trip; a DIRTY read above the safe watermark comes back as
        // `ConfirmWithLeader` and is resolved off-lock below.
        let first = {
            let Ok(srv) = self.server.lock() else {
                return None;
            };
            // Only a FOLLOWER serves a follower read. A leader / no-role partition returns `None` so the
            // caller uses the normal consume path (the single-writer / leader read plane), never this.
            if !srv.seam().controller().is_follower(partition) {
                return None;
            }
            // A serve fault (IO) or a role race maps to `None` (the caller serves the normal path) — never
            // a panic on the serve path and never an unsafe stale serve.
            srv.seam()
                .controller()
                .serve_follower_read(
                    partition,
                    tier,
                    known_committed_hw,
                    from,
                    max_records,
                    max_bytes,
                )
                .ok()?
        };
        match first {
            // CLEAN serve (or an empty run): the common, zero-round-trip path. Return it verbatim.
            served @ FollowerReadOutcome::Served(_) => Some(served),
            // DIRTY tier above the safe watermark: perform the real, bounded, over-the-wire leader confirm
            // OFF-LOCK, then re-serve. Never speculative — the re-serve is clamped to the CONFIRMED HW.
            FollowerReadOutcome::ConfirmWithLeader { .. } => {
                self.resolve_dirty_tier(partition, known_committed_hw, from, max_records, max_bytes)
            }
        }
    }

    /// Resolve a DIRTY-TIER follower-read (#739) that reached above the safe watermark: perform the
    /// bounded, over-the-wire committed-HW CONFIRM with the partition leader OFF-LOCK, then re-serve at the
    /// CLEAN tier with the bar raised to the leader-confirmed HW (fail-closed to the un-raised bar on a
    /// failed confirm). Returns the re-served outcome (always a `Served` run — never another confirm, and
    /// never an unconfirmed offset).
    fn resolve_dirty_tier(
        &self,
        partition: u64,
        known_committed_hw: Option<u64>,
        from: Offset,
        max_records: usize,
        max_bytes: Option<usize>,
    ) -> Option<FollowerReadOutcome> {
        // Find the partition's current leader (the follower's committed fetch target) and its DATA-plane
        // address, under a SHORT lock that is released BEFORE the network round-trip.
        let leader_data_addr = {
            let Ok(srv) = self.server.lock() else {
                return None;
            };
            srv.follower_leader(partition)
                .and_then(|leader_id| self.leader_data_addrs.get(&leader_id).copied())
        };
        // The real, bounded, over-the-wire confirm (#723's `ConfirmWithLeader`): ask the leader for its
        // CURRENT committed HW. `None` on no route / timeout / link error -> fail closed (the clean tier).
        let confirmed_hw = leader_data_addr
            .and_then(|addr| super::serve::query_leader_committed_hw(addr, partition));
        // RAISE the bar to the confirmed HW (never lower it): the re-serve uses `max(known, confirmed)`,
        // so it serves up to `min(own_flushed, raised_bar)`. On a FAILED confirm `confirmed_hw` is `None`,
        // so the bar stays the original `known_committed_hw` and the re-serve is the plain clean tier —
        // never an offset above the safe watermark, never unconfirmed.
        let raised_bar = match (known_committed_hw, confirmed_hw) {
            (Some(k), Some(c)) => Some(k.max(c)),
            (None, Some(c)) => Some(c),
            (k, None) => k,
        };
        // RE-SERVE at the CLEAN tier (committed-only) with the raised bar, under a short lock. The clean
        // tier serves only `<= min(own_flushed, raised_bar)` — every served offset is leader-confirmed
        // committed AND durably held here. This NEVER returns `ConfirmWithLeader` (the clean tier never
        // does), so the dirty read is fully resolved with no second round-trip.
        let Ok(srv) = self.server.lock() else {
            return None;
        };
        if !srv.seam().controller().is_follower(partition) {
            return None;
        }
        srv.seam()
            .controller()
            .serve_follower_read(
                partition,
                ReadTier::FollowerCommitted,
                raised_bar,
                from,
                max_records,
                max_bytes,
            )
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::dataplane::{DataPlaneController, ProduceAckSeam};
    use crate::cluster::isr::IsrConfig;
    use crate::cluster::state_machine::Placement;
    use ironbus_core::clock::ManualClock;
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::{Log, LogConfig};

    const P: u64 = 0;

    /// A leaked leader log so the read plane's `Arc` lifetime is `'static` for the test (the same
    /// pattern the serve.rs cluster tests use). The gate's seam logic does not read the plane content —
    /// the gate/quorum decision is what is under test — so an empty leader log suffices.
    fn leader_plane() -> Arc<ironbus_storage::read_plane::ReadPlane<InMemoryFs>> {
        let log: &'static Log<InMemoryFs, ManualClock> = Box::leak(Box::new(
            Log::open(InMemoryFs::new(), ManualClock::new(), LogConfig::default())
                .expect("open leader log"),
        ));
        Arc::new(log.read_plane().expect("read plane"))
    }

    fn quorum3() -> IsrConfig {
        IsrConfig {
            min_isr: 2,
            max_lag_records: 0,
        }
    }

    /// Build a leader [`ClientAckGate`] for node 1 leading `{1,2,3}` with `min_isr = 2`, held to
    /// `level`. `leader_fsync` seeds the leader's OWN fsync'd frontier (the leader has locally fsync'd
    /// through it, the I2 ack), so a follower report at or past an offset can bring the 2-of-3 quorum.
    fn leader_gate_at(
        level: ClusterAckLevel,
        leader_fsync: u64,
    ) -> ClientAckGate<InMemoryFs, ManualClock> {
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 1,
        };
        let mut controller = DataPlaneController::new(1);
        controller.start_leader(
            P,
            leader_plane(),
            ironbus_core::epoch_cache::EpochCache::new(),
            &placement.replicas,
            quorum3(),
        );
        // The leader has locally fsync'd through `leader_fsync` (its own I2). The quorum-commit is the
        // min_isr-th largest fsync'd frontier, so a single in-sync follower past an offset meets the
        // 2-of-3 quorum for it.
        controller.observe_leader_fsync(P, leader_fsync);
        let seam = ProduceAckSeam::new(controller);
        let server = DataPlaneServer::new(1, seam);
        ClientAckGate::new(Arc::new(Mutex::new(server)), level)
    }

    /// A C2-fsync gate (the quorum-gated default for a 3-replica cluster).
    fn leader_gate(leader_fsync: u64) -> ClientAckGate<InMemoryFs, ManualClock> {
        leader_gate_at(ClusterAckLevel::C2Fsync, leader_fsync)
    }

    fn wire_ack(offset: u64) -> Vec<u8> {
        // A stand-in for the real wire PubAck frame bytes — the gate treats them as opaque; the test
        // asserts the EXACT bytes round-trip through park -> release -> drain.
        let mut v = b"PUBACK".to_vec();
        v.extend_from_slice(&offset.to_le_bytes());
        v
    }

    #[test]
    fn a_c2_fsync_led_produce_is_parked_then_released_to_its_owner_outbox_on_quorum() {
        // The leader has locally fsync'd record 0 (frontier 1); no follower has it yet, so the 2-of-3
        // quorum is not met.
        let gate = leader_gate(1);
        let member = MemberId::new(42);
        let offset = 0;
        let reply = wire_ack(offset);

        // The clustered C2-fsync led produce parks: the wire PubAck is WITHHELD.
        let disposition = gate.on_local_fsynced_ack(member, P, offset, reply.clone());
        assert_eq!(disposition, AckDisposition::Parked);
        // Nothing is in the owner's outbox yet (no quorum).
        assert!(gate.drain_released(member).is_empty());

        // A single follower at offset 0 brings min_isr=2 (leader + follower 2) for offset 0.
        let report = AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 1,
        };
        let released = gate.on_follower_report(P, &report);
        assert_eq!(
            released, 1,
            "the quorum-fsync released exactly one parked ack"
        );

        // The owner connection drains the REAL reply bytes (byte-identical to what was parked).
        let drained = gate.drain_released(member);
        assert_eq!(
            drained,
            vec![reply],
            "the released bytes ARE the original PubAck"
        );
        // A second drain is empty (the outbox entry was removed).
        assert!(gate.drain_released(member).is_empty());
    }

    #[test]
    fn below_min_isr_the_wire_puback_stays_withheld_no_false_ack() {
        // The leader has fsync'd through offset 5 (frontier 6), but with NO follower in sync the ISR is
        // the leader alone (size 1 < min_isr 2): no quorum, so a parked ack is NEVER released.
        let gate = leader_gate(6);
        let member = MemberId::new(7);
        let offset = 5;
        let disposition = gate.on_local_fsynced_ack(member, P, offset, wire_ack(offset));
        assert_eq!(disposition, AckDisposition::Parked);
        // A follower at offset 0 does NOT bring quorum at offset 5: nothing released.
        let report = AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 0,
        };
        assert_eq!(gate.on_follower_report(P, &report), 0);
        assert!(
            gate.drain_released(member).is_empty(),
            "below min_isr the client's wire PubAck is NEVER released (no false ack)"
        );
    }

    #[test]
    fn non_c2_fsync_levels_ack_immediately_never_parked() {
        let member = MemberId::new(1);
        for level in [
            ClusterAckLevel::C0,
            ClusterAckLevel::C1,
            ClusterAckLevel::C2Pagecache,
        ] {
            // A gate CONFIGURED at a non-C2-fsync level acks immediately (never quorum-gated), without
            // even taking the shared lock.
            let gate = leader_gate_at(level, 1);
            let reply = wire_ack(0);
            let disposition = gate.on_local_fsynced_ack(member, P, 0, reply.clone());
            assert_eq!(
                disposition,
                AckDisposition::WriteNow(reply),
                "{level:?} acks immediately (never quorum-gated)"
            );
            // Nothing was ever parked or released.
            assert!(gate.drain_released(member).is_empty());
        }
    }

    #[test]
    fn a_produce_to_a_partition_this_node_does_not_lead_acks_immediately() {
        // Node 1 FOLLOWS partition 0 (leader is node 2). A produce routed here (the #693 multi-partition
        // routing concern, or a stale role) must ack IMMEDIATELY with the REAL bytes — never quorum-
        // withhold a produce this node does not lead, and never lose the reply.
        let placement = Placement {
            replicas: vec![1, 2, 3],
            leader: 2,
            epoch: 1,
        };
        let mut controller = DataPlaneController::new(1);
        let replica_log =
            Log::open(InMemoryFs::new(), ManualClock::new(), LogConfig::default()).unwrap();
        controller.start_follower(P, replica_log);
        let _ = placement; // the role is set directly via start_follower (node 1 is a follower here)
        let seam = ProduceAckSeam::new(controller);
        let server = DataPlaneServer::new(1, seam);
        let gate = ClientAckGate::new(Arc::new(Mutex::new(server)), ClusterAckLevel::C2Fsync);

        let member = MemberId::new(3);
        let reply = wire_ack(7);
        assert_eq!(
            gate.on_local_fsynced_ack(member, P, 7, reply.clone()),
            AckDisposition::WriteNow(reply),
            "a non-led produce acks immediately with the REAL reply (no quorum withholding, no loss)"
        );
        assert!(gate.drain_released(member).is_empty());
    }

    #[test]
    fn a_disconnect_drops_undrained_released_acks() {
        let gate = leader_gate(1);
        let member = MemberId::new(99);
        let reply = wire_ack(0);
        assert_eq!(
            gate.on_local_fsynced_ack(member, P, 0, reply),
            AckDisposition::Parked
        );
        let report = AckReplicatedBody {
            follower_id: 2,
            fsynced_offset: 1,
        };
        assert_eq!(gate.on_follower_report(P, &report), 1);
        // The released ack is waiting in the outbox; the connection disconnects before draining.
        gate.drop_connection(member);
        assert!(
            gate.drain_released(member).is_empty(),
            "a disconnect drops the undrained released acks (no outbox leak)"
        );
    }

    // ---- #735 half A: the NOT_LEADER produce-routing decision ------------------------------------

    /// A follower [`ClientAckGate`] for node 1 FOLLOWING partition 0 (leader is node `leader_id`), built
    /// over a fresh empty replica log. The follower target names `leader_id` so `produce_routing` finds
    /// the leader to redirect to. The optional `(leader_id, addr)` advertise entries fill the leader hint.
    fn follower_gate_with_addrs(
        leader_id: u64,
        addrs: &[(u64, SocketAddr)],
    ) -> ClientAckGate<InMemoryFs, ManualClock> {
        let mut controller = DataPlaneController::new(1);
        let replica_log =
            Log::open(InMemoryFs::new(), ManualClock::new(), LogConfig::default()).unwrap();
        controller.start_follower(P, replica_log);
        let seam = ProduceAckSeam::new(controller);
        let mut server = DataPlaneServer::new(1, seam);
        // Name the leader to redirect to (the follower fetch target the produce-routing reads).
        server.set_follower_target(P, leader_id);
        let map: BTreeMap<u64, SocketAddr> = addrs.iter().copied().collect();
        ClientAckGate::new(Arc::new(Mutex::new(server)), ClusterAckLevel::C2Fsync)
            .with_leader_client_addrs(map)
    }

    #[test]
    fn produce_routing_redirects_a_non_led_partition_with_the_leader_hint() {
        // Node 1 FOLLOWS partition 0 (leader node 2). A produce here must REDIRECT to node 2's advertised
        // client address — the NOT_LEADER hint — never appended/acked locally.
        let leader_addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        let gate = follower_gate_with_addrs(2, &[(2, leader_addr)]);
        assert_eq!(
            gate.produce_routing(P),
            ClusterProduceRouting::Redirect {
                leader_hint: Some(leader_addr),
            },
            "a non-led produce redirects to the current leader's advertised client address"
        );
    }

    #[test]
    fn produce_routing_redirects_with_no_hint_when_the_leader_addr_is_unknown() {
        // Same follower role, but NO advertised address for the leader: still REDIRECT (the mechanism is
        // load-bearing), just with no hint — the client re-tries its known peers.
        let gate = follower_gate_with_addrs(2, &[]);
        assert_eq!(
            gate.produce_routing(P),
            ClusterProduceRouting::Redirect { leader_hint: None },
            "the redirect fires even with no advertised leader address (no hint)"
        );
    }

    #[test]
    fn produce_routing_on_the_leader_is_local_never_a_false_not_leader() {
        // Node 1 LEADS partition 0: the produce proceeds LOCALLY (the #720 quorum gate applies) — NEVER a
        // false NOT_LEADER on the leader.
        let gate = leader_gate(1);
        assert_eq!(
            gate.produce_routing(P),
            ClusterProduceRouting::Local,
            "the leader proceeds locally, never a false NOT_LEADER"
        );
    }

    #[test]
    fn produce_routing_after_a_failover_redirects_to_the_new_leader() {
        // FAILOVER RECOVERY (#735, composes with #720/#722): node 1 starts as the LEADER of partition 0
        // (a produce proceeds locally). Then leadership MOVES to node 2 (a committed placement change):
        // node 1 becomes a FOLLOWER of node 2. A produce on the OLD leader now redirects to the NEW
        // leader's advertised client address — the client recovers automatically.
        let new_leader_addr: SocketAddr = "127.0.0.1:9002".parse().unwrap();
        // Build a node-1 LEADER gate that ALSO advertises node 2's client address (for after the failover).
        let mut controller = DataPlaneController::new(1);
        controller.start_leader(
            P,
            leader_plane(),
            ironbus_core::epoch_cache::EpochCache::new(),
            &[1, 2, 3],
            quorum3(),
        );
        let seam = ProduceAckSeam::new(controller);
        let server = Arc::new(Mutex::new(DataPlaneServer::new(1, seam)));
        let gate = ClientAckGate::new(Arc::clone(&server), ClusterAckLevel::C2Fsync)
            .with_leader_client_addrs([(2, new_leader_addr)].into_iter().collect());
        // BEFORE the failover: node 1 leads, so a produce proceeds locally (no false NOT_LEADER).
        assert_eq!(gate.produce_routing(P), ClusterProduceRouting::Local);

        // FAILOVER: leadership moves to node 2. Apply it to the SAME shared server the gate reads: node 1
        // stops leading and becomes a follower of node 2 (exactly the role transition a committed
        // re-placement drives).
        {
            let mut srv = server.lock().unwrap();
            assert!(srv.seam_mut().controller_mut().stop_partition(P));
            srv.seam_mut().controller_mut().start_follower(
                P,
                Log::open(InMemoryFs::new(), ManualClock::new(), LogConfig::default()).unwrap(),
            );
            srv.set_follower_target(P, 2);
        }

        // AFTER the failover: a produce on the OLD leader redirects to the NEW leader (node 2).
        assert_eq!(
            gate.produce_routing(P),
            ClusterProduceRouting::Redirect {
                leader_hint: Some(new_leader_addr),
            },
            "after leadership moves, the old leader redirects to the new leader"
        );
    }

    #[test]
    fn produce_routing_with_no_role_for_the_partition_is_local() {
        // Node 1 leads partition 0 but the produce names a DIFFERENT partition it holds no role for (the
        // bootstrap window / a non-clustered partition): proceed LOCALLY — never a false NOT_LEADER on a
        // partition this node is not a clustered replica of.
        const OTHER_PARTITION: u64 = 7;
        let gate = leader_gate(1);
        assert_eq!(
            gate.produce_routing(OTHER_PARTITION),
            ClusterProduceRouting::Local,
            "a partition this node holds no role for proceeds locally (no false NOT_LEADER)"
        );
    }

    // ---- #735 half B: the follower-read consume routing ------------------------------------------

    /// A small segment cap so a handful of records rolls to multiple segments (the follower's read plane
    /// serves the SEALED prefix).
    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn rec(payload: &[u8]) -> ironbus_storage::log::Append<'_> {
        ironbus_storage::log::Append {
            timestamp_ms: 7,
            flags: ironbus_core::types::RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    /// Build a FOLLOWER gate (node 2 following partition 0, leader node 1) whose replica log has been
    /// caught up to a leader holding `n` records, plus a status snapshot whose committed-HW covers the
    /// whole replicated prefix. Returns the gate and the served-end the leader's read plane reaches (the
    /// committed bar). The follower then serves committed records LOCALLY off its own read plane.
    fn caught_up_follower_gate(n: u32) -> (ClientAckGate<InMemoryFs, ManualClock>, u64) {
        // Seed the leader log + read plane. Leaked as `&'static mut` so the read plane's `Arc` lifetime is
        // `'static` for the test (the same leaked-log pattern the serve.rs cluster tests use) while the
        // appends/sync below still have the `&mut` they need.
        let leader_log: &'static mut Log<InMemoryFs, ManualClock> = Box::leak(Box::new(
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap(),
        ));
        for i in 0..n {
            leader_log
                .append(&rec(format!("c6-{i:02}").as_bytes()))
                .unwrap();
        }
        leader_log.sync().unwrap();
        let plane = Arc::new(leader_log.read_plane().unwrap());
        // The sealed-served end (the prefix the follower converges to).
        let mut served_end = 0u64;
        loop {
            let raw = plane
                .read_range_raw(Offset::new(served_end), 1_000, None)
                .unwrap();
            let next = raw.run.next_offset.get();
            if next <= served_end {
                break;
            }
            served_end = next;
        }
        // The leader controller (to serve fetches from) and the follower controller (to catch up).
        let mut leader: DataPlaneController<InMemoryFs, ManualClock> = DataPlaneController::new(1);
        leader.start_leader(
            P,
            Arc::clone(&plane),
            ironbus_core::epoch_cache::EpochCache::new(),
            &[1, 2],
            quorum3(),
        );
        let mut follower = DataPlaneController::new(2);
        follower.start_follower(
            P,
            Log::open(InMemoryFs::new(), ManualClock::new(), small_config()).unwrap(),
        );
        for _ in 0..(served_end + 8) {
            if follower.follower_high_watermark(P).unwrap() >= served_end {
                break;
            }
            let req = follower.make_fetch_request(P, 8, 4096).unwrap();
            let resp = leader.serve_fetch(P, &req).unwrap();
            follower.apply_fetch_response(P, &resp).unwrap();
        }
        // Wrap the follower controller in a gate with a status snapshot whose committed-HW covers the
        // served prefix (a checkpoint has caught up), so the safe watermark admits the whole prefix.
        let seam = ProduceAckSeam::new(follower);
        let server = DataPlaneServer::new(2, seam);
        let mut status = super::super::runtime::ClusterStatus::default();
        status.last_committed_hw.insert(P, served_end);
        let gate = ClientAckGate::new(Arc::new(Mutex::new(server)), ClusterAckLevel::C2Fsync)
            .with_status_handle(Arc::new(Mutex::new(status)));
        (gate, served_end)
    }

    /// Decode a follower-read run into (offset, payload), re-validating each frame's CRC.
    fn decode_run(run: &ironbus_storage::segment::RawByteRun) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        let mut cursor = 0usize;
        let mut offset = run.first_offset.get();
        while cursor < run.bytes.len() {
            let (view, consumed) = ironbus_core::codec::decode(&run.bytes[cursor..]).unwrap();
            out.push((offset, view.payload.to_vec()));
            offset += 1;
            cursor += consumed;
        }
        out
    }

    #[test]
    fn serve_follower_consume_serves_committed_records_from_a_follower() {
        let (gate, served_end) = caught_up_follower_gate(30);
        assert!(served_end > 0, "the follower replicated a committed prefix");
        // The follower serves the committed prefix LOCALLY off its own read plane.
        let mut from = Offset::ZERO;
        let mut total = 0u64;
        let mut guard = 0u32;
        loop {
            guard += 1;
            assert!(guard < 10_000, "follower-read chain failed to terminate");
            let outcome = gate
                .serve_follower_consume(P, ReadTier::FollowerCommitted, from, usize::MAX, None)
                .expect("a follower returns Some(outcome)");
            let run = match outcome {
                FollowerReadOutcome::Served(r) => r.run,
                FollowerReadOutcome::ConfirmWithLeader { .. } => panic!("expected a local serve"),
            };
            let recs = decode_run(&run);
            for (off, _payload) in &recs {
                assert!(
                    *off < served_end,
                    "served offset {off} past the committed bar {served_end}"
                );
            }
            if recs.is_empty() {
                break;
            }
            total += recs.len() as u64;
            let next = run.next_offset.get();
            if next <= from.get() {
                break;
            }
            from = Offset::new(next);
        }
        assert!(
            total > 0,
            "the follower served committed records locally (not vacuously empty)"
        );
        assert!(
            total <= served_end,
            "the follower never serves past the committed bar"
        );
    }

    #[test]
    fn serve_follower_consume_fails_closed_with_no_committed_hw() {
        // SAME caught-up follower, but NO status handle -> the committed-HW bar is unknown -> the safe
        // watermark is 0 -> the follower serves NOTHING (fail-closed), never a stale/uncommitted read.
        let (gate, _served_end) = caught_up_follower_gate(30);
        // Rebuild the gate WITHOUT a status handle by routing through a fresh gate over the same server.
        let server = Arc::clone(gate.server());
        let no_hw_gate = ClientAckGate::new(server, ClusterAckLevel::C2Fsync);
        let outcome = no_hw_gate
            .serve_follower_consume(
                P,
                ReadTier::FollowerCommitted,
                Offset::ZERO,
                usize::MAX,
                None,
            )
            .expect("a follower returns Some(outcome)");
        match outcome {
            FollowerReadOutcome::Served(r) => assert_eq!(
                r.run.record_count, 0,
                "with no known committed HW the follower serves NOTHING (fail-closed)"
            ),
            FollowerReadOutcome::ConfirmWithLeader { .. } => {
                panic!("a clean read with no HW serves nothing, not a confirm")
            }
        }
    }

    #[test]
    fn serve_follower_consume_on_the_leader_is_none() {
        // A LEADER returns `None` (the caller serves the normal leader path), never the follower-read.
        let gate = leader_gate(1);
        assert!(
            gate.serve_follower_consume(P, ReadTier::FollowerCommitted, Offset::ZERO, 8, None)
                .is_none(),
            "the leader uses the normal consume path, not the follower-read"
        );
    }
}
