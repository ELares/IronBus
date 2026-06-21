// SPDX-License-Identifier: MIT OR Apache-2.0
//! The cluster RUNTIME that runs a broker as a metadata-Raft cluster member (V2-C1-I6, #682).
//!
//! Everything else in [`crate::cluster`] is a standalone, caller-driven building block — the
//! [`MetadataRaftGroup`](crate::cluster::metadata_group::MetadataRaftGroup) (tick / step / propose /
//! `drive_ready`), its durable [`MetadataLogStorage`](crate::cluster::metadata_storage), the bounded
//! fail-closed [`transport`](crate::cluster::transport) ([`PeerLink`] + the size/recursion-bounded
//! codec), the joint-consensus [`membership`](crate::cluster::membership) API, and the leader-epoch
//! lease. Until this module NONE of them was ever STARTED by a running broker: the group ran only in
//! in-process tests that hand-delivered `Message` VALUES between nodes.
//!
//! This module is the integration that turns those parts into a running cluster member. Behind a
//! [`ClusterConfig`] (a node id + a peer-id→address map) it starts:
//!
//! 1. a **driver thread** that OWNS the [`MetadataRaftGroup`] (raft-rs is synchronous and
//!    caller-driven, so exactly one thread advances it) and drives the tick / `step` / `drive_ready`
//!    loop on a fixed cadence, with the group's persist-before-advance fsync (#659) intact;
//! 2. a **peer LISTENER** thread that accepts inbound TCP peer links and, per accepted connection, a
//!    reader thread that pulls bounded, peer-id-authenticated `Message`s off the wire
//!    ([`PeerLink::recv`]) and hands them to the driver;
//! 3. a **dialer** thread per remote peer that connects to that peer's address (reconnecting on a
//!    drop) and drains that peer's outbound queue, writing each `Message` with [`PeerLink::send`].
//!
//! The driver and the peer-I/O threads communicate over `std::sync::mpsc` channels — the inbound
//! `Message`s the readers receive flow to the driver, and the driver routes each outbound `Message`
//! `drive_ready` surfaces to the addressed peer's dialer queue. No peer-I/O thread ever touches the
//! `RawNode`; only the driver does.
//!
//! ## The single-node (no-cluster) default is byte-for-byte today's broker
//!
//! A broker with NO cluster config never constructs a [`ClusterRuntime`]: `serve` calls
//! [`ClusterRuntime::start`] only when a [`ClusterConfig`] is present. With no config:
//!
//! * NO `metaraft/` subdirectory is created (the metadata log is opened only by the runtime);
//! * NO peer listener is bound and NO dialer is spawned (no new socket);
//! * NO raft tick thread runs (zero added per-op cost on the data path).
//!
//! So the on-disk layout, the produce/consume path, and the process's threads are identical to the
//! pre-C1 broker. The cluster runtime is a purely ADDITIVE side metadata plane.
//!
//! A 1-member cluster (`--cluster-id N` with only its own address) is the degenerate case: the
//! driver still runs, but the lone voter self-elects, binds its listener (so a 2nd node could later
//! join), and dials no remote peer. It does NOT replicate any DATA log — data-log replication is C2;
//! this runtime is the METADATA plane only.
//!
//! ## Scope / deferred
//!
//! * **DATA-log replication (C2)** — this runtime replicates only the cluster METADATA (membership /
//!   placement / config) over the one metadata Raft group; the broker's produce/consume data logs
//!   are untouched.
//! * **Snapshot transfer / log compaction (#660)**, **mTLS peer auth**, and **dynamic peer
//!   discovery** are out of scope: peers are a static configured set, plaintext TCP, bound by the
//!   [`transport`] codec's size + recursion limits and the [`PeerRegistry`] peer-id check.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ironbus_core::clock::Clock;
use ironbus_core::leader_lease::LeaderEpoch;
use ironbus_core::placement::PlacementNode;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::LogConfig;
use raft::eraftpb::Message;

use crate::cluster::membership::MembershipChange;
use crate::cluster::metadata_group::{GroupError, MetadataRaftGroup};
use crate::cluster::state_machine::{MetadataCommand, Placement};
use crate::cluster::transport::{PeerLink, PeerRegistry, PeerWireError};

/// How often the driver advances the raft election/heartbeat timer with one
/// [`MetadataRaftGroup::tick`]. raft-rs's tick is a logical timer step (election ~10 ticks,
/// heartbeat ~3 — see the group's [`Config`](raft::Config)); at this cadence an election fires in
/// ~1 s and heartbeats every ~300 ms, which is comfortable for a small metadata group and cheap on
/// an edge box. The driver also re-checks the shutdown flag and drains inbound messages every tick,
/// so the loop never sleeps longer than this between shutdown checks. It does NOT busy-spin: between
/// ticks the driver BLOCKS on the inbound channel with this as the timeout, so an idle 1-node
/// cluster wakes ~10x/s, not in a hot loop.
const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// The bound on each per-peer outbound queue. The metadata group emits a tiny, bounded number of
/// messages per ready cycle (heartbeats / votes / a bounded run of small append entries — never
/// asset data), so a healthy peer drains far faster than this fills. The bound exists only so a
/// WEDGED / unreachable peer cannot make the driver's outbound routing grow without limit: once a
/// peer's queue is full the driver DROPS the message for that peer (raft re-sends on the next
/// heartbeat, so a dropped heartbeat/append is self-healing), keeping the runtime edge-safe.
const PEER_OUTBOUND_BOUND: usize = 1024;

/// The reconnect backoff a dialer waits after a failed connect / a dropped link before retrying, so
/// a down peer is retried at a steady, low rate rather than in a hot reconnect loop.
const DIALER_RECONNECT_BACKOFF: Duration = Duration::from_millis(500);

/// The DEFAULT peer-liveness death-detection deadline (F1, #618): how long a voter peer may be
/// SILENT (no metadata-Raft message stepped from it) before the metadata leader proposes its removal
/// from the membership — which a committed shrink then turns into an automatic failover (F2).
///
/// ## Why this value avoids a FALSE / premature failover (the non-negotiable)
///
/// The metadata group's heartbeat fires every `heartbeat_tick = 3` ticks at the [`TICK_INTERVAL`]
/// 100 ms cadence, i.e. **every ~300 ms** a live leader→follower (and the follower's response) crosses
/// the wire, refreshing `last_heard`. This deadline is `3_000 ms` = **10x that heartbeat interval**, so
/// a peer must miss roughly TEN consecutive heartbeat round-trips before it is declared dead. A brief
/// network hiccup, a GC pause, or a single dropped heartbeat (raft re-sends on the next beat — see
/// [`route_outbound`]) is far inside this window and NEVER trips a removal. Only a genuinely
/// crashed / partitioned-away peer stays silent for 10 beats. The ratio (deadline ÷ heartbeat ≈ 10)
/// is the safety margin; raise [`LivenessConfig::timeout`] to widen it further on a jittery link.
///
/// It is a DEFAULT: the deadline is injectable ([`LivenessConfig`]) and the clock is the I6 monotonic
/// seam, so the kill-the-leader test drives detection deterministically (advance a [`ManualClock`])
/// rather than sleeping a real 3 s — no wall-clock flake.
pub const DEFAULT_LIVENESS_TIMEOUT: Duration = Duration::from_secs(3);

/// How often the data-plane LEADER proposes a committed-HW CHECKPOINT into the metadata Raft (#618b):
/// the cadence at which it persists "every offset below this is quorum-fsync'd" so the bar SURVIVES its
/// death. It is deliberately PERIODIC, NOT per record — a per-record checkpoint would put a metadata
/// Raft round-trip on the produce hot path. At this cadence the persisted bar trails the live committed
/// HW by at most one interval; a successor is only ever required to hold up to the LAST checkpointed bar,
/// so it never loses *checkpointed* committed data, and the small trailing window is the documented
/// availability/cost trade (the checkpoint is cheap; raising the cadence tightens the window). It is the
/// committed-HW analogue of [`TICK_INTERVAL`]: bounded, low-rate, self-healing if a single proposal is
/// dropped (the next cycle re-proposes the then-current HW). Proposed only when this node both LEADS the
/// metadata group AND leads the partition's data plane (it is the only node that knows the live HW).
const COMMITTED_HW_CHECKPOINT_INTERVAL: Duration = Duration::from_millis(500);

/// The fixed TCP-port offset the DATA-plane peer listener binds at, RELATIVE to a node's configured
/// metadata address (#717). One `--cluster-peer <id>=<addr>` entry thus serves BOTH transports: the
/// metadata Raft listener on `<addr>` and the data-plane (replication-fetch / ISR-report) listener on
/// `<addr>+offset`. A follower resolves its leader's data-plane address by applying the same offset to
/// the leader's configured metadata address, so no new config is needed for the data plane.
///
/// The offset is small and fixed so it stays inside the same ephemeral / operator-allocated port band;
/// a `0` configured port (OS-assigned, used only in tests) is left untouched (the data plane binds its
/// own OS-assigned port and the caller reads it back).
pub const DATAPLANE_PORT_OFFSET: u16 = 1;

/// The DATA-plane peer listener address for a node's configured metadata `addr` (#717): the same IP
/// with the port shifted by [`DATAPLANE_PORT_OFFSET`]. A configured port of `0` (OS-assigned) is left
/// as `0` (the caller binds and reads back the assigned port); a non-zero port is shifted, saturating
/// at `u16::MAX` so the arithmetic never wraps to a privileged/zero port.
#[must_use]
pub fn dataplane_addr(addr: SocketAddr) -> SocketAddr {
    let port = addr.port();
    let data_port = if port == 0 {
        0
    } else {
        port.saturating_add(DATAPLANE_PORT_OFFSET)
    };
    let mut out = addr;
    out.set_port(data_port);
    out
}

/// The configurable peer-liveness death-detector tuning (F1, #618). The deadline is INJECTABLE (not a
/// hard-coded wall-clock value) so the kill-the-leader test drives detection deterministically over a
/// [`ManualClock`](ironbus_core::clock::ManualClock); production uses [`Self::default`].
#[derive(Clone, Copy, Debug)]
pub struct LivenessConfig {
    /// How long a voter peer may be silent (no metadata message stepped from it) before the metadata
    /// leader proposes its removal. Defaults to [`DEFAULT_LIVENESS_TIMEOUT`] (10x the heartbeat —
    /// the no-false-failover margin). Must be safely longer than the heartbeat interval.
    pub timeout: Duration,
    /// Master switch for the detector. `true` by default; a `false` here disables crash-detection
    /// (only a CLEAN committed leave then drives failover). The single-node / no-cluster paths never
    /// reach the detector regardless (it only ever acts as the metadata-Raft leader over >1 voters).
    pub enabled: bool,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_LIVENESS_TIMEOUT,
            enabled: true,
        }
    }
}

/// The ISR-aware survivor-state projection the F2 auto-fire driver needs, supplied CROSS-PLANE by the
/// data plane (the ISR + durable frontiers live in the DATA plane; the proposal happens in the METADATA
/// plane, so the metadata driver cannot compute this itself — it is INJECTED). Given a partition id and
/// the surviving replica ids, it returns each survivor's [`PlacementNode`] (in-ISR flag + durable
/// frontier + divergence), so [`plan_failovers`] chooses a successor ONLY from the in-sync, complete
/// survivors — a stale / out-of-ISR node is never auto-promoted (committed-never-lost, #721 CI5).
pub type SurvivorStateFn = dyn Fn(u64, &[u64]) -> Vec<PlacementNode> + Send + Sync;

/// The committed high-watermark a partition's successor must be complete to (the prefix every ISR
/// member already holds), supplied cross-plane by the data plane alongside [`SurvivorStateFn`].
pub type CommittedHwFn = dyn Fn(u64) -> u64 + Send + Sync;

/// THIS node's OWN real data-plane durable frontier for a partition (its follower high-watermark, or
/// its leader quorum-commit) — the prefix it has itself durably appended (#618b). Supplied cross-plane
/// by the data plane. The auto-failover path can ONLY prove a successor complete from data the surviving
/// cluster actually holds, and the only frontier the metadata leader KNOWS is its OWN; so the
/// provably-complete-or-fail-closed rule compares THIS against the persisted committed-HW checkpoint.
pub type OwnFrontierFn = dyn Fn(u64) -> u64 + Send + Sync;

/// The cross-plane inputs the F2 auto-failover driver reads. INSTALLED by the data-plane bootstrap
/// ([`ClusterRuntime::set_failover_inputs`]) once it owns the live data plane; ABSENT until then, so a
/// runtime with no data plane fails CLOSED — it auto-proposes NO promotion (rather than promoting
/// blind).
///
/// As of #618b these inputs serve BOTH the (cheap, periodic) committed-HW CHECKPOINT the data-plane
/// leader proposes AND the provably-complete-or-fail-closed auto-promotion: `own_frontier` is THIS
/// node's real durable frontier (the only frontier the metadata leader can vouch for), `survivors` is
/// the live ISR-aware projection, and `committed_hw` is this node's own committed frontier (what it
/// checkpoints when it leads).
#[derive(Clone)]
pub struct FailoverInputs {
    /// The live ISR-aware survivor-state projection (see [`SurvivorStateFn`]).
    pub survivors: Arc<SurvivorStateFn>,
    /// The live per-partition committed high-watermark THIS node observes (see [`CommittedHwFn`]). When
    /// this node is the data-plane leader it is the quorum-commit frontier it CHECKPOINTS periodically.
    pub committed_hw: Arc<CommittedHwFn>,
    /// THIS node's own real durable frontier per partition (see [`OwnFrontierFn`]). The provably-complete
    /// auto-failover compares this against the PERSISTED committed-HW checkpoint to decide whether THIS
    /// node may safely self-promote (frontier >= checkpoint) or must fail closed.
    pub own_frontier: Arc<OwnFrontierFn>,
}

/// A point-in-time snapshot of the local cluster member's metadata-plane state, published by the
/// driver each cycle so the rest of the broker (and tests / future admin endpoints) can OBSERVE the
/// running consensus without touching the `RawNode` the driver owns. Read with
/// [`ClusterRuntime::status`].
#[derive(Clone, Debug, Default)]
pub struct ClusterStatus {
    /// This node's id.
    pub node_id: u64,
    /// Whether this node currently believes itself the metadata leader.
    pub is_leader: bool,
    /// The current cluster leader epoch (the monotonic raft term / fencing token).
    pub leader_epoch: u64,
    /// The number of voting members the durable cluster membership currently has — the voter set of
    /// the replicated raft `ConfState` (the real quorum basis from open), NOT the state machine's
    /// apply-driven membership table (which is empty until a membership command is applied through
    /// it).
    pub voter_count: usize,
    /// The applied index of the local metadata state machine (how far the replicated metadata log
    /// has been applied here).
    pub applied_index: u64,
    /// A snapshot of EVERY committed partition placement (#717), published by the driver each cycle so
    /// the DATA-plane serve path can derive its per-partition role from the committed metadata without
    /// touching the `RawNode`. Empty until a placement command commits + applies on this node.
    pub placements: BTreeMap<u64, Placement>,
    /// The set of node ids that LEFT the committed cluster membership (the durable raft `ConfState`)
    /// since the cluster formed — the leaderless-FAILOVER (#618) detection signal. A node is in this set
    /// once a committed joint-consensus membership change (a graceful leave / admin remove) has dropped
    /// it from the voter+learner set. The data-plane FAILOVER driver reads this together with
    /// [`Self::placements`]: for every partition a departed node LED, the metadata leader proposes a
    /// re-placement promoting an in-sync survivor (the #618 [`reassign_leadership`]). Monotonic: a node
    /// that left stays listed (it can rejoin as a fresh add).
    ///
    /// As of #618b BOTH paths feed this: a CLEAN committed leave (graceful / admin remove) AND a CRASH
    /// converted to a committed shrink by the F1 peer-liveness detector — the metadata leader proposes a
    /// silent voter's removal ([`MembershipChange::remove_node`]), and once that conf-change commits the
    /// crashed node lands here exactly like a clean leave. So `departed_members` is the unified
    /// failover-detection signal the F2 auto-fire driver consumes; it carries no timing assumption (the
    /// timing lives in the detector that PRODUCES the shrink, not in this committed fact).
    pub departed_members: BTreeSet<u64>,
    /// The voter peers the F1 detector currently believes are SILENT past the liveness deadline (it has
    /// proposed their removal). Observability only — a peer leaves here once its removal commits (it then
    /// appears in [`Self::departed_members`]) or once it is heard from again before the deadline. Empty on
    /// a healthy cluster; this is the no-false-failover witness (it stays empty under a brief hiccup).
    pub suspected_dead: BTreeSet<u64>,
    /// The partitions the F2 auto-fire driver has proposed a failover promotion for (a committed dead
    /// leader's partitions, re-placed onto an ISR successor). Observability only; cleared when the
    /// promotion commits (the placement's leader is no longer the departed node).
    pub failover_proposed: BTreeSet<u64>,
    /// The last-checkpointed quorum-committed high-watermark per partition (#618b), as applied from the
    /// replicated metadata ([`MetadataCommand::CheckpointCommittedHw`]). This is the SAFE bar that
    /// SURVIVES the leader's death: after a leader dies a survivor reads this to know the committed offset
    /// a successor MUST hold before it may be auto-promoted. Empty until the data-plane leader has
    /// checkpointed at least once. Monotonic per partition (the state machine only ever raises it).
    pub last_committed_hw: BTreeMap<u64, u64>,
}

/// A command for the driver to propose to the metadata group on behalf of the broker (or a test):
/// the driver is the only thread that may touch the `RawNode`, so a metadata write is sent to it
/// over a channel and proposed on the next cycle (it takes effect only if this node is the leader
/// and the entry commits + applies).
enum DriverCmd {
    /// Propose a metadata command (leader-only; ignored with a log line if not leader).
    Propose(MetadataCommand),
    /// TEST SEAM (and ops hook): force a peer to be treated as UNREACHABLE by the F1 liveness
    /// detector, regardless of when it was last heard from. This makes the kill-the-leader test drive
    /// death-detection DETERMINISTICALLY (no real-time sleep): the test kills a node's threads, then
    /// marks it unreachable, and the metadata leader proposes its removal on the next cycle. `true`
    /// marks it unreachable; `false` clears the override (it must then be heard from to stay alive).
    ForcePeerUnreachable { peer: u64, unreachable: bool },
}

/// The driver side of a per-peer outbound queue: a `Sender` plus a shared depth counter so the
/// driver can enforce [`PEER_OUTBOUND_BOUND`] (std `mpsc` is unbounded). The driver increments the
/// depth on enqueue and the dialer decrements it on dequeue; once the depth is at the bound the
/// driver DROPS the message (raft re-sends on the next heartbeat), so a wedged/unreachable peer can
/// never make the queue grow without limit — the edge-safety bound.
struct PeerOutbound {
    tx: Sender<Message>,
    depth: Arc<AtomicUsize>,
}

/// The dialer side of a per-peer outbound queue: the `Receiver` plus the same shared depth counter.
struct PeerInbox {
    rx: Receiver<Message>,
    depth: Arc<AtomicUsize>,
}

/// Errors starting the cluster runtime.
#[derive(Debug)]
pub enum RuntimeError {
    /// The cluster config was invalid (e.g. `node_id` is not one of the configured peers, or the
    /// peer count is not a supported metadata-group size).
    Config(String),
    /// The metadata group could not be opened / constructed (durable storage open, raft validate).
    Group(GroupError),
    /// The peer listener could not bind its configured address.
    Listen(io::Error),
}

impl core::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RuntimeError::Config(m) => write!(f, "invalid cluster config: {m}"),
            RuntimeError::Group(e) => write!(f, "cannot open metadata group: {e}"),
            RuntimeError::Listen(e) => write!(f, "cannot bind cluster peer listener: {e}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<GroupError> for RuntimeError {
    fn from(e: GroupError) -> Self {
        RuntimeError::Group(e)
    }
}

/// The additive, default-OFF cluster configuration: a node id plus the full peer-id→address map of
/// the metadata group (INCLUDING this node's own id+address). Absent ⇒ no cluster runtime (the
/// single-node default), so constructing one is the explicit opt-in.
///
/// The peer set must be a supported metadata-group size (1, 3, or 5) and must contain `node_id`.
/// Every node's address is where its peer LISTENER binds and where the OTHER nodes dial it.
#[derive(Clone, Debug)]
pub struct ClusterConfig {
    /// This broker's node id within the metadata group (a non-zero raft node id).
    pub node_id: u64,
    /// The full membership: every node id mapped to the socket address its peer listener binds /
    /// the address the others dial. Includes `node_id` itself.
    pub peers: BTreeMap<u64, SocketAddr>,
}

impl ClusterConfig {
    /// The local node's bind/listen address (its own entry in `peers`).
    fn self_addr(&self) -> Option<SocketAddr> {
        self.peers.get(&self.node_id).copied()
    }

    /// The sorted voter id set (every configured node is a voter in C1; learners join later via the
    /// membership API).
    fn voters(&self) -> Vec<u64> {
        self.peers.keys().copied().collect()
    }

    /// The remote peers (every node except this one), as id→addr.
    fn remote_peers(&self) -> Vec<(u64, SocketAddr)> {
        self.peers
            .iter()
            .filter(|(&id, _)| id != self.node_id)
            .map(|(&id, &addr)| (id, addr))
            .collect()
    }

    /// Validate the config: `node_id` must be one of the peers, the peer set must be a supported
    /// metadata-group size, and every id must be a valid (non-zero) raft node id.
    fn validate(&self) -> Result<(), RuntimeError> {
        if !self.peers.contains_key(&self.node_id) {
            return Err(RuntimeError::Config(format!(
                "node id {} is not in the configured peer set",
                self.node_id
            )));
        }
        if self.peers.contains_key(&raft::INVALID_ID) {
            return Err(RuntimeError::Config(
                "node id 0 is reserved (raft INVALID_ID) and cannot be a cluster member"
                    .to_string(),
            ));
        }
        let n = self.peers.len();
        if !matches!(n, 1 | 3 | 5) {
            return Err(RuntimeError::Config(format!(
                "cluster peer count {n} is unsupported (must be 1, 3, or 5)"
            )));
        }
        Ok(())
    }
}

/// A handle to a running cluster metadata-plane runtime. Holds the spawned threads (the driver, the
/// peer listener, and one dialer per remote peer); [`stop`](ClusterRuntime::stop) signals shutdown
/// and joins them. Dropping the handle without `stop` still signals shutdown (so a panic on the
/// serve path never leaks the threads), but `stop` is the deterministic join.
pub struct ClusterRuntime {
    /// This node's id within the metadata group (carried so the data-plane serve path can read it
    /// without re-parsing the config).
    node_id: u64,
    /// The full peer-id -> address map (including this node). The data-plane serve path resolves a
    /// leader's data-plane listener address from this (the metadata address with a fixed port offset).
    peers: BTreeMap<u64, SocketAddr>,
    /// The shutdown flag the runtime OWNS (separate from the broker's serve-loop flag so a caller
    /// can stop the cluster plane independently; serve flips both on a stop).
    shutdown: Arc<AtomicBool>,
    /// The latest status snapshot the driver publishes each cycle (leader / epoch / membership /
    /// applied index), read with [`status`](ClusterRuntime::status).
    status: Arc<Mutex<ClusterStatus>>,
    /// The cross-plane F2 auto-failover inputs (the live ISR survivor-state + committed-HW providers),
    /// installed by the data-plane bootstrap via [`set_failover_inputs`](ClusterRuntime::set_failover_inputs).
    /// `None` until installed: a runtime with no data plane fails closed (auto-proposes NO promotion).
    /// Shared with the driver thread, which reads it each cycle to plan failovers off the LIVE ISR.
    failover_inputs: Arc<Mutex<Option<FailoverInputs>>>,
    /// The channel to the driver for proposing metadata commands (the driver owns the `RawNode`).
    cmd_tx: Sender<DriverCmd>,
    /// The metadata-group driver thread (owns the `RawNode`).
    driver: Option<JoinHandle<()>>,
    /// The peer-listener thread (accepts inbound links).
    listener: Option<JoinHandle<()>>,
    /// One dialer thread per remote peer (connects + drains that peer's outbound queue).
    dialers: Vec<JoinHandle<()>>,
}

impl ClusterRuntime {
    /// Start the cluster metadata-plane runtime for `config` over `parent_fs` (the broker's data
    /// dir; the metadata log roots its `metaraft/` subdirectory under it) and `clock` (the I6
    /// monotonic seam the leadership lease is timed off). `log_config` is reused from the broker's
    /// storage config so the metadata log inherits the same segment cap.
    ///
    /// This binds the peer listener and spawns the driver + listener + dialer threads, then returns.
    /// The single-node-default guarantee lives in the CALLER (`serve` only calls this when a
    /// [`ClusterConfig`] is present); a 1-member config here still runs the full runtime (a lone
    /// self-electing voter), it just has no remote peer to dial.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Config`] on an invalid config, [`RuntimeError::Group`] if the durable
    /// metadata group cannot be opened, or [`RuntimeError::Listen`] if the peer listener cannot
    /// bind. On any error NO threads are left running.
    ///
    /// # Panics
    ///
    /// Panics only if the OS refuses to spawn a runtime thread (driver / listener / dialer) — an
    /// unrecoverable resource-exhaustion condition at process start, treated like a failed
    /// allocation. Once `start` returns `Ok`, the runtime never panics on the serve path.
    pub fn start<F, C>(
        config: &ClusterConfig,
        parent_fs: &F,
        clock: C,
        log_config: LogConfig,
    ) -> Result<Self, RuntimeError>
    where
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
    {
        Self::start_with_liveness(
            config,
            parent_fs,
            clock,
            log_config,
            LivenessConfig::default(),
        )
    }

    /// Like [`start`](Self::start) but with an explicit [`LivenessConfig`] for the F1 peer-liveness
    /// death-detector (the injectable deadline that makes the kill-the-leader test deterministic, #618).
    /// [`start`](Self::start) delegates here with [`LivenessConfig::default`] (the 10x-heartbeat
    /// no-false-failover deadline).
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start).
    ///
    /// # Panics
    ///
    /// As [`start`](Self::start).
    pub fn start_with_liveness<F, C>(
        config: &ClusterConfig,
        parent_fs: &F,
        clock: C,
        log_config: LogConfig,
        liveness: LivenessConfig,
    ) -> Result<Self, RuntimeError>
    where
        F: Filesystem + 'static,
        C: Clock + Clone + 'static,
    {
        config.validate()?;
        let self_addr = config
            .self_addr()
            .ok_or_else(|| RuntimeError::Config("missing this node's own address".to_string()))?;

        // Open (or recover) the durable metadata group. This is the ONLY place a `metaraft/`
        // subdirectory is created, and it happens ONLY here in the runtime — never on the no-cluster
        // default path, which keeps that path byte-for-byte today's broker. Keep a clock CLONE for the
        // driver's F1 liveness detector (it times peer silence off the SAME I6 monotonic seam the group
        // uses, never the wall clock — so the kill-the-leader test drives it via a ManualClock).
        let driver_clock = clock.clone();
        let voters = config.voters();
        let group = MetadataRaftGroup::open(config.node_id, &voters, parent_fs, clock, log_config)?;

        // Bind the peer listener BEFORE spawning anything, so a bind failure is reported synchronously
        // (no half-started runtime). Non-blocking so the accept loop can poll the shutdown flag.
        let listener = TcpListener::bind(self_addr).map_err(RuntimeError::Listen)?;
        listener
            .set_nonblocking(true)
            .map_err(RuntimeError::Listen)?;

        let shutdown = Arc::new(AtomicBool::new(false));

        // The shared peer registry: the set of node ids whose messages a reader will accept. Seeded
        // from the configured membership and refreshed by the driver from the group's `ConfState`
        // after a committed membership change. Shared with every reader thread for the peer-id check.
        let registry = Arc::new(Mutex::new(PeerRegistry::from_members(&voters, &[])));

        // The inbound message channel: every reader thread sends decoded, authenticated `Message`s
        // here; the driver receives them and feeds `step`.
        let (inbound_tx, inbound_rx) = mpsc::channel::<Message>();

        // One bounded outbound queue per remote peer. The driver routes each outbound `Message` to
        // the addressed peer's sender; that peer's dialer drains the receiver to the wire. The depth
        // counter enforces PEER_OUTBOUND_BOUND on the (unbounded std mpsc) channel.
        let mut outbound_tx: BTreeMap<u64, PeerOutbound> = BTreeMap::new();
        let mut dialer_specs: Vec<(u64, SocketAddr, PeerInbox)> = Vec::new();
        for (peer_id, addr) in config.remote_peers() {
            let (tx, rx) = mpsc::channel::<Message>();
            let depth = Arc::new(AtomicUsize::new(0));
            outbound_tx.insert(
                peer_id,
                PeerOutbound {
                    tx,
                    depth: Arc::clone(&depth),
                },
            );
            dialer_specs.push((peer_id, addr, PeerInbox { rx, depth }));
        }

        // Spawn the dialers (one per remote peer). Each connects to its peer and drains its queue.
        let mut dialers = Vec::with_capacity(dialer_specs.len());
        for (peer_id, addr, inbox) in dialer_specs {
            let shutdown_d = Arc::clone(&shutdown);
            let handle = std::thread::Builder::new()
                .name(format!("ib-cluster-dial-{peer_id}"))
                .spawn(move || run_dialer(peer_id, addr, inbox, &shutdown_d))
                .expect("spawn cluster dialer thread");
            dialers.push(handle);
        }

        // Spawn the listener (accepts inbound peer links; spawns a reader per connection). It is
        // handed an OWNED `Arc<AtomicBool>` (not a borrow) so it can clone the flag into each
        // per-connection reader it spawns.
        let shutdown_l = Arc::clone(&shutdown);
        let registry_l = Arc::clone(&registry);
        let inbound_tx_l = inbound_tx.clone();
        let listener_handle = std::thread::Builder::new()
            .name("ib-cluster-listen".to_string())
            .spawn(move || run_listener(listener, inbound_tx_l, registry_l, shutdown_l))
            .expect("spawn cluster listener thread");

        // The shared status snapshot the driver publishes each cycle, and the command channel the
        // broker/tests use to propose metadata writes (the driver owns the group).
        let status = Arc::new(Mutex::new(ClusterStatus {
            node_id: config.node_id,
            ..ClusterStatus::default()
        }));
        let (cmd_tx, cmd_rx) = mpsc::channel::<DriverCmd>();

        // The cross-plane F2 auto-failover inputs, ABSENT until the data-plane bootstrap installs them
        // (fail-closed: no data plane => no blind auto-promotion). Shared with the driver thread.
        let failover_inputs: Arc<Mutex<Option<FailoverInputs>>> = Arc::new(Mutex::new(None));

        // The remote VOTER peers the F1 detector watches (every configured node except this one — the
        // peers whose silence past the deadline means a crash). The local node is never "silent to
        // itself", so it is excluded.
        let remote_voters: Vec<u64> = config
            .peers
            .keys()
            .copied()
            .filter(|&id| id != config.node_id)
            .collect();

        // Spawn the driver (owns the group; drives tick/step/drive_ready and routes outbound).
        let shutdown_dr = Arc::clone(&shutdown);
        let registry_dr = Arc::clone(&registry);
        let status_dr = Arc::clone(&status);
        let failover_inputs_dr = Arc::clone(&failover_inputs);
        // Move `inbound_tx` (a keepalive sender) into the driver so the inbound channel never closes
        // while the driver runs, even if every reader has exited.
        let driver_handle = std::thread::Builder::new()
            .name("ib-cluster-driver".to_string())
            .spawn(move || {
                run_driver(
                    group,
                    DriverShared {
                        inbound_rx,
                        _inbound_keepalive: inbound_tx,
                        outbound_tx,
                        cmd_rx,
                        registry: registry_dr,
                        status: status_dr,
                        failover_inputs: failover_inputs_dr,
                    },
                    DriverFailover {
                        clock: driver_clock,
                        liveness,
                        remote_voters,
                    },
                    &shutdown_dr,
                );
            })
            .expect("spawn cluster driver thread");

        Ok(Self {
            node_id: config.node_id,
            peers: config.peers.clone(),
            shutdown,
            status,
            failover_inputs,
            cmd_tx,
            driver: Some(driver_handle),
            listener: Some(listener_handle),
            dialers,
        })
    }

    /// The latest metadata-plane status snapshot the driver published (leader / epoch / membership /
    /// applied index). A cheap clone of the shared snapshot; never touches the `RawNode`.
    #[must_use]
    pub fn status(&self) -> ClusterStatus {
        self.status.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// A snapshot of EVERY committed partition placement (#717) the driver last published — the input
    /// the DATA-plane serve path derives its per-partition role from (leader / follower / none). Empty
    /// until a placement command commits + applies on this node. Reads the shared status snapshot only;
    /// it never touches the `RawNode` the driver owns.
    #[must_use]
    pub fn placements(&self) -> BTreeMap<u64, Placement> {
        self.status
            .lock()
            .map(|s| s.placements.clone())
            .unwrap_or_default()
    }

    /// This node's id within the metadata cluster.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// The shared status snapshot handle (the driver publishes leadership / epoch / committed
    /// placements into it each cycle). Cloned so the data-plane serve bootstrap (#717) can poll the
    /// committed placement + leadership on its OWN thread without borrowing the runtime — it never
    /// touches the `RawNode` the driver owns.
    #[must_use]
    pub fn status_handle(&self) -> Arc<Mutex<ClusterStatus>> {
        Arc::clone(&self.status)
    }

    /// A cloneable handle to propose a metadata command to the driver (e.g. the data-plane bootstrap
    /// proposing the static partition placement once this node is the metadata leader). The driver owns
    /// the `RawNode`, so a write is sent over the channel and proposed on the next cycle; it takes
    /// effect only if this node is the leader and the entry commits + applies across a quorum.
    #[must_use]
    pub fn metadata_proposer(&self) -> MetadataProposer {
        MetadataProposer {
            cmd_tx: self.cmd_tx.clone(),
        }
    }

    /// INSTALL the cross-plane F2 auto-failover inputs (the live ISR survivor-state + committed-HW
    /// providers, #618). Called by the data-plane bootstrap once it owns the live data plane: from then
    /// on, when a committed membership shrink names a dead leader's partition, the metadata-Raft leader
    /// AUTO-plans + proposes a promotion of an in-sync survivor (chosen ONLY from the LIVE ISR these
    /// closures surface — never a stale snapshot). Before install the runtime fails CLOSED (it
    /// auto-proposes NO promotion), so a runtime with no data plane never promotes blind.
    ///
    /// Idempotent / last-writer-wins: re-installing replaces the providers (the data plane may rebuild).
    pub fn set_failover_inputs(&self, inputs: FailoverInputs) {
        if let Ok(mut slot) = self.failover_inputs.lock() {
            *slot = Some(inputs);
        }
    }

    /// A cloneable, `Send` handle the data-plane bootstrap thread holds to install the cross-plane F2
    /// inputs WITHOUT borrowing the runtime (the bootstrap is a `'static` thread). It shares the same
    /// slot [`set_failover_inputs`](Self::set_failover_inputs) writes, so the driver picks the providers
    /// up on its next cycle.
    #[must_use]
    pub fn failover_installer(&self) -> FailoverInstaller {
        FailoverInstaller {
            slot: Arc::clone(&self.failover_inputs),
        }
    }

    /// TEST SEAM (and ops hook): force/clear the F1 liveness detector treating `peer` as UNREACHABLE,
    /// independent of when it was last heard from. This is the deterministic seam the kill-the-leader
    /// integration test uses to drive crash-detection WITHOUT a real-time sleep: the test stops a node's
    /// threads, marks it unreachable here, and the metadata leader proposes its removal on the next
    /// cycle (which the auto-fire path then turns into a promotion). `true` marks unreachable; `false`
    /// clears it. A no-op if the driver has already stopped.
    pub fn force_peer_unreachable(&self, peer: u64, unreachable: bool) {
        let _ = self
            .cmd_tx
            .send(DriverCmd::ForcePeerUnreachable { peer, unreachable });
    }

    /// The peer-id -> address map of the whole metadata group (including this node). The data-plane
    /// serve path (#717) resolves a follower's leader address from this to dial the data-plane peer
    /// listener (which binds an offset port — see [`dataplane_addr`]).
    #[must_use]
    pub fn peers(&self) -> BTreeMap<u64, SocketAddr> {
        self.peers.clone()
    }

    /// Ask the driver to propose a metadata command on the next cycle (the driver owns the group, so
    /// a write is sent to it over a channel). It takes effect only if this node is the leader and the
    /// resulting entry commits and applies across a quorum. Returns an error only if the driver has
    /// already stopped.
    ///
    /// # Errors
    ///
    /// Returns a [`RuntimeError::Config`] if the driver channel is closed (the runtime is stopping).
    pub fn propose_metadata(&self, cmd: MetadataCommand) -> Result<(), RuntimeError> {
        self.cmd_tx
            .send(DriverCmd::Propose(cmd))
            .map_err(|_| RuntimeError::Config("cluster driver has stopped".to_string()))
    }

    /// Signal shutdown and join every runtime thread. Idempotent: a second call is a no-op (the
    /// handles are already taken). Called by `serve` on a stop, alongside flipping the broker's own
    /// serve-loop flag.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.driver.take() {
            let _ = h.join();
        }
        if let Some(h) = self.listener.take() {
            let _ = h.join();
        }
        for h in self.dialers.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for ClusterRuntime {
    fn drop(&mut self) {
        // Best-effort: a caller that forgets `stop` (or a panic on the serve path) still signals the
        // threads to wind down rather than leaking them. The deterministic join is `stop`.
        self.shutdown.store(true, Ordering::Release);
    }
}

/// A cloneable handle for proposing a metadata command to a running [`ClusterRuntime`]'s driver, from
/// another thread (the data-plane serve bootstrap, #717). It carries only the driver command channel,
/// so it is `Send` and outlives a borrow of the runtime. A proposal takes effect only if this node is
/// the metadata leader and the resulting entry commits + applies across a quorum.
#[derive(Clone)]
pub struct MetadataProposer {
    cmd_tx: Sender<DriverCmd>,
}

impl MetadataProposer {
    /// Propose a metadata command on the next driver cycle. Returns an error only if the driver has
    /// already stopped (the runtime is tearing down).
    ///
    /// # Errors
    /// [`RuntimeError::Config`] if the driver channel is closed.
    pub fn propose(&self, cmd: MetadataCommand) -> Result<(), RuntimeError> {
        self.cmd_tx
            .send(DriverCmd::Propose(cmd))
            .map_err(|_| RuntimeError::Config("cluster driver has stopped".to_string()))
    }
}

/// A cloneable, `Send` handle for installing the cross-plane F2 auto-failover inputs from another
/// thread (the data-plane bootstrap, #618), without borrowing the [`ClusterRuntime`]. It shares the
/// same slot the driver reads each cycle; installing makes the auto-fire path choose an ISR successor
/// from the LIVE data-plane ISR these providers surface.
#[derive(Clone)]
pub struct FailoverInstaller {
    slot: Arc<Mutex<Option<FailoverInputs>>>,
}

impl FailoverInstaller {
    /// Install (or replace) the cross-plane F2 inputs. Last-writer-wins; a no-op if the mutex is
    /// poisoned (the runtime is tearing down).
    pub fn install(&self, inputs: FailoverInputs) {
        if let Ok(mut slot) = self.slot.lock() {
            *slot = Some(inputs);
        }
    }
}

/// The partitions a `node` currently LEADS, from a committed `placements` snapshot — the partitions a
/// leaderless-FAILOVER (#618) must re-place when `node` departs. Pure, deterministic (sorted by id).
#[must_use]
pub fn partitions_led_by(
    placements: &BTreeMap<u64, Placement>,
    node: u64,
) -> Vec<(u64, Placement)> {
    placements
        .iter()
        .filter(|(_, p)| p.leader == node)
        .map(|(&id, p)| (id, p.clone()))
        .collect()
}

/// Plan the leaderless-node FAILOVER re-placements for a set of `departed` nodes against a committed
/// `placements` snapshot (#618). For every partition a departed node LED, this consults the #618
/// [`reassign_leadership`](crate::cluster::placement::reassign_leadership) policy — which chooses a
/// successor ONLY from the in-sync, complete SURVIVORS (the ISR) — and collects the committable
/// [`MetadataCommand::PlacePartition`] that promotes it (one entry per re-placed partition).
///
/// `survivor_states` is the ISR-AWARE projection the caller supplies: given a partition id and the
/// surviving replica ids, it returns each survivor's [`PlacementNode`](ironbus_core::placement::PlacementNode)
/// (its in-ISR flag + durable frontier + divergence). The data-plane FAILOVER driver fills this from the
/// live ISR / replica-log frontiers (the metadata plane does not itself hold ISR state — keeping the
/// decision ISR-aware is exactly why the caller, which DOES, supplies it). `committed_hw_for` gives each
/// partition's cluster-known committed high-watermark the successor must be complete to.
///
/// Returns the proposals to commit through the metadata raft (via [`MetadataProposer::propose`]), so
/// every node converges on the same new placements. A partition with NO eligible survivor yields NO
/// proposal (fail-closed — it is left leaderless until a survivor catches up, never promoting an
/// incomplete replica that would lose committed data).
///
/// Pure + deterministic + IO-free: it reads no wall clock and the choice is the pure
/// [`reassign_leadership`](crate::cluster::placement::reassign_leadership) policy.
#[must_use]
pub fn plan_failovers<S, H>(
    placements: &BTreeMap<u64, Placement>,
    departed: &std::collections::BTreeSet<u64>,
    mut survivor_states: S,
    mut committed_hw_for: H,
    leader_load: &ironbus_core::placement::LeaderLoad,
) -> Vec<MetadataCommand>
where
    S: FnMut(u64, &[u64]) -> Vec<ironbus_core::placement::PlacementNode>,
    H: FnMut(u64) -> u64,
{
    let mut proposals = Vec::new();
    for &dead in departed {
        for (partition, placement) in partitions_led_by(placements, dead) {
            let survivors: Vec<u64> = placement
                .replicas
                .iter()
                .copied()
                .filter(|&n| n != dead)
                .collect();
            let states = survivor_states(partition, &survivors);
            let committed_hw = committed_hw_for(partition);
            if let crate::cluster::placement::FailoverOutcome::Promoted { command, .. } =
                crate::cluster::placement::reassign_leadership(
                    partition,
                    dead,
                    &placement.replicas,
                    placement.epoch,
                    placement.epoch,
                    &states,
                    committed_hw,
                    leader_load,
                )
            {
                proposals.push(command);
            }
            // No eligible survivor => no proposal (fail-closed; left leaderless until one catches up).
        }
    }
    proposals
}

/// The shared channels + Arcs the driver thread owns for its whole lifetime. Bundled so the driver's
/// entry point stays under the argument-count lint while keeping each a distinct, named concern.
struct DriverShared {
    /// Inbound peer messages a reader delivered (drained + fed to `step`).
    inbound_rx: Receiver<Message>,
    /// A keepalive `Sender` held so the inbound channel never closes while the driver runs, even if
    /// every reader has exited. Never sent on.
    _inbound_keepalive: Sender<Message>,
    /// Per-remote-peer bounded outbound queues (the driver routes `drive_ready` output here).
    outbound_tx: BTreeMap<u64, PeerOutbound>,
    /// The broker/test command channel (propose metadata / the liveness test seam).
    cmd_rx: Receiver<DriverCmd>,
    /// The shared peer-id registry (refreshed from the committed `ConfState`).
    registry: Arc<Mutex<PeerRegistry>>,
    /// The published status snapshot (leader / epoch / placements / departed-members).
    status: Arc<Mutex<ClusterStatus>>,
    /// The cross-plane F2 auto-failover inputs (installed by the data-plane bootstrap; `None` until then).
    failover_inputs: Arc<Mutex<Option<FailoverInputs>>>,
}

/// The F1/F2 auto-failover wiring the driver thread owns: the monotonic clock seam, the liveness
/// tuning, and the remote voter set it watches.
struct DriverFailover<C: Clock + Clone> {
    /// The I6 monotonic clock the liveness detector times peer silence off (never the wall clock).
    clock: C,
    /// The peer-liveness detector tuning (the injectable deadline + enable switch).
    liveness: LivenessConfig,
    /// The remote voter peers watched for silence (every configured node except this one).
    remote_voters: Vec<u64>,
}

/// The driver loop: OWNS the metadata group and is the only thread that touches the `RawNode`.
///
/// On a fixed cadence it (1) advances the election/heartbeat timer with `tick`, (2) drains every
/// inbound `Message` a reader delivered and feeds each to `step` (recording `last_heard` per peer —
/// the F1 liveness signal), (3) runs `drive_ready` (which persists + fsyncs before advancing, #659)
/// and routes the outbound messages to each addressed peer's outbound queue, (4) refreshes the shared
/// peer registry from the group's `ConfState` so a committed membership change updates which peers a
/// reader will accept, (5) runs the **F1 peer-liveness death-detector** (if metadata leader, proposes
/// the removal of any voter silent past the deadline — converting a crash into a committed shrink), and
/// (6) runs the **F2 auto-fire** path (if metadata leader, plans + proposes a failover promotion for
/// every partition a departed node led, choosing the successor from the LIVE ISR). It blocks on the
/// inbound channel with a `TICK_INTERVAL` timeout, so it is responsive to inbound traffic yet never
/// busy-spins and re-checks shutdown at least every tick.
///
/// SINGLE PROPOSER: F1's removal AND F2's promotion are proposed ONLY when this node is the
/// metadata-Raft leader, both go through the metadata Raft log (committed, ordered), and both are
/// idempotent (a removal of an already-gone node and a promotion of an already-converged placement are
/// skipped) — so no two nodes can drive a different failover; the Raft log linearizes it.
#[allow(clippy::too_many_lines)]
// the driver loop is ONE linear consensus cycle (tick, step+record,
// drive_ready, registry refresh, F1 detect, F2 auto-fire, publish);
// splitting it would scatter a single tightly-ordered concern.
#[allow(clippy::needless_pass_by_value)] // a thread entry point: it OWNS the group + the shared
                                         // channels/Arcs + the failover wiring for the thread's whole
                                         // lifetime; a borrow would fight the 'static spawn bound.
fn run_driver<F, C>(
    mut group: MetadataRaftGroup<F, C>,
    shared: DriverShared,
    failover: DriverFailover<C>,
    shutdown: &AtomicBool,
) where
    F: Filesystem,
    C: Clock + Clone,
{
    // The membership view last published to the registry, so we only re-lock + rewrite it when the
    // committed `ConfState` actually changes (a committed membership change), not every cycle.
    let mut last_members: Vec<u64> = Vec::new();
    // Every node id ever seen in the committed membership, so a node that LEAVES (dropped from a later
    // `ConfState`) can be detected as departed = (ever-seen) - (currently-present). The #618 failover
    // detection signal; published in the status snapshot for the data-plane failover driver.
    let mut ever_seen_members: BTreeSet<u64> = BTreeSet::new();
    let mut departed_members: BTreeSet<u64> = BTreeSet::new();
    // The durable `ConfState` voter count, refreshed each cycle below and published as the status
    // `voter_count`. This is the cluster's AGREED voter set (the seeded-then-replicated raft
    // `ConfState`), not the state machine's apply-driven membership table — the latter is empty on a
    // freshly-formed group until a membership COMMAND is applied through it, whereas the `ConfState`
    // is the real quorum basis from open.
    let mut conf_voter_count: usize = 0;
    let node_id = group.node_id();

    // F1 STATE: the last monotonic time (nanos) we heard ANY metadata message from each remote voter.
    // The metadata-Raft heartbeat (every ~3 ticks) refreshes this for a live peer, so a peer whose
    // entry is older than the deadline (and which is not in `forced_unreachable`) is a crashed peer.
    // Seeded to "now" so the cluster gets a full deadline of grace before anyone is suspected (no
    // false failover at startup before the first heartbeat round-trip lands).
    let mut last_heard: BTreeMap<u64, u64> = BTreeMap::new();
    let now0 = failover.clock.now_monotonic_nanos();
    for &peer in &failover.remote_voters {
        last_heard.insert(peer, now0);
    }
    // The deterministic test/ops override: peers forced unreachable regardless of `last_heard`.
    let mut forced_unreachable: BTreeSet<u64> = BTreeSet::new();
    // Peers whose removal we have already proposed (avoid re-proposing every cycle while the conf
    // change commits). Cleared for a peer once it actually departs (lands in `departed_members`).
    let mut removal_proposed: BTreeSet<u64> = BTreeSet::new();
    // Partitions we have already proposed an F2 promotion for (avoid re-proposing while it commits).
    // Cleared once the committed placement's leader is no longer the departed node (promotion landed).
    let mut failover_proposed: BTreeSet<u64> = BTreeSet::new();

    let deadline_nanos = duration_to_nanos(failover.liveness.timeout);

    // CP STATE (#618b): the cadence + the last monotonic time we proposed a committed-HW checkpoint, so
    // a leader checkpoints PERIODICALLY (not per cycle / per record). Seeded back a full interval so the
    // first checkpoint can fire as soon as the data plane installs its inputs.
    let checkpoint_interval_nanos = duration_to_nanos(COMMITTED_HW_CHECKPOINT_INTERVAL);
    let mut last_checkpoint_nanos = failover
        .clock
        .now_monotonic_nanos()
        .saturating_sub(checkpoint_interval_nanos);

    while !shutdown.load(Ordering::Acquire) {
        // Advance the logical election/heartbeat timer once per cadence.
        group.tick();

        // Apply any pending driver commands from the broker/tests. A `Propose` is leader-only (a
        // non-leader proposal is rejected by the core and logged, never panics); a `ForcePeerUnreachable`
        // updates the F1 override (the deterministic kill-the-leader test seam).
        while let Ok(cmd) = shared.cmd_rx.try_recv() {
            match cmd {
                DriverCmd::Propose(mcmd) => {
                    if let Err(e) = group.propose(&mcmd) {
                        tracing::debug!(error = %e, "cluster: metadata proposal rejected (not leader?)");
                    }
                }
                DriverCmd::ForcePeerUnreachable { peer, unreachable } => {
                    if unreachable {
                        forced_unreachable.insert(peer);
                    } else {
                        forced_unreachable.remove(&peer);
                    }
                }
            }
        }

        // Wait up to one tick for an inbound peer message, then drain every other message already
        // queued (non-blocking) before driving ready, so a burst is consumed in one pass rather than
        // one per cadence. The wait keeps the loop responsive to traffic without busy-spinning. Every
        // stepped message records `last_heard[from] = now` — the F1 liveness signal (a live peer's
        // heartbeats keep it fresh; a crashed peer's entry goes stale).
        match shared.inbound_rx.recv_timeout(TICK_INTERVAL) {
            Ok(msg) => {
                record_heard(&msg, &failover.clock, &mut last_heard);
                if let Err(e) = group.step(msg) {
                    // A step error for a message addressed to a node mid-membership-change is benign
                    // (it may no longer recognise the sender); drop it and continue.
                    tracing::debug!(error = %e, "cluster: dropped a peer message on step");
                }
                drain_inbound_nonblocking(
                    &shared.inbound_rx,
                    &mut group,
                    &failover.clock,
                    &mut last_heard,
                );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Every sender (readers + the keepalive) dropped: the runtime is tearing down.
                return;
            }
        }

        // Drive the ready cycle (persist + fsync before advance, #659) and route the outbound
        // messages to the addressed peers' queues.
        match group.drive_ready() {
            Ok(outbound) => route_outbound(outbound, &shared.outbound_tx),
            Err(e) => {
                tracing::error!(error = %e, "cluster: drive_ready failed");
            }
        }

        // Refresh the shared peer registry from the durable membership if it changed, and track the
        // durable voter count for the status snapshot (the cluster's agreed quorum basis).
        if let Ok(cs) = group.conf_state() {
            conf_voter_count = cs.get_voters().len();
            let mut members: Vec<u64> = cs.get_voters().to_vec();
            members.extend_from_slice(cs.get_learners());
            members.sort_unstable();
            members.dedup();
            if members != last_members {
                if let Ok(mut reg) = shared.registry.lock() {
                    *reg = PeerRegistry::from_members(cs.get_voters(), cs.get_learners());
                }
                // Update the failover detection signal: any node ever seen but now ABSENT has departed.
                // (The set only grows / shifts on a real committed membership change, not every cycle.)
                ever_seen_members.extend(members.iter().copied());
                let present: BTreeSet<u64> = members.iter().copied().collect();
                departed_members = ever_seen_members.difference(&present).copied().collect();
                last_members = members;
                // A peer that has now committed-departed no longer needs its removal re-proposed.
                removal_proposed.retain(|p| !departed_members.contains(p));
            }
        }

        // ----- F1: the peer-liveness DEATH DETECTOR. Only the metadata-Raft leader proposes (single
        // proposer), and only for a CURRENT voter that is silent past the deadline (or forced
        // unreachable in a test). A removed/already-departed peer is skipped (idempotent). This
        // converts a crash (a still-a-voter-but-silent node) into a committed membership shrink, which
        // F2 below then turns into a promotion. The no-false-failover guarantee is the deadline ratio:
        // a peer must be silent for ~10 heartbeat intervals (see DEFAULT_LIVENESS_TIMEOUT). -----
        let now = failover.clock.now_monotonic_nanos();
        let mut suspected: BTreeSet<u64> = BTreeSet::new();
        if failover.liveness.enabled && group.is_leader() {
            // Snapshot the current voter set so we never propose removing a node that already left.
            let current_voters: BTreeSet<u64> = group
                .conf_state()
                .map(|cs| cs.get_voters().iter().copied().collect())
                .unwrap_or_default();
            for &peer in &failover.remote_voters {
                if !current_voters.contains(&peer) {
                    continue; // already gone from the membership — nothing to remove.
                }
                // `is_none_or` is stable only since 1.82; MSRV is 1.78, so spell it out: a peer with no
                // recorded `last_heard` (never heard from) OR one silent past the deadline is silent.
                let silent = forced_unreachable.contains(&peer)
                    || last_heard
                        .get(&peer)
                        .map_or(true, |&t| now.saturating_sub(t) >= deadline_nanos);
                if !silent {
                    continue;
                }
                suspected.insert(peer);
                if removal_proposed.contains(&peer) {
                    continue; // removal already in flight; let it commit (don't spam the log).
                }
                // Propose the conf-change removal through the metadata Raft (validated + replicated +
                // committed). Refused if it would empty the voter set (the membership validator) or if a
                // conf change is already pending — both benign; we retry next cycle.
                let change = MembershipChange::new().remove_node(peer);
                match group.propose_membership_change(&change) {
                    Ok(()) => {
                        removal_proposed.insert(peer);
                        tracing::info!(
                            peer,
                            "cluster: F1 liveness detector proposed removal of a silent voter (crash failover)"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(peer, error = %e, "cluster: removal proposal deferred");
                    }
                }
            }
        }

        let placements = group.state().placements();

        // ----- CP: PERSIST the committed-HW CHECKPOINT (#618b). On a cadence the metadata leader, IF it
        // also leads a partition's data plane (so it knows the live committed HW), proposes a
        // `CheckpointCommittedHw` into the metadata Raft. This is what makes the committed bar SURVIVE the
        // leader's death: after the leader dies a survivor reads the last committed checkpoint and knows
        // the SAFE offset a successor MUST hold. It is PERIODIC + bounded (never per record). -----
        if group.is_leader() {
            let due = now.saturating_sub(last_checkpoint_nanos) >= checkpoint_interval_nanos;
            if due {
                if let Some(inputs) = shared.failover_inputs.lock().ok().and_then(|g| g.clone()) {
                    // Checkpoint only the partitions THIS node currently LEADS in the committed
                    // placement (it is the only node that knows their live committed HW). A new placement
                    // value re-checkpoints under the next leader once it owns the data plane.
                    for (&partition, placement) in &placements {
                        if placement.leader != node_id {
                            continue;
                        }
                        let hw = (inputs.committed_hw)(partition);
                        // Skip a no-op: the bar is monotonic, so re-proposing an already-recorded (or
                        // lower) value adds nothing. Only propose when it would RAISE the persisted bar.
                        let persisted = group.state().committed_hw(partition).unwrap_or(0);
                        if hw <= persisted {
                            continue;
                        }
                        let cmd = MetadataCommand::CheckpointCommittedHw {
                            partition,
                            offset: hw,
                        };
                        if let Err(e) = group.propose(&cmd) {
                            tracing::debug!(partition, error = %e, "cluster: committed-HW checkpoint deferred");
                        }
                    }
                }
                last_checkpoint_nanos = now;
            }
        }

        // ----- F2: AUTO-FIRE the failover — PROVABLY committed-safe, fail-closed (#618b). On a committed
        // membership shrink (`departed_members` non-empty), the metadata leader auto-promotes a partition
        // a departed node LED, but ONLY a successor it can PROVE holds every committed record — i.e.
        // ONLY ITSELF, and only when its own real durable frontier has reached the PERSISTED committed-HW
        // checkpoint (the bar that survived the dead leader). It does NOT know remote frontiers (no ISR
        // gossip yet), so a remote node — even a committed replica — is NEVER blind-promoted. In EVERY
        // case it cannot prove safety (own frontier behind the bar, or only a remote node might be
        // complete) it FAILS CLOSED: proposes nothing, leaves the partition leaderless, and logs the
        // withholding. The chosen successor is re-verified against CI5 before it is proposed, so the
        // runtime — not just a test — enforces the committed-completeness invariant. Single proposer +
        // idempotent (a partition already re-led by a survivor is skipped). -----
        // Drop any "proposed" marks whose committed placement has already moved off the departed leader
        // (the promotion landed) so a later, distinct departure can re-fire.
        failover_proposed.retain(|p| {
            placements
                .get(p)
                .is_some_and(|pl| departed_members.contains(&pl.leader))
        });
        if group.is_leader() && !departed_members.is_empty() {
            let inputs = shared.failover_inputs.lock().ok().and_then(|g| g.clone());
            if let Some(inputs) = inputs {
                for (&partition, placement) in &placements {
                    if !departed_members.contains(&placement.leader) {
                        continue; // not led by a departed node (or already failed over).
                    }
                    if failover_proposed.contains(&partition) {
                        continue; // promotion already in flight; let it commit.
                    }
                    // The SAFE bar: the PERSISTED committed-HW checkpoint that survived the dead leader.
                    // Absent (no checkpoint ever committed for this partition) => we cannot prove ANY
                    // successor safe => fail closed.
                    let Some(safe_bar) = group.state().committed_hw(partition) else {
                        tracing::info!(
                            partition,
                            "cluster: F2 auto-failover WITHHELD — no persisted committed-HW checkpoint; \
                             leaving the partition leaderless until a provably-complete replica is known"
                        );
                        continue;
                    };
                    // The ONLY successor we can PROVE complete is THIS node, and only when its own real
                    // durable frontier has reached the safe bar. We do not know remote frontiers.
                    let own_frontier = (inputs.own_frontier)(partition);
                    if own_frontier < safe_bar {
                        tracing::info!(
                            partition,
                            own_frontier,
                            safe_bar,
                            "cluster: F2 auto-failover WITHHELD (fail-closed) — the metadata leader's own \
                             frontier is behind the persisted committed-HW checkpoint; no provably-complete \
                             replica is known, so the partition stays leaderless (recoverable)"
                        );
                        continue;
                    }
                    // Build the self-promotion and re-verify it against CI5 (the runtime gate, not just a
                    // test): the successor is THIS node, it is in its own ISR by construction (it leads /
                    // holds the committed log to the bar), its durable prefix >= the bar, and the new
                    // epoch strictly exceeds the dead leader's. If CI5 rejects it for ANY reason, fail
                    // closed rather than propose it.
                    let new_epoch = placement.epoch.saturating_add(1);
                    let failover = ironbus_core::cluster_invariants::Failover {
                        dead_leader: placement.leader,
                        successor: node_id,
                        successor_in_isr: true,
                        successor_durable_prefix: own_frontier,
                        committed_hw: safe_bar,
                        dead_leader_epoch: LeaderEpoch::new(placement.epoch),
                        successor_epoch: LeaderEpoch::new(new_epoch),
                    };
                    if let Err(violation) =
                        ironbus_core::cluster_invariants::check_failover_preserves_committed(
                            &failover,
                        )
                    {
                        tracing::warn!(
                            partition,
                            %violation,
                            "cluster: F2 auto-failover WITHHELD — the self-promotion failed the CI5 \
                             committed-completeness gate; failing closed"
                        );
                        continue;
                    }
                    // Survivors = the old replica set minus the departed leader, with THIS node ensured
                    // present (it is the new leader). The bar is carried in the command so the apply-time
                    // self-verify (defense in depth) can re-check it before this node becomes leader.
                    let mut survivors: Vec<u64> = placement
                        .replicas
                        .iter()
                        .copied()
                        .filter(|&n| n != placement.leader)
                        .collect();
                    if !survivors.contains(&node_id) {
                        survivors.push(node_id);
                    }
                    let cmd = MetadataCommand::PlacePartition {
                        partition,
                        replicas: survivors,
                        leader: node_id,
                        epoch: new_epoch,
                    };
                    match group.propose(&cmd) {
                        Ok(()) => {
                            failover_proposed.insert(partition);
                            tracing::info!(
                                partition,
                                successor = node_id,
                                safe_bar,
                                "cluster: F2 auto-fire proposed a PROVABLY-COMPLETE self-promotion (the \
                                 metadata leader's frontier holds the persisted committed-HW checkpoint)"
                            );
                        }
                        Err(e) => {
                            tracing::debug!(partition, error = %e, "cluster: failover proposal deferred");
                        }
                    }
                }
            }
            // else: no installed providers (no data plane) => fail-closed, propose nothing.
        }

        // Publish the latest status snapshot for observers (status() / future admin endpoints). The
        // committed placements are published too, so the data-plane serve path (#717) reads its
        // per-partition role from the committed metadata via `placements()` without ever touching the
        // `RawNode` the driver owns. The snapshot is only re-cloned when the applied index advances, so
        // a steady cluster does not re-clone the (small) placement map every tick.
        if let Ok(mut s) = shared.status.lock() {
            s.node_id = node_id;
            s.is_leader = group.is_leader();
            s.leader_epoch = group.leader_epoch().get();
            s.voter_count = conf_voter_count;
            let applied = group.state().applied_index();
            if applied != s.applied_index {
                s.placements = placements.clone();
                // The persisted committed-HW checkpoints (#618b) advance with the applied log, so
                // re-publish them whenever the applied index does (they are the SAFE bars survivors read
                // after a leader death).
                s.last_committed_hw = group.state().committed_hws();
            }
            s.applied_index = applied;
            // Publish the leaderless-failover detection signal (the departed-members set), so the
            // data-plane failover driver can re-place every partition a departed node led (#618). Only
            // re-cloned when it actually changed (a committed membership shrink), not every tick.
            if s.departed_members != departed_members {
                s.departed_members.clone_from(&departed_members);
            }
            // Publish the F1/F2 observability witnesses (the no-false-failover witness `suspected_dead`
            // and the in-flight `failover_proposed`), only re-cloned when they change.
            if s.suspected_dead != suspected {
                s.suspected_dead.clone_from(&suspected);
            }
            if s.failover_proposed != failover_proposed {
                s.failover_proposed.clone_from(&failover_proposed);
            }
        }
    }
}

/// Record that we just heard a metadata message FROM a peer at the current monotonic time — the F1
/// liveness signal. A message with no sender (id 0, e.g. a local tick artifact) is ignored.
fn record_heard<C: Clock>(msg: &Message, clock: &C, last_heard: &mut BTreeMap<u64, u64>) {
    let from = msg.get_from();
    if from != raft::INVALID_ID {
        last_heard.insert(from, clock.now_monotonic_nanos());
    }
}

/// Convert a [`Duration`] to nanoseconds, saturating at `u64::MAX`, so an absurdly large injected
/// deadline never wraps (and a deadline of 0 disables the grace window, which the tests may use).
fn duration_to_nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Drain any inbound messages already queued, without blocking, feeding each to `step` and recording
/// `last_heard` per sender (the F1 liveness signal). Called after the first blocking receive so a
/// burst of peer messages is consumed in one pass before driving ready, rather than one per cadence.
fn drain_inbound_nonblocking<F, C>(
    rx: &Receiver<Message>,
    group: &mut MetadataRaftGroup<F, C>,
    clock: &C,
    last_heard: &mut BTreeMap<u64, u64>,
) where
    F: Filesystem,
    C: Clock + Clone,
{
    loop {
        match rx.try_recv() {
            Ok(msg) => {
                record_heard(&msg, clock, last_heard);
                if let Err(e) = group.step(msg) {
                    tracing::debug!(error = %e, "cluster: dropped a peer message on step");
                }
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

/// Route each outbound `Message` `drive_ready` produced to the addressed peer's bounded queue. A
/// message to an unknown peer (not in the outbound map) or to a peer whose queue is already at
/// [`PEER_OUTBOUND_BOUND`] is DROPPED (raft re-sends on the next heartbeat, so a dropped message is
/// self-healing); this never blocks the driver on a wedged peer — the edge-safety bound.
fn route_outbound(outbound: Vec<Message>, outbound_tx: &BTreeMap<u64, PeerOutbound>) {
    for msg in outbound {
        let to = msg.to;
        if let Some(peer) = outbound_tx.get(&to) {
            // Enforce the per-peer queue bound: if the dialer is not draining (peer wedged /
            // unreachable), drop rather than grow the queue. The depth counter is incremented here
            // and decremented by the dialer on dequeue.
            if peer.depth.load(Ordering::Acquire) >= PEER_OUTBOUND_BOUND {
                continue;
            }
            peer.depth.fetch_add(1, Ordering::AcqRel);
            if peer.tx.send(msg).is_err() {
                // Dialer thread is gone (runtime tearing down); undo the count.
                peer.depth.fetch_sub(1, Ordering::AcqRel);
            }
        }
        // else: unknown destination (e.g. a self-addressed message, or a peer not in the static
        // set) — dropped.
    }
}

/// A dialer thread: connect to one remote peer and drain its outbound queue to the wire. On a failed
/// connect or a dropped link it backs off and reconnects (raft tolerates a transiently down peer:
/// the next heartbeat re-sends), polling the shutdown flag between attempts so a stop is prompt.
// A thread entry point: it OWNS its per-peer `inbox` (the receiver it drains) for the thread's
// lifetime; a borrow would fight the 'static spawn bound.
#[allow(clippy::needless_pass_by_value)]
fn run_dialer(peer_id: u64, addr: SocketAddr, inbox: PeerInbox, shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Acquire) {
        match TcpStream::connect_timeout(&addr, DIALER_RECONNECT_BACKOFF) {
            Ok(stream) => {
                // A short write timeout so a stalled peer doesn't wedge the dialer past a stop.
                let _ = stream.set_write_timeout(Some(DIALER_RECONNECT_BACKOFF));
                let mut link = PeerLink::new(stream);
                pump_outbound_to_link(peer_id, &mut link, &inbox, shutdown);
            }
            Err(_) => {
                // Peer not reachable yet; back off and retry, checking shutdown.
                sleep_interruptible(DIALER_RECONNECT_BACKOFF, shutdown);
            }
        }
    }
    // Drain and discard anything left (decrementing the depth) so the channel can close cleanly.
    while inbox.rx.try_recv().is_ok() {
        inbox.depth.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Drain the per-peer outbound queue to the link until shutdown, the link breaks, or the queue
/// disconnects. On a send (write) error the link is dropped and the dialer reconnects. Each dequeued
/// message decrements the shared depth counter (the bound the driver enforces on enqueue).
fn pump_outbound_to_link(
    peer_id: u64,
    link: &mut PeerLink<TcpStream>,
    inbox: &PeerInbox,
    shutdown: &AtomicBool,
) {
    while !shutdown.load(Ordering::Acquire) {
        match inbox.rx.recv_timeout(TICK_INTERVAL) {
            Ok(msg) => {
                inbox.depth.fetch_sub(1, Ordering::AcqRel);
                if let Err(e) = link.send(&msg) {
                    tracing::debug!(peer = peer_id, error = %e, "cluster: peer send failed; reconnecting");
                    return;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Nothing to send this window; loop re-checks shutdown.
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// The listener thread: accept inbound peer connections and spawn a reader per connection. Reader
/// threads are detached; they exit on a closed/broken link or shutdown. The accept loop is
/// non-blocking and polls the shutdown flag so a stop is prompt. It owns an `Arc<AtomicBool>` so it
/// can clone the shutdown flag into each reader it spawns.
// A thread entry point: it OWNS the listener, the inbound sender, and the shared Arcs (cloned into
// each per-connection reader) for the thread's lifetime; a borrow would fight the 'static spawn
// bound and prevent cloning into the spawned readers.
#[allow(clippy::needless_pass_by_value)]
fn run_listener(
    listener: TcpListener,
    inbound_tx: Sender<Message>,
    registry: Arc<Mutex<PeerRegistry>>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // A short read timeout so a reader's blocking `recv` re-checks shutdown promptly and
                // an idle inbound link never wedges a stop.
                let _ = stream.set_read_timeout(Some(TICK_INTERVAL));
                let tx = inbound_tx.clone();
                let reg = Arc::clone(&registry);
                let sd = Arc::clone(&shutdown);
                let _ = std::thread::Builder::new()
                    .name("ib-cluster-read".to_string())
                    .spawn(move || run_reader(PeerLink::new(stream), tx, reg, sd));
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                sleep_interruptible(TICK_INTERVAL, &shutdown);
            }
            Err(_) => sleep_interruptible(TICK_INTERVAL, &shutdown),
        }
    }
}

/// Sleep for `dur` but wake early if shutdown is set, in small slices, so a stop is never delayed by
/// a full sleep. Used by the accept poll and the dialer backoff.
fn sleep_interruptible(dur: Duration, shutdown: &AtomicBool) {
    let slice = Duration::from_millis(20);
    let mut left = dur;
    while left > Duration::ZERO && !shutdown.load(Ordering::Acquire) {
        let this = slice.min(left);
        std::thread::sleep(this);
        left = left.checked_sub(this).unwrap_or(Duration::ZERO);
    }
}

/// Read bounded, authenticated peer messages off `link` and forward them to the driver's inbound
/// channel until the link closes/breaks or shutdown is set. Every message is size+recursion bounded
/// and peer-id-authenticated by [`PeerLink::recv`] against the shared registry before it is
/// forwarded (a hostile/unknown peer is dropped here, never reaching `step`).
// A per-connection thread entry point: it OWNS its link, inbound sender, and shared Arcs for the
// connection's lifetime; a borrow would fight the 'static spawn bound.
#[allow(clippy::needless_pass_by_value)]
fn run_reader(
    mut link: PeerLink<TcpStream>,
    inbound_tx: Sender<Message>,
    registry: Arc<Mutex<PeerRegistry>>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        // Snapshot the current membership for the auth check (cheap clone of a small BTreeSet).
        let reg = match registry.lock() {
            Ok(g) => g.clone(),
            Err(_) => return,
        };
        match link.recv(&reg) {
            Ok(Some(msg)) => {
                if inbound_tx.send(msg).is_err() {
                    return; // driver gone
                }
            }
            Ok(None) => return, // peer closed cleanly
            Err(PeerWireError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                // The read timeout elapsed with no full frame (the SO_RCVTIMEO surfaces as
                // WouldBlock or TimedOut depending on the platform); the link's buffer keeps any
                // partial frame, so loop and re-check shutdown, then read more.
            }
            Err(e) => {
                // A framing/decode/auth error from a misbehaving or hostile peer: drop the link.
                tracing::debug!(error = %e, "cluster: peer read error; dropping link");
                return;
            }
        }
    }
}

// Pure, platform-agnostic tests for the #618 leaderless-failover DETECTION + PLANNING helpers
// (`partitions_led_by` / `plan_failovers`). They touch no filesystem / socket, so they are NOT
// unix-gated (unlike the StdFs runtime tests below) and run on every platform.
#[cfg(test)]
mod failover_planning_tests {
    use super::*;
    use ironbus_core::placement::{LeaderLoad, PlacementNode};
    use std::collections::{BTreeMap, BTreeSet};

    fn placements(entries: &[(u64, Vec<u64>, u64, u64)]) -> BTreeMap<u64, Placement> {
        entries
            .iter()
            .map(|(p, replicas, leader, epoch)| {
                (
                    *p,
                    Placement {
                        replicas: replicas.clone(),
                        leader: *leader,
                        epoch: *epoch,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn partitions_led_by_finds_exactly_the_dead_leaders_partitions() {
        // Node 1 leads partitions 0 + 2; node 2 leads partition 1. When node 1 departs, partitions 0 + 2
        // are the ones to re-place.
        let pl = placements(&[
            (0, vec![1, 2, 3], 1, 5),
            (1, vec![1, 2, 3], 2, 5),
            (2, vec![1, 2, 3], 1, 5),
        ]);
        let led = partitions_led_by(&pl, 1);
        let ids: Vec<u64> = led.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            ids,
            vec![0, 2],
            "exactly the partitions node 1 leads, sorted"
        );
        assert!(
            partitions_led_by(&pl, 3).is_empty(),
            "a non-leader leads nothing"
        );
    }

    #[test]
    fn plan_failovers_proposes_one_isr_promotion_per_partition_the_dead_node_led() {
        // Node 1 (leading partitions 0 + 2) departs. Survivors 2 + 3 are in-sync + complete. The plan
        // proposes ONE PlacePartition per partition, each promoting an in-sync survivor at a bumped epoch
        // over the surviving replica set — and NONE for partition 1 (which node 1 did not lead).
        let pl = placements(&[
            (0, vec![1, 2, 3], 1, 5),
            (1, vec![1, 2, 3], 2, 5),
            (2, vec![1, 2, 3], 1, 7),
        ]);
        let departed: BTreeSet<u64> = [1u64].into_iter().collect();
        let proposals = plan_failovers(
            &pl,
            &departed,
            // ISR-aware survivor states: both survivors are healthy + complete to HW 100.
            |_partition, survivors| {
                survivors
                    .iter()
                    .map(|&n| PlacementNode::healthy(n, 100))
                    .collect()
            },
            |_partition| 100,
            &LeaderLoad::new(),
        );
        assert_eq!(
            proposals.len(),
            2,
            "one proposal per partition the dead node led (0 + 2)"
        );
        for cmd in &proposals {
            match cmd {
                MetadataCommand::PlacePartition {
                    partition,
                    replicas,
                    leader,
                    epoch,
                } => {
                    assert!(*partition == 0 || *partition == 2);
                    assert_eq!(
                        replicas,
                        &vec![2, 3],
                        "the dead leader is dropped from the replica set"
                    );
                    assert_ne!(*leader, 1, "the dead leader is never re-chosen");
                    assert!(
                        replicas.contains(leader),
                        "the new leader is one of the survivors"
                    );
                    // Partition 0 was at epoch 5 => fenced to 6; partition 2 at epoch 7 => fenced to 8.
                    let expected = if *partition == 0 { 6 } else { 8 };
                    assert_eq!(
                        *epoch, expected,
                        "the epoch is bumped strictly above the dead leader's"
                    );
                }
                other => panic!("expected PlacePartition, got {other:?}"),
            }
        }
    }

    #[test]
    fn plan_failovers_proposes_nothing_when_no_survivor_is_in_sync() {
        // Node 1 departs, but the only survivor (node 2) is OUT of the ISR (it lagged out). There is no
        // eligible successor => NO proposal (fail-closed: the partition is left leaderless rather than
        // promoting an incomplete replica that would lose committed data).
        let pl = placements(&[(0, vec![1, 2], 1, 5)]);
        let departed: BTreeSet<u64> = [1u64].into_iter().collect();
        let proposals = plan_failovers(
            &pl,
            &departed,
            |_p, survivors| {
                survivors
                    .iter()
                    .map(|&n| {
                        let mut node = PlacementNode::healthy(n, 100);
                        node.in_isr = false; // out of the ISR => ineligible
                        node
                    })
                    .collect()
            },
            |_p| 100,
            &LeaderLoad::new(),
        );
        assert!(
            proposals.is_empty(),
            "no in-sync survivor => no failover proposal (fail-closed, never promote an incomplete replica)"
        );
    }

    #[test]
    fn plan_failovers_is_empty_when_no_node_departed() {
        // A steady cluster (no departures) plans NO failover — the no-false-failover property.
        let pl = placements(&[(0, vec![1, 2, 3], 1, 5)]);
        let proposals = plan_failovers(
            &pl,
            &BTreeSet::new(),
            |_p, survivors| {
                survivors
                    .iter()
                    .map(|&n| PlacementNode::healthy(n, 100))
                    .collect()
            },
            |_p| 100,
            &LeaderLoad::new(),
        );
        assert!(proposals.is_empty(), "no departure => no failover");
    }
}

// Unix-only: these tests use `StdFs` (the real on-disk backend), which is `#[cfg(unix)]` —
// the cluster runtime is a Unix-only on-disk feature, like `serve`. Gating the module keeps the
// Windows CI build green (no `StdFs` reference there).
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::cluster::state_machine::MetadataCommand;
    use crate::cluster::transport::{encode_raft_message, MAX_RAFT_MSG_BYTES};
    use ironbus_server_test_clock::SystemClock;
    use ironbus_storage::fs::StdFs;
    use raft::eraftpb::{Message, MessageType};
    use std::io::Write as _;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Instant;

    // The runtime needs a concrete `Clock` (the SystemClock the broker uses) and a real on-disk
    // `StdFs` (the cluster runtime is a Unix-only on-disk feature, like serve). We bring SystemClock
    // in via a tiny shim module below so the test file names ONE clock type.

    /// Acquire the shared heavy-cluster-test serial guard (defined in the parent `cluster` module so it
    /// serializes against the `serve` module's heavy tests too): each heavy multi-node test holds it for
    /// its whole body, so the clusters form on an un-contended host (the #687 starvation, amplified by N
    /// concurrent clusters, never bites). See [`super::super::heavy_cluster_test_guard`].
    fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::cluster::heavy_cluster_test_guard()
    }

    /// Allocate `n` free localhost TCP ports by binding ephemeral sockets, reading the assigned
    /// ports, then dropping the listeners. There is a small TOCTOU window before the runtime rebinds,
    /// but for an in-process loopback test on a quiet port range it is reliable.
    fn free_ports(n: usize) -> Vec<u16> {
        let mut listeners = Vec::with_capacity(n);
        let mut ports = Vec::with_capacity(n);
        for _ in 0..n {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
            ports.push(l.local_addr().expect("local addr").port());
            listeners.push(l);
        }
        // listeners drop here, freeing the ports for the runtime to rebind.
        ports
    }

    /// Build a `BTreeMap<u64, SocketAddr>` peer map from ids and their loopback ports.
    fn peer_map(ids: &[u64], ports: &[u16]) -> BTreeMap<u64, SocketAddr> {
        ids.iter()
            .zip(ports.iter())
            .map(|(&id, &port)| (id, SocketAddr::from((Ipv4Addr::LOCALHOST, port))))
            .collect()
    }

    /// Spin until `pred` holds or `timeout` elapses; returns whether it held. Used to wait for the
    /// asynchronous, thread-driven cluster to reach a state (a leader elected, an entry applied)
    /// without sleeping a fixed, brittle duration.
    ///
    /// It POLLS at a fine interval and returns the instant `pred` first holds, so on a healthy host
    /// it exits early (the cluster elects in ~1 s, so these waits cost ~1 s, not the full `timeout`).
    /// The `timeout` is only the GENEROUS upper bound for a slow/contended host; pair it with
    /// [`host_scaled`] so that bound stretches with the host rather than being a fixed wall-clock
    /// value that races under CI CPU starvation.
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

    /// A fixed slug of pure-CPU work whose wall-clock cost MEASURES how much CPU this thread is
    /// actually getting. On an idle host it runs in well under a millisecond; on a CPU-starved CI
    /// runner (every core pegged by other test binaries) the SAME work takes many times longer in
    /// wall-clock because the thread is repeatedly preempted. That ratio is exactly the starvation
    /// that slows the runtime's driver thread (which must accumulate ~10 election-timeout `tick`s to
    /// elect), so it is the right thing to scale the election-wait deadline by. Pure arithmetic with a
    /// `black_box` fence so the optimiser cannot fold it away.
    fn probe_busy_nanos() -> u128 {
        // ~2M iterations of dependent integer work: long enough to dwarf timer granularity and to
        // span several scheduler slices under contention, short enough to be negligible on an idle
        // host (sub-millisecond).
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

    /// Scale a GENEROUS base election-wait deadline by the observed host slowdown so the cluster
    /// election tests are robust to CI CPU contention WITHOUT weakening what they prove.
    ///
    /// The fix for #687: the runtime drives raft on a fixed-ms `tick` cadence on a driver thread, and
    /// an election needs ~10 ticks. A FIXED wall-clock wait races under CI starvation — the starved
    /// driver thread doesn't accumulate enough ticks inside the bound, so the leader-elected assertion
    /// flakes (a timing race, not a logic bug: it passes locally and on re-run). Rather than bump a
    /// fixed sleep (which still races on a slow-enough host) or weaken the assertion, we calibrate the
    /// deadline to the host: [`probe_busy_nanos`] measures this thread's real CPU throughput, and we
    /// multiply the base deadline by how many times slower than a fast reference host we are (clamped).
    ///
    /// On an unloaded host the factor is ~1, so the deadline stays the generous base and the poll
    /// still exits early the instant a leader is elected (the test is FAST). On a starved host the
    /// factor grows, stretching the cap so the (equally starved) driver thread is given proportionally
    /// more wall-clock time to do the SAME number of ticks. The assertion is UNCHANGED — it still
    /// fails if a leader is never elected / nothing commits within the (now host-tolerant) deadline,
    /// which is a real regression. Same adaptive-calibration philosophy as the #666 `injected_stall` fix.
    fn host_scaled(base: Duration) -> Duration {
        /// A fast, unloaded reference host runs [`probe_busy_nanos`]'s slug in roughly this long. The
        /// scale factor is `observed / reference`, clamped to `[1, MAX_SCALE]`: a host at or faster
        /// than the reference gets the base deadline (factor 1, never SHORTER — we only ever extend),
        /// a slower/contended host gets a proportionally longer one.
        const REFERENCE_BUSY_NANOS: u128 = 4_000_000; // ~4 ms for ~2M iters on a fast core.
        /// Cap the multiplier so a pathologically wedged host still fails in bounded time rather than
        /// hanging the suite — a genuinely never-electing cluster (a real bug) must still surface.
        const MAX_SCALE: u32 = 12;

        // Take the median of three probes so a single descheduled probe doesn't skew the estimate.
        let mut samples = [probe_busy_nanos(), probe_busy_nanos(), probe_busy_nanos()];
        samples.sort_unstable();
        let observed = samples[1];

        let factor = (observed / REFERENCE_BUSY_NANOS).clamp(1, u128::from(MAX_SCALE));
        // `factor` is clamped to [1, MAX_SCALE] (both fit a u32), so the conversion is infallible;
        // fall back to the cap rather than `unwrap` to keep the helper panic-free regardless.
        let factor = u32::try_from(factor).unwrap_or(MAX_SCALE);
        base * factor
    }

    /// Start a runtime for one node of a cluster, rooted at a per-node temp dir.
    fn start_node(config: &ClusterConfig, dir: &std::path::Path) -> ClusterRuntime {
        let fs = StdFs::new(dir.to_path_buf());
        ClusterRuntime::start(
            config,
            &fs,
            SystemClock::new(),
            LogConfig::new(64 * 1024).unwrap(),
        )
        .expect("start cluster node")
    }

    /// A 3-node in-process cluster over the REAL loopback peer transport forms a quorum, ELECTS A
    /// LEADER, and COMMITS a metadata entry replicated to a quorum (with the group's
    /// fsync-before-advance durability). This is the multi-node consensus the issue asks for, run
    /// over the bounded peer codec — not the hand-delivered-`Message` in-process mesh the group's own
    /// tests use.
    #[test]
    fn three_node_cluster_elects_a_leader_and_commits_a_metadata_entry() {
        let _serial = serial_guard();
        let ids = [1u64, 2, 3];
        let ports = free_ports(3);
        let peers = peer_map(&ids, &ports);

        let dirs: Vec<_> = ids
            .iter()
            .map(|_| tempfile::tempdir().expect("tempdir"))
            .collect();
        let mut nodes: Vec<ClusterRuntime> = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| {
                let cfg = ClusterConfig {
                    node_id: id,
                    peers: peers.clone(),
                };
                start_node(&cfg, dirs[i].path())
            })
            .collect();

        // A leader is elected within a few seconds (election ~1 s at the 100 ms tick cadence). The
        // poll exits the instant exactly one leader appears (fast on a healthy host); the deadline is
        // a GENEROUS upper bound that `host_scaled` stretches under CI CPU starvation so the starved
        // driver thread still gets enough wall-clock time to accumulate its election ticks (#687).
        let elected = wait_until(host_scaled(Duration::from_secs(20)), || {
            nodes.iter().filter(|n| n.status().is_leader).count() == 1
        });
        assert!(elected, "exactly one leader should be elected");

        let leader_idx = nodes
            .iter()
            .position(|n| n.status().is_leader)
            .expect("a leader");
        let leader_epoch = nodes[leader_idx].status().leader_epoch;
        assert!(leader_epoch >= 1, "the leader holds a real (>=1) epoch");

        // Propose a metadata write on the leader and confirm it commits + applies on a QUORUM
        // (every node here, since the cluster is healthy) — replicated over the peer transport.
        nodes[leader_idx]
            .propose_metadata(MetadataCommand::SetConfig {
                key: "cluster.tier".to_string(),
                value: "prod".to_string(),
            })
            .expect("propose");

        // The applied index advances past the leader's no-op election entry on every node once the
        // SetConfig entry commits and applies across the quorum. Same host-scaled, early-exit poll:
        // it returns as soon as the entry is replicated everywhere, and the deadline stretches under
        // contention rather than racing the (starved) replication round-trip (#687).
        let committed = wait_until(host_scaled(Duration::from_secs(20)), || {
            nodes.iter().all(|n| n.status().applied_index >= 2)
        });
        assert!(
            committed,
            "the metadata entry should commit + apply on a quorum (applied indices: {:?})",
            nodes
                .iter()
                .map(|n| n.status().applied_index)
                .collect::<Vec<_>>()
        );

        // Every node sees 3 voters (the membership the durable ConfState agrees on).
        for n in &nodes {
            assert_eq!(
                n.status().voter_count,
                3,
                "3 voters agreed across the cluster"
            );
        }

        for n in &mut nodes {
            n.stop();
        }
    }

    /// A node RESTART recovers its durable metadata log and REJOINS the quorum. We run a 3-node
    /// cluster, commit an entry, stop one node, then start it again over the SAME data dir; it
    /// recovers its metadata log (its epoch is seeded from the durable term, #659) and rejoins, and
    /// the cluster keeps (or re-forms) a quorum.
    #[test]
    fn a_restarted_node_recovers_its_metadata_log_and_rejoins() {
        let _serial = serial_guard();
        let ids = [1u64, 2, 3];
        let ports = free_ports(3);
        let peers = peer_map(&ids, &ports);
        let dirs: Vec<_> = ids
            .iter()
            .map(|_| tempfile::tempdir().expect("tempdir"))
            .collect();

        let mk = |id: u64| ClusterConfig {
            node_id: id,
            peers: peers.clone(),
        };

        let mut nodes: Vec<ClusterRuntime> = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| start_node(&mk(id), dirs[i].path()))
            .collect();

        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || nodes
                .iter()
                .filter(|n| n.status().is_leader)
                .count()
                == 1),
            "initial leader elected"
        );

        // Stop node index 2 (id 3) — its durable metaraft/ image stays on disk in dirs[2].
        nodes[2].stop();
        // Confirm its data dir has a metaraft/ subdir (the durable metadata log was written).
        assert!(
            dirs[2].path().join(super::super::METADATA_SUBDIR).exists(),
            "the restarted node has a durable metaraft/ log to recover"
        );

        // The remaining two nodes still form a quorum (2 of 3 is a majority).
        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || nodes[..2]
                .iter()
                .filter(|n| n.status().is_leader)
                .count()
                == 1),
            "the 2 surviving nodes keep a quorum + a leader"
        );

        // Restart node id 3 over the SAME data dir; it recovers and rejoins.
        nodes[2] = start_node(&mk(3), dirs[2].path());
        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || {
                // The rejoined node catches up to a non-zero applied index (it is replicated to) and
                // the cluster still has exactly one leader.
                nodes.iter().filter(|n| n.status().is_leader).count() == 1
                    && nodes[2].status().leader_epoch >= 1
            }),
            "the restarted node rejoins and the cluster holds a single leader"
        );

        for n in &mut nodes {
            n.stop();
        }
    }

    /// A 1-member cluster runs the full runtime (it self-elects), binds its listener, and dials no
    /// remote peer. This is the degenerate `n=1` case the runtime supports; it still creates a
    /// metaraft/ log (it is a configured cluster), unlike the NO-cluster default (which never
    /// constructs a runtime at all — tested at the serve level).
    #[test]
    fn a_single_member_cluster_self_elects() {
        let ports = free_ports(1);
        let peers = peer_map(&[1], &ports);
        let dir = tempfile::tempdir().expect("tempdir");
        let mut node = start_node(&ClusterConfig { node_id: 1, peers }, dir.path());

        assert!(
            wait_until(host_scaled(Duration::from_secs(10)), || node
                .status()
                .is_leader),
            "the lone voter self-elects"
        );
        assert!(
            dir.path().join(super::super::METADATA_SUBDIR).exists(),
            "a configured 1-member cluster does create its metaraft/ log"
        );
        node.stop();
    }

    /// The bounded peer codec stays bounded on the WIRED path: a connection that sends an oversized
    /// frame (a length prefix beyond `MAX_RAFT_MSG_BYTES`) or an unauthenticated/garbage frame is
    /// rejected by the reader and never crashes the node. The cluster keeps running.
    #[test]
    fn the_wired_reader_rejects_hostile_frames_without_crashing() {
        let _serial = serial_guard();
        let ids = [1u64, 2, 3];
        let ports = free_ports(3);
        let peers = peer_map(&ids, &ports);
        let dirs: Vec<_> = ids.iter().map(|_| tempfile::tempdir().unwrap()).collect();
        let mut nodes: Vec<ClusterRuntime> = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| {
                start_node(
                    &ClusterConfig {
                        node_id: id,
                        peers: peers.clone(),
                    },
                    dirs[i].path(),
                )
            })
            .collect();

        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || nodes
                .iter()
                .filter(|n| n.status().is_leader)
                .count()
                == 1),
            "leader elected before the hostile probe"
        );

        // Connect to node 1's listener and send a hostile, oversized length prefix. The reader must
        // reject it (it never allocates the claimed size, never panics) and just drop the link.
        let addr = peers[&1];
        if let Ok(mut s) = TcpStream::connect(addr) {
            // A frame length prefix far beyond the cap; the reader rejects pre-allocation.
            let bogus_len = u64::from(MAX_RAFT_MSG_BYTES) + 1_000_000;
            let mut buf = Vec::new();
            buf.extend_from_slice(&bogus_len.to_le_bytes());
            buf.extend_from_slice(b"garbage");
            let _ = s.write_all(&buf);
            // Also send a well-formed-looking but UNKNOWN-peer message (from id 99, not a member):
            // the registry authentication rejects it.
            let mut msg = Message::new();
            msg.set_msg_type(MessageType::MsgHeartbeat);
            msg.set_from(99);
            msg.set_to(1);
            if let Ok(frame) = encode_raft_message(&msg) {
                let _ = s.write_all(&frame);
            }
            drop(s);
        }

        // The cluster survives the hostile probe: a leader is still present a moment later.
        assert!(
            wait_until(host_scaled(Duration::from_secs(10)), || nodes
                .iter()
                .filter(|n| n.status().is_leader)
                .count()
                == 1),
            "the cluster survives a hostile peer frame (no crash, still a leader)"
        );

        for n in &mut nodes {
            n.stop();
        }
    }

    /// The single-node (no-cluster) default is byte-identical: with NO [`ClusterRuntime`] constructed
    /// over a data dir, NO `metaraft/` subdirectory is ever created (the metadata log is opened ONLY
    /// by the runtime), and no peer listener binds. This is the serve-level guarantee tested at the
    /// layer that owns it — `serve` simply never calls [`ClusterRuntime::start`] absent a config, so
    /// the on-disk layout + threads are today's broker. We assert the absence directly: a data dir
    /// that the runtime never touched has no `metaraft/`, whereas a configured 1-member runtime over
    /// the SAME shape of dir does create it (proving the subdir's existence is the runtime's doing).
    #[test]
    fn no_cluster_runtime_leaves_no_metaraft_and_binds_nothing() {
        // A data dir a broker uses WITHOUT a cluster config: nothing in this module ran against it,
        // so it must have no metaraft/ (and, transitively, no peer listener was bound for it).
        let plain = tempfile::tempdir().expect("tempdir");
        assert!(
            !plain.path().join(super::super::METADATA_SUBDIR).exists(),
            "a no-cluster data dir must have NO metaraft/ subdir (byte-identical default)"
        );

        // The contrast: a configured 1-member runtime over a fresh dir DOES create metaraft/, so the
        // subdir's presence is exactly the runtime opt-in — nothing creates it on the default path.
        let configured = tempfile::tempdir().expect("tempdir");
        let ports = free_ports(1);
        let peers = peer_map(&[1], &ports);
        let mut node = start_node(&ClusterConfig { node_id: 1, peers }, configured.path());
        assert!(
            wait_until(host_scaled(Duration::from_secs(10)), || configured
                .path()
                .join(super::super::METADATA_SUBDIR)
                .exists()),
            "a configured cluster runtime DOES create metaraft/ (the opt-in side plane)"
        );
        node.stop();

        // The no-cluster dir is STILL untouched after a configured runtime ran elsewhere: the two
        // are fully isolated, confirming the default path never grows a metadata plane.
        assert!(
            !plain.path().join(super::super::METADATA_SUBDIR).exists(),
            "the no-cluster data dir stays free of metaraft/"
        );
    }

    /// An invalid cluster config (a node id not in the peer set, or an unsupported size) is rejected
    /// at `start` without binding anything.
    #[test]
    fn an_invalid_cluster_config_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        // node id not in the peer set
        let peers: BTreeMap<u64, SocketAddr> = [(1u64, SocketAddr::from((Ipv4Addr::LOCALHOST, 9)))]
            .into_iter()
            .collect();
        let r = ClusterRuntime::start(
            &ClusterConfig { node_id: 2, peers },
            &StdFs::new(dir.path().to_path_buf()),
            SystemClock::new(),
            LogConfig::new(64 * 1024).unwrap(),
        );
        assert!(matches!(r, Err(RuntimeError::Config(_))));

        // an unsupported size (2 voters)
        let peers2 = peer_map(&[1, 2], &[10, 11]);
        let r2 = ClusterRuntime::start(
            &ClusterConfig {
                node_id: 1,
                peers: peers2,
            },
            &StdFs::new(dir.path().to_path_buf()),
            SystemClock::new(),
            LogConfig::new(64 * 1024).unwrap(),
        );
        assert!(matches!(r2, Err(RuntimeError::Config(_))));
    }

    // ============================================================================================
    // #618b AUTOMATIC leaderless failover — the END-TO-END proof: kill the leader, let the
    // AUTOMATIC path (F1 detect + F2 auto-fire) run, and assert the cluster self-heals leadership
    // with NO test-driven manual reconcile. These extend the #721 harness; the #721 mechanism-level
    // test (in serve.rs) stays as the by-construction proof.
    // ============================================================================================

    const TEST_PARTITION: u64 = 0;

    /// Install a SIMULATED healthy-ISR failover-input provider on a node: every surviving committed
    /// replica is reported in-ISR and complete to the committed HW, and THIS node's own frontier is
    /// reported AT the committed HW (a caught-up survivor). With every survivor caught up, the metadata
    /// leader's own frontier reaches the persisted committed-HW checkpoint, so the SAFE path
    /// self-promotes (#618b). The metadata plane does not itself hold ISR/frontier state — this is the
    /// seam the real data-plane bootstrap fills. `committed_hw` is the quorum-acked frontier every ISR
    /// member holds; `replicas` the committed replica set.
    fn install_healthy_isr(node: &ClusterRuntime, replicas: Vec<u64>, committed_hw: u64) {
        install_isr_with_own_frontier(node, replicas, committed_hw, committed_hw);
    }

    /// Like [`install_healthy_isr`] but with an explicit OWN-frontier value, so a test can model THIS
    /// node LAGGING the committed HW (own frontier < committed HW) — the case the safe path must FAIL
    /// CLOSED on. Every surviving committed replica is still reported in-ISR + complete (the cross-plane
    /// ISR cannot see remote frontiers), but this node's own frontier is what the provably-complete rule
    /// actually compares against the persisted checkpoint.
    fn install_isr_with_own_frontier(
        node: &ClusterRuntime,
        replicas: Vec<u64>,
        committed_hw: u64,
        own_frontier: u64,
    ) {
        let committed: BTreeSet<u64> = replicas.into_iter().collect();
        let survivors: Arc<SurvivorStateFn> = Arc::new(move |_partition, survivor_ids: &[u64]| {
            survivor_ids
                .iter()
                .filter(|n| committed.contains(n))
                .map(|&n| PlacementNode::healthy(n, committed_hw))
                .collect()
        });
        let committed_hw_fn: Arc<CommittedHwFn> = Arc::new(move |_partition| committed_hw);
        let own_frontier_fn: Arc<OwnFrontierFn> = Arc::new(move |_partition| own_frontier);
        node.set_failover_inputs(FailoverInputs {
            survivors,
            committed_hw: committed_hw_fn,
            own_frontier: own_frontier_fn,
        });
    }

    /// Bring up a 3-node cluster, wait for a metadata leader, commit the static placement naming the
    /// metadata leader as the partition leader, and install a healthy-ISR provider on every node.
    /// Returns the running nodes, their ids, their data dirs (kept alive), and the elected leader's
    /// index — the shared setup for the auto-failover tests. `liveness` tunes the F1 detector.
    #[allow(clippy::type_complexity)]
    fn bring_up_placed_cluster(
        liveness: LivenessConfig,
    ) -> (
        std::sync::MutexGuard<'static, ()>,
        Vec<ClusterRuntime>,
        [u64; 3],
        Vec<tempfile::TempDir>,
        usize,
    ) {
        // Serialize against the other heavy multi-node tests so this cluster forms on an un-contended
        // host (the guard is held by the caller for its whole body — returned below).
        let serial = serial_guard();
        let ids = [1u64, 2, 3];
        let ports = free_ports(3);
        let peers = peer_map(&ids, &ports);
        let dirs: Vec<_> = ids
            .iter()
            .map(|_| tempfile::tempdir().expect("tempdir"))
            .collect();
        let nodes: Vec<ClusterRuntime> = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| {
                let cfg = ClusterConfig {
                    node_id: id,
                    peers: peers.clone(),
                };
                let fs = StdFs::new(dirs[i].path().to_path_buf());
                ClusterRuntime::start_with_liveness(
                    &cfg,
                    &fs,
                    SystemClock::new(),
                    LogConfig::new(64 * 1024).unwrap(),
                    liveness,
                )
                .expect("start cluster node")
            })
            .collect();

        // A metadata leader is elected.
        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || nodes
                .iter()
                .filter(|n| n.status().is_leader)
                .count()
                == 1),
            "a metadata leader is elected"
        );
        let leader_idx = nodes
            .iter()
            .position(|n| n.status().is_leader)
            .expect("a leader");
        let leader_id = ids[leader_idx];

        // Commit the static placement: the metadata leader leads partition 0 over all three replicas
        // at epoch >= 1. Every node converges on it (the input the failover re-places).
        let epoch = nodes[leader_idx].status().leader_epoch.max(1);
        nodes[leader_idx]
            .propose_metadata(MetadataCommand::PlacePartition {
                partition: TEST_PARTITION,
                replicas: vec![1, 2, 3],
                leader: leader_id,
                epoch,
            })
            .expect("propose placement");
        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || nodes.iter().all(
                |n| {
                    n.status()
                        .placements
                        .get(&TEST_PARTITION)
                        .is_some_and(|p| p.leader == leader_id)
                }
            )),
            "the placement (leader = node {leader_id}) committed on every node"
        );

        // Install a healthy-ISR provider on every node (the cross-plane seam): committed HW = 100, the
        // surviving committed replicas are all in-sync and every node's OWN frontier is at the HW. This
        // is what lets the safe F2 path self-promote a caught-up successor.
        for n in &nodes {
            install_healthy_isr(n, vec![1, 2, 3], 100);
        }

        // The metadata leader (it leads the partition's data plane in this model) auto-checkpoints the
        // committed HW on its cadence. Wait until the persisted committed-HW checkpoint has committed on
        // every node, so the SAFE bar (= 100) survives the leader's death and a successor can be proven
        // complete against it (#618b). Without this persisted bar the safe path would (correctly) fail
        // closed, so the kill-the-leader test depends on it being durably recorded first.
        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || nodes.iter().all(
                |n| { n.status().last_committed_hw.get(&TEST_PARTITION).copied() == Some(100) }
            )),
            "the committed-HW checkpoint (=100) committed on every node"
        );

        (serial, nodes, ids, dirs, leader_idx)
    }

    /// THE deliverable's heart: bring up a 3-node cluster with a committed placement, KILL the leader,
    /// and let the AUTOMATIC path run (mark the dead leader unreachable — the deterministic detection
    /// seam, no real-time sleep). Assert, with NO manual `reconcile` / `plan_failovers` in the test:
    ///   (a) the runtime AUTO-detects the dead leader and proposes + commits its REMOVAL (the F1 path
    ///       converts a crash into a committed membership shrink → `departed_members`);
    ///   (b) it AUTO-plans + proposes + commits a PROMOTION of an ISR successor (F2 auto-fire);
    ///   (c) the committed placement names a SURVIVING replica (never the dead leader) — the in-place
    ///       successor — with the committed prefix preserved (the successor is ISR + complete: CI5);
    ///   (d) the old leader's epoch is FENCED (the new placement's epoch strictly exceeds the old);
    ///   (e) the cluster RESUMES: the surviving 2-node quorum commits a NEW metadata entry under the
    ///       new metadata leader.
    #[test]
    fn killing_the_leader_auto_detects_promotes_an_isr_successor_and_the_cluster_resumes() {
        // Detection here is driven by the DETERMINISTIC `force_peer_unreachable` seam (clock-independent),
        // so we keep the DEFAULT (long) timeout: only the explicitly-killed node is ever detected — a
        // healthy peer is NEVER spuriously suspected (no false failover), even under CI load. The seam
        // is what makes this fast WITHOUT a real-time sleep; the timeout path is proven separately below.
        let (_serial, mut nodes, ids, _dirs, leader_idx) =
            bring_up_placed_cluster(LivenessConfig::default());
        let dead_id = ids[leader_idx];
        let old_epoch = nodes[leader_idx]
            .status()
            .placements
            .get(&TEST_PARTITION)
            .expect("placement")
            .epoch;

        // --- KILL the leader node: stop its threads (its metadata + would-be data plane go away). ---
        nodes[leader_idx].stop();

        // Drive the AUTOMATIC path deterministically: tell every SURVIVING node's liveness detector the
        // dead node is unreachable. Whichever survivor becomes the new metadata leader will, on its next
        // cycle, propose the dead node's removal (F1) and then the ISR-successor promotion (F2). This is
        // the ONLY thing the test drives — NO manual reconcile / plan_failovers / promote call.
        for (i, n) in nodes.iter().enumerate() {
            if i != leader_idx {
                n.force_peer_unreachable(dead_id, true);
            }
        }

        // The surviving two nodes re-form a quorum and elect a NEW metadata leader (2 of 3 is a
        // majority; raft re-elects on the tick cadence regardless of the clock).
        let survivors: Vec<usize> = (0..3).filter(|&i| i != leader_idx).collect();
        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || survivors
                .iter()
                .filter(|&&i| nodes[i].status().is_leader)
                .count()
                == 1),
            "the surviving quorum elects a new metadata leader"
        );

        // (a) the dead leader is AUTO-detected + REMOVED: it commits as a membership shrink, so it
        // appears in `departed_members` on a surviving node (and the voter count drops to 2). No manual
        // membership change was proposed by the test — only `force_peer_unreachable` + the driver's F1.
        assert!(
            wait_until(host_scaled(Duration::from_secs(25)), || survivors.iter().any(
                |&i| {
                    let s = nodes[i].status();
                    s.departed_members.contains(&dead_id) && s.voter_count <= 2
                }
            )),
            "(a) the dead leader is auto-detected and committed-removed (departed_members + voter_count<=2)"
        );

        // (b)+(c)+(d) the promotion AUTO-commits: a surviving node's committed placement for the
        // partition now names a SURVIVING replica as leader, at a STRICTLY higher epoch (the fence),
        // over the surviving replica set (the dead leader dropped).
        assert!(
            wait_until(host_scaled(Duration::from_secs(25)), || survivors.iter().any(
                |&i| {
                    nodes[i]
                        .status()
                        .placements
                        .get(&TEST_PARTITION)
                        .is_some_and(|p| p.leader != dead_id && p.epoch > old_epoch)
                }
            )),
            "(b) a promotion auto-committed: the partition's committed leader changed to a survivor"
        );

        // Read the converged new placement from a survivor that has it.
        let new_placement = survivors
            .iter()
            .find_map(|&i| {
                nodes[i]
                    .status()
                    .placements
                    .get(&TEST_PARTITION)
                    .filter(|p| p.leader != dead_id)
                    .cloned()
            })
            .expect("the new placement is committed on a survivor");
        // (c) the successor is a SURVIVING in-sync replica (one of {1,2,3} minus the dead leader), and
        // the dead leader was dropped from the replica set (no data move — survivors already held the log).
        assert_ne!(new_placement.leader, dead_id, "(c) never the dead leader");
        assert!(
            ids.contains(&new_placement.leader),
            "(c) the successor is a known surviving replica"
        );
        assert!(
            !new_placement.replicas.contains(&dead_id),
            "(c) the dead leader is dropped from the replica set"
        );
        assert!(
            new_placement.replicas.contains(&new_placement.leader),
            "(c) the new leader is one of the surviving replicas"
        );
        // (d) the fence: the new epoch strictly exceeds the dead leader's (KIP-101). A returning old
        // leader carrying the old epoch is rejected by this higher committed epoch.
        assert!(
            new_placement.epoch > old_epoch,
            "(d) the new epoch ({}) is fenced strictly above the dead leader's ({old_epoch})",
            new_placement.epoch
        );

        // (e) the cluster RESUMES: the surviving quorum commits a NEW metadata entry under the new
        // metadata leader (proving consensus is live again after the failover). Propose on whichever
        // survivor is now leader and confirm both survivors apply it.
        let new_leader_i = *survivors
            .iter()
            .find(|&&i| nodes[i].status().is_leader)
            .expect("a surviving leader");
        let applied_before = nodes[new_leader_i].status().applied_index;
        nodes[new_leader_i]
            .propose_metadata(MetadataCommand::SetConfig {
                key: "post.failover".to_string(),
                value: "ok".to_string(),
            })
            .expect("propose post-failover");
        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || survivors
                .iter()
                .all(|&i| nodes[i].status().applied_index > applied_before)),
            "(e) the cluster resumes: a new metadata entry commits + applies on the surviving quorum"
        );

        for &i in &survivors {
            nodes[i].stop();
        }
    }

    /// The TIMEOUT path is deterministic too: with an injected SHORT deadline and a node whose
    /// heartbeats stop, the F1 detector fires WITHOUT the force-unreachable seam — proving the
    /// real production trigger (silence past the deadline) works, driven only by stopping a node (its
    /// heartbeats cease, the survivors' `last_heard` for it goes stale past the deadline). No manual
    /// reconcile; the auto path detects + promotes.
    #[test]
    fn the_liveness_timeout_alone_auto_fails_over_a_silent_leader() {
        // The deadline is HOST-SCALED (base 2 s, stretched by the measured host slowdown, like every
        // wait bound here) so the SURVIVORS' mutual heartbeats — themselves slowed proportionally under
        // CI load — always stay a small FRACTION of the deadline and a healthy survivor is NEVER falsely
        // suspected (the no-false-failover margin holds even on a starved runner). The KILLED node's
        // heartbeats cease ENTIRELY, so its silence grows without bound and crosses the deadline
        // regardless of scale. This is the one place a real-time interval is the trigger (it IS the
        // production silence path); the post-trigger convergence is polled with the host-scaled bound.
        let liveness = LivenessConfig {
            timeout: host_scaled(Duration::from_secs(2)),
            enabled: true,
        };
        let (_serial, mut nodes, ids, _dirs, leader_idx) = bring_up_placed_cluster(liveness);
        let dead_id = ids[leader_idx];
        let old_epoch = nodes[leader_idx]
            .status()
            .placements
            .get(&TEST_PARTITION)
            .expect("placement")
            .epoch;

        // KILL the leader — its heartbeats STOP. We do NOT force-unreachable; the survivors' detector
        // must trip purely on the silence-past-deadline timeout.
        nodes[leader_idx].stop();
        let survivors: Vec<usize> = (0..3).filter(|&i| i != leader_idx).collect();

        // The surviving quorum re-elects AND the timeout-driven F1+F2 path auto-detects + promotes.
        // The bound covers the (host-scaled) liveness deadline the dead node must first cross PLUS the
        // post-detection convergence, so it never races even on a starved runner.
        assert!(
            wait_until(host_scaled(Duration::from_secs(50)), || survivors.iter().any(
                |&i| {
                    let s = nodes[i].status();
                    s.departed_members.contains(&dead_id)
                        && s.placements
                            .get(&TEST_PARTITION)
                            .is_some_and(|p| p.leader != dead_id && p.epoch > old_epoch)
                }
            )),
            "the liveness TIMEOUT alone (silence past the deadline) auto-detects + auto-promotes a survivor"
        );

        for &i in &survivors {
            nodes[i].stop();
        }
    }

    /// NO FALSE FAILOVER (the hardest non-negotiable): a healthy cluster with a brief, sub-deadline
    /// hiccup NEVER auto-fails-over. With the DEFAULT (long) deadline, all three nodes stay up and
    /// heartbeat; over a window many times the heartbeat interval the detector suspects NOBODY, removes
    /// nobody, and promotes nobody — the placement is untouched, the leader unchanged.
    #[test]
    fn a_healthy_cluster_never_auto_fails_over() {
        // Host-scale the liveness deadline: on a contended CI runner the driver threads heartbeat more
        // slowly, so the deadline must scale by the SAME factor that slows the heartbeats to preserve the
        // deadline >> heartbeat ratio — otherwise a healthy-but-starved node would be falsely suspected
        // during/after bring-up (a CI scheduler artifact, not a product fault). The ratio — and thus the
        // no-false-failover property under test — is unchanged; only the absolute timing tracks the host.
        let (_serial, mut nodes, ids, _dirs, leader_idx) =
            bring_up_placed_cluster(LivenessConfig {
                timeout: host_scaled(DEFAULT_LIVENESS_TIMEOUT),
                enabled: true,
            });
        let leader_id = ids[leader_idx];
        let placement0 = nodes[leader_idx]
            .status()
            .placements
            .get(&TEST_PARTITION)
            .expect("placement")
            .clone();

        // Observe for a window many heartbeat intervals long but strictly SHORTER than the (host-scaled)
        // deadline, so a healthy heartbeating peer is NEVER suspected within it. Both the window and the
        // deadline host-scale, so the margin holds on a fast host (deadline 3 s ≈ 10x the ~300 ms
        // heartbeat) and on a slow/contended runner alike.
        let observe_until = Instant::now() + host_scaled(Duration::from_secs(2));
        while Instant::now() < observe_until {
            for n in &nodes {
                let s = n.status();
                assert!(
                    s.suspected_dead.is_empty(),
                    "no healthy peer is ever suspected dead: {:?}",
                    s.suspected_dead
                );
                assert!(
                    s.departed_members.is_empty(),
                    "no healthy peer ever departs: {:?}",
                    s.departed_members
                );
                assert!(
                    s.failover_proposed.is_empty(),
                    "no failover is ever proposed for a healthy cluster"
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // The placement is byte-for-byte unchanged: same leader, same replicas, same epoch — the
        // no-false-promotion / no-epoch-bump guarantee under a healthy cluster.
        for n in &nodes {
            if let Some(p) = n.status().placements.get(&TEST_PARTITION) {
                assert_eq!(
                    p.leader, leader_id,
                    "the leader is unchanged (no false failover)"
                );
                assert_eq!(p.epoch, placement0.epoch, "no spurious epoch bump");
                assert_eq!(
                    p.replicas, placement0.replicas,
                    "the replica set is unchanged"
                );
            }
        }
        // Every node still sees 3 voters (nobody was removed).
        assert!(
            nodes.iter().all(|n| n.status().voter_count == 3),
            "all 3 voters remain (no spurious removal)"
        );

        for n in &mut nodes {
            n.stop();
        }
    }

    /// THE #618b REGRESSION TEST — a LAGGING survivor is NEVER promoted (committed-data-loss is closed).
    ///
    /// Scenario (the realistic 3-node R3, `min_isr`=2 bug): a committed, client-acked record reached quorum
    /// on the leader + ONE follower only, so the THIRD survivor is BEHIND the committed HW. The leader
    /// dies. We drive the deterministic auto path and assert the auto path NEVER promotes the lagging
    /// node — EITHER it promotes the COMPLETE survivor (when that survivor is the new metadata leader,
    /// whose own frontier reaches the persisted committed-HW checkpoint and self-promotes) OR it FAILS
    /// CLOSED (no leader elected for the partition, because the new metadata leader is the lagging one and
    /// cannot prove itself complete). In BOTH outcomes NO committed record is lost: no surviving leader is
    /// ever missing a pre-death quorum-acked offset.
    ///
    /// Modeled deterministically (no real-time sleep): the persisted committed-HW checkpoint = 100 (the
    /// pre-death committed bar); the COMPLETE survivor's own frontier = 100; the LAGGING survivor's own
    /// frontier = 80 (it missed the last committed record). The lagging node can therefore never satisfy
    /// `own_frontier >= safe_bar`, so it can never self-promote — exactly the safety property.
    #[test]
    fn a_lagging_survivor_is_never_auto_promoted_and_no_committed_record_is_lost() {
        // Bring up the placed cluster with the persisted committed-HW checkpoint = 100 (the safe bar).
        let (_serial, mut nodes, ids, _dirs, leader_idx) =
            bring_up_placed_cluster(LivenessConfig::default());
        let dead_id = ids[leader_idx];
        let safe_bar = 100u64; // the persisted committed HW every promotion must clear.

        // The two survivors. Pick ONE to be the LAGGING node (behind the committed HW) and the other to
        // be the COMPLETE node (caught up). We model their REAL own-frontiers via the cross-plane seam:
        // the lagging node's own frontier is 80 (< the bar), the complete node's is 100 (== the bar).
        let survivors: Vec<usize> = (0..3).filter(|&i| i != leader_idx).collect();
        let lagging_i = survivors[0];
        let complete_i = survivors[1];
        let lagging_id = ids[lagging_i];
        let complete_id = ids[complete_i];
        // Re-install the providers to reflect the divergent frontiers (the bar persisted from setup
        // stays = 100; only each node's OWN frontier differs now).
        install_isr_with_own_frontier(&nodes[lagging_i], vec![1, 2, 3], safe_bar, 80);
        install_isr_with_own_frontier(&nodes[complete_i], vec![1, 2, 3], safe_bar, safe_bar);

        // KILL the leader and drive detection deterministically on the survivors.
        nodes[leader_idx].stop();
        for &i in &survivors {
            nodes[i].force_peer_unreachable(dead_id, true);
        }

        // A new metadata leader is elected among the survivors and the dead leader is removed (F1).
        assert!(
            wait_until(host_scaled(Duration::from_secs(25)), || survivors
                .iter()
                .any(|&i| {
                    let s = nodes[i].status();
                    s.departed_members.contains(&dead_id) && s.is_leader
                })),
            "a surviving metadata leader is elected and the dead leader is removed"
        );

        // Give the auto path a generous window to do WHATEVER it is going to do, then assert the two
        // safety properties hold throughout AND at the end. We poll the converged outcome.
        let observe_until = Instant::now() + host_scaled(Duration::from_secs(8));
        while Instant::now() < observe_until {
            for &i in &survivors {
                let s = nodes[i].status();
                // PROPERTY 1: the LAGGING node is NEVER the committed partition leader. This is the core
                // committed-data-loss guard — promoting it would lose offsets 80..100.
                if let Some(p) = s.placements.get(&TEST_PARTITION) {
                    assert_ne!(
                        p.leader, lagging_id,
                        "the lagging survivor must NEVER be auto-promoted (it is missing committed offsets 80..100)"
                    );
                    // PROPERTY 2 (no committed loss): any committed partition leader is either the dead
                    // leader (not yet failed over) or the COMPLETE survivor — never an incomplete node.
                    assert!(
                        p.leader == dead_id || p.leader == complete_id,
                        "a committed partition leader is only ever the (pre-failover) dead leader or the complete survivor, got {}",
                        p.leader
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // FINAL converged outcome: EITHER the complete survivor was promoted (it became the metadata
        // leader and self-promoted) OR the partition stayed leaderless under the dead leader (the new
        // metadata leader was the lagging one and FAILED CLOSED). Both are committed-safe.
        let promoted_complete = survivors.iter().any(|&i| {
            nodes[i]
                .status()
                .placements
                .get(&TEST_PARTITION)
                .is_some_and(|p| p.leader == complete_id)
        });
        let stayed_leaderless = survivors.iter().all(|&i| {
            nodes[i]
                .status()
                .placements
                .get(&TEST_PARTITION)
                .is_some_and(|p| p.leader == dead_id)
        });
        assert!(
            promoted_complete || stayed_leaderless,
            "the auto path either promoted the COMPLETE survivor or failed closed (leaderless) — never the lagging node"
        );
        // The lagging node is never promoted in EITHER outcome (re-assert at the converged state).
        for &i in &survivors {
            if let Some(p) = nodes[i].status().placements.get(&TEST_PARTITION) {
                assert_ne!(
                    p.leader, lagging_id,
                    "converged: the lagging node was never promoted"
                );
            }
        }

        for &i in &survivors {
            nodes[i].stop();
        }
    }

    /// FAIL-CLOSED, safety-over-availability (#618b): when the metadata leader's OWN frontier is BEHIND
    /// the persisted committed-HW checkpoint, it proposes NO promotion — the partition stays leaderless
    /// (recoverable) rather than risk losing committed data. This pins the safety-over-availability
    /// trade: a complete replica may exist REMOTELY, but the metadata leader cannot prove it (no ISR
    /// gossip), so it withholds. Deterministic: we force EVERY survivor's own frontier behind the bar, so
    /// whichever one wins the election cannot self-promote.
    #[test]
    fn the_metadata_leader_behind_the_committed_bar_proposes_no_promotion_fail_closed() {
        let (_serial, mut nodes, ids, _dirs, leader_idx) =
            bring_up_placed_cluster(LivenessConfig::default());
        let dead_id = ids[leader_idx];
        let safe_bar = 100u64;
        let survivors: Vec<usize> = (0..3).filter(|&i| i != leader_idx).collect();

        // BOTH survivors lag the persisted bar (own frontier 70 < 100) — model the case where the only
        // complete replica is the (now-dead) one, so no survivor can prove itself complete.
        for &i in &survivors {
            install_isr_with_own_frontier(&nodes[i], vec![1, 2, 3], safe_bar, 70);
        }

        nodes[leader_idx].stop();
        for &i in &survivors {
            nodes[i].force_peer_unreachable(dead_id, true);
        }

        // The dead leader IS detected + removed (F1 needs no completeness).
        assert!(
            wait_until(host_scaled(Duration::from_secs(25)), || survivors
                .iter()
                .any(|&i| nodes[i].status().departed_members.contains(&dead_id))),
            "the dead leader is auto-detected + removed"
        );

        // But NO promotion is ever proposed (fail-closed): no survivor can prove it holds the bar. The
        // partition stays led by the (departed) old leader; `failover_proposed` stays empty. Observe for
        // a generous window AFTER the removal committed.
        let check_until = Instant::now() + host_scaled(Duration::from_secs(6));
        while Instant::now() < check_until {
            for &i in &survivors {
                let s = nodes[i].status();
                assert!(
                    s.failover_proposed.is_empty(),
                    "fail-closed: NO promotion proposed when no survivor can prove it holds the committed bar"
                );
                if let Some(p) = s.placements.get(&TEST_PARTITION) {
                    assert_eq!(
                        p.leader, dead_id,
                        "fail-closed: the partition stays leaderless (still names the departed leader), never blind-promoted"
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        for &i in &survivors {
            nodes[i].stop();
        }
    }

    /// FAIL-CLOSED with NO data plane: a runtime with NO installed failover inputs (no data plane)
    /// detects a dead leader and removes it, but AUTO-PROMOTES NOTHING — it never promotes blind
    /// without the cross-plane ISR. The partition is left leaderless (its committed leader stays the
    /// departed node) rather than promoting an unvetted successor that could lose committed data.
    #[test]
    fn no_data_plane_inputs_means_no_blind_promotion_fail_closed() {
        let _serial = serial_guard();
        let ids = [1u64, 2, 3];
        let ports = free_ports(3);
        let peers = peer_map(&ids, &ports);
        let dirs: Vec<_> = ids
            .iter()
            .map(|_| tempfile::tempdir().expect("tempdir"))
            .collect();
        // DEFAULT (long) deadline: detection is driven by the deterministic `force_peer_unreachable`
        // seam below, so only the killed node is detected — no healthy peer is spuriously suspected.
        let liveness = LivenessConfig::default();
        let mut nodes: Vec<ClusterRuntime> = ids
            .iter()
            .enumerate()
            .map(|(i, &id)| {
                let fs = StdFs::new(dirs[i].path().to_path_buf());
                ClusterRuntime::start_with_liveness(
                    &ClusterConfig {
                        node_id: id,
                        peers: peers.clone(),
                    },
                    &fs,
                    SystemClock::new(),
                    LogConfig::new(64 * 1024).unwrap(),
                    liveness,
                )
                .expect("start node")
            })
            .collect();

        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || nodes
                .iter()
                .filter(|n| n.status().is_leader)
                .count()
                == 1),
            "leader elected"
        );
        let leader_idx = nodes.iter().position(|n| n.status().is_leader).unwrap();
        let leader_id = ids[leader_idx];
        let epoch = nodes[leader_idx].status().leader_epoch.max(1);
        nodes[leader_idx]
            .propose_metadata(MetadataCommand::PlacePartition {
                partition: TEST_PARTITION,
                replicas: vec![1, 2, 3],
                leader: leader_id,
                epoch,
            })
            .expect("propose placement");
        assert!(
            wait_until(host_scaled(Duration::from_secs(20)), || nodes.iter().all(
                |n| n
                    .status()
                    .placements
                    .get(&TEST_PARTITION)
                    .is_some_and(|p| p.leader == leader_id)
            )),
            "placement committed"
        );

        // NB: NO `install_healthy_isr` — the failover inputs are ABSENT (no data plane).
        nodes[leader_idx].stop();
        let survivors: Vec<usize> = (0..3).filter(|&i| i != leader_idx).collect();
        for &i in &survivors {
            nodes[i].force_peer_unreachable(leader_id, true);
        }

        // The dead leader IS auto-detected + removed (F1 doesn't need the data plane).
        assert!(
            wait_until(host_scaled(Duration::from_secs(25)), || survivors
                .iter()
                .any(|&i| nodes[i].status().departed_members.contains(&leader_id))),
            "F1 still removes the dead leader (detection needs no data plane)"
        );

        // But NO promotion is ever proposed (fail-closed): the committed placement's leader stays the
        // departed node. Observe for a generous window AFTER the removal committed.
        let check_until = Instant::now() + host_scaled(Duration::from_secs(4));
        while Instant::now() < check_until {
            for &i in &survivors {
                let s = nodes[i].status();
                assert!(
                    s.failover_proposed.is_empty(),
                    "fail-closed: NO promotion proposed without cross-plane ISR inputs"
                );
                if let Some(p) = s.placements.get(&TEST_PARTITION) {
                    assert_eq!(
                        p.leader, leader_id,
                        "fail-closed: the partition stays led by the departed node (leaderless), never blind-promoted"
                    );
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        for &i in &survivors {
            nodes[i].stop();
        }
    }
}

/// A tiny shim so the test module can name the broker's `SystemClock` without ironbus-server
/// depending on ironbus-cli. The cluster runtime is generic over any `Clock`; the broker uses
/// [`crate::clock::SystemClock`], so the tests use it directly via this re-export path.
#[cfg(all(test, unix))]
mod ironbus_server_test_clock {
    pub use crate::clock::SystemClock;
}
