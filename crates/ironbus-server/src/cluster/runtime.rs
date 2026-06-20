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

use std::collections::BTreeMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ironbus_core::clock::Clock;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::LogConfig;
use raft::eraftpb::Message;

use crate::cluster::metadata_group::{GroupError, MetadataRaftGroup};
use crate::cluster::state_machine::MetadataCommand;
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
}

/// A command for the driver to propose to the metadata group on behalf of the broker (or a test):
/// the driver is the only thread that may touch the `RawNode`, so a metadata write is sent to it
/// over a channel and proposed on the next cycle (it takes effect only if this node is the leader
/// and the entry commits + applies).
enum DriverCmd {
    /// Propose a metadata command (leader-only; ignored with a log line if not leader).
    Propose(MetadataCommand),
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
    /// The shutdown flag the runtime OWNS (separate from the broker's serve-loop flag so a caller
    /// can stop the cluster plane independently; serve flips both on a stop).
    shutdown: Arc<AtomicBool>,
    /// The latest status snapshot the driver publishes each cycle (leader / epoch / membership /
    /// applied index), read with [`status`](ClusterRuntime::status).
    status: Arc<Mutex<ClusterStatus>>,
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
        config.validate()?;
        let self_addr = config
            .self_addr()
            .ok_or_else(|| RuntimeError::Config("missing this node's own address".to_string()))?;

        // Open (or recover) the durable metadata group. This is the ONLY place a `metaraft/`
        // subdirectory is created, and it happens ONLY here in the runtime — never on the no-cluster
        // default path, which keeps that path byte-for-byte today's broker.
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

        // Spawn the driver (owns the group; drives tick/step/drive_ready and routes outbound).
        let shutdown_dr = Arc::clone(&shutdown);
        let registry_dr = Arc::clone(&registry);
        let status_dr = Arc::clone(&status);
        // Move `inbound_tx` (a keepalive sender) into the driver so the inbound channel never closes
        // while the driver runs, even if every reader has exited.
        let driver_handle = std::thread::Builder::new()
            .name("ib-cluster-driver".to_string())
            .spawn(move || {
                run_driver(
                    group,
                    inbound_rx,
                    inbound_tx,
                    outbound_tx,
                    cmd_rx,
                    registry_dr,
                    status_dr,
                    &shutdown_dr,
                );
            })
            .expect("spawn cluster driver thread");

        Ok(Self {
            shutdown,
            status,
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

/// The driver loop: OWNS the metadata group and is the only thread that touches the `RawNode`.
///
/// On a fixed cadence it (1) advances the election/heartbeat timer with `tick`, (2) drains every
/// inbound `Message` a reader delivered and feeds each to `step`, (3) runs `drive_ready` (which
/// persists + fsyncs before advancing, #659) and routes the outbound messages to each addressed
/// peer's outbound queue, and (4) refreshes the shared peer registry from the group's `ConfState`
/// so a committed membership change updates which peers a reader will accept. It blocks on the
/// inbound channel with a `TICK_INTERVAL` timeout, so it is responsive to inbound traffic yet never
/// busy-spins and re-checks shutdown at least every tick.
#[allow(clippy::too_many_arguments)]
// each input is a distinct concern (the group, the inbound /
// outbound / command channels, the shared registry + status,
// and the shutdown flag); a bundling struct would only move
// the noise. The driver is the one place they all meet.
#[allow(clippy::needless_pass_by_value)] // a thread entry point: it OWNS the group, channels, and
                                         // shared Arcs for the thread's whole lifetime (the
                                         // receivers are drained, the senders/Arcs held alive); a
                                         // borrow would fight the 'static spawn bound.
fn run_driver<F, C>(
    mut group: MetadataRaftGroup<F, C>,
    inbound_rx: Receiver<Message>,
    _inbound_keepalive: Sender<Message>,
    outbound_tx: BTreeMap<u64, PeerOutbound>,
    cmd_rx: Receiver<DriverCmd>,
    registry: Arc<Mutex<PeerRegistry>>,
    status: Arc<Mutex<ClusterStatus>>,
    shutdown: &AtomicBool,
) where
    F: Filesystem,
    C: Clock + Clone,
{
    // The membership view last published to the registry, so we only re-lock + rewrite it when the
    // committed `ConfState` actually changes (a committed membership change), not every cycle.
    let mut last_members: Vec<u64> = Vec::new();
    // The durable `ConfState` voter count, refreshed each cycle below and published as the status
    // `voter_count`. This is the cluster's AGREED voter set (the seeded-then-replicated raft
    // `ConfState`), not the state machine's apply-driven membership table — the latter is empty on a
    // freshly-formed group until a membership COMMAND is applied through it, whereas the `ConfState`
    // is the real quorum basis from open.
    let mut conf_voter_count: usize = 0;
    let node_id = group.node_id();

    while !shutdown.load(Ordering::Acquire) {
        // Advance the logical election/heartbeat timer once per cadence.
        group.tick();

        // Apply any pending metadata proposals from the broker/tests (leader-only; a non-leader
        // proposal is rejected by the core and logged, never panics).
        while let Ok(DriverCmd::Propose(cmd)) = cmd_rx.try_recv() {
            if let Err(e) = group.propose(&cmd) {
                tracing::debug!(error = %e, "cluster: metadata proposal rejected (not leader?)");
            }
        }

        // Wait up to one tick for an inbound peer message, then drain every other message already
        // queued (non-blocking) before driving ready, so a burst is consumed in one pass rather than
        // one per cadence. The wait keeps the loop responsive to traffic without busy-spinning.
        match inbound_rx.recv_timeout(TICK_INTERVAL) {
            Ok(msg) => {
                if let Err(e) = group.step(msg) {
                    // A step error for a message addressed to a node mid-membership-change is benign
                    // (it may no longer recognise the sender); drop it and continue.
                    tracing::debug!(error = %e, "cluster: dropped a peer message on step");
                }
                drain_inbound_nonblocking(&inbound_rx, &mut group);
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
            Ok(outbound) => route_outbound(outbound, &outbound_tx),
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
                if let Ok(mut reg) = registry.lock() {
                    *reg = PeerRegistry::from_members(cs.get_voters(), cs.get_learners());
                }
                last_members = members;
            }
        }

        // Publish the latest status snapshot for observers (status() / future admin endpoints).
        if let Ok(mut s) = status.lock() {
            s.node_id = node_id;
            s.is_leader = group.is_leader();
            s.leader_epoch = group.leader_epoch().get();
            s.voter_count = conf_voter_count;
            s.applied_index = group.state().applied_index();
        }
    }
}

/// Drain any inbound messages already queued, without blocking, feeding each to `step`. Called after
/// the first blocking receive so a burst of peer messages is consumed in one pass before driving
/// ready, rather than one per cadence.
fn drain_inbound_nonblocking<F, C>(rx: &Receiver<Message>, group: &mut MetadataRaftGroup<F, C>)
where
    F: Filesystem,
    C: Clock + Clone,
{
    loop {
        match rx.try_recv() {
            Ok(msg) => {
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

        // A leader is elected within a few seconds (election ~1 s at the 100 ms tick cadence; allow
        // generous head-room for thread scheduling + the loopback connect/backoff).
        let elected = wait_until(Duration::from_secs(20), || {
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
        // SetConfig entry commits and applies across the quorum.
        let committed = wait_until(Duration::from_secs(20), || {
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
            wait_until(Duration::from_secs(20), || nodes
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
            wait_until(Duration::from_secs(20), || nodes[..2]
                .iter()
                .filter(|n| n.status().is_leader)
                .count()
                == 1),
            "the 2 surviving nodes keep a quorum + a leader"
        );

        // Restart node id 3 over the SAME data dir; it recovers and rejoins.
        nodes[2] = start_node(&mk(3), dirs[2].path());
        assert!(
            wait_until(Duration::from_secs(20), || {
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
            wait_until(Duration::from_secs(10), || node.status().is_leader),
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
            wait_until(Duration::from_secs(20), || nodes
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
            wait_until(Duration::from_secs(10), || nodes
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
            wait_until(Duration::from_secs(10), || configured
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
}

/// A tiny shim so the test module can name the broker's `SystemClock` without ironbus-server
/// depending on ironbus-cli. The cluster runtime is generic over any `Clock`; the broker uses
/// [`crate::clock::SystemClock`], so the tests use it directly via this re-export path.
#[cfg(all(test, unix))]
mod ironbus_server_test_clock {
    pub use crate::clock::SystemClock;
}
