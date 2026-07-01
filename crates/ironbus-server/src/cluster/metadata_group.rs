// SPDX-License-Identifier: MIT OR Apache-2.0
//! The embedded metadata Raft group (V2-C1, #578).
//!
//! [`MetadataRaftGroup`] wraps a single `raft::RawNode` — the production tikv/raft-rs core
//! — that replicates the cluster metadata log for a 1, 3, or 5 voter group, and applies
//! committed entries into a [`MetadataStateMachine`]. raft-rs is a SYNCHRONOUS, caller-
//! driven state machine (`tick` / `step` / `ready` / `advance`); this type owns that loop
//! so it composes with IronBus's existing single-writer-actor cadence rather than an async
//! runtime. There is no IO and no async here — the group is advanced by the caller.
//!
//! ## Scope (C1-I2: durable storage)
//!
//! As of C1-I2 (#580) the group's storage is the DURABLE
//! [`MetadataLogStorage`](crate::cluster::metadata_storage::MetadataLogStorage) over an IronBus
//! CRC-framed log, NOT the in-memory `MemStorage` C1-I1 (#578) used. The `Ready` persist step now
//! writes raft entries + the `HardState`/`ConfState` checkpoint to that log and FSYNCS before the
//! group advances (the metadata analogue of IronBus's I2 ack-after-fsync, the foundation for C3's
//! quorum-fsync), and the metadata log inherits the storage crate's I1–I4 bounded/reported recovery.
//!
//! Still deliberately deferred:
//!
//! * there is no peer transport, no membership change, no leader-epoch exposure, and no
//!   wiring into the append actor (those are **C1-I3 / C1-I4** and later);
//! * crucially, this module is NOT yet referenced by the running broker, so adding it does
//!   not change the single-node binary's behavior or on-disk layout.

use ironbus_core::clock::Clock;
use ironbus_core::leader_lease::{EpochObservation, LeaderEpoch, LeaderLease, LeadershipTracker};
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::LogConfig;
use protobuf::Message as _;
use raft::eraftpb::{ConfChange, ConfChangeV2, ConfState, Entry, EntryType, Message};
use raft::{Config, RawNode, StateRole, Storage as _};
use raft_proto::ConfChangeI;
use slog::{o, Discard, Logger};

use crate::cluster::membership::{validate_change, LearnerCatchup, MembershipChange, PeerIdError};
use crate::cluster::metadata_storage::{MetadataLogStorage, MetadataStorageError};
use crate::cluster::state_machine::{DecodeError, MetadataCommand, MetadataStateMachine};

/// The leadership-lease window the metadata group grants, in monotonic nanoseconds.
///
/// Derived from the I6 monotonic clock (never the wall clock). It must comfortably exceed the
/// election window (`election_tick` heartbeats) so a stable leader renews its lease well before
/// it lapses, yet stay short enough to bound the stale-leader window. We use the core default
/// (10 s) expressed in nanoseconds.
const LEADER_LEASE_NANOS: u64 = LeaderLease::DEFAULT_LEASE_MS * 1_000_000;

/// Errors constructing or driving the metadata group.
#[derive(Debug)]
pub enum GroupError {
    /// The voter set was not a supported size (must be 1, 3, or 5).
    UnsupportedVoterCount(usize),
    /// `node_id` was not one of the configured voters.
    SelfNotAVoter { node_id: u64 },
    /// The underlying raft-rs core returned an error.
    Raft(raft::Error),
    /// A committed entry's bytes did not decode to a metadata command.
    Decode(DecodeError),
    /// The durable metadata storage (open / persist / fsync / recover) returned an error.
    Storage(MetadataStorageError),
    /// A proposed membership change failed peer-id validation (the #6403-class rejection):
    /// a mangled / duplicate / phantom peer was refused before it could enter the metadata log.
    PeerId(PeerIdError),
}

impl core::fmt::Display for GroupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GroupError::UnsupportedVoterCount(n) => {
                write!(
                    f,
                    "unsupported metadata voter count {n} (must be 1, 3, or 5)"
                )
            }
            GroupError::SelfNotAVoter { node_id } => {
                write!(f, "node id {node_id} is not in the configured voter set")
            }
            GroupError::Raft(e) => write!(f, "raft error: {e}"),
            GroupError::Decode(e) => write!(f, "metadata command decode error: {e}"),
            GroupError::Storage(e) => write!(f, "metadata storage error: {e}"),
            GroupError::PeerId(e) => write!(f, "membership peer-id validation error: {e}"),
        }
    }
}

impl std::error::Error for GroupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GroupError::Raft(e) => Some(e),
            GroupError::Decode(e) => Some(e),
            GroupError::Storage(e) => Some(e),
            GroupError::PeerId(e) => Some(e),
            _ => None,
        }
    }
}

impl From<raft::Error> for GroupError {
    fn from(e: raft::Error) -> Self {
        GroupError::Raft(e)
    }
}

impl From<DecodeError> for GroupError {
    fn from(e: DecodeError) -> Self {
        GroupError::Decode(e)
    }
}

impl From<MetadataStorageError> for GroupError {
    fn from(e: MetadataStorageError) -> Self {
        GroupError::Storage(e)
    }
}

impl From<PeerIdError> for GroupError {
    fn from(e: PeerIdError) -> Self {
        GroupError::PeerId(e)
    }
}

/// The supported metadata group sizes. Odd sizes only, so a single partition cannot split
/// the vote; capped at 5 (the design's metadata group is small by construction — one group
/// for the cluster, not per-asset).
const SUPPORTED_VOTER_COUNTS: [usize; 3] = [1, 3, 5];

/// An embedded metadata Raft group: a `RawNode` over the durable
/// [`MetadataLogStorage`] plus the applied [`MetadataStateMachine`]. Synchronous and
/// caller-driven. Generic over the storage [`Filesystem`] (`F`) and [`Clock`] (`C`) seams,
/// exactly like the rest of the storage engine (`StdFs` in production, `InMemoryFs` in the
/// deterministic simulation).
pub struct MetadataRaftGroup<F: Filesystem, C: Clock> {
    node: RawNode<MetadataLogStorage<F, C>>,
    state: MetadataStateMachine,
    /// The monotonic-clock seam (I6), used to time the leadership lease. The SAME logical clock
    /// the storage was opened with; ordering never consults the wall clock.
    clock: C,
    /// The cluster leader epoch + the local leadership lease, advanced from the raft term and the
    /// monotonic clock on every ready cycle. The epoch is the cluster-wide fencing token (C1-I3).
    leadership: LeadershipTracker,
    /// #872 FAIL-STOP LATCH: set true the first time [`Self::drive_ready`] fails AFTER it has taken
    /// the raft-rs `Ready` (a persist / fsync error). Such a failure leaves the `Ready` UN-ADVANCED
    /// — a raft-rs advance-after-ready contract violation — and, for a metadata-log fsync error, the
    /// log FREEZES its writer read-only (every later append/sync then also fails), so the node can
    /// never make safe Raft progress again. Rather than log-and-continue into a SILENT DEAD VOTER
    /// (re-taking a never-advanced `Ready` every tick, re-applying the same committed entries, and
    /// dropping outbound heartbeats/votes while still advertising as a healthy voter), we FAIL-STOP
    /// this node's Raft role: once latched, [`Self::drive_ready`] NEVER re-enters the `Ready` path,
    /// [`Self::tick`]/[`Self::step`] become no-ops (stop ticking), and [`Self::is_leader`] /
    /// [`Self::can_act_as_leader`] report false (step down). The condition is unrecoverable in-process
    /// (the frozen writer) — the node must be repaired/replaced — so the latch is deliberately sticky.
    health_failed: bool,
}

impl<F: Filesystem, C: Clock + Clone> MetadataRaftGroup<F, C> {
    /// Construct a metadata group for `node_id` over the `voters` set, persisting to a durable
    /// metadata log rooted in the `metaraft/` subdirectory of `parent_fs`.
    ///
    /// `voters` must be one of the supported sizes (1, 3, or 5) and must contain `node_id`.
    /// The storage is opened (recovering any prior durable state, or creating fresh and
    /// seeding the voter `ConfState`); on a recovered group the persisted `HardState` +
    /// `ConfState` win, so a restart resumes where it left off. No logger is attached
    /// (default-logger is off): raft-rs logs are discarded for now; bridging `slog` to
    /// `tracing` is deferred (C1-I3+).
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::UnsupportedVoterCount`] for a bad size,
    /// [`GroupError::SelfNotAVoter`] if `node_id` is not a voter, [`GroupError::Storage`] if
    /// the durable metadata log cannot be opened or recovered, or [`GroupError::Raft`] if the
    /// raft-rs config fails to validate.
    pub fn open(
        node_id: u64,
        voters: &[u64],
        parent_fs: &F,
        clock: C,
        config: LogConfig,
    ) -> Result<Self, GroupError> {
        let n = voters.len();
        if !SUPPORTED_VOTER_COUNTS.contains(&n) {
            return Err(GroupError::UnsupportedVoterCount(n));
        }
        if !voters.contains(&node_id) {
            return Err(GroupError::SelfNotAVoter { node_id });
        }
        Self::open_inner(node_id, voters, parent_fs, clock, config)
    }

    /// Open (or recover) a metadata group for a node JOINING an existing cluster as a NON-VOTING
    /// LEARNER (C5-I2, #617). Unlike [`Self::open`], `node_id` is NOT itself in the seeded voter set:
    /// the learner seeds the EXISTING voters (`existing_voters`, a supported 1/3/5 size) as its
    /// initial `ConfState` WITHOUT including itself, so it knows the cluster it follows but is not a
    /// member of it. It then learns its OWN role (learner, then voter) purely by REPLICATION, once the
    /// metadata leader's committed
    /// [`MembershipChange::add_learner`](crate::cluster::membership::MembershipChange::add_learner)
    /// (then `promote_learner`) for it reaches this node. The learner back-fills the committed
    /// metadata log by replication exactly like a follower — non-voting, so it never counts toward
    /// quorum while it catches up. It is promoted to a voter only ONCE CAUGHT UP (the leader's #617
    /// promotion gate), via a committed joint-consensus change.
    ///
    /// Seeding the EXISTING voters (rather than an empty set) is what lets the learner apply the
    /// committed membership DELTAS correctly without a snapshot: the base membership is the seed, and
    /// the `add_learner`/`promote_learner` conf changes that arrive over the log fold onto it. (An
    /// empty seed would mis-apply the deltas — it would never learn the base `[voters]`.) Snapshot
    /// transfer for a compacted log is a follow-on (it pairs with metadata-log compaction, not yet
    /// implemented; today the full committed log is replicated to the learner).
    ///
    /// On a RECOVERED group the persisted `ConfState` wins (a restarted learner resumes with its
    /// durable role), exactly as for a voter — the seed is only used for a brand-new join.
    ///
    /// # Errors
    ///
    /// [`GroupError::UnsupportedVoterCount`] if `existing_voters` is not a supported size,
    /// [`GroupError::Storage`] if the durable metadata log cannot be opened / recovered, or
    /// [`GroupError::Raft`] if the raft-rs config fails to validate.
    pub fn open_as_learner(
        node_id: u64,
        existing_voters: &[u64],
        parent_fs: &F,
        clock: C,
        config: LogConfig,
    ) -> Result<Self, GroupError> {
        let n = existing_voters.len();
        if !SUPPORTED_VOTER_COUNTS.contains(&n) {
            return Err(GroupError::UnsupportedVoterCount(n));
        }
        // The learner seeds the EXISTING voters as its initial ConfState but is NOT itself in it (it
        // follows that quorum as a non-member until the leader's committed conf-change adds it).
        Self::open_inner(node_id, existing_voters, parent_fs, clock, config)
    }

    /// The shared open path for a voter ([`Self::open`]) or a joining learner
    /// ([`Self::open_as_learner`]): `seed_voters` is the voter `ConfState` to seed for a BRAND-NEW
    /// group (the full voter set for a seeded voter, or EMPTY for a joining learner); a recovered
    /// group always keeps its persisted membership and ignores the seed.
    fn open_inner(
        node_id: u64,
        seed_voters: &[u64],
        parent_fs: &F,
        clock: C,
        config: LogConfig,
    ) -> Result<Self, GroupError> {
        let raft_config = Config {
            id: node_id,
            // Standard etcd-style ratio (heartbeat every tick window, election ~10x).
            election_tick: 10,
            heartbeat_tick: 3,
            ..Default::default()
        };
        raft_config.validate()?;

        // Open (or recover) the durable metadata log, seeding the voter ConfState for a fresh
        // group; the persisted membership wins on a recovered one. Keep a clone of the clock for
        // the leadership lease so the group times leases off the SAME monotonic seam (I6) the
        // storage uses; the clock is moved into storage and re-read here only for monotonic time.
        let storage = MetadataLogStorage::open(parent_fs, clock.clone(), config, seed_voters)?;
        // default-logger is disabled; discard raft-rs's own slog output.
        let logger = Logger::root(Discard, o!());
        let node = RawNode::new(&raft_config, storage, &logger)?;

        // Seed the cluster epoch from the recovered durable term (the metadata log's HardState),
        // so a restarted node never regresses the epoch (#659 durability). No lease is granted at
        // open: a recovered node holds NO leadership lease until it re-wins leadership and grants a
        // fresh one, so it can never resume acting as a stale leader across a restart.
        let mut leadership = LeadershipTracker::new(LEADER_LEASE_NANOS);
        let recovered_term = node.store().initial_state()?.hard_state.term;
        if recovered_term > 0 {
            // Observe as a non-leader so the epoch advances to the durable term without granting
            // a lease (the node must re-campaign to lead again).
            leadership.observe(recovered_term, false, clock.now_monotonic_nanos());
        }

        // RESTORE the application state machine from the durable SNAPSHOT (#660), if one was
        // recovered: the snapshot is the committed metadata cut at its index, and the retained log
        // TAIL above it folds on top through the normal ready/apply cycle the caller drives next.
        // So a node restarting from {snapshot + tail} re-derives the EXACT committed state a full
        // log replay would (#660 non-negotiable 1). A group with no snapshot starts with a fresh SM
        // and recovers entirely from the log, exactly as before.
        let state = match node.store().snapshot_state_bytes() {
            Some(bytes) if !bytes.is_empty() => {
                MetadataStateMachine::restore_from_snapshot(&bytes)?
            }
            _ => MetadataStateMachine::new(),
        };

        Ok(Self {
            node,
            state,
            clock,
            leadership,
            health_failed: false,
        })
    }

    /// The node id of this group member.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node.raft.id
    }

    /// True if this node currently believes itself the leader.
    ///
    /// A FAIL-STOPPED node ([`Self::is_health_failed`]) always reports false here: on a metadata-log
    /// persist/fsync failure it has stepped down and stopped ticking (#872), so it must never be
    /// observed as a healthy leader even if the (now-frozen) raft core last held the leader role.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        !self.health_failed && self.node.raft.state == StateRole::Leader
    }

    /// True once this node's metadata-Raft role has FAIL-STOPPED (#872): a [`Self::drive_ready`]
    /// persist/fsync failure left the raft-rs `Ready` un-advanced and (for an fsync error) froze the
    /// metadata log's writer, so the node can never make safe Raft progress again. A health-failed
    /// node has stepped down, stopped ticking, and drops peer messages — it is the LOUD signal that
    /// replaces the old silent-dead-voter wedge. Sticky: once set it never clears in-process.
    #[must_use]
    pub fn is_health_failed(&self) -> bool {
        self.health_failed
    }

    /// The metadata log's COMMITTED high-watermark (the raft committed index): every entry at or
    /// below it is committed across a quorum. This is the bar a joining LEARNER must DURABLY hold
    /// before it may be promoted to a voter (#617) — the metadata-plane committed frontier, read
    /// directly off the core (no wall clock, no IO).
    #[must_use]
    pub fn committed_index(&self) -> u64 {
        self.node.raft.raft_log.committed
    }

    /// The committed-frontier catch-up evidence for a LEARNER `node`, as the metadata LEADER sees it
    /// (#617). On the leader, raft-rs tracks each peer's durably-acked log index in its progress set;
    /// `matched` is that index for `node` (the prefix the learner is PROVEN to durably hold), and
    /// `committed` is this leader's committed high-watermark. The leader compares them
    /// ([`LearnerCatchup::is_caught_up`]) to decide whether the learner may be promoted.
    ///
    /// Returns `None` when this node is NOT the metadata leader (only the leader maintains peer
    /// progress) or when `node` is not a tracked peer (a phantom learner the core has never seen) —
    /// both cases FAIL CLOSED at the call site (no progress evidence ⇒ no promotion). A learner that
    /// is tracked but has acked nothing reads `matched == 0`, which is below any real committed bar,
    /// so it is correctly not-yet-caught-up.
    #[must_use]
    pub fn learner_catchup(&self, node: u64) -> Option<LearnerCatchup> {
        if self.node.raft.state != StateRole::Leader {
            return None;
        }
        let matched = self.node.raft.prs().get(node)?.matched;
        Some(LearnerCatchup {
            node,
            matched,
            committed: self.committed_index(),
        })
    }

    /// True if the group has a pending `Ready` to drain (work the caller's transport should pump
    /// with [`Self::drive_ready`]). A driver loops [`Self::tick`] + [`Self::drive_ready`] until this
    /// is false to reach a fixed point. (The peer transport, #667, uses this to know when a node has
    /// nothing more to say.)
    #[must_use]
    pub fn has_pending_ready(&self) -> bool {
        self.node.has_ready()
    }

    /// The current Raft term (the raw consensus term). Prefer [`Self::leader_epoch`] as the
    /// monotonic cluster fencing token: the term raw off the raft core can briefly read lower
    /// than the highest epoch this group has observed mid-transition, whereas the epoch never
    /// regresses (C1-I3).
    #[must_use]
    pub fn term(&self) -> u64 {
        self.node.raft.term
    }

    /// The cluster-wide monotonic **leader epoch** — the Raft term surfaced as a fencing token
    /// (C1-I3). It advances strictly on each leadership change and NEVER regresses; Election
    /// Safety gives at most one leader per epoch, so an old-epoch leader is fenced by a
    /// newer-epoch one. Later issues (C2 replication, C4 divergence) fence with this so a stale
    /// leader cannot commit. Durable across a restart (seeded from the metadata log's term, #659).
    #[must_use]
    pub fn leader_epoch(&self) -> LeaderEpoch {
        self.leadership.epoch()
    }

    /// The local leadership lease, if this node currently holds one (it is the leader and its
    /// monotonic-clock lease has not lapsed). `None` on a follower, or once a stale leader's
    /// lease has expired.
    #[must_use]
    pub fn leader_lease(&self) -> Option<LeaderLease> {
        self.leadership.lease()
    }

    /// Whether this node may ACT as leader **right now** (at the current monotonic time): it
    /// holds a still-valid lease at the current epoch. Once the lease lapses on the monotonic
    /// clock this is false even if the raft core still believes it is leader — the stale-leader
    /// fence that makes safe local leader reads possible later (C6). Reads the I6 monotonic
    /// clock, never the wall clock.
    #[must_use]
    pub fn can_act_as_leader(&self) -> bool {
        // A fail-stopped node (#872) has stepped down: it may never act as leader regardless of any
        // still-valid lease the (now-frozen) core last held.
        !self.health_failed
            && self
                .leadership
                .can_act_as_leader(self.clock.now_monotonic_nanos())
    }

    /// Whether a write/commit stamped with `epoch` is FENCED right now: its epoch is below the
    /// current cluster epoch, or this node does not hold a valid lease under it. The fencing
    /// predicate C2/C4 call before letting a (possibly stale) leader commit.
    #[must_use]
    pub fn fences(&self, epoch: LeaderEpoch) -> bool {
        self.leadership
            .fences(epoch, self.clock.now_monotonic_nanos())
    }

    /// The applied view of the replicated control plane.
    #[must_use]
    pub fn state(&self) -> &MetadataStateMachine {
        &self.state
    }

    /// Fold the raft core's current `(term, is_leader)` into the leadership tracker at the
    /// current monotonic time: advance the epoch monotonically and (re)grant / drop the local
    /// lease. Called after every state-changing step (tick, ready) so the epoch and lease track
    /// leadership without the caller reaching into raft-rs. Returns the epoch observation.
    fn refresh_leadership(&mut self) -> EpochObservation {
        let term = self.node.raft.term;
        let is_leader = self.node.raft.state == StateRole::Leader;
        let now = self.clock.now_monotonic_nanos();
        self.leadership.observe(term, is_leader, now)
    }

    /// Drive the election timer by one tick. Returns true if the tick produced new work
    /// (a `Ready` to drain). At n=1 a single tick window elapsing makes the lone voter
    /// elect itself. The leadership lease is refreshed off the monotonic clock so a leader
    /// renews (and a stale leader's lapsed lease is observed) on the heartbeat cadence.
    pub fn tick(&mut self) -> bool {
        if self.health_failed {
            // #872 FAIL-STOP: a fail-stopped node STOPS TICKING — it drives no more elections or
            // heartbeats, so it cannot campaign or masquerade as a live leader. No new work.
            return false;
        }
        let work = self.node.tick();
        self.refresh_leadership();
        work
    }

    /// Campaign to become leader immediately (used at n=1 / in tests to avoid waiting out
    /// the election timer).
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::Raft`] if the core rejects the campaign.
    pub fn campaign(&mut self) -> Result<(), GroupError> {
        self.node.campaign()?;
        self.refresh_leadership();
        Ok(())
    }

    /// Feed a peer message into the core (the `step` half of the loop). At n=1 there are no
    /// peers; this is the seam C1-I3's transport will drive.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::Raft`] if the core rejects the message.
    pub fn step(&mut self, msg: Message) -> Result<(), GroupError> {
        if self.health_failed {
            // #872 FAIL-STOP: a fail-stopped node touches the frozen core no further — drop the peer
            // message (benignly, like a message to a node mid-membership-change). It votes for no one
            // and replicates nothing.
            return Ok(());
        }
        self.node.step(msg)?;
        self.refresh_leadership();
        Ok(())
    }

    /// Propose one metadata command to the group (leader only). The command is encoded and
    /// appended to the Raft log; it takes effect when the resulting entry commits and is
    /// applied (drive [`Self::drive_ready`] after proposing).
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::Raft`] if the core rejects the proposal (e.g. not leader).
    pub fn propose(&mut self, cmd: &MetadataCommand) -> Result<(), GroupError> {
        self.node.propose(vec![], cmd.encode())?;
        Ok(())
    }

    /// The current durable configuration state (the voter / learner membership), as recovered /
    /// maintained by the metadata log storage. This is the membership a [`MembershipChange`] is
    /// validated against, and it survives a restart (the persisted `ConfState`, #659).
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::Raft`] if the storage's `initial_state` read fails.
    pub fn conf_state(&self) -> Result<ConfState, GroupError> {
        Ok(self.node.store().initial_state()?.conf_state)
    }

    /// Propose a joint-consensus MEMBERSHIP CHANGE (leader only): add / remove voters, add a
    /// learner, or promote a learner to a voter. The change is **peer-id-validated first** (the
    /// #6403 fix) against the current durable `ConfState`; only if every named peer id is
    /// well-formed and consistent is it proposed, as a raft-rs `ConfChangeV2`, through the
    /// metadata raft log. It takes effect when the resulting conf-change entry commits and is
    /// applied (drive [`Self::drive_ready`] after proposing).
    ///
    /// A change touching more than one voter goes through raft-rs **joint consensus** — the
    /// configuration is briefly *joint*, requiring a majority of BOTH the old and new voter
    /// sets, so the old and new majorities always overlap (Raft §6) and the change can never
    /// split the cluster. A lone single change uses the simpler single-server protocol, which is
    /// itself safe (one voter changed at a time). The conf change is proposed through the durable
    /// log, so it is replicated and committed exactly like a normal entry.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::PeerId`] if the change names a mangled (id 0) / duplicate / phantom
    /// peer or would remove the last voter (validation REFUSES it before it can be proposed);
    /// [`GroupError::Raft`] if the core rejects the proposal (e.g. this node is not the leader,
    /// or a conf change is already pending); or [`GroupError::Storage`] if reading the current
    /// `ConfState` fails.
    pub fn propose_membership_change(
        &mut self,
        change: &MembershipChange,
    ) -> Result<(), GroupError> {
        // THE #6403 FIX: validate the proposed peer identities against the CURRENT membership
        // before anything enters the log. A mangled / duplicate / phantom peer is rejected here,
        // so a bad peer-id can never be replicated and can never freeze quorum.
        let conf_state = self.conf_state()?;
        validate_change(change, &conf_state)?;

        let cc = change.to_conf_change_v2();
        self.node.propose_conf_change(vec![], cc)?;
        Ok(())
    }

    /// Convenience: propose adding `node` as a NON-VOTING learner (it back-fills the log but
    /// never counts toward quorum until promoted). The over-the-wire catch-up is peer transport
    /// (#667); this proposes the learner ROLE.
    ///
    /// # Errors
    ///
    /// As [`Self::propose_membership_change`].
    pub fn add_learner(&mut self, node: u64) -> Result<(), GroupError> {
        self.propose_membership_change(&MembershipChange::new().add_learner(node))
    }

    /// Convenience: propose promoting an existing learner `node` to a voter (the catch-up →
    /// promote path).
    ///
    /// # Errors
    ///
    /// As [`Self::propose_membership_change`].
    pub fn promote_learner(&mut self, node: u64) -> Result<(), GroupError> {
        self.propose_membership_change(&MembershipChange::new().promote_learner(node))
    }

    /// Run one full `ready` cycle: persist the `Ready` (entries, hard state, snapshot)
    /// DURABLY to the IronBus metadata log and FSYNC it, hand outbound messages to the
    /// (currently absent) transport, then `advance` and apply the committed entries into the
    /// state machine.
    ///
    /// Returns the outbound messages the caller's transport should send (empty at n=1).
    ///
    /// This is the persist-before-advance contract raft-rs requires, made DURABLE for C1-I2:
    /// the persist step (entries + the `HardState` checkpoint) is written to the metadata log
    /// and the log is `sync`ed (fdatasync) BEFORE the group `advance`s. So an entry/hard-state
    /// the group acts on is durable first — the metadata analogue of IronBus's I2
    /// ack-after-fsync, and the foundation for C3's quorum-fsync.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::Storage`] on a durable append / fsync failure, [`GroupError::Raft`]
    /// on a core error, or [`GroupError::Decode`] if a committed entry's bytes are not a valid
    /// metadata command.
    ///
    /// # Fail-stop (#872)
    ///
    /// ANY error returned AFTER the `Ready` has been taken (`self.node.ready()`) leaves that `Ready`
    /// UN-ADVANCED — a raft-rs advance-after-ready contract violation — and, for a metadata-log fsync
    /// error, freezes the log's writer permanently. Re-entering with that same never-advanced `Ready`
    /// every tick would re-apply the same committed entries and drop the cycle's outbound
    /// heartbeats/votes while the node still advertised as a healthy voter (a silent dead voter). So
    /// such a failure LATCHES [`Self::is_health_failed`]: the node FAIL-STOPS its Raft role (steps
    /// down, stops ticking) and this method NEVER re-enters the `Ready` path again — every later call
    /// returns `Ok(empty)` without touching the frozen core. The caller (the driver loop) surfaces the
    /// latched failure as a loud health-failed status.
    pub fn drive_ready(&mut self) -> Result<Vec<Message>, GroupError> {
        // #872: a fail-stopped node NEVER takes another `Ready`. Taking one would re-apply the same
        // committed entries (the last cycle's un-advanced `Ready` is still pending) and accumulate more
        // un-advanced state against the frozen writer. Report no outbound work and make no progress.
        if self.health_failed || !self.node.has_ready() {
            return Ok(Vec::new());
        }
        // Any error from here — AFTER `ready()` is taken below — leaves the `Ready` un-advanced, so
        // LATCH the fail-stop before propagating it. From now on the guard above short-circuits.
        match self.drive_ready_inner() {
            Ok(outbound) => Ok(outbound),
            Err(e) => {
                self.health_failed = true;
                Err(e)
            }
        }
    }

    /// The fallible body of one `Ready` cycle (see [`Self::drive_ready`] for the full contract). Split
    /// out so [`Self::drive_ready`] can LATCH the #872 fail-stop on ANY error the moment the `Ready`
    /// has been taken (an un-advanced `Ready` is unrecoverable), rather than log-and-continue.
    fn drive_ready_inner(&mut self) -> Result<Vec<Message>, GroupError> {
        let mut ready = self.node.ready();

        // 1. Outbound messages to peers (none at n=1) — collected for the caller.
        let mut outbound = ready.take_messages();

        // 2. APPLY A RECEIVED SNAPSHOT if present (#660 snapshot-based catch-up): a far-behind
        //    follower/learner that raft-rs decided to catch up via snapshot transfer gets the
        //    leader's point-in-time snapshot here. We DURABLY persist it (fsync) and install it into
        //    storage (clearing the log prefix it subsumes), then RESTORE the application state
        //    machine from the snapshot's DATA bytes. The replicated log TAIL above the snapshot then
        //    arrives as normal committed entries (steps 3/8) and folds on top — no gap, no dup, no
        //    replay of pre-snapshot entries.
        if !ready.snapshot().is_empty() {
            let snapshot = ready.snapshot().clone();
            self.install_snapshot(&snapshot)?;
        }

        // 3. Apply committed entries that came with this Ready (after a snapshot, or once
        //    already-persisted entries commit).
        self.apply_committed(ready.take_committed_entries())?;

        // 4. Persist newly-appended (uncommitted) entries DURABLY (no fsync yet — one barrier
        //    per Ready below). A leader-change suffix rewrite is handled by the storage's
        //    append: the conflicting tail is superseded and recovery replays the last writer.
        if !ready.entries().is_empty() {
            self.node.mut_store().append(ready.entries())?;
        }

        // 5. Persist the hard state (term / vote / commit) checkpoint if it changed.
        if let Some(hs) = ready.hs() {
            self.node.mut_store().set_hard_state(hs)?;
        }

        // 6. THE DURABILITY BARRIER: fdatasync the metadata log so every record appended in
        //    steps 4–5 is durable BEFORE the group advances/acks. Persist-before-advance.
        self.node.mut_store().sync()?;

        // 7. Persisted messages (for async-append flows) — also handed to the transport.
        outbound.extend(ready.take_persisted_messages());

        // 8. Advance the core; the LightReady carries entries that committed as a result, plus
        //    a possibly-updated commit index. The new commit index is folded into the durable
        //    hard state (and fsynced) so a recovered group never replays past a committed-and-
        //    acted-on index.
        let mut light = self.node.advance(ready);
        if let Some(commit) = light.commit_index() {
            let mut hs = self.node.store().initial_state()?.hard_state;
            hs.commit = commit;
            self.node.mut_store().set_hard_state(&hs)?;
            self.node.mut_store().sync()?;
        }
        outbound.extend(light.take_messages());
        self.apply_committed(light.take_committed_entries())?;

        // 9. Advance the core's APPLIED index now that every committed entry from this cycle has
        //    been applied to our state machine. This is the apply half of the raft-rs contract
        //    (`advance` only advances the APPEND position; `advance_apply` advances the APPLIED
        //    position). It is load-bearing for JOINT CONSENSUS (C1-I4): when the enter-joint
        //    conf change is marked applied, the leader auto-appends the empty leave-joint conf
        //    change, so the cluster transitions OUT of the joint configuration. Without this the
        //    config would be stuck joint forever (the old + new majorities never collapse to the
        //    new one). The auto-appended leave-joint entry surfaces as new ready work and is
        //    persisted / committed / applied on the next cycle.
        self.node.advance_apply();

        // Fold the (possibly-changed) term / leadership into the epoch + lease: an election that
        // committed this cycle advances the epoch and grants the new leader its monotonic-clock
        // lease; a step-down drops it. The epoch is durable (it is the persisted term) and the
        // lease is timed off the I6 monotonic clock — never the wall clock.
        self.refresh_leadership();

        Ok(outbound)
    }

    /// Install a snapshot RECEIVED from the leader (#660): durably persist it + install it into the
    /// storage (clearing the subsumed log prefix), then RESTORE the application state machine from
    /// the snapshot's DATA. A STALE snapshot (below our durable first index) is ignored — we already
    /// hold that state and a newer tail, so re-installing would regress committed state.
    ///
    /// The state machine is restored from the snapshot's bytes ONLY when the snapshot actually
    /// installs (it advances us); the membership view is also refreshed from the installed
    /// `ConfState` so the SM's voter/learner table tracks the snapshot's membership.
    fn install_snapshot(&mut self, snapshot: &raft::eraftpb::Snapshot) -> Result<(), GroupError> {
        let installed = self.node.mut_store().install_received_snapshot(snapshot)?;
        if !installed {
            // Stale snapshot: keep our newer committed state. (raft-rs only sends a snapshot to a
            // behind node, so this is defensive.)
            return Ok(());
        }
        let meta = snapshot.get_metadata();
        // RESTORE the application state machine from the snapshot's DATA (the serialized committed
        // metadata cut). An empty data payload is only ever produced by the legacy/no-data path,
        // which the storage never serves now (it returns SnapshotTemporarilyUnavailable instead), so
        // a non-empty install always carries a full SM cut.
        if snapshot.data.is_empty() {
            // No SM bytes: keep the membership from the ConfState but leave the SM otherwise empty
            // at the snapshot index (defensive; not produced by this storage's snapshot()).
            self.state = MetadataStateMachine::new();
        } else {
            self.state = MetadataStateMachine::restore_from_snapshot(&snapshot.data)?;
        }
        // Track the snapshot's membership in the SM (the ConfState is the durable membership).
        self.state.set_membership(
            meta.index,
            meta.get_conf_state().get_voters(),
            meta.get_conf_state().get_voters_outgoing(),
            meta.get_conf_state().get_learners(),
            meta.get_conf_state().get_learners_next(),
        );
        Ok(())
    }

    /// The committed metadata-log index that has been APPLIED to this node's state machine. A
    /// snapshot may be taken at or below this index (every entry up to it is durably applied).
    #[must_use]
    pub fn applied_index(&self) -> u64 {
        self.state.applied_index()
    }

    /// The index of the last durable snapshot/compaction (0 before any). Every metadata log entry
    /// at or below it is subsumed by the durable snapshot; the retained log is the tail above it.
    #[must_use]
    pub fn snapshot_index(&self) -> u64 {
        self.node.store().snapshot_index()
    }

    /// The number of metadata log entries RETAINED above the last snapshot (the live, un-compacted
    /// tail). The driver uses this as the bounded log-size signal for its snapshot cadence: when the
    /// retained tail grows past a threshold, it snapshots + compacts to bound the log (#660). Reads
    /// the durable storage's first/last index, never the wall clock.
    #[must_use]
    pub fn retained_log_len(&self) -> u64 {
        let store = self.node.store();
        let last = store.last_index().unwrap_or(0);
        let first = store.first_index().unwrap_or(1);
        // first_index is last_index + 1 for an empty (fully-compacted) log, so saturate.
        last.saturating_add(1).saturating_sub(first)
    }

    /// CREATE a metadata snapshot at the current applied index and COMPACT the log up to it (#660),
    /// IF the applied frontier has advanced past the last snapshot (else a no-op). The snapshot
    /// captures the EXACT committed state machine at `applied_index` BEFORE the log prefix is
    /// truncated, so a node restarting from snapshot+tail holds the identical committed state, and a
    /// far-behind learner can be caught up from the snapshot + tail.
    ///
    /// Returns `true` if a snapshot was created (the log was compacted), `false` if it was a no-op
    /// (nothing new to snapshot). Safe to call on any cadence; it only does work when the applied
    /// frontier has moved.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::Storage`] if the snapshot fails to persist durably or the compaction
    /// fails, or [`GroupError::Raft`] if the applied index's term cannot be read.
    pub fn create_snapshot(&mut self) -> Result<bool, GroupError> {
        let applied = self.state.applied_index();
        // Only snapshot a committed+applied index strictly above the last snapshot. raft-rs never
        // compacts past the applied index, so this is always safe.
        if applied <= self.node.store().snapshot_index() {
            return Ok(false);
        }
        // The term of the entry at the applied index (the snapshot's term). It must be a present log
        // entry (applied <= committed <= last_index), so `term` resolves it.
        let term = self.node.store().term(applied)?;
        // Serialize the EXACT committed state machine at the applied index.
        let data = self.state.snapshot();
        self.node
            .mut_store()
            .create_snapshot_and_compact(applied, term, &data)?;
        Ok(true)
    }

    /// Fold a batch of committed entries into the state machine. A leader's empty no-op entry
    /// (which establishes its term) advances the index but applies nothing; a normal entry is a
    /// metadata command; a CONF-CHANGE entry (C1-I4) is applied to the raft `ConfState` AND the
    /// state machine's membership.
    fn apply_committed(&mut self, entries: Vec<Entry>) -> Result<(), GroupError> {
        for entry in entries {
            match entry.get_entry_type() {
                EntryType::EntryNormal => {
                    if entry.data.is_empty() {
                        // A leader's empty no-op entry: nothing to apply, but it advances the index.
                        continue;
                    }
                    self.state.apply_encoded(entry.index, &entry.data)?;
                }
                EntryType::EntryConfChange => {
                    // A legacy single-server (V1) conf change. (The C1-I4 membership API always
                    // proposes V2, but we apply a V1 entry too for completeness / forward-compat.)
                    let cc = ConfChange::parse_from_bytes(&entry.data)
                        .map_err(MetadataStorageError::from)?;
                    self.apply_conf_change_entry(entry.index, &cc)?;
                }
                EntryType::EntryConfChangeV2 => {
                    // A joint-consensus (V2) conf change — the C1-I4 path. An EMPTY V2 entry is
                    // the auto-appended LEAVE-JOINT change raft-rs emits to transition out of a
                    // joint configuration; it parses to a default (empty) ConfChangeV2 and is
                    // applied exactly the same way (leaving the joint config).
                    let cc = ConfChangeV2::parse_from_bytes(&entry.data)
                        .map_err(MetadataStorageError::from)?;
                    self.apply_conf_change_entry(entry.index, &cc)?;
                }
            }
        }
        Ok(())
    }

    /// Apply one committed conf-change entry: hand it to the raft core (`apply_conf_change`,
    /// which mutates the active configuration and returns the new `ConfState`), DURABLY persist
    /// the new `ConfState` to the metadata log (and fsync — membership is as load-bearing as the
    /// hard state, so it survives a restart, #659), then fold the new membership into the state
    /// machine so its voter / learner view tracks the durable config.
    ///
    /// The empty leave-joint change is applied here too (it transitions out of the joint config);
    /// raft-rs auto-appends it once the enter-joint change is applied, so the caller never has to.
    fn apply_conf_change_entry(
        &mut self,
        index: u64,
        cc: &impl ConfChangeI,
    ) -> Result<(), GroupError> {
        let new_conf_state = self.node.apply_conf_change(cc)?;
        // Persist the new membership durably (paired with the current hard state) and fsync, the
        // same persist-before-act discipline as the hard state — then fold it into the SM.
        self.node.mut_store().set_conf_state(&new_conf_state)?;
        self.node.mut_store().sync()?;
        self.state.set_membership(
            index,
            new_conf_state.get_voters(),
            new_conf_state.get_voters_outgoing(),
            new_conf_state.get_learners(),
            new_conf_state.get_learners_next(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::state_machine::{NodeRole, Placement};
    use ironbus_core::clock::ManualClock;
    use ironbus_storage::fs::InMemoryFs;

    /// The concrete group type the durable tests use: the in-memory filesystem + a manual
    /// clock, exactly the seams the storage crate's own tests drive.
    type TestGroup = MetadataRaftGroup<InMemoryFs, ManualClock>;

    fn log_config() -> LogConfig {
        LogConfig::new(64 * 1024).expect("valid segment cap")
    }

    /// Open a durable single-voter group over `fs` (so a test can reuse the same `fs` to
    /// simulate a restart by dropping the group and re-opening over the SAME durable image).
    fn open_on(fs: &InMemoryFs, node_id: u64, voters: &[u64]) -> TestGroup {
        MetadataRaftGroup::open(node_id, voters, fs, ManualClock::new(), log_config())
            .expect("open durable group")
    }

    /// Drive the group until it has settled (no more pending Ready), bounded so a bug can't
    /// hang the test.
    fn settle(group: &mut TestGroup) {
        for _ in 0..256 {
            let _ = group.drive_ready().expect("drive ready");
            if !group.node.has_ready() {
                break;
            }
        }
    }

    #[test]
    fn unsupported_voter_count_is_rejected() {
        let fs = InMemoryFs::new();
        assert!(matches!(
            MetadataRaftGroup::open(1, &[1, 2], &fs, ManualClock::new(), log_config()),
            Err(GroupError::UnsupportedVoterCount(2))
        ));
        assert!(matches!(
            MetadataRaftGroup::open(1, &[], &fs, ManualClock::new(), log_config()),
            Err(GroupError::UnsupportedVoterCount(0))
        ));
    }

    #[test]
    fn self_must_be_a_voter() {
        let fs = InMemoryFs::new();
        assert!(matches!(
            MetadataRaftGroup::open(9, &[1, 2, 3], &fs, ManualClock::new(), log_config()),
            Err(GroupError::SelfNotAVoter { node_id: 9 })
        ));
    }

    #[test]
    fn constructs_for_one_three_and_five_voters() {
        // Each group gets its OWN data dir (separate fs) so the metaraft/ subdirs don't collide.
        assert!(MetadataRaftGroup::open(
            1,
            &[1],
            &InMemoryFs::new(),
            ManualClock::new(),
            log_config()
        )
        .is_ok());
        assert!(MetadataRaftGroup::open(
            2,
            &[1, 2, 3],
            &InMemoryFs::new(),
            ManualClock::new(),
            log_config()
        )
        .is_ok());
        assert!(MetadataRaftGroup::open(
            5,
            &[1, 2, 3, 4, 5],
            &InMemoryFs::new(),
            ManualClock::new(),
            log_config()
        )
        .is_ok());
    }

    /// A single-voter group elects itself via tick/ready and a proposed command round-trips
    /// through propose -> step/tick -> ready -> apply into the state machine — now on the
    /// DURABLE `MetadataLogStorage`, not `MemStorage`.
    #[test]
    fn single_node_group_propose_tick_ready_roundtrips_on_durable_log() {
        let fs = InMemoryFs::new();
        let mut group = open_on(&fs, 1, &[1]);
        assert!(!group.is_leader());

        // Elect via the campaign + ready cycle, then settle the no-op commit.
        group.campaign().expect("campaign");
        settle(&mut group);
        assert!(group.is_leader(), "lone voter should self-elect");
        assert!(group.term() >= 1);

        // Propose a membership command and drive it to commit + apply.
        let cmd = MetadataCommand::AddNode {
            node: 1,
            role: NodeRole::Voter,
        };
        group.propose(&cmd).expect("propose");
        settle(&mut group);

        // The command is now applied in the replicated state machine.
        assert_eq!(group.state().role(1), Some(NodeRole::Voter));
        assert_eq!(group.state().voter_count(), 1);
        assert!(
            group.state().applied_index() > 0,
            "an entry should have been applied"
        );

        // A second, different command also round-trips and is ordered after the first.
        let prev_index = group.state().applied_index();
        let cmd2 = MetadataCommand::AssignPartition {
            partition: 7,
            leader: 1,
            epoch: group.term(),
        };
        group.propose(&cmd2).expect("propose 2");
        settle(&mut group);
        assert_eq!(
            group.state().placement(7),
            Some(Placement::leader_only(1, group.term()))
        );
        assert!(group.state().applied_index() > prev_index);
    }

    #[test]
    fn tick_drives_election_without_explicit_campaign() {
        let fs = InMemoryFs::new();
        let mut group = open_on(&fs, 1, &[1]);
        // Ticking past the election timeout makes the lone voter campaign on its own.
        for _ in 0..50 {
            group.tick();
            settle(&mut group);
            if group.is_leader() {
                break;
            }
        }
        assert!(group.is_leader(), "tick alone should elect the lone voter");
    }

    /// The C1-I2 acceptance test: a committed metadata entry driven through the DURABLE
    /// storage SURVIVES a simulated restart — reopening the group over the SAME durable image
    /// recovers the committed placement and the term/commit, proving the metadata group
    /// drives propose/commit through `MetadataLogStorage` (not `MemStorage`) and the committed
    /// entry is durable across a reopen.
    #[test]
    fn committed_entry_survives_a_group_reopen() {
        let fs = InMemoryFs::new();
        let (term, last_index, applied_index) = {
            let mut group = open_on(&fs, 1, &[1]);
            group.campaign().expect("campaign");
            settle(&mut group);
            assert!(group.is_leader());

            group
                .propose(&MetadataCommand::AssignPartition {
                    partition: 3,
                    leader: 1,
                    epoch: 1,
                })
                .expect("propose");
            settle(&mut group);
            assert_eq!(
                group.state().placement(3),
                Some(Placement::leader_only(1, 1))
            );
            (
                group.term(),
                group.node.store().last_index().expect("last index"),
                group.state().applied_index(),
            )
        };
        assert!(applied_index > 0);

        // Reopen the group over the SAME durable fs image: this is a process restart. The
        // recovered storage must report the same last index and the persisted hard state, and
        // re-applying the durable entries must re-derive the committed placement.
        let mut reopened = open_on(&fs, 1, &[1]);
        let recovered_state = reopened
            .node
            .store()
            .initial_state()
            .expect("initial state");
        assert_eq!(
            recovered_state.hard_state.term, term,
            "the persisted term must survive the restart"
        );
        assert!(
            recovered_state.hard_state.commit >= applied_index,
            "the persisted commit index must cover the committed entry"
        );
        assert_eq!(
            reopened.node.store().last_index().expect("last index"),
            last_index,
            "the recovered log must have the same last index"
        );

        // Re-applying the committed (durable) entries reconstructs the state machine: campaign
        // is unnecessary (the entries are already durable), so drive the recovered commit
        // through the ready loop and confirm the placement comes back.
        settle(&mut reopened);
        assert_eq!(
            reopened.state().placement(3),
            Some(Placement::leader_only(1, 1)),
            "the committed placement must survive a reopen of the durable group"
        );
    }

    /// The C5-I1 (#616) durability acceptance test: a full REPLICA-SET placement (a
    /// `PlacePartition` command — `R` replicas + a designated leader) commits through the metadata
    /// log and SURVIVES a reopen, exactly like the leader-only placement above. This proves the
    /// placement is durable-through-the-metadata-log (one entry, reusing the #659 round-trip), not
    /// a transient in-memory decision.
    #[test]
    fn committed_replica_set_placement_survives_a_group_reopen() {
        let fs = InMemoryFs::new();
        let expected = Placement {
            replicas: vec![1, 2, 3],
            leader: 1,
            epoch: 4,
        };
        {
            let mut group = open_on(&fs, 1, &[1]);
            group.campaign().expect("campaign");
            settle(&mut group);
            assert!(group.is_leader());

            group
                .propose(&MetadataCommand::PlacePartition {
                    partition: 8,
                    replicas: vec![1, 2, 3],
                    leader: 1,
                    epoch: 4,
                })
                .expect("propose placement");
            settle(&mut group);
            assert_eq!(
                group.state().placement(8),
                Some(expected.clone()),
                "the replica-set placement applied on the live group"
            );
        }

        // Reopen over the SAME durable image (a process restart): re-applying the durable entries
        // must reconstruct the identical replica-set placement.
        let mut reopened = open_on(&fs, 1, &[1]);
        settle(&mut reopened);
        assert_eq!(
            reopened.state().placement(8),
            Some(expected),
            "the committed replica-set placement must survive a reopen of the durable group"
        );
    }

    // --- C1-I3 (#582): leader epoch (fencing token) + monotonic leadership lease. ---

    use std::sync::Arc;

    /// A group whose monotonic clock is a SHARED `Arc<ManualClock>`, so a test can drive the
    /// very clock the group's leadership lease reads (the storage and the lease share it). The
    /// returned handle is that clock; advancing it advances the group's monotonic time.
    fn open_with_shared_clock(
        fs: &InMemoryFs,
        node_id: u64,
        voters: &[u64],
    ) -> (
        MetadataRaftGroup<InMemoryFs, Arc<ManualClock>>,
        Arc<ManualClock>,
    ) {
        let clock = Arc::new(ManualClock::new());
        let group = MetadataRaftGroup::open(node_id, voters, fs, Arc::clone(&clock), log_config())
            .expect("open shared-clock group");
        (group, clock)
    }

    /// Settle a shared-clock group (same bounded drive as `settle`, monomorphized for the
    /// `Arc<ManualClock>` group).
    fn settle_shared(group: &mut MetadataRaftGroup<InMemoryFs, Arc<ManualClock>>) {
        for _ in 0..256 {
            let _ = group.drive_ready().expect("drive ready");
            if !group.node.has_ready() {
                break;
            }
        }
    }

    /// The leader epoch is strictly monotonic across leadership changes and is exposed as the
    /// cluster fencing token: a fresh group is at genesis (0); winning term T puts it at epoch T;
    /// it never regresses.
    #[test]
    fn leader_epoch_is_monotonic_and_exposed_as_a_fencing_token() {
        let fs = InMemoryFs::new();
        let mut group = open_on(&fs, 1, &[1]);
        // Before any election the epoch is genesis (0), strictly below every real leadership.
        assert_eq!(group.leader_epoch(), LeaderEpoch::GENESIS);
        assert!(!group.can_act_as_leader(), "no lease before an election");

        group.campaign().expect("campaign");
        settle(&mut group);
        assert!(group.is_leader());
        let epoch = group.leader_epoch();
        assert!(
            epoch.get() >= 1,
            "winning the first election advances the epoch off genesis"
        );
        assert_eq!(
            epoch.get(),
            group.term(),
            "the leader epoch is the raft term surfaced as a fencing token"
        );
        // The epoch never regresses: re-driving the settled leader keeps it at the same epoch.
        settle(&mut group);
        assert_eq!(
            group.leader_epoch(),
            epoch,
            "a stable leader's epoch does not regress"
        );
        // The current leader is not fenced by its own epoch; a strictly-older epoch IS fenced.
        assert!(
            !group.fences(epoch),
            "the current leader's own-epoch write commits"
        );
        assert!(
            group.fences(LeaderEpoch::new(epoch.get() - 1)),
            "a write at a strictly-older epoch is fenced"
        );
    }

    /// Election Safety surfaced through the metadata group: while leading, this node holds a
    /// valid lease at its epoch and is the only actor at that epoch; a strictly-older-epoch
    /// write is always fenced (≤ 1 acting leader per epoch).
    #[test]
    fn at_most_one_leader_per_epoch_holds_through_the_metadata_group() {
        let fs = InMemoryFs::new();
        let (mut group, _clock) = open_with_shared_clock(&fs, 1, &[1]);
        group.campaign().expect("campaign");
        settle_shared(&mut group);
        assert!(group.is_leader());
        let epoch = group.leader_epoch();
        assert!(
            group.can_act_as_leader(),
            "the elected leader holds a valid lease at its epoch"
        );
        // No older-epoch leadership can act: any epoch below the current one is fenced.
        for older in 0..epoch.get() {
            assert!(
                group.fences(LeaderEpoch::new(older)),
                "epoch {older} is older than the current leadership and must be fenced"
            );
        }
    }

    /// A leadership lease expires on the MONOTONIC clock (not the wall clock), and a post-expiry
    /// stale leader is fenced: with no newer term observed (a partition), once the lease lapses
    /// the node can no longer act and its write cannot commit.
    #[test]
    fn a_leadership_lease_expires_and_fences_a_stale_leader_on_the_monotonic_clock() {
        let fs = InMemoryFs::new();
        let (mut group, clock) = open_with_shared_clock(&fs, 1, &[1]);
        group.campaign().expect("campaign");
        settle_shared(&mut group);
        assert!(group.is_leader());
        let epoch = group.leader_epoch();

        // The lease was granted at monotonic time 0; it is valid now and the leader may act.
        let lease = group.leader_lease().expect("leader holds a lease");
        assert!(
            group.can_act_as_leader(),
            "within the lease the leader acts"
        );
        assert!(
            !group.fences(epoch),
            "its current-epoch write commits within the lease"
        );

        // WALL-clock motion alone must NOT expire the lease (the lease is monotonic-only): step
        // the wall clock far forward, leaving the monotonic clock fixed.
        clock.set_unix_millis(10_000_000_000);
        assert!(
            group.can_act_as_leader(),
            "a wall-clock step does not expire a monotonic lease"
        );

        // Now advance ONLY the monotonic clock past the lease deadline, observing NO new term
        // (the partition): the lease lapses and the stale leader is fenced.
        let past_deadline = lease.deadline() - clock.now_monotonic_nanos() + 1;
        clock.advance_monotonic_nanos(past_deadline);
        assert!(
            !group.can_act_as_leader(),
            "the lapsed lease fences the stale leader off the monotonic clock"
        );
        assert!(
            group.fences(epoch),
            "a post-expiry write by the stale leader cannot commit"
        );
    }

    /// The n=1 degenerate case: the lone voter self-elects, holds the only (trivial) lease, is
    /// never fenced by itself, and the epoch/lease are bookkeeping with no behavior change.
    #[test]
    fn the_single_node_n1_case_is_trivial_and_degenerate() {
        let fs = InMemoryFs::new();
        let mut group = open_on(&fs, 1, &[1]);
        group.campaign().expect("campaign");
        settle(&mut group);
        assert!(group.is_leader(), "the lone voter self-elects");
        let epoch = group.leader_epoch();
        assert!(epoch.get() >= 1);
        assert!(
            group.can_act_as_leader(),
            "the sole leader trivially holds the only lease"
        );
        // There is no other leadership to fence it; its own-epoch write always commits.
        assert!(
            !group.fences(epoch),
            "the lone leader is never fenced by itself"
        );
        assert!(group.leader_lease().is_some());
    }

    /// The leader epoch SURVIVES the durable metadata-log round-trip (#659): a reopened group
    /// recovers the epoch from the persisted term and never regresses below it — but holds NO
    /// lease at open, so a recovered node cannot resume acting as a stale leader.
    #[test]
    fn the_leader_epoch_survives_the_metadata_log_roundtrip() {
        let fs = InMemoryFs::new();
        let epoch_before = {
            let mut group = open_on(&fs, 1, &[1]);
            group.campaign().expect("campaign");
            settle(&mut group);
            assert!(group.is_leader());
            // Commit something so the term is durably checkpointed.
            group
                .propose(&MetadataCommand::AssignPartition {
                    partition: 1,
                    leader: 1,
                    epoch: group.leader_epoch().get(),
                })
                .expect("propose");
            settle(&mut group);
            group.leader_epoch()
        };
        assert!(epoch_before.get() >= 1);

        // Reopen over the SAME durable image (a restart): the epoch is recovered from the
        // persisted term and is at least what it was — it never regresses.
        let reopened = open_on(&fs, 1, &[1]);
        assert!(
            reopened.leader_epoch().get() >= epoch_before.get(),
            "the recovered epoch never regresses below the durable term"
        );
        // A recovered node holds NO lease until it re-wins leadership: it cannot act as a stale
        // leader across the restart.
        assert!(
            !reopened.can_act_as_leader(),
            "a recovered node holds no leadership lease until it re-campaigns"
        );
        assert!(reopened.leader_lease().is_none());
    }

    // --- C1-I4 (#584): joint-consensus membership + learners + peer-id validation. ---

    use crate::cluster::membership::{MembershipChange, PeerIdError};

    /// Elect the lone voter and settle, returning a leader-ready single-node group over `fs`.
    fn elected_single(fs: &InMemoryFs) -> TestGroup {
        let mut group = open_on(fs, 1, &[1]);
        group.campaign().expect("campaign");
        settle(&mut group);
        assert!(group.is_leader(), "lone voter self-elects");
        group
    }

    /// The voters currently in the durable conf state, sorted.
    fn voters_of(group: &TestGroup) -> Vec<u64> {
        let mut v = group.conf_state().expect("conf state").voters;
        v.sort_unstable();
        v
    }

    /// The learners currently in the durable conf state, sorted.
    fn learners_of(group: &TestGroup) -> Vec<u64> {
        let mut l = group.conf_state().expect("conf state").learners;
        l.sort_unstable();
        l
    }

    /// THE FIRST REAL JOINT CHANGE: n=1 -> add the 2nd member as a voter. The change is proposed
    /// through the metadata raft log, committed, applied to the `ConfState` AND the state machine,
    /// and — crucially — SURVIVES a reopen (durable via #659). At n=1 the single change uses the
    /// simple protocol; this is the degenerate-but-correct case the brief calls out.
    #[test]
    fn n1_add_second_voter_is_committed_through_the_log_and_survives_reopen() {
        let fs = InMemoryFs::new();
        {
            let mut group = elected_single(&fs);
            assert_eq!(voters_of(&group), vec![1]);

            group
                .propose_membership_change(&MembershipChange::new().add_voter(2))
                .expect("propose add-voter");
            settle(&mut group);

            // The new voter is in the durable ConfState AND folded into the state machine.
            assert_eq!(voters_of(&group), vec![1, 2], "node 2 is now a voter");
            assert_eq!(group.state().role(2), Some(NodeRole::Voter));
            assert_eq!(
                group.state().voter_count(),
                2,
                "the state machine tracks 2 voters"
            );
            // Not joint anymore: the (auto-)leave finished, no outgoing voters remain.
            assert!(
                group.conf_state().unwrap().voters_outgoing.is_empty(),
                "the joint config was left"
            );
        }

        // Reopen over the SAME durable image (a restart): the membership change is durable. The
        // recovered ConfState carries both voters.
        let reopened = open_on(&fs, 1, &[1]);
        assert_eq!(
            voters_of(&reopened),
            vec![1, 2],
            "the committed membership change survives a reopen (#659)"
        );
    }

    /// A learner JOINS as a non-voting member first (it never counts toward quorum), then is
    /// PROMOTED to a voter via a second conf change. The wire catch-up of the learner is peer
    /// transport (#667); here the learner ROLE + promotion in the conf change + state machine is
    /// what is exercised.
    #[test]
    fn add_a_learner_then_promote_it_to_a_voter() {
        let fs = InMemoryFs::new();
        let mut group = elected_single(&fs);

        // Add node 2 as a NON-VOTING learner.
        group.add_learner(2).expect("add learner");
        settle(&mut group);
        assert_eq!(learners_of(&group), vec![2], "node 2 joined as a learner");
        assert_eq!(group.state().role(2), Some(NodeRole::Learner));
        assert_eq!(
            group.state().voter_count(),
            1,
            "a learner does NOT count toward quorum"
        );
        assert_eq!(voters_of(&group), vec![1]);

        // Promote the learner to a voter.
        group.promote_learner(2).expect("promote learner");
        settle(&mut group);
        assert_eq!(voters_of(&group), vec![1, 2], "node 2 is now a voter");
        assert!(
            learners_of(&group).is_empty(),
            "node 2 is no longer a learner"
        );
        assert_eq!(group.state().role(2), Some(NodeRole::Voter));
        assert_eq!(group.state().voter_count(), 2);
    }

    // --- A deterministic in-memory MESH of metadata groups. ---
    //
    // Removing a voter (or any change touching the quorum past n=1) requires the new voters to
    // actually replicate, so a single isolated group cannot commit it. The OVER-THE-WIRE peer
    // transport (serialization + bounding untrusted bytes) is #667 and explicitly out of scope
    // here. To exercise REAL joint consensus deterministically WITHOUT that wire, the tests run a
    // small in-process mesh: each node is a `MetadataRaftGroup`, and we hand-deliver the
    // `Message`s a node's `drive_ready` emits to the addressed peer's `step` — moving in-memory
    // `Message` VALUES between groups, parsing no bytes. This is the raft-rs `five_mem_node`
    // pattern, scoped to tests.

    /// A fixed-membership mesh of groups keyed by node id, each over its own in-memory fs so the
    /// `metaraft/` subdirs never collide.
    struct Mesh {
        nodes: std::collections::BTreeMap<u64, TestGroup>,
    }

    impl Mesh {
        /// Build a mesh of `voters`, each a group that knows the full voter set.
        fn new(voters: &[u64]) -> Self {
            Self::with_segment_cap(voters, 64 * 1024)
        }

        /// Build a mesh whose nodes use a specific log segment cap, so a small cap forces several
        /// sealed segments (and thus reclaimable prefix segments under compaction, #660).
        fn with_segment_cap(voters: &[u64], segment_cap: u64) -> Self {
            let mut nodes = std::collections::BTreeMap::new();
            for &id in voters {
                // Each node gets its OWN fs (its own durable metaraft/ image).
                let fs = InMemoryFs::new();
                let group = MetadataRaftGroup::open(
                    id,
                    voters,
                    &fs,
                    ManualClock::new(),
                    LogConfig::new(segment_cap).expect("valid segment cap"),
                )
                .expect("open mesh node");
                // Leak the fs into the group's storage lifetime: the group owns its log, and the
                // InMemoryFs is reference-counted internally, so we just drop our handle.
                nodes.insert(id, group);
            }
            Self { nodes }
        }

        /// Add a new node to the mesh as a non-voting LEARNER joining an EXISTING cluster of
        /// `existing_voters` (#617): it opens via `open_as_learner`, so it follows the quorum but
        /// never campaigns (no term disruption) and back-fills by replication / snapshot transfer.
        fn add_learner_node(&mut self, id: u64, existing_voters: &[u64], segment_cap: u64) {
            let fs = InMemoryFs::new();
            let group = MetadataRaftGroup::open_as_learner(
                id,
                existing_voters,
                &fs,
                ManualClock::new(),
                LogConfig::new(segment_cap).expect("valid segment cap"),
            )
            .expect("open learner node");
            self.nodes.insert(id, group);
        }

        /// Tick every node once (drives election timers).
        fn tick_all(&mut self) {
            for node in self.nodes.values_mut() {
                node.tick();
            }
        }

        /// Drain every node's ready cycle once, routing each emitted message to its destination
        /// node's `step`. Returns the number of messages routed this round (0 once the mesh has
        /// nothing more to say).
        fn pump_once(&mut self) -> usize {
            // Collect outbound from every node's drive_ready, then deliver. Two phases so the
            // borrow of `self.nodes` for draining is dropped before the borrow for delivery.
            let mut outbox: Vec<Message> = Vec::new();
            for node in self.nodes.values_mut() {
                let msgs = node.drive_ready().expect("drive ready");
                outbox.extend(msgs);
            }
            let routed = outbox.len();
            for msg in outbox {
                let to = msg.to;
                if let Some(dst) = self.nodes.get_mut(&to) {
                    // Ignore a step error for a message addressed to a node mid-removal (it may
                    // no longer recognise the sender); the mesh is a best-effort router.
                    let _ = dst.step(msg);
                }
            }
            routed
        }

        /// True once no node has pending ready work (the mesh has quiesced).
        fn quiesced(&self) -> bool {
            self.nodes.values().all(|n| !n.node.has_ready())
        }

        /// Run the mesh to a fixed point: repeatedly tick (to drive heartbeats / re-broadcasts)
        /// and pump messages until the mesh has been QUIESCED for several consecutive idle rounds.
        /// The per-pass pump is itself iterated so a message produced by one node's `step` is drained
        /// and routed in the same pass — important so a leader's just-appended entry (e.g. the
        /// auto-appended LEAVE-JOINT conf change) replicates and commits within `run`.
        ///
        /// It does NOT break on the FIRST idle round: a multi-phase catch-up (notably SNAPSHOT
        /// transfer to a freshly-added learner, #660) spans several heartbeat intervals — the leader
        /// probes on a `heartbeat_tick` cadence, the learner rejects, the leader backs off and sends
        /// a snapshot, the learner installs it and acks, then the tail replicates — with idle rounds
        /// in between while waiting for the next heartbeat tick. Requiring a run of consecutive idle
        /// rounds (well past `heartbeat_tick`) before stopping lets the whole negotiation complete,
        /// while the outer fuel cap still bounds a genuinely stuck mesh.
        fn run(&mut self) {
            // Idle rounds needed to conclude the mesh has truly settled: comfortably more than
            // `heartbeat_tick` (3) so a between-heartbeat lull is never mistaken for completion.
            const QUIET_ROUNDS_TO_SETTLE: u32 = 12;
            let mut consecutive_idle: u32 = 0;
            for _ in 0..2048 {
                self.tick_all();
                // Drain-and-route to a local fixed point before the next tick.
                let mut progressed = false;
                for _ in 0..256 {
                    let routed = self.pump_once();
                    if routed > 0 {
                        progressed = true;
                    }
                    if routed == 0 && self.quiesced() {
                        break;
                    }
                }
                if self.quiesced() && !progressed {
                    consecutive_idle += 1;
                    if consecutive_idle >= QUIET_ROUNDS_TO_SETTLE {
                        break;
                    }
                } else {
                    consecutive_idle = 0;
                }
            }
        }

        /// Elect node `id` as leader and drive the mesh to a stable leadership.
        fn elect(&mut self, id: u64) {
            self.nodes
                .get_mut(&id)
                .expect("node")
                .campaign()
                .expect("campaign");
            self.run();
            assert!(self.nodes[&id].is_leader(), "node {id} should be leader");
        }

        /// The leader node's id, if exactly one node believes it leads.
        fn leader(&self) -> Option<u64> {
            let leaders: Vec<u64> = self
                .nodes
                .iter()
                .filter(|(_, n)| n.is_leader())
                .map(|(id, _)| *id)
                .collect();
            (leaders.len() == 1).then(|| leaders[0])
        }

        /// Propose a membership change on the current leader and drive the mesh to convergence.
        fn change_on_leader(&mut self, change: &MembershipChange) -> Result<(), GroupError> {
            let leader = self.leader().expect("a leader");
            self.nodes
                .get_mut(&leader)
                .unwrap()
                .propose_membership_change(change)?;
            self.run();
            Ok(())
        }

        /// The sorted voter set as seen by node `id`.
        fn voters_seen_by(&self, id: u64) -> Vec<u64> {
            let mut v = self.nodes[&id].conf_state().expect("conf state").voters;
            v.sort_unstable();
            v
        }
    }

    /// Remove a voter via joint consensus on a REAL 3-node mesh. A 3-voter group elects a leader,
    /// replicates, then removes one voter; the change goes through the joint configuration
    /// (overlapping old+new majorities, Raft §6) and converges to the 2-voter config on the
    /// surviving voters.
    #[test]
    fn remove_a_voter_via_joint_consensus_on_a_mesh() {
        let mut mesh = Mesh::new(&[1, 2, 3]);
        mesh.elect(1);
        assert_eq!(mesh.voters_seen_by(1), vec![1, 2, 3]);

        // Remove node 3 (a single-voter change; raft-rs uses the simple protocol, still safe).
        mesh.change_on_leader(&MembershipChange::new().remove_node(3))
            .expect("remove 3");

        // The two surviving voters converge to {1, 2}, with the joint state (if any) left.
        let leader = mesh.leader().expect("still a leader after removal");
        assert_eq!(mesh.voters_seen_by(leader), vec![1, 2], "node 3 removed");
        let cs = mesh.nodes[&leader].conf_state().unwrap();
        assert!(cs.voters_outgoing.is_empty(), "joint config left");
        assert_eq!(
            mesh.nodes[&leader].state().voter_count(),
            2,
            "the state machine tracks 2 voters"
        );
    }

    /// A genuine MULTI-VOTER change ENTERS JOINT CONSENSUS on a REAL mesh: a 5-voter group
    /// atomically removes TWO voters in one transition (distinct ids 4 and 5). raft-rs reports
    /// `enter_joint`, the configuration is briefly joint (a majority of the old {1..5} and of the
    /// new {1,2,3} overlap — Raft §6), then auto-leaves to the 3-voter config. This is the
    /// load-bearing joint-consensus correctness case: more than one voter changes atomically,
    /// safely, through the durable log.
    #[test]
    fn a_multi_voter_change_enters_joint_consensus_and_converges_on_a_mesh() {
        let mut mesh = Mesh::new(&[1, 2, 3, 4, 5]);
        mesh.elect(1);
        assert_eq!(mesh.voters_seen_by(1), vec![1, 2, 3, 4, 5]);

        // Atomically remove voters 4 AND 5 — a 2-op change is joint consensus. Quorum is
        // preserved throughout: a majority of {1..5} (3 nodes) overlaps a majority of {1,2,3}.
        let change = MembershipChange::new().remove_node(4).remove_node(5);
        assert_eq!(
            change.to_conf_change_v2().enter_joint(),
            Some(true),
            "a 2-voter change uses joint consensus"
        );
        mesh.change_on_leader(&change)
            .expect("joint remove of 4 and 5");

        let leader = mesh.leader().expect("leader after joint change");
        assert_eq!(
            mesh.voters_seen_by(leader),
            vec![1, 2, 3],
            "both voters were removed atomically"
        );
        let cs = mesh.nodes[&leader].conf_state().unwrap();
        assert!(
            cs.voters_outgoing.is_empty(),
            "the joint config was auto-left"
        );
        assert_eq!(
            mesh.nodes[&leader].state().voter_count(),
            3,
            "the state machine tracks the new 3-voter config"
        );
    }

    /// A learner added on a real mesh never counts toward quorum: a 3-voter mesh adds a 4th node
    /// as a learner; the voter set stays {1,2,3} and the learner is {4} on the committed config.
    #[test]
    fn a_learner_added_on_a_mesh_does_not_count_toward_quorum() {
        let mut mesh = Mesh::new(&[1, 2, 3]);
        mesh.elect(1);
        // Node 4 is not in the mesh's transport, but adding it as a LEARNER does not change the
        // quorum (still a majority of {1,2,3}), so the change commits without node 4 replicating.
        mesh.change_on_leader(&MembershipChange::new().add_learner(4))
            .expect("add learner 4");
        let leader = mesh.leader().expect("leader");
        assert_eq!(
            mesh.voters_seen_by(leader),
            vec![1, 2, 3],
            "the voter set is unchanged: a learner is non-voting"
        );
        assert_eq!(
            mesh.nodes[&leader].conf_state().unwrap().learners,
            vec![4],
            "node 4 joined as a learner"
        );
    }

    /// The #617 learner-catchup ACCESSORS read the metadata core fail-closed: on the LEADER,
    /// `learner_catchup(node)` reports the learner's durably-replicated `matched` vs the committed
    /// bar, and a learner that has NOT replicated reads `matched < committed` (not caught up); on a
    /// FOLLOWER (no progress set) it is `None`. `committed_index()` exposes the committed bar.
    #[test]
    fn learner_catchup_accessor_reads_progress_fail_closed() {
        let mut mesh = Mesh::new(&[1, 2, 3]);
        mesh.elect(1);
        // Commit a few entries so the committed bar is well above 0 (the learner must clear it).
        for i in 0..3u64 {
            let cmd = MetadataCommand::SetConfig {
                key: format!("k{i}"),
                value: i.to_string(),
            };
            let leader = mesh.leader().expect("leader");
            mesh.nodes.get_mut(&leader).unwrap().propose(&cmd).unwrap();
            mesh.run();
        }
        // Add node 4 as a learner. It is NOT in the mesh transport, so it never replicates — its
        // `matched` stays 0 while the committed bar is non-zero, i.e. NOT caught up (fail-closed).
        mesh.change_on_leader(&MembershipChange::new().add_learner(4))
            .expect("add learner 4");
        let leader = mesh.leader().expect("leader");
        let committed = mesh.nodes[&leader].committed_index();
        assert!(committed > 0, "the committed bar is non-trivial");

        let catchup = mesh.nodes[&leader]
            .learner_catchup(4)
            .expect("the leader tracks the learner's progress");
        assert_eq!(catchup.node, 4);
        assert_eq!(
            catchup.committed, committed,
            "the bar is the committed index"
        );
        assert!(
            catchup.matched < committed,
            "a learner that has not replicated is behind the committed bar (matched {} < {committed})",
            catchup.matched
        );
        assert!(
            !catchup.is_caught_up(),
            "the never-replicated learner is NOT caught up — the gate fails closed"
        );

        // A FOLLOWER has no progress set, so the accessor is None (fail-closed at the call site).
        let follower = mesh
            .nodes
            .keys()
            .copied()
            .find(|&id| id != leader)
            .expect("a follower");
        assert!(
            mesh.nodes[&follower].learner_catchup(4).is_none(),
            "a non-leader has no learner-progress evidence (None => never promote)"
        );
    }

    /// THE #6403-CLASS FIX: peer-id validation REJECTS a mangled / duplicate / phantom peer with
    /// a typed error, and the change NEVER enters the log (the membership and conf state are
    /// unchanged after a rejected propose).
    #[test]
    fn peer_id_validation_rejects_mangled_duplicate_and_phantom_peers() {
        let fs = InMemoryFs::new();
        let mut group = elected_single(&fs);
        // Establish a 2-voter group so a remove is meaningful.
        group
            .propose_membership_change(&MembershipChange::new().add_voter(2))
            .expect("add 2");
        settle(&mut group);
        assert_eq!(voters_of(&group), vec![1, 2]);

        // (a) MANGLED: peer id 0 (raft's INVALID_ID) is rejected — raft-rs would silently drop it.
        assert!(matches!(
            group.propose_membership_change(&MembershipChange::new().add_voter(0)),
            Err(GroupError::PeerId(PeerIdError::MangledPeerId))
        ));

        // (b) DUPLICATE: the same id twice in one change is rejected.
        assert!(matches!(
            group.propose_membership_change(&MembershipChange::new().add_voter(3).remove_node(3)),
            Err(GroupError::PeerId(PeerIdError::DuplicatePeerId { node: 3 }))
        ));

        // (c) PHANTOM remove: removing a node that is not a member is rejected.
        assert!(matches!(
            group.propose_membership_change(&MembershipChange::new().remove_node(99)),
            Err(GroupError::PeerId(PeerIdError::NotAMember { node: 99 }))
        ));

        // (d) PHANTOM promote: promoting a non-member is rejected.
        assert!(matches!(
            group.propose_membership_change(&MembershipChange::new().promote_learner(99)),
            Err(GroupError::PeerId(PeerIdError::NotAMember { node: 99 }))
        ));

        // (e) LAST-VOTER freeze: a change that would empty the voter set is rejected.
        assert!(matches!(
            group.propose_membership_change(&MembershipChange::new().remove_node(1).remove_node(2)),
            Err(GroupError::PeerId(PeerIdError::WouldRemoveLastVoter))
        ));

        // After ALL the rejected proposes, the membership is UNCHANGED — no bad change leaked
        // into the log, so quorum cannot be frozen by a phantom peer (the #6403 property).
        settle(&mut group);
        assert_eq!(
            voters_of(&group),
            vec![1, 2],
            "no rejected change touched the durable membership"
        );
        assert_eq!(group.state().voter_count(), 2);
    }

    /// A membership change is proposed through the LOCAL raft log API (built from caller node
    /// ids), NOT by parsing untrusted peer wire bytes — so C1-I4 introduces no new peer-byte
    /// parsing. This test documents the seam: the change is constructed and validated entirely
    /// from in-process data.
    #[test]
    fn membership_changes_parse_no_peer_bytes() {
        let fs = InMemoryFs::new();
        let mut group = elected_single(&fs);
        // The change is a value built from a node id; there is no peer-supplied byte buffer
        // anywhere on this path. Proposing it touches only the local log.
        let change = MembershipChange::new().add_learner(2);
        group
            .propose_membership_change(&change)
            .expect("propose from local data");
        settle(&mut group);
        assert_eq!(learners_of(&group), vec![2]);
    }

    // --- #660: metadata log snapshot + compaction at the GROUP layer. ---

    /// THE GROUP-LAYER COMMITTED-STATE-PRESERVED TEST (#660 non-negotiable 1): commit many metadata
    /// commands on a single-node group, SNAPSHOT + COMPACT, and confirm (a) the log is BOUNDED (its
    /// retained tail collapses, `snapshot_index` rises), (b) the live state is unchanged, and (c) a
    /// REOPEN over the same durable image (a restart) recovers the IDENTICAL committed state from the
    /// snapshot + the (empty/short) tail — equal to a full replay.
    #[test]
    fn snapshot_and_compaction_bounds_the_log_and_survives_reopen() {
        let fs = InMemoryFs::new();
        let expected_placements;
        {
            // A small segment so the many entries roll into several sealed segments (so compaction
            // can reclaim whole prefix segments).
            let mut group = MetadataRaftGroup::open(
                1,
                &[1],
                &fs,
                ManualClock::new(),
                LogConfig::new(512).unwrap(),
            )
            .expect("open");
            group.campaign().expect("campaign");
            settle(&mut group);
            assert!(group.is_leader());

            // Commit a batch of placement + config commands so the log grows well past one segment.
            for p in 0..30u64 {
                group
                    .propose(&MetadataCommand::AssignPartition {
                        partition: p,
                        leader: 1,
                        epoch: 1,
                    })
                    .expect("propose");
                settle(&mut group);
            }
            let applied_before = group.applied_index();
            assert!(applied_before > 30, "many entries committed + applied");
            assert_eq!(group.snapshot_index(), 0, "no snapshot yet");
            let tail_before = group.retained_log_len();
            assert!(tail_before > 20, "the log is long before compaction");

            // SNAPSHOT + COMPACT at the applied index.
            let created = group.create_snapshot().expect("create snapshot");
            assert!(created, "a snapshot was created");
            assert_eq!(
                group.snapshot_index(),
                applied_before,
                "snapshot taken at the applied index"
            );
            assert!(
                group.retained_log_len() < tail_before,
                "the retained log shrank ({} < {tail_before})",
                group.retained_log_len()
            );

            // The live state is unchanged by compaction.
            for p in 0..30u64 {
                assert_eq!(
                    group.state().placement(p),
                    Some(Placement::leader_only(1, 1)),
                    "placement {p} survives compaction"
                );
            }
            expected_placements = group.state().placements();

            // A second snapshot with no new applied entries is a no-op.
            assert!(
                !group.create_snapshot().expect("noop snapshot"),
                "snapshotting an unchanged applied frontier is a no-op"
            );
        }

        // REOPEN over the same durable image (a restart): recovery installs the snapshot, then folds
        // the (empty) tail. The committed state is IDENTICAL — equal to a full replay.
        let mut reopened = MetadataRaftGroup::open(
            1,
            &[1],
            &fs,
            ManualClock::new(),
            LogConfig::new(512).unwrap(),
        )
        .expect("reopen");
        settle(&mut reopened);
        assert_eq!(
            reopened.state().placements(),
            expected_placements,
            "the committed metadata state survives snapshot + compaction + restart"
        );
        assert!(
            reopened.snapshot_index() >= 30,
            "the durable snapshot was recovered"
        );
    }

    /// THE SNAPSHOT-CATCH-UP TEST on a REAL multi-node mesh (#660 non-negotiable 4): a far-behind
    /// LEARNER that joins AFTER the leader has compacted its log receives a SNAPSHOT, installs it,
    /// then applies the replicated log TAIL and converges to the leader's committed metadata state —
    /// no gap, no dup, no replay of pre-snapshot entries. This is the #617/#724 fast-learner-join
    /// scenario the issue calls out: the prefix the learner needs is GONE from the leader's log, so
    /// snapshot transfer is the ONLY way to catch it up. A learner never campaigns, so there is no
    /// term-disruption (the realistic catch-up shape, unlike an isolated voter).
    #[test]
    fn a_far_behind_learner_catches_up_via_snapshot_transfer_on_a_mesh() {
        const CAP: u64 = 512; // small segments so compaction reclaims whole prefix segments
        let mut mesh = Mesh::with_segment_cap(&[1, 2, 3], CAP);
        mesh.elect(1);
        let leader = mesh.leader().expect("leader");

        // Commit a long run of commands across the 3 voters.
        for p in 0..40u64 {
            mesh.nodes
                .get_mut(&leader)
                .unwrap()
                .propose(&MetadataCommand::AssignPartition {
                    partition: p,
                    leader,
                    epoch: 1,
                })
                .expect("propose");
            mesh.run();
        }

        // Add node 4 as a LEARNER through a committed conf change, so the leader knows to replicate
        // to it. (It is not yet in the mesh transport, so it does not actually replicate yet.)
        mesh.change_on_leader(&MembershipChange::new().add_learner(4))
            .expect("add learner 4");

        // SNAPSHOT + COMPACT on every voter, so the prefix the learner needs is physically GONE
        // from the leader's retained log — the only way to catch the learner up is a snapshot.
        for &id in &[1u64, 2u64, 3u64] {
            let _ = mesh.nodes.get_mut(&id).unwrap().create_snapshot();
        }
        assert!(
            mesh.nodes[&leader].snapshot_index() >= 40,
            "the leader compacted past the entries the learner is missing"
        );
        let expected = mesh.nodes[&leader].state().placements();
        assert_eq!(expected.len(), 40);

        // NOW bring the learner online (it joins the mesh transport). It opens far behind (genesis),
        // and the leader's first index is past its next index, so raft-rs must send a SNAPSHOT.
        mesh.add_learner_node(4, &[1, 2, 3], CAP);
        assert!(
            mesh.nodes[&4].state().placements().is_empty(),
            "the joining learner has none of the committed placements yet"
        );

        mesh.run();

        assert_eq!(
            mesh.nodes[&4].state().placements(),
            expected,
            "the far-behind learner converged to the leader's committed state via snapshot catch-up"
        );
        assert!(
            mesh.nodes[&4].snapshot_index() > 0,
            "the learner installed a snapshot (it did not replay the whole log)"
        );
        // No gap / no dup: the learner's applied index reached the leader's committed bar.
        assert_eq!(
            mesh.nodes[&4].applied_index(),
            mesh.nodes[&leader].applied_index(),
            "the learner's applied frontier matches the leader's (no gap, no dup)"
        );
    }

    // --- #872: metadata-Raft FAIL-STOP on a persist/fsync failure in `drive_ready`. ---
    //
    // A metadata-log fsync error inside `drive_ready` leaves the raft-rs `Ready` UN-ADVANCED (a
    // contract violation) and freezes the log's writer read-only. The pre-#872 behavior re-took that
    // never-advanced `Ready` every tick — re-applying committed entries and dropping outbound
    // heartbeats/votes — while the node still advertised as a healthy voter (a silent dead voter).
    // The fix FAIL-STOPS the node's Raft role: it steps down, stops ticking, latches a loud
    // health-failed status, and NEVER re-enters `drive_ready` on the un-advanced `Ready`.
    mod fail_stop_872 {
        use super::{log_config, MetadataCommand, MetadataRaftGroup, NodeRole};
        use ironbus_core::clock::ManualClock;
        use ironbus_storage::fs::{Filesystem, InMemoryFs};
        use ironbus_storage::io::RandomAccessFile;
        use std::io;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        /// A filesystem wrapping [`InMemoryFs`] whose file fsyncs (`sync_data`/`sync_all`) FAIL once
        /// `fail_sync` is armed — the deterministic ENOSPC/EIO-on-fsync seam. A subdir shares the
        /// SAME `fail_sync` flag, so the metadata group's `metaraft/` view faults too.
        #[derive(Clone)]
        struct FaultFs {
            inner: InMemoryFs,
            fail_sync: Arc<AtomicBool>,
        }

        /// A file over [`InMemoryFs`]'s file whose durability barrier fails while `fail_sync` is armed.
        struct FaultFile {
            inner: Arc<ironbus_storage::io::InMemoryFile>,
            fail_sync: Arc<AtomicBool>,
        }

        impl FaultFile {
            fn barrier(&self) -> io::Result<()> {
                if self.fail_sync.load(Ordering::SeqCst) {
                    return Err(io::Error::other(
                        "injected fsync failure (#872 fail-stop test): ENOSPC/EIO on the barrier",
                    ));
                }
                Ok(())
            }
        }

        impl RandomAccessFile for FaultFile {
            fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
                self.inner.read_at(buf, offset)
            }
            fn write_all_at(&self, buf: &[u8], offset: u64) -> io::Result<()> {
                self.inner.write_all_at(buf, offset)
            }
            fn sync_data(&self) -> io::Result<()> {
                self.barrier()?;
                self.inner.sync_data()
            }
            fn sync_all(&self) -> io::Result<()> {
                self.barrier()?;
                self.inner.sync_all()
            }
            fn len(&self) -> io::Result<u64> {
                self.inner.len()
            }
            fn set_len(&self, len: u64) -> io::Result<()> {
                self.inner.set_len(len)
            }
        }

        impl Filesystem for FaultFs {
            type File = FaultFile;
            fn open(&self, name: &str) -> io::Result<Self::File> {
                Ok(FaultFile {
                    inner: self.inner.open(name)?,
                    fail_sync: Arc::clone(&self.fail_sync),
                })
            }
            fn create_new(&self, name: &str) -> io::Result<Self::File> {
                Ok(FaultFile {
                    inner: self.inner.create_new(name)?,
                    fail_sync: Arc::clone(&self.fail_sync),
                })
            }
            fn remove(&self, name: &str) -> io::Result<()> {
                self.inner.remove(name)
            }
            fn list(&self) -> io::Result<Vec<String>> {
                self.inner.list()
            }
            fn exists(&self, name: &str) -> io::Result<bool> {
                self.inner.exists(name)
            }
            fn sync_dir(&self) -> io::Result<()> {
                self.inner.sync_dir()
            }
            fn subdir(&self, name: &str) -> io::Result<Self> {
                Ok(FaultFs {
                    inner: self.inner.subdir(name)?,
                    fail_sync: Arc::clone(&self.fail_sync),
                })
            }
            fn subdir_exists(&self, name: &str) -> io::Result<bool> {
                self.inner.subdir_exists(name)
            }
            fn list_subdirs(&self) -> io::Result<Vec<String>> {
                self.inner.list_subdirs()
            }
        }

        type FaultGroup = MetadataRaftGroup<FaultFs, ManualClock>;

        fn settle(group: &mut FaultGroup) {
            for _ in 0..256 {
                let _ = group.drive_ready().expect("drive ready (fault not armed)");
                if !group.is_health_failed() && !group.has_pending_ready() {
                    break;
                }
                if group.is_health_failed() {
                    break;
                }
            }
        }

        /// The #872 acceptance test. A single-voter metadata group elects itself and applies a
        /// command healthily. Then the metadata-log fsync barrier is armed to FAIL: the next
        /// `drive_ready` (persisting a proposed command) errors AFTER taking the raft-rs `Ready`,
        /// leaving it un-advanced. The node MUST fail-stop — assert (a) it is no longer a healthy
        /// voter/leader, (b) it does not re-enter `drive_ready` on the un-advanced `Ready` (a later
        /// call returns Ok, never re-erroring and never re-applying), and (c) it surfaces the
        /// health-failed status. WITHOUT the fix the node would keep re-taking the never-advanced
        /// `Ready`, re-erroring every tick, and still report `is_leader()`.
        #[test]
        fn a_persist_fsync_failure_fail_stops_the_node_instead_of_silently_wedging() {
            let fail_sync = Arc::new(AtomicBool::new(false));
            let fs = FaultFs {
                inner: InMemoryFs::new(),
                fail_sync: Arc::clone(&fail_sync),
            };
            let mut group = MetadataRaftGroup::open(1, &[1], &fs, ManualClock::new(), log_config())
                .expect("open durable group");

            // Elect + apply a first command HEALTHILY (the fault is not yet armed).
            group.campaign().expect("campaign");
            settle(&mut group);
            assert!(group.is_leader(), "lone voter self-elects while healthy");
            group
                .propose(&MetadataCommand::AddNode {
                    node: 1,
                    role: NodeRole::Voter,
                })
                .expect("propose while healthy");
            settle(&mut group);
            let applied_before = group.applied_index();
            assert!(applied_before > 0, "the first command applied healthily");
            assert!(!group.is_health_failed(), "healthy before the fault");

            // ARM the fsync fault, then propose a command whose persist barrier will fail.
            fail_sync.store(true, Ordering::SeqCst);
            group
                .propose(&MetadataCommand::AssignPartition {
                    partition: 7,
                    leader: 1,
                    epoch: group.term(),
                })
                .expect("propose (append succeeds; the fsync barrier is what fails)");

            // The cycle takes the `Ready`, then the fsync barrier fails -> Err, leaving the `Ready`
            // un-advanced. The group must LATCH the fail-stop.
            let first = group.drive_ready();
            assert!(
                first.is_err(),
                "the armed fsync barrier must fail the ready cycle"
            );
            assert!(
                group.is_health_failed(),
                "(c) the node latches a HEALTH-FAILED status on the persist/fsync failure"
            );
            assert!(
                !group.is_leader(),
                "(a) a fail-stopped node STEPS DOWN — it is no longer a healthy leader/voter"
            );
            assert!(
                !group.can_act_as_leader(),
                "(a) a fail-stopped node may never act as leader"
            );

            // (b) It NEVER re-enters `drive_ready` on the un-advanced `Ready`: even with the fault
            // still armed, a later call returns Ok(empty) (it does not re-take the `Ready`, so it
            // neither re-errors against the frozen writer nor re-applies committed entries).
            let applied_after_faults = group.applied_index();
            for _ in 0..8 {
                let again = group.drive_ready();
                assert!(
                    again.is_ok(),
                    "(b) a fail-stopped node never re-enters the un-advanced ready path"
                );
                assert!(
                    again.expect("ok").is_empty(),
                    "(b) a fail-stopped node produces no outbound work"
                );
            }
            assert_eq!(
                group.applied_index(),
                applied_after_faults,
                "(b) no committed entries are re-applied after fail-stop"
            );

            // Ticking is a no-op: a fail-stopped node drives no elections/heartbeats.
            assert!(!group.tick(), "a fail-stopped node stops ticking");
            assert!(!group.is_leader(), "still stepped down after a tick");
        }
    }
}
