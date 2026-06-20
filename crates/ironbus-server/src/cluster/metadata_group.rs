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

use crate::cluster::membership::{validate_change, MembershipChange, PeerIdError};
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

impl std::error::Error for GroupError {}

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
        let storage = MetadataLogStorage::open(parent_fs, clock.clone(), config, voters)?;
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

        Ok(Self {
            node,
            state: MetadataStateMachine::new(),
            clock,
            leadership,
        })
    }

    /// The node id of this group member.
    #[must_use]
    pub fn node_id(&self) -> u64 {
        self.node.raft.id
    }

    /// True if this node currently believes itself the leader.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.node.raft.state == StateRole::Leader
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
        self.leadership
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
    pub fn drive_ready(&mut self) -> Result<Vec<Message>, GroupError> {
        if !self.node.has_ready() {
            return Ok(Vec::new());
        }

        let mut ready = self.node.ready();

        // 1. Outbound messages to peers (none at n=1) — collected for the caller.
        let mut outbound = ready.take_messages();

        // 2. Apply a snapshot if present (handled for safety; not produced in the n=1 flows).
        //    A snapshot replaces the durable log prefix; that is C1-I2's compaction follow-up,
        //    so for now we surface it as an error rather than silently dropping it (the
        //    metadata group's current flows never emit one).
        if !ready.snapshot().is_empty() {
            return Err(GroupError::Raft(raft::Error::Store(
                raft::StorageError::SnapshotTemporarilyUnavailable,
            )));
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
            let mut nodes = std::collections::BTreeMap::new();
            for &id in voters {
                // Each node gets its OWN fs (its own durable metaraft/ image).
                let fs = InMemoryFs::new();
                let group =
                    MetadataRaftGroup::open(id, voters, &fs, ManualClock::new(), log_config())
                        .expect("open mesh node");
                // Leak the fs into the group's storage lifetime: the group owns its log, and the
                // InMemoryFs is reference-counted internally, so we just drop our handle.
                nodes.insert(id, group);
            }
            Self { nodes }
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
        /// and pump messages until a full pass routes nothing and no node has pending work. The
        /// per-pass pump is itself iterated so a message produced by one node's `step` is drained
        /// and routed in the same pass — important so a leader's just-appended entry (e.g. the
        /// auto-appended LEAVE-JOINT conf change) replicates and commits within `run`. Bounded by
        /// generous fuel so a bug cannot hang the test.
        fn run(&mut self) {
            for _ in 0..1024 {
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
                    break;
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
}
