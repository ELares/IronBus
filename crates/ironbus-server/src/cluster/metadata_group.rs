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
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::LogConfig;
use raft::eraftpb::{Entry, EntryType, Message};
use raft::{Config, RawNode, StateRole, Storage as _};
use slog::{o, Discard, Logger};

use crate::cluster::metadata_storage::{MetadataLogStorage, MetadataStorageError};
use crate::cluster::state_machine::{DecodeError, MetadataCommand, MetadataStateMachine};

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
}

impl<F: Filesystem, C: Clock> MetadataRaftGroup<F, C> {
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
        // group; the persisted membership wins on a recovered one.
        let storage = MetadataLogStorage::open(parent_fs, clock, config, voters)?;
        // default-logger is disabled; discard raft-rs's own slog output.
        let logger = Logger::root(Discard, o!());
        let node = RawNode::new(&raft_config, storage, &logger)?;

        Ok(Self {
            node,
            state: MetadataStateMachine::new(),
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

    /// The current Raft term (the cluster-wide monotonic leader epoch; exposing it to the
    /// broker as the per-partition fencing token is C1-I3).
    #[must_use]
    pub fn term(&self) -> u64 {
        self.node.raft.term
    }

    /// The applied view of the replicated control plane.
    #[must_use]
    pub fn state(&self) -> &MetadataStateMachine {
        &self.state
    }

    /// Drive the election timer by one tick. Returns true if the tick produced new work
    /// (a `Ready` to drain). At n=1 a single tick window elapsing makes the lone voter
    /// elect itself.
    pub fn tick(&mut self) -> bool {
        self.node.tick()
    }

    /// Campaign to become leader immediately (used at n=1 / in tests to avoid waiting out
    /// the election timer).
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::Raft`] if the core rejects the campaign.
    pub fn campaign(&mut self) -> Result<(), GroupError> {
        self.node.campaign()?;
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

        Ok(outbound)
    }

    /// Fold a batch of committed entries into the state machine. Empty entries (the no-op a
    /// new leader commits to establish its term) and config-change entries are skipped here
    /// — config changes are applied to the conf state in C1-I4, not the metadata SM.
    fn apply_committed(&mut self, entries: Vec<Entry>) -> Result<(), GroupError> {
        for entry in entries {
            if entry.data.is_empty() {
                // A leader's empty no-op entry: nothing to apply, but it advances the index.
                continue;
            }
            match entry.get_entry_type() {
                EntryType::EntryNormal => {
                    self.state.apply_encoded(entry.index, &entry.data)?;
                }
                EntryType::EntryConfChange | EntryType::EntryConfChangeV2 => {
                    // Membership changes are C1-I4; ignore for C1-I1.
                }
            }
        }
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
            Some(Placement {
                leader: 1,
                epoch: group.term()
            })
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
                Some(Placement {
                    leader: 1,
                    epoch: 1
                })
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
            Some(Placement {
                leader: 1,
                epoch: 1
            }),
            "the committed placement must survive a reopen of the durable group"
        );
    }
}
