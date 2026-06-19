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
//! ## Scope (C1-I1 only)
//!
//! This issue proves the vendored-codec raft-rs builds clean under every IronBus gate and
//! that a metadata group is *constructible and self-consistent* in memory:
//!
//! * storage is the in-memory `raft::storage::MemStorage` (the durable IronBus-log
//!   `Storage` is **C1-I2**);
//! * there is no peer transport, no membership change, no leader-epoch exposure, and no
//!   wiring into the append actor (those are **C1-I3 / C1-I4** and later);
//! * crucially, this module is NOT yet referenced by the running broker, so adding it does
//!   not change the single-node binary's behavior or on-disk layout.
//!
//! What it does do: construct a group, drive a `tick`/`step`/`propose`/`ready` round-trip,
//! and fold committed entries into the state machine — enough to prove the wiring end to
//! end on `MemStorage`.

use raft::eraftpb::{Entry, EntryType, Message};
use raft::storage::MemStorage;
use raft::{Config, RawNode, StateRole};
use slog::{o, Discard, Logger};

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

/// The supported metadata group sizes. Odd sizes only, so a single partition cannot split
/// the vote; capped at 5 (the design's metadata group is small by construction — one group
/// for the cluster, not per-asset).
const SUPPORTED_VOTER_COUNTS: [usize; 3] = [1, 3, 5];

/// An embedded metadata Raft group: a `RawNode` over `MemStorage` plus the applied
/// [`MetadataStateMachine`]. Synchronous and caller-driven.
pub struct MetadataRaftGroup {
    node: RawNode<MemStorage>,
    state: MetadataStateMachine,
}

impl MetadataRaftGroup {
    /// Construct a metadata group for `node_id` over the `voters` set.
    ///
    /// `voters` must be one of the supported sizes (1, 3, or 5) and must contain
    /// `node_id`. Storage is the in-memory `MemStorage` seeded with the voter `ConfState`
    /// (the durable IronBus-log storage is C1-I2). No logger is attached (default-logger is
    /// off): raft-rs logs are discarded for now; bridging `slog` to `tracing` is deferred.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::UnsupportedVoterCount`] for a bad size,
    /// [`GroupError::SelfNotAVoter`] if `node_id` is not a voter, or [`GroupError::Raft`]
    /// if the raft-rs config fails to validate.
    pub fn new(node_id: u64, voters: &[u64]) -> Result<Self, GroupError> {
        let n = voters.len();
        if !SUPPORTED_VOTER_COUNTS.contains(&n) {
            return Err(GroupError::UnsupportedVoterCount(n));
        }
        if !voters.contains(&node_id) {
            return Err(GroupError::SelfNotAVoter { node_id });
        }

        let config = Config {
            id: node_id,
            // Standard etcd-style ratio (heartbeat every tick window, election ~10x).
            election_tick: 10,
            heartbeat_tick: 3,
            ..Default::default()
        };
        config.validate()?;

        let storage = MemStorage::new_with_conf_state((voters.to_vec(), vec![]));
        // default-logger is disabled; discard raft-rs's own slog output for C1-I1.
        let logger = Logger::root(Discard, o!());
        let node = RawNode::new(&config, storage, &logger)?;

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

    /// Run one full `ready` cycle: persist the `Ready` (entries, hard state, snapshot) into
    /// `MemStorage`, hand outbound messages to the (currently absent) transport, then
    /// `advance` and apply the committed entries into the state machine.
    ///
    /// Returns the outbound messages the caller's transport should send (empty at n=1).
    ///
    /// This is the persist-before-advance contract raft-rs requires; with the durable
    /// IronBus-log storage (C1-I2) the persist step becomes the group-commit fsync barrier.
    ///
    /// # Errors
    ///
    /// Returns [`GroupError::Raft`] on a storage append failure or [`GroupError::Decode`]
    /// if a committed entry's bytes are not a valid metadata command.
    pub fn drive_ready(&mut self) -> Result<Vec<Message>, GroupError> {
        if !self.node.has_ready() {
            return Ok(Vec::new());
        }

        let mut ready = self.node.ready();

        // 1. Outbound messages to peers (none at n=1) — collected for the caller.
        let mut outbound = ready.take_messages();

        // 2. Apply a snapshot if present (none in C1-I1's flows, but handle it for safety).
        if !ready.snapshot().is_empty() {
            let snap = ready.snapshot().clone();
            self.node.store().wl().apply_snapshot(snap)?;
        }

        // 3. Apply committed entries that came with this Ready (after a snapshot, or once
        //    already-persisted entries commit).
        self.apply_committed(ready.take_committed_entries())?;

        // 4. Persist newly-appended (uncommitted) entries to storage.
        if !ready.entries().is_empty() {
            self.node.store().wl().append(ready.entries())?;
        }

        // 5. Persist the hard state (term / vote / commit) if it changed.
        if let Some(hs) = ready.hs() {
            self.node.store().wl().set_hardstate(hs.clone());
        }

        // 6. Persisted messages (for async-append flows) — also handed to the transport.
        outbound.extend(ready.take_persisted_messages());

        // 7. Advance the core; the LightReady carries entries that committed as a result.
        let mut light = self.node.advance(ready);
        if let Some(commit) = light.commit_index() {
            self.node.store().wl().mut_hard_state().commit = commit;
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
    use crate::cluster::state_machine::NodeRole;

    /// Drive the group until it has settled (no more pending Ready), bounded so a bug can't
    /// hang the test.
    fn settle(group: &mut MetadataRaftGroup) {
        for _ in 0..256 {
            let _ = group.drive_ready().expect("drive ready");
            if !group.node.has_ready() {
                break;
            }
        }
    }

    #[test]
    fn unsupported_voter_count_is_rejected() {
        assert!(matches!(
            MetadataRaftGroup::new(1, &[1, 2]),
            Err(GroupError::UnsupportedVoterCount(2))
        ));
        assert!(matches!(
            MetadataRaftGroup::new(1, &[]),
            Err(GroupError::UnsupportedVoterCount(0))
        ));
    }

    #[test]
    fn self_must_be_a_voter() {
        assert!(matches!(
            MetadataRaftGroup::new(9, &[1, 2, 3]),
            Err(GroupError::SelfNotAVoter { node_id: 9 })
        ));
    }

    #[test]
    fn constructs_for_one_three_and_five_voters() {
        assert!(MetadataRaftGroup::new(1, &[1]).is_ok());
        assert!(MetadataRaftGroup::new(2, &[1, 2, 3]).is_ok());
        assert!(MetadataRaftGroup::new(5, &[1, 2, 3, 4, 5]).is_ok());
    }

    /// The C1-I1 acceptance test: a single-voter group constructs, elects itself via
    /// tick/ready, and a proposed command round-trips through propose -> step/tick ->
    /// ready -> apply into the state machine on `MemStorage`.
    #[test]
    fn single_node_group_propose_tick_ready_roundtrips_on_memstorage() {
        let mut group = MetadataRaftGroup::new(1, &[1]).expect("construct");
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
            Some(crate::cluster::state_machine::Placement {
                leader: 1,
                epoch: group.term()
            })
        );
        assert!(group.state().applied_index() > prev_index);
    }

    #[test]
    fn tick_drives_election_without_explicit_campaign() {
        let mut group = MetadataRaftGroup::new(1, &[1]).expect("construct");
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
}
