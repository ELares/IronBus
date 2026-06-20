// SPDX-License-Identifier: MIT OR Apache-2.0
//! Joint-consensus membership changes, learners, and peer-id validation (V2-C1, #584).
//!
//! This is C1-I4: it turns the metadata Raft group's static voter set into a *changeable*
//! membership, safely. Three things ship here, all of them ON TOP of the production
//! tikv/raft-rs core (no hand-rolled consensus — the joint-config mechanics are raft-rs's):
//!
//! * **Joint-consensus membership changes.** Adding or removing a voter is proposed as a
//!   raft-rs [`ConfChangeV2`](raft::eraftpb::ConfChangeV2) — the Joint Consensus mechanism
//!   (Raft §6). While the change is in flight the cluster is in a *joint* configuration whose
//!   quorum requires a majority of BOTH the old and the new voter sets, so the old and new
//!   majorities always overlap and a single configuration change can never split the cluster
//!   into two disjoint majorities. The change is proposed through the metadata raft log
//!   (durable via #659) and applied to the `ConfState` + the metadata state machine.
//! * **Learners.** A new node joins as a NON-VOTING learner first
//!   ([`MembershipChange::add_learner`]): it receives the log and back-fills but never counts
//!   toward quorum. Once it has caught up it is promoted to a voter
//!   ([`MembershipChange::promote_learner`]) via a second conf change. (The actual over-the-wire
//!   catch-up / snapshot transfer is PEER TRANSPORT, issue #667 — NOT here; this issue
//!   implements the learner ROLE + the promotion, which is the membership-state-machine /
//!   conf-change half.)
//! * **Peer-id validation (the #6403 fix).** Before ANY membership change is proposed, the
//!   proposed peer identities are validated against the current membership:
//!   [`validate_change`] rejects a mangled (id 0 / `INVALID_ID`), duplicate, or phantom peer
//!   with a typed [`PeerIdError`]. This is the safety property NATS lacked
//!   ([nats-server #6403](https://github.com/nats-io/nats-server/issues/6403)): a meta group
//!   that can never elect a leader because a mangled / phantom peer inflated or corrupted the
//!   voter set. raft-rs's own `Changer` *silently ignores* a `node_id == 0` change (it treats
//!   it as a downstream no-op), so a bad id would otherwise slip into the log as a degenerate
//!   entry — we reject it at the propose seam instead, so a bad peer-id can never enter the
//!   metadata log, let alone freeze quorum.
//!
//! ## What is and is NOT parsed from a peer
//!
//! A membership change is *proposed locally* through the raft log API — it is built from
//! caller-supplied node ids ([`MembershipChange`]), not by parsing an untrusted peer's wire
//! bytes. So this issue introduces NO new untrusted-peer-byte parsing: the RUSTSEC-2024-0437
//! advisory ignore stays scoped to the peer-transport issue (#667), unchanged here.
//!
//! ## n=1
//!
//! At n=1 the group is a 1-voter configuration; a membership change is degenerate but must be
//! CORRECT. Adding the 2nd member (as a learner, then promoting it; or directly as a voter) is
//! the first *real* joint-consensus change and is exercised by the tests.

use std::collections::BTreeSet;

use raft::eraftpb::{ConfChangeSingle, ConfChangeType, ConfChangeV2, ConfState};

use super::state_machine::NodeRole;

/// raft-rs's `INVALID_ID`: node id `0` is reserved (`raft::INVALID_ID`) and is never a valid
/// peer. A conf change that names it is a *mangled* peer — raft-rs would silently drop it, so
/// we reject it up front (the #6403-class fix).
pub const INVALID_PEER_ID: u64 = 0;

/// One requested membership mutation, in IronBus's own vocabulary (independent of raft-rs's
/// `ConfChangeSingle` so the validation can reason about it before it ever becomes a conf
/// change). A [`MembershipChange`] is an ordered list of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberOp {
    /// Add `node` (or promote it from learner) to be a VOTER in the new configuration.
    AddVoter { node: u64 },
    /// Add `node` as a NON-VOTING learner: it receives the log but never counts toward quorum
    /// until a later [`MemberOp::PromoteLearner`].
    AddLearner { node: u64 },
    /// Promote an existing learner `node` to a voter (the catch-up→promote path).
    PromoteLearner { node: u64 },
    /// Remove `node` from the configuration entirely.
    RemoveNode { node: u64 },
}

impl MemberOp {
    /// The node id this op touches.
    #[must_use]
    pub fn node(self) -> u64 {
        match self {
            MemberOp::AddVoter { node }
            | MemberOp::AddLearner { node }
            | MemberOp::PromoteLearner { node }
            | MemberOp::RemoveNode { node } => node,
        }
    }

    /// The raft-rs `ConfChangeSingle` this op encodes to. (`AddVoter` and `PromoteLearner`
    /// both encode to `AddNode`: in raft-rs adding a node that is already a learner promotes
    /// it; adding a fresh node makes it a voter — `make_voter` handles both.)
    fn to_single(self) -> ConfChangeSingle {
        let (node, ty) = match self {
            MemberOp::AddVoter { node } | MemberOp::PromoteLearner { node } => {
                (node, ConfChangeType::AddNode)
            }
            MemberOp::AddLearner { node } => (node, ConfChangeType::AddLearnerNode),
            MemberOp::RemoveNode { node } => (node, ConfChangeType::RemoveNode),
        };
        ConfChangeSingle {
            node_id: node,
            change_type: ty,
            ..Default::default()
        }
    }
}

/// A requested membership change: an ordered, non-empty list of [`MemberOp`]s applied
/// atomically as one joint-consensus transition. A change touching >1 voter (or any change the
/// caller marks must use joint consensus) goes through the joint configuration; raft-rs decides
/// the simple-vs-joint protocol from the change shape (`ConfChangeV2::enter_joint`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MembershipChange {
    ops: Vec<MemberOp>,
}

impl MembershipChange {
    /// An empty change builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a voter (or promote an existing learner) in this change.
    #[must_use]
    pub fn add_voter(mut self, node: u64) -> Self {
        self.ops.push(MemberOp::AddVoter { node });
        self
    }

    /// Add a non-voting learner in this change.
    #[must_use]
    pub fn add_learner(mut self, node: u64) -> Self {
        self.ops.push(MemberOp::AddLearner { node });
        self
    }

    /// Promote an existing learner to a voter in this change.
    #[must_use]
    pub fn promote_learner(mut self, node: u64) -> Self {
        self.ops.push(MemberOp::PromoteLearner { node });
        self
    }

    /// Remove a node in this change.
    #[must_use]
    pub fn remove_node(mut self, node: u64) -> Self {
        self.ops.push(MemberOp::RemoveNode { node });
        self
    }

    /// The ops in this change.
    #[must_use]
    pub fn ops(&self) -> &[MemberOp] {
        &self.ops
    }

    /// True if this change is empty (no ops). An empty change is never proposed; the empty
    /// `ConfChangeV2` raft-rs uses to LEAVE a joint configuration is produced internally by the
    /// group, not via this builder.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Encode this (already-validated) change to a raft-rs [`ConfChangeV2`].
    ///
    /// The transition is left `Auto` (the default): raft-rs then uses the *simple* protocol for
    /// a lone single change and *joint consensus* for a multi-op change — `ConfChangeV2::enter_joint`
    /// is the authority. A multi-voter change therefore always goes through the joint
    /// configuration (overlapping old+new majorities, Raft §6).
    #[must_use]
    pub fn to_conf_change_v2(&self) -> ConfChangeV2 {
        let mut cc = ConfChangeV2::default();
        let changes: Vec<ConfChangeSingle> = self.ops.iter().map(|op| op.to_single()).collect();
        cc.set_changes(changes.into());
        cc
    }
}

/// A typed peer-id / membership-change validation failure — the #6403-class rejections. Every
/// variant means the change was REFUSED before it could enter the metadata log, so a mangled /
/// duplicate / phantom peer can never reach consensus and freeze quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdError {
    /// The change had no ops. An empty membership change is meaningless (the empty conf change
    /// that leaves a joint config is internal, never caller-proposed).
    EmptyChange,
    /// A peer id was the reserved `INVALID_ID` (0) — a mangled peer. raft-rs would silently
    /// drop it; we reject it.
    MangledPeerId,
    /// The same node id appears more than once within a single change — a duplicate peer that
    /// would make the resulting configuration ambiguous.
    DuplicatePeerId { node: u64 },
    /// An add/learner op named a node that is ALREADY in the configuration (a phantom re-add
    /// that does not match its current role): adding an existing voter as a voter, or an
    /// existing learner as a learner, is a no-op-or-worse and is rejected so membership stays
    /// unambiguous. (Promotion of a learner to a voter is a *distinct*, allowed op.)
    AlreadyPresent { node: u64, role: NodeRole },
    /// A remove/promote op named a node that is NOT in the configuration — a phantom peer the
    /// cluster has never heard of. Removing or promoting a non-member is rejected.
    NotAMember { node: u64 },
    /// A promote op named a node that is a member but is already a VOTER (nothing to promote).
    NotALearner { node: u64 },
    /// The change would remove the LAST voter (leaving a zero-voter configuration that can
    /// never elect a leader — a self-inflicted quorum freeze).
    WouldRemoveLastVoter,
}

impl core::fmt::Display for PeerIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PeerIdError::EmptyChange => write!(f, "membership change has no operations"),
            PeerIdError::MangledPeerId => {
                write!(
                    f,
                    "membership change names the reserved peer id 0 (INVALID_ID)"
                )
            }
            PeerIdError::DuplicatePeerId { node } => {
                write!(f, "membership change names node {node} more than once")
            }
            PeerIdError::AlreadyPresent { node, role } => {
                write!(f, "node {node} is already a {role:?} in the configuration")
            }
            PeerIdError::NotAMember { node } => {
                write!(f, "node {node} is not a member of the configuration")
            }
            PeerIdError::NotALearner { node } => {
                write!(f, "node {node} is a voter, not a learner to promote")
            }
            PeerIdError::WouldRemoveLastVoter => {
                write!(f, "membership change would remove the last voter")
            }
        }
    }
}

impl std::error::Error for PeerIdError {}

/// The current membership, projected from a raft-rs [`ConfState`], that a change is validated
/// against. Both the *incoming* and *outgoing* voter sets of a (possibly joint) config are
/// considered members, so a change proposed mid-joint-transition still validates against the
/// full set; learners (and `learners_next`, the staged learners) are members too.
struct MembershipView {
    voters: BTreeSet<u64>,
    learners: BTreeSet<u64>,
}

impl MembershipView {
    fn from_conf_state(cs: &ConfState) -> Self {
        let mut voters: BTreeSet<u64> = cs.voters.iter().copied().collect();
        // The outgoing majority of a joint config is still a member set we must respect.
        voters.extend(cs.voters_outgoing.iter().copied());
        let mut learners: BTreeSet<u64> = cs.learners.iter().copied().collect();
        learners.extend(cs.learners_next.iter().copied());
        Self { voters, learners }
    }

    fn is_voter(&self, node: u64) -> bool {
        self.voters.contains(&node)
    }

    fn is_learner(&self, node: u64) -> bool {
        self.learners.contains(&node)
    }

    fn is_member(&self, node: u64) -> bool {
        self.is_voter(node) || self.is_learner(node)
    }

    /// The number of voters that would remain after `change` applies — used to refuse a change
    /// that empties the voter set. (Promotions add a voter; removes of a voter drop one; adding
    /// a learner does not change the voter count.)
    fn voters_after(&self, change: &MembershipChange) -> usize {
        let mut voters = self.voters.clone();
        for op in change.ops() {
            match op {
                MemberOp::AddVoter { node } | MemberOp::PromoteLearner { node } => {
                    voters.insert(*node);
                }
                MemberOp::RemoveNode { node } => {
                    voters.remove(node);
                }
                MemberOp::AddLearner { .. } => {}
            }
        }
        voters.len()
    }
}

/// Validate a membership `change` against the current `conf_state` BEFORE it is proposed — the
/// #6403 fix. Returns `Ok(())` only if every named peer id is well-formed and consistent with
/// the current membership; otherwise a typed [`PeerIdError`] that the caller surfaces and the
/// change is NEVER proposed (so a bad peer-id cannot enter the metadata log).
///
/// The rules, in order:
/// 1. the change is non-empty;
/// 2. no op names the reserved `INVALID_ID` (0) — a mangled peer;
/// 3. no node id appears twice in the change — a duplicate peer;
/// 4. an `AddVoter`/`AddLearner` does not re-add a node already in that exact role;
/// 5. a `PromoteLearner` names an existing LEARNER (a member, and not already a voter);
/// 6. a `RemoveNode` names an existing member;
/// 7. the change does not remove the last voter (a zero-voter quorum freeze).
///
/// # Errors
///
/// Returns the first [`PeerIdError`] the change violates.
pub fn validate_change(
    change: &MembershipChange,
    conf_state: &ConfState,
) -> Result<(), PeerIdError> {
    if change.is_empty() {
        return Err(PeerIdError::EmptyChange);
    }

    let view = MembershipView::from_conf_state(conf_state);

    // (2) + (3): no mangled id, no duplicate id within the change.
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for op in change.ops() {
        let node = op.node();
        if node == INVALID_PEER_ID {
            return Err(PeerIdError::MangledPeerId);
        }
        if !seen.insert(node) {
            return Err(PeerIdError::DuplicatePeerId { node });
        }
    }

    // (4)–(6): each op must be consistent with the CURRENT membership.
    for op in change.ops() {
        match *op {
            MemberOp::AddVoter { node } => {
                // Re-adding an existing voter is a phantom re-add. (Promoting a learner to a
                // voter is the distinct PromoteLearner op, not AddVoter.)
                if view.is_voter(node) {
                    return Err(PeerIdError::AlreadyPresent {
                        node,
                        role: NodeRole::Voter,
                    });
                }
            }
            MemberOp::AddLearner { node } => {
                if view.is_learner(node) {
                    return Err(PeerIdError::AlreadyPresent {
                        node,
                        role: NodeRole::Learner,
                    });
                }
                if view.is_voter(node) {
                    // Adding an existing voter "as a learner" is a demotion masquerading as an
                    // add; reject it as a phantom re-add (demotion would be its own op).
                    return Err(PeerIdError::AlreadyPresent {
                        node,
                        role: NodeRole::Voter,
                    });
                }
            }
            MemberOp::PromoteLearner { node } => {
                if !view.is_member(node) {
                    return Err(PeerIdError::NotAMember { node });
                }
                if !view.is_learner(node) {
                    return Err(PeerIdError::NotALearner { node });
                }
            }
            MemberOp::RemoveNode { node } => {
                if !view.is_member(node) {
                    return Err(PeerIdError::NotAMember { node });
                }
            }
        }
    }

    // (7): never empty the voter set.
    if view.voters_after(change) == 0 {
        return Err(PeerIdError::WouldRemoveLastVoter);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cs(voters: &[u64], learners: &[u64]) -> ConfState {
        ConfState {
            voters: voters.to_vec(),
            learners: learners.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn add_voter_to_a_one_voter_group_is_valid_and_uses_joint_consensus_when_multi() {
        let conf = cs(&[1], &[]);
        // The first real joint change: add the 2nd voter directly.
        let change = MembershipChange::new().add_voter(2);
        assert!(validate_change(&change, &conf).is_ok());

        // A single op uses the simple protocol; a multi-op change enters joint consensus.
        assert!(change.to_conf_change_v2().enter_joint().is_none());
        let multi = MembershipChange::new().add_voter(2).add_voter(3);
        assert_eq!(multi.to_conf_change_v2().enter_joint(), Some(true));
    }

    #[test]
    fn mangled_peer_id_zero_is_rejected() {
        let conf = cs(&[1], &[]);
        let change = MembershipChange::new().add_voter(INVALID_PEER_ID);
        assert_eq!(
            validate_change(&change, &conf),
            Err(PeerIdError::MangledPeerId)
        );
    }

    #[test]
    fn duplicate_peer_id_within_a_change_is_rejected() {
        let conf = cs(&[1], &[]);
        let change = MembershipChange::new().add_voter(2).remove_node(2);
        assert_eq!(
            validate_change(&change, &conf),
            Err(PeerIdError::DuplicatePeerId { node: 2 })
        );
    }

    #[test]
    fn phantom_remove_of_a_non_member_is_rejected() {
        let conf = cs(&[1, 2, 3], &[]);
        let change = MembershipChange::new().remove_node(99);
        assert_eq!(
            validate_change(&change, &conf),
            Err(PeerIdError::NotAMember { node: 99 })
        );
    }

    #[test]
    fn re_adding_an_existing_voter_is_rejected_as_already_present() {
        let conf = cs(&[1, 2, 3], &[]);
        let change = MembershipChange::new().add_voter(2);
        assert_eq!(
            validate_change(&change, &conf),
            Err(PeerIdError::AlreadyPresent {
                node: 2,
                role: NodeRole::Voter
            })
        );
    }

    #[test]
    fn add_learner_then_promote_is_valid_but_promoting_a_voter_is_not() {
        // Add a learner (4) to a 3-voter group: valid.
        let conf = cs(&[1, 2, 3], &[]);
        let add = MembershipChange::new().add_learner(4);
        assert!(validate_change(&add, &conf).is_ok());

        // With 4 now a learner, promotion is valid.
        let conf2 = cs(&[1, 2, 3], &[4]);
        let promote = MembershipChange::new().promote_learner(4);
        assert!(validate_change(&promote, &conf2).is_ok());

        // Promoting a node that is already a voter is rejected.
        let promote_voter = MembershipChange::new().promote_learner(2);
        assert_eq!(
            validate_change(&promote_voter, &conf2),
            Err(PeerIdError::NotALearner { node: 2 })
        );

        // Promoting a non-member is rejected as a phantom peer.
        let promote_phantom = MembershipChange::new().promote_learner(77);
        assert_eq!(
            validate_change(&promote_phantom, &conf2),
            Err(PeerIdError::NotAMember { node: 77 })
        );
    }

    #[test]
    fn re_adding_an_existing_learner_is_rejected() {
        let conf = cs(&[1, 2, 3], &[4]);
        let change = MembershipChange::new().add_learner(4);
        assert_eq!(
            validate_change(&change, &conf),
            Err(PeerIdError::AlreadyPresent {
                node: 4,
                role: NodeRole::Learner
            })
        );
    }

    #[test]
    fn removing_the_last_voter_is_rejected() {
        let conf = cs(&[1], &[]);
        let change = MembershipChange::new().remove_node(1);
        assert_eq!(
            validate_change(&change, &conf),
            Err(PeerIdError::WouldRemoveLastVoter)
        );
    }

    #[test]
    fn remove_one_of_several_voters_via_joint_consensus_is_valid() {
        let conf = cs(&[1, 2, 3], &[]);
        let change = MembershipChange::new().remove_node(3);
        assert!(validate_change(&change, &conf).is_ok());
    }

    #[test]
    fn empty_change_is_rejected() {
        let conf = cs(&[1], &[]);
        assert_eq!(
            validate_change(&MembershipChange::new(), &conf),
            Err(PeerIdError::EmptyChange)
        );
    }

    #[test]
    fn validation_respects_a_joint_configs_outgoing_voters() {
        // A joint config: incoming {1,2,4}, outgoing {1,2,3}. Node 3 is still a member (it is in
        // the outgoing majority), so removing it is valid and re-adding it as a voter is not.
        let conf = ConfState {
            voters: vec![1, 2, 4],
            voters_outgoing: vec![1, 2, 3],
            ..Default::default()
        };
        assert!(validate_change(&MembershipChange::new().remove_node(3), &conf).is_ok());
        assert_eq!(
            validate_change(&MembershipChange::new().add_voter(3), &conf),
            Err(PeerIdError::AlreadyPresent {
                node: 3,
                role: NodeRole::Voter
            })
        );
    }
}
