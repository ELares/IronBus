// SPDX-License-Identifier: MIT OR Apache-2.0
//! The metadata state machine: the deterministic, replicated cluster control plane.
//!
//! This is the application state machine that sits behind the embedded metadata Raft
//! group (V2-C1, #578). It holds the four pieces of cluster metadata the design names:
//!
//! * **cluster membership** — the set of nodes and the role (voter / learner) of each;
//! * **partition placement** — which node currently leads each partition;
//! * **leader epoch** — the per-partition monotonic term assigned at placement time
//!   (the fencing token a later issue, C1-I3, pairs with the lease clock);
//! * **config** — opaque cluster-wide configuration key/value entries.
//!
//! It is deliberately a plain, synchronous, allocation-only Rust type with NO IO and NO
//! Raft dependency: committed Raft entries are decoded into a [`MetadataCommand`] and
//! `apply`-ed here. Keeping the state machine free of `raft` types means the membership /
//! placement / epoch model can later be shared with IO-free code if needed, and it makes
//! the apply path trivially unit-testable without standing up a `RawNode`.
//!
//! The wire form of a command is a small, explicit, length-prefixed little-endian binary
//! encoding (the same hand-rolled, zero-dependency style as `ironbus-proto`), so a
//! committed log entry's bytes have one canonical meaning across nodes and the codec adds
//! no new dependency. It is intentionally minimal for C1-I1; the real durable framing
//! (and reuse of the `ironbus-storage` CRC-framed log) is C1-I2.

use std::collections::BTreeMap;

/// The role a node plays in the metadata Raft group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeRole {
    /// A full voting member: counts toward quorum.
    Voter,
    /// A non-voting learner: receives the log and back-fills, but never counts toward
    /// quorum until promoted (the C1-I4 join path).
    Learner,
}

impl NodeRole {
    const fn tag(self) -> u8 {
        match self {
            NodeRole::Voter => 0,
            NodeRole::Learner => 1,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(NodeRole::Voter),
            1 => Some(NodeRole::Learner),
            _ => None,
        }
    }
}

/// The current placement of a single partition: the ordered set of `R` replica nodes that hold
/// it, which one of them leads it, and under which monotonic leader epoch. The epoch is the
/// fencing token (a stale leader's writes are rejected once a higher epoch exists); exposing it
/// to the broker is C1-I3.
///
/// `replicas` is the ordered replica set the C5-I1 placement policy
/// ([`ironbus_core::placement`]) decided — `R` distinct nodes spread across failure domains, the
/// leader first. The `leader` is always one of `replicas` and is always an ELIGIBLE replica
/// (#700: in-ISR, complete, non-divergent), because the policy only ever designates an eligible
/// replica leader.
///
/// For BACKWARD compatibility, a [`MetadataCommand::AssignPartition`] (the C1 leader-only command,
/// which carries no replica set) yields a placement whose `replicas` is just `[leader]` — the
/// single-node degenerate shape, unchanged on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The ordered set of replica node ids that hold this partition (leader first). For an
    /// `AssignPartition` (leader-only) command this is `[leader]`.
    pub replicas: Vec<u64>,
    /// The node id currently designated leader for the partition (always one of `replicas`, always
    /// an eligible replica).
    pub leader: u64,
    /// The monotonic leadership epoch assigned at this placement.
    pub epoch: u64,
}

impl Placement {
    /// A leader-only placement: the single-node / `AssignPartition` degenerate shape, whose replica
    /// set is exactly `[leader]`.
    #[must_use]
    pub fn leader_only(leader: u64, epoch: u64) -> Self {
        Placement {
            replicas: vec![leader],
            leader,
            epoch,
        }
    }

    /// The replication factor (number of replica nodes holding this partition).
    #[must_use]
    pub fn replication_factor(&self) -> usize {
        self.replicas.len()
    }
}

/// One deterministic mutation of the metadata state machine. A committed Raft log entry's
/// data is exactly one encoded `MetadataCommand`; `apply` folds it into the state. The set
/// is intentionally small for C1-I1 (membership add/remove, placement assign, config set);
/// joint-consensus membership and learner promotion drive these from C1-I4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataCommand {
    /// Add (or re-role) a node in the membership table.
    AddNode { node: u64, role: NodeRole },
    /// Remove a node from the membership table.
    RemoveNode { node: u64 },
    /// Assign `partition` to `leader` at `epoch` (placement + leader-epoch in one step). The
    /// leader-only C1 command: it carries no replica set, so it yields a placement whose replicas
    /// are exactly `[leader]`. Retained for backward compatibility and the n=1 degenerate case.
    AssignPartition {
        partition: u64,
        leader: u64,
        epoch: u64,
    },
    /// Place `partition`'s full replica set (the C5-I1 command): the ordered `replicas` the
    /// placement policy decided, the `leader` among them (always an eligible replica), and the
    /// monotonic `epoch`. This commits a whole placement — `R` replicas + a balanced eligible
    /// leader — through the metadata log as ONE entry (not a per-partition Raft group).
    ///
    /// The leader MUST be one of `replicas` (the placement policy guarantees this); a command whose
    /// leader is absent from its replica set is rejected at decode time
    /// ([`DecodeError::LeaderNotAReplica`]) so a malformed placement can never enter the state.
    PlacePartition {
        partition: u64,
        replicas: Vec<u64>,
        leader: u64,
        epoch: u64,
    },
    /// Set a cluster-wide configuration key to a value.
    SetConfig { key: String, value: String },
    /// CHECKPOINT the last-known quorum-committed high-watermark for `partition` into the replicated
    /// metadata (#618b committed-data-loss fix). The data-plane LEADER proposes this PERIODICALLY (on a
    /// cadence — NOT per record; cheap + bounded), so the committed bar SURVIVES the leader's death: a
    /// surviving node reads this checkpoint and knows the SAFE offset a successor MUST hold before it may
    /// be auto-promoted. `offset` is the committed HW (every offset strictly below it was quorum-fsync'd
    /// on `min_isr` replicas). It is MONOTONIC per partition in the state machine — a stale/lower
    /// checkpoint never lowers the bar, so the bar can only ever rise (a successor must always clear the
    /// highest committed HW the cluster ever durably recorded).
    CheckpointCommittedHw { partition: u64, offset: u64 },
}

/// Errors from decoding a [`MetadataCommand`] off a committed log entry's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer ended before a fully-formed command was read.
    Truncated,
    /// The leading command tag is not a known variant.
    UnknownTag(u8),
    /// A node-role byte is not a known role.
    UnknownRole(u8),
    /// A length-prefixed field claimed more bytes than remain.
    BadLength,
    /// A string field was not valid UTF-8.
    BadUtf8,
    /// Bytes remained after a single command was decoded.
    TrailingBytes,
    /// A `PlacePartition` command named a leader that is not in its own replica set — a malformed
    /// placement (the leader must always be one of the replicas), rejected fail-closed.
    LeaderNotAReplica,
    /// A `PlacePartition` command had an empty replica set (a placement must hold at least one
    /// replica).
    EmptyReplicaSet,
    /// A serialized state-machine SNAPSHOT (#660) carried an unknown format version, so it was not
    /// written by a compatible encoder — fail closed rather than mis-decode a torn/foreign blob.
    UnknownSnapshotVersion(u8),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "metadata command is truncated"),
            DecodeError::UnknownTag(t) => write!(f, "unknown metadata command tag {t}"),
            DecodeError::UnknownRole(r) => write!(f, "unknown node role byte {r}"),
            DecodeError::BadLength => {
                write!(f, "metadata command length field overruns the buffer")
            }
            DecodeError::BadUtf8 => write!(f, "metadata command string field is not valid UTF-8"),
            DecodeError::TrailingBytes => write!(f, "trailing bytes after a metadata command"),
            DecodeError::LeaderNotAReplica => {
                write!(f, "placement leader is not in its own replica set")
            }
            DecodeError::EmptyReplicaSet => write!(f, "placement has an empty replica set"),
            DecodeError::UnknownSnapshotVersion(v) => {
                write!(f, "unknown metadata snapshot format version {v}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

// Command tags. Stable on the wire; never renumber.
const TAG_ADD_NODE: u8 = 1;
const TAG_REMOVE_NODE: u8 = 2;
const TAG_ASSIGN_PARTITION: u8 = 3;
const TAG_SET_CONFIG: u8 = 4;
const TAG_PLACE_PARTITION: u8 = 5;
const TAG_CHECKPOINT_COMMITTED_HW: u8 = 6;

impl MetadataCommand {
    /// Encode the command to its canonical little-endian wire bytes.
    ///
    /// Layout: `[tag:u8] [fields...]`, with `u64` little-endian and each string as
    /// `[len:u32-le][utf8 bytes]`. The encoding is total and allocation-only.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            MetadataCommand::AddNode { node, role } => {
                out.push(TAG_ADD_NODE);
                out.extend_from_slice(&node.to_le_bytes());
                out.push(role.tag());
            }
            MetadataCommand::RemoveNode { node } => {
                out.push(TAG_REMOVE_NODE);
                out.extend_from_slice(&node.to_le_bytes());
            }
            MetadataCommand::AssignPartition {
                partition,
                leader,
                epoch,
            } => {
                out.push(TAG_ASSIGN_PARTITION);
                out.extend_from_slice(&partition.to_le_bytes());
                out.extend_from_slice(&leader.to_le_bytes());
                out.extend_from_slice(&epoch.to_le_bytes());
            }
            MetadataCommand::PlacePartition {
                partition,
                replicas,
                leader,
                epoch,
            } => {
                out.push(TAG_PLACE_PARTITION);
                out.extend_from_slice(&partition.to_le_bytes());
                let count = u32::try_from(replicas.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&count.to_le_bytes());
                for r in replicas {
                    out.extend_from_slice(&r.to_le_bytes());
                }
                out.extend_from_slice(&leader.to_le_bytes());
                out.extend_from_slice(&epoch.to_le_bytes());
            }
            MetadataCommand::SetConfig { key, value } => {
                out.push(TAG_SET_CONFIG);
                push_str(&mut out, key);
                push_str(&mut out, value);
            }
            MetadataCommand::CheckpointCommittedHw { partition, offset } => {
                out.push(TAG_CHECKPOINT_COMMITTED_HW);
                out.extend_from_slice(&partition.to_le_bytes());
                out.extend_from_slice(&offset.to_le_bytes());
            }
        }
        out
    }

    /// Decode exactly one command from `buf`, requiring `buf` to be fully consumed.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] if the buffer is truncated, carries an unknown tag/role,
    /// has an overrunning length prefix, holds invalid UTF-8, or has trailing bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = Cursor::new(buf);
        let tag = cur.u8()?;
        let cmd = match tag {
            TAG_ADD_NODE => {
                let node = cur.u64()?;
                let role = NodeRole::from_tag(cur.u8()?)
                    .ok_or(DecodeError::UnknownRole(buf[buf.len() - 1]))?;
                MetadataCommand::AddNode { node, role }
            }
            TAG_REMOVE_NODE => {
                let node = cur.u64()?;
                MetadataCommand::RemoveNode { node }
            }
            TAG_ASSIGN_PARTITION => {
                let partition = cur.u64()?;
                let leader = cur.u64()?;
                let epoch = cur.u64()?;
                MetadataCommand::AssignPartition {
                    partition,
                    leader,
                    epoch,
                }
            }
            TAG_PLACE_PARTITION => {
                let partition = cur.u64()?;
                let count = cur.u32()? as usize;
                // Each replica is a u64 (8 bytes): reject a count whose bytes cannot all be present
                // BEFORE allocating, so a hostile/truncated length can never over-allocate.
                if cur.remaining() < count.saturating_mul(8) {
                    return Err(DecodeError::BadLength);
                }
                let mut replicas = Vec::with_capacity(count);
                for _ in 0..count {
                    replicas.push(cur.u64()?);
                }
                let leader = cur.u64()?;
                let epoch = cur.u64()?;
                if replicas.is_empty() {
                    return Err(DecodeError::EmptyReplicaSet);
                }
                if !replicas.contains(&leader) {
                    return Err(DecodeError::LeaderNotAReplica);
                }
                MetadataCommand::PlacePartition {
                    partition,
                    replicas,
                    leader,
                    epoch,
                }
            }
            TAG_SET_CONFIG => {
                let key = cur.string()?;
                let value = cur.string()?;
                MetadataCommand::SetConfig { key, value }
            }
            TAG_CHECKPOINT_COMMITTED_HW => {
                let partition = cur.u64()?;
                let offset = cur.u64()?;
                MetadataCommand::CheckpointCommittedHw { partition, offset }
            }
            other => return Err(DecodeError::UnknownTag(other)),
        };
        if cur.remaining() != 0 {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(cmd)
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// A tiny bounds-checked little-endian reader for the command wire form.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(s);
        Ok(u32::from_le_bytes(a))
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        let len = self.u32()? as usize;
        if self.remaining() < len {
            return Err(DecodeError::BadLength);
        }
        let bytes = self.take(len)?;
        core::str::from_utf8(bytes)
            .map(ToOwned::to_owned)
            .map_err(|_| DecodeError::BadUtf8)
    }
}

/// The replicated cluster control-plane state. Built up by `apply`-ing the committed
/// stream of [`MetadataCommand`]s in log order; identical commit order yields an identical
/// state on every voter, which is the state-machine-safety property the Raft group
/// guarantees. Pure data + pure transitions: no IO, no `raft` types.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataStateMachine {
    /// node id -> role.
    members: BTreeMap<u64, NodeRole>,
    /// partition id -> current placement (leader + epoch).
    placements: BTreeMap<u64, Placement>,
    /// partition id -> the last-checkpointed quorum-committed high-watermark (#618b). The data-plane
    /// leader proposes a [`MetadataCommand::CheckpointCommittedHw`] periodically; this is the SAFE bar a
    /// successor must hold before it may be auto-promoted on a leader death (it SURVIVES the leader's
    /// death because it is replicated metadata). MONOTONIC per partition (a lower checkpoint never lowers
    /// the bar), so committed data the cluster once recorded as quorum-fsync'd can never be "forgotten".
    committed_hw: BTreeMap<u64, u64>,
    /// cluster-wide config key -> value.
    config: BTreeMap<String, String>,
    /// The index of the last entry applied to this state machine (monotonic).
    applied_index: u64,
}

impl MetadataStateMachine {
    /// A fresh, empty control plane.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one committed command, recording the entry's log `index` as `applied_index`.
    ///
    /// `index` must be monotonic in commit order (the Raft group provides this); the
    /// method is otherwise a total fold over the command set.
    pub fn apply(&mut self, index: u64, cmd: &MetadataCommand) {
        match cmd {
            MetadataCommand::AddNode { node, role } => {
                self.members.insert(*node, *role);
            }
            MetadataCommand::RemoveNode { node } => {
                self.members.remove(node);
            }
            MetadataCommand::AssignPartition {
                partition,
                leader,
                epoch,
            } => {
                self.placements
                    .insert(*partition, Placement::leader_only(*leader, *epoch));
            }
            MetadataCommand::PlacePartition {
                partition,
                replicas,
                leader,
                epoch,
            } => {
                self.placements.insert(
                    *partition,
                    Placement {
                        replicas: replicas.clone(),
                        leader: *leader,
                        epoch: *epoch,
                    },
                );
            }
            MetadataCommand::SetConfig { key, value } => {
                self.config.insert(key.clone(), value.clone());
            }
            MetadataCommand::CheckpointCommittedHw { partition, offset } => {
                // MONOTONIC: only ever RAISE the bar. A late/duplicate/stale checkpoint (a lower offset,
                // e.g. from an out-of-order proposal or a node that briefly read a lower frontier) must
                // NEVER lower the safe bar a successor has to clear — that would silently re-admit a loss
                // window. So we keep the maximum committed HW the cluster has ever durably recorded.
                let entry = self.committed_hw.entry(*partition).or_insert(0);
                *entry = (*entry).max(*offset);
            }
        }
        self.applied_index = index;
    }

    /// Decode and apply one committed entry's bytes.
    ///
    /// # Errors
    ///
    /// Returns the [`DecodeError`] if the entry's bytes are not a valid command (so a
    /// malformed entry is a typed, fail-closed error, never a silent no-op).
    pub fn apply_encoded(&mut self, index: u64, data: &[u8]) -> Result<(), DecodeError> {
        let cmd = MetadataCommand::decode(data)?;
        self.apply(index, &cmd);
        Ok(())
    }

    /// Replace the membership table from an applied raft `ConfState`'s voter / learner sets.
    ///
    /// This is the C1-I4 seam: when a committed conf-change entry is applied to the raft core
    /// (`apply_conf_change`), the resulting `ConfState`'s voters become [`NodeRole::Voter`] and
    /// its learners [`NodeRole::Learner`] in this state machine, so the state machine's view of
    /// membership always tracks the durable `ConfState` (and a node present in BOTH the incoming
    /// and outgoing majorities of a joint config, or staged in `learners_next`, is reflected). A
    /// voter takes precedence over a learner for the same id (a node can be listed in both during
    /// a joint transition; it is acting as a voter). `index` is the applied entry index.
    pub fn set_membership(
        &mut self,
        index: u64,
        voters: &[u64],
        voters_outgoing: &[u64],
        learners: &[u64],
        learners_next: &[u64],
    ) {
        self.members.clear();
        // Learners first, then voters, so a voter overrides a learner for the same id.
        for &node in learners.iter().chain(learners_next) {
            self.members.insert(node, NodeRole::Learner);
        }
        for &node in voters.iter().chain(voters_outgoing) {
            self.members.insert(node, NodeRole::Voter);
        }
        self.applied_index = index;
    }

    /// The role of `node`, if it is a member.
    #[must_use]
    pub fn role(&self, node: u64) -> Option<NodeRole> {
        self.members.get(&node).copied()
    }

    /// The number of voting members (the quorum basis).
    #[must_use]
    pub fn voter_count(&self) -> usize {
        self.members
            .values()
            .filter(|r| **r == NodeRole::Voter)
            .count()
    }

    /// The current placement for `partition`, if assigned.
    #[must_use]
    pub fn placement(&self, partition: u64) -> Option<Placement> {
        self.placements.get(&partition).cloned()
    }

    /// A snapshot of EVERY committed partition placement, keyed by partition id. The data-plane serve
    /// path (#717) reads this to derive its per-partition role from the committed metadata: the driver
    /// publishes this snapshot each cycle so the data plane can construct / refresh its roles without
    /// touching the `RawNode`. Empty until a placement command commits + applies.
    #[must_use]
    pub fn placements(&self) -> BTreeMap<u64, Placement> {
        self.placements.clone()
    }

    /// The last-checkpointed quorum-committed high-watermark for `partition` (#618b), or `None` if no
    /// [`MetadataCommand::CheckpointCommittedHw`] has committed for it yet. This is the SAFE bar a
    /// successor MUST hold before the auto-failover path may promote it — it survives the leader's death
    /// because it is replicated metadata.
    #[must_use]
    pub fn committed_hw(&self, partition: u64) -> Option<u64> {
        self.committed_hw.get(&partition).copied()
    }

    /// A snapshot of EVERY partition's last-checkpointed committed high-watermark (#618b), keyed by
    /// partition id. The driver publishes this each cycle so a surviving node can read the SAFE bar a
    /// successor must clear AFTER the leader that produced it has died. Empty until a checkpoint commits.
    #[must_use]
    pub fn committed_hws(&self) -> BTreeMap<u64, u64> {
        self.committed_hw.clone()
    }

    /// A config value by key.
    #[must_use]
    pub fn config(&self, key: &str) -> Option<&str> {
        self.config.get(key).map(String::as_str)
    }

    /// The index of the last applied entry.
    #[must_use]
    pub fn applied_index(&self) -> u64 {
        self.applied_index
    }

    /// Serialize a CONSISTENT, point-in-time SNAPSHOT of the committed state machine (#660).
    ///
    /// A snapshot is a complete, canonical serialization of EVERY piece of committed metadata —
    /// membership, placements, committed-HW, config — plus the `applied_index` the snapshot is
    /// taken at. It is what the metadata Raft log snapshot/compaction (#660) captures BEFORE the
    /// log prefix is truncated, and what a far-behind learner installs to catch up without
    /// replaying the whole log (the snapshot-based catch-up that pairs with #617/#724).
    ///
    /// The encoding is the SAME explicit, length-prefixed, little-endian, zero-dependency style as
    /// [`MetadataCommand::encode`] (so the snapshot adds NO new dependency and has one canonical
    /// meaning across nodes), prefixed by a one-byte format `version` so a future field can be
    /// added without mis-decoding an older blob. Maps are written in their `BTreeMap` order, which
    /// is deterministic (sorted by key), so two state machines with identical committed state
    /// serialize to BYTE-IDENTICAL snapshots — the property the round-trip and catch-up tests
    /// rely on.
    ///
    /// The snapshot is BOUNDED: the metadata state is small by construction (a cluster's
    /// members / placements / config, not per-record data), so the serialization is O(members +
    /// placements + config) bytes — kilobytes, not the unbounded log.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&self.applied_index.to_le_bytes());

        // members: [count:u32][ (node:u64, role:u8) ... ] in BTreeMap (sorted) order.
        push_u32_len(&mut out, self.members.len());
        for (node, role) in &self.members {
            out.extend_from_slice(&node.to_le_bytes());
            out.push(role.tag());
        }

        // placements: [count:u32][ (partition:u64, replica_count:u32, replicas:u64..., leader:u64,
        // epoch:u64) ... ] in sorted order.
        push_u32_len(&mut out, self.placements.len());
        for (partition, placement) in &self.placements {
            out.extend_from_slice(&partition.to_le_bytes());
            push_u32_len(&mut out, placement.replicas.len());
            for r in &placement.replicas {
                out.extend_from_slice(&r.to_le_bytes());
            }
            out.extend_from_slice(&placement.leader.to_le_bytes());
            out.extend_from_slice(&placement.epoch.to_le_bytes());
        }

        // committed_hw: [count:u32][ (partition:u64, offset:u64) ... ] in sorted order.
        push_u32_len(&mut out, self.committed_hw.len());
        for (partition, offset) in &self.committed_hw {
            out.extend_from_slice(&partition.to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
        }

        // config: [count:u32][ (key:str, value:str) ... ] in sorted order.
        push_u32_len(&mut out, self.config.len());
        for (key, value) in &self.config {
            push_str(&mut out, key);
            push_str(&mut out, value);
        }

        out
    }

    /// Decode a serialized snapshot (the inverse of [`Self::snapshot`]) into a fresh state machine.
    ///
    /// Installing a snapshot REPLACES the whole committed state (it is a point-in-time cut, not a
    /// delta), so this returns a brand-new [`MetadataStateMachine`] whose maps + `applied_index`
    /// are exactly the snapshot's. A node restoring from a snapshot then applies the retained log
    /// TAIL (entries strictly above `applied_index`) on top, reaching the identical committed state
    /// it would have by replaying the full log.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] if the buffer carries an unknown version, is truncated, has an
    /// overrunning length, holds invalid UTF-8, names a malformed placement (leader absent from
    /// its replica set / empty replica set), or has trailing bytes — so a torn or foreign blob is
    /// a typed, fail-closed error, never a silently-mis-installed state.
    pub fn restore_from_snapshot(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = Cursor::new(buf);
        let version = cur.u8()?;
        if version != SNAPSHOT_VERSION {
            return Err(DecodeError::UnknownSnapshotVersion(version));
        }
        let applied_index = cur.u64()?;

        let mut members = BTreeMap::new();
        let member_count = cur.u32()? as usize;
        // Reject a hostile/torn count before allocating per-element: each member is 9 bytes.
        if cur.remaining() < member_count.saturating_mul(9) {
            return Err(DecodeError::BadLength);
        }
        for _ in 0..member_count {
            let node = cur.u64()?;
            let role = NodeRole::from_tag(cur.u8()?).ok_or(DecodeError::UnknownRole(0))?;
            members.insert(node, role);
        }

        let mut placements = BTreeMap::new();
        let placement_count = cur.u32()? as usize;
        for _ in 0..placement_count {
            let partition = cur.u64()?;
            let replica_count = cur.u32()? as usize;
            if cur.remaining() < replica_count.saturating_mul(8) {
                return Err(DecodeError::BadLength);
            }
            let mut replicas = Vec::with_capacity(replica_count);
            for _ in 0..replica_count {
                replicas.push(cur.u64()?);
            }
            let leader = cur.u64()?;
            let epoch = cur.u64()?;
            if replicas.is_empty() {
                return Err(DecodeError::EmptyReplicaSet);
            }
            if !replicas.contains(&leader) {
                return Err(DecodeError::LeaderNotAReplica);
            }
            placements.insert(
                partition,
                Placement {
                    replicas,
                    leader,
                    epoch,
                },
            );
        }

        let mut committed_hw = BTreeMap::new();
        let hw_count = cur.u32()? as usize;
        if cur.remaining() < hw_count.saturating_mul(16) {
            return Err(DecodeError::BadLength);
        }
        for _ in 0..hw_count {
            let partition = cur.u64()?;
            let offset = cur.u64()?;
            committed_hw.insert(partition, offset);
        }

        let mut config = BTreeMap::new();
        let config_count = cur.u32()? as usize;
        for _ in 0..config_count {
            let key = cur.string()?;
            let value = cur.string()?;
            config.insert(key, value);
        }

        if cur.remaining() != 0 {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(MetadataStateMachine {
            members,
            placements,
            committed_hw,
            config,
            applied_index,
        })
    }
}

/// The serialized-snapshot format version (#660). Bumped only if the snapshot field layout changes
/// incompatibly; an unknown version is rejected fail-closed at decode time.
const SNAPSHOT_VERSION: u8 = 1;

/// Push a `usize` count as a `u32-le` length prefix, saturating at `u32::MAX` (a count this large
/// is unreachable for the small metadata state, but the saturation keeps the encode total).
fn push_u32_len(out: &mut Vec<u8>, n: usize) {
    let len = u32::try_from(n).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_remove_member_roundtrips_through_apply() {
        let mut sm = MetadataStateMachine::new();
        sm.apply(
            1,
            &MetadataCommand::AddNode {
                node: 7,
                role: NodeRole::Voter,
            },
        );
        sm.apply(
            2,
            &MetadataCommand::AddNode {
                node: 8,
                role: NodeRole::Learner,
            },
        );
        assert_eq!(sm.role(7), Some(NodeRole::Voter));
        assert_eq!(sm.role(8), Some(NodeRole::Learner));
        assert_eq!(sm.voter_count(), 1);
        assert_eq!(sm.applied_index(), 2);

        sm.apply(3, &MetadataCommand::RemoveNode { node: 7 });
        assert_eq!(sm.role(7), None);
        assert_eq!(sm.voter_count(), 0);
    }

    #[test]
    fn placement_and_config_apply() {
        let mut sm = MetadataStateMachine::new();
        sm.apply(
            1,
            &MetadataCommand::AssignPartition {
                partition: 4,
                leader: 2,
                epoch: 9,
            },
        );
        sm.apply(
            2,
            &MetadataCommand::SetConfig {
                key: "replication".to_owned(),
                value: "3".to_owned(),
            },
        );
        assert_eq!(sm.placement(4), Some(Placement::leader_only(2, 9)));
        assert_eq!(sm.config("replication"), Some("3"));
        assert_eq!(sm.config("missing"), None);
    }

    #[test]
    fn place_partition_applies_the_full_replica_set_and_leader() {
        let mut sm = MetadataStateMachine::new();
        sm.apply(
            1,
            &MetadataCommand::PlacePartition {
                partition: 4,
                replicas: vec![2, 1, 3],
                leader: 2,
                epoch: 9,
            },
        );
        let placement = sm.placement(4).expect("placement applied");
        assert_eq!(
            placement.replicas,
            vec![2, 1, 3],
            "the ordered replica set is stored"
        );
        assert_eq!(placement.leader, 2, "the designated leader is stored");
        assert_eq!(placement.epoch, 9);
        assert_eq!(placement.replication_factor(), 3);
        assert!(
            placement.replicas.contains(&placement.leader),
            "the leader is always one of the replicas"
        );
    }

    #[test]
    fn assign_partition_yields_a_leader_only_replica_set() {
        // The backward-compatible C1 command: a leader-only placement has replicas == [leader].
        let mut sm = MetadataStateMachine::new();
        sm.apply(
            1,
            &MetadataCommand::AssignPartition {
                partition: 7,
                leader: 5,
                epoch: 3,
            },
        );
        let placement = sm.placement(7).expect("placement applied");
        assert_eq!(placement.replicas, vec![5]);
        assert_eq!(placement.leader, 5);
        assert_eq!(placement.replication_factor(), 1);
    }

    #[test]
    fn decode_rejects_a_placement_whose_leader_is_not_a_replica() {
        // A hand-built PlacePartition whose leader (99) is absent from its replica set must be
        // rejected fail-closed at decode time — a malformed placement can never enter the state.
        let cmd = MetadataCommand::PlacePartition {
            partition: 1,
            replicas: vec![1, 2, 3],
            leader: 99,
            epoch: 1,
        };
        let bytes = cmd.encode();
        assert_eq!(
            MetadataCommand::decode(&bytes),
            Err(DecodeError::LeaderNotAReplica)
        );
    }

    #[test]
    fn decode_rejects_a_placement_with_an_empty_replica_set() {
        let cmd = MetadataCommand::PlacePartition {
            partition: 1,
            replicas: vec![],
            leader: 0,
            epoch: 1,
        };
        let bytes = cmd.encode();
        assert_eq!(
            MetadataCommand::decode(&bytes),
            Err(DecodeError::EmptyReplicaSet)
        );
    }

    #[test]
    fn decode_rejects_a_placement_with_an_overrunning_replica_count() {
        // A length prefix claiming more replicas than the buffer holds must be rejected BEFORE any
        // large allocation (the hostile-length guard).
        let mut buf = vec![TAG_PLACE_PARTITION];
        buf.extend_from_slice(&1u64.to_le_bytes()); // partition
        buf.extend_from_slice(&1000u32.to_le_bytes()); // claims 1000 replicas
        buf.extend_from_slice(&1u64.to_le_bytes()); // but only one u64 follows
        assert_eq!(MetadataCommand::decode(&buf), Err(DecodeError::BadLength));
    }

    #[test]
    fn every_command_encode_decode_roundtrips() {
        let cmds = [
            MetadataCommand::AddNode {
                node: 42,
                role: NodeRole::Voter,
            },
            MetadataCommand::AddNode {
                node: 43,
                role: NodeRole::Learner,
            },
            MetadataCommand::RemoveNode { node: 99 },
            MetadataCommand::AssignPartition {
                partition: 1,
                leader: 5,
                epoch: 12,
            },
            MetadataCommand::PlacePartition {
                partition: 8,
                replicas: vec![3, 1, 2],
                leader: 3,
                epoch: 7,
            },
            MetadataCommand::PlacePartition {
                partition: 9,
                replicas: vec![42],
                leader: 42,
                epoch: 1,
            },
            MetadataCommand::SetConfig {
                key: "k".to_owned(),
                value: "value with spaces".to_owned(),
            },
            MetadataCommand::SetConfig {
                key: String::new(),
                value: String::new(),
            },
            MetadataCommand::CheckpointCommittedHw {
                partition: 0,
                offset: 0,
            },
            MetadataCommand::CheckpointCommittedHw {
                partition: 7,
                offset: 123_456,
            },
        ];
        for cmd in &cmds {
            let bytes = cmd.encode();
            let back = MetadataCommand::decode(&bytes).expect("decode");
            assert_eq!(&back, cmd, "round-trip mismatch for {cmd:?}");
        }
    }

    #[test]
    fn decode_rejects_malformed() {
        assert_eq!(MetadataCommand::decode(&[]), Err(DecodeError::Truncated));
        assert_eq!(
            MetadataCommand::decode(&[200]),
            Err(DecodeError::UnknownTag(200))
        );
        // AddNode tag with a truncated u64.
        assert_eq!(
            MetadataCommand::decode(&[TAG_ADD_NODE, 1, 2, 3]),
            Err(DecodeError::Truncated)
        );
        // RemoveNode with a trailing extra byte.
        let mut buf = MetadataCommand::RemoveNode { node: 1 }.encode();
        buf.push(0xff);
        assert_eq!(
            MetadataCommand::decode(&buf),
            Err(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn checkpoint_committed_hw_stores_and_is_monotonic() {
        // The committed-HW checkpoint (#618b) records the SAFE bar a successor must hold. It is stored
        // per partition and is MONOTONIC: a later, LOWER checkpoint never lowers the bar (it would
        // silently re-open a loss window), so the bar only ever rises.
        let mut sm = MetadataStateMachine::new();
        assert_eq!(sm.committed_hw(0), None, "no checkpoint yet");
        sm.apply(
            1,
            &MetadataCommand::CheckpointCommittedHw {
                partition: 0,
                offset: 100,
            },
        );
        assert_eq!(sm.committed_hw(0), Some(100));
        // A higher checkpoint raises the bar.
        sm.apply(
            2,
            &MetadataCommand::CheckpointCommittedHw {
                partition: 0,
                offset: 150,
            },
        );
        assert_eq!(sm.committed_hw(0), Some(150));
        // A LOWER (stale / out-of-order) checkpoint must NOT lower the bar.
        sm.apply(
            3,
            &MetadataCommand::CheckpointCommittedHw {
                partition: 0,
                offset: 120,
            },
        );
        assert_eq!(
            sm.committed_hw(0),
            Some(150),
            "a stale lower checkpoint never lowers the safe bar"
        );
        // It is per-partition.
        sm.apply(
            4,
            &MetadataCommand::CheckpointCommittedHw {
                partition: 9,
                offset: 42,
            },
        );
        assert_eq!(sm.committed_hw(9), Some(42));
        assert_eq!(sm.committed_hw(0), Some(150));
        assert_eq!(sm.committed_hws().get(&0), Some(&150));
        assert_eq!(sm.committed_hws().get(&9), Some(&42));
    }

    #[test]
    fn apply_encoded_decodes_then_folds() {
        let mut sm = MetadataStateMachine::new();
        let data = MetadataCommand::AddNode {
            node: 1,
            role: NodeRole::Voter,
        }
        .encode();
        sm.apply_encoded(5, &data).expect("apply encoded");
        assert_eq!(sm.role(1), Some(NodeRole::Voter));
        assert_eq!(sm.applied_index(), 5);
    }

    // --- #660: state-machine snapshot serialization + restore. ---

    /// Build a state machine with one of every kind of committed state, so the snapshot exercises
    /// every map (members, placements, committed-HW, config) and the applied index.
    fn populated_sm() -> MetadataStateMachine {
        let mut sm = MetadataStateMachine::new();
        sm.apply(
            1,
            &MetadataCommand::AddNode {
                node: 1,
                role: NodeRole::Voter,
            },
        );
        sm.apply(
            2,
            &MetadataCommand::AddNode {
                node: 2,
                role: NodeRole::Learner,
            },
        );
        sm.apply(
            3,
            &MetadataCommand::PlacePartition {
                partition: 7,
                replicas: vec![1, 2, 3],
                leader: 1,
                epoch: 4,
            },
        );
        sm.apply(
            4,
            &MetadataCommand::AssignPartition {
                partition: 9,
                leader: 2,
                epoch: 5,
            },
        );
        sm.apply(
            5,
            &MetadataCommand::CheckpointCommittedHw {
                partition: 7,
                offset: 1234,
            },
        );
        sm.apply(
            6,
            &MetadataCommand::SetConfig {
                key: "replication".to_owned(),
                value: "3".to_owned(),
            },
        );
        sm
    }

    /// A snapshot round-trips: restoring a serialized snapshot yields a state machine BYTE-EQUAL to
    /// the original (every map + the applied index), proving the snapshot captures ALL committed
    /// state at its index (the #660 committed-state-preserved invariant, at the SM layer).
    #[test]
    fn snapshot_then_restore_yields_an_identical_state_machine() {
        let sm = populated_sm();
        let bytes = sm.snapshot();
        let restored = MetadataStateMachine::restore_from_snapshot(&bytes).expect("restore");
        assert_eq!(restored, sm, "the restored state machine equals the original");
        assert_eq!(restored.applied_index(), sm.applied_index());
        // Spot-check a representative value from each map survived.
        assert_eq!(restored.role(1), Some(NodeRole::Voter));
        assert_eq!(restored.role(2), Some(NodeRole::Learner));
        assert_eq!(
            restored.placement(7),
            Some(Placement {
                replicas: vec![1, 2, 3],
                leader: 1,
                epoch: 4
            })
        );
        assert_eq!(restored.placement(9), Some(Placement::leader_only(2, 5)));
        assert_eq!(restored.committed_hw(7), Some(1234));
        assert_eq!(restored.config("replication"), Some("3"));
    }

    /// Two state machines with IDENTICAL committed state serialize to BYTE-IDENTICAL snapshots
    /// (the `BTreeMap` order is deterministic), regardless of the ORDER the commands were applied —
    /// the point-in-time-consistency property a snapshot relies on.
    #[test]
    fn snapshot_is_deterministic_regardless_of_apply_order() {
        let a = populated_sm();
        // Apply the same commands in a DIFFERENT order, but at the same final applied index.
        let mut b = MetadataStateMachine::new();
        b.apply(
            6,
            &MetadataCommand::SetConfig {
                key: "replication".to_owned(),
                value: "3".to_owned(),
            },
        );
        b.apply(
            5,
            &MetadataCommand::CheckpointCommittedHw {
                partition: 7,
                offset: 1234,
            },
        );
        b.apply(
            4,
            &MetadataCommand::AssignPartition {
                partition: 9,
                leader: 2,
                epoch: 5,
            },
        );
        b.apply(
            3,
            &MetadataCommand::PlacePartition {
                partition: 7,
                replicas: vec![1, 2, 3],
                leader: 1,
                epoch: 4,
            },
        );
        b.apply(
            2,
            &MetadataCommand::AddNode {
                node: 2,
                role: NodeRole::Learner,
            },
        );
        // Re-set the applied index to match `a` (the last apply above set it to 2).
        b.apply(
            6,
            &MetadataCommand::AddNode {
                node: 1,
                role: NodeRole::Voter,
            },
        );
        assert_eq!(a.snapshot(), b.snapshot(), "snapshots are byte-identical");
    }

    /// Restoring a snapshot then applying the log TAIL on top reaches the SAME state as a full
    /// replay (the snapshot+tail == full-replay invariant, at the SM layer). This is the heart of
    /// snapshot-based catch-up: a node that installs a snapshot at index N and applies N+1.. is
    /// identical to a node that replayed 1...
    #[test]
    fn restore_then_apply_tail_equals_full_replay() {
        // Full replay: apply commands 1..=8.
        let mut full = populated_sm();
        full.apply(
            7,
            &MetadataCommand::AddNode {
                node: 3,
                role: NodeRole::Voter,
            },
        );
        full.apply(
            8,
            &MetadataCommand::SetConfig {
                key: "k".to_owned(),
                value: "v".to_owned(),
            },
        );

        // Snapshot-at-6 + tail 7,8: restore the snapshot, then apply only the tail.
        let snapshot = populated_sm().snapshot();
        let mut from_snap = MetadataStateMachine::restore_from_snapshot(&snapshot).expect("restore");
        assert_eq!(from_snap.applied_index(), 6, "restored at the snapshot index");
        from_snap.apply(
            7,
            &MetadataCommand::AddNode {
                node: 3,
                role: NodeRole::Voter,
            },
        );
        from_snap.apply(
            8,
            &MetadataCommand::SetConfig {
                key: "k".to_owned(),
                value: "v".to_owned(),
            },
        );

        assert_eq!(
            from_snap, full,
            "restore(snapshot@6) + apply(7,8) == full replay(1..=8)"
        );
        assert_eq!(from_snap.applied_index(), 8);
    }

    /// An empty (fresh) state machine snapshots and restores cleanly (the genesis case).
    #[test]
    fn an_empty_state_machine_snapshots_and_restores() {
        let sm = MetadataStateMachine::new();
        let bytes = sm.snapshot();
        let restored = MetadataStateMachine::restore_from_snapshot(&bytes).expect("restore empty");
        assert_eq!(restored, sm);
        assert_eq!(restored.applied_index(), 0);
    }

    /// Restore fails CLOSED on a foreign / torn blob: an unknown version, trailing bytes, and a
    /// truncated buffer are typed errors, never a silently mis-installed state.
    #[test]
    fn restore_rejects_a_foreign_or_torn_snapshot() {
        // Unknown version byte.
        assert_eq!(
            MetadataStateMachine::restore_from_snapshot(&[0xff, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::UnknownSnapshotVersion(0xff))
        );
        // Trailing bytes after a valid snapshot.
        let mut bytes = populated_sm().snapshot();
        bytes.push(0x00);
        assert_eq!(
            MetadataStateMachine::restore_from_snapshot(&bytes),
            Err(DecodeError::TrailingBytes)
        );
        // Truncated mid-snapshot.
        let good = populated_sm().snapshot();
        assert!(matches!(
            MetadataStateMachine::restore_from_snapshot(&good[..good.len() / 2]),
            Err(DecodeError::Truncated | DecodeError::BadLength)
        ));
        // Empty buffer.
        assert_eq!(
            MetadataStateMachine::restore_from_snapshot(&[]),
            Err(DecodeError::Truncated)
        );
    }
}
