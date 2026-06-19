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

/// The current placement of a single partition: which node leads it and under which
/// monotonic leader epoch. The epoch is the fencing token (a stale leader's writes are
/// rejected once a higher epoch exists); exposing it to the broker is C1-I3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    /// The node id currently designated leader for the partition.
    pub leader: u64,
    /// The monotonic leadership epoch assigned at this placement.
    pub epoch: u64,
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
    /// Assign `partition` to `leader` at `epoch` (placement + leader-epoch in one step).
    AssignPartition {
        partition: u64,
        leader: u64,
        epoch: u64,
    },
    /// Set a cluster-wide configuration key to a value.
    SetConfig { key: String, value: String },
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
        }
    }
}

impl std::error::Error for DecodeError {}

// Command tags. Stable on the wire; never renumber.
const TAG_ADD_NODE: u8 = 1;
const TAG_REMOVE_NODE: u8 = 2;
const TAG_ASSIGN_PARTITION: u8 = 3;
const TAG_SET_CONFIG: u8 = 4;

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
            MetadataCommand::SetConfig { key, value } => {
                out.push(TAG_SET_CONFIG);
                push_str(&mut out, key);
                push_str(&mut out, value);
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
            TAG_SET_CONFIG => {
                let key = cur.string()?;
                let value = cur.string()?;
                MetadataCommand::SetConfig { key, value }
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
                self.placements.insert(
                    *partition,
                    Placement {
                        leader: *leader,
                        epoch: *epoch,
                    },
                );
            }
            MetadataCommand::SetConfig { key, value } => {
                self.config.insert(key.clone(), value.clone());
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
        self.placements.get(&partition).copied()
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
        assert_eq!(
            sm.placement(4),
            Some(Placement {
                leader: 2,
                epoch: 9
            })
        );
        assert_eq!(sm.config("replication"), Some("3"));
        assert_eq!(sm.config("missing"), None);
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
            MetadataCommand::SetConfig {
                key: "k".to_owned(),
                value: "value with spaces".to_owned(),
            },
            MetadataCommand::SetConfig {
                key: String::new(),
                value: String::new(),
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
}
