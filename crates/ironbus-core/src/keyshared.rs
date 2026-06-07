// SPDX-License-Identifier: MIT OR Apache-2.0
//! `key_shared` work-group routing: per-key affinity over a competing group (#64).
//!
//! A competing work-group drains a single log in parallel: each record goes to exactly one
//! member, with no per-key affinity. The optional `key_shared` ordering mode layers per-key
//! affinity on top: a record's KEY maps to exactly one of the group's CURRENT live members,
//! so every record sharing a key is delivered to the same member, and the group still drains
//! in parallel ACROSS keys. The default ordering mode is [`KeyOrdering::None`] (plain
//! competing distribution, this module is not even consulted), so an unconfigured group is
//! completely unaffected.
//!
//! This module is pure and IO-free, like the rest of `ironbus-core`. It owns two pieces of
//! state for a `key_shared` group and nothing else:
//!
//! 1. The live-MEMBER set. The caller (the server engine) registers a member when a consumer
//!    joins the group and removes it when the consumer leaves or disconnects. Membership is
//!    driven by explicit join/leave events, never a clock, so routing is deterministic.
//! 2. The per-KEY in-flight offset: for each key that currently has a delivered-but-unacked
//!    record, the log offset of that record. This is what enforces per-key serialization and
//!    the drain-or-expire guard on a rebalance (see below).
//!
//! ## Routing
//! A key maps to a member by RENDEZVOUS (highest-random-weight) hashing: of every live
//! member, the one whose `hash(member, key)` is largest owns the key. Rendezvous hashing has
//! the minimal-reshuffle property a single sticky cursor lacks: adding or removing one member
//! moves only the keys that hashed to (or away from) that member, never the whole keyspace, so
//! a membership change re-routes the smallest possible set of keys. A record with an EMPTY key
//! has no affinity and keeps plain competing distribution (any member may take it).
//!
//! ## Per-key serialization and the drain-or-expire guard
//! A member never receives key K's NEXT record until K's prior record is acked or its lease
//! expires. The router tracks, per key, the offset of K's currently-outstanding record; while
//! that entry is present the router refuses to route any HIGHER offset of K to anyone. The
//! lease layer still decides whether the outstanding offset ITSELF is redeliverable (in-flight
//! while its visibility holds, reclaimable once it expires), so per-key order is preserved even
//! across parallel members AND across a rebalance: if a key's owner changes while it has an
//! in-flight record, the new owner cannot receive K's next record until that in-flight record
//! drains (is acked, clearing the entry) or expires and is redelivered, so an old in-flight and
//! a newly-routed record can never interleave out of order on the same key.

use crate::types::Offset;
use std::collections::{BTreeMap, BTreeSet};
use xxhash_rust::xxh3::xxh3_64;

/// The per-group ordering mode of a competing work-group (#64). The default,
/// [`KeyOrdering::None`], is plain competing distribution (no per-key affinity), so an
/// unconfigured group behaves exactly as before; [`KeyOrdering::KeyShared`] opts in to per-key
/// routing through a [`KeyRouter`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyOrdering {
    /// Plain competing distribution: each record goes to whichever member claims it next, with
    /// no per-key affinity. The default, so an unconfigured group is unaffected.
    #[default]
    None,
    /// `key_shared`: a record's key routes to one current live member (rendezvous hash), and
    /// per-key order is preserved while the group drains in parallel across keys.
    KeyShared,
}

/// A stable, opaque identity for one member (one consumer connection) of a `key_shared` group.
///
/// The value only has to be stable for the life of a membership and distinct between
/// concurrently-live members; the router uses it solely as the rendezvous-hash seed for a key.
/// The server mints it from the per-connection identity it already tracks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberId(u64);

impl MemberId {
    /// Wraps a raw `u64` connection identity as a [`MemberId`].
    #[must_use]
    pub fn new(id: u64) -> MemberId {
        MemberId(id)
    }

    /// The raw `u64` this id wraps.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

/// The rendezvous (highest-random-weight) score of a `(member, key)` pair: the member whose
/// score is the largest for a key owns that key. Pure: it is a fixed hash of the member id
/// (little-endian) followed by the key bytes, so the same inputs always yield the same score
/// regardless of iteration order, machine, or run (the determinism gate depends on this).
fn score(member: MemberId, key: &[u8]) -> u64 {
    // 8 bytes of member id then the key, hashed as one buffer. Mixing the id INTO the hash (not
    // xoring two independent hashes) avoids the symmetry pitfalls of naive HRW combiners.
    let mut buf = Vec::with_capacity(8 + key.len());
    buf.extend_from_slice(&member.get().to_le_bytes());
    buf.extend_from_slice(key);
    xxh3_64(&buf)
}

/// Per-`key_shared`-group routing state (#64): the live-member set and the per-key in-flight
/// offset. Created only when a group's [`KeyOrdering`] is [`KeyOrdering::KeyShared`]; a
/// [`KeyOrdering::None`] group has no router and is routed by plain competing claim.
#[derive(Clone, Debug, Default)]
pub struct KeyRouter {
    /// The current live members. Routing is over THIS set, so a join or leave re-routes only
    /// the keys whose rendezvous owner changed (the minimal-reshuffle property).
    members: BTreeSet<MemberId>,
    /// For each key with a currently delivered-but-unacked record, the log offset of that
    /// record. Present means the key is BUSY: no higher offset of the key may be routed until
    /// this one is acked (the entry is cleared) or expires and is redelivered as the SAME
    /// offset (the entry stays, so the redelivery precedes the next key record).
    in_flight: BTreeMap<Vec<u8>, u64>,
}

/// Whether a `key_shared` group may route a given offset to a given member right now (#64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    /// The member owns this key (or the key is empty, plain competing) and the key is free, so
    /// the offset may be claimed for this member.
    Deliver,
    /// The key is owned by a DIFFERENT member, so this member must not take the offset.
    NotOwner,
    /// The key already has an earlier in-flight record (per-key serialization / drain guard):
    /// no member may take a higher offset of this key until the earlier one drains or expires.
    KeyBusy,
}

impl KeyRouter {
    /// A new router with no members and nothing in flight.
    #[must_use]
    pub fn new() -> KeyRouter {
        KeyRouter::default()
    }

    /// Registers `member` as live (a consumer joined the group). Idempotent: re-adding a live
    /// member is a no-op. Returns `true` if the set changed, so the caller can tell a genuine
    /// join (which may re-route keys) from a repeat.
    pub fn join(&mut self, member: MemberId) -> bool {
        self.members.insert(member)
    }

    /// Removes `member` from the live set (a consumer left or disconnected). Idempotent.
    /// Returns `true` if the set changed. Any record still in flight to the departed member is
    /// left in `in_flight`: it drains or expires through the lease layer, and only then is the
    /// key free to re-route to its new owner, which is exactly the drain-or-expire guard.
    pub fn leave(&mut self, member: MemberId) -> bool {
        self.members.remove(&member)
    }

    /// The number of live members.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Whether `member` is currently live.
    #[must_use]
    pub fn contains(&self, member: MemberId) -> bool {
        self.members.contains(&member)
    }

    /// The current rendezvous owner of `key`: the live member with the highest `(member, key)`
    /// score. `None` only when the group has no live members. On a tie (astronomically
    /// unlikely with a 64-bit score) the LARGER `MemberId` wins, so the choice is total and
    /// deterministic. An empty key has no single owner under plain competing distribution; the
    /// caller routes an empty key without consulting this.
    #[must_use]
    pub fn owner(&self, key: &[u8]) -> Option<MemberId> {
        self.members
            .iter()
            .copied()
            .max_by_key(|&member| (score(member, key), member))
    }

    /// The routing decision for delivering `offset` (carrying `key`) to `member` right now
    /// (#64). An EMPTY key keeps plain competing distribution: it has no affinity and no per-key
    /// order, so any live member may take any free empty-keyed offset, and empty-keyed records
    /// drain IN PARALLEL across members (the lease layer alone guarantees a single member claims a
    /// given offset). A non-empty key is deliverable to `member` only if `member` is its rendezvous
    /// owner AND the key is not already busy with an EARLIER offset.
    ///
    /// A key that is busy with THIS SAME offset returns [`RouteDecision::Deliver`]: that is a
    /// redelivery of the outstanding record itself (its lease expired), which the lease layer
    /// gates, and it must precede the key's next record, so it is allowed through here.
    #[must_use]
    pub fn decide(&self, member: MemberId, key: &[u8], offset: Offset) -> RouteDecision {
        // An empty key has no affinity and no per-key order: it competes plainly, so it bypasses
        // the per-key serialization gate entirely and any live member may take any free empty-keyed
        // offset in parallel. The lease layer (the is_claimable peek the caller already applied)
        // bounds it to one member per offset; serializing the empty key here would falsely throttle
        // empty-keyed traffic to a single in-flight record across the whole group.
        if key.is_empty() {
            return RouteDecision::Deliver;
        }
        // Per-key serialization / drain guard: if the key holds an EARLIER in-flight offset, no
        // member may take this (higher) one yet. The same offset is the outstanding record's own
        // redelivery and is allowed.
        if let Some(&busy) = self.in_flight.get(key) {
            if busy != offset.get() {
                return RouteDecision::KeyBusy;
            }
            // Same offset: fall through. Ownership is re-checked below so a rebalance that moved
            // the key cannot deliver even its own redelivery to a non-owner.
        }
        match self.owner(key) {
            Some(owner) if owner == member => RouteDecision::Deliver,
            // No members cannot happen here (this `member` is polling, so it is live), but treat
            // an absent owner conservatively as not-this-member rather than delivering.
            _ => RouteDecision::NotOwner,
        }
    }

    /// Records that `offset` (carrying `key`) is now in flight for its key, so the key is busy
    /// until the offset is acked or redelivered. Called right after a successful claim. A key
    /// only ever has one outstanding offset at a time (the serialization gate guarantees the
    /// next is not routed until this clears), so this overwrites at most a stale equal entry.
    pub fn mark_in_flight(&mut self, key: &[u8], offset: Offset) {
        // An empty key is plain competing with no per-key order, so it is never tracked here: the
        // lease layer alone bounds empty-keyed records. Tracking b"" would falsely serialize them
        // (and `decide` already bypasses the gate for the empty key), so this is a no-op for it.
        if key.is_empty() {
            return;
        }
        self.in_flight.insert(key.to_vec(), offset.get());
    }

    /// Clears the in-flight entry for whatever key currently holds `offset` (an ack, term, or
    /// commit-past of that offset), freeing the key to route its next record. A no-op if no key
    /// holds `offset`. Linear in the number of busy keys, which is bounded by the in-flight
    /// window, so it stays cheap.
    pub fn clear_offset(&mut self, offset: Offset) {
        let off = offset.get();
        if let Some(key) = self
            .in_flight
            .iter()
            .find_map(|(k, &v)| (v == off).then(|| k.clone()))
        {
            self.in_flight.remove(&key);
        }
    }

    /// Drops every in-flight entry at or below `committed`, keeping the per-key map bounded to
    /// the in-flight window (mirrors how the session prunes its `leased` map past the committed
    /// cursor). An offset below the committed cursor is acked, so its key is no longer busy.
    pub fn retain_above(&mut self, committed: Offset) {
        let floor = committed.get();
        self.in_flight.retain(|_, &mut off| off >= floor);
    }

    /// The number of keys currently busy (with a delivered-but-unacked record). A small
    /// hot-spot signal: a `key_shared` group whose busy keys cluster on one member skews load,
    /// which #16 can surface as per-member in-flight depth.
    #[must_use]
    pub fn busy_keys(&self) -> usize {
        self.in_flight.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    #[test]
    fn an_empty_group_has_no_owner() {
        let router = KeyRouter::new();
        assert_eq!(router.owner(b"k"), None);
        assert_eq!(router.member_count(), 0);
    }

    #[test]
    fn join_and_leave_track_membership_idempotently() {
        let mut router = KeyRouter::new();
        assert!(router.join(member(1)), "a new join changes the set");
        assert!(!router.join(member(1)), "re-joining is a no-op");
        assert_eq!(router.member_count(), 1);
        assert!(router.contains(member(1)));
        assert!(router.leave(member(1)), "a leave changes the set");
        assert!(!router.leave(member(1)), "leaving twice is a no-op");
        assert_eq!(router.member_count(), 0);
    }

    #[test]
    fn the_same_key_always_maps_to_the_same_owner() {
        let mut router = KeyRouter::new();
        for id in 1..=5 {
            router.join(member(id));
        }
        let owner = router.owner(b"order-42").unwrap();
        // Stable across repeated lookups with the same membership.
        for _ in 0..10 {
            assert_eq!(router.owner(b"order-42"), Some(owner));
        }
        // The owner is one of the live members.
        assert!(router.contains(owner));
    }

    #[test]
    fn keys_spread_across_members_not_all_to_one() {
        // Rendezvous hashing should distribute distinct keys across members, not pin them all
        // to a single member (a sanity check that the score actually varies by member).
        let mut router = KeyRouter::new();
        for id in 1..=4 {
            router.join(member(id));
        }
        let mut seen = BTreeSet::new();
        for k in 0..200u32 {
            let key = format!("key-{k}");
            seen.insert(router.owner(key.as_bytes()).unwrap());
        }
        assert!(
            seen.len() >= 2,
            "distinct keys should reach more than one member, got {}",
            seen.len()
        );
    }

    #[test]
    fn removing_a_member_remaps_only_its_keys_minimal_reshuffle() {
        // The minimal-reshuffle property: removing one member moves ONLY the keys it owned, and
        // every other key keeps its owner. This is the consistent-hash guarantee a sticky cursor
        // lacks (which would remap half the keyspace on a single change).
        let mut router = KeyRouter::new();
        for id in 1..=5 {
            router.join(member(id));
        }
        let keys: Vec<String> = (0..500).map(|k| format!("k{k}")).collect();
        let before: Vec<MemberId> = keys
            .iter()
            .map(|k| router.owner(k.as_bytes()).unwrap())
            .collect();
        // Remove the member that owned the most keys, so the test is non-vacuous.
        let victim = member(3);
        router.leave(victim);
        for (key, &was) in keys.iter().zip(before.iter()) {
            let now = router.owner(key.as_bytes()).unwrap();
            if was == victim {
                assert_ne!(now, victim, "the victim's keys must move");
            } else {
                assert_eq!(now, was, "a key not owned by the victim must NOT move");
            }
        }
    }

    #[test]
    fn adding_a_member_remaps_only_the_keys_that_move_to_it() {
        // Adding a member only steals the keys whose new rendezvous owner is the newcomer; every
        // other key keeps its owner.
        let mut router = KeyRouter::new();
        for id in 1..=4 {
            router.join(member(id));
        }
        let keys: Vec<String> = (0..500).map(|k| format!("k{k}")).collect();
        let before: Vec<MemberId> = keys
            .iter()
            .map(|k| router.owner(k.as_bytes()).unwrap())
            .collect();
        let newcomer = member(99);
        router.join(newcomer);
        let mut moved = 0;
        for (key, &was) in keys.iter().zip(before.iter()) {
            let now = router.owner(key.as_bytes()).unwrap();
            if now == newcomer {
                moved += 1; // a key that moved to the newcomer
            } else {
                assert_eq!(now, was, "a key not stolen by the newcomer must NOT move");
            }
        }
        assert!(moved > 0, "the newcomer should own at least one key");
    }

    #[test]
    fn an_owner_gets_deliver_and_a_non_owner_gets_not_owner() {
        let mut router = KeyRouter::new();
        router.join(member(1));
        router.join(member(2));
        let key = b"route-me";
        let owner = router.owner(key).unwrap();
        let other = if owner == member(1) {
            member(2)
        } else {
            member(1)
        };
        assert_eq!(
            router.decide(owner, key, Offset::new(0)),
            RouteDecision::Deliver
        );
        assert_eq!(
            router.decide(other, key, Offset::new(0)),
            RouteDecision::NotOwner
        );
    }

    #[test]
    fn an_empty_key_is_deliverable_to_any_member() {
        let mut router = KeyRouter::new();
        router.join(member(1));
        router.join(member(2));
        // No affinity: both members get Deliver for the empty key.
        assert_eq!(
            router.decide(member(1), b"", Offset::new(0)),
            RouteDecision::Deliver
        );
        assert_eq!(
            router.decide(member(2), b"", Offset::new(0)),
            RouteDecision::Deliver
        );
    }

    #[test]
    fn empty_keys_drain_in_parallel_and_are_not_serialized() {
        // Plain competing distribution for the empty key (#64 review S1): unlike a real key, an
        // empty key is NOT throttled to one in-flight record at a time. Even with one empty-keyed
        // offset outstanding, a HIGHER empty-keyed offset is still deliverable (to either member),
        // so empty-keyed traffic drains in parallel; the lease layer alone bounds each offset.
        let mut router = KeyRouter::new();
        router.join(member(1));
        router.join(member(2));
        // mark_in_flight is a no-op for the empty key, so it never goes "busy".
        router.mark_in_flight(b"", Offset::new(0));
        assert_eq!(
            router.busy_keys(),
            0,
            "an empty key is never tracked as busy"
        );
        // A higher empty-keyed offset is still deliverable to a DIFFERENT member in parallel.
        assert_eq!(
            router.decide(member(2), b"", Offset::new(1)),
            RouteDecision::Deliver
        );
        assert_eq!(
            router.decide(member(1), b"", Offset::new(1)),
            RouteDecision::Deliver
        );
    }

    #[test]
    fn a_busy_key_blocks_a_higher_offset_until_cleared() {
        let mut router = KeyRouter::new();
        router.join(member(1));
        let key = b"k";
        let owner = router.owner(key).unwrap();
        // First record of the key is deliverable and marked in flight.
        assert_eq!(
            router.decide(owner, key, Offset::new(0)),
            RouteDecision::Deliver
        );
        router.mark_in_flight(key, Offset::new(0));
        // The key's NEXT record (a higher offset) is blocked until offset 0 drains.
        assert_eq!(
            router.decide(owner, key, Offset::new(5)),
            RouteDecision::KeyBusy
        );
        // Offset 0 itself stays deliverable (its own redelivery on lease expiry).
        assert_eq!(
            router.decide(owner, key, Offset::new(0)),
            RouteDecision::Deliver
        );
        // Acking offset 0 clears the key, freeing the next record.
        router.clear_offset(Offset::new(0));
        assert_eq!(
            router.decide(owner, key, Offset::new(5)),
            RouteDecision::Deliver
        );
    }

    #[test]
    fn a_busy_key_blocks_its_next_record_for_a_new_owner_after_a_rebalance() {
        // The drain-or-expire guard across a rebalance: a key with an in-flight record does not
        // deliver its NEXT record to the NEW owner until the in-flight one clears, so an old
        // in-flight and a newly routed record cannot interleave out of order.
        let mut router = KeyRouter::new();
        for id in 1..=4 {
            router.join(member(id));
        }
        // Find a key and a membership change that actually moves the key's owner.
        let key = (0..1000)
            .map(|k| format!("k{k}"))
            .find(|k| {
                let before = router.owner(k.as_bytes()).unwrap();
                before == member(2)
            })
            .expect("some key must be owned by member 2");
        let old_owner = router.owner(key.as_bytes()).unwrap();
        // The old owner takes offset 0; it is now busy for the key.
        router.mark_in_flight(key.as_bytes(), Offset::new(0));
        // Member 2 leaves: the key's owner changes.
        router.leave(member(2));
        let new_owner = router.owner(key.as_bytes()).unwrap();
        assert_ne!(new_owner, old_owner, "the key's owner moved");
        // The new owner still cannot take the key's NEXT record while offset 0 is in flight.
        assert_eq!(
            router.decide(new_owner, key.as_bytes(), Offset::new(7)),
            RouteDecision::KeyBusy
        );
        // Once offset 0 drains (acked or expired-and-redelivered-then-acked), the new owner gets it.
        router.clear_offset(Offset::new(0));
        assert_eq!(
            router.decide(new_owner, key.as_bytes(), Offset::new(7)),
            RouteDecision::Deliver
        );
    }

    #[test]
    fn retain_above_prunes_committed_keys() {
        let mut router = KeyRouter::new();
        router.mark_in_flight(b"a", Offset::new(2));
        router.mark_in_flight(b"b", Offset::new(5));
        assert_eq!(router.busy_keys(), 2);
        // Committing past offset 4 frees key "a" (offset 2 < 4) but not "b" (offset 5 >= 4).
        router.retain_above(Offset::new(4));
        assert_eq!(router.busy_keys(), 1);
    }

    #[test]
    fn clear_offset_is_a_noop_for_an_unknown_offset() {
        let mut router = KeyRouter::new();
        router.mark_in_flight(b"a", Offset::new(2));
        router.clear_offset(Offset::new(9));
        assert_eq!(router.busy_keys(), 1, "an unknown offset clears nothing");
    }

    #[test]
    fn key_ordering_defaults_to_none() {
        assert_eq!(KeyOrdering::default(), KeyOrdering::None);
    }
}
