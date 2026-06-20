// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key -> partition routing: the pure, IO-free math behind a stream's P sub-logs (#591, V2-M2 M2-I11).
//!
//! A stream may OPTIONALLY be subdivided into `P` independent sub-logs (partitions). `P = 1` (the
//! default) is today's single log — every record goes to the one partition, so total order is
//! preserved. `P > 1` spreads a stream's records across `P` partitions, which is the parallel-consume
//! LEVER: each partition is an independent log with its own cursor/poll/lease, so `P` partitions can
//! be consumed `P`-way in parallel (per-partition order, NO total order across partitions — exactly
//! Kafka's model). This module owns only the SELECTION math; the per-partition storage and consume
//! state live in `ironbus-storage` (`PartitionedStream`), which stays IO-bearing.
//!
//! ## The two routing rules
//!
//! 1. **Keyed records** route by a STABLE hash of the key: `partition = xxh3_64(key) % P`. The same
//!    key always lands in the same partition (for a fixed `P`), so every record sharing a key keeps
//!    its relative order WITHIN that partition — the per-key-order guarantee a partitioned stream
//!    must preserve. The hash is `xxh3_64`, the SAME function `keyshared` uses for key routing, so a
//!    deployment has one key-hash contract. It is deterministic across machines, runs, and builds
//!    (no per-process seed), so a key's partition is reproducible — required for any future
//!    rebalance to agree on placement.
//! 2. **Keyless records** (an empty key) have NO affinity and no per-key order to preserve, so they
//!    spread across partitions by ROUND-ROBIN ([`PartitionSelector`]) — or STICKY per producer
//!    connection, which is round-robin advanced once per batch rather than per record, to keep a
//!    keyless producer's records batched into one partition's segment at a time (fewer cross-partition
//!    seeks) while still spreading load over many connections. Either way a keyless record has no
//!    cross-partition order to break.
//!
//! ## Why `xxh3 % P` (and the caveat)
//!
//! `xxh3_64` is a strong, fast, non-cryptographic hash with good avalanche, so `% P` distributes
//! distinct keys near-uniformly across partitions without a per-key skew table. The honest caveat:
//! plain modulo hashing is NOT consistent — changing `P` reshuffles ~all keys (unlike the rendezvous
//! hashing `keyshared` uses for MEMBER routing, where the live-member set changes often). That is
//! acceptable here because a stream's partition count is a DECLARED, rarely-changed property (you pick
//! `P` when you create the stream), not a per-membership-change quantity; a future "repartition"
//! operation is its own migration, out of scope for this issue. Within a fixed `P` the mapping is
//! perfectly stable, which is the property per-key order depends on.
//!
//! This module is pure and IO-free, like the rest of `ironbus-core`.

use core::num::NonZeroU32;
use xxhash_rust::xxh3::xxh3_64;

/// A stream's partition count `P`: a [`NonZeroU32`] so `P = 0` (a stream with no log to write to) is
/// unrepresentable, and `P >= 1` is a type invariant every routing call can rely on without a runtime
/// check. The DEFAULT is `P = 1` ([`PartitionCount::ONE`]) — a single partition, i.e. today's single
/// log with full total order — so an unpartitioned stream is the zero-configuration case.
///
/// The count is `u32`: far more partitions than any single node services (a partition is an open log
/// with its own fds and resident index), while leaving the wire/declare field a fixed small width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartitionCount(NonZeroU32);

impl PartitionCount {
    /// The single-partition count `P = 1`: one sub-log, full total order — today's single log. This
    /// is the DEFAULT (a stream declared with no partition count, or a total-order stream).
    pub const ONE: PartitionCount = PartitionCount(match NonZeroU32::new(1) {
        Some(n) => n,
        // Unreachable: 1 is non-zero. Written as a match so the const is total without `unwrap`.
        None => unreachable!(),
    });

    /// Constructs a partition count from `p`, returning `None` for `p == 0` (a stream must have at
    /// least one partition — there must be a log to write to). A `Some` is a count with the `P >= 1`
    /// invariant baked in.
    #[must_use]
    pub const fn new(p: u32) -> Option<PartitionCount> {
        match NonZeroU32::new(p) {
            Some(n) => Some(PartitionCount(n)),
            None => None,
        }
    }

    /// The raw count `P` (always `>= 1`).
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// Whether this is the single-partition (total-order) count `P = 1` — the default. A
    /// single-partition stream is today's single log: one cursor, one poll, full total order, and (in
    /// storage) the same on-disk bytes as a non-partitioned stream.
    #[must_use]
    pub const fn is_single(self) -> bool {
        self.0.get() == 1
    }
}

impl Default for PartitionCount {
    /// The default partition count is `P = 1` — a single partition, full total order, today's single
    /// log. So a stream that does not opt into partitioning behaves exactly as before.
    fn default() -> Self {
        PartitionCount::ONE
    }
}

/// A zero-based partition index in `0..P` for a stream with `P` partitions. The newtype keeps a
/// partition index from being confused with an [`crate::types::Offset`], a stream id, or a raw
/// `usize`; every value returned by this module is guaranteed `< P` for the `P` it was computed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PartitionIndex(u32);

impl PartitionIndex {
    /// Partition 0 — the only partition of a single-partition (`P = 1`) stream, and the first of any
    /// stream. A keyed or keyless record on a `P = 1` stream always routes here, which is what makes a
    /// single-partition stream behave as today's single log.
    pub const ZERO: PartitionIndex = PartitionIndex(0);

    /// Wraps a raw index. `idx` MUST be `< P` for the partition count it indexes; the routing
    /// functions in this module only ever construct in-range values, so a caller using them never
    /// needs this.
    #[must_use]
    pub const fn new(idx: u32) -> PartitionIndex {
        PartitionIndex(idx)
    }

    /// The raw zero-based index.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The index as a `usize`, for indexing a `Vec<Log>` of length `P`. Always `< P`, so the index is
    /// in bounds for a partition array sized to its stream's count.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

/// The STABLE partition for a non-empty `key` over `count` partitions: `xxh3_64(key) % P`. The same
/// key always maps to the same partition for a fixed `P`, so every record sharing a key keeps its
/// order within that one partition (the per-key-order guarantee). Deterministic across machines,
/// runs, and builds (no per-process seed). For `P = 1` this is always [`PartitionIndex::ZERO`] (the
/// modulo collapses), so a single-partition stream routes every key to its one log.
///
/// The caller must only route NON-EMPTY keys here — an empty key has no affinity and spreads by
/// round-robin via [`PartitionSelector`]; see [`partition_for`].
#[must_use]
pub fn partition_for_key(key: &[u8], count: PartitionCount) -> PartitionIndex {
    // `xxh3_64(key) % P` is in `0..P`, and `P <= u32::MAX`, so the remainder is provably `< u32::MAX`
    // and the conversion to `u32` is exact. It is written as a CHECKED `try_from` (not a truncating
    // `as` cast — so the `cast_possible_truncation` pedantic lint is satisfied) with a NON-panicking
    // `unwrap_or` fallback (so no panic path is introduced and `missing_panics_doc` stays satisfied).
    // The fallback to partition 0 is unreachable given the proof above; it would, at worst, route to a
    // valid partition rather than panic.
    let p = u64::from(count.get());
    let idx = u32::try_from(xxh3_64(key) % p).unwrap_or(0);
    PartitionIndex(idx)
}

/// A round-robin (optionally STICKY) partition selector for KEYLESS records, owned per producer
/// connection. A keyless record has no per-key order to preserve, so the selector just spreads its
/// records across the `P` partitions; the only state is a monotonically advancing cursor.
///
/// - **Round-robin** ([`PartitionSelector::next`]): advance one partition per record — the most even
///   spread.
/// - **Sticky** ([`PartitionSelector::sticky`] + [`PartitionSelector::rotate`]): keep returning the
///   SAME partition until the caller rotates (e.g. once per produced batch), so a keyless producer's
///   records cluster into one partition's open segment at a time (fewer cross-partition segment seeks)
///   while still spreading across many connections/batches. This mirrors Kafka's sticky partitioner.
///
/// Each producer connection owns its OWN selector, so two connections spread independently; there is
/// no shared global cursor to contend on.
#[derive(Clone, Debug, Default)]
pub struct PartitionSelector {
    /// The next partition to hand out (round-robin) or the currently-stuck partition (sticky). Wraps
    /// modulo the count on each use, so it never has to be reset when the count is small.
    cursor: u32,
}

impl PartitionSelector {
    /// A fresh selector starting at partition 0.
    #[must_use]
    pub fn new() -> PartitionSelector {
        PartitionSelector { cursor: 0 }
    }

    /// The NEXT partition in round-robin order over `count` partitions, advancing the cursor by one.
    /// Successive calls cycle `0, 1, …, P-1, 0, …`, the most even keyless spread. For `P = 1` this is
    /// always [`PartitionIndex::ZERO`].
    pub fn next(&mut self, count: PartitionCount) -> PartitionIndex {
        let p = count.get();
        let idx = self.cursor % p;
        // Advance with wraparound at P (not at u32::MAX) so the cursor stays small and the sequence is
        // a clean cycle; `wrapping_add` only matters at the astronomically unreachable u32::MAX.
        self.cursor = (idx + 1) % p;
        PartitionIndex(idx)
    }

    /// The currently-STUCK partition over `count` partitions WITHOUT advancing — the sticky choice.
    /// Returns the same partition on every call until [`PartitionSelector::rotate`] moves it, so a
    /// producer can batch many keyless records into one partition before rotating. For `P = 1` this is
    /// always [`PartitionIndex::ZERO`].
    #[must_use]
    pub fn sticky(&self, count: PartitionCount) -> PartitionIndex {
        PartitionIndex(self.cursor % count.get())
    }

    /// Advances the sticky partition to the next one over `count` partitions (call once per batch).
    /// After this, [`PartitionSelector::sticky`] returns the next partition in the cycle.
    pub fn rotate(&mut self, count: PartitionCount) {
        let p = count.get();
        self.cursor = (self.cursor % p + 1) % p;
    }
}

/// The partition for a record carrying `key` over `count` partitions, applying BOTH rules in one
/// place: a NON-EMPTY key routes by the stable hash ([`partition_for_key`], preserving per-key
/// order); an EMPTY (keyless) key spreads by round-robin through `selector` (no per-key order to
/// preserve). This is the single entry point a producer uses per record, so the keyed/keyless split
/// is decided in exactly one spot.
///
/// For a single-partition stream (`P = 1`) every record — keyed or keyless — routes to
/// [`PartitionIndex::ZERO`], so the stream behaves as today's single total-order log regardless of
/// keys.
pub fn partition_for(
    key: &[u8],
    count: PartitionCount,
    selector: &mut PartitionSelector,
) -> PartitionIndex {
    if key.is_empty() {
        selector.next(count)
    } else {
        partition_for_key(key, count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn count(p: u32) -> PartitionCount {
        PartitionCount::new(p).expect("p >= 1")
    }

    #[test]
    fn partition_count_rejects_zero_and_defaults_to_one() {
        assert_eq!(PartitionCount::new(0), None, "P = 0 has no log to write to");
        assert_eq!(PartitionCount::default(), PartitionCount::ONE);
        assert_eq!(PartitionCount::ONE.get(), 1);
        assert!(PartitionCount::ONE.is_single());
        assert!(!count(4).is_single());
        assert_eq!(count(7).get(), 7);
    }

    #[test]
    fn single_partition_routes_everything_to_partition_zero() {
        // The total-order case: P = 1 collapses every key (and every keyless record) to partition 0,
        // so a single-partition stream is today's single log.
        let one = PartitionCount::ONE;
        assert_eq!(partition_for_key(b"any-key", one), PartitionIndex::ZERO);
        assert_eq!(partition_for_key(b"", one), PartitionIndex::ZERO);
        let mut sel = PartitionSelector::new();
        for _ in 0..10 {
            assert_eq!(partition_for(b"", one, &mut sel), PartitionIndex::ZERO);
            assert_eq!(partition_for(b"k", one, &mut sel), PartitionIndex::ZERO);
        }
        assert_eq!(sel.sticky(one), PartitionIndex::ZERO);
    }

    #[test]
    fn key_to_partition_is_stable_for_a_fixed_count() {
        // THE per-key-order property: the same key always maps to the same partition for a fixed P, so
        // records sharing a key stay in one partition (and keep their order there).
        let c = count(8);
        let first = partition_for_key(b"order-42", c);
        for _ in 0..100 {
            assert_eq!(partition_for_key(b"order-42", c), first);
        }
        // Distinct keys are independent of iteration/run order — recomputing gives the same answers.
        let a = partition_for_key(b"alpha", c);
        let b = partition_for_key(b"beta", c);
        assert_eq!(partition_for_key(b"alpha", c), a);
        assert_eq!(partition_for_key(b"beta", c), b);
    }

    #[test]
    fn every_keyed_partition_is_in_range() {
        // Every routed partition is < P, for several counts and many keys, so a Vec<Log> of length P
        // is always indexed in bounds.
        for p in [1u32, 2, 3, 5, 16, 64, 1000] {
            let c = count(p);
            for k in 0..500u32 {
                let key = format!("k{k}");
                let idx = partition_for_key(key.as_bytes(), c);
                assert!(idx.get() < p, "partition {idx:?} must be < {p}");
                assert_eq!(idx.as_usize(), idx.get() as usize);
            }
        }
    }

    #[test]
    fn keys_spread_across_partitions_not_all_to_one() {
        // xxh3 % P distributes distinct keys across partitions (a sanity check that the hash actually
        // varies the result), so a partitioned stream genuinely spreads load.
        let c = count(8);
        let mut seen = BTreeSet::new();
        for k in 0..1000u32 {
            let key = format!("key-{k}");
            seen.insert(partition_for_key(key.as_bytes(), c).get());
        }
        assert!(
            seen.len() >= 6,
            "distinct keys should reach most partitions, hit {} of 8",
            seen.len()
        );
    }

    #[test]
    fn keyless_round_robin_cycles_evenly() {
        // A keyless record spreads by round-robin: successive empty-key records cycle through every
        // partition, the most even keyless distribution.
        let c = count(4);
        let mut sel = PartitionSelector::new();
        let seq: Vec<u32> = (0..8)
            .map(|_| partition_for(b"", c, &mut sel).get())
            .collect();
        assert_eq!(seq, vec![0, 1, 2, 3, 0, 1, 2, 3]);
    }

    #[test]
    fn keyless_round_robin_is_independent_per_selector() {
        // Each producer connection owns its OWN selector, so two connections spread independently with
        // no shared global cursor to contend on.
        let c = count(3);
        let mut a = PartitionSelector::new();
        let mut b = PartitionSelector::new();
        assert_eq!(a.next(c).get(), 0);
        assert_eq!(a.next(c).get(), 1);
        // b is untouched by a's advances: it starts its own cycle at 0.
        assert_eq!(b.next(c).get(), 0);
        assert_eq!(b.next(c).get(), 1);
        assert_eq!(a.next(c).get(), 2);
    }

    #[test]
    fn sticky_holds_a_partition_until_rotated() {
        // Sticky: the same partition is returned until the caller rotates (e.g. once per batch), so a
        // keyless producer batches into one partition's segment at a time.
        let c = count(4);
        let mut sel = PartitionSelector::new();
        assert_eq!(sel.sticky(c).get(), 0);
        assert_eq!(sel.sticky(c).get(), 0, "sticky does not advance on its own");
        sel.rotate(c);
        assert_eq!(sel.sticky(c).get(), 1);
        sel.rotate(c);
        assert_eq!(sel.sticky(c).get(), 2);
        // It wraps at P.
        sel.rotate(c);
        sel.rotate(c);
        assert_eq!(sel.sticky(c).get(), 0);
    }

    #[test]
    fn partition_for_applies_keyed_vs_keyless_split() {
        // The single entry point: a non-empty key routes by the stable hash (ignores the selector), an
        // empty key advances the selector (round-robin).
        let c = count(4);
        let mut sel = PartitionSelector::new();
        // A keyed record does NOT advance the selector — two keyed records leave the keyless cursor put.
        let keyed = partition_for(b"stable", c, &mut sel);
        assert_eq!(partition_for(b"stable", c, &mut sel), keyed);
        // The keyless cursor is still at 0 (untouched by the keyed routes), then advances per keyless.
        assert_eq!(partition_for(b"", c, &mut sel).get(), 0);
        assert_eq!(partition_for(b"", c, &mut sel).get(), 1);
    }
}
