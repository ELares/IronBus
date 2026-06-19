// SPDX-License-Identifier: MIT OR Apache-2.0
//! The per-connection, generation-guarded subject-resolve cache (#569, V2-M2).
//!
//! A stable publisher hits the **same** literal subject over and over. Resolving that
//! subject against the routing trie ([`crate::sublist`]) every single time re-walks the
//! arena on the publish hot path even though the answer has not changed. This module caches
//! the resolution **per connection**, keyed by the literal subject string, so the trie walk
//! happens ONCE per `(connection, subject)` and every subsequent publish of that subject is
//! a hash lookup with no walk.
//!
//! Correctness across rebinds is kept by a single integer: the cache remembers the
//! [`SublistSnapshot`](crate::sublist::SublistSnapshot) **generation** its entries were
//! resolved against. Every resolve loads the current snapshot once (a wait-free `ArcSwap`
//! load) and compares its generation to the cache's. If they match, a cached answer is used
//! directly — no walk. If they differ (a bind changed the routing table, so the snapshot
//! advanced its generation), the whole cache is dropped and the subject is re-resolved
//! against the new table. So the hot-path GUARD a bind change adds is a single `O(1)`
//! generation-compare; the invalidation itself is one wholesale `clear` (freeing the entries
//! this connection held — inherently `O(entries held)`, but a single off-lock free, not a
//! per-entry scan) paid LAZILY on the next resolve, plus a per-subject re-resolve on next use.
//!
//! # Why this beats the NATS `Sublist` results-cache
//!
//! NATS keeps a results cache **inside** its shared `Sublist`:
//!
//! * it consults that shared cache on every published message under a `sync.RWMutex`, and
//! * it FLUSHES the cache on every subscription change, and on a wildcard sub/unsub it
//!   linear-scans the whole cache (bounded by `slCacheMax = 1024`) under the **write lock**
//!   to evict stale entries.
//!
//! So in NATS a single subscription change does `O(slCacheMax)` work under a global write
//! lock and contends with every concurrent publisher.
//!
//! IronBus moves the cache OFF the shared routing structure and onto the connection:
//!
//! * The shared [`SublistSnapshot`](crate::sublist::SublistSnapshot) carries no cache at all
//!   — a bind change just rebuilds an immutable trie and atomically swaps it in (#568), with
//!   no cache to flush and no lock.
//! * Each connection owns a [`ResolveCache`]. A bind change is invisible to it until its
//!   next resolve, when a single `generation` compare tells it "the table moved, drop my
//!   cached answers". There is no global flush, no write lock, and the publish hot path
//!   never blocks on a rebuild.
//!
//! The net effect: steady-state publish is `O(1)` (a hash lookup, no walk), and a bind
//! change is `O(1)` on the hot path (one generation-compare) plus a lazy re-resolve of only
//! the subjects the connection actually re-publishes.
//!
//! # Boundedness (cardinality discipline)
//!
//! An unbounded cache is an unbounded memory hazard: a connection that publishes to a
//! firehose of distinct subjects could grow it without limit, the same cardinality hazard
//! the bounded subject grammar (#567) and the fail-closed fork bound (#568) guard against. So
//! the cache is **bounded**: it holds at most [`ResolveCache::capacity`] distinct subjects and
//! evicts the least-recently-used entry when a new subject would exceed the cap. A connection
//! with a small working set of hot subjects keeps them all resident; a connection spraying
//! unbounded distinct subjects is bounded to `capacity` entries and simply re-walks the cold
//! ones (still correct, just not cached) — it can never grow the cache without bound.
//!
//! # IO-free
//!
//! This module is pure compute: a `HashMap`, a `Vec`, and integer compares. It touches no
//! filesystem, network, clock, process, or async runtime, so it stays inside
//! `ironbus-core`'s IO-free invariant (enforced by `tools/io-free-check`).
//!
//! # Where this is wired
//!
//! This is the resolve-cache **primitive**: it wraps a
//! [`SublistSnapshot`](crate::sublist::SublistSnapshot) lookup with the generation guard and
//! the bound. The subject→stream **binding** that produces the routing table, and the live
//! publish path that owns one cache per connection, land with the binding policy (#585,
//! M2-I9); the wire frames are M2-I10. This module ships the cache so #585 can drop it onto
//! the publish path without re-deriving the generation-guard or the bound.

use std::collections::HashMap;

use crate::subject::Subject;
use crate::sublist::SublistSnapshot;

/// The default per-connection cache capacity.
///
/// `1024` mirrors NATS's `slCacheMax` so the comparison is like-for-like — but here it is a
/// per-connection LRU bound on a lock-free, per-connection structure, not a shared cache a
/// wildcard unsub must linear-scan under a global write lock. A connection's hot working set
/// of distinct publish subjects is almost always far smaller than this; the cap exists only
/// to fence a pathological publisher that sprays unbounded distinct subjects.
pub const DEFAULT_CAPACITY: usize = 1024;

/// One cached resolution: the resolved targets for a subject, plus the LRU recency stamp.
///
/// The generation is NOT stored per entry: the whole cache shares a single
/// [`ResolveCache::generation`], so a generation change drops every entry at once (a bind
/// change invalidates the entire table). Storing it per entry would add a compare per entry
/// for no gain — the snapshot generation is global to the routing table, not per subject.
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    /// The resolved targets, exactly what a fresh `match()` against the cached generation's
    /// trie would return (same contents, same order).
    targets: Vec<T>,
    /// A monotonically increasing recency stamp; the entry with the smallest stamp is the
    /// least-recently-used and is the eviction victim. Refreshed on every hit.
    last_used: u64,
}

/// A per-connection, generation-guarded, bounded subject→targets resolve cache.
///
/// `T` is the routing target — the same opaque, `Clone`-able id the trie carries (a
/// `StreamId` newtype, a `u64`, …). The cache only stores and returns it.
///
/// Each connection owns one `ResolveCache`. It is NOT shared across connections and adds no
/// lock to the publish path: the only synchronization the resolve touches is the wait-free
/// `ArcSwap` load inside [`SublistSnapshot`](crate::sublist::SublistSnapshot), exactly as a
/// direct `match()` would.
#[derive(Debug)]
pub struct ResolveCache<T> {
    /// Subject string -> its resolved targets. Bounded by `capacity`.
    entries: HashMap<String, CacheEntry<T>>,
    /// The snapshot generation every entry in `entries` was resolved against. A resolve
    /// whose loaded snapshot generation differs clears `entries` and adopts the new one.
    generation: u64,
    /// The maximum number of distinct subjects the cache retains. When a miss would push the
    /// count past this, the least-recently-used entry is evicted first.
    capacity: usize,
    /// A monotonic counter sourced into each entry's `last_used` to order LRU eviction. It
    /// only ever increases while the cache is live; it is reset when the cache is cleared.
    tick: u64,
    /// Count of resolves that walked the trie (a miss or a generation-invalidation). Exposed
    /// for tests/metrics so a HIT can be proven NOT to walk; it is not used for routing.
    walks: u64,
}

impl<T: Clone> ResolveCache<T> {
    /// A new, empty cache with [`DEFAULT_CAPACITY`].
    ///
    /// The cache starts at generation 0 with no entries; the first resolve adopts whatever
    /// generation the snapshot it is given is currently at.
    #[must_use]
    pub fn new() -> ResolveCache<T> {
        ResolveCache::with_capacity(DEFAULT_CAPACITY)
    }

    /// A new, empty cache bounded to at most `capacity` distinct subjects.
    ///
    /// A `capacity` of 0 is clamped to 1 so the cache can always hold the single subject it
    /// is currently resolving (a 0-capacity cache would be a pure pass-through that re-walks
    /// every publish, which is never what a caller wants).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> ResolveCache<T> {
        ResolveCache {
            entries: HashMap::new(),
            generation: 0,
            capacity: capacity.max(1),
            tick: 0,
            walks: 0,
        }
    }

    /// The maximum number of distinct subjects this cache retains.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The number of subjects currently cached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no subject is currently cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The number of resolves that walked the trie (a cold miss, or a re-walk after a bind
    /// changed the generation). Steady-state hits do NOT advance this, so a test can prove a
    /// hit took the no-walk path by asserting this stays unchanged across the call.
    #[must_use]
    pub const fn walk_count(&self) -> u64 {
        self.walks
    }

    /// The generation the currently-cached entries were resolved against.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Resolves `subject` against `snapshot`, returning its matching targets — from the cache
    /// on a hit, or by walking the trie once and caching the result on a miss.
    ///
    /// # The hot path
    ///
    /// 1. Load the current trie snapshot ONCE — a single wait-free `ArcSwap` load (no lock).
    /// 2. If the snapshot's generation differs from the cache's, a bind changed the routing
    ///    table: clear the whole cache and adopt the new generation. (This is the only
    ///    invalidation — no per-entry scan, no shared-cache flush, no lock.)
    /// 3. If `subject` is present, it is a HIT: refresh its recency and return its targets
    ///    with NO trie walk.
    /// 4. Otherwise it is a MISS: walk the trie once against the loaded snapshot, cache the
    ///    result (evicting the least-recently-used entry first if at capacity), and return it.
    ///
    /// The returned `Vec<T>` is a clone of the cached targets, so the caller owns it and the
    /// cache keeps its copy for the next hit. (Callers that want to avoid the per-call clone
    /// can use [`ResolveCache::resolve_with`].)
    ///
    /// A cache HIT returns EXACTLY what a fresh `snapshot.match_subject(subject)` would return
    /// against the same generation — same targets, same order — because the cached value IS
    /// that result, captured at the generation the cache currently holds.
    pub fn resolve(&mut self, snapshot: &SublistSnapshot<T>, subject: &Subject<'_>) -> Vec<T> {
        self.resolve_with(snapshot, subject, <[T]>::to_vec)
    }

    /// Resolves `subject` against `snapshot` and applies `f` to the cached target slice,
    /// returning `f`'s result. The borrow-returning core of [`ResolveCache::resolve`] for
    /// callers that want to act on the targets without cloning the whole `Vec` (e.g. fan a
    /// record out to each target in place).
    ///
    /// Same hot path and same generation guard as [`ResolveCache::resolve`]; only the final
    /// hand-off differs (a projection of the cached slice instead of a clone).
    pub fn resolve_with<R>(
        &mut self,
        snapshot: &SublistSnapshot<T>,
        subject: &Subject<'_>,
        f: impl FnOnce(&[T]) -> R,
    ) -> R {
        // (1) One wait-free load. The guard pins this exact table version for this resolve.
        let guard = snapshot.load();
        let current_gen = guard.generation();

        // (2) Generation guard: a bind moved the table -> drop the whole (now-stale) cache and
        // adopt the new generation. O(1) on the hot path; the clear only touches THIS
        // connection's own entries, never a shared structure and never under a lock.
        if current_gen != self.generation {
            self.entries.clear();
            self.generation = current_gen;
            self.tick = 0;
        }

        // (3) HIT: the subject is cached at the current generation. Refresh recency and hand
        // back the cached targets with NO trie walk.
        let next_tick = self.tick.wrapping_add(1);
        if let Some(entry) = self.entries.get_mut(subject.as_str()) {
            self.tick = next_tick;
            entry.last_used = next_tick;
            return f(&entry.targets);
        }

        // (4) MISS: walk the trie ONCE against the loaded snapshot, then cache the result.
        self.walks += 1;
        let mut targets = Vec::new();
        guard.match_into(subject, &mut targets);
        // Drop the wait-free guard before mutating the map; the targets are already owned.
        drop(guard);

        self.tick = next_tick;
        self.evict_if_full();
        let result = f(&targets);
        self.entries.insert(
            subject.as_str().to_owned(),
            CacheEntry {
                targets,
                last_used: next_tick,
            },
        );
        result
    }

    /// Evicts the least-recently-used entry if inserting one more would exceed `capacity`.
    ///
    /// Called only on the MISS path (a cold subject), never on a hit, so the steady-state hot
    /// path never pays for eviction. The scan is `O(capacity)` and bounded; it runs only when
    /// the cache is genuinely full and a new distinct subject arrives.
    fn evict_if_full(&mut self) {
        if self.entries.len() < self.capacity {
            return;
        }
        // Find the least-recently-used key (smallest `last_used`) and drop it. `capacity >= 1`
        // and the map is full, so there is always a victim to find.
        if let Some(victim) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| k.clone())
        {
            self.entries.remove(&victim);
        }
    }

    /// Clears every cached entry. The next resolve re-walks. Useful if a caller wants to drop
    /// the cache's memory without dropping the cache itself (e.g. on a connection idle).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.tick = 0;
    }
}

impl<T: Clone> Default for ResolveCache<T> {
    fn default() -> ResolveCache<T> {
        ResolveCache::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sublist::{Sublist, SublistBuilder};

    /// Build a trie from `(pattern, target)` pairs (generation 0 from the builder; the
    /// snapshot restamps on store).
    fn build(entries: &[(&str, u32)]) -> Sublist<u32> {
        let mut b = SublistBuilder::new();
        for (p, t) in entries {
            b.insert(p, *t).expect("valid test pattern");
        }
        b.build(0).expect("test set within fork bound")
    }

    /// A sorted match straight off the snapshot, the differential oracle a cached answer
    /// must equal.
    fn oracle(snap: &SublistSnapshot<u32>, subject: &str) -> Vec<u32> {
        let s = Subject::parse_literal(subject).expect("valid subject");
        let mut v = snap.match_subject(&s);
        v.sort_unstable();
        v
    }

    fn resolve_sorted(
        cache: &mut ResolveCache<u32>,
        snap: &SublistSnapshot<u32>,
        subject: &str,
    ) -> Vec<u32> {
        let s = Subject::parse_literal(subject).expect("valid subject");
        let mut v = cache.resolve(snap, &s);
        v.sort_unstable();
        v
    }

    #[test]
    fn miss_then_hit_returns_same_targets_and_only_one_walk() {
        let snap = SublistSnapshot::new(build(&[("a.>", 1), ("a.b.c", 2), ("a.*.c", 3)]));
        let mut cache = ResolveCache::new();

        // First resolve is a MISS: it walks once and matches the trie.
        assert_eq!(cache.walk_count(), 0);
        assert_eq!(resolve_sorted(&mut cache, &snap, "a.b.c"), vec![1, 2, 3]);
        assert_eq!(
            cache.walk_count(),
            1,
            "the cold resolve walked the trie once"
        );
        assert_eq!(cache.len(), 1);

        // Subsequent resolves are HITs: NO further walks, identical answer.
        for _ in 0..100 {
            assert_eq!(resolve_sorted(&mut cache, &snap, "a.b.c"), vec![1, 2, 3]);
        }
        assert_eq!(
            cache.walk_count(),
            1,
            "every repeat was a HIT — the trie was NOT re-walked",
        );
    }

    #[test]
    fn hit_equals_a_fresh_match_differentially() {
        // A routing table with literal, `*`, and `>` overlap, exercised over many subjects.
        let snap = SublistSnapshot::new(build(&[
            ("a.b.c", 1),
            ("a.*.c", 2),
            ("a.>", 3),
            ("a.b.*", 4),
            ("x.>", 5),
            ("*", 6),
        ]));
        let subjects = [
            "a.b.c",
            "a.b.d",
            "a.q.c",
            "x.y.z",
            "lonely",
            "a",
            "nomatch.here",
        ];
        let mut cache = ResolveCache::new();

        for subj in subjects {
            let want = oracle(&snap, subj);
            // First touch (MISS) and a second touch (HIT) must BOTH equal the oracle.
            assert_eq!(resolve_sorted(&mut cache, &snap, subj), want, "miss {subj}");
            assert_eq!(resolve_sorted(&mut cache, &snap, subj), want, "hit {subj}");
        }
    }

    #[test]
    fn a_bind_change_invalidates_stale_entries_and_reresolves() {
        let snap = SublistSnapshot::new(build(&[("a.b", 1)]));
        let mut cache = ResolveCache::new();

        // Cache `a.b -> [1]` at generation 0.
        assert_eq!(resolve_sorted(&mut cache, &snap, "a.b"), vec![1]);
        assert_eq!(cache.generation(), 0);
        assert_eq!(cache.walk_count(), 1);

        // A bind changes the routing table: now `a.b -> [99]`. The snapshot generation
        // advances on store.
        let g = snap.store(build(&[("a.b", 99)]));
        assert_eq!(g, 1);

        // The very next resolve sees the new generation, drops the stale entry, and
        // re-walks: it must return the NEW result, never the stale `[1]`.
        assert_eq!(
            resolve_sorted(&mut cache, &snap, "a.b"),
            vec![99],
            "no stale routing after a bind",
        );
        assert_eq!(cache.generation(), 1, "cache adopted the new generation");
        assert_eq!(cache.walk_count(), 2, "the bind change forced one re-walk");
        // And the re-resolved entry is itself cached again (a follow-up is a HIT).
        assert_eq!(resolve_sorted(&mut cache, &snap, "a.b"), vec![99]);
        assert_eq!(cache.walk_count(), 2);
    }

    #[test]
    fn a_bind_change_costs_one_compare_not_a_per_subject_scan() {
        // Cache MANY distinct subjects, then bump the generation ONCE. The invalidation is a
        // single O(1) generation-compare that detects the change, then one wholesale clear,
        // NOT a per-subject scan/flush. We assert the post-bind state: the cache is empty
        // (dropped wholesale on the next resolve), and exactly ONE re-walk happens for the one
        // subject re-touched — the others are simply gone, never individually flushed.
        let snap = SublistSnapshot::new(build(&[("t.>", 1)]));
        let mut cache = ResolveCache::with_capacity(4096);
        for i in 0..1000u32 {
            let subj = format!("t.{i}");
            let s = Subject::parse_literal(&subj).unwrap();
            cache.resolve(&snap, &s);
        }
        assert_eq!(cache.len(), 1000);
        let walks_before = cache.walk_count();

        // One bind change.
        snap.store(build(&[("t.>", 2)]));

        // The next resolve clears the WHOLE cache via one generation-compare and re-walks
        // only the single subject it touches. The other 999 are dropped wholesale, not
        // scanned or flushed one by one.
        let s = Subject::parse_literal("t.0").unwrap();
        let got = cache.resolve(&snap, &s);
        assert_eq!(got, vec![2]);
        assert_eq!(cache.len(), 1, "the whole stale cache was dropped");
        assert_eq!(
            cache.walk_count(),
            walks_before + 1,
            "exactly ONE re-walk, not one per previously-cached subject",
        );
    }

    #[test]
    fn cache_is_bounded_and_evicts_lru() {
        let snap = SublistSnapshot::new(build(&[("s.>", 1)]));
        let mut cache = ResolveCache::with_capacity(3);

        // Fill to capacity with three distinct subjects.
        for subj in ["s.a", "s.b", "s.c"] {
            let s = Subject::parse_literal(subj).unwrap();
            cache.resolve(&snap, &s);
        }
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.capacity(), 3);

        // Touch `s.a` so `s.b` becomes the least-recently-used.
        let sa = Subject::parse_literal("s.a").unwrap();
        cache.resolve(&snap, &sa);

        // A fourth distinct subject evicts the LRU (`s.b`), staying at capacity.
        let sd = Subject::parse_literal("s.d").unwrap();
        cache.resolve(&snap, &sd);
        assert_eq!(cache.len(), 3, "cache stayed bounded at capacity");

        let walks_before = cache.walk_count();
        // `s.a`, `s.c`, `s.d` are resident -> HITs (no walk). `s.b` was evicted -> a MISS.
        for subj in ["s.a", "s.c", "s.d"] {
            let s = Subject::parse_literal(subj).unwrap();
            cache.resolve(&snap, &s);
        }
        assert_eq!(
            cache.walk_count(),
            walks_before,
            "resident subjects all HIT"
        );

        let sb = Subject::parse_literal("s.b").unwrap();
        cache.resolve(&snap, &sb);
        assert_eq!(
            cache.walk_count(),
            walks_before + 1,
            "the evicted subject re-walked (proving it was actually evicted)",
        );
    }

    #[test]
    fn unbounded_distinct_subjects_cannot_grow_the_cache() {
        // A firehose of distinct subjects can never push the cache past its capacity.
        let snap = SublistSnapshot::new(build(&[(">", 1)]));
        let mut cache = ResolveCache::with_capacity(8);
        for i in 0..10_000u32 {
            let subj = format!("spray.{i}");
            let s = Subject::parse_literal(&subj).unwrap();
            let got = cache.resolve(&snap, &s);
            assert_eq!(got, vec![1]); // still correct, just not cached
            assert!(cache.len() <= 8, "never exceeds capacity");
        }
        assert_eq!(cache.len(), 8);
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let snap = SublistSnapshot::new(build(&[("a", 1)]));
        let mut cache = ResolveCache::with_capacity(0);
        assert_eq!(cache.capacity(), 1, "a 0 capacity is clamped to 1");
        let s = Subject::parse_literal("a").unwrap();
        assert_eq!(cache.resolve(&snap, &s), vec![1]);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn resolve_with_avoids_the_clone_but_sees_the_same_targets() {
        let snap = SublistSnapshot::new(build(&[("a.>", 1), ("a.b", 2)]));
        let mut cache = ResolveCache::new();
        let s = Subject::parse_literal("a.b").unwrap();

        // `resolve_with` projects the cached slice without cloning the whole Vec.
        let count_miss = cache.resolve_with(&snap, &s, <[u32]>::len);
        assert_eq!(count_miss, 2);
        let sum_hit = cache.resolve_with(&snap, &s, |t| t.iter().sum::<u32>());
        assert_eq!(sum_hit, 3);
        assert_eq!(cache.walk_count(), 1, "the second call was a HIT");
    }

    #[test]
    fn empty_match_is_cached_too() {
        // A subject that matches NOTHING is a legitimate (empty) result and must be cached,
        // so a hot publisher to an unbound subject doesn't re-walk every time.
        let snap = SublistSnapshot::new(build(&[("a.b", 1)]));
        let mut cache = ResolveCache::new();
        let s = Subject::parse_literal("z.z.z").unwrap();
        assert_eq!(cache.resolve(&snap, &s), Vec::<u32>::new());
        assert_eq!(cache.walk_count(), 1);
        assert_eq!(cache.resolve(&snap, &s), Vec::<u32>::new());
        assert_eq!(cache.walk_count(), 1, "the empty result was cached (HIT)");
    }
}
