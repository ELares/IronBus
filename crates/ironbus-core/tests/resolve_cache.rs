// SPDX-License-Identifier: MIT OR Apache-2.0
//! Differential + property tests for the per-connection resolve cache (#569, V2-M2).
//!
//! The central guarantee is DIFFERENTIAL: a cached resolve must return EXACTLY what a fresh
//! `SublistSnapshot::match_subject` would return against the live routing table — including
//! across bind changes, where the cache's generation guard must drop stale entries and
//! re-resolve. The cache is just a per-connection fast path over the trie; proving the two
//! agree over randomized tables, subjects, and interleaved binds proves the cache never
//! routes stale.
//!
//! Layered like the trie tests (#568):
//!
//! 1. A GOLDEN sequence pins miss/hit/invalidate behavior on hand-picked cases.
//! 2. A PROPTEST differential oracle interleaves random resolves and random binds and
//!    asserts cache-resolve == fresh-match on every draw, and that the cache stays bounded.

use std::collections::BTreeSet;

use ironbus_core::resolve_cache::ResolveCache;
use ironbus_core::subject::Subject;
use ironbus_core::sublist::{Sublist, SublistBuilder, SublistSnapshot};

/// Build a trie at generation 0 from `(pattern, target)` pairs. The test sets are
/// small/shallow, so their worst-case fork frontier is far under the cap and the build
/// always succeeds here.
fn build(entries: &[(&str, u32)]) -> Sublist<u32> {
    let mut b = SublistBuilder::new();
    for (p, t) in entries {
        b.insert(p, *t).expect("valid test pattern");
    }
    b.build(0).expect("test set within fork bound")
}

/// The authoritative reference: a fresh match straight off the live snapshot, sorted.
fn fresh_match(snap: &SublistSnapshot<u32>, subject: &str) -> BTreeSet<u32> {
    let s = Subject::parse_literal(subject).expect("valid subject");
    snap.match_subject(&s).into_iter().collect()
}

/// What the cache returns for `subject`, sorted, for an order-independent comparison.
fn cache_match(
    cache: &mut ResolveCache<u32>,
    snap: &SublistSnapshot<u32>,
    subject: &str,
) -> BTreeSet<u32> {
    let s = Subject::parse_literal(subject).expect("valid subject");
    cache.resolve(snap, &s).into_iter().collect()
}

// ---------------------------------------------------------------------------
// 1. Golden sequence: miss -> hit -> bind -> re-resolve.
// ---------------------------------------------------------------------------

#[test]
fn golden_cache_sequence_never_routes_stale() {
    let snap = SublistSnapshot::new(build(&[("a.b.c", 1), ("a.*.c", 2), ("a.>", 3)]));
    let mut cache = ResolveCache::new();

    // Cold MISS then warm HIT both equal the fresh match.
    let want0 = fresh_match(&snap, "a.b.c");
    assert_eq!(cache_match(&mut cache, &snap, "a.b.c"), want0);
    assert_eq!(cache.walk_count(), 1);
    assert_eq!(cache_match(&mut cache, &snap, "a.b.c"), want0);
    assert_eq!(cache.walk_count(), 1, "second touch was a HIT, no walk");

    // A bind changes the table. The very next resolve must reflect the NEW table.
    snap.store(build(&[("a.b.c", 7), ("a.>", 3)]));
    let want1 = fresh_match(&snap, "a.b.c");
    assert_ne!(want0, want1, "the bind actually changed the routing answer");
    assert_eq!(
        cache_match(&mut cache, &snap, "a.b.c"),
        want1,
        "no stale routing after the bind",
    );
    assert_eq!(cache.walk_count(), 2, "the bind forced exactly one re-walk");
}

// ---------------------------------------------------------------------------
// 2. Property: cache-resolve == fresh-match under interleaved binds; bounded.
// ---------------------------------------------------------------------------

use proptest::prelude::*;

/// A legal literal token from a SMALL alphabet so random patterns and subjects collide
/// often (forcing real matches, not just empty sets).
const LITERAL_TOKEN: &str = "[ab][12]?";

/// One pattern token: mostly literals, sometimes a `*`.
fn pattern_token() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => LITERAL_TOKEN.prop_map(String::from),
        2 => Just("*".to_string()),
    ]
}

/// A syntactically-valid pattern: 1..=4 literal-or-`*` tokens, optionally a trailing `>`.
fn arb_pattern() -> impl Strategy<Value = String> {
    (
        proptest::collection::vec(pattern_token(), 1..=4),
        any::<bool>(),
    )
        .prop_map(|(mut toks, tail)| {
            if tail {
                toks.push(">".to_string());
            }
            toks.join(".")
        })
}

/// A valid literal subject: 1..=5 literal tokens (no wildcards).
fn arb_subject() -> impl Strategy<Value = String> {
    proptest::collection::vec(LITERAL_TOKEN.prop_map(String::from), 1..=5)
        .prop_map(|toks| toks.join("."))
}

/// A pattern set -> `(pattern, target)` entries with distinct targets, offset by `base` so
/// successive tables are distinguishable.
fn entries(patterns: &[String], base: u32) -> Vec<(&str, u32)> {
    patterns
        .iter()
        .enumerate()
        .map(|(i, p)| (p.as_str(), base + u32::try_from(i).unwrap()))
        .collect()
}

/// One step in the randomized interleaving: resolve a subject, or rebind the whole table.
#[derive(Clone, Debug)]
enum Step {
    Resolve(String),
    Rebind(Vec<String>),
}

fn arb_step() -> impl Strategy<Value = Step> {
    prop_oneof![
        7 => arb_subject().prop_map(Step::Resolve),
        3 => proptest::collection::vec(arb_pattern(), 1..=6).prop_map(Step::Rebind),
    ]
}

proptest! {
    /// THE differential property: against a cache and a live snapshot, an arbitrary
    /// interleaving of resolves and rebinds always yields, for every resolve, EXACTLY the
    /// set a fresh match against the then-current snapshot yields. This proves the
    /// generation guard never serves a stale answer no matter how binds interleave with
    /// publishes — the property #569 exists to guarantee.
    #[test]
    fn cache_resolve_equals_fresh_match_under_interleaved_binds(
        initial in proptest::collection::vec(arb_pattern(), 1..=6),
        steps in proptest::collection::vec(arb_step(), 1..=40),
    ) {
        let snap = SublistSnapshot::<u32>::new(build(&entries(&initial, 0)));
        // A small capacity so eviction is exercised within a run.
        let mut cache = ResolveCache::<u32>::with_capacity(8);
        let mut base = 1000u32;

        for step in steps {
            match step {
                Step::Resolve(subj) => {
                    let want = fresh_match(&snap, &subj);
                    let got = cache_match(&mut cache, &snap, &subj);
                    prop_assert_eq!(got, want, "subject={:?}", subj);
                    // The cache is ALWAYS bounded, no matter the resolve history.
                    prop_assert!(cache.len() <= cache.capacity());
                }
                Step::Rebind(pats) => {
                    snap.store(build(&entries(&pats, base)));
                    base += 1000;
                }
            }
        }
    }

    /// A HIT is byte-identical to a fresh match for the SAME generation: resolve once
    /// (miss, caches), then resolve again (hit) without an intervening bind; the hit must
    /// equal a fresh match taken at that same generation.
    #[test]
    fn hit_is_identical_to_fresh_match_at_same_generation(
        patterns in proptest::collection::vec(arb_pattern(), 1..=8),
        subject in arb_subject(),
    ) {
        let snap = SublistSnapshot::<u32>::new(build(&entries(&patterns, 0)));
        let mut cache = ResolveCache::<u32>::new();

        let miss = cache_match(&mut cache, &snap, &subject); // walks, caches
        let fresh = fresh_match(&snap, &subject);
        let hit = cache_match(&mut cache, &snap, &subject); // no walk
        prop_assert_eq!(&miss, &fresh, "miss == fresh");
        prop_assert_eq!(&hit, &fresh, "hit == fresh (no stale)");
        prop_assert_eq!(cache.walk_count(), 1, "exactly one walk for the miss");
    }
}
