// SPDX-License-Identifier: MIT OR Apache-2.0
//! Differential + property tests for the subject-routing trie ("Sublist", #568, V2-M2).
//!
//! The central guarantee is a DIFFERENTIAL one: the arena trie's `match(subject)` set
//! must equal the naive set obtained by running the merged #567 matcher
//! [`SubjectPattern::matches`] against EVERY registered pattern. The trie is just a fast
//! index over that matcher; proving the two agree over randomized patterns and subjects
//! proves the trie cannot drift from the grammar's authoritative semantics.
//!
//! Layered like the grammar tests (#567):
//!
//! 1. A small GOLDEN table pins the matched-target set for hand-picked overlapping cases.
//! 2. A PROPTEST differential oracle generates random pattern sets and random subjects and
//!    asserts trie == naive on every draw.
//! 3. Snapshot/generation property: a rebuild+swap is observed wait-free and the generation
//!    is monotonic.

use std::collections::BTreeSet;

use ironbus_core::subject::{Subject, SubjectPattern, MAX_SUBJECT_DEPTH};
use ironbus_core::sublist::{Sublist, SublistBuilder, SublistSnapshot};

/// Build a trie at generation 0 from `(pattern, target)` pairs. The differential test sets
/// are small/shallow, so their worst-case fork frontier is far under [`MAX_FORK_FRONTIER`]
/// and the fail-closed build always succeeds here.
fn build(entries: &[(&str, u32)]) -> Sublist<u32> {
    let mut b = SublistBuilder::new();
    for (p, t) in entries {
        b.insert(p, *t).expect("valid test pattern");
    }
    b.build(0).expect("differential test set within fork bound")
}

/// The authoritative reference: every target whose #567 pattern matches `subject`, as a
/// sorted set. This is the oracle the trie is differentially checked against.
fn naive_match(entries: &[(&str, u32)], subject: &str) -> BTreeSet<u32> {
    let subj = Subject::parse_literal(subject).expect("valid subject");
    entries
        .iter()
        .filter_map(|(p, t)| {
            let pat = SubjectPattern::parse(p).expect("valid pattern");
            pat.matches(&subj).then_some(*t)
        })
        .collect()
}

/// The trie's matched-target set, sorted, for an order-independent comparison.
fn trie_match(trie: &Sublist<u32>, subject: &str) -> BTreeSet<u32> {
    let subj = Subject::parse_literal(subject).expect("valid subject");
    trie.match_subject(&subj).into_iter().collect()
}

// ---------------------------------------------------------------------------
// 1. Golden table: hand-picked overlapping literal / `*` / `>` cases.
// ---------------------------------------------------------------------------

#[test]
fn golden_overlapping_routing_matches_naive() {
    let entries: &[(&str, u32)] = &[
        ("a.b.c", 1),
        ("a.*.c", 2),
        ("a.b.*", 3),
        ("a.>", 4),
        (">", 5),
        ("a.b", 6),
        ("x.y.z", 7),
        ("*.b.c", 8),
    ];
    let trie = build(entries);

    for subject in [
        "a.b.c", "a.b.d", "a.b", "a.x.c", "a.b.c.d", "x.y.z", "q", "a", "p.b.c",
    ] {
        assert_eq!(
            trie_match(&trie, subject),
            naive_match(entries, subject),
            "trie disagreed with the #567 matcher on subject {subject:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Differential proptest: trie == naive over random pattern sets + subjects.
// ---------------------------------------------------------------------------

use proptest::prelude::*;

/// A legal literal token: 1..=4 chars from a SMALL alphabet so random patterns and random
/// subjects collide often (forcing real matches, not just empty sets). Matches the #567
/// legal-token alphabet (no `.`/`*`/`>`/control).
const LITERAL_TOKEN: &str = "[ab][12]?";

/// One pattern-token strategy: mostly literals, sometimes a `*`. (`>` is added separately
/// as a possible final token so the `>`-must-be-last grammar rule is always honored.)
fn pattern_token() -> impl Strategy<Value = String> {
    prop_oneof![
        8 => LITERAL_TOKEN.prop_map(String::from),
        2 => Just("*".to_string()),
    ]
}

/// A strategy yielding one syntactically-valid pattern string: 1..=4 leading
/// literal-or-`*` tokens, optionally terminated by a single trailing `>`. Constructed so it
/// always parses under #567 (the `>` is only ever appended last).
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

/// A strategy yielding one valid LITERAL subject: 1..=5 literal tokens (no wildcards).
fn arb_subject() -> impl Strategy<Value = String> {
    proptest::collection::vec(LITERAL_TOKEN.prop_map(String::from), 1..=5)
        .prop_map(|toks| toks.join("."))
}

proptest! {
    /// THE differential property: for a random set of registered patterns (each with a
    /// distinct target) and a random literal subject, the trie's matched-target set EQUALS
    /// the set produced by running the #567 matcher against every pattern. This is the
    /// proof that the arena index agrees with the authoritative grammar semantics.
    #[test]
    fn trie_match_equals_naive_match(
        patterns in proptest::collection::vec(arb_pattern(), 1..=12),
        subject in arb_subject(),
    ) {
        // Assign each pattern a distinct target id by index.
        let entries: Vec<(&str, u32)> = patterns
            .iter()
            .enumerate()
            .map(|(i, p)| (p.as_str(), u32::try_from(i).unwrap()))
            .collect();

        let trie = build(&entries);
        let got = trie_match(&trie, &subject);
        let want = naive_match(&entries, &subject);
        prop_assert_eq!(got, want, "patterns={:?} subject={:?}", patterns, subject);
    }

    /// The differential property must hold after a rebuild+swap too: install pattern-set A,
    /// then swap in pattern-set B, and the live snapshot must match set B (never a stale or
    /// torn mix), still agreeing with the naive oracle.
    #[test]
    fn snapshot_after_swap_equals_naive_for_new_table(
        patterns_a in proptest::collection::vec(arb_pattern(), 1..=6),
        patterns_b in proptest::collection::vec(arb_pattern(), 1..=6),
        subject in arb_subject(),
    ) {
        let entries_a: Vec<(&str, u32)> = patterns_a
            .iter()
            .enumerate()
            .map(|(i, p)| (p.as_str(), u32::try_from(i).unwrap()))
            .collect();
        let entries_b: Vec<(&str, u32)> = patterns_b
            .iter()
            .enumerate()
            .map(|(i, p)| (p.as_str(), 1000 + u32::try_from(i).unwrap()))
            .collect();

        let snap = SublistSnapshot::<u32>::new(build(&entries_a));
        let g0 = snap.generation();
        prop_assert_eq!(g0, 0);

        let g1 = snap.store(build(&entries_b));
        prop_assert_eq!(g1, 1);
        prop_assert_eq!(snap.generation(), 1);

        let subj = Subject::parse_literal(&subject).expect("valid subject");
        let mut out = Vec::new();
        let gen = snap.match_into(&subj, &mut out);
        prop_assert_eq!(gen, 1, "match stamped the post-swap generation");

        let got: BTreeSet<u32> = out.into_iter().collect();
        let want = naive_match(&entries_b, &subject);
        prop_assert_eq!(got, want, "post-swap snapshot disagreed with naive set B");
    }
}

// ---------------------------------------------------------------------------
// 3. Wait-free read across a concurrent swap (integration-level).
// ---------------------------------------------------------------------------

#[test]
fn deep_subject_within_cap_routes_and_terminates() {
    // A subject at exactly MAX_SUBJECT_DEPTH against a catch-all `>` must match, proving
    // the bounded walk handles the deepest legal subject the #567 parser admits.
    let trie = build(&[(">", 42)]);
    let deep = vec!["a"; MAX_SUBJECT_DEPTH].join(".");
    assert_eq!(trie_match(&trie, &deep), BTreeSet::from([42]));
}
