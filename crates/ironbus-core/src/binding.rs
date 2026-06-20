// SPDX-License-Identifier: MIT OR Apache-2.0
//! Subject->stream binding + fail-closed single-home resolution (#585, V2-M2-I9).
//!
//! This is the routing POLICY that sits on top of the wait-free trie ([`crate::sublist`]) and the
//! per-connection resolve cache ([`crate::resolve_cache`]): given a literal [`Subject`], it answers the
//! ONE question a publish needs — *which single stream stores this record?* — as a TOTAL function with
//! explicit, typed outcomes.
//!
//! # The binding
//!
//! A *binding* is a `(SubjectPattern -> target)` registration in the trie: a stream that BINDS
//! `order.>` and `payment.*.done` registers those two patterns with its own id as the target. The
//! binding table IS a [`Sublist`](crate::sublist::Sublist): `target = T` is the stream id (the trie is
//! generic, so `ironbus-core` stays IO-free and never names a storage type). Adding or removing a
//! binding rebuilds the immutable trie and swaps a fresh [`SublistSnapshot`](crate::sublist) generation
//! in — which is exactly the signal the per-connection [`ResolveCache`](crate::resolve_cache) watches to
//! drop a stale routing answer, so a bind change can never leave a connection routing to the old stream.
//!
//! # Single-home resolution (the default, fail-closed)
//!
//! A publish to a literal subject resolves to the *set* of bound streams (the trie match), then this
//! module reduces that set to a single destination under the SINGLE-HOME default:
//!
//! * **exactly one** bound stream -> [`Resolution::Routed`] (route the record there);
//! * **zero** bound streams -> [`Resolution::NoStream`] — a typed, FAIL-CLOSED reject, NOT a silent
//!   drop. This is the explicit beat over NATS, which silently discards a publish to a subject with no
//!   matching interest while still returning a successful `PubAck`: the producer believes the message
//!   landed when it vanished. IronBus refuses the publish with a typed error so the producer learns
//!   immediately that the subject is unbound;
//! * **two or more** bound streams -> [`Resolution::Ambiguous`] — also a typed reject under the
//!   single-home default, because storing one record requires ONE unambiguous destination log. The
//!   `overlap_ok` opt-in FAN-OUT (publish the record to every bound stream) is a SEPARATE, later issue;
//!   the single-home default refuses rather than guessing or silently fanning out.
//!
//! Resolution is therefore a total function: every literal subject maps to exactly one of the three
//! outcomes, none of which is a silent drop or a panic. That totality is the first-principles reason the
//! primitive lives here, beside the grammar ([`crate::subject`]) and the trie it reduces.
//!
//! # IO-free
//!
//! This module is pure compute: it inspects a borrowed target slice (or a trie match) and returns a
//! decision. It touches no filesystem, network, clock, process, or async runtime, so it stays inside
//! `ironbus-core`'s IO-free invariant (enforced by `tools/io-free-check`). The wire framing and the
//! storage-side wiring (mapping the resolved `T` to a real stream log) land in `ironbus-server`.

use crate::resolve_cache::ResolveCache;
use crate::subject::Subject;
use crate::sublist::SublistSnapshot;

/// The outcome of resolving a literal [`Subject`] to a single bound stream under the single-home
/// default. A TOTAL function: a subject is always exactly one of these, never a silent drop or a panic.
///
/// `T` is the routing target the trie carries (the stream id; a `Clone`-able opaque value here). The
/// `Routed` variant hands back the single resolved target; the two reject variants are the fail-closed
/// beat over NATS's silent-drop — a publish that resolves to zero or many streams is REFUSED with a
/// typed reason, never accepted-and-discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution<T> {
    /// EXACTLY ONE bound stream matched: route the record to `target`.
    Routed(T),
    /// ZERO bound streams matched: a fail-closed reject (`NoStreamForSubject` on the wire). The publish
    /// is REFUSED, not silently dropped — the explicit beat over NATS, which would discard it while
    /// acking success. The producer must bind the subject to a stream first.
    NoStream,
    /// TWO OR MORE bound streams matched: a fail-closed reject (`AmbiguousSubject` on the wire) under the
    /// single-home default, because one record needs one unambiguous destination log. Carries the number
    /// of streams that matched so a caller (and an operator) can see HOW ambiguous the binding set is.
    /// The opt-in `overlap_ok` fan-out is a separate, later feature; until then an ambiguous subject is
    /// refused rather than fanned out or guessed.
    Ambiguous {
        /// How many bound streams matched the subject (always `>= 2` for this variant).
        matched: usize,
    },
}

impl<T> Resolution<T> {
    /// The single routed target, or `None` for either reject. A convenience for a caller that only
    /// cares about the happy path.
    #[must_use]
    pub fn routed(self) -> Option<T> {
        match self {
            Resolution::Routed(t) => Some(t),
            Resolution::NoStream | Resolution::Ambiguous { .. } => None,
        }
    }

    /// Whether this resolution is the happy-path single route.
    #[must_use]
    pub const fn is_routed(&self) -> bool {
        matches!(self, Resolution::Routed(_))
    }
}

/// Reduces a slice of matched targets to a single-home [`Resolution`], the FAIL-CLOSED core decision:
/// zero matches -> [`Resolution::NoStream`], exactly one -> [`Resolution::Routed`], two or more ->
/// [`Resolution::Ambiguous`]. This is the one place the single-home policy lives, shared by the cached
/// and uncached resolve paths so they can never disagree.
///
/// The slice is the trie's match result for a literal subject (every bound stream whose pattern matched).
/// It is reduced WITHOUT allocating and without inspecting target identity beyond counting — two
/// DISTINCT streams binding the same subject is ambiguous, and so is one stream that (pathologically)
/// registered two patterns both matching the subject; either way a single record cannot pick one
/// destination, so both are refused under the single-home default. (Deduplicating a single stream that
/// matched via two of its own patterns into one route is a refinement the binding API avoids by not
/// registering a stream's overlapping patterns; it is called out in the #585 scope, not silently
/// collapsed here.)
#[must_use]
pub fn single_home<T: Clone>(matched: &[T]) -> Resolution<T> {
    match matched {
        [] => Resolution::NoStream,
        [one] => Resolution::Routed(one.clone()),
        many => Resolution::Ambiguous {
            matched: many.len(),
        },
    }
}

/// Resolves `subject` to a single-home [`Resolution`] DIRECTLY against `snapshot` (no cache): one
/// wait-free trie walk, then the single-home reduction. Use this for a cold or one-shot resolve; a hot
/// publisher should use [`resolve_single_home_cached`] so the steady-state resolve is O(1).
///
/// This is the uncached twin of [`resolve_single_home_cached`] and shares the exact [`single_home`]
/// reduction, so the two return identical outcomes for the same subject + routing table.
#[must_use]
pub fn resolve_single_home<T: Clone>(
    snapshot: &SublistSnapshot<T>,
    subject: &Subject<'_>,
) -> Resolution<T> {
    let mut matched = Vec::new();
    snapshot.match_into(subject, &mut matched);
    single_home(&matched)
}

/// Resolves `subject` to a single-home [`Resolution`] THROUGH the per-connection resolve cache: a cache
/// HIT is an O(1) hash lookup with NO trie walk (and no global cache flush on a bind change), a MISS
/// walks the trie once and caches the targets. The single-home reduction runs over the cached target
/// slice WITHOUT cloning the whole `Vec` (the reduction clones only the ONE routed target on the happy
/// path), via [`ResolveCache::resolve_with`].
///
/// # Why this beats NATS's per-publish global Sublist walk
///
/// NATS resolves EVERY publish through its shared `Sublist` (under a read lock) and flushes a global
/// results cache on every subscription change. Here the trie is wait-free and carries NO shared cache;
/// the cache is per-connection and generation-guarded, so steady-state resolution is O(1) and a bind
/// change costs a single generation-compare on the next publish (the cache drops its stale answers
/// lazily) rather than a global flush. A bind change therefore NEVER leaves this connection routing to a
/// stale stream: the next resolve sees the advanced [`SublistSnapshot`](crate::sublist) generation, drops
/// the cached answer, and re-resolves against the new table.
#[must_use]
pub fn resolve_single_home_cached<T: Clone>(
    cache: &mut ResolveCache<T>,
    snapshot: &SublistSnapshot<T>,
    subject: &Subject<'_>,
) -> Resolution<T> {
    cache.resolve_with(snapshot, subject, single_home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sublist::{Sublist, SublistBuilder};

    /// Build a binding trie from `(pattern, stream-id)` pairs. `T` here is a `u32` stand-in for a stream
    /// id (the server wires the real `StreamId`); the trie is generic, so the policy is identical.
    fn bindings(entries: &[(&str, u32)]) -> Sublist<u32> {
        let mut b = SublistBuilder::new();
        for (p, t) in entries {
            b.insert(p, *t).expect("valid binding pattern");
        }
        b.build(0).expect("binding set within fork bound")
    }

    fn subject(s: &str) -> Subject<'_> {
        Subject::parse_literal(s).expect("valid literal subject")
    }

    #[test]
    fn single_bound_stream_routes() {
        // "orders" binds "order.>"; a publish to "order.us.created" routes to exactly that stream.
        let snap = SublistSnapshot::new(bindings(&[("order.>", 42)]));
        assert_eq!(
            resolve_single_home(&snap, &subject("order.us.created")),
            Resolution::Routed(42)
        );
    }

    #[test]
    fn unbound_subject_is_no_stream_not_a_silent_drop() {
        // No binding matches: a FAIL-CLOSED NoStream reject, never a silent drop (the beat over NATS).
        let snap = SublistSnapshot::new(bindings(&[("order.>", 42)]));
        assert_eq!(
            resolve_single_home(&snap, &subject("telemetry.cpu")),
            Resolution::NoStream
        );
        // An EMPTY binding table refuses everything fail-closed (nothing is bound yet).
        let empty = SublistSnapshot::<u32>::empty();
        assert_eq!(
            resolve_single_home(&empty, &subject("anything")),
            Resolution::NoStream
        );
    }

    #[test]
    fn subject_bound_to_two_streams_is_ambiguous() {
        // TWO distinct streams both bind a pattern matching the subject: single-home refuses with the
        // typed AmbiguousSubject, carrying the match count.
        let snap = SublistSnapshot::new(bindings(&[("order.>", 1), ("order.us.*", 2)]));
        assert_eq!(
            resolve_single_home(&snap, &subject("order.us.created")),
            Resolution::Ambiguous { matched: 2 }
        );
        // A subject only the first pattern covers is unambiguous again.
        assert_eq!(
            resolve_single_home(&snap, &subject("order.eu.created")),
            Resolution::Routed(1)
        );
    }

    #[test]
    fn single_home_reduction_is_total() {
        assert_eq!(single_home::<u32>(&[]), Resolution::NoStream);
        assert_eq!(single_home(&[7u32]), Resolution::Routed(7));
        assert_eq!(
            single_home(&[7u32, 8, 9]),
            Resolution::Ambiguous { matched: 3 }
        );
    }

    #[test]
    fn cached_resolution_equals_uncached_and_hits_without_walking() {
        let snap = SublistSnapshot::new(bindings(&[
            ("order.>", 1),
            ("payment.*.done", 2),
            ("metric.cpu", 3),
        ]));
        let mut cache = ResolveCache::new();
        for s in [
            "order.us.created",
            "payment.visa.done",
            "metric.cpu",
            "unbound.subject",
        ] {
            let subj = subject(s);
            let want = resolve_single_home(&snap, &subj);
            // MISS then HIT both equal the uncached oracle.
            assert_eq!(resolve_single_home_cached(&mut cache, &snap, &subj), want);
            assert_eq!(resolve_single_home_cached(&mut cache, &snap, &subj), want);
        }
        // Every subject was walked exactly once (the second touch HIT without a walk).
        assert_eq!(cache.walk_count(), 4);
    }

    #[test]
    fn a_bind_change_invalidates_the_cache_no_stale_routing() {
        // Bind "order.>" -> stream 1, cache the route, then REBIND "order.>" -> stream 2. The next
        // resolve must route to the NEW stream, never the stale 1 (the generation guard drops it).
        let snap = SublistSnapshot::new(bindings(&[("order.>", 1)]));
        let mut cache = ResolveCache::new();
        let subj = subject("order.us.created");
        assert_eq!(
            resolve_single_home_cached(&mut cache, &snap, &subj),
            Resolution::Routed(1)
        );
        assert_eq!(cache.walk_count(), 1);

        // A bind change: rebuild the trie so "order.>" now targets stream 2, swap it in (the snapshot
        // advances its generation on store).
        snap.store(bindings(&[("order.>", 2)]));
        assert_eq!(
            resolve_single_home_cached(&mut cache, &snap, &subj),
            Resolution::Routed(2),
            "no stale routing after a rebind"
        );
        assert_eq!(cache.walk_count(), 2, "the bind change forced one re-walk");

        // Add a SECOND binding for the same subject: it becomes ambiguous, and the cache reflects it.
        snap.store(bindings(&[("order.>", 2), ("order.us.created", 3)]));
        assert_eq!(
            resolve_single_home_cached(&mut cache, &snap, &subj),
            Resolution::Ambiguous { matched: 2 }
        );
    }

    #[test]
    fn resolution_accessors() {
        assert_eq!(Resolution::Routed(5u32).routed(), Some(5));
        assert!(Resolution::Routed(5u32).is_routed());
        assert_eq!(Resolution::<u32>::NoStream.routed(), None);
        assert!(!Resolution::<u32>::NoStream.is_routed());
        assert_eq!(Resolution::<u32>::Ambiguous { matched: 2 }.routed(), None);
    }
}
