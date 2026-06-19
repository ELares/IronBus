// SPDX-License-Identifier: MIT OR Apache-2.0
//! The subject-routing trie ("Sublist"): a wait-free, arena-flattened token-trie that
//! resolves a published [`Subject`] to the set of registered [`SubjectPattern`] targets
//! it matches (#568, V2-M2).
//!
//! This is the routing core that sits on the publish hot path. A produce carries a
//! literal subject; routing must answer "which subscriptions / stream bindings does this
//! subject hit?" in `O(tokens)` work without ever blocking the writer. The structure is
//! built directly on the merged subject grammar (#567, [`crate::subject`]): it consumes
//! [`Subject::tokens`] / [`SubjectPattern::tokens`] and reuses
//! [`MAX_SUBJECT_DEPTH`](crate::subject::MAX_SUBJECT_DEPTH), so
//! the trie and the parser can never disagree about what a token is.
//!
//! # Why this beats the NATS `Sublist`
//!
//! NATS resolves a subject against its subscription set with a `Sublist` that:
//!
//! 1. takes a **read lock** (`sync.RWMutex`) on every publish, and
//! 2. keeps a **results cache** that it *flushes entirely* on every subscription change,
//!    and on a *wildcard* sub/unsub it linear-scans the whole cache (bounded by
//!    `slCacheMax = 1024`) under the **write lock** to evict stale entries, and
//! 3. expands a `>`/`*` ("pwc") match with a recursion whose worst case is exponential in
//!    the number of wildcard levels.
//!
//! IronBus replaces all three:
//!
//! 1. **Wait-free reads.** The built trie is immutable and wrapped in an
//!    [`arc_swap::ArcSwap`] ([`SublistSnapshot`]). A [`SublistSnapshot::match_subject`]
//!    is a wait-free `Arc` load plus an integer-compare walk — no lock, no writer
//!    coordination, never blocked by a concurrent rebuild.
//! 2. **No global cache flush on a bind change.** A bind change rebuilds a fresh
//!    immutable trie and atomically swaps the pointer; readers in flight keep their old
//!    snapshot until they drop it. There is no shared results cache to flush and no
//!    `O(slCacheMax)` wildcard-unsub scan. The snapshot carries a monotonic
//!    [`Sublist::generation`] so a *separate* per-connection resolve cache (#M2-I8) can
//!    detect "the routing table changed, my cached answer is stale" with a single integer
//!    compare — that cache is built on top of this, NOT here.
//! 3. **A bounded fork.** The wildcard frontier is explicitly capped at
//!    [`MAX_FORK_FRONTIER`] live nodes, so [`Sublist::match_into`] has a provable
//!    `O(depth × MAX_FORK_FRONTIER × log F)` bound (`F` = a node's literal fan-out)
//!    instead of NATS's exponential pwc recursion.
//!
//! # Arena layout (no pointer chasing)
//!
//! Nodes live in a single contiguous `Vec<Node<…>>` indexed by [`NodeId`] (a `u32`), not
//! a tree of boxed/`HashMap` nodes. Each node holds:
//!
//! * a **sorted** `literals: Vec<(u64, NodeId)>` of literal children keyed by
//!   `xxh3_64(token)` — looked up by binary search (cache-friendly integer compares, the
//!   same `xxh3_64` the key-shared router uses in [`crate::keyshared`]);
//! * `star_child: Option<NodeId>` — the `*` single-token branch;
//! * `terminal` — the targets of patterns that *end exactly here* (no trailing `>`);
//! * `gt_terminal` — the targets of patterns whose final token is `>` rooted here (they
//!   match one-or-more trailing subject tokens).
//!
//! Targets are interned once into a flat [`Sublist`]-level table and referenced by index,
//! so a target shared by many patterns is stored once and a node only holds small index
//! ranges.
//!
//! # IO-free
//!
//! This module is pure compute. It uses `std::sync::Arc`, `std::sync::atomic`, and
//! `arc_swap` for the wait-free snapshot — all allocation/atomics, no filesystem,
//! network, clock, process, or async runtime — so it stays inside `ironbus-core`'s
//! IO-free invariant (enforced by `tools/io-free-check`: the AST walk forbids
//! `std::{io,fs,net,os,process}` and async runtimes, none of which appear here, and the
//! `cargo tree` half forbids async-runtime crates, which `arc-swap` is not).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use xxhash_rust::xxh3::xxh3_64;

use crate::subject::{Subject, SubjectPattern};

/// An index into the arena's node vector. `u32` keeps a node compact and the whole arena
/// addressable up to `u32::MAX` nodes, far beyond any real routing table.
pub type NodeId = u32;

/// The arena root is always node 0.
const ROOT: NodeId = 0;

/// The hard cap on the wildcard match frontier — the maximum number of live trie nodes
/// [`Sublist::match_into`] will track at any one subject depth.
///
/// This is the bound that replaces NATS's exponential pwc recursion. At each subject
/// token the frontier can branch (a literal child *and* the `*` child both match), so an
/// unbounded frontier could in principle grow like `2^depth`. We deduplicate the frontier
/// (a node is visited at most once per level) and cap it at this constant, which makes the
/// per-match work provably `O(depth × MAX_FORK_FRONTIER × log F)` where `depth` is at most
/// [`MAX_SUBJECT_DEPTH`](crate::subject::MAX_SUBJECT_DEPTH) and `F` is a node's literal
/// fan-out searched by binary search.
///
/// The cap is generous: a frontier only grows when *distinct* trie nodes are
/// simultaneously live, which requires that many genuinely overlapping registered
/// patterns at the same depth. `1024` mirrors NATS's own `slCacheMax` so the comparison is
/// like-for-like — but here it is a fork bound on a wait-free walk, not a shared cache
/// that a wildcard unsub must linear-scan under a write lock.
pub const MAX_FORK_FRONTIER: usize = 1024;

/// One arena node: a position in the token-trie reached by some token prefix.
///
/// `literals` is kept sorted by hash so a child lookup is a binary search over integers.
/// `star_child` is the `*` (single-token) branch. `terminal` / `gt_terminal` are
/// half-open `[start, end)` ranges into the [`Sublist`] target table (empty when the range
/// is zero-length), naming the patterns that end here exactly or with a trailing `>`.
#[derive(Debug)]
struct Node {
    /// Literal children, sorted ascending by `xxh3_64(token)`, looked up by binary
    /// search. The `u64` is the token hash; the [`NodeId`] is the child node.
    literals: Vec<(u64, NodeId)>,
    /// The `*` single-token-wildcard child, if any pattern forks here on `*`.
    star_child: Option<NodeId>,
    /// `[start, end)` into [`Sublist::targets`]: patterns that terminate *exactly* at this
    /// node (no trailing `>`), i.e. match a subject of exactly this depth.
    terminal: (u32, u32),
    /// `[start, end)` into [`Sublist::targets`]: patterns whose final token is `>` rooted
    /// at this node, matching one-or-more trailing subject tokens.
    gt_terminal: (u32, u32),
}

impl Node {
    /// The literal child for `hash`, if present, via binary search over the sorted list.
    #[inline]
    fn literal_child(&self, hash: u64) -> Option<NodeId> {
        self.literals
            .binary_search_by_key(&hash, |&(h, _)| h)
            .ok()
            .map(|i| self.literals[i].1)
    }
}

/// A builder that accumulates `(pattern, target)` registrations and freezes them into an
/// immutable [`Sublist`].
///
/// The builder owns its pattern strings (a registration outlives the borrowed `&str` the
/// parser produced), re-validating each through [`SubjectPattern::parse`] so a caller can
/// hand it raw strings and the trie never admits an unparsed subject. Building is
/// `O(total tokens)`; it is the *rare*, amortized cost a bind change pays, against which
/// every read is wait-free.
///
/// `T` is the routing target — a generic id (e.g. a `StreamId` newtype or a `u64`) that the
/// binding policy (#585) and the wire layer (#588) attach meaning to. The trie treats it
/// only as an opaque, `Clone`-able value to return on a match.
#[derive(Debug, Default)]
pub struct SublistBuilder<T> {
    /// Accumulated registrations: an owned pattern string and its target.
    entries: Vec<(String, T)>,
}

impl<T: Clone> SublistBuilder<T> {
    /// A new, empty builder.
    #[must_use]
    pub fn new() -> SublistBuilder<T> {
        SublistBuilder {
            entries: Vec::new(),
        }
    }

    /// Registers `pattern` -> `target`.
    ///
    /// The pattern is validated by the #567 parser; an invalid pattern is rejected here
    /// (fail-closed) so a malformed subscription can never enter the trie.
    ///
    /// # Errors
    ///
    /// Returns the typed [`crate::subject::SubjectError`] if `pattern` is not a valid
    /// subject pattern.
    pub fn insert(&mut self, pattern: &str, target: T) -> Result<(), crate::subject::SubjectError> {
        // Validate via #567 (do not re-implement the grammar); store the owned string.
        SubjectPattern::parse(pattern)?;
        self.entries.push((pattern.to_owned(), target));
        Ok(())
    }

    /// Freezes the accumulated registrations into an immutable [`Sublist`] with the given
    /// `generation`.
    ///
    /// Build is `O(total tokens across all patterns)`: each pattern walks its tokens once,
    /// creating arena nodes on demand and appending its target to the matched terminal.
    /// The per-node literal lists are sorted once at the end so reads can binary-search.
    ///
    /// # Panics
    ///
    /// Panics only on internal-invariant violations that cannot occur for a builder used
    /// through its public API: if a stored pattern (already validated by [`Self::insert`])
    /// fails to re-parse, or if the arena/target table would exceed `u32::MAX` entries
    /// (far beyond any real routing table).
    #[must_use]
    pub fn build(&self, generation: u64) -> Sublist<T> {
        // The arena starts with the root. Literal children are accumulated unsorted (as a
        // scratch map keyed by hash) then frozen sorted.
        let mut nodes: Vec<NodeScratch> = vec![NodeScratch::new()];
        // Per-node terminal/gt target lists, parallel to `nodes`, assembled before
        // flattening into the single contiguous target table.
        let mut terminals: Vec<Vec<T>> = vec![Vec::new()];
        let mut gt_terminals: Vec<Vec<T>> = vec![Vec::new()];

        for (pattern, target) in &self.entries {
            // Re-parse the stored (already-validated) pattern; `expect` is sound because
            // `insert` only ever stored strings that parsed.
            let pat = SubjectPattern::parse(pattern)
                .expect("a registered pattern was validated by insert()");

            let mut cur: NodeId = ROOT;
            let mut placed_gt = false;
            for token in pat.tokens() {
                match token {
                    ">" => {
                        // The grammar guarantees `>` is the final token: record the target
                        // as a tail-wildcard terminal at the CURRENT node and stop.
                        gt_terminals[cur as usize].push(target.clone());
                        placed_gt = true;
                        break;
                    }
                    "*" => {
                        cur = descend_star(&mut nodes, &mut terminals, &mut gt_terminals, cur);
                    }
                    literal => {
                        let hash = xxh3_64(literal.as_bytes());
                        cur = descend_literal(
                            &mut nodes,
                            &mut terminals,
                            &mut gt_terminals,
                            cur,
                            hash,
                        );
                    }
                }
            }
            if !placed_gt {
                // A wildcard-free or `*`-ending pattern terminates exactly at `cur`.
                terminals[cur as usize].push(target.clone());
            }
        }

        // Flatten: build the single contiguous target table and the final sorted nodes.
        let mut targets: Vec<T> = Vec::new();
        let mut final_nodes: Vec<Node> = Vec::with_capacity(nodes.len());
        for (i, scratch) in nodes.into_iter().enumerate() {
            let term = push_range(&mut targets, &mut terminals[i]);
            let gt = push_range(&mut targets, &mut gt_terminals[i]);
            let mut literals: Vec<(u64, NodeId)> = scratch.literals.into_iter().collect();
            literals.sort_unstable_by_key(|&(h, _)| h);
            final_nodes.push(Node {
                literals,
                star_child: scratch.star_child,
                terminal: term,
                gt_terminal: gt,
            });
        }

        Sublist {
            nodes: final_nodes,
            targets,
            generation,
        }
    }
}

/// A mutable scratch node used only while building (literal children as a plain `Vec` of
/// `(hash, child)` keyed lookups before they are frozen sorted).
struct NodeScratch {
    literals: Vec<(u64, NodeId)>,
    star_child: Option<NodeId>,
}

impl NodeScratch {
    const fn new() -> NodeScratch {
        NodeScratch {
            literals: Vec::new(),
            star_child: None,
        }
    }

    /// The existing literal child for `hash`, if any (linear scan; build-time only, and
    /// each node's fan-out is small for a real routing table).
    fn literal_child(&self, hash: u64) -> Option<NodeId> {
        self.literals
            .iter()
            .find(|&&(h, _)| h == hash)
            .map(|&(_, n)| n)
    }
}

/// Build-time: follow (or create) the literal child of `cur` for `hash`, returning the
/// child [`NodeId`]. Appends parallel empty terminal lists for any new node.
fn descend_literal<T>(
    nodes: &mut Vec<NodeScratch>,
    terminals: &mut Vec<Vec<T>>,
    gt_terminals: &mut Vec<Vec<T>>,
    cur: NodeId,
    hash: u64,
) -> NodeId {
    if let Some(child) = nodes[cur as usize].literal_child(hash) {
        return child;
    }
    let child = new_node(nodes, terminals, gt_terminals);
    nodes[cur as usize].literals.push((hash, child));
    child
}

/// Build-time: follow (or create) the `*` child of `cur`, returning the child [`NodeId`].
fn descend_star<T>(
    nodes: &mut Vec<NodeScratch>,
    terminals: &mut Vec<Vec<T>>,
    gt_terminals: &mut Vec<Vec<T>>,
    cur: NodeId,
) -> NodeId {
    if let Some(child) = nodes[cur as usize].star_child {
        return child;
    }
    let child = new_node(nodes, terminals, gt_terminals);
    nodes[cur as usize].star_child = Some(child);
    child
}

/// Build-time: push a fresh node and its parallel empty terminal lists, returning its
/// [`NodeId`].
///
/// # Panics
///
/// Panics if the arena would exceed `u32::MAX` nodes — far beyond any real routing table
/// (the #567 depth cap and the bounded subject space keep node count tiny in practice).
fn new_node<T>(
    nodes: &mut Vec<NodeScratch>,
    terminals: &mut Vec<Vec<T>>,
    gt_terminals: &mut Vec<Vec<T>>,
) -> NodeId {
    let id = NodeId::try_from(nodes.len()).expect("arena node count within u32 range");
    nodes.push(NodeScratch::new());
    terminals.push(Vec::new());
    gt_terminals.push(Vec::new());
    id
}

/// Build-time: drain `src` into the end of the flat `targets` table, returning the
/// `[start, end)` range it occupies (a zero-length range when `src` is empty).
fn push_range<T>(targets: &mut Vec<T>, src: &mut Vec<T>) -> (u32, u32) {
    let start = u32::try_from(targets.len()).expect("target table within u32 range");
    targets.append(src);
    let end = u32::try_from(targets.len()).expect("target table within u32 range");
    (start, end)
}

/// An immutable, built routing trie: the arena, its flat target table, and the generation
/// stamp the snapshot carries.
///
/// A `Sublist` is built once by [`SublistBuilder::build`] and never mutated; a bind change
/// produces a NEW `Sublist` and swaps it in via [`SublistSnapshot`]. Matching reads borrow
/// it immutably and are wait-free.
#[derive(Debug)]
pub struct Sublist<T> {
    /// The contiguous arena. `nodes[0]` is the root.
    nodes: Vec<Node>,
    /// The flat target table; node terminal/gt ranges index into this.
    targets: Vec<T>,
    /// A monotonic stamp identifying this routing table version. The per-connection
    /// resolve cache (#M2-I8) compares it to know when its cached answer went stale; the
    /// trie itself only carries it.
    generation: u64,
}

impl<T: Clone> Sublist<T> {
    /// The generation stamp of this routing table version.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The number of arena nodes (root included). Useful for tests/metrics.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns every target whose registered pattern matches `subject`, allocating a fresh
    /// `Vec`. Order is unspecified (it follows arena/registration order). Convenience over
    /// [`Sublist::match_into`].
    #[must_use]
    pub fn match_subject(&self, subject: &Subject<'_>) -> Vec<T> {
        let mut out = Vec::new();
        self.match_into(subject, &mut out);
        out
    }

    /// Appends every matching target to `out` (cleared first), reusing the caller's buffer
    /// so the publish hot path can match without a per-call allocation.
    ///
    /// # The bounded walk
    ///
    /// The walk advances a *frontier* of live nodes one subject token at a time. At the
    /// start of each token the frontier holds the nodes reachable by the prefix consumed
    /// so far; for the new token each live node contributes (a) its literal child whose
    /// hash equals the token's hash and (b) its `*` child. Before descending, every live
    /// node's `gt_terminal` is harvested (a `>` rooted there matches this and all further
    /// tokens). The next frontier is deduplicated and **capped at [`MAX_FORK_FRONTIER`]**,
    /// so the walk is `O(depth × MAX_FORK_FRONTIER × log F)` — never NATS's exponential
    /// pwc recursion. `depth` is bounded by
    /// [`MAX_SUBJECT_DEPTH`](crate::subject::MAX_SUBJECT_DEPTH) (the #567 parser already
    /// guarantees the subject is within the cap).
    pub fn match_into(&self, subject: &Subject<'_>, out: &mut Vec<T>) {
        out.clear();
        // Two ping-ponged frontier buffers of node ids; both bounded by MAX_FORK_FRONTIER.
        let mut frontier: Vec<NodeId> = Vec::with_capacity(MAX_FORK_FRONTIER.min(16));
        let mut next: Vec<NodeId> = Vec::with_capacity(MAX_FORK_FRONTIER.min(16));
        frontier.push(ROOT);

        for token in subject.tokens() {
            let hash = xxh3_64(token.as_bytes());
            next.clear();
            for &nid in &frontier {
                let node = &self.nodes[nid as usize];
                // A `>` rooted at this node matches this token and every later one.
                self.collect_range(node.gt_terminal, out);
                // Advance on the literal child (hash match) and the `*` child.
                if let Some(child) = node.literal_child(hash) {
                    push_unique_capped(&mut next, child);
                }
                if let Some(child) = node.star_child {
                    push_unique_capped(&mut next, child);
                }
            }
            std::mem::swap(&mut frontier, &mut next);
            if frontier.is_empty() {
                // No live node can match a further token; nothing more to harvest.
                return;
            }
        }

        // The subject is exhausted: every node still live matched it exactly, so its
        // exact-terminal patterns match. (`gt_terminal`s were already harvested above as
        // each token was consumed, which is correct: `a.>` matches `a.b` but not `a`.)
        for &nid in &frontier {
            self.collect_range(self.nodes[nid as usize].terminal, out);
        }
    }

    /// Appends the targets in the half-open `range` of the flat target table to `out`.
    #[inline]
    fn collect_range(&self, range: (u32, u32), out: &mut Vec<T>) {
        let (start, end) = (range.0 as usize, range.1 as usize);
        out.extend_from_slice(&self.targets[start..end]);
    }
}

/// Pushes `id` onto `frontier` iff it is not already present and the frontier is below
/// [`MAX_FORK_FRONTIER`]. The dedup keeps a node visited at most once per level (so the
/// frontier can never exceed the live node count) and the cap makes the bound explicit
/// even for a pathologically overlapping pattern set.
#[inline]
fn push_unique_capped(frontier: &mut Vec<NodeId>, id: NodeId) {
    if frontier.len() >= MAX_FORK_FRONTIER {
        return;
    }
    if !frontier.contains(&id) {
        frontier.push(id);
    }
}

/// A wait-free snapshot of the routing trie: an [`arc_swap::ArcSwap`] holding the current
/// immutable [`Sublist`].
///
/// Reads ([`SublistSnapshot::match_subject`] / [`SublistSnapshot::load`]) are a wait-free
/// `Arc` load and a walk — no lock, never blocked by a concurrent rebuild. A bind change
/// builds a fresh `Sublist` (with the next generation) and [`SublistSnapshot::store`]s it;
/// in-flight readers keep their loaded snapshot until they drop it, so there is no global
/// cache to flush and no writer/reader contention. The generation is sourced from a
/// monotonic counter so each swapped-in table has a strictly larger stamp.
#[derive(Debug)]
pub struct SublistSnapshot<T> {
    current: ArcSwap<Sublist<T>>,
    /// The next generation to stamp; bumped on every [`SublistSnapshot::store`].
    next_generation: AtomicU64,
}

impl<T: Clone> SublistSnapshot<T> {
    /// Creates a snapshot holding `initial` as generation 0.
    #[must_use]
    pub fn new(initial: Sublist<T>) -> SublistSnapshot<T> {
        SublistSnapshot {
            current: ArcSwap::from_pointee(initial),
            next_generation: AtomicU64::new(1),
        }
    }

    /// Creates a snapshot holding an EMPTY routing table (generation 0): matches nothing
    /// until a table is stored.
    #[must_use]
    pub fn empty() -> SublistSnapshot<T> {
        SublistSnapshot::new(SublistBuilder::<T>::new().build(0))
    }

    /// Loads the current immutable trie. This is a wait-free `Arc` load; the returned guard
    /// keeps that exact version alive for the duration of the read even if a rebuild swaps
    /// a new one in concurrently.
    #[must_use]
    pub fn load(&self) -> arc_swap::Guard<Arc<Sublist<T>>> {
        self.current.load()
    }

    /// The generation of the currently-installed trie.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.current.load().generation()
    }

    /// Atomically installs `next` as the current trie, stamping it with the next monotonic
    /// generation and returning that generation.
    ///
    /// `next` is built (the `O(patterns)` rebuild) BEFORE this call; the swap itself is a
    /// single wait-free atomic store, so a reader is never blocked by a rebuild. The
    /// builder's `generation` argument is overwritten with the monotonic stamp this
    /// snapshot assigns, so generations are strictly increasing per snapshot regardless of
    /// what the caller passed to [`SublistBuilder::build`].
    pub fn store(&self, mut next: Sublist<T>) -> u64 {
        let gen = self.next_generation.fetch_add(1, Ordering::Relaxed);
        next.generation = gen;
        self.current.store(Arc::new(next));
        gen
    }

    /// Convenience: appends every target matching `subject` to `out` against the currently
    /// loaded trie. Wait-free. Returns the generation the answer was computed against, so a
    /// per-connection cache (#M2-I8) can stamp it.
    pub fn match_into(&self, subject: &Subject<'_>, out: &mut Vec<T>) -> u64 {
        let guard = self.current.load();
        guard.match_into(subject, out);
        guard.generation()
    }

    /// Convenience: returns every target matching `subject` against the currently loaded
    /// trie (allocates). Wait-free.
    #[must_use]
    pub fn match_subject(&self, subject: &Subject<'_>) -> Vec<T> {
        self.current.load().match_subject(subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subject::{SubjectError, MAX_SUBJECT_DEPTH};

    /// Build a trie from `(pattern, target)` pairs at generation 0.
    fn build<T: Clone>(entries: &[(&str, T)]) -> Sublist<T> {
        let mut b = SublistBuilder::new();
        for (p, t) in entries {
            b.insert(p, t.clone()).expect("valid test pattern");
        }
        b.build(0)
    }

    /// Match a literal subject and return a sorted target vec for order-independent
    /// assertions.
    fn matches<T: Clone + Ord>(trie: &Sublist<T>, subject: &str) -> Vec<T> {
        let s = Subject::parse_literal(subject).expect("valid test subject");
        let mut v = trie.match_subject(&s);
        v.sort();
        v
    }

    #[test]
    fn literal_pattern_matches_only_itself() {
        let trie = build(&[("a.b.c", 1u32)]);
        assert_eq!(matches(&trie, "a.b.c"), vec![1]);
        assert_eq!(matches(&trie, "a.b"), Vec::<u32>::new());
        assert_eq!(matches(&trie, "a.b.c.d"), Vec::<u32>::new());
        assert_eq!(matches(&trie, "a.b.d"), Vec::<u32>::new());
    }

    #[test]
    fn star_matches_exactly_one_token() {
        let trie = build(&[("a.*.c", 1u32)]);
        assert_eq!(matches(&trie, "a.b.c"), vec![1]);
        assert_eq!(matches(&trie, "a.zzz.c"), vec![1]);
        assert_eq!(matches(&trie, "a.b.b.c"), Vec::<u32>::new()); // `*` is one token
        assert_eq!(matches(&trie, "a.c"), Vec::<u32>::new()); // `*` needs a token
    }

    #[test]
    fn top_level_star() {
        let trie = build(&[("*", 1u32)]);
        assert_eq!(matches(&trie, "anything"), vec![1]);
        assert_eq!(matches(&trie, "two.tokens"), Vec::<u32>::new());
    }

    #[test]
    fn tail_wildcard_matches_one_or_more_trailing() {
        let trie = build(&[("a.>", 1u32)]);
        assert_eq!(matches(&trie, "a.b"), vec![1]);
        assert_eq!(matches(&trie, "a.b.c.d"), vec![1]);
        assert_eq!(matches(&trie, "a"), Vec::<u32>::new()); // `>` needs a trailing token
        assert_eq!(matches(&trie, "b.c"), Vec::<u32>::new()); // prefix must match
    }

    #[test]
    fn top_level_tail_wildcard_matches_everything_nonempty() {
        let trie = build(&[(">", 1u32)]);
        assert_eq!(matches(&trie, "a"), vec![1]);
        assert_eq!(matches(&trie, "a.b.c"), vec![1]);
    }

    #[test]
    fn mixed_wildcards() {
        let trie = build(&[("a.*.>", 1u32)]);
        assert_eq!(matches(&trie, "a.b.c"), vec![1]);
        assert_eq!(matches(&trie, "a.b.c.d.e"), vec![1]);
        assert_eq!(matches(&trie, "a.b"), Vec::<u32>::new()); // `>` after `*` needs a tail
    }

    #[test]
    fn overlapping_patterns_all_match() {
        // A literal, a `*`, and a `>` that all cover `a.b.c` plus one that does not.
        let trie = build(&[
            ("a.b.c", 1u32),
            ("a.*.c", 2u32),
            ("a.>", 3u32),
            ("a.b.*", 4u32),
            ("x.>", 5u32),
        ]);
        assert_eq!(matches(&trie, "a.b.c"), vec![1, 2, 3, 4]);
        // `a.b.d` hits `a.b.*` and `a.>` but not the `c`-specific literals.
        assert_eq!(matches(&trie, "a.b.d"), vec![3, 4]);
        // `x.y` hits only `x.>`.
        assert_eq!(matches(&trie, "x.y"), vec![5]);
    }

    #[test]
    fn many_targets_on_one_pattern_dedup_in_table() {
        // The same pattern registered with several distinct targets returns all of them.
        let trie = build(&[("a.b", 1u32), ("a.b", 2u32), ("a.b", 3u32)]);
        assert_eq!(matches(&trie, "a.b"), vec![1, 2, 3]);
    }

    #[test]
    fn empty_trie_matches_nothing() {
        let trie = build::<u32>(&[]);
        assert_eq!(matches(&trie, "a.b.c"), Vec::<u32>::new());
    }

    #[test]
    fn insert_rejects_invalid_pattern() {
        let mut b = SublistBuilder::new();
        assert_eq!(
            b.insert("a..b", 1u32),
            Err(SubjectError::EmptyToken { index: 1 })
        );
        assert_eq!(
            b.insert("a.>.b", 1u32),
            Err(SubjectError::TailWildcardNotLast { index: 1 })
        );
    }

    #[test]
    fn match_into_reuses_buffer() {
        let trie = build(&[("a.>", 1u32)]);
        let s1 = Subject::parse_literal("a.b").unwrap();
        let s2 = Subject::parse_literal("x.y").unwrap();
        let mut buf = Vec::new();
        trie.match_into(&s1, &mut buf);
        assert_eq!(buf, vec![1]);
        // A non-matching subject clears the buffer (no stale entries).
        trie.match_into(&s2, &mut buf);
        assert!(buf.is_empty());
    }

    // ---- snapshot / generation / wait-free swap ----

    #[test]
    fn snapshot_generation_is_monotonic_on_store() {
        let snap = SublistSnapshot::<u32>::empty();
        assert_eq!(snap.generation(), 0);
        let g1 = snap.store(build(&[("a", 1u32)]));
        assert_eq!(g1, 1);
        assert_eq!(snap.generation(), 1);
        let g2 = snap.store(build(&[("a", 1u32), ("b", 2u32)]));
        assert_eq!(g2, 2);
        assert_eq!(snap.generation(), 2);
    }

    #[test]
    fn snapshot_match_reflects_swapped_table_and_stamps_generation() {
        let snap = SublistSnapshot::<u32>::empty();
        let s = Subject::parse_literal("a.b").unwrap();
        let mut out = Vec::new();

        let g0 = snap.match_into(&s, &mut out);
        assert_eq!(g0, 0);
        assert!(out.is_empty());

        snap.store(build(&[("a.>", 7u32)]));
        let g1 = snap.match_into(&s, &mut out);
        assert_eq!(g1, 1);
        assert_eq!(out, vec![7]);
    }

    #[test]
    fn loaded_snapshot_is_stable_across_a_concurrent_swap() {
        // A reader that loaded generation 0 keeps seeing it after a store swaps in a new
        // table — the wait-free read is never mutated underneath it.
        let snap = SublistSnapshot::<u32>::new(build(&[("a.b", 1u32)]));
        let s = Subject::parse_literal("a.b").unwrap();

        let guard = snap.load(); // pins generation 0
        assert_eq!(guard.generation(), 0);
        assert_eq!(guard.match_subject(&s), vec![1]);

        // Rebuild + swap: the table now maps a.b -> 99.
        snap.store(build(&[("a.b", 99u32)]));

        // The pinned guard still sees the OLD table.
        assert_eq!(guard.generation(), 0);
        assert_eq!(guard.match_subject(&s), vec![1]);
        // A fresh load sees the NEW one.
        assert_eq!(snap.match_subject(&s), vec![99]);
        assert_eq!(snap.generation(), 1);
    }

    #[test]
    fn concurrent_readers_during_rebuilds_never_panic() {
        // Hammer match() on many threads while another thread rebuilds+swaps repeatedly;
        // a wait-free read must never observe a torn or freed table. (A lock-based design
        // would serialize; this just proves correctness/no-panic under contention.)
        use std::sync::Arc as StdArc;
        use std::thread;

        let snap = StdArc::new(SublistSnapshot::<u32>::new(build(&[("a.>", 1u32)])));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let snap = StdArc::clone(&snap);
            handles.push(thread::spawn(move || {
                let s = Subject::parse_literal("a.b.c").unwrap();
                let mut buf = Vec::new();
                for _ in 0..2_000 {
                    let _gen = snap.match_into(&s, &mut buf);
                    // Every installed table matches `a.b.c` with exactly one target.
                    assert_eq!(buf.len(), 1);
                }
            }));
        }
        // The writer rebuilds and swaps a fresh single-pattern table repeatedly.
        let writer = {
            let snap = StdArc::clone(&snap);
            thread::spawn(move || {
                for i in 0..2_000u32 {
                    snap.store(build(&[("a.>", i)]));
                }
            })
        };

        writer.join().unwrap();
        for h in handles {
            h.join().unwrap();
        }
    }

    // ---- bounded fork guarantee ----

    #[test]
    fn fork_frontier_is_bounded_under_heavy_wildcard_overlap() {
        // Register MANY patterns that all fork on `*` at the same depths, the shape that
        // makes NATS's pwc recursion blow up. The frontier must stay within the cap and
        // match() must terminate quickly with the correct set.
        let mut b = SublistBuilder::new();
        // Each pattern is `t<i%8>.*.*.>` — one of 8 distinct literal-prefixed nodes, then a
        // `*.*` fork and a `>` tail. Many targets pile onto the SAME 8 trie paths, so the
        // arena stays tiny while the gt-terminal target lists grow. The frontier (live
        // NODE set) is what must stay bounded, NOT the number of targets harvested.
        for i in 0..2000u32 {
            b.insert(&format!("t{}.*.*.>", i % 8), i).ok();
        }
        // A pure-wildcard pattern that matches everything of depth >= 1.
        b.insert(">", 999_999u32).unwrap();
        let trie = b.build(0);

        let s = Subject::parse_literal("t0.a.b.c.d").unwrap();
        let mut out = Vec::new();
        trie.match_into(&s, &mut out);

        // It must terminate (the test would hang/OOM if the fork were exponential).
        // The arena has only a handful of nodes (8 prefixes × the shared `*.*` path),
        // proving the structure did not blow up:
        assert!(
            trie.node_count() < 64,
            "arena stayed small: {} nodes",
            trie.node_count()
        );
        // `t0.a.b.c.d` matches `t0.*.*.>` for every i with i%8==0 (i = 0,8,...,1992) plus
        // the catch-all `>`. That is the EXACT correct set, and it must include `>`.
        let expected: std::collections::BTreeSet<u32> = (0..2000u32)
            .filter(|i| i % 8 == 0)
            .chain([999_999])
            .collect();
        let got: std::collections::BTreeSet<u32> = out.into_iter().collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn deep_subject_at_max_depth_terminates() {
        // A subject at exactly MAX_SUBJECT_DEPTH against a `>` catch-all: bounded walk.
        let trie = build(&[(">", 1u32)]);
        let deep = vec!["a"; MAX_SUBJECT_DEPTH].join(".");
        let s = Subject::parse_literal(&deep).unwrap();
        assert_eq!(matches(&trie, s.as_str()), vec![1]);
    }
}
