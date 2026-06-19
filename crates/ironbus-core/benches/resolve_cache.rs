// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmarks for the per-connection resolve cache (#569).
//!
//! These back the "beats the NATS results-cache" claim with numbers on the two operations
//! that matter on the publish hot path:
//!
//! * a steady-state HIT — a hash lookup + a single generation-compare, NO trie walk —
//!   measured against a direct `SublistSnapshot::match_into` (a wait-free load + arena walk)
//!   on the SAME subject, across routing tables of growing size. The HIT cost is flat in the
//!   table size; the direct walk grows with overlap/depth. That gap is the steady-state win.
//! * the bind-change cost — what a connection's cache pays when the routing table is
//!   rebound. On the hot path this is a single `O(1)` generation-compare; the actual
//!   invalidation is one wholesale `HashMap::clear` of the entries that connection happened
//!   to hold (freeing `cached` allocations is inherently `O(cached)` — no cache can free N
//!   entries in `O(1)`), paid LAZILY on the next resolve, OFF any lock, on a PER-CONNECTION
//!   structure. NATS instead, on every subscription change, flushes a SHARED results cache
//!   and on a wildcard unsub linear-scans it (`O(slCacheMax = 1024)`) under a GLOBAL write
//!   lock that contends with every concurrent publisher. The IronBus cost is borne once, by
//!   the one connection, with no lock and no publisher contention. We bench the IronBus side
//!   (resolve right after a bind with N entries already cached) to show the SHAPE of that
//!   cost and that the hot-path guard is the flat generation-compare, not a per-subject scan.
//!
//! Run on demand (`cargo bench -p ironbus-core --bench resolve_cache`); not wired into
//! per-PR CI. Inputs are fixed so a run is deterministic, and `black_box` hides them.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use ironbus_core::resolve_cache::ResolveCache;
use ironbus_core::subject::Subject;
use ironbus_core::sublist::{Sublist, SublistBuilder, SublistSnapshot};

/// The routing-table sizes the curves sweep.
const SIZES: &[usize] = &[16, 256, 4096];

/// A routing table of `n` patterns with genuine literal/`*`/`>` overlap, plus a global
/// catch-all so the benched subject always matches at least one wildcard target (a realistic
/// non-trivial match the walk has to assemble).
fn table(n: usize) -> Sublist<u32> {
    let mut b = SublistBuilder::new();
    for i in 0..n {
        let target = u32::try_from(i).expect("bench table size within u32");
        match i % 4 {
            0 => b.insert(&format!("t{i}.svc.req.metric"), target),
            1 => b.insert(&format!("t{i}.svc.*.metric"), target),
            2 => b.insert(&format!("t{i}.svc.>"), target),
            _ => b.insert(&format!("t{i}.evt.click"), target),
        }
        .expect("valid bench pattern");
    }
    // A catch-all so the hot subject matches a wildcard target regardless of `n`.
    b.insert(">", u32::MAX).expect("valid catch-all");
    b.build(0).expect("bench table within fork bound")
}

/// The hot subject the publisher hammers — present in the table for `i % 4 == 0`.
const HOT_SUBJECT: &str = "t0.svc.req.metric";

/// Steady-state publish: a cache HIT (hash lookup + generation-compare, NO walk) vs a direct
/// trie walk on the same subject. The HIT is flat in table size; the direct walk is not.
fn bench_hit_vs_direct_walk(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve_cache/steady_state");
    group.throughput(Throughput::Elements(1));
    let subject = Subject::parse_literal(HOT_SUBJECT).expect("valid");

    for &n in SIZES {
        let snap = SublistSnapshot::new(table(n));

        // Direct walk: the publish path WITHOUT the cache.
        let mut out = Vec::new();
        group.bench_with_input(BenchmarkId::new("direct_walk", n), &n, |bch, _| {
            bch.iter(|| {
                let gen = snap.match_into(black_box(&subject), &mut out);
                black_box((gen, out.len()));
            });
        });

        // Cache HIT: the publish path WITH the cache, warmed so every iter is a hit.
        let mut cache = ResolveCache::<u32>::new();
        cache.resolve(&snap, &subject); // warm
        group.bench_with_input(BenchmarkId::new("cache_hit", n), &n, |bch, _| {
            bch.iter(|| {
                let targets = cache.resolve_with(&snap, black_box(&subject), <[u32]>::len);
                black_box(targets);
            });
        });
    }
    group.finish();
}

/// The number of stale entries a connection's cache holds when a bind invalidates it. This
/// is the axis NATS's results-cache flush scales on (`O(slCacheMax)`); IronBus must NOT.
const CACHED_COUNTS: &[usize] = &[16, 256, 1024];

/// The bind-change cost ON THE CACHE, isolated from both the trie rebuild AND the cache
/// fill: with `cached` stale entries resident, a bind bumps the generation and the next
/// resolve invalidates the whole cache.
///
/// `iter_batched_ref` builds a fresh cache pre-filled with `cached` distinct entries OUTSIDE
/// the timed region AND drops it outside the timed region (it hands the routine a `&mut`), so
/// neither the fill nor the cache's Drop is counted. The timed routine is ONLY `store(a tiny
/// pre-built table) + one resolve`. The `store` is a wait-free swap of an already-built `Arc`
/// (no per-iter trie rebuild), so the measured cost is exactly the post-bind invalidation:
/// one generation-compare, one wholesale `HashMap::clear` of the `cached` stale entries, and
/// one re-walk of a single subject.
///
/// The number grows roughly linearly with `cached` — but that growth is the `HashMap::clear`
/// FREEING the `cached` entries the connection legitimately held, which no cache can do in
/// `O(1)`. The point the sweep makes is not that the number is constant; it is that the
/// hot-path GUARD is the flat `O(1)` generation-compare (see the steady-state bench), and the
/// clear is a single wholesale free OFF ANY LOCK on a per-connection structure — never NATS's
/// `O(slCacheMax)` scan of a SHARED cache under a GLOBAL write lock that every concurrent
/// publisher contends on.
fn bench_bind_invalidation_cost(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve_cache/bind_invalidation");
    group.throughput(Throughput::Elements(1));
    let subject = Subject::parse_literal(HOT_SUBJECT).expect("valid");
    // A tiny, PRE-BUILT table; a `store` of it is a constant-cost wait-free swap that just
    // bumps the generation — never a large trie rebuild inside the timed routine.
    let snap = SublistSnapshot::new(table(4));
    let swap_in = || table(4);

    for &cached in CACHED_COUNTS {
        group.bench_with_input(
            BenchmarkId::from_parameter(cached),
            &cached,
            |bch, &cached| {
                bch.iter_batched_ref(
                    || {
                        // SETUP (untimed, and dropped untimed): a cache pre-filled with `cached`
                        // distinct stale entries against the current generation.
                        let mut cache = ResolveCache::<u32>::with_capacity(cached + 16);
                        for i in 0..cached {
                            let subj = format!("warm.{i}");
                            let s = Subject::parse_literal(&subj).expect("valid");
                            cache.resolve(&snap, &s);
                        }
                        cache
                    },
                    |cache| {
                        // TIMED: a wait-free swap (bumps the generation) + one resolve. The resolve
                        // does ONE generation-compare, drops ALL `cached` stale entries in a single
                        // clear, and re-walks one subject. This op must not scale with `cached`.
                        snap.store(swap_in());
                        let targets = cache.resolve_with(&snap, black_box(&subject), <[u32]>::len);
                        black_box(targets);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_hit_vs_direct_walk,
    bench_bind_invalidation_cost
);
criterion_main!(benches);
