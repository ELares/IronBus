// SPDX-License-Identifier: MIT OR Apache-2.0
//! Informational micro-benchmarks for the subject-routing trie ("Sublist", #568).
//!
//! These back the "beats the NATS `Sublist`" claim with numbers on the two operations
//! that matter:
//!
//! * `match()` throughput on the publish hot path — a wait-free `Arc` load + arena walk —
//!   measured against routing tables of growing size (the scaling-with-pattern-count
//!   curve), for a literal hit, a `*` hit, and a `>` catch-all;
//! * the bind-change cost — the `O(patterns)` rebuild + the wait-free atomic swap — which
//!   IronBus pays on a subscription change INSTEAD of NATS's global results-cache flush
//!   and its `O(slCacheMax = 1024)` wildcard-unsub linear scan under the write lock.
//!
//! Run on demand (`cargo bench -p ironbus-core --bench sublist`); not wired into per-PR
//! CI. Inputs are fixed so a run is deterministic, and `black_box` hides them from the
//! optimizer.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ironbus_core::subject::Subject;
use ironbus_core::sublist::{Sublist, SublistBuilder, SublistSnapshot};

/// The routing-table sizes the scaling curves sweep.
const SIZES: &[usize] = &[16, 256, 4096];

/// Builds a routing table of `n` patterns with a realistic shape: a literal-prefixed,
/// moderately-deep namespace with a `*` fork and a `>` tail, plus one global catch-all.
/// `t<i>.svc.<j>.metric` style so the literal fan-out is wide (many distinct first tokens)
/// and there is genuine wildcard overlap.
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
    // One global catch-all so every subject has at least one match.
    b.insert(">", u32::MAX).expect("valid catch-all");
    b.build(0)
}

/// `match()` throughput as the routing table grows: a literal hit, a `*` hit, and a `>`
/// catch-all subject, each matched into a reused buffer (the publish hot path).
fn bench_match_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("sublist/match");
    group.throughput(Throughput::Elements(1));

    for &n in SIZES {
        let trie = table(n);
        // A subject that hits the literal pattern for t0 (`t0.svc.req.metric`).
        let literal = Subject::parse_literal("t0.svc.req.metric").expect("valid");
        // A subject that hits a `*` fork (`t1.svc.*.metric`).
        let star = Subject::parse_literal("t1.svc.anything.metric").expect("valid");
        // A subject that only the global `>` catch-all matches.
        let catchall = Subject::parse_literal("zzz.unmatched.deep.subject").expect("valid");

        let mut out = Vec::new();
        group.bench_with_input(BenchmarkId::new("literal_hit", n), &n, |bch, _| {
            bch.iter(|| {
                trie.match_into(black_box(&literal), &mut out);
                black_box(out.len());
            });
        });
        group.bench_with_input(BenchmarkId::new("star_hit", n), &n, |bch, _| {
            bch.iter(|| {
                trie.match_into(black_box(&star), &mut out);
                black_box(out.len());
            });
        });
        group.bench_with_input(BenchmarkId::new("catchall_only", n), &n, |bch, _| {
            bch.iter(|| {
                trie.match_into(black_box(&catchall), &mut out);
                black_box(out.len());
            });
        });
    }
    group.finish();
}

/// The wait-free read through the `ArcSwap` snapshot: load + walk, the exact publish-time
/// path (a `match()` on a `SublistSnapshot`), to show the snapshot indirection is cheap.
fn bench_snapshot_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("sublist/snapshot_match");
    group.throughput(Throughput::Elements(1));
    for &n in SIZES {
        let snap = SublistSnapshot::new(table(n));
        let subject = Subject::parse_literal("t0.svc.req.metric").expect("valid");
        let mut out = Vec::new();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |bch, _| {
            bch.iter(|| {
                let gen = snap.match_into(black_box(&subject), &mut out);
                black_box((gen, out.len()));
            });
        });
    }
    group.finish();
}

/// The bind-change cost: rebuild a fresh trie of `n` patterns and atomically swap it in.
/// This is the work IronBus does on a subscription change — and it is the whole story:
/// there is NO global results-cache flush and NO `O(slCacheMax)` wildcard-unsub scan, both
/// of which NATS pays under its write lock on top of its own rebuild.
fn bench_bind_change_rebuild(c: &mut Criterion) {
    let mut group = c.benchmark_group("sublist/bind_change");
    for &n in SIZES {
        group.throughput(Throughput::Elements(n as u64));
        let snap = SublistSnapshot::new(table(n));
        group.bench_with_input(BenchmarkId::new("rebuild_and_swap", n), &n, |bch, _| {
            bch.iter(|| {
                // The amortized, rare cost: build a new table, then a wait-free swap.
                let next = table(black_box(n));
                let gen = snap.store(next);
                black_box(gen);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_match_scaling,
    bench_snapshot_match,
    bench_bind_change_rebuild
);
criterion_main!(benches);
