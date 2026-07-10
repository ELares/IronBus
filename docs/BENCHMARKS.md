<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# IronBus vs NATS: measured results (AWS t4g.large, 2026-07)

This page is the consolidated record of the 2026-07 single-host head-to-head between IronBus
and NATS (core and JetStream), run for the flat-routing / filtered-consumer study
([#606](https://github.com/ELares/IronBus/issues/606)) and the push-delivery validation
([#1100](https://github.com/ELares/IronBus/issues/1100)). Everything here is **measured, not
asserted** — and it is measured on one loopback host with a burstable instance, so read it as
**p50/p99-grade and directional at the tails**, not as a datacenter certification. Wins and
losses are both reported; the caveats section is part of the result, not a footnote.

Related material: the earlier t4g.small round is
[benchmarks/t4g-single-node-vs-nats-2026-06-22.md](benchmarks/t4g-single-node-vs-nats-2026-06-22.md),
the matched-durability corpus method lives in [benchmarks/README.md](benchmarks/README.md), the
on-device history is [PERF_LEDGER.md](PERF_LEDGER.md), and the Redpanda studies are linked from
the [README benchmarks section](../README.md#benchmarks). The corruption-recovery head-to-head
([#644](https://github.com/ELares/IronBus/issues/644): the same four on-disk corruption classes
injected into both brokers' file stores, behavior measured on both sides) is
[benchmarks/corruption-recovery.md](benchmarks/corruption-recovery.md).

## Headlines

| # | Axis | Result |
| --- | --- | --- |
| 1 | Filtered consumers | IronBus subject-filtered consume costs **~1x** vs unfiltered; NATS JetStream's filtered consumer measured a **~7x re-scan penalty** (13.5–14.8k filtered vs 105k unfiltered msg/s) |
| 2 | Sparse filters (1-in-100) | The IronBus filtered consumer traverses the same 60k-offset window **~21x sooner** (0.36 s vs 7.68 s) |
| 3 | Flat subject routing | 1 → 10,000 subjects costs IronBus **-10.9%** publish throughput vs NATS core's **~35%** degradation |
| 4 | Streaming consume | IronBus **acked** streaming consume **716–735k msg/s** beats NATS core's **unacked** delivery 667–681k msg/s |
| 5 | Durable consume | IronBus disk consume **333k msg/s = 3.4x JetStream** (97–98k; file storage, explicit acks) |
| 6 | Push delivery | `--consume-longpoll-ms` push is **2.1x better at p50** than pull-poll (175–198 µs vs 372–383 µs round-trip at 2,000 msg/s) |
| 7 | **NATS wins: unacked ingest** | NATS core fire-and-forget ingest 1.64–1.75M msg/s vs IronBus acked ingest 251–254k (different guarantee: theirs is a fire-and-forget socket write) |
| 8 | **NATS wins: async durable ingest** | JetStream async ingest 90–91k msg/s vs IronBus 54.6k — but JetStream's publish ack is **not fsynced** (154 µs ack) where IronBus's is fsync-backed (1.03 ms ack): a strictly stronger guarantee |

## Methodology

- **Hardware:** one AWS **t4g.large** (2 vCPU Graviton2, aarch64), Ubuntu 24.04 arm64,
  single-host **loopback**. Both brokers ran on the same box class with the same payloads and
  methodology; a fresh broker per scenario.
- **Versions:** `ironbus` release binary **2607.109.15** (round 1 and the push-delivery
  validation) and **2607.110.11** (round 2 — the first build with the `bench --subjects` /
  `--filter` modes, [#1126](https://github.com/ELares/IronBus/issues/1126)/[#1127](https://github.com/ELares/IronBus/pull/1127))
  vs **nats-server 2.14.3** driven by **natscli 0.4.0**.
- **Payloads:** 256 B throughout.
- **Runs:** two runs per configuration in round 2; round-1 rows as recorded in
  [#606](https://github.com/ELares/IronBus/issues/606).
- **Warmed groups:** each broker reuses one warmed, named consumer group — a fresh random
  group drains prior runs' backlog and poisons the latency distribution (methodology note
  recorded in [#1100](https://github.com/ELares/IronBus/issues/1100)).
- **Multi-subject publish is awaited per-publish RTT:** the `--subjects` publish mode refuses
  the pipelined shapes, so its absolute msg/s is a round-trip-bound number. Compare the
  **degradation ratio** across subject counts, not the absolute throughput.

## 1. Filtered consumers: ~1x vs JetStream's ~7x re-scan penalty

The claim under test: a subject-filtered IronBus consumer pays roughly nothing over an
unfiltered one, because non-matching runs of offsets are skipped via coalesced
`GapMarker(FILTERED)` frames instead of being re-scanned per consumer.

- **The NATS side (round 1):** a JetStream filtered consumer measured **13.5–14.8k msg/s**
  against **105k msg/s** unfiltered — a **~7x re-scan penalty**.
- **The IronBus side (round 2), 1-in-3 interleave** (three subjects round-robin, the
  marker-per-message worst case for the coalescer): filtered/unfiltered throughput ratio
  **~1x** (measured 1.09x; burstable-host spread — the claim is ~1x, not the precise figure).
- **1-in-100 sparse:** the filtered consumer traverses the same 60k-offset window **~21x
  sooner** (0.36 s vs 7.68 s; 166k offsets/s traversal vs 7.8k).
- **Exact gap accounting, every run:** `delivered + gap_offsets_skipped == window` — e.g.
  20,001 coalesced FILTERED markers covering 40,000 skipped offsets at 1-in-3. The filter's
  wire-visible overhead is counted, not estimated.
- **Durable (disk, fsync-backed) filtered:** ratio **~0.77x** (~1.3x per-delivered cost) —
  still nowhere near the 7x class, on the strictly-stronger-guarantee path.

## 2. Flat subject routing: 1 → 10,000 subjects

Awaited per-publish RTT, memory broker (see the methodology note: compare the ratio, not the
absolute msg/s).

| subjects | avg msg/s | ack p50/p99 (µs) | vs 1 subject |
| ---: | ---: | --- | ---: |
| 1 | 11,414 | 84.1 / 121.5 | — |
| 8 | 11,297 | 85.0 / 123.5 | -1.0% |
| 100 | 11,290 | 84.7 / 127.9 | -1.1% |
| 10,000 | 10,166 | 95.6 / 138.8 | **-10.9%** |

**1 → 10k-subject degradation: IronBus -10.9% vs NATS core ~35%** (round 1, same box class) —
the wait-free routing-trie flat-routing claim, validated.

## 3. Streaming consume: acked beats their unacked

IronBus memory-mode streaming consume: **716–735k msg/s, acked, over a replayable log** — vs
NATS core delivery at **667–681k msg/s, unacked** (NATS core has no persistence, so its
non-durable delivery is the matching tier). IronBus wins the delivery race while acking every
message and retaining a log you can replay.

## 4. Durable consume: 3.4x JetStream

IronBus disk consume: **333k msg/s = 3.4x** NATS JetStream's **97–98k** (file storage,
explicit acks on both sides).

## 5. Push delivery: 2.1x better p50 than pull-poll

`serve --consume-longpoll-ms <n>` opts an idle consumer into commit-driven wakeup (push)
instead of empty-poll-and-return. Clean-host validation
([#1100](https://github.com/ELares/IronBus/issues/1100)): rate 2,000 msg/s, fetch-batch 1,
256 B, loopback.

| config | p50 | p99 | p999 |
| --- | --- | --- | --- |
| push ON (`--consume-longpoll-ms 1000`) | **175–198 µs** | **2.2–2.9 ms** | 13–20 ms |
| push OFF (pull-poll) | 372–383 µs | 6.9–8.4 ms | 21–24 ms |

**p50 2.1x better, p99 ~2.7x better.** The p999 rows are not publishable claims: the t4g is a
burstable instance and showed intermittent ~100 ms host-level stalls (0–1% steal, no swap/IO
on clean runs — instance jitter, not mode-related); a dedicated or metal instance is needed
for real p999 numbers.

## 6. Where NATS wins (measured, stated plainly)

- **Unacked ingest:** NATS core fire-and-forget ingest measured **1.64–1.75M msg/s** vs
  IronBus acked ingest **251–254k msg/s** — roughly 6.7x. This is a different guarantee:
  NATS core's number is a fire-and-forget socket write with no ack and no retention; the
  IronBus number acks every message. The gap is real; so is the difference in what you get.
- **Async durable ingest:** JetStream async ingest measured **90–91k msg/s** vs IronBus
  **54.6k** — roughly 1.7x. But JetStream's publish ack is **not fsynced** (a 154 µs ack),
  where IronBus's ack is fsync-backed (1.03 ms): an acked IronBus record has survived a power
  cut, an acked JetStream record has not necessarily — a strictly stronger guarantee, paid
  for on this row.

## Caveats (read before quoting any number)

- **Single host, loopback.** No real network, no cross-AZ, no packet loss.
- **Burstable instance.** t4g.large is p50/p99-grade; intermittent ~100 ms host stalls make
  p999 non-publishable here. Treat every tail number as directional.
- **256 B payloads only.** Per-byte costs (compression, copies) shift the picture at larger
  sizes — see the [corpus findings](benchmarks/README.md) for how.
- **Multi-subject publish is awaited RTT** (the mode refuses pipelining): compare degradation
  ratios across subject counts, not absolute throughput.
- **Two runs per configuration** (round 2), warmed groups, fresh broker per scenario. Raw
  artifacts are retained privately by the maintainer, not committed.

## Reproducing

The IronBus side is driven by the built-in, production-safe load generator (`ironbus bench`
spawns its own isolated broker by default; `--subjects`/`--filter` shipped in
[#1127](https://github.com/ELares/IronBus/pull/1127)):

```sh
# Flat routing: multi-subject publish scaling (awaited per-publish RTT; refuses pipelining).
# Sweep --subjects over 1 / 8 / 100 / 10000.
ironbus bench --mode publish --storage memory --payload-bytes 256 --count 60000 --subjects 10000

# Filtered vs unfiltered consume on the same multi-subject stream (Tier-W work queue).
# 1-in-3: --subjects 3 --filter bench.s0. 1-in-100 sparse: --subjects 100 --filter bench.s0.
ironbus bench --mode subscribe --payload-bytes 256 --count 60000 --subjects 3 --filter bench.s0
ironbus bench --mode subscribe --payload-bytes 256 --count 60000 --subjects 3   # unfiltered baseline

# Streaming / durable consume rates.
ironbus bench --mode subscribe --consume-tier streaming --payload-bytes 256 --count 100000

# Push delivery: serve with commit-driven wakeup, then drive a paced consumer against it
# (rate 2000/s, fetch-batch 1; reuse one warmed named --group per broker — see #1100).
ironbus serve --data-dir /tmp/ib-bench --consume-longpoll-ms 1000
ironbus bench --addr 127.0.0.1:7777 --i-understand-this-is-live \
  --mode round-trip --rate 2000 --fetch-batch 1 --payload-bytes 256 --group push-check
```

The NATS side used `nats bench` (natscli 0.4.0 against nats-server 2.14.3): core pub/sub for
the unacked rows, JetStream with file storage and explicit acks for the durable rows, a
subject-filtered JetStream consumer for the filtered-consumer row, and a multi-subject core
publish sweep for the Sublist-degradation row. Full run notes, per-row provenance, and the
recorded intermediate numbers are in
[#606](https://github.com/ELares/IronBus/issues/606) and
[#1100](https://github.com/ELares/IronBus/issues/1100).
