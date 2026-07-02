# Cross-broker benchmark study, July 2026: IronBus vs Kafka vs Redpanda vs NATS on one Apple M4 Pro

> The measured, matched-durability, single-node head-to-head behind the README's
> [Benchmarks](../../README.md#benchmarks) section. Study issue:
> [#1023](https://github.com/ELares/IronBus/issues/1023); it extends the in-repo rig discipline
> (durability labels on every number, warmup/steady-state protocol, honest attribution) to four
> brokers on one machine. Every number below is the **median of 3 timed runs**; the harness that
> produced them is committed at [cross-broker-harness/](cross-broker-harness/).

## 1. Environment

| Component | Version / spec |
| --- | --- |
| Machine | Apple M4 Pro, 14 cores, 48 GB RAM, macOS 26.5, internal NVMe |
| IronBus | current `main` (release build; includes the #1024–#1032 fixes below) |
| Kafka | 4.3.1 (Scala 2.13 build), KRaft single node, Temurin JDK 21 |
| Redpanda | v26.1.12 — Linux-only, so it runs in a **lima vz VM** (Ubuntu, 8 vCPU / 8 GB; broker pinned `--smp=6 --memory=6G`), Kafka API port-forwarded to the host |
| NATS | nats-server 2.14.3 (JetStream file + memory tiers, plus one NATS Core datapoint), `nats` CLI bench |
| Load drivers | `ironbus bench` (spawns its own isolated broker), `nats bench js`, `kafka-producer-perf-test.sh` / `kafka-consumer-perf-test.sh` (also used against Redpanda's Kafka API) |
| Network | loopback TCP only |

Two environment facts shape how the durable rows must be read:

- **The macOS durability wall.** On macOS, `fsync(2)` does **not** flush the drive's volatile
  cache; the power-loss barrier is the separate `F_FULLFSYNC` fcntl, which costs ~4 ms per call
  on this NVMe. IronBus and NATS (`sync_interval: always`) pay that barrier before acking.
  Kafka's `log.flush.interval.messages` path calls `fsync(2)` — so its "fsync" rows are **not
  power-loss-comparable** on this host (marked † throughout).
- **The VM wall.** Redpanda's guest-side fsync goes through a virtual disk; a guest flush does
  not guarantee a host-media flush, and lima adds a user-space port-forward hop. Redpanda's
  numbers are therefore an *appendix datapoint* (marked \*, parenthesized), excluded from the
  native rankings **in both directions** — they prove nothing about bare-metal Redpanda, for it
  or against it.

## 2. The matrix

Seven rows × two payload sizes (128 B and 1 KiB), each row a pinned, labeled durability tier:

| Row | What it measures | Durability label | Entrants |
| --- | --- | --- | --- |
| P1 | sync-per-message produce (one awaited ack per publish, flush before every ack) | fsync-before-every-ack | ironbus, nats, kafka †, redpanda \* |
| P2 | group-commit produce (pipelined window, coalesced flush before ack) | group-commit-fsync | ironbus, kafka †, redpanda \* — NATS: no such mode ‡ |
| P3 | relaxed produce (ack from page cache; **not** power-loss-safe, and labeled so) | page-cache-async | ironbus, nats, kafka, redpanda \* |
| P4 | in-memory produce (ephemeral broker, no files at all) | memory | ironbus, nats — kafka/redpanda have no in-RAM mode |
| C1 | single-consumer drain of a pre-filled durable log (consume/replay) | durable-consume | ironbus, nats, kafka, redpanda \* |
| L1 | durable produce→ack RTT percentiles, single in-flight | fsync-before-ack | ironbus, nats, kafka †, redpanda \* |
| L2 | in-memory produce→ack RTT percentiles, single in-flight | memory | ironbus, nats (+ NATS Core request-reply, an extra non-comparable datapoint) |

‡ NATS JetStream has no ack-after-coalesced-fsync mode: `sync_interval: always` fsyncs per
message (that is the P1 row) and the default `sync_interval` (~2 min) acks from page cache
(that is the P3 row). The P2 cell is marked structurally absent rather than faked with a
mislabeled number.

## 3. Pinned per-broker configuration, per tier

Exactly what the harness sets and **validates** before each cell (see `lib.sh` / `run_cell.sh`):

### IronBus (driver-spawned isolated broker, fresh temp data dir per run)

| Row | Driver invocation (via `ironbus bench --json --payload-shape realistic`) |
| --- | --- |
| P1 / L1 | `--mode publish --pubwindow 1 --storage disk` — sync durability (default): one awaited, `F_FULLFSYNC`'d ack per publish; L1 reads the #1024 `ack_p50/p99` fields |
| P2 | `--mode publish --stream --pubwindow 1024 --storage disk` — sync durability, group-commit `fdatasync` over the sliding window |
| P3 | `--mode publish --stream --pubwindow 1024 --no-fsync --storage disk` — the spawned broker runs **interval** durability (bounded-loss page-cache acks, #1027) |
| P4 | `--mode publish --stream --pubwindow 1024 --storage memory` |
| C1 | `--mode subscribe --consume-tier streaming --storage disk` — Tier-S drain at the shipped default fetch batch (2048, #1027); bench pre-fills the log itself |
| L2 | `--mode publish --pubwindow 1 --storage memory` — closed-loop ack RTT percentiles |

IronBus ran its shipped defaults throughout, **including `--compression lz4` (the default codec)**
with realistic (compressible) payloads — disclosed, not disabled.

### NATS

| Tier | Server | Driver |
| --- | --- | --- |
| sync (P1, L1) | `nats-server` with a config pinning `sync_interval: always` (validated by grep before each run), JetStream file store R1 | `nats bench js pub sync` (single in-flight publish awaiting PubAck; P50/P99 are per-publish ack RTT) |
| default (P3) | `-js` CLI defaults (`sync_interval` ~2 min — page cache, labeled not power-loss-safe) | `nats bench js pub async --batch 100` |
| memory (P4, L2) | JetStream **memory** storage stream | P4: `js pub async --batch 100`; L2: `js pub sync` (ack RTT) |
| consume (C1) | file stream pre-filled with the frozen count, then drained | explicit durable **pull** consumer, `nats bench js fetch --batch 256` |
| L2 extra | NATS **Core** request-reply (`nats bench service serve/request`, 1 client, single in-flight) | at-most-once, no persistence, includes a responder hop (2 network RTTs) — NATS's home-turf latency number, shown as an extra datapoint, **not label-comparable** with the ack-RTT cells |

### Kafka (KRaft single node, RF1, one partition)

| Tier | Broker + topic | Producer props |
| --- | --- | --- |
| fsync (P1, L1) † | `log.flush.interval.messages=1` + topic `flush.messages=1` | `acks=all batch.size=1 linger.ms=0 max.in.flight.requests.per.connection=1 compression.type=none`; L1 throttled to 100 msg/s (below saturation, so latency = ack RTT, not queue wait; tool reports whole-ms resolution) |
| group (P2) † | `log.flush.interval.messages=1000` + topic `flush.messages=1000` | `acks=all batch.size=65536 linger.ms=5 compression.type=none` |
| default (P3) | flush interval unset (OS page cache) | same as P2 |
| consume (C1) | topic pre-filled (`acks=1`, batched), drained by `kafka-consumer-perf-test` with a fresh group | msgs/s = the tool's `fetch.nMsg.sec` (fetch phase, excludes rebalance); the tool reports no latency |

Fresh KRaft storage format per cell; one **unrecorded JVM warm-up run** per cell before the
timed runs.

### Redpanda (lima VM — appendix datapoint \*)

| Tier | Cluster config (validated after every wipe/boot) |
| --- | --- |
| durable (P1, P2, C1, L1) | `developer_mode: false` (no `--unsafe-bypass-fsync`), `write_caching_default: false` + topic `write.caching=false` — fsync before ack *inside the VM* |
| relaxed (P3) | `developer_mode: false`, `write_caching_default: true` + topic `write.caching=true` |

Driven by the same Kafka perf tools over the forwarded port. The harness re-asserts all three
knobs (developer_mode, write_caching, no fsync-bypass flag on the live process) after every
data wipe, because a wipe re-bootstraps cluster config.

## 4. Run protocol

Per (row × size × broker) cell, strictly serial (never two brokers at once — a port scan
asserts it):

1. **Fresh state**: wipe + recreate the broker's data dir (Kafka: re-format KRaft storage;
   Redpanda: wipe inside the VM and re-validate config; IronBus: the bench driver's own fresh
   temp dir per run).
2. **Start** the broker with the row's pinned tier config; block until it answers clients.
3. **Pilot run** (small count) to observe the cell's rate.
4. **Freeze the count** at pilot-rate × 20 s, clamped to 50 k–5 M (2 k–200 k on the
   fsync-wall rows P1/L1/L2, which run at ~100–500 ops/s), byte-capped under the JetStream
   stream limits.
5. Kafka only: one extra **unrecorded JVM warm-up run** at the frozen count.
6. **3 timed runs** at the frozen count, 20 s cooldown between runs.
7. **Teardown** (verify the port is free), 20 s cooldown, next cell.

Every raw tool output is kept under `logs/`; each run appends one normalized JSON line
(row, size, broker, tier label, config summary, msgs/s, p50/p99/p999 µs, raw-log path) to
`results/results.jsonl`; the per-cell **median of the 3 timed runs** produces
`results/final-medians.json`, which is the single source for every table here and in the README.

### Fairness rules

- **Matched durability per row, labeled per cell** — never a page-cache number against an fsync
  number without the label saying so.
- **msgs/s recomputed uniformly** as `MB/s = msgs/s × size / 1e6` — no broker benefits from its
  tool's MiB-vs-MB labeling.
- **Latency rows are ack-RTT symmetric**: `ironbus bench` publish `--pubwindow 1` reports
  produce→ack RTT percentiles (#1024) exactly like `nats js pub sync`; both are closed-loop.
  Kafka/Redpanda L1 run throttled to 100 msg/s so their latency is ack RTT, not queue wait
  (their tool cannot run closed-loop single-in-flight unthrottled).
- **Structural gaps are marked, not faked** (NATS P2, Kafka/Redpanda P4/L2).
- **Peers ran their own official load tools** at their own defaults for anything unpinned.
- **Coordinated-omission awareness**: throughput rows are fixed-work (count, not duration);
  latency rows are single-in-flight closed-loop, where CO does not apply.

## 5. Results — every cell (medians of 3)

msgs/s as measured; latencies in µs. "—" = not measured / not applicable (see notes).
\* Redpanda-in-VM appendix datapoint. † Kafka flush = `fsync(2)`, not `F_FULLFSYNC`.

### P1 — sync-per-message durable produce (fsync-before-every-ack)

| Broker | 128 B msg/s | 128 B p50 / p99 | 1 KiB msg/s | 1 KiB p50 / p99 |
| --- | ---: | --- | ---: | --- |
| ironbus | 249.7 | 3,999 / 4,202 | 249.6 | 3,999 / 4,168 |
| nats | 253.0 | 3,995 / 4,852 | 250.0 | 3,999 / 4,810 |
| kafka † | 241.6 | 9,538,000 / 18,891,000 | 220.6 | 10,459,000 / 20,431,000 |
| redpanda \* | *(2,547.2)* | *(7,241,000 / 14,085,000)* | *(2,322.4)* | *(7,361,000 / 12,881,000)* |

IronBus and NATS-sync sit at the ~4 ms `F_FULLFSYNC` wall (~250 msg/s) — the only two entrants
whose ack means the bytes survived power loss on this host. Kafka's per-message-flush pipeline
saturates: its unthrottled P1 latencies are queueing (seconds), not ack RTT (see L1 for its
throttled RTT). Redpanda's 2.5 k is a VM-virtualized fsync.

### P2 — group-commit durable produce (coalesced fsync-before-ack)

| Broker | 128 B msg/s | 1 KiB msg/s |
| --- | ---: | ---: |
| ironbus | 88,348.4 | 15,261.9 |
| nats | — ‡ (no such mode) | — ‡ |
| kafka † | 352,089.3 | 193,669.2 |
| redpanda \* | *(1,085,633.7)* | *(196,834.4)* |

IronBus latencies are not attributed on windowed produce (amortized per-op attribution would be
dishonest — the #1024/#1025 gating); Kafka/Redpanda tool percentiles for this row (kafka 128 B
72,000 / 198,000; 1 KiB 4,000 / 155,000; redpanda 128 B *2,000 / 11,000*; 1 KiB
*156,000 / 178,000*) are producer-tool batch latencies, not single-record ack RTTs.
**Read this row as a durability-label mismatch**: on macOS only the IronBus cell pays the
drive-cache barrier before ack. On Linux, where `fdatasync` is the real barrier, this
comparison must be re-run before quoting a ranking (see the follow-ups in §7).

### P3 — relaxed produce (page-cache ack; NOT power-loss-safe)

| Broker | 128 B msg/s | 1 KiB msg/s |
| --- | ---: | ---: |
| ironbus | 1,600,097.9 | 1,044,512.7 |
| nats | 284,906.0 | 228,683.0 |
| kafka | 2,339,663.0 | 582,336.9 |
| redpanda \* | *(1,733,198.6)* | *(295,551.7)* |

IronBus beats NATS 5.6x / 4.6x and beats Kafka at 1 KiB (1.79x). The 128 B Kafka lead is its
client's five-in-flight 128 KiB-batch request pipeline (per-request framing amortization) —
the acknowledged gap filed as [#1035](https://github.com/ELares/IronBus/issues/1035).
(Peer tool percentiles at this row are batch-amortized and sub-ms-quantized: kafka p50 0–1 ms;
nats 128 B 335 / 594 µs, 1 KiB 418 / 756 µs; redpanda *1,000–14,000 µs*.)

### P4 — in-memory produce (ephemeral)

| Broker | 128 B msg/s | 1 KiB msg/s |
| --- | ---: | ---: |
| ironbus | 1,888,985.0 | 1,197,558.6 |
| nats | 408,727.0 (227.66 / 502.5) | 371,522.0 (250.29 / 558.37) |
| kafka / redpanda | n/a — no true in-RAM broker mode | n/a |

IronBus 4.6x / 3.2x. (NATS percentiles shown parenthesized are its tool's batch-amortized
publish latencies.)

### C1 — durable consume / replay (single-consumer drain)

| Broker | 128 B msg/s | 1 KiB msg/s |
| --- | ---: | ---: |
| ironbus | 1,649,669.9 | 1,165,954.5 |
| nats | 393,704.0 | 370,566.0 |
| kafka | 6,242,197.3 | 2,016,492.3 |
| redpanda \* | *(2,745,744.1)* | *(428,048.4)* |

IronBus (Tier-S streaming, shipped default fetch batch) beats NATS JetStream pull 4.2x / 3.1x.
Kafka's consumer rides `sendfile(2)` zero-copy from page cache to socket — an
architecture-class gap, filed as [#1034](https://github.com/ELares/IronBus/issues/1034).
Latency columns are omitted for this row: the Kafka tool reports none; the NATS numbers are
per-fetch-op; the IronBus bench figures (p50 ≈ 107 s @128 B, ≈ 217 s @1 KiB) are the **record
age at delivery during a replay drain** (prefill time included), not an operation latency —
kept in the raw JSON for completeness, meaningless as a comparison.

### L1 — durable produce→ack RTT (single in-flight)

| Broker | 128 B msg/s | 128 B p50 / p99 (µs) | 1 KiB msg/s | 1 KiB p50 / p99 (µs) |
| --- | ---: | --- | ---: | --- |
| ironbus | 247.8 | 4,002 / 4,994 | 249.4 | 3,998 / 4,185 |
| nats | 252.0 | 3,996 / 5,045 | 248.0 | 4,001 / 4,987 |
| kafka † | 100.0 (throttled) | 5,000 / 13,000 | 99.9 (throttled) | 5,000 / 13,000 |
| redpanda \* | *(100.0, throttled)* | *(3,000 / 9,000)* | *(99.9, throttled)* | *(3,000 / 9,000)* |

A p50 tie with NATS at the `F_FULLFSYNC` wall; IronBus carries the tighter p99 at both sizes.
Kafka/Redpanda ran at a fixed 100 msg/s (their tool's below-saturation latency mode) with
whole-millisecond resolution.

### L2 — in-memory produce→ack RTT (single in-flight)

| Broker | 128 B msg/s | 128 B p50 / p99 (µs) | 1 KiB msg/s | 1 KiB p50 / p99 (µs) |
| --- | ---: | --- | ---: | --- |
| ironbus | 46,000.3 | 20.58 / 28.08 | 41,909.0 | 22.38 / 28.92 |
| nats (JetStream memory) | 28,855.0 | 32.83 / 69.08 | 28,651.0 | 33.29 / 69.83 |
| natscore (Core request-reply, extra datapoint) | 15,624.0 | 61.41 / 105.50 | 15,392.0 | 62.58 / 106.54 |

The row that flipped (see §6): IronBus now leads JetStream-memory 1.6x on p50 and 2.5x on p99 —
and the ack RTT is faster than NATS Core's request-reply round trip (which includes a responder
hop; extra datapoint, not label-comparable).

## 6. What the study fixed: five defects found by measuring

Benchmarking against serious peers is a bug-finder. Every cell where IronBus did not lead was
attributed (CPU sampling, pacing probes, config bisection) before being accepted, and that
attribution produced five merged fixes and two filed design issues:

| Issue | What was found | Before → after |
| --- | --- | --- |
| [#1024](https://github.com/ELares/IronBus/issues/1024) / [#1025](https://github.com/ELares/IronBus/issues/1025) | `ironbus bench` could not report the produce→ack RTT percentiles the peer tools report (only a disk-only p50), making the L rows structurally unfair to fill | bench now emits `ack_p50/p99/p999/max_us`, gated to honestly-attributable awaited-per-produce paths only |
| [#1026](https://github.com/ELares/IronBus/issues/1026) | the append actor's 200 µs commit-gather window (correct for amortizing sync-tier fsyncs) also paced tiers with **no fsync to amortize**, quantizing memory/interval acks to ~200 µs cycles | memory produce @1 KiB 52 k → **687 k** msg/s (13x) in the probe; interval 53 k → 337 k; the gather now engages only when a covering fsync precedes the ack |
| [#1027](https://github.com/ELares/IronBus/issues/1027) | two bench-driver defects: `--no-fsync` did not actually relax the spawned broker (the published "relaxed" row had been measuring the **sync** tier), and the streaming-consume default fetch batch of 256 was RTT-bound | P3 measured honestly relaxed (e.g. 15 k → ~1 M @1 KiB class); consume drain @128 B 180 k → ~1–1.2 M msg/s with the new default fetch batch 2048 |
| [#1028](https://github.com/ELares/IronBus/issues/1028) | zero `TCP_NODELAY` anywhere in the workspace (broker accepted sockets, both client crates) | set on both ends — standard practice; not the dominant loopback term but real-network insurance |
| [#1032](https://github.com/ELares/IronBus/issues/1032) | L2 single-in-flight ack RTT was ~5x NATS (163 vs 33 µs p50): two cross-thread wake-up hops (session → append actor → session) at ~30–60 µs each of macOS scheduler latency, while NATS serves the publish on one connection-owned thread | spin-assisted produce-reply handoff on the no-pre-ack-fsync tiers: 163 / 405 µs → **20.6 / 28.1 µs** p50/p99 — the row flipped from a 5x loss to the win in §5 |

Still open, filed from this study: [#1034](https://github.com/ELares/IronBus/issues/1034)
(zero-copy DeliverBatch fetch — the Kafka C1 gap) and
[#1035](https://github.com/ELares/IronBus/issues/1035) (multi-batch produce pipelining for
small records — the Kafka P3-128 B gap).

## 7. Scope, and what this study is not

- **Single node, one machine, macOS.** The `F_FULLFSYNC` wall makes the durable rows a
  *durability-honesty* comparison more than a throughput race; a Linux bare-metal rerun (where
  `fdatasync` is the barrier and Kafka/Redpanda run native) is the natural follow-up, as is the
  OpenMessaging-driver epic ([#769](https://github.com/ELares/IronBus/issues/769)) for
  third-party-recognizable results.
- **No cluster numbers.** The cluster benchmarks are tracked separately and are not yet
  CI-gated ([#636](https://github.com/ELares/IronBus/issues/636)).
- **Kafka and Redpanda are cluster-class systems** benched here in single-node mode — their
  design center is elsewhere; this study answers "on one edge-class node, matched durability,
  who does what", not "which system should run your 100-node estate".
- The Raspberry Pi 4 60 k msg/s @ p99 < 6 ms figure remains a **target** (an SLO floor), not a
  measurement — see [docs/SLO.md](../SLO.md).

## 8. Artifacts and reproduction

- **Harness**: [cross-broker-harness/](cross-broker-harness/) — the exact `lib.sh` /
  `run_cell.sh` / `run_row.sh` / `run_all.sh` used, with a README covering prerequisites
  (user-local broker installs, the lima VM for Redpanda) and the environment variables to
  point it at your own machine.
- **Raw artifacts** (this study's run): per-run tool outputs (`logs/`), the normalized
  `results/results.jsonl` (one line per run, with each cell's full pinned-config summary
  string), the pacing/attribution probe outputs behind #1026/#1032, and the
  `results/final-medians.json` this document's tables are generated from. They live in the
  study workspace (they are run-machine artifacts, not repo history); `final-medians.json`'s
  values are reproduced **verbatim** in §5, so the tables here are the durable record.
- To reproduce: build IronBus release, install the peer brokers user-locally, then
  `run_all.sh` (or `run_row.sh P1` etc.) — see the harness README.
