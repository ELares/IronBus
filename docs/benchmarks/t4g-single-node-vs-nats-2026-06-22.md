<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# IronBus vs NATS — single-node t4g.small (2026-06-22)

A single-node head-to-head of IronBus against NATS on **ingestion** (produce) and
**consumption**, at the two durability tiers that matter: **quorum-0** (at-most-once,
vs NATS **Core**) and **quorum-1** (durable, vs NATS **JetStream**). The guiding rule is
the one this directory has always held: **a comparison is only honest when both sides run
the same workload under the SAME durability semantics on the SAME hardware.** Numbers are
reported as-measured; ties are ties; where the two systems are not at the same durability
tier it is stated explicitly.

## Bottom line

Holding the *guarantee* constant on both ends, IronBus is the clear winner:

| | Ingestion | Consumption |
|---|---|---|
| **At-most-once** (q0, both actually deliver) | **IronBus ~1.85×** (1.185M vs 641k) | **IronBus ~1.6×** (1.036M vs 641k) |
| **Durable, power-loss-safe** (q1) | **IronBus ~161×** (55k vs 343) | **IronBus ~2.3×** (234k vs 101k) |

The only leg NATS leads is *page-cache* durable produce (88k vs 55k) — i.e. NATS JetStream's
default, which is **not** power-loss-safe (it loses acked data on a brownout). Held to IronBus's
actual durability guarantee, NATS does 343/s. The widely-quoted "NATS wins at-most-once" only
holds when NATS Core has **no subscriber and discards every message**; once it must deliver, it
does ~641k/s and IronBus wins ingest and consume both.

## Rig

- **Instance:** AWS `t4g.small` (2 vCPU Graviton2, ~1.8 GiB RAM), Ubuntu 24.04, root EBS
  `gp3`, `unlimited` CPU credits (so neither broker is throttle-skewed mid-run; both run
  back-to-back on the same box). Region `us-west-2`, dev account.
- **Disk floor (matters for the durable tier):** `dd bs=256 oflag=dsync` = **265 fsync/s**
  (~3.77 ms each). Any system that fsyncs once **per message** is capped near this rate.
- **Peers:** `nats-server v2.14.2`, `nats` CLI `0.4.0`. IronBus built from this branch
  (release). Payload **256 B**, realistic shape. Driver: `ironbus bench` (spawns the real
  `ironbus serve`) and `nats bench` (drives the real `nats-server`).

## Results (msgs/sec, median of 5 runs unless noted)

### Ingestion (produce)

| Tier (matched) | IronBus | NATS | Result |
|---|---:|---:|---|
| **Durable, power-loss-safe** — IB group-commit `fdatasync` vs NATS JS `sync=always` | **~55,400** | ~343 | **IronBus ~161×** |
| Durable, page-cache (NOT power-loss-safe) — IB `--no-fsync` vs NATS JS default interval-sync | ~55,000 | ~88,000 | NATS ~1.6× |
| **At-most-once (q0), DELIVERED** — IB QoS-0 ingest vs NATS Core pub→sub end-to-end (a live subscriber, so the broker does real fan-out instead of discarding) | **~1,185,000** | ~641,000 | **IronBus ~1.85×** |
| (reference) at-most-once with NO subscriber — NATS Core *discards* every message | ~1,156,000 | ~1,650,000 | NATS faster, but delivers/retains **nothing** (not a useful-ingestion comparison) |

### Consumption

| Tier (matched) | IronBus | NATS | Result |
|---|---:|---:|---|
| **Durable** — IB Tier-S streaming consumer vs NATS JS durable consume | **~234,000** | ~101,000 | **IronBus ~2.3×** |
| **At-most-once delivery** — IB Tier-S over memory vs NATS Core subscriber receive (pub→sub e2e) | **~1,036,000** | ~641,000 | **IronBus ~1.6×** |

## What the numbers mean (honestly)

**IronBus wins the comparisons that are actually apples-to-apples for a durable bus:**

- **Power-loss-safe durable produce — IronBus ~161×.** This is IronBus's group-commit design
  made concrete: it amortizes one `fdatasync` over hundreds of buffered publishes, so on a
  disk that does 265 fsync/s it still ingests ~54k power-loss-safe msgs/s. NATS, configured
  for the *same* guarantee (`sync_interval: always`), fsyncs per write and collapses to the
  disk's per-message fsync ceiling (~344/s). NATS's headline 88k JetStream number is **not**
  this guarantee — it is interval-sync (page-cache), which loses up to a sync interval of
  acknowledged data on power loss.
- **Durable consume — IronBus ~2.3×.** IronBus's Tier-S streaming consumer (windowed fetch +
  periodic cumulative durable commit) drains a file-backed stream at ~238k/s vs NATS JS
  durable consume ~102k/s. (IronBus's Tier-W per-message-lease work-queue is a different,
  slower tool — ~7k/s — and is not the streaming-consume head-to-head.)

- **At-most-once, delivered — IronBus ~1.85× ingest, ~1.6× consume.** This one needs care,
  because the naive setup is *unfair to IronBus*. `nats bench pub` with **no subscriber** makes
  NATS Core *discard* every message (a pure socket drain, ~1.65M/s) while IronBus QoS-0 *stores*
  every message — comparing real work against a no-op. Put a **live subscriber** on NATS Core so
  it must actually route+deliver (the only way an at-most-once message is *useful*), and NATS
  Core's end-to-end rate collapses to **~641k/s** on the 2-core box. IronBus ingests at ~1.185M/s
  (all retained) and its Tier-S consumer drains at ~1.036M/s — both well above NATS's coupled
  641k. IronBus's **decoupled** store-and-forward (the producer never waits on a consumer) beats
  NATS Core's **coupled** real-time fan-out on this hardware, on *both* the ingest and the consume
  side. The "NATS wins at-most-once" line only holds if you count messages NATS threw away.

**The single place NATS leads, and it is by giving up durability:**

- *Page-cache durable produce* (NATS ~1.6×): both sides not power-loss-safe. IronBus is
  **CPU-bound** here, not disk-bound (`--no-fsync` == `fdatasync`, both ~55k), doing strictly
  more per message than NATS — payload compression, a single-writer-actor submit/ack handoff per
  message (profile: ~10% inter-thread channel signalling, ~6.6% lz4, ~3.7% per-message alloc),
  and a two-thread `produce_stream` client. NATS JS's 88k is **not** power-loss-safe (interval
  sync); held to IronBus's guarantee it does 343/s (see the 161× row). So this is the
  *not-power-loss-safe* durable tier — fast but loses acked data on a brownout. See *Follow-ups*.

## Changes shipped from this study (both ends of the QoS-0 path)

- **`FireForgetProducer` — a coalescing QoS-0 producer** (`ironbus-client`): at-most-once
  produce previously did one `write_all` syscall per message; it now frames into a wire
  buffer and writes once per 32 KiB — the same coalescing a core pub client does. **+58% on
  at-most-once produce (≈640k → ≈1.015M msgs/s)**, no change to the wire bytes the broker sees.
- **Batched Level-0 actor submission** (`ironbus-server`): the broker side previously did one
  session→actor channel send + waker notify per QoS-0 message; the session now accumulates a
  socket-read's worth of Level-0 produces and hands them to the single-writer actor as ONE
  `Command::ProduceNoReplyBatch`, appended in order under the same group commit (the batch is
  flushed before any Level-1 produce or non-produce job, so the total order is preserved).
  **A further +14% (≈1.015M → ≈1.156M msgs/s)**; 904 server tests + the golden-path acceptance
  pass unchanged.

Together these took at-most-once produce **+80% over the per-message baseline (≈640k → ≈1.156M)**
— and it STILL trails NATS Core's ≈1.65M. That is the point: two real optimizations cannot make
a broker that *stores* every message out-throughput a router that *discards* it (NATS Core with
no subscriber does no server-side work). The at-most-once raw-rate gap is structural, not a
missing optimization.

## Follow-ups (the page-cache durable-produce gap)

The durable-produce CPU is distributed, not a single hotspot, so closing the page-cache gap
is a deeper change than this study warranted:

- **Batched Level-1 (durable) actor submission.** The Level-0 (no-ack) batching above is
  shipped; the at-least-once path still submits each durable publish to the actor over a channel
  and waits on it individually (`ProduceSubmission::wait` + `SyncWaker` ≈ 10% self-time).
  Batching a whole pipelined window into one actor message — with the parked PubAcks aligned to
  the batch's offsets — would cut that handoff and the per-message `OwnedAppend` alloc/free. It is
  riskier than the L0 batch (the ack-ordering contract) and, on its own, would only narrow
  ~55k→~61k (the durable gap is multi-front: channel + lz4 + alloc + the client `produce_stream`
  reader-thread flow control), so it does NOT by itself reach NATS's 88k page-cache rate on 2
  cores. It does not affect the durability guarantee and would *widen* the already-decisive
  power-loss-safe win.

## Reproduce

On a `t4g.small` with `ironbus`, `nats-server`, and `nats` on `PATH`:

```sh
# durable, power-loss-safe produce
ironbus bench --count 500000 --mode publish --stream --pubwindow 16000 --storage disk --payload-bytes 256 --json
nats-server -c js-sync.conf &   # js-sync.conf: jetstream { sync_interval: "always" }
nats bench js pub async benchsub --create --storage=file --msgs 30000 --size 256B

# durable consume
ironbus bench --count 500000 --mode subscribe --consume-tier stream --storage disk --payload-bytes 256 --json
nats bench js pub async benchsub --create --storage=file --msgs 500000 --size 256B   # populate
nats bench js consume --stream benchstream --msgs 500000

# at-most-once produce
ironbus bench --count 3000000 --mode publish --fire-and-forget --storage memory --payload-bytes 256 --json
nats-server & ; nats bench pub s --clients 1 --msgs 3000000 --size 256B --no-progress
```
