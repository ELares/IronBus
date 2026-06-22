<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# IronBus vs NATS — single-node t4g.small (2026-06-22)

A single-node head-to-head of IronBus against NATS on **ingestion** (produce) and
**consumption**, at the two durability tiers that matter: **quorum-0** (at-most-once,
vs NATS **Core**) and **quorum-1** (durable, vs NATS **JetStream**). The guiding rule is
the one this directory has always held: **a comparison is only honest when both sides run
the same workload under the SAME durability semantics on the SAME hardware.** Numbers are
reported as-measured; ties are ties; where the two systems are not at the same durability
tier it is stated explicitly.

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
| At-most-once (q0) — IB QoS-0 memory (**retains**) vs NATS Core pub (**drops**, no subscriber) | ~1,011,000 | ~1,650,000 | NATS ~1.6× raw rate |

### Consumption

| Tier (matched) | IronBus | NATS | Result |
|---|---:|---:|---|
| **Durable** — IB Tier-S streaming consumer vs NATS JS durable consume | **~234,000** | ~101,000 | **IronBus ~2.3×** |
| (memory, IB only) IB Tier-S over memory | ~900,000 | — | — |

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

**Where NATS leads, it is by doing less or giving up durability:**

- *Page-cache durable produce* (NATS ~1.6×): both sides not power-loss-safe. IronBus is
  **CPU-bound** here, not disk-bound (`--no-fsync` == `fdatasync`, both ~55k), doing strictly
  more per message than NATS — payload compression, and a single-writer-actor submit/ack
  handoff per message (profile: ~10% inter-thread channel signalling, ~6.6% lz4, ~3.7%
  per-message alloc). See *Follow-ups*.
- *At-most-once* (NATS Core ~1.6×): NATS Core with no subscriber **drops** every message
  (pure socket drain); IronBus QoS-0 **retains** each message in its log for consumers. The
  raw send rate favours the broker that stores nothing; IronBus delivers ingested, readable
  data at ~1.0M/s.

## Change shipped from this study

- **`FireForgetProducer` — a coalescing QoS-0 producer** (`ironbus-client`): at-most-once
  produce previously did one `write_all` syscall per message; it now frames into a wire
  buffer and writes once per 32 KiB — the same coalescing a core pub client does. **+60% on
  at-most-once produce (≈640k → ≈1.015M msgs/s)** with no change to the wire bytes the broker
  sees. (`Client::fire_and_forget_producer`; the bench QoS-0 leg uses it.)

## Follow-ups (the page-cache durable-produce gap)

The durable-produce CPU is distributed, not a single hotspot, so closing the page-cache gap
is a deeper change than this study warranted:

- **Batched actor submission.** Today each durable publish is submitted to the single-writer
  actor over a channel and waited on individually (`ProduceSubmission::wait` + `SyncWaker`
  ≈ 10% self-time). Submitting a whole pipelined window as one actor message (one wake per
  batch) would cut that handoff and the per-message `OwnedAppend` alloc/free.
- These are the meaningful levers for matching NATS's page-cache throughput; they do not
  affect the durability guarantee and would *widen* the already-decisive power-loss-safe win.

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
