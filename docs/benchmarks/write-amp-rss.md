<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Write amplification + RSS per message: IronBus vs NATS JetStream

The [#645](https://github.com/ELares/IronBus/issues/645) (V2-M12) benchmark: measure, on both
brokers at matched workloads, (1) **write amplification** — bytes actually written to disk per
logical payload byte during a durable produce phase — and (2) **RSS per stored message** — the
broker's resident memory at idle, after 200k stored, and after 1M stored. These are the two
resource axes behind IronBus's **memory-honesty** posture (the `memory honesty` milestone:
[#492](https://github.com/ELares/IronBus/issues/492) one-copy ephemeral storage,
[#493](https://github.com/ELares/IronBus/issues/493) `max_total_bytes` documents its physical
multiplier, [#520](https://github.com/ELares/IronBus/issues/520) the boot RAM guard charges 1x;
the enforced RAM-ceiling guard and itemized RSS budget are
[RAM_BUDGET.md](../RAM_BUDGET.md)) and its **durable-produce efficiency** claim (one
group-commit `fdatasync` over an append-only segmented log,
[#177](https://github.com/ELares/IronBus/issues/177)). Comparative and reproducible; wins,
losses, and caveats are all recorded — **two of the four scored axes are honest IronBus
losses** (see the honest read below).

## Harnesses (how to re-run)

One scripted harness runs BOTH sides and prints every measurement as an `OBSERV:` line
([`write_amp_rss.sh`](write_amp_rss.sh)):

```sh
cargo build --release --bin ironbus
IRONBUS_BIN=target/release/ironbus bash docs/benchmarks/write_amp_rss.sh   # [--side ib|nats]
```

Linux only (it reads `/proc/<pid>/io` and `/proc/<pid>/status`); it downloads the pinned
nats-server + natscli for the host arch. Keep `WORK` on a real local filesystem (not a bind
mount), or the `write_bytes`/`du` readings lose meaning. The committed machine-readable rows
([`write-amp-rss-rows.jsonl`](write-amp-rss-rows.jsonl)) and this doc are kept from drifting
apart by the offline CI gate `scripts/ci/write-amp-rss-check.sh` — a live comparative run in CI
would be a flaky percent gate (the #114 design consideration), so re-runs are manual, on a
quiet box, updating the rows and this doc together.

## Methodology and versions

- **Environment:** Linux container (aarch64), single host, loopback, one run per leg.
  2026-07-10. **No throughput number is read from this harness** — the durable
  produce/consume rates live in the [#646 scoreboard](../PERF_LEDGER.md).
- **Versions:** IronBus at this commit (release build, disk-durable defaults:
  `durability_level=sync`, `power_loss_safe=true`, lz4 on, balanced profile) vs
  **nats-server v2.14.3** driven by **natscli 0.4.0** (JetStream file storage, `replicas=1`,
  fresh store per leg).
- **Matched workload, both sides:** same message count and payload bytes (200,000 x 256 B,
  200,000 x 4 KiB, and a 1,000,000 x 256 B extension), pipelined durable publish (IronBus
  `bench --stream --pubwindow 1024` vs `nats bench js pub async --batch 500`), one
  subject/stream, no consumers.
- **Payload shape:** the scored IronBus legs use `--payload-shape random` (incompressible), so
  the default lz4 **cannot flatter** the IronBus numbers; a compressible-payload context leg
  is recorded separately.
- **NATS sync discipline:** the scored legs run JetStream `sync_interval: always` — the
  closest available match to IronBus's fsync-backed group commit, and required for a fair
  `write_bytes` reading (without it JetStream's writeback is attributed to kernel flusher
  threads, not the broker). A shipped-default-sync context leg is recorded so this choice is
  auditable. Even under `sync_interval: always` the JetStream publish ack is
  **NOT fsync-coupled** (the [#646 asymmetry](../PERF_LEDGER.md)); the IronBus ack is
  fsync-backed. The workloads are matched; that residual guarantee gap is stated, not scored.
- **Two write-amplification numbers, deliberately different in meaning:**
  `write_bytes captures` the produce-phase **churn** — everything the broker process caused
  the storage layer to write, including rewrites that never stay on disk
  (`/proc/<pid>/io write_bytes` delta / logical payload bytes); `du captures` what is
  **retained** after the phase settles, including preallocation slack (`du -sB1` delta /
  logical payload bytes). Both are reported for both sides.
- **RSS:** steady `VmRSS` (plus peak `VmHWM`) from `/proc/<pid>/status`, read after a settle
  pause at idle, after 200k stored, and after 1M stored.

## Results

### Write amplification (200,000 messages, disk-durable, matched fsync discipline)

| Axis | IronBus (measured) | NATS 2.14.3 (measured) | Read |
| --- | --- | --- | --- |
| 256 B, write_bytes (churn) | **1.21x** | **17.1x** | IronBus writes **14.1x** fewer disk-layer bytes for the same payload at the matched fsync discipline |
| 256 B, du (retained) | 1.17x | **1.13x** | **NATS retains slightly less**: ~34 B/msg framing vs IronBus ~43 B/msg (record framing + CRC + lz4 descriptor) |
| 4 KiB, write_bytes (churn) | **1.01x** | **2.01x** | the churn gap narrows as payload dominates, but JetStream still writes every byte twice |
| 4 KiB, du (retained) | 1.07x | **1.01x (du)** | NATS leaner again; the IronBus figure carries rolled-segment preallocation slack (13 x 64 MiB retained vs 829 MB written) |

Context rows (unpaired, each with its caveat in the rows file):

- **IronBus + default lz4 on a compressible (telemetry-shaped) payload: 0.52x** — on realistic
  structured payloads the default path writes about half the logical bytes. Not scored: NATS
  does not compress by default.
- **NATS at its shipped default sync interval (2 min): 1.13x (default sync)** — the churn
  collapses to ~du level when JetStream barely fsyncs, which is exactly the durability
  discipline IronBus refuses by default (acks not backed by any fsync for up to 2 minutes),
  and that leg's `write_bytes` undercounts real disk traffic (flusher-thread attribution).
- At 1M messages (256 B) the cumulative figures hold: IronBus write_bytes 1.21x, NATS 17.1x;
  IronBus du grows to 1.31x (up to one 64 MiB segment of preallocation slack at any moment),
  NATS du stays 1.13x.

### RSS per stored message (256 B payloads)

| Point | IronBus VmRSS (VmHWM) | NATS VmRSS (VmHWM) |
| --- | --- | --- |
| idle (empty broker) | **5.5 MiB** (5.5) | **13.3 MiB** (13.3) |
| after 200k stored | 7.0 MiB (7.0) | 36.1 MiB (42.0) |
| after 1M stored | **7.9 MiB** (7.9) | **36.9 MiB** (42.0) |
| after 200k x 4 KiB stored | 13.6 MiB (13.6) | 38.9 MiB (47.0) |

| Derived | IronBus | NATS |
| --- | --- | --- |
| RSS per stored message, 0 -> 1M | **2.55 B/msg** | **24.7 B/msg** |
| RSS per stored message, marginal 200k -> 1M | 1.22 B/msg | **1.04 B/msg** |

## The honest read

- **Write churn is the real differentiator, and the WHY is structural.** IronBus appends
  framed records to a segmented log and group-commits a drained batch with ONE `fdatasync`
  (#177): a byte is written once, plus ~4.7% framing at 256 B. JetStream's file store, made to
  honor the same per-write sync discipline, causes **17.1x** the logical bytes to hit the
  storage layer at 256 B — the retained store is only 1.13x, so ~16x of it is **rewrite churn**
  (message-block + index rewrites around each synced write), not retention. On flash-budgeted
  edge hardware (the [EDGE_CONSTRAINTS.md](../EDGE_CONSTRAINTS.md) wear budget), write churn
  is lifetime; 14.1x fewer written bytes at equal payload is the durable-produce-efficiency
  claim, measured.
- **Retained bytes: an honest IronBus loss, twice.** JetStream's file format is leaner at rest
  (1.13x vs 1.17x at 256 B; 1.01x (du) vs 1.07x at 4 KiB). IronBus pays ~43 B/msg of framing
  (header + CRC + compression descriptor) against NATS's ~34 B/msg, plus up to one 64 MiB
  segment of preallocation slack until the next roll. Anyone quoting the churn win should
  see this column too.
- **Absolute RSS substantiates the memory-honesty posture.** With 1M durable 256 B messages
  stored, the IronBus broker sits at **7.9 MiB** resident — **4.7x** below NATS's 36.9 MiB —
  and the per-stored-message cost over the full window is **2.55 B/msg** vs **24.7 B/msg**.
  This is the RAM_BUDGET.md stance made visible: bounded buffers, no mmap'd store, no
  per-message index resident by default. Even the 4 KiB leg (819 MB durable) holds 13.6 MiB
  steady. (The [#115 refuse-to-boot RAM-ceiling guard](../RAM_BUDGET.md) is about worst-case
  *bounded-buffer* footprint, which is config-provable, not measured here; these steady-state
  numbers are consistent with it, not a proof of it.)
- **Marginal RSS at scale: effectively a tie, honestly NATS's by a hair.** Past the first
  200k (buffer/cache warm-up on both sides), each additional stored message costs ~1 B of
  resident memory on either broker (1.22 B/msg IronBus vs 1.04 B/msg NATS over 200k -> 1M).
  Neither broker keeps per-message state in RAM for a single-subject stream at rest; the
  IronBus advantage is the absolute footprint and the flat ramp, NOT an unbounded-index claim
  against NATS.

## Caveats (read before quoting any number)

- **One virtualized aarch64 container, one host, one run per leg.** Ratios are the meaningful
  output; absolute byte counts and MiB figures are directional. The RSS readings in the table
  are from the scored 256 B leg's process; idle RSS varied run-to-run by ~1 MiB on the NATS
  side (Go allocator) and ~0.1 MiB on the IronBus side.
- **`write_bytes` vs `du` measure different things** (churn vs retained — see methodology);
  quoting one as the other is exactly the dishonesty this page exists to avoid. `wchar` and
  `cancelled_write_bytes` are also recorded in the transcripts.
- **One payload mix** (fixed-size 256 B / 4 KiB, single subject, no consumers, no replication).
  Subject-heavy or fan-out workloads shift both axes; JetStream `R>1` replication multiplies
  its write path further, as does the IronBus cluster (#392) — neither is measured here.
- **The sync disciplines are matched, not identical:** `sync_interval: always` is the closest
  JetStream analog to IronBus's group commit, and the JetStream ack remains NOT fsync-coupled.
  The default-sync context leg shows what the shipped NATS default does to the churn column.
- **Allocator/GC semantics differ** (Go returns freed pages lazily; VmHWM is reported so the
  peak is visible). Steady VmRSS after a settle pause is the comparable number.
- IronBus ran a release build at shipped defaults; nats-server ran its release binary at the
  stated JetStream config. Counts, sizes, and every raw probe value are in the harness
  transcript (`grep OBSERV:`).
