# S1 — many-streams fsync-storm durable produce (#1192, epic #1196 P1-B; the row that GATES #1193)

**Date:** 2026-07-27 · **Engine:** `0686d0bea014` (bench/1192-differentiation-cells, = main `ab74519` + the S1 harness)
· **Redpanda:** v26.1.12, production mode validated · **Substrate:** the matched lima vz VM
(Ubuntu kernel 7.0, 8 vCPU / 8 GiB, ext4 on virtio vda1, guest loopback) per
[../../REDPANDA_MATCHED_2026_07.md](../../REDPANDA_MATCHED_2026_07.md) §1.

## The cell

N concurrent producers, EACH to its OWN stream, every message an awaited durable ack with a
single in-flight per producer (the per-message storm shape):

- **IronBus**: N named streams `storm.0..N-1` on one LIVE `ironbus serve` (shipping defaults:
  sync durability = fsync-before-ack, per-stream storage mode = one log per named stream —
  exactly the K-dirty-streams shape the #1193 ceiling audit describes), one `publish_to` await
  per message per connection. Driver: `storm-produce` (Rust, the real client).
- **Redpanda**: N topics `storm0..N-1` (1 partition, r=1, `write.caching=false` = fsync before
  ack), `acks=all`, `max.in.flight=1`, `linger.ms=0`, compression none, idempotence off, one
  sync `send().get()` per message. Driver: `StormProducers.java` (official kafka-clients, one
  JVM, N threads).

Both drivers are method-identical (whole-phase wall aggregate, raw ns ack RTTs, nearest-rank
percentiles) — a same-instrument pair per the epic's coordinated-omission guardrail. Both sides
carry the `sync-per-message` durability label (matched; no new lint label needed). 128 B
realistic payloads. Pilot → freeze (30000/9000/2500 msgs/producer for N=8/32/128) → 3-run
medians, fresh broker + fresh data dir per run. Raw rows: [storm.jsonl](storm.jsonl) (pilots
included, `mode=timed` is the record); medians: [storm-final-medians.json](storm-final-medians.json).

## Medians (3 runs)

| N | broker | aggregate msg/s | per-producer ack p50 | per-producer ack p99 | pooled p99.9 |
|---|--------|----------------:|---------------------:|---------------------:|-------------:|
| 8   | IronBus  | 7 878  | 0.93 ms | 2.34 ms | 3.1 ms |
| 8   | Redpanda | **14 959** | **0.45 ms** | **1.58 ms** | 4.0 ms |
| 32  | IronBus  | 8 003  | 3.62 ms | **9.13 ms** | 24.0 ms |
| 32  | Redpanda | **12 317** | **1.37 ms** | 15.34 ms | 36.6 ms |
| 128 | IronBus  | 5 215  | 15.78 ms | 129.59 ms | 242.4 ms |
| 128 | Redpanda | **13 433** | **3.87 ms** | **67.84 ms** | 480.3 ms |

**Redpanda wins the cell at every N in this VM: 1.90x / 1.54x / 2.58x aggregate.**

## Shapes (the point of the row)

- **IronBus DEGRADES with N — the #1193 signal, confirmed.** Aggregate plateaus ~8 k msg/s at
  N≤32 and FALLS to 5.2 k at N=128 (worst run 3.7 k). Per-producer p50 grows ~linearly with N
  (0.93 → 3.62 → 15.78 ms ≈ N serial guest fdatasyncs per commit window), p99 reaches 129.6 ms
  and pooled p99.9 reaches 1.32 s in the worst N=128 run. This is exactly the ceiling the #1193
  audit predicted: K dirty named streams = K serial `fdatasync` barriers per commit tick (the
  #1040 pipelined flusher covers only the default log). **The gate for #1193 is met; this row
  is the before-baseline its fix re-measures.**
- **Redpanda holds aggregate roughly flat (12–15 k) across N** — its per-core raft/fsync
  batching absorbs this storm size — with per-producer p50 growing sub-linearly (0.45 → 1.37 →
  3.87 ms). Its pain shows in the TAIL and in RUN-TO-RUN INSTABILITY at high N: N=32 runs spread
  6.0–18.3 k msg/s (worst run p99 83 ms), N=128 pooled p99.9 reaches 480–652 ms. The externally
  reported fsync-storm weakness appears here as variance and tail (N=128 pooled p99.9 median
  480 ms, worst run 652 ms), not as a median collapse.

## Disclosures

- **VM fsync floor**: guest fdatasync through virtio is ~200–300 µs — far cheaper than the
  bare-metal/EBS fsyncs of the external evidence (Vanlightly 2023, 50+ producers on real disks).
  This cell does not reproduce that Redpanda collapse and does not refute it; a t4g/EBS re-run
  (fsync ~2.8 ms) would stress both brokers ~10x harder per barrier and is the epic's
  real-hardware follow-up.
- **Run walls**: Redpanda's timed rates came in ~2x above its pilot rates (JVM warm-up depressed
  the 500-msg pilots), so its walls landed at 15–26 s versus the 25–40 s target band; IronBus
  walls 30–86 s. Counts stayed frozen per the protocol rather than re-tuned after the fact.
- **Client fix**: kafka-clients 4.3.1 idempotence-on default races N concurrent InitProducerId
  handshakes into a client-side FindCoordinator NPE against this broker; the driver disables
  idempotence (plain at-least-once, matching IronBus's ack semantics — also the
  charitable-config direction).
- Single-node sync is a local barrier on both sides; clustered Redpanda `acks=all` is raft
  majority — a different (cluster) semantic, out of scope for this single-binary row. Guest
  fdatasync through virtio is matched across brokers, not a host-power-loss claim.
