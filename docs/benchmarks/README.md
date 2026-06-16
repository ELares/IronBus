# Competitor benchmark corpus

A reproducible, **matched-durability** comparison of IronBus against the
edge-class peers named in the prior-art survey ([`docs/PRIOR_ART.md`](../PRIOR_ART.md))
and the baseline rig ([`docs/BASELINE_RIG.md`](../BASELINE_RIG.md)): NATS
JetStream, Redis Streams, and Mosquitto (MQTT). This fills the "host residual"
the rig was built for -- the rig (schema + fairness lints + Little's-Law) shipped
in [`crates/ironbus-bench`](../../crates/ironbus-bench) long before the live peer
runs existed; this corpus is those runs.

## The honesty contract

A comparison is honest only if both sides run the **same workload** under the
**same durability semantics** on the **same device**. The assembler enforces it
mechanically: [`ComparisonReport::build`](../../crates/ironbus-bench/src/comparison.rs)
**fails to build** a pair whose two rows carry mismatched durability labels,
message sizes, or devices. You cannot assemble a report that quotes IronBus's
durable group-commit-fdatasync number against a peer's page-cache number -- that
build is a hard error, not a footnote.

### Durability tiers (the matched labels)

| tier | power-loss safe? | IronBus | NATS JetStream | Redis Streams |
| --- | --- | --- | --- | --- |
| `sync-per-message` | yes | `--pubwindow 1` (fdatasync per ack) | `pub sync` + `sync_interval: always` | `appendfsync always`, **1 client** (no fsync coalescing) |
| `group-commit-fsync` | yes | `--pubwindow 1024 --stream` (1 conn, batched fdatasync) | -- (no ack-after-fsync mode) | `appendfsync always`, **50 clients** (fsync coalesces across writers) |
| `page-cache-async` | **no** | `--no-fsync` | async file store (default ~2 min sync) | `appendfsync everysec`, pipelined |
| `memory` | no (ephemeral) | `--storage memory` | memory-storage stream | AOF disabled |

Concurrency is part of durability fairness: `redis-benchmark` defaults to 50
clients, so `appendfsync always` silently coalesces fsyncs across them -- that is
NOT per-message durability. The `sync-per-message` tier therefore pins Redis to
`-c 1` (one fsync per message, SD-bound, the true apples-to-apples for IronBus
window=1 and NATS `pub sync`); the concurrent `appendfsync always` number lives
in `group-commit-fsync`, where it is the honest analog to IronBus's group commit.

### MQTT is reported as context, not paired

Mosquitto is a routing protocol over broker session state, not a replayable
durable log, and its persistence is periodic autosave, not per-ack fsync. Its
labels are `mqtt-qos{0,1}` (their own enum variants), so the lint can never pair
it head-to-head with a log system under a shared durability label. It is reported
as context (QoS 1 / QoS 0 publish throughput), never as a durable head-to-head.

## Metrics

- **publish throughput** (produce → ack), per durability tier -- the primary
  comparable number.
- **consume throughput** (drain a pre-filled store) -- closes the previously-unbenched
  consume side, measured once per system with a fast pre-fill (drain rate is
  durability-independent). NOT a matched head-to-head like publish: each system
  drains via its NATIVE default consume path, and those differ fundamentally.
  IronBus's synthetic group is a COMPETING work-queue, which acks each lease
  individually and checkpoints the cursor (cumulative ack is a broadcast-only
  primitive), so its drain is ack-RPC-bound; NATS `js consume`, Redis
  `XREADGROUP`, and MQTT live delivery batch or stream their acks. So the consume
  row shows each system's real default consume behavior, not a like-for-like
  durability comparison -- a fair matched consume (e.g. an IronBus broadcast group,
  or a batched/multi-ack work-queue drain) is follow-up work.
- **latency** is reported only where a tool yields a natively-saturated percentile
  (NATS publish). The load models differ across systems (IronBus/Redis closed-loop
  vs NATS open-loop), so cross-system latency is NOT headlined; throughput is the
  apples-to-apples metric, exactly as `ComparisonRow` centers on throughput.

## Findings from the 2026-06-16 run (RPi4 armv7)

The committed `corpus-report.md` is the data; the read:

- **Durable per-message (`sync-per-message`): IronBus leads at every size** (256/1024/4096 B:
  211/192/182 vs NATS 179/153/132, Redis -c1 181/178/150 msg/s). All three are fdatasync-bound
  on the SD card, and IronBus is fastest at that floor.
- **Durable at throughput (`group-commit-fsync`): IronBus's differentiator, strongest small.**
  256 B: 17,278 vs Redis-50-clients 3,505 (~5x); it narrows with payload (1024 B 5,622 vs 2,507;
  4096 B 1,488 vs 1,564, ~parity) as per-byte cost dominates. NATS has no ack-after-fsync mode.
- **Memory: IronBus dominates at every size** (84k/61k/26k vs NATS 17k/18k/12k, Redis 44k/32k/15k).
- **Page-cache (relaxed): IronBus leads at 256 B but LOSES at larger payloads** (4096 B: 1,359 vs
  NATS 6,128 / Redis 6,376). This is IronBus's shipped default lz4 compression: it compresses every
  payload byte, so on this small ARM core throughput at the relaxed tier becomes per-byte-CPU-bound
  while the peers (no default compression) do not pay it. It is an honest cost of a real feature
  (less disk/uplink); `--compression none` would close the gap at the cost of that feature.
- **Consume: NOT a fair head-to-head (see Metrics).** IronBus's work-queue per-message-ack drain is
  ack-RPC-bound (~250 msg/s) vs the peers' batched/streamed consume (NATS ~20k, Redis ~11k); the
  reported `p99` for IronBus consume is closed-loop drain (queue-depth) latency, not service latency.
  A matched consume is tracked follow-up work.

## Bugs found and fixed (and findings) along the way

Building this corpus exercised paths the unit tests do not, and surfaced real
issues (all in the `bench` harness / rig, none in the broker's data path):

- **FIXED -- `bench --mode subscribe` hung on shed/loss.** The drain only stopped
  at `recorded >= expected`, so any preloaded record shed under a byte cap left it
  looping forever. Now it also stops on a sustained-empty queue and reports the
  shed count (`drain_should_stop`, unit-tested).
- **FIXED -- subscribe preload was fsync-bound.** It produced the preload serially
  (one fdatasync per message, ~SD speed), making a large preload take minutes for
  a metric (drain rate) that does not depend on write speed. Now pipelined
  (group-committed) per chunk.
- **Finding (not a bug) -- work-queue consume acks per message.** A competing
  work-queue acks each lease individually; cumulative ack is correctly rejected on
  a work-queue ("broadcast consumers only"). So IronBus's work-queue drain is
  ack-RPC-bound; the corpus reports it with that caveat rather than papering over
  it. A faster fair consume path (broadcast group / batched ack) is a tracked
  follow-up.
- **Finding to investigate -- `--storage memory` produce can block at capacity.**
  A produce that the memory broker sheds under its cap appeared to leave the
  blocking client waiting (the preload did not return). The corpus avoids it
  (it pre-fills consume on disk); worth a separate look at whether a shed produce
  should surface a typed error/timeout to the client.

## Reproduce

On the device (the canonical edge box is an RPi4 armv7, Raspbian buster, all
loopback). Requires `redis-server`, `mosquitto`, `nats-server`/`nats`, `python3`
with `redis` and `paho-mqtt`, and a current `ironbus` binary:

```sh
python3 corpus_bench.py --ironbus /path/to/ironbus --out rows.jsonl
cargo run -p ironbus-bench --bin assemble-corpus -- \
    --rows rows.jsonl --json-out report.json --md-out report.md
```

`corpus_bench.py` starts each peer on a scratch dir/port and stops it after;
nothing is left running. `assemble-corpus` builds the lint-validated report -- if
any pair is mislabeled it exits non-zero. The generated `report.md` and
`report.json`, plus the raw `rows.jsonl`, are committed alongside this README so
each corpus is versioned with the IronBus revision that produced it.
