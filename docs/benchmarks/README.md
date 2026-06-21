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
| `at-most-once` | no (best-effort) | `--fire-and-forget` (QoS-0, no ack) | core `nats bench pub` (no JetStream)\* | -- |

\* The `at-most-once` row's NATS column is the **CORE router** (`nats bench pub`, no JetStream, no
persistence, no ack), NOT the durable JetStream of every other row. It is a separate,
deliberately-unmatched send-rate probe (detailed in the findings below), added 2026-06-16, not part
of the matched-durability comparison. The Redis cell is empty: Redis Streams has no at-most-once
fire-and-forget publish. Reproduce this tier alone with `corpus_bench.py --faf-only` (needs
natscli >= ~0.2.x for the `nats bench pub` subcommand form).

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
  durability-independent). As of #464 the IronBus consume row is now a FAIR
  head-to-head: the `bench --mode subscribe` drain settles each fetched batch with
  one pipelined `ack_many` round-trip BY DEFAULT (the consume-side twin of the
  publish window), so it measures the broker's real fetch + batch-ack throughput,
  matched to how the peers consume -- NATS `js consume`, Redis `XREADGROUP`, and
  MQTT live delivery all batch or stream their acks. The synthetic group is still a
  COMPETING work-queue (each lease committed INDIVIDUALLY by the broker; cumulative
  ack stays broadcast-only), so the at-least-once contract is unchanged -- only the
  client's ack FLUSH is amortized. The previous per-message-ack drain (one
  synchronous `ack` RPC per message) is kept available behind `--per-message-ack`
  as a legitimate ack-RPC-LATENCY probe, NOT a throughput head-to-head.
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
- **Consume: now a FAIR head-to-head (#464).** The 2026-06-16 RPi4 consume row (~250 msg/s) was the
  OLD per-message-ack drain: ack-RPC-bound (one synchronous `ack` RPC per message), not fetch-bound,
  which the RPi4 sweep proved by staying flat across `--fetch-batch` sizes -- the ack round-trip, not
  the fetch, was the ceiling. As of #464 the drain batches the acks BY DEFAULT (one pipelined
  `ack_many` per fetched batch), so the IronBus consume number now reflects the broker's real fetch +
  batch-ack throughput, matched to the peers' batched/streamed consume (NATS ~20k, Redis ~11k). A
  same-config dev A/B (loopback, 256 B, `--fetch-batch 256`, `--no-fsync`) shows batched beating
  per-message at every backend (disk 2,382 -> 2,955 msg/s; memory 2,710 -> 3,734 msg/s avg-of-3, on a
  build that predates the #552 credit auto-tune); the amortization was bounded on fast loopback by the
  then-fixed 64-record consumer credit (so each round-trip carried only ~64 acks) and grows on a box
  where the per-RPC syscall cost dominates (the RPi4/edge case, where 63 of every 64 ack round-trips
  are removed). Post-#552 the per-connection count credit no longer pins the loopback window at 64: it
  auto-tunes from the 64 floor up toward the 2048 ceiling as the consumer keeps draining (RAM-bounded
  by the byte budget), so more acks amortize per round-trip on loopback than the figures above show --
  re-run to refresh. The reported `p99` for IronBus consume is
  closed-loop drain (queue-depth) latency, not service latency. The consume ROW in `corpus-report.md`
  is still the old per-message data; re-run the consume rows on the device (default `subscribe`) to
  refresh it -- the harness now drives the fair path with no flag change.
- **At-most-once (fire-and-forget / QoS-0): NATS core leads the raw SEND rate; IronBus pays for being
  a log.** This is a SEPARATE, deliberately-unmatched experiment, NOT part of the matched-durability
  comparison above: the NATS peer here is the CORE router (`nats bench pub`, no JetStream, no
  persistence), not the JetStream column of the durable tiers (where IronBus leads the memory tier).
  Both numbers are CLIENT SEND RATES into the socket -- no ack, no read-back, TCP backpressure is the
  only pacing -- so they are upper bounds on what each broker accepted, NOT delivered throughput. On
  that send rate NATS core leads IronBus QoS-0 (memory) at every size (256/1024/4096 B):
  168,981 / 144,350 / 62,710 vs 82,477 / 36,607 / 22,022 msg/s (~2.0x / 3.9x / 2.8x; the ratio is
  non-monotonic -- IronBus's absolute rate decays faster per byte). NATS core is a pure router (no
  log, no offsets, no compression); the gap is consistent with IronBus QoS-0 still assigning an
  offset, appending to an in-RAM log with a CRC, and lz4-compressing each message -- strictly more
  per-message work even with acks off (the harness measures end-to-end send rate, it does not isolate
  that cost). The flip side, which NATS core cannot do at all: IronBus QoS-0 on DISK does at-most-once
  delivery that STILL durably appends (18,408 / 5,995 / 1,696 msg/s, the only column here paying real
  fdatasync backpressure, so the closest cell to a true broker-accept rate). And in every tier that
  actually persists or queues, NATS core does not compete -- it has no durability at all. Single-rig
  RPi4 armv7 loopback, median-of-3; directional, not a universal constant.

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
- **FIXED (#464) -- work-queue consume was ack-RPC-bound (one ack RPC per message).**
  A competing work-queue commits each lease individually (cumulative ack is correctly
  rejected on a work-queue, "broadcast consumers only"), and the old drain issued one
  SYNCHRONOUS `ack` round-trip per message, so its throughput measured the per-message
  ack RPC, not the broker's fetch/consume rate -- an unfair self-handicap vs peers whose
  clients batch their acks. The drain now settles each fetched batch with one pipelined
  `ack_many` round-trip BY DEFAULT (the consume-side twin of `--pubwindow`); every lease
  is still committed individually by the broker, so the at-least-once contract is
  unchanged -- only the client's ack flush is amortized. The old behavior is kept behind
  `--per-message-ack` as a legitimate ack-RPC-LATENCY probe.
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

## Single-consumer consume corpus (#554, V2-M1)

The produce corpus above benched the produce axis (and an appendix consume row on
the OLD Tier-W work-queue). The CONSUME corpus is the V2-M1 headline: IronBus's
Tier-S STREAMING consumer (`bench --mode subscribe --consume-tier streaming`: the
merged streaming-tier consume path — windowed `StreamFetch` + bounded read-ahead +
periodic cumulative `StreamCommit`) vs a NATS JetStream durable PULL consumer
(`nats bench <subj> --js --sub 1 --pull`), at the matched `durable-consume` label
(both persist a consume cursor; a crash redelivers only the uncommitted span). The
NATS CORE sub (no JetStream) is the non-durable at-most-once reference (appendix
only). The same fairness lint applies: a durable-vs-non-durable pair fails the
build (`consume_corpus.rs` tests + `comparison.rs`), so the head-to-head cannot be
mislabeled. Run it (a t4g AWS Graviton2 here; needs `nats-server`/`nats` and a
current `ironbus`, no Redis/MQTT/Python deps beyond the stdlib):

```sh
python3 consume_bench.py --ironbus /path/to/ironbus \
    --out consume-rows.jsonl --sweep-out consume-sweep.jsonl
cargo run -p ironbus-bench --bin consume-corpus -- \
    --rows consume-rows.jsonl --json-out consume-report.json --md-out consume-report.md
```

The committed `consume-rows.jsonl` (the matched 20k-record head-to-head),
`consume-sweep.jsonl` (the 256 B record-count sweep curve), and the generated
`consume-report.{md,json}` are versioned alongside this README. The honest read is
in [PERF_LEDGER.md](../PERF_LEDGER.md#consume-scoreboard-single-consumer-durable-consume-vs-nats-554-v2-m1):
post-#665 (the O(N²) read-span fix, re-validated 2026-06-19 on the same t4g rig),
**IronBus Tier-S beats NATS JS pull at EVERY point of the 20k → 200k prefix sweep
(6.2x – 8.5x) and the IronBus curve is FLAT-to-rising (~640k – 904k /s) instead of
collapsing** — the prior super-linear degradation (148k → 23k across 20k → 200k,
crossing under NATS near ~30k records) is gone because #665 clamps the server
`StreamFetch` read span to the consumer window. The win is now unconditional across
the measured range; NATS JS pull stays flat ~104k – 109k /s.

## Cluster performance corpus (#634, #632, V2-C8)

The single-node corpora above bench one broker. The C8 cluster corpus benches the
**clustered** broker — the consensus + replication + read-consistency machinery
(`crates/ironbus-server/src/cluster/`) — on two axes, on real local clusters
(loopback) on commodity hardware. These are the SCALING SHAPE + relative ratios;
the absolute edge (t4g) numbers are issue #636, a separate hardware run, NOT
fabricated here. Each leg's report carries its machine spec, run count, and the
honest caveats (including where IronBus loses).

### Clustered-consume apportioned-read scaling (#634, C8-I5)

The headline: with the #723 follower-read tiers, a consumer fleet can fan its
committed reads across all `R` replicas (a follower serves a `<=` safe-HW committed
read LOCALLY from its own replicated copy — CRAQ clean; the leader serves a 0-RTT
lease-local read), so aggregate consume throughput scales ~`O(R)`, vs NATS where
consume is served from the one stream leader (`O(1)` in stream replicas).
[`cluster_consume_bench.py`](cluster_consume_bench.py) drives the
[`cluster-consume-bench`](../../crates/ironbus-bench/src/bin/cluster_consume_bench.rs)
Rust harness (a real on-disk leader log + a live `DataPlaneRuntime` cluster over
loopback; followers replicate the committed prefix, then a fleet drains it via the
#723 serve path) for `R` in {1,3,5} and the matched NATS file-stream pull leg. The
committed [`cluster-consume-rows.jsonl`](cluster-consume-rows.jsonl) and
[`cluster-consume-report.md`](cluster-consume-report.md) are the data. HONEST scope
(in the report): the IronBus side drives the `DataPlaneController` follower-read
SERVE PATH in-process over the REAL live runtime (the #723 tiers are not yet threaded
into the per-connection wire `session.rs`), while NATS is end-to-end over the wire —
so read the IronBus SCALING SHAPE, not the literal wire-to-wire ratio.

```sh
cargo build --release -p ironbus-bench --bin cluster-consume-bench
python3 cluster_consume_bench.py \
    --bench-bin ../../target/release/cluster-consume-bench \
    --out cluster-consume-rows.jsonl --md-out cluster-consume-report.md
```

### Heartbeat-cost scaling (#632, C8-I4)

The per-node cost a cluster pays JUST to stay alive (heartbeats, liveness,
consensus) when IDLE, as it grows. IronBus uses one KRaft-style metadata-Raft
(`O(N)` heartbeat from one leader to N-1 voters every ~300 ms); NATS uses a full
route mesh (`O(N²)` gossip). [`cluster_heartbeat_bench.py`](cluster_heartbeat_bench.py)
launches real `ironbus serve --cluster-*` and `nats-server` cluster processes,
settles them, and measures per-node CPU (CPU-time delta) and network bytes/s
(`nettop` delta) over a window, 5 runs each. IronBus runs at N in {3,5} (its
metadata-Raft supports only 1/3/5 voters; 7 is refused at startup); NATS at {3,5,7}.
The committed [`cluster-heartbeat-rows.jsonl`](cluster-heartbeat-rows.jsonl) and
[`cluster-heartbeat-report.md`](cluster-heartbeat-report.md) are the data. HONEST
(in the report): the network bytes/s curve is the trustworthy `O(N)`-vs-`O(N²)`
asymptote; the measured IronBus idle CPU is dominated by a per-peer dialer-thread
busy-spin (a real bug this benchmark surfaced — IronBus LOSES the idle-CPU comparison
to NATS's ≈0% until it is fixed), reported plainly, not spun.

```sh
cargo build --release -p ironbus-cli --bin ironbus
python3 cluster_heartbeat_bench.py --ironbus ../../target/release/ironbus \
    --out cluster-heartbeat-rows.jsonl --md-out cluster-heartbeat-report.md
```
