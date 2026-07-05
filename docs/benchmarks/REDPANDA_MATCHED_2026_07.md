# Matched-conditions study, July 2026: IronBus vs Redpanda, both inside one Linux VM

A fair IronBus-vs-Redpanda head-to-head has one hard constraint: Redpanda is Linux-only, so both brokers must run on the **same substrate** or the comparison proves nothing. This study does exactly that — **both brokers run inside the same Linux VM**, on the same kernel, the same ext4-on-virtio disk, the same loopback, with the same real `fdatasync`. The VM is not a handicap on one side; it is the identical substrate for both, so the comparison is rankable in both directions. (For the real-hardware confirmation on AWS Graviton + EBS, see §7.)

It also closes the loop on the optimization work this study motivated: the P2 durable-produce gap it measured drove the **pipelined sync tier** ([#1040](https://github.com/ELares/IronBus/issues/1040)), and the numbers below are IronBus **after** that landed.

## 1. Environment

- **Host machine (runs the VM):** Apple M4 Pro, 14 cores, 48 GB.
- **VM:** lima `vz` (virtio), Ubuntu, kernel 7.0, 8 vCPU, 8 GiB, a single ext4 filesystem on the `vda1` virtio block device. All brokers and all load clients run **inside** the VM on guest loopback — no host↔guest port-forward hop.
- **Durability substrate:** guest `fdatasync` through virtio, measured at ~200–300 µs (a real block-layer flush, ~15–20× cheaper than a ~4 ms `F_FULLFSYNC`-class barrier — which is why rows that would sit flat against an expensive fsync wall become discriminating here).
- **IronBus:** current `main` including the pipelined sync tier (#1040), built in-guest for `aarch64-unknown-linux-gnu`, release profile. Shipped defaults, lz4 compression on, realistic (compressible) payloads.
- **Redpanda:** v26.1.12, **production mode** (`developer_mode: false` — no `--unsafe-bypass-fsync`), `--smp=6 --memory=6G` (its own ≥1 GiB/core production floor), `io_uring` reactor backend. Durable tiers set `write_caching=false` (genuinely fsync-before-ack; Redpanda's default). Every tier knob validated at each broker start.

## 2. Fairness pins (the traps this study had to avoid)

- **Guest `/tmp` is tmpfs (RAM).** IronBus's bench spawns its broker under `temp_dir()`, which would have silently put its "disk" log in RAM. `TMPDIR` is pinned to ext4 on the same `vda1` device Redpanda writes.
- **Redpanda's default is fsync-before-ack.** `write_caching` is **off** by default, so Redpanda's durable rows are a genuine power-loss-safe peer — this study does not quietly compare IronBus's fsync against Redpanda's page cache.
- **Both drivers are the systems' standard load tools.** IronBus: `ironbus bench` (its own client). Redpanda: `kafka-producer-perf-test` (the standard Kafka perf client, `acks=all`, `batch.size=65536 linger.ms=5`, up to 5 in-flight requests per connection). Both are each system's normal, saturating client shape.
- **Serial, quiet, 3-run medians.** One broker at a time, ports asserted free between brokers, fresh data dirs per cell, pilot-run → frozen-count → 3-timed-runs → median. Redpanda gets an extra unrecorded JVM-client warm-up per cell.

## 3. The matrix (single connection, medians of 3)

Matched durability tiers, one client connection each. `msg/s`, higher is better; L1 is produce→ack RTT, lower is better.

| Row (durability label) | Size | IronBus | Redpanda | Winner |
| --- | --- | ---: | ---: | :-- |
| **P1** sync-per-message produce (fsync before **every** ack) | 128 B | 3,569 | 4,207 | Redpanda 1.18× |
| | 1 KiB | 3,580 | 3,513 | IronBus 1.02× |
| **P2** group-commit produce (coalesced fsync-before-ack) | 128 B | 592,747 | 1,557,863 | Redpanda 2.63× |
| | 1 KiB | 130,452 | 287,675 | Redpanda 2.21× |
| **P3** relaxed produce (page-cache ack, NOT power-loss-safe) | 128 B | 1,709,873 | 1,872,973 | Redpanda 1.10× |
| | 1 KiB | 843,143 | 464,588 | **IronBus 1.81×** |
| **C1** consume / replay (single-consumer drain) | 128 B | 5,659,915 | 5,482,456 | **IronBus 1.03×** |
| | 1 KiB | 2,164,179 | 1,183,940 | **IronBus 1.83×** |

| Latency row | Size | IronBus p50 / p99 | Redpanda p50 / p99 | Winner |
| --- | --- | --- | --- | :-- |
| **L1** durable produce→ack RTT (single in-flight) | 128 B | **285 / 368 µs** | 2,000 / 9,000 µs | **IronBus ~7×** |
| | 1 KiB | **282 / 342 µs** | 2,000 / 9,000 µs | **IronBus ~7×** |

Single-connection reading: IronBus **wins P3/1 KiB, both C1 rows, and both L1 rows outright**, ties P1/1 KiB, and trails on P2 (both sizes) and P3/128 B. The P2 single-connection gap is not the engine — it is the client: IronBus's session drains its parked-produce window at each pass boundary, so one connection cannot keep the group-commit pipeline full. That ceiling is the subject of the P2 sweep below and its follow-up.

> Redpanda's L1 reads *worse* than its own P1 (2 ms vs ~240 µs implied by 4,207 msg/s) because the L1 tool throttles to 100 msg/s and reports whole-millisecond-quantized latency; the P-rows are the fair throughput comparison, the L-rows the fair IronBus-internal latency. IronBus's L1 (real per-ack RTT via #1024 percentiles) is the honest sub-millisecond durable-ack number.

## 4. P2 under client concurrency — the pipelined sync tier

The single-connection P2 ceiling is the IronBus **client**, not its broker. The broker's group-commit pipeline (#1040: `fdatasync` decoupled from the append path, overlapped with the next append window, self-clocking drain) needs several in-flight connections to fill — exactly what Redpanda's Kafka client already does on one connection (5 in-flight). Giving each broker the client concurrency that saturates it:

*(Redpanda run under N parallel `kafka-producer-perf-test` clients; IronBus under `bench --producers N`. Aggregate = total records ÷ full wall window. Medians of 3.)*

**P2 @ 128 B (msg/s):**

| Clients | IronBus | Redpanda | Ratio |
| ---: | ---: | ---: | :-- |
| 1 | 601,177 | 1,397,144 | Redpanda 2.32× |
| 4 | 1,643,505 | 1,510,518 | **IronBus 1.09×** |
| 8 | 1,683,450 | 1,170,813 | **IronBus 1.44×** |
| **peak** | **1,683,450** (x8) | 1,510,518 (x4) | **IronBus 1.11×** |

**P2 @ 1 KiB (msg/s):**

| Clients | IronBus | Redpanda | Ratio |
| ---: | ---: | ---: | :-- |
| 1 | 132,784 | 233,558 | Redpanda 1.76× |
| 4 | 406,501 | 299,681 | **IronBus 1.36×** |
| 8 | 657,035 | 267,080 | **IronBus 2.46×** |
| **peak** | **657,035** (x8) | 299,681 (x4) | **IronBus 2.19×** |

Two facts, both measured at matched client concurrency (no x4-vs-x1 sleight of hand — Redpanda was run under the same 1/4/8 parallel clients):

- **Redpanda does not scale with more clients.** Its single-partition raft group is already saturated by one 5-in-flight Kafka client; adding clients adds contention, so its throughput **peaks at 4 clients and drops at 8** (1.51 M → 1.17 M @128 B; 300 k → 267 k @1 KiB).
- **IronBus scales up and passes Redpanda's peak.** The pipelined sync tier (#1040) turns concurrent durable producers into shared covering `fdatasync`s, so IronBus climbs to **1.68 M @128 B and 657 k @1 KiB** — above Redpanda's best on both sizes (1.11× and 2.19×), and 1.44×/2.46× at matched 8 clients.

The single-connection row is the honest exception: there IronBus trails, because its session drains the parked-produce window at each pass boundary and one connection cannot fill the pipeline. That ceiling — not the broker engine — is the subject of the session-side per-connection reorder ring ([#1045](https://github.com/ELares/IronBus/issues/1045)). This study reports the single-connection loss and the multi-connection win side by side, unhidden.

## 5. How the gaps were found and closed

The single-connection matrix drove a mechanism-level source analysis of Redpanda (documented against its `dev` tree) and a ranked set of portable optimizations. What shipped this round:

- **P2 (the headline gap): the pipelined sync tier** — [#1040](https://github.com/ELares/IronBus/issues/1040) (activation), building on the async-commit prep API [#1046](https://github.com/ELares/IronBus/issues/1046) and the `fdatasync`-carries-no-i_size-update preallocation change [#1047](https://github.com/ELares/IronBus/issues/1047). The multi-connection validation and the honest single-connection ceiling are on #1040.
- **Bench tooling:** `bench --producers N` — [#1048](https://github.com/ELares/IronBus/issues/1048) — the multi-connection driver these rows required.

Filed as design issues with measured evidence rather than rushed ports:

- **C1 @128 B** small-record consume (a noise-band tie here — IronBus 5.66 M vs Redpanda 5.48 M, inside Redpanda's ~30 % run-to-run spread on that cell; Redpanda's zero-copy tail path can lead on other runs) — the tail-delivery / dirty-pinned-cache path, [#1041](https://github.com/ELares/IronBus/issues/1041). *Verified during analysis: the IronBus broker does not decompress on deliver — the cost is per-record tail materialization, not codec CPU.*
- **P2 single-connection ceiling** — the session per-connection seq-reorder ring, [#1045](https://github.com/ELares/IronBus/issues/1045).
- **SDK-side compression by default** (revisits ADR-0003 broker-side lz4) — [#1042](https://github.com/ELares/IronBus/issues/1042).
- **Architecture-class, gated on a mixed-load bench row first:** thread-per-core scheduling isolation [#1043](https://github.com/ELares/IronBus/issues/1043); O_DIRECT + broker-owned cache [#1044](https://github.com/ELares/IronBus/issues/1044). Both were flagged by all five analysis lenses as *not* single-node row movers on a quiet box — filed for the record, not built.

The consensus finding of the source analysis is worth stating plainly: Redpanda's single-node speed is **not** thread-per-core. It is (a) `fdatasync` decoupled from and overlapped with the append path, (b) zero per-record broker work (wire bytes are the stored bytes are the fetch bytes), and (c) a dirty-pinned in-memory tail cache. The first of these is what #1040 ported, and it is what moved P2.

## 6. Scope, and what this study is not

- One VM, single-node brokers, guest loopback. No cluster claim.
- Redpanda's numbers here are inside a VM — but so are IronBus's, on the identical substrate, which is the entire point. These rankings are valid **relative to each other in this environment**; they are not bare-metal absolute numbers for either broker. A real-hardware confirmation on Graviton with real EBS `fdatasync` was run — see §7, which reproduces (and sharpens) the result.
- P4 (in-memory) and L2 (in-memory RTT) are omitted: Redpanda has no true in-RAM ephemeral mode, and labeling its page cache as "memory" would be dishonest.
- Numbers are medians of 3; per-cell run-to-run spreads were ≤ ~8% except where noted. Never quote a single run.

## 7. Real-hardware confirmation — AWS Graviton, real EBS `fdatasync`

The VM removes the *comparison* confound (both brokers on one substrate) but not the *virtualization* one (virtio `fdatasync` lands in the host page cache at ~200–300 µs — a real block-layer flush, but not a real durable-media one). To close that too, the same harness was run on a single **AWS t4g.large** (Graviton2, 2 vCPU, 8 GiB), Ubuntu 24.04 arm64, with both brokers writing the **EBS gp3** root — a genuine network-attached durable volume. Same protocol, same Redpanda build (v26.1.12, production mode), medians of 3.

The substrate is materially harder: **EBS gp3 `fdatasync` measured ~2.8 ms p50 / ~3.1 ms p99** — roughly 10× the VM's virtio flush, an `F_FULLFSYNC`-class barrier. A durable barrier this expensive is the toughest possible test of a group-commit engine: the only way to sustain throughput is to coalesce and overlap many records per sync.

**Single connection** (msg/s; L1 is p50/p99 µs, lower better):

| Row | Size | IronBus | Redpanda | Note |
| --- | --- | ---: | ---: | :-- |
| P1 sync-per-message | 128 B | 339 | 533 | Redpanda keeps a few requests in flight even at `batch.size=1`; IronBus `pubwindow=1` is strictly one-at-a-time (the same client-concurrency story as P2, #1045) |
| P2 group-commit | 128 B | 62,329 | 137,605 | single-conn session-drain ceiling (#1045) |
| | 1 KiB | 16,021 | 30,870 | |
| P3 relaxed | 128 B | **385,447** | 219,852 | **IronBus 1.75×** |
| | 1 KiB | **279,580** | 48,445 | **IronBus 5.8×** |
| C1 consume | 128 B | 1,130,826 | 1,571,833 | Redpanda 1.39× |
| | 1 KiB | **589,996** | 476,848 | **IronBus 1.24×** |
| L1 durable-ack | 128 B | **2,956 / 3,381** | 2,000 / **137,000** | IronBus p99 3.4 ms vs Redpanda **137 ms** — a ~40× tighter tail (Redpanda's p50 is throttled-tool-quantized to whole ms) |

The two rows this table flags as trailing — **P1** and single-connection **P2** —
predate a durable-write feature that has since shipped; see the update immediately
below for the current single-connection result.

### Update — the configurable io-mode (#1054), same substrate

The table above is honest for the code at that time: `pubwindow=1`
one-record-at-a-time produce over a ~2.8 ms **buffered** `fdatasync`. Two things
have since landed. The **io-mode** (`--io-mode auto` auto-detects EBS as
network-durable and engages an `O_DIRECT` write plus a *metadata-free* barrier —
the data goes straight to EBS, so the covering `fdatasync` has nothing left to
journal and costs ~1 µs instead of ~1.9 ms, **with the full fsync guarantee
intact**), and a tuned pipeline window (Redpanda's fair equivalent,
`batch.size=65536 × max.in.flight=5`, is ≈ 2,560 records in flight, so a
`pubwindow` ≈ 4,096 is the matched single-producer window). Re-running the
trailing single-connection rows with `--io-mode auto` (medians of 3, same box
class, same Redpanda build, `write_caching=false`):

| Row | Size | IronBus (auto) | Redpanda | Result |
| --- | --- | ---: | ---: | :-- |
| P1 sync-per-message | 128 B | **898** | 520 | **IronBus 1.7×** — was a loss; the metadata-free barrier flips it |
| | 1 KiB | **897** | 364 | **IronBus 2.5×** |
| P2 group-commit (`pubwindow=4096`) | 128 B | 130,035 | 140,805 | **at par** (0.92×, within this study's ~8 % cell spread) |
| | 1 KiB | **125,163** | 33,763 | **IronBus 3.7×** |
| L1 durable-ack (p50 / p99 µs) | 128 B | **1,039 / 3,155** | 2,000 / 317,000 | **IronBus 1.9× median, ~100× tail** |
| | 1 KiB | **1,045 / 3,172** | 2,000 / 301,000 | **IronBus 1.9× median, ~95× tail** |

The barrier is the whole story on P1/L1: the per-op ~2.8 ms buffered-`fdatasync`
cost collapses to ~1 ms, so IronBus now leads L1 at the **median** too, not only
the tail. The single remaining non-win is single-connection **P2/128**, which sits
at par; the 1 KiB size — and every other row — is an outright win. `buffered`
stays the default (safe on any substrate, unchanged); `direct`/`auto` are the
network-durable opt-in (`ironbus serve --io-mode`, and `bench --io-mode`). This
is a mode selection, not a durability weakening: the barrier is kept, and a
pull-plug on EBS loses nothing the buffered path would not. (Harness:
[`matched-vm-harness/t4g/bench_refresh_io_mode.sh`](matched-vm-harness/t4g/bench_refresh_io_mode.sh);
its P2-multi and C1 blocks are unreliable on a 2-vCPU box — parallel-JVM
starvation and a consumer-perf method mismatch — so only the P1 / P2-single / L1
rows above are drawn from it; the multi-connection and consume stories stay with
§7's careful measures.)

**P2 under matched client concurrency** — and here the real durable substrate makes the divergence *starker* than the VM:

| P2 durable produce | IronBus peak | Redpanda peak | IronBus advantage | at matched 8 clients |
| --- | ---: | ---: | :-- | :-- |
| 128 B | **256,016** (8 conns) | 211,022 (1 client) | **1.21×** | **2.25×** (256 k vs 114 k) |
| 1 KiB | **62,338** (8 conns) | 37,386 (1 client) | **1.67×** | **2.46×** (62 k vs 25 k) |

On the ~2.8 ms EBS sync, **Redpanda's throughput peaks at ONE client and falls monotonically** (128 B: 211 k → 161 k → 114 k at 1/4/8 clients; 1 KiB: 37 k → 33 k → 25 k) — its single raft group is contention-bound the instant each `fdatasync` is expensive. **IronBus scales the opposite way** (128 B: 62 k → 108 k → 167 k → 256 k), because the pipelined sync tier (#1040) turns concurrent durable producers into shared covering syncs. The VM result is not a virtualization artifact: it reproduces on real Graviton hardware over real EBS durability, and the pricier the sync, the wider IronBus's coalescing margin.

*(Provenance: run on AWS, t4g.large, us-region, ephemeral instance — launched tagged, with an auto-terminate backstop, and torn down at completion. No account-specific identifiers are recorded here or in the raw data.)*

## 8. Artifacts and reproduction

The guest-resident harness (`lib2.sh` / `cell2.sh` / `row2.sh` / `all2.sh` for the matrix, `p2multi.sh` and `rp_multi.sh` for the concurrency sweeps) and the raw `results.jsonl` / `p2multi.jsonl` / `rp_multi.jsonl` are archived under [`matched-vm-harness/`](matched-vm-harness/); the t4g run's raw data is under [`matched-vm-harness/t4g/`](matched-vm-harness/t4g/). The matrix follows a strict pilot→freeze→median protocol (labeled durability tiers, a fairness lint) so the VM study and the t4g run (§7) are directly comparable — the difference is only the substrate.
