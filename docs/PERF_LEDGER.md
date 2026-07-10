# Performance ledger

This is the running record of deliberate performance rounds: one entry per round, each
carrying its hypothesis, its research basis, the expected gain, and the measured on-device
result once it lands. The ledger exists so a performance claim is never folklore: every
number is dated, sourced, and tied to the change that produced it, and a round that did NOT
pay off is recorded as honestly as one that did.

The SCOREBOARD is the NATS comparison matrix from the apples-to-apples baseline rig (see
[BASELINE_RIG.md](BASELINE_RIG.md) and `crates/ironbus-bench/src/comparison.rs`): IronBus is
measured against NATS JetStream at MATCHED durability labels on the reference edge device,
and a round's target is stated as a multiple of the matched NATS leg, never against an
unmatched (relaxed-durability) number.

## Baselines (reference edge device)

Measured 2026-06-11 on the reference hive (Raspberry Pi 4, SD card, 256 B payloads),
durable produce path (`fdatasync` per commit, ack-after-fsync):

| System | Leg | Durable acked msg/s |
|--------|-----|---------------------|
| IronBus | pub-only, one awaited ack per publish (window 1) | 203 |
| NATS JetStream | `sync_interval=always`, pipelined async publish | ~203 |

Both sides bottleneck on the same ~4.5 ms SD-card `fdatasync`. NATS pipelines its async
publish window but does NOT amortize the journal sync across it at `sync_interval=always`;
IronBus's append actor (#177, #49) ALREADY amortizes the sync across whatever is in its
queue, but a single connection never queues more than one produce because both the client
and the session await one ack per publish.

## Round 1: pipelined publish (the in-flight window meets the group commit)

- **Issue:** [#450](https://github.com/ELares/IronBus/issues/450)
- **Date opened:** 2026-06-11
- **Hypothesis:** letting ONE connection keep a window of W un-acked PUBs in flight lets the
  EXISTING group-commit batcher cover the whole window with one (worst case two) `fdatasync`
  instead of W, multiplying durable acked throughput by up to W at unchanged durability
  (I2, ack-after-fdatasync, is untouched: only WHEN the client awaits acks changes, never
  what an ack means). The wire format already permits this (ordered, self-describing acks,
  no correlation id), so the change is client + session behavior only.
- **Sources:** DeWitt et al. 1984, "Implementation Techniques for Main Memory Database
  Systems" (group commit: amortize the log force across concurrent commits); Apache
  BookKeeper's grouped journal sync (per the Confluent Kafka / Pulsar / RabbitMQ benchmark);
  Kafka producer batching (`linger.ms` / `batch.size`); NATS asynchronous publish window
  (`PublishAsync` / `PublishAsyncMaxPending`).
- **Expected gain:** >= 10x the NATS sync-always pipelined leg, i.e. >= 2,030 durable acked
  msg/s on the hive at window 64 (the ~4.5 ms fsync amortized over the in-flight window;
  even the worst-case two-commits-per-window split leaves >= 32x headroom over the target).
- **Status:** PENDING. The on-hive bench result lands here after merge
  (`ironbus bench --mode publish --pub-window 64` on the reference device).

### Measured (hive 1000000088e76a84, 2026-06-11, pre-merge cross-compiled PR head, 256B, publish mode, disk + full fsync)

| pubwindow | random | realistic |
| --- | --- | --- |
| 1 | 205/s (4.48ms/op fsync) | -- |
| 8 | 637/s | -- |
| 64 | 1,334/s | -- |
| 256 | 1,684/s | -- |
| 512 | 1,930/s | 1,643/s |
| 1024 | 1,749/s | 1,956/s |

Verdict: KEEP. 9.5x over the unpipelined baseline and over NATS sync-always pipelined (~203/s); the leg-2 target (>=2,030/s, 10x) is NOT yet met. The fsync is fully amortized (9ms/512 ~ 18us/op); the remaining ~450us/op floor is per-record server cost, NOT the client (coalescing the window into one client write() moved nothing) and NOT the wire/actor (the same window over --storage memory measures 4,882/s).

### Round 2 hypothesis (queued)

Batch the drained produce batch into ONE WAL write() per group commit (today Log::append issues one write per record): the memory-mode diagnostic bounds the non-storage floor at ~205us/op, predicting roughly 2,900-4,000/s durable at window 512 if the per-record write cost collapses. Sources: Kafka segment-batched appends; Redpanda's iobuf batch writes; the group-commit literature already cited.

## Round 2: batch the group-commit window into one WAL write (#452)

Date: 2026-06-11. Hypothesis: Log::append issued one synchronous write_all_at per record, so a
512-record group commit cost 512 pwrite syscalls plus one fdatasync; batching them into one
write per flush point should approach the 4,882 msg/s non-storage ceiling. Sources: Kafka
segment-batched appends, Redpanda iobuf batching, round 1's group-commit literature.

Implementation: the segment writer parks encoded records in a pending buffer and writes them
with ONE write_all_at at each flush point (sync before its fdatasync, the visible-head raise,
the seal, a 256 KiB spill cap). Sound by construction: readers are gated on flushed_offset,
which only advances at those same points. Every crash-recovery, corruption-corpus, conformance,
and determinism suite passes unchanged.

### Measured (hive, 256B, publish mode, disk + full fsync, pre-merge cross-compiled)

| pubwindow | round 1 | round 2 |
| --- | --- | --- |
| 1 | 205/s | 201/s |
| 64 | 1,334/s | 1,502/s |
| 512 | 1,930/s | 1,842-2,178/s across 5 runs (median ~1,951) |

Verdict: KEEP, honestly scoped. The hypothesis was WRONG about the ceiling: per-record page-cache
pwrites cost microseconds, not the ~300us/op gap, so the 512-window number is flat within noise.
The keep case: +13 percent at window 64, syscall hygiene (one write per flush point), and the
round exposed and fixed a real round-1 parse bug (--pubwindow swallowed the flag that followed
it). Diagnostics that bound round 3: the raw SD floor is 13ms per 150KB write+fdatasync (storage
is NOT the bound); compression-attempt overhead is noise at 256B; no hidden per-batch checkpoint
exists in the actor produce path. The unexplained ~270us/op disk-only cost remains.

### Round 3 hypothesis (queued)

Instrument the actual group-commit BATCH-SIZE distribution (the drain self-sizes to arrival rate
times fsync latency; if the steady-state drain is far below the client window, each window pays
several fsyncs). If confirmed, add a bounded group-commit gather delay or min-batch (the MySQL
binlog_group_commit_sync_delay precedent; PostgreSQL commit_delay) so a pipelined window commits
in one or two batches. Leg 2 stands at median ~1,951/s vs the 2,030 target (9.6x of NATS's 203).

## Round 3 (#454): the 4 KiB read chunk was the pipeline cap; 64 KiB chunk = 7,200-10,300/s durable

Sources: MySQL binlog_group_commit_sync_delay and PostgreSQL commit_delay (bounded group-commit
gather); DeWitt et al. 1984 (group commit); the round-2 ledger entry (batch-size hypothesis).

### Hypothesis and what the instrumentation actually showed

Hypothesis: the actor drain self-sizes to arrival rate x fsync latency, so a 512-record client
window commits in many small batches; a bounded gather window would merge them. The zero-code
measurement (delta ironbus_produced_total / delta fsync_duration_seconds_count on the hive)
confirmed tiny batches: mean 12-13 records per fsync against a 512 window, ~40 fsyncs per window.

The gather knob alone then DISPROVED the mechanism: with gather windows of 1/3/5/13 ms the batch
stayed at 13-15 and throughput fell monotonically (2,384 -> 645/s at 13 ms). The batch was not
arrival-sized; it was CAPPED. The session's pipelined window (#450) is pass-scoped, a pass sees
at most one connection-loop read chunk, and the chunk was a 4 KiB stack array: ~13 frames of
256 B realistic payloads, after which the session blocks awaiting its parked acks while the
actor waits out the gather. The two waits compound; nothing feeds.

### Fix shipped

1. Read chunk 4 KiB -> 64 KiB zero-page heap buffer (the actual win). A pass now carries
   hundreds of frames, so the pass-scoped window group-commits in a few fsyncs, not ~40.
   Untouched pages cost no RSS; idle/ping-only connections still touch about a page.
2. serve --commit-gather-us (validation-capped at 1 s) as the multi-producer lever: many
   connections each trickling singles can amortize one fsync. It only engages when a drain
   pass already holds >= 2 produces (a single-produce pass never gathers, so an unpipelined
   producer pays no window; the MySQL no-delay-count analogue). Originally shipped default-OFF
   (`0`); #472 changed the SHIPPED DEFAULT to a small conservative window (200 us,
   `DEFAULT_COMMIT_GATHER_US`) so out-of-the-box durable produce batches fsyncs under a
   concurrent publisher. `0` still restores the byte-identical historical actor.

### Measured (hive, 256B realistic, 15s runs, pre-merge cross-compiled, scratch broker)

| leg | round 2 | round 3 (64 KiB chunk) |
| --- | --- | --- |
| disk w=1 | 201/s | 198/s (fsync physics, unchanged) |
| disk w=64 | 1,502/s | 5,215/s |
| disk w=512 | ~1,951/s | 7,193/s (batch 90 rec/fsync) |
| disk w=1024 | 1,956/s | 9,197-10,294/s (batch 104) |
| memory w=1 | 980/s | 1,364/s |
| memory w=512 | 4,882/s | 8,023/s |
| memory w=1024 | -- | 11,171/s |

Gather on a single pipelined connection now HURTS (6,839 vs 7,193 at w=512): default 0 stays.
Guardrails: binary 1.53 MB (<= 3 MB), peak RSS under w=1024 load 2.1 MB (<= 8 MB), ack-after-
fdatasync default untouched, all suites green.

Verdict: KEEP. Win-condition leg 2 (durable pipelined >= 2,030/s = 10x NATS sync-always) is
cleared at 35-50x (7,193-10,294 vs 203). Leg 1 holds (198-205 vs NATS 191-203). Legs 3 and 4
(memory per-ack >= 2,491; memory pipelined >= 27,250) remain open: both are now CPU-floor bound
(~125 us/op at w=512), not batching bound.

### Round 4 hypothesis (queued)

Profile the per-op CPU floor on the wire/session/engine path (memory w=1 is 733 us round-trip;
NATS does 401 us). Candidates: per-record allocations in decode/dispatch (arena or reuse), the
per-frame reply flush (vectored writes), checkpoint cadence in the hot loop. Target: memory
w=1 >= 2,491/s (leg 3) and memory pipelined toward 27,250/s (leg 4).

## Round 4 (#456): InMemoryFile::sync_data cloned the whole segment per commit; dirty ranges = leg 3 cleared

Sources: the round-3 ledger entry (CPU-floor hypothesis); LMAX Disruptor (Thompson et al. 2011,
mechanical sympathy: the hot path should never copy what it does not have to); the incremental
checkpoint/shadow-paging tradition (copy only what changed since the last barrier).

### What the profile showed

Round 3 left legs 3 and 4 "CPU-floor bound". A symbolized macOS `sample` of the broker under a
memory-mode w=512 publish run located the floor precisely: 82 percent of the append-actor
thread was `actor::flush_pending -> Log::sync -> SegmentWriter::sync -> Vec::clone_from ->
memmove`. `InMemoryFile::sync_data` maintained the power-loss-simulation durable image by
CLONING THE ENTIRE LIVE FILE on every sync: every group commit memcpy'd the whole accumulated
segment (64 MiB profile segments), and window-1 publishing re-copied everything per MESSAGE
(quadratic in segment fill). Strace corroborated: mmap/munmap churn from the repeated large
clones. The hive's earlier "memory barely beats disk" oddity (8,023 vs 7,193) was this copy.

Also measured and parked for later rounds: clock_gettime64 is a REAL syscall on the 32-bit ARM
musl static build (~3/msg pipelined, 6/msg at w=1; no time64 vDSO) ~ a few us/op; futex 4/msg at
w=1 from the per-produce sync_channel rendezvous; TCP_NODELAY is never set. All second-order
next to the clone.

### Fix shipped

`State` tracks the byte ranges written since the last sync (sorted, disjoint, coalesced; the
append pattern is the O(1) fast path). `sync_data` copies only those ranges into the durable
image and clears the list. Byte-for-byte identical durable semantics: zero-fill growth gaps are
dirty, an unsynced truncation clamps ranges while the durable image keeps its longer tail until
`sync_all`, and both power-loss models clear the list when they rewrite the live image. The
determinism, crash-recovery, torn-write, and power-loss suites pass unchanged, plus a focused
equivalence test walks the tricky interleavings against the old clone-everything image.

### Measured (hive, 256B realistic, 15s runs, pre-merge cross-compiled, scratch broker)

| leg | round 3 | round 4 (dirty ranges) |
| --- | --- | --- |
| memory w=1 | 1,364/s | 7,045/s (5.2x; the quadratic clone is gone) |
| memory w=512 | 8,023/s | 9,012/s |
| memory w=1024 | 11,171/s | 16,461-16,753/s |
| disk w=512 | 7,193/s | 6,791/s (run noise; disk never cloned) |
| disk w=1024 | 9,197-10,294/s | 9,346/s |

Guardrails: binary 1.54 MB (<= 3 MB); bounded-cap memory RSS 6.2 MB peak under w=1024 load with
a 2 MiB store cap (the #443 model, <= 8 MB); the big-cap RSS scales with STORED MESSAGES by
memory-mode design (45 MB at a 512 MiB cap, the queue itself, not overhead).

Verdict: KEEP. Win-condition leg 3 (memory per-ack >= 2,491 = NATS memory sync) CLEARED at
7,045 = 2.8x NATS. Standing: leg 1 held (198-205 vs 191-203), leg 2 cleared (46x), leg 3
cleared (2.8x), leg 5 cleared (two legs led by >= 2x). OPEN: leg 4 only (memory pipelined
16,461 vs 27,250 = 60 percent).

### Round 5 hypothesis (queued)

Leg 4 is now genuinely wire/session/engine CPU. Candidates in measured order: per-record
allocations on the produce path (OwnedAppend payload Vec + per-produce reply sync_channel:
reuse/arena them), the parked-ack reply encode path, clock_gettime64 batching (stamp once per
drain batch), TCP_NODELAY + vectored reply writes. Re-profile AFTER the clone is gone; the 82
percent memmove was masking everything downstream.

## Round 5 (#458): the half-duplex window was the leg-4 gap; full-duplex produce_stream = 92.8k/s, ALL FIVE LEGS CLEARED

Sources: the NATS bench tool's async JetStream publisher (the leg-4 baseline itself: a writer
that never stops for acks); classic sliding-window pipelining (TCP, HTTP/2 streams); the round-4
ledger's queued candidates (all parked: see below).

### What the measurement showed

Per-thread CPU on the hive during a memory w=1024 publish run at 16.2k msg/s: append-actor 25.4
percent of one core, session 20.5, bench client 16.1, on a 4-core box. NOTHING saturated; the
same code does 1.02M msg/s on an M-series laptop. Leg 4 was not CPU and not the engine: it was
SYNCHRONIZATION BUBBLES. Client::produce_window writes a window then blocks draining all W acks
(feeding nothing); the session's pass-scoped parked-ack drain serializes read -> actor round
trip -> write. The two half-duplex loops interlock so every stage idles most of the time. The
NATS async baseline never had this handicap. (Also measured and parked again as second-order:
broker-side lz4 ~5 percent at this shape; clock_gettime64 syscalls; per-produce futex pair;
TCP_NODELAY unset.)

### Fix shipped

Client::produce_stream(messages, window) (#458): FULL-DUPLEX sliding window. The caller's
thread keeps encoding and writing coalesced PUB batches (32 KiB flush budget, never more than
`window` unacked) while a scoped reader thread drains the FIFO acks concurrently from a
try_clone'd read half; termination rides the wire's frame-order guarantee (a trailing Ping
whose Pong proves every prior reply was consumed). Server Err replies COUNT in the returned
tally instead of failing the call (the stream has fully drained by then; a drop-new shed no
longer discards the run's counts). The reply classifier is shared with produce_window so the
two paths cannot drift. `bench --stream` (requires --pubwindow >= 2) drives it. NO broker, wire,
or engine changes: the server side already handled a saturated socket; no client could present
one until now.

### Measured (hive, 256B realistic, 15s runs, pre-merge cross-compiled, scratch broker)

| leg | half-duplex window | full-duplex --stream |
| --- | --- | --- |
| memory w=512 | 9,012/s | 87,368/s |
| memory w=1024 | 16,165/s | 92,801-93,097/s |
| memory w=4096 | -- | 88,877/s (saturates ~90k) |
| disk w=1024 (full fsync) | 9,346/s | 16,172/s |

NATS fairness rerun SAME DAY, same box, matched batch 1024: JS memory async 28,337/s (28,337 vs
yesterday's 27,250: consistent); JS memory sync 2,555/s. IronBus memory stream = 3.3x NATS
async. Guardrails: binary 1.55 MB; bounded-cap RSS 6.1 MB peak under stream load at a 2 MiB
store cap, with drop-new shedding exercised end to end (the bench reports acked-only goodput).

### Win condition: ALL FIVE LEGS CLEARED

1. Durable single-ack within 10 percent of NATS: 198-205 vs 191-203 (fsync physics parity).
2. Durable pipelined >= 10x NATS sync-always (2,030): 16,172 = 80x.
3. Memory per-ack >= NATS (2,491): 7,045 = 2.8x.
4. Memory pipelined >= NATS (27,250; rerun 28,337): 92,801 = 3.3x.
5. At least 2 legs led by >= 2x: legs 2 (80x), 3 (2.8x), 4 (3.3x).

Verdict: KEEP. The goal's standing follow-ups: a final full NATS matrix rerun is recorded above
for the contested legs; the consume-side legs (NATS ordered consume 43,877/s) were never part
of the win condition and remain the natural next frontier, along with the parked second-order
CPU items (clocks, futex pairs, NODELAY) if a future round needs them.

---

# Consume scoreboard: single-consumer durable consume vs NATS (#554, V2-M1)

The produce scoreboard above closed the PRODUCE axis. This is the CONSUME axis — the V2-M1
headline: that the streaming-tier consume rearchitecture (Tier-S #655, tier negotiation #656, #661
`DeliverBatch`, #662 the batched-fetch + bounded-read-ahead + periodic-cumulative-commit client
default) makes a single durable consumer beat a NATS JetStream durable PULL consumer, the axis on
which the old per-message-lease work-queue consume LOST to NATS by ~3-20x. Driven by
`docs/benchmarks/consume_bench.py` and assembled by `cargo run -p ironbus-bench --bin
consume-corpus` (the consume-side twin of the produce `assemble-corpus`, same durability-label
fairness lint). The legs:

- **IronBus Tier-S streaming** (`bench --mode subscribe --consume-tier streaming`): the merged
  streaming consumer — a windowed `StreamFetch` with bounded read-ahead and a periodic cumulative
  `StreamCommit` (the #662 default), durable file-backed, cursor persisted.
- **NATS JetStream durable PULL** (`nats bench <subj> --js --sub 1 --pull --consumerbatch 256`): one
  durable pull consumer, explicit batched ack against a file-backed stream. The matched durable peer.
- Context (appendix, NOT a durable head-to-head): **IronBus Tier-W work-queue** (the
  per-message-lease path IronBus used to lose on) and **NATS CORE sub** (`nats bench <subj> --pub 1
  --sub 1`, no JetStream — non-durable at-most-once live delivery, a reference ceiling).

Matched durability label `durable-consume` on the head-to-head pair (both persist a consume cursor;
a crash redelivers only the uncommitted span); the non-durable core sub carries `at-most-once`, so
the lint can never force-pair it against a durable consumer. The label match is the CI gate
(`consume_corpus.rs` unit tests + `comparison.rs`), exactly as the produce legs are gated.

## The rig

AWS Graviton2 `t4g.large` (2× Cortex-A72-class, 8 GiB), Ubuntu 24.04 aarch64, `us-west-2` dev,
all loopback; `nats-server` v2.10.22, `natscli` 0.1.6; IronBus release `aarch64` built on-box.
Each broker runs on a scratch dir/port and is stopped after (the EC2 instance was STOPPED at the
end of the run). The numbers below are the post-#665 RE-VALIDATION run (2026-06-19, `origin/main`
HEAD `18f131b` with the #665 O(N²) read-span fix), replacing the earlier pre-#665 figures that
showed the prefix-bounded crossover; the methodology, rig, and durability labels are identical, so
the before/after delta is the fix. Both durable sides drain a pre-filled durable prefix with a
256-record consumer window (`--fetch-batch 256` / `StreamConsumerConfig.max_records 256` /
`--consumerbatch 256`), so the TIER, not the window, is what differs. The IronBus pre-fill is
`--no-fsync` (page-cache): the DRAIN rate is the metric and is write-durability-independent, exactly
as the produce corpus's consume row. NOTE on rig discipline: this is a single-run, 2-core box; the
[EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md) cpuset-pinning / steady-state-CoV / thermal
instrumentation is NOT yet wired into this harness (the same documented residual the produce
ledger ran under), so these are directional single-rig numbers, not ratified edge SLO numbers. The
2-core box means broker and harness contend; the absolute IronBus numbers would rise with the
broker pinned to its own core — but the head-to-head holds the contention equal on both sides.

## The headline (the committed corpus point, 20k records): IronBus Tier-S WINS at both sizes

`docs/benchmarks/consume-rows.jsonl`, the lint-validated head-to-head the `consume-corpus`
assembler pairs at the matched 20,000-record prefill (the realistic small/moderate prefill a real
edge consumer keeps caught-up against). Re-validated post-#665 (the O(N²) drain fix, see the sweep
below):

| payload | IronBus Tier-S streaming | NATS JS pull | IronBus / NATS |
| --- | --- | --- | --- |
| 256 B | 700,855 /s | 106,448 /s | **6.58x (IronBus wins)** |
| 4096 B | 195,892 /s | 54,780 /s | **3.58x (IronBus wins)** |

Both clear the #554 single-consumer criterion (Tier-S ≥1.25x NATS pull) by a wide margin — 6.58x at
256 B, 3.58x at 4096 B. These numbers are an order of magnitude above the pre-#665 figures (the old
ledger recorded 114,984 /s at 256 B and 81,410 /s at 4096 B at this same point): #665 removed the
super-linear read-span cost, so the streaming-tier consume drain now runs at its true page-cache
rate even at this small prefill.

## The full prefix sweep: FLAT after #665 (the win is now UNCONDITIONAL)

256 B, IronBus Tier-S streaming vs NATS JS pull, record-count sweep
(`docs/benchmarks/consume-sweep.jsonl`, the full curve, not one cherry-picked point), re-run on the
same t4g rig at `origin/main` (HEAD `18f131b`, includes the #665 O(N²) fix):

| pre-filled records | IronBus Tier-S streaming | NATS JS pull | IronBus / NATS |
| --- | --- | --- | --- |
| 20,000 | 681,628 /s | 104,045 /s | **6.55x (IronBus wins)** |
| 50,000 | 638,559 /s | 102,701 /s | **6.22x (IronBus wins)** |
| 100,000 | 889,251 /s | 104,551 /s | **8.51x (IronBus wins)** |
| 200,000 | 904,131 /s | 109,322 /s | **8.27x (IronBus wins)** |

The read, stated honestly: **IronBus Tier-S now beats NATS JS pull at EVERY point of the 20k → 200k
sweep (6.2x – 8.5x), and the IronBus curve is FLAT-to-rising (~640k – 904k /s) rather than
collapsing.** This is the post-#665 re-validation of the #554 finding. The prior (pre-#665) sweep
on this rig degraded super-linearly — 148k → 84k → 46k → 23k across 20k → 200k, crossing UNDER NATS
near ~30k records and losing 0.22x at 200k — because the server's `StreamFetch(start_offset, …)`
allocated and read the entire `[anchor, segment_end)` span on each forward fetch (an O(distance-to-
end) read ⇒ ~O(N²) over the whole drain). #665 clamps the read span to the consumer WINDOW (the
first sparse anchor strictly above `start + want_records`), so each fetch buffers `O(window +
stride)` bytes regardless of how deep into the segment the cursor is. With the span bounded, the
drain is flat in `start`, and the prefix-length dependence that made the win conditional is gone.
NATS JS pull is flat ~104k – 109k /s across the same sweep, as before — the cross-over with NATS is
no longer reached at any prefill in range, so the small/moderate-prefill caveat the old ledger
carried no longer applies. (The growing p99 — ~1.0 s at 20k to ~10.8 s at 200k — is the
preloaded-drain queue-wait, i.e. records sat in the prefix before the timed drain began, NOT a
per-record service latency; it is reported but is not the throughput signal, and it grows linearly
with N as expected for a fixed-rate drain of a larger backlog.)

## Context (appendix, not a durable head-to-head)

20,000 records: IronBus Tier-W work-queue **9,776 /s** (256 B) / **9,178 /s** (4096 B) — the
per-message-lease drain the V2-M1 rearchitecture replaced; Tier-S at the SAME workload is **~72x**
(256 B: 700,855 vs 9,776) and **~21x** (4096 B) the work-queue, the in-family streaming win. NATS
CORE sub **685,770 /s** (256 B) / **131,845 /s** (4096 B): non-durable, no JetStream, no replay — a
different durability tier, a reference ceiling, never paired against a durable consumer. Notably,
post-#665 the durable Tier-S streaming drain at 256 B (700,855 /s) now sits at parity with the
NON-durable NATS core-sub ceiling (685,770 /s): the durable streaming consume path is no longer
read-span-bound, so its throughput is set by the same page-cache/loopback ceiling as a non-durable
live delivery.

## Verdict (honest): UNCONDITIONAL after #665

The V2-M1 headline now holds UNIVERSALLY across the measured prefix range, not just at the
small/moderate prefill. The prefix-bounded caveat the prior ledger carried is RESOLVED by #665:

- **WON, #554 single-consumer criterion (Tier-S ≥1.25x NATS pull), at EVERY prefill:** 6.55x (20k),
  6.22x (50k), 8.51x (100k), 8.27x (200k) at 256 B, and 6.58x / 3.58x at the matched 20k corpus
  point (256 B / 4096 B). The IronBus Tier-S curve is FLAT-to-rising (~640k – 904k /s) across
  20k → 200k instead of collapsing, and NATS JS pull stays flat ~104k – 109k /s. There is no longer
  a cross-over with NATS at any prefill in range.
- **The prefix dependence is GONE (#665):** the prior super-linear degradation (148k → 23k across
  20k → 200k, 0.22x vs NATS at 200k) was the server `StreamFetch(start, …)` allocating and reading
  the whole `[anchor, segment_end)` span per fetch (O(distance-to-end) ⇒ ~O(N²) over the drain).
  #665 clamps the read span to the consumer window (the first sparse anchor above
  `start + want_records`), so each fetch buffers `O(window + stride)` bytes and the drain is flat in
  `start`. The locate stays the existing O(log) binary search; no on-disk format, write, or recovery
  change. This is the lever the prior ledger named as "remaining" — it has landed.
- **Downstream levers now compound on a flat base:** the `#552` consumer-credit auto-tune (merged)
  and a `#658` `sendfile` zero-copy read are no longer gated behind the O(N²) read-span cost, so
  they raise the flat ceiling rather than fighting a super-linear floor.

The multi-consumer aggregate criterion (≥1.5x at M≥4) and the Tier-W-batched-≥10x-baseline
criterion from #554 are separate legs not measured in this single-consumer round; they are the
natural next consume frontier now that the single-consumer streaming-consume win is unconditional.

---

# Durable produce + consume scoreboard vs NATS JetStream AND Core at matched durability (#646, V2-M12)

First principles, stated before any number: "beats NATS" is only credible at EQUAL durability. A
leg is scored as a head-to-head win or loss ONLY when both sides give the same guarantee on the
same box under the same workload; every leg where the guarantees differ is context, carries its
asymmetry explicitly, and is never paired. The matched-durability legs are the load-bearing
comparison and a CI gate (below). The produce scoreboard (rounds 1-5 above, the Pi rig) and the
#554 consume scoreboard pinned single axes; this section is the consolidated durable
produce + consume matrix from the 2026-07 t4g round
([#606](https://github.com/ELares/IronBus/issues/606) rounds 1+2,
[#1100](https://github.com/ELares/IronBus/issues/1100)) — the same measurements published in
[BENCHMARKS.md](BENCHMARKS.md).

## The rig

AWS t4g.large (2 vCPU Graviton2), Ubuntu 24.04 arm64, single-host loopback, 256 B payloads;
`ironbus` release 2607.109.15 (round 1) / 2607.110.11 (round 2) vs `nats-server` 2.14.3 driven by
natscli 0.4.0; one warmed named group per broker, fresh broker per scenario; two runs per round-2
configuration. Raw artifacts retained privately by the maintainer (not committed). The
machine-readable form of this scoreboard is
[benchmarks/durable-scoreboard-rows.jsonl](benchmarks/durable-scoreboard-rows.jsonl). Ranges are
recorded as measured; where a single number is needed the CONSERVATIVE endpoint is used (IronBus
low end vs peer high end), so every stated ratio is a floor, not a flatter.

## Matched-durability legs (the load-bearing head-to-head)

| leg | the matched guarantee (both sides) | IronBus | NATS | score |
| --- | --- | --- | --- | --- |
| Durable consume | file/disk-backed stream, explicit acks / committed cursor: a crash redelivers only the uncommitted span | **333k msg/s** (disk, streaming consumer) | JetStream 97-98k msg/s (file storage, explicit acks) | **IronBus 3.4x** |
| Non-durable delivery | live delivery of every message; NATS Core has no persistence, so this is its matching tier | **716-735k msg/s** (memory mode, ACKED, replayable log) | Core 667-681k msg/s (unacked) | **IronBus wins while acking every message** |

The durable consume leg is THE scoreboard row: both sides at the strongest common consume
guarantee, IronBus leading 3.4x (333k over the 98k conservative endpoint). The non-durable
delivery leg is matched at NATS Core's own tier, and IronBus still leads while doing strictly
more work per message (an ack, plus a replayable log).

## Guarantee-asymmetric legs (context: never paired, scored honestly)

The publish-side legs CANNOT be scored head-to-head, and this is exactly what the CI gate refuses
to pair:

| leg | IronBus | NATS | the asymmetry (why this is NOT a matched pair) |
| --- | --- | --- | --- |
| Sync publish (one awaited ack per publish) | 844/s, ack fsync-backed (1.03 ms) | JetStream sync publish 6.3-6.4k/s, ack in 154 us, NOT fsynced | An acked IronBus record has survived a power cut; an acked JetStream record has not necessarily. The ~7.5x NATS rate buys a strictly weaker ack. |
| Windowed / async durable publish | 54.6k/s (group commit; every ack still fsync-backed) | JetStream async 90-91k/s (acks not fsynced) | NATS wins ~1.7x on the UNMATCHED comparison — recorded as the honest loss it is, with the guarantee gap stated. Held to IronBus's actual guarantee (sync-always), the produce scoreboard above measured JetStream at the fsync floor (~203/s-class on the Pi rig). |
| Raw ingest | 251-254k/s, every message acked (memory mode) | Core 1.64-1.75M/s fire-and-forget | ~6.7x for NATS at a different guarantee entirely: a fire-and-forget socket write with no ack, no retention, no delivery. |

Round-2 context on the same rig, recorded in the [BENCHMARKS.md](BENCHMARKS.md) tables:
subject-filtered consume costs IronBus ~1x vs JetStream's measured ~7x re-scan penalty, and
1 -> 10,000-subject publish costs IronBus -10.9% vs NATS Core's ~35% degradation.

## Caveats (part of the result)

- Single host, loopback: no real network, no cross-AZ, no packet loss.
- t4g.large is BURSTABLE: read every number as p50/p99-grade and directional at the tails
  (intermittent ~100 ms host stalls were observed and documented in #1100); a dedicated or metal
  box is needed for publishable p999 claims.
- 256 B payloads only; per-byte costs shift the picture at larger sizes (see
  [benchmarks/README.md](benchmarks/README.md)).
- The sync-publish rates (844/s vs 6.3-6.4k) are the awaited-publish rates behind the recorded
  1.03 ms vs 154 us acks (#606 round-1 raw runs); they are round-trip-bound numbers, coherent
  with those ack latencies (1/1.03 ms is a ~970/s ceiling, 1/154 us a ~6.5k/s ceiling).

## The CI gate (#646)

The gate holds the PRINCIPLE, not a benchmark run: a live NATS-vs-IronBus comparison on a shared
CI runner is exactly the flaky percent gate the #114 design notes warn trains people to ignore
gates. Three layers, all deterministic:

1. **Matched-durability fairness + drift gate (per-PR, new with this section):**
   [benchmarks/durable-scoreboard-rows.jsonl](benchmarks/durable-scoreboard-rows.jsonl) is the
   machine-readable scoreboard, and `scripts/ci/durable-scoreboard-check.sh` (wired into ci.yml)
   fails the PR if a head-to-head pair ever carries mismatched durability labels, if an
   asymmetric row loses its asymmetry note, if the load-bearing durable-consume pair is dropped,
   or if the numbers here and in the rows drift apart. Offline, history-free, jq-only — the same
   discipline as the #554 consume-corpus fairness gate and the #359 SLO drift gate.
2. **Absolute regression protection (existing):** IronBus's own durable produce/consume rates are
   gated by the #114 rolling-median regression gate against the release-archived baseline, fed by
   the #111 macro-bench device residual. That is where "our durable legs must not regress"
   lives; this scoreboard adds the comparative fairness layer on top of it.
3. **The comparative re-run is MANUAL by design:**
   [../scripts/bench/nats-scoreboard.sh](../scripts/bench/nats-scoreboard.sh) reproduces every
   leg above (both brokers, the recorded flags, natscli-0.4.0-verified) on a quiet box. Run it
   after any change that could move a scoreboard row, then update the rows and this section
   together — the drift gate makes updating one without the other fail.
