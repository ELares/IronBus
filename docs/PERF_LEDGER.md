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
