# Prior art: the mechanism-level take/leave survey

This document is the comparative prior-art survey for IronBus: for every system
that already solved a piece of the durable-edge-queue problem, the one or two
mechanisms IronBus TAKES (borrows) and the one thing it LEAVES (explicitly
rejects), each with a mechanism-level reason tied to a tenet or a concrete edge
failure mode. It is the evidence base [#2](https://github.com/ELares/IronBus/issues/2)
asks for, formalizing the draft comparison in that issue, and it adds the
embeddable single-node tier [#27](https://github.com/ELares/IronBus/issues/27)
asks for.

It is DESIGN (docs) only. It introduces no flag and changes no source. It is
DESCRIPTIVE about other systems; the PRESCRIPTIVE IronBus decisions live in the
merged design docs it cites and are never re-derived here.

## How to read this document, and how it relates to the other prior-art docs

There are two tiers, kept visually separate:

1. [The network-broker tier](#tier-1-the-network-broker-tier-2) (#2): the eight
   systems in the parent issue title, MQTT, NATS JetStream, Kafka, Pulsar,
   Redpanda, RocksDB, Redis Streams, SQS.
2. [The embeddable single-node tier](#tier-2-the-embeddable-single-node-tier-27)
   (#27): Chronicle Queue, SQLite WAL mode, LMDB and bbolt/etcd-on-bolt, plus an
   explicit [mmap-durability-hazards note](#23-the-mmap-durability-hazards-note).

This doc COMPLEMENTS, and does not duplicate, two already-merged pieces:

- [PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md) already settled (a)
  the single edge IO stance (page cache for reads and write-coalescing PLUS a
  forced group-committed `fdatasync` boundary, with Redpanda-style no-page-cache
  direct-DMA explicitly rejected for the edge, #28), and (b) the open
  per-feature prior-art GAPS where no surveyed system gives a usable answer (the
  poison-skip-with-bounded-reported-loss, the recovery loss report, and the
  producer spill/shed, #29). This survey does NOT re-derive either. Where a
  "leave" below turns on the IO stance or a novel-feature gap, it CROSS-LINKS
  that doc rather than restating it.
- [BASELINE_RIG.md](BASELINE_RIG.md) is the measurement rig that keeps
  cluster-class Kafka/Redpanda in an appendix labeled `not an edge-class
  comparison`; this survey takes their MECHANISMS but agrees with that doc that
  they are not edge-class peers.

Every load-bearing NUMERIC or version-specific claim below carries a `[id]` tag
that names an entry in
[`prior-art/claims.yaml`](prior-art/claims.yaml), the VERSION-PINNED SOURCE OF
RECORD ([#26](https://github.com/ELares/IronBus/issues/26)). See
[The claims contract](#the-claims-contract-26) at the end for the agree-with-the-yaml
rule and the CI check. Claims flagged `confidence: low` in the yaml are also
called out inline here with `(low-confidence)` so a reviewer re-verifies them
first.

The IronBus tenets the "take" / "leave" decisions appeal to are, in priority
order: **Resilient > Simple > Edge First > HyperScale > Cross Platform**
(see [README.md](../README.md), "The five tenets"). The recurring edge failure
modes a "leave" is justified by are: correlated POWER LOSS on a battery-less
shared-power node, FLASH WEAR on eMMC/SD, bounded RAM, a COORDINATION dependency
that assumes datacenter hardware, and a SINGLE-WRITER stall.

---

## Tier 1: the network-broker tier (#2)

### 1.1 The comparison table

Numbers carry a bracketed claim id (for example `[kafka-acks-default]`) into
[`prior-art/claims.yaml`](prior-art/claims.yaml).

| System | Storage model | Durability knob (and default) | Delivery semantics | Consumer model | Backpressure |
| --- | --- | --- | --- | --- | --- |
| MQTT 5 | Broker session state (not a replayable log) | per-message QoS 0/1/2 `[mqtt-qos-levels]` | at-most / at-least / exactly-once per message | shared subscriptions (`$share`) | Receive Maximum credit window `[mqtt-receive-maximum]` |
| NATS JetStream | append-only `<n>.blk` blocks + index `[nats-filestore-block-sizes]` (low-confidence) | FileStore + explicit acks; `AckWait` 30s `[nats-ackwait-default]` | at-least-once, double-ack | pull batch/expires, explicit ack vocabulary `[nats-ack-vocabulary]` | `MaxAckPending` 1000 `[nats-maxackpending-default]` + pull credit |
| Kafka | segmented commit log + sparse `.index`/`.timeindex` `[kafka-index-entry-format]` | replication; `log.flush.interval.messages` = Long.MAX `[kafka-flush-interval-messages-default]`, `acks=all` `[kafka-acks-default]` but fsync-decoupled | at-least / exactly-once (idempotent producer) | offset per consumer group | producer buffer block/fail |
| Pulsar | immutable ledgers on BookKeeper, `E >= Qw >= Qa` `[pulsar-quorum-inequality]` | `journalSyncData=true` (Qa journal fsync) `[pulsar-journal-sync-data-default]` | 4 subscription types `[pulsar-subscription-types]` | durable cursors in storage | per-consumer |
| Redpanda | per-partition Raft log, no page cache (direct DMA) `[redpanda-raft-quorum]` | fsync-batched; opt-in write caching ack-before-fsync `[redpanda-write-caching]` | at-least / exactly-once (Kafka-compatible) | Kafka-compatible offsets | per-partition |
| RocksDB | LSM: WAL `[rocksdb-wal-block-format]` + SST, leveled compaction | `WriteOptions.sync` default false `[rocksdb-write-sync-default]`; group commit | N/A (key-value store) | N/A | group commit |
| Redis Streams | radix-tree macro-nodes, `<ms>-<seq>` IDs `[redis-stream-id-format]` | AOF `appendfsync everysec` `[redis-appendfsync-default]` (also `always` / `no`) | at-least-once | consumer groups + PEL `[redis-pel-mechanism]` | none native |
| SQS | managed, multi-AZ | managed | at-least-once / FIFO exactly-once | visibility-timeout lease + explicit delete `[sqs-visibility-timeout-default]` | in-flight cap, long poll |

### 1.2 Per-system take / leave

#### MQTT 5 (Mosquitto)

- **Mechanism.** Tiered per-message QoS 0/1/2 with effective QoS = min(publisher,
  subscriber), a 4-step PUBREC/PUBREL/PUBCOMP exactly-once handshake at QoS 2,
  and Receive Maximum credit-based flow control (a hard cap on unacked QoS 1/2
  PUBLISH packets in flight, DISCONNECT reason `0x93` on violation) `[mqtt-qos-levels]`
  `[mqtt-receive-maximum]`. QoS 0 is exempt from the credit window.
- **TAKE: the credit window and per-message reliability tiers.** IronBus borrows
  the credit-based flow-control SHAPE (a bounded number of in-flight messages the
  consumer must drain) and the idea that a fast fire-and-forget path can coexist
  with a reliable acked path. IronBus's wire credit is the FLOW frame
  (`consumer_credit` default 64 messages or 8 MiB; see
  [FLOW_CONTROL.md](FLOW_CONTROL.md)), and its fire-and-forget tier is the
  optional producer fast path (README, "What IronBus is").
- **LEAVE: QoS 0 exempt from flow control, and a protocol-not-a-log.** IronBus
  rejects an UNCREDITED tier that can flood a small device (the fire-and-forget
  path still funnels every shed through the drop-new/drop-oldest disposition and
  a counter, never an unbounded firehose; see [BACKPRESSURE.md](BACKPRESSURE.md)).
  More fundamentally, MQTT is a routing PROTOCOL over broker session state, not a
  durable replayable LOG, so it cannot offer offset replay or
  longest-valid-prefix recovery (README, "MQTT is edge-friendly and simple, but
  it is a protocol, not a durable, replayable log"). Edge failure mode: a flood
  on an uncredited tier exhausts bounded RAM; a non-log broker cannot recover a
  consistent prefix after power loss.

#### NATS JetStream

- **Mechanism.** A tiny line-oriented Core protocol (CRLF framing with explicit
  byte-count headers) plus JetStream durability: append-only `<n>.blk` blocks
  `[nats-filestore-block-sizes]` (low-confidence), explicit acks with an
  `AckWait` 30s redelivery timer `[nats-ackwait-default]`, a four-reply ack
  vocabulary (`+ACK` / `-NAK` / in-progress / `+TERM`) `[nats-ack-vocabulary]`,
  and `MaxAckPending` 1000 `[nats-maxackpending-default]` as the central
  pull-consumer backpressure lever.
- **TAKE: the framed protocol, the ack vocabulary, and pull-batch credit.**
  IronBus borrows the small length-framed binary protocol (README, "a tiny
  length-framed binary wire protocol"), the rich ack vocabulary (its
  `AckStatus` frame distinguishes fenced / committed-requeued-extended / progress
  cap, the analog of NAK / in-progress / term; see the CHANGELOG #179 entry and
  [FLOW_CONTROL.md](FLOW_CONTROL.md)), and pull-batch credit as natural
  one-to-one flow control.
- **LEAVE: `MaxDeliver=-1` poison loops and the time-only dedup window.**
  IronBus rejects an unbounded redelivery default that loops a poison message
  forever `[nats-maxdeliver-poison]`: it caps redelivery at a default max-deliver
  of 5 then routes to a DLQ (README, "Key decisions"). It also rejects a
  TIME-ONLY dedup window `[nats-dedup-window-default]` as the only protection,
  because a 2-minute window stops protecting an edge device that was offline for
  hours; IronBus's opt-in dedup is bounded by BOTH a count and a time window and
  can persist a producer-id high-watermark to survive an arbitrarily long offline
  gap (README, "Dedup"; CHANGELOG #33). Edge failure mode: a poison loop wastes a
  scarce ARM core forever; a too-short dedup window readmits duplicates after a
  long brownout.

#### Kafka

- **Mechanism.** Each partition is an append-only commit log of monotonic-offset
  records in 1 GiB segment files (`log.segment.bytes` `[kafka-segment-bytes-default]`)
  with a sparse `.index` (8-byte entries) and `.timeindex` (12-byte entries), one
  entry per `log.index.interval.bytes` (default 4096) `[kafka-index-entry-format]`
  `[kafka-log-index-interval-bytes-default]`. It leans on the OS page cache and
  `sendfile` zero-copy, batches on the producer (`batch.size` 16384 `[kafka-batch-size-default]`,
  `linger.ms` 5 `[kafka-linger-ms-default]`), and DECOUPLES durability from the
  write path: `log.flush.interval.messages` defaults to Long.MAX
  `[kafka-flush-interval-messages-default]`, with `acks=all` `[kafka-acks-default]`
  but `min.insync.replicas` defaulting to 1 `[kafka-min-insync-replicas-default]`,
  so durability comes from ISR replication, not fsync. Recovery uses checkpoint
  files (recovery-point,
  high-watermark, leader-epoch).
- **TAKE: monotonic offsets, append-only segments, the derived sparse index,
  page-cache reliance, and recovery checkpoints.** This is IronBus's core
  storage shape: monotonic u64 offsets, immutable sealed segments, a DERIVED
  rebuildable offset index, and reads served through the OS page cache for
  warm-cache-on-restart (ADR-0001, [README.md](../README.md);
  [PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md) section 1 is the
  authority for the page-cache half of this).
- **LEAVE: fsync-off-by-default durability and replication-as-the-contract on
  shared power.** IronBus rejects Kafka's flush-off default `[kafka-flush-interval-messages-default]`
  and its reliance on `acks=all` `[kafka-acks-default]` + replication for
  durability. On a battery-less edge box, replicas usually share one power rail,
  so the independent-failure assumption that makes replication durable is FALSE,
  and a correlated power loss before the OS flush loses acknowledged writes
  (README, "Why IronBus exists"). IronBus's floor is instead a forced
  group-committed `fdatasync` BEFORE ack (invariant I2, ack-implies-durable; see
  [DURABILITY.md](DURABILITY.md) and
  [PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md) section 1). Edge
  failure mode: correlated power loss across same-rail replicas defeats
  replication-as-durability. (Kafka is also cluster-class and JVM-based, kept
  appendix-only by [BASELINE_RIG.md](BASELINE_RIG.md).)

#### Pulsar

- **Mechanism.** Stateless brokers separated from BookKeeper storage; a topic is
  a managed ledger of immutable ledgers (segments) striped across bookies with
  `E >= Qw >= Qa` `[pulsar-quorum-inequality]`, acked only after Qa bookies fsync
  the journal (`journalSyncData=true` `[pulsar-journal-sync-data-default]`).
  Cursors are stored durably; four subscription types cover
  exclusive/failover/shared/key_shared `[pulsar-subscription-types]`.
- **TAKE: immutable segments, durably-stored cursors, and key-shared routing.**
  IronBus borrows immutable sealed segments (its core storage model) and the idea
  that the consumer CURSOR is itself a durable record, not in-memory state (its
  cursor checkpoints, see [WAL.md](WAL.md)). The key_shared subscription informs
  its optional per-key head-of-line ordering (CHANGELOG #35 conformance vectors).
- **LEAVE: the ZooKeeper coordination dependency and the in-memory redelivery
  counter.** IronBus rejects a heavyweight external coordination dependency: the
  Edge-First tenet forbids assuming datacenter hardware and independent power
  domains (README, "No ZooKeeper, no JVM, no external dependencies"). It also
  rejects an IN-MEMORY redelivery counter (which makes DLQ routing best-effort
  and loses the count on restart); IronBus PERSISTS the redelivery count with the
  record so max-deliver and DLQ routing survive a restart (README, "Key
  decisions"; the persisted-counter choice is the one
  [PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md) 2.1 builds the
  bounded-loss accounting on top of). Edge failure mode: a coordination
  dependency cannot be met on a single unattended node; an in-memory counter
  resets the poison budget on every brownout restart.

#### Redpanda

- **Mechanism.** A single static C++/Seastar binary, no JVM or ZooKeeper,
  thread-per-core with NO page cache (direct DMA), per-partition Raft (2f+1)
  `[redpanda-raft-quorum]`, fsync batching, and OPT-IN ack-before-fsync write
  caching `[redpanda-write-caching]`.
- **TAKE: the single static self-contained binary and fsync batching.** IronBus
  matches Redpanda's single-static-binary stance (one musl binary, kernel-only
  dependency; README, Cross Platform tenet) and its fsync BATCHING (IronBus
  group-commits one `fdatasync` over a drained batch; CHANGELOG #177 append
  actor). It takes the no-JVM, no-ZooKeeper self-containment without the cost
  below.
- **LEAVE: no-page-cache direct-DMA thread-per-core, and ack-before-fsync write
  caching as a default.** This "leave" is already SETTLED in
  [PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md) section 1.2 and is not
  re-derived here: IronBus rejects no-page-cache direct-DMA / thread-per-core-pinned
  IO for the edge for three cited reasons (single-core ARM targets have no spare
  core for an IO reactor, bypassing the page cache loses warm-cache-on-restart,
  and a pinned-but-idle core without work-stealing wastes a scarce core). On the
  durability side, IronBus rejects ack-before-fsync write caching `[redpanda-write-caching]`
  as a DEFAULT: its correlated-majority loss window is a silent power-loss footgun
  on a shared-power node, so IronBus's relaxed async level is opt-in only and
  labeled not power-loss safe ([DURABILITY.md](DURABILITY.md);
  [SLO.md](SLO.md) durability rows). Edge failure mode: single-core ARM,
  cold-restart penalty, and a correlated-majority power-loss window.

#### RocksDB

- **Mechanism.** The crash-safety reference: WAL-then-memtable with group commit
  (one fsync over a batch), `WriteOptions.sync` default false (page-cache only)
  `[rocksdb-write-sync-default]`, a 32 KiB-block WAL with per-record CRC32c +
  length + type so a torn tail is detectable `[rocksdb-wal-block-format]`,
  `kPointInTimeRecovery` (replay the longest valid prefix, stop at the first bad
  record) `[rocksdb-pit-recovery]`, and MANIFEST/CURRENT as the authoritative
  live-file set instead of the directory listing.
- **TAKE: the checksummed torn-tail-tolerant WAL, group commit, and
  longest-valid-prefix recovery.** IronBus borrows the per-record CRC32C framing
  so a flipped bit on an SD card is caught on read, the group-commit-one-fsync
  shape, and point-in-time longest-valid-prefix recovery (these are IronBus's
  record format #5 and recovery #7; see [RECOVERY.md](RECOVERY.md), ADR-0001).
  IronBus also takes the FORCED-BARRIER-AT-COMMIT model (the RocksDB `sync=true`
  shape) as its durability boundary, the complement to the Kafka page-cache TAKE
  ([PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md) section 1).
- **LEAVE: the LSM compaction write-amplification, the MANIFEST, and
  stop-at-first-bad-record.** IronBus rejects leveled-compaction write
  amplification (~10x to 30x `[rocksdb-compaction-write-amp]`, low-confidence)
  because a queue is append-and-trim, not random-key, so whole-segment retention
  is gentler on flash (README #4/#13; this is the rejection
  [PRIOR_ART_AND_IO_STANCE.md] backs with the log-is-WAL flash argument). It also
  has NO MANIFEST (a compacted segment self-describes its covered range instead;
  see [COMPACTION.md](COMPACTION.md)). Finally, IronBus does NOT stop recovery at
  the first bad record the way `kPointInTimeRecovery` does `[rocksdb-pit-recovery]`;
  it SKIPS the poison span and resumes with bounded, reported loss, the
  genuinely-novel delta owned by #7/#8 and documented in
  [PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md) section 2.1 (do not
  re-derive it here). Edge failure mode: compaction burns eMMC endurance; a
  stop-at-first-bad recovery would strand every valid record after one bad frame.

#### Redis Streams

- **Mechanism.** 128-bit `<ms>-<seq>` IDs (monotonic, reused ms on clock
  regression) `[redis-stream-id-format]` in a radix tree of macro-nodes, with a
  per-group/per-consumer Pending Entries List, `XACK`, `XCLAIM`/`XAUTOCLAIM` with
  min-idle-time, and a per-message delivery counter `[redis-pel-mechanism]`.
  `appendfsync everysec` (default) bounds loss to about 1 second
  `[redis-appendfsync-default]`.
- **TAKE: monotonic IDs, the Pending Entries List, claim-with-idle, and the
  delivery counter.** IronBus borrows the PEL model directly: its consumer model
  is leases + acks + a persisted redelivery count + claim-on-expiry (README #9;
  the visibility-timeout lease is the SQS analog of XCLAIM min-idle-time). It also
  borrows the never-emit-a-smaller-timestamp rule under a clock regression
  ([EDGE_CONSTRAINTS.md](EDGE_CONSTRAINTS.md), the Redis-Streams clock rule).
- **LEAVE: async-replication acked-but-lost, and the AOF `everysec` floor as the
  durable default.** IronBus rejects async replication that acks BEFORE replicas
  have the data `[redis-async-replication-loss]` (a failover loses acknowledged
  writes; Redis is explicitly AP, not CP). It also rejects `everysec`
  `[redis-appendfsync-default]` as the DURABLE contract: a ~1-second fsync window
  is a real power-loss loss window on a battery-less node, so IronBus's default
  is a forced `fdatasync` BEFORE ack, not an every-second background flush
  ([DURABILITY.md](DURABILITY.md), invariant I2). (Redis `everysec` and `always`
  are exactly the two labeled peer rows in [BASELINE_RIG.md](BASELINE_RIG.md),
  both reported with their durability label.) Edge failure mode: power loss
  inside the everysec window or before async replication loses an acknowledged
  write.

#### SQS

- **Mechanism.** The lease model: visibility timeout (default 30s, max 12h from
  first receipt) `[sqs-visibility-timeout-default]`, explicit `DeleteMessage` to
  remove, `ReceiveCount` driving redrive to a DLQ at `maxReceiveCount`
  `[sqs-redrive-maxreceivecount]`, FIFO ordering per `MessageGroupId`, a 5-minute
  dedup window `[sqs-fifo-dedup-window]`, and long polling to cut empty receives.
- **TAKE: the visibility-timeout lease, redrive to a DLQ, and the dedup window.**
  This is IronBus's headline delivery primitive: SQS-style visibility-timeout
  leases with explicit ack/delete, redelivery, max-deliver, and a dead-letter
  queue (README, "IronBus is one durable, ordered queue (think a single AWS SQS
  queue)"; the lease/visibility-timeout choice over two-phase commit is the
  Simple tenet). IronBus uses a 30s default visibility timeout with a hard 5-minute
  cap (README, "Key decisions").
- **LEAVE: the managed-cloud shape (not embeddable), the implied duplicates, and
  DLQ-on-FIFO reorder.** IronBus rejects the managed-cloud deployment shape: SQS
  is the opposite of embeddable and edge-first (README, "it is a managed cloud
  service, the opposite of embeddable and edge-first"). The lease primitive is
  taken; the service is not. At-least-once plus a lease never PREVENTS duplicates,
  so IronBus is honest that at-least-once is the contract (exactly-once is a
  non-goal) and offers OPT-IN dedup rather than implying exactly-once. Edge
  failure mode: a managed service cannot run on the device at all; an implied
  exactly-once would be a false durability/ordering promise.

---

## Tier 2: the embeddable single-node tier (#27)

This tier is the closest analog to IronBus's real deployment shape: a
single-binary, single-node, power-loss-tested embeddable engine. The
network-broker tier above is about distribution and delivery; THIS tier is about
how a local engine makes one node durable, which is exactly IronBus's hard part.
Each entry has the same take/leave rigor, and each "leave" ties to a concrete
edge failure mode. #4 (storage engine) and #7 (recovery) can cite these
directly.

### 2.1 Chronicle Queue, SQLite WAL, LMDB/bbolt: take / leave

#### Chronicle Queue

- **Mechanism.** A memory-mapped append-only log split into roll-cycle files
  (default daily roll) with a per-cycle index; appends are serialized through a
  single-writer mode, ordering enforced by a write lock `[chronicle-single-writer]`
  (medium-confidence).
- **TAKE: the append-and-roll model with a per-cycle index.** IronBus borrows the
  shape of an append-only log that ROLLS into immutable cycle/segment files with a
  derived index per file (its segment roll + derived offset index; see
  [WAL.md](WAL.md)). The roll boundary is exactly where IronBus seals a segment
  and where preallocation/ENOSPC are handled ([PREALLOCATION.md](PREALLOCATION.md)).
- **LEAVE: the mmap append path and the single-writer-as-the-only-model framing.**
  IronBus does NOT mmap the active segment for writing: it appends through
  positioned `pwrite` and makes durability a forced `fdatasync`, because an
  mmap'd write path makes the durability boundary an `msync` whose ordering and
  writeback window are a power-loss hazard (see
  [the mmap hazards note](#23-the-mmap-durability-hazards-note) and
  [PREALLOCATION.md](PREALLOCATION.md) / [RAM_BUDGET.md](RAM_BUDGET.md), "there is
  no mmap in storage"). The single-writer model is FINE for IronBus (it runs one
  logical append actor; CHANGELOG #177), so that is noted, not rejected; what is
  rejected is the mmap write path. Edge failure mode: an mmap'd write turns the
  power-loss-safe `fdatasync` boundary into an msync-ordering hazard on a
  battery-less node.

#### SQLite WAL mode

- **Mechanism.** A separate `-wal` file holds committed frames until a checkpoint
  folds them back into the main database. Checkpoint modes are PASSIVE (default,
  non-blocking), FULL, RESTART, and TRUNCATE `[sqlite-wal-checkpoint-modes]`.
  `synchronous=NORMAL` fsyncs the WAL only at checkpoint (a power loss can lose
  the last transactions but never corrupts the DB); `synchronous=FULL` fsyncs
  enough to be durable across power loss `[sqlite-synchronous-normal-vs-full]`.
  WAL allows concurrent readers with ONE writer (a database-level write lock)
  `[sqlite-single-writer]`, and a checkpoint can only reclaim frames up to the
  oldest reader's mark, so continuous overlapping readers can STARVE the
  checkpoint and the `-wal` file grows without bound `[sqlite-checkpoint-starvation]`.
- **TAKE: WAL-plus-checkpoint, and the explicit NORMAL-vs-FULL fsync contract.**
  IronBus borrows the WAL-then-fold-forward idea AND, crucially, the lesson that
  the fsync policy must be EXPLICIT and labeled: SQLite's `synchronous=NORMAL` vs
  `FULL` is the exact "is this row power-loss safe?" distinction IronBus encodes
  as its sync (default, power-loss safe) vs async (opt-in, not power-loss safe)
  levels ([DURABILITY.md](DURABILITY.md); [SLO.md](SLO.md) durability rows). Note
  IronBus's log IS the WAL (ADR-0001), so it folds nothing forward, but the
  checkpoint-as-a-conservative-floor idea survives as its cursor checkpoints
  ([RECOVERY.md](RECOVERY.md), "checkpoint as a conservative floor never a
  ceiling").
- **LEAVE: the single-writer database-level lock and checkpoint starvation under
  continuous readers.** IronBus rejects letting a reader STALL durability:
  SQLite's checkpoint starvation `[sqlite-checkpoint-starvation]` means a
  continuous reader can grow the `-wal` file without bound, which on an edge node
  with a fixed flash budget is a disk-exhaustion failure. IronBus's readers are
  lock-free positioned reads of immutable sealed segments and CANNOT block the
  writer or hold back retention; retention is whole-segment delete bounded by
  byte/count caps that a reader cannot veto ([WAL.md](WAL.md),
  [BACKPRESSURE.md](BACKPRESSURE.md)). The single-writer LOCK itself is not the
  problem (IronBus is single-writer by design); the problem #4 must NOT inherit
  is a reader being able to stall the writer or starve reclamation. Edge failure
  mode: a stuck reader grows the WAL until the flash fills (single-writer stall +
  disk exhaustion).

#### LMDB and bbolt (and etcd-on-bolt)

- **Mechanism.** A memory-mapped copy-on-write B+tree with MVCC readers (readers
  never block the single writer). A write transaction is made durable by a
  batched fsync at commit: LMDB syncs the data then writes a meta page
  `[lmdb-cow-btree-single-fsync]` (medium-confidence); bbolt writes and fsyncs
  dirty pages, then writes and fsyncs the meta page, an ordered data-then-meta
  commit `[bbolt-cow-btree-single-fsync]` (medium-confidence) that etcd relies
  on. COW rewrites every TOUCHED page in FULL (page-granular), and a long-lived
  reader prevents freed pages from being reclaimed, so the free list and the file
  grow `[lmdb-freelist-growth]` (low-confidence) `[bbolt-full-page-write-amp]`.
- **TAKE: the single batched fsync at commit, and MVCC lock-free readers.**
  IronBus borrows the BATCHED-SINGLE-FSYNC-AT-COMMIT shape: amortize one durable
  barrier over a batch of work rather than one fsync per record (its group-commit
  append actor is exactly this, one `fdatasync` over a drained batch; CHANGELOG
  #177, [DURABILITY.md](DURABILITY.md)). It also borrows MVCC-style lock-free
  readers: IronBus consumers read immutable sealed segments without blocking the
  writer (the page-cache read path,
  [PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md) section 1).
- **LEAVE: full-page copy-on-write write amplification and free-list growth.**
  IronBus rejects full-page COW `[bbolt-full-page-write-amp]`: rewriting every
  touched B+tree page in full is heavy write amplification on flash, and the free
  list growing under a long-lived reader `[lmdb-freelist-growth]` (low-confidence)
  is exactly the reader-stalls-reclamation hazard the SQLite entry also names.
  A queue is append-and-trim, not a mutable B+tree, so IronBus appends sequentially
  and reclaims by WHOLE-SEGMENT delete, with no per-page COW and no free list to
  grow (ADR-0001 log-is-WAL; #13 retention). It also does NOT mmap the store for
  writing (see the hazards note). Edge failure mode: full-page COW burns eMMC
  endurance; free-list growth under a stuck reader exhausts the flash budget.

### 2.2 Why this tier matters more than the network tier for the edge

The network-broker tier teaches distribution and delivery; this tier teaches the
part IronBus actually has to get right alone: making ONE node durable across
power loss on cheap flash. The honest summary is that IronBus's storage engine is
closest to "an append-only log with a forced-fsync commit and longest-valid-prefix
recovery", which is the RocksDB-WAL shape (tier 1) realized in the
single-binary-embeddable form of THIS tier, minus the mutable B+tree, minus
mmap-as-the-durability-path, and minus any reader that can stall the writer or
reclamation.

### 2.3 The mmap-durability-hazards note

Three of the four embeddable engines above (Chronicle, LMDB, bbolt) use mmap as
their primary IO path. IronBus deliberately does NOT use mmap in storage
(confirmed in [RAM_BUDGET.md](RAM_BUDGET.md): "There is no mmap in storage" and
`mmap_max_bytes = N/A (no mmap in storage)`, and in
[PREALLOCATION.md](PREALLOCATION.md): the sealed-read primitive is positioned
`pread`, "NOT a memory map"). This note GROUNDS that decision in three concrete
hazards, each tied to an edge failure mode, so a downstream design (#4, #7) never
assumes mmap gives write ordering or durability for free.

1. **msync ordering is NOT write ordering.** `msync(MS_SYNC)` writes the named
   dirty pages back to the file, but it imposes no ordering between unrelated
   dirty pages, and the kernel does not guarantee that dirty mapped pages reach
   the device in modification order between msync calls `[mmap-msync-not-write-ordering]`
   (medium-confidence). A WAL needs a write BARRIER (the record before the commit
   marker must be durable before the marker), and msync does not provide one
   across the mapping. IronBus's forced `fdatasync` after a positioned append IS
   a barrier at the commit point ([DURABILITY.md](DURABILITY.md), invariant I2).
   Edge failure mode: on power loss, an mmap'd log can have the commit marker
   durable while the record it commits is not, silently violating
   ack-implies-durable.

2. **SIGBUS on file truncation under an active mapping.** If a mapped file is
   truncated, or a backing block cannot be materialized (an ENOSPC hole), a
   subsequent access to the now-invalid page raises SIGBUS and crashes a process
   that does not handle the signal `[mmap-sigbus-on-truncation]`. IronBus's
   recovery TRUNCATES a torn tail and its retention DELETES whole segments;
   doing that under an active write mapping is a SIGBUS-crash hazard. Using
   positioned `pread`/`pwrite` over a non-mapped file, a truncation or a delete is
   a clean `read` returning short / `ENOENT`, handled as data, not a fatal signal
   ([RECOVERY.md](RECOVERY.md) torn-tail truncation; #13 whole-segment delete).
   Edge failure mode: recovery truncation or retention delete SIGBUS-crashes a
   broker that mmaps the active file on a node that restarts on every brownout.

3. **The page-cache writeback window.** A store to a writable mapped page only
   dirties a page-cache page; it becomes durable on the device only at the next
   msync/fsync or when kernel writeback flushes it (the
   `dirty_expire_centisecs` / `dirty_writeback_centisecs` window, default order
   of tens of seconds) `[mmap-writeback-window]` (medium-confidence). So an
   un-msynced store has an unbounded-until-flush loss window. This is the SAME
   loss window IronBus already rejects as a DEFAULT in the IO stance: the relaxed
   page-cache-async level is opt-in only and labeled not power-loss safe
   ([PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md) section 1.1;
   [DURABILITY.md](DURABILITY.md) section 3). An mmap write path makes that
   window the DEFAULT and hides it behind a memory store, which is exactly the
   silent footgun the Edge-First safe default exists to prevent. Edge failure
   mode: a store that looks committed in memory is lost on power loss until the
   writeback timer or an explicit msync fires.

The conclusion is the one already recorded in the merged docs and merely grounded
here: IronBus reads through the page cache but WRITES through positioned
`pwrite` + a forced `fdatasync`, never an mmap whose durability is an msync. The
"sealed-read-map" primitive in [PREALLOCATION.md](PREALLOCATION.md) is named for
its contract (positioned reads of a sealed file) precisely so a future mmap-backed
READ implementation could satisfy it on a platform where that wins, without ever
making the WRITE path an mmap.

---

## The claims contract (#26)

[`prior-art/claims.yaml`](prior-art/claims.yaml) is the VERSION-PINNED SOURCE OF
RECORD for every numeric and version-specific claim in this survey. The contract:

- **The yaml wins.** The table and prose above may be hand-maintained, but they
  MUST agree with the value pinned in the yaml. On any disagreement, the yaml is
  authoritative and the prose is the bug. Every load-bearing number here carries a
  `[id]` tag naming its yaml entry, so a reviewer can reproduce any single number
  from its entry (system, version, value, `source_url` with a `#section` anchor
  where the source exposes one, `accessed_date`, `confidence`) in well under a
  minute.
- **Descriptive, not prescriptive.** The yaml records only what an upstream
  system does at a pinned version. It NEVER records an IronBus default; those
  live in the merged design docs. This keeps a contributor from copying a Kafka
  value as an IronBus default.
- **Staleness is visible, not silent.** Each entry carries the pinned `version`
  and the `accessed_date` (`2026-06-08` for this pass). When an upstream default
  changes, the stale entry is visibly stale (old version, old date), not silently
  wrong.
- **Low-confidence is flagged twice.** A claim that rests on a single source
  sentence, an easily-misread default, or a value we could not anchor to an exact
  upstream sentence is `confidence: low` in the yaml AND tagged `(low-confidence)`
  inline above, so it is re-verified first. The low-confidence claims in this pass
  are: `nats-filestore-block-sizes` (block sizes are derived in `filestore.go`,
  not a public knob), `rocksdb-compaction-write-amp` (the 10x-30x range is an
  order-of-magnitude rule of thumb, not one pinned number), and
  `lmdb-freelist-growth` (the reader-blocks-reclamation hazard is documented
  across mailing-list and design-paper sources, not one anchored sentence).
  Several `medium`-confidence entries carry an inline `why` in the yaml
  (`kafka-linger-ms-default`, `nats-maxackpending-default`, `nats-ack-vocabulary`,
  `pulsar-journal-sync-data-default`, `redpanda-write-caching`, `mqtt-receive-maximum`,
  `chronicle-single-writer`, `lmdb-cow-btree-single-fsync`,
  `bbolt-cow-btree-single-fsync`, `mmap-msync-not-write-ordering`,
  `mmap-writeback-window`).

The agree-with-the-yaml contract is mechanized, cheaply, by
[`scripts/ci/check-prior-art-claims.sh`](../scripts/ci/check-prior-art-claims.sh):
it asserts that every `[id]` cited in this document exists in the yaml (no
dangling citation), and that every id in the yaml is unique. It does NOT re-fetch
sources (it is offline and deterministic, like the other IronBus doc gates); a
number drifting upstream is surfaced by the `accessed_date` going stale and by a
reviewer re-checking a low-confidence entry, not by the script. A full
table-renderer that regenerates the markdown from the yaml is intentionally NOT
built here (#26 can add one later); the contract this doc commits to is
agreement, plus the dangling-citation gate.

---

## Cross-references

- [PRIOR_ART_AND_IO_STANCE.md](PRIOR_ART_AND_IO_STANCE.md): the edge IO stance
  (#28, the page-cache + forced-`fdatasync` position, Redpanda direct-DMA
  rejected) and the open per-feature gaps (#29, the IronBus-novel poison-skip,
  loss report, and producer spill/shed). This survey COMPLEMENTS it and does not
  re-derive either.
- [README.md](../README.md): the "Why IronBus exists" narrative and the five
  tenets the take/leave decisions appeal to.
- [DURABILITY.md](DURABILITY.md): invariant I2 (ack-implies-durable), the
  group-commit append actor, and the opt-in not-power-loss-safe async level.
- [PREALLOCATION.md](PREALLOCATION.md) and [RAM_BUDGET.md](RAM_BUDGET.md): the
  no-mmap-in-storage decision the mmap-hazards note grounds.
- [RECOVERY.md](RECOVERY.md): longest-valid-prefix, stop-at-first-bad-frame, and
  torn-tail truncation.
- [BACKPRESSURE.md](BACKPRESSURE.md) and [WAL.md](WAL.md): the durable-log
  overflow policy and the segment lifecycle the retention "leaves" reference.
- [BASELINE_RIG.md](BASELINE_RIG.md): why cluster-class Kafka/Redpanda are
  appendix-only, and the labeled NATS/Redis/Mosquitto peer rows.
- [adr/0001-log-is-wal.md](adr/0001-log-is-wal.md): the active segment is the
  write-ahead log, the basis for several "leave" decisions.
- [`prior-art/claims.yaml`](prior-art/claims.yaml): the version-pinned source of
  record for every numeric claim above.
- Issues: [#2](https://github.com/ELares/IronBus/issues/2) (the network-broker
  survey), [#27](https://github.com/ELares/IronBus/issues/27) (the embeddable
  tier + mmap hazards), [#26](https://github.com/ELares/IronBus/issues/26) (the
  version-pinned claims), and the downstream consumers
  [#4](https://github.com/ELares/IronBus/issues/4) (storage engine),
  [#6](https://github.com/ELares/IronBus/issues/6) (durability),
  [#7](https://github.com/ELares/IronBus/issues/7) (crash recovery),
  [#9](https://github.com/ELares/IronBus/issues/9) (consumer model),
  [#10](https://github.com/ELares/IronBus/issues/10) (backpressure).
