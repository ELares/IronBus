# Prior art and the IO stance: page cache vs direct DMA, and the open prior-art gaps

This document consolidates two decisions that are already MADE in the merged
design but were never written down as a single piece of reconciling prose. Both
are deliverables of the architecture-specification milestone (M1):

1. [The edge IO stance](#1-the-edge-io-stance-28): one coherent position on the
   OS page cache, the `fdatasync` durability boundary, and the page-cache-async
   relaxation, with the explicit rejection of Redpanda-style no-page-cache
   direct-DMA IO for the edge. This settles
   [#28](https://github.com/ELares/IronBus/issues/28).
2. [The open prior-art gaps](#2-the-open-prior-art-gaps-29): for each
   IronBus-novel feature, the closest partial analog, the precise delta IronBus
   adds, and the downstream issue that owns the invention. This settles
   [#29](https://github.com/ELares/IronBus/issues/29).

It is design (docs) only. It introduces no flag and changes no source. Every
position below is cross-checked against the merged docs it cites and contradicts
none of them. Where a number or a behavior is load-bearing it is quoted from the
owning doc, never invented here.

The canonical sources this document reconciles are
[ADR-0001 (the active segment is the WAL)](adr/0001-log-is-wal.md),
[DURABILITY.md (the durability contract and the levels model)](DURABILITY.md),
[SLO.md (the durability-mode rows)](SLO.md),
[EDGE_CONSTRAINTS.md (the constraint-to-knob map)](EDGE_CONSTRAINTS.md), and
[BACKPRESSURE.md (overflow and shedding)](BACKPRESSURE.md). For the shared
invariants (I1 to I8) see [INVARIANTS.md](INVARIANTS.md); for the recovery loss
report see [the `ironbus.loss-report.v1` schema](schemas/loss-report.v1.md).

---

## 1. The edge IO stance (#28)

The parent survey ([#2](https://github.com/ELares/IronBus/issues/2)) carried two
unreconciled tensions. It praised Kafka's reliance on the OS page cache AND
Redpanda's no-page-cache direct-DMA design in the same breath, and it named both
a forced-`fsync` floor and a page-cache-async path without saying which one is
the default on the SAME battery-less edge box. Left standing, each tension lets a
downstream issue pick a different half and diverge. This section states the
single stance so [#4](https://github.com/ELares/IronBus/issues/4) (storage
engine), [#6](https://github.com/ELares/IronBus/issues/6) (durability), and
[#19](https://github.com/ELares/IronBus/issues/19) (SLO) each cite one
unambiguous position.

### 1.1 The stance

IronBus uses the OS page cache and a forced, group-committed `fdatasync`
together. They are COMPLEMENTARY, not alternatives:

- **Reads go through the page cache.** A consumer read
  (`Log::read_from`) reads from the segment files through the kernel, so the
  working set the OS holds resident is served without a device round trip, and a
  freshly restarted broker reaches a WARM CACHE on its own as soon as it touches
  the recent tail. The read path materializes at most one record at a time, so
  the page cache, not a broker-private buffer, is what holds recent data hot (see
  [RAM_BUDGET.md](RAM_BUDGET.md), "Active segment and page cache", which records
  that the page cache is reclaimable kernel memory shared by the OS and is NOT
  the broker's private RSS). This is the Kafka model: lean on the kernel's cache
  rather than reimplement one in the process.

- **Writes coalesce in the page cache, then a forced `fdatasync` is the
  durability boundary.** A publish is one framed, checksummed, record-aligned
  append to the active segment, which IS the write-ahead log (ADR-0001: there is
  no separate WAL file). The append actor
  ([#177](https://github.com/ELares/IronBus/issues/177)) drains a batch of queued
  produces, issues ONE `fdatasync` covering the whole batch, and only THEN acks
  every record in it. The page cache absorbs and coalesces the sequential write
  traffic between barriers; the `fdatasync` is the line past which an ack is
  durable. This is the RocksDB model of a forced barrier at the commit point.
  The contract this enforces is invariant I2, ack-implies-durable: no ack is
  observable for a record not already covered by a returned `fdatasync`, so
  acknowledged loss on power loss is ZERO (see [DURABILITY.md](DURABILITY.md),
  section 1). A failed `fdatasync` is fatal, never a retried false success: the
  writer freezes read-only (`WriterFrozen`) rather than ack a record that is not
  durable (the fsyncgate lesson, DURABILITY.md section 2).

So the page cache buys read warmth and write coalescing, and the forced
`fdatasync` buys the durability boundary. The cache does not weaken the barrier
and the barrier does not bypass the cache. They sit on opposite sides of the same
publish path.

- **Page-cache-async is OPT-IN ONLY, and it is labeled not power-loss safe.**
  The relaxed `async` level (the README's `none`) acks on append and lets the
  `fdatasync` happen only opportunistically, so it trades durability for
  throughput. It is CONTRARY to the Edge-First safe default. It is SPECIFIED but
  NOT implemented, it is off by default, it cannot be reached from the `serve`
  command line today, and selecting it requires an explicit data-loss
  acknowledgement (`async_loss_ack`) because its acknowledged loss is unbounded
  until the next sync (see [DURABILITY.md](DURABILITY.md) section 3, the level
  model). The SLO target table carries the async row with a literal
  `not power-loss safe` safety label sitting beside the power-loss-safe
  group-commit `fdatasync` default (see [SLO.md](SLO.md), the durability-mode
  rows). The edge constraint map agrees: the power-loss-safe `sync` level is the
  only level exposed and cannot be weakened from the command line (see
  [EDGE_CONSTRAINTS.md](EDGE_CONSTRAINTS.md), the power-loss / brownout row and
  the "no silent relaxed mode" point). Async is therefore an operator's
  deliberate, declared choice, never the default and never silent.

### 1.2 Why IronBus rejects Redpanda-style no-page-cache direct-DMA IO for the edge

IronBus EXPLICITLY REJECTS the Redpanda-style design for the edge default:
bypassing the page cache with direct DMA and pinning IO to one core per shard
(the Seastar thread-per-core model). The reasons are specific to the edge
target, not taste:

- **Single-core-constrained ARM edge targets.** The reference edge box is a
  battery-less, weak-ARM node with few cores. A thread-per-core, shard-per-core
  IO model assumes spare cores to dedicate; on a node where the marquee target is
  stated as "tens of thousands of small messages per second per core" (see
  [SLO.md](SLO.md)), there is no spare core to give an IO reactor. Cluster-class
  brokers like Kafka and Redpanda are JVM / Seastar multi-node systems, not
  single-edge-node brokers, which is exactly why the baseline rig EXCLUDES them
  from the edge SLO gates and allows them only in an x86-ref appendix labeled
  `not an edge-class comparison` (see [BASELINE_RIG.md](BASELINE_RIG.md)).

- **Loss of warm-cache-on-restart.** Bypassing the page cache means the broker
  owns its own cache and a restart starts COLD. The page-cache model gives
  warm-cache-on-restart for free: after a power cut or an in-place upgrade the
  OS refills the cache from the recent segment tail with no broker bookkeeping.
  On an unattended edge node that restarts on brownout and on every upgrade, a
  cold-start penalty on every restart is the wrong trade.

- **Core-pinning without work-stealing wastes a scarce core.** A direct-DMA IO
  reactor pinned to a core, with no work-stealing across cores, leaves that core
  idle while other work piles up and cannot borrow it. On a node where every core
  is scarce, a pinned-but-idle core is pure waste. IronBus instead runs a single
  logical writer (the append actor) over the shared kernel page cache, so the OS
  scheduler and the kernel's own cache do the cross-core balancing the edge node
  cannot afford to reimplement.

### 1.3 The decision table

| Concern | IronBus stance |
| --- | --- |
| Read path | OS page cache (warm-cache-on-restart) |
| Write coalescing | OS page cache |
| Durability boundary | forced group-committed `fdatasync` (ack-implies-durable, I2) |
| Async (page-cache, ack-before-sync) | opt-in only, off by default, NOT power-loss safe |

No-page-cache direct-DMA / thread-per-core-pinned IO is REJECTED as the edge
default for the three cited reasons above (single-core ARM, lost
warm-cache-on-restart, core-pinning without work-stealing). The exact
group-commit sizing (how large a batch the actor drains before it syncs) is a
tuning decision owned by [#6](https://github.com/ELares/IronBus/issues/6); this
document states the stance, not the constants.

---

## 2. The open prior-art gaps (#29)

The parent survey catalogs what to take and leave from existing systems but never
names the places where NO surveyed system gives a usable answer. IronBus's
riskiest promises have only PARTIAL prior art. This section gives each one the
closest analog, the precise delta IronBus must invent, and the downstream issue
that owns the invention, so [#7](https://github.com/ELares/IronBus/issues/7),
[#8](https://github.com/ELares/IronBus/issues/8), and
[#10](https://github.com/ELares/IronBus/issues/10) have a grounded starting
point instead of a blank page. Each entry cites a real analog and claims only the
specific delta IronBus adds; where IronBus is genuinely novel it says so.

### 2.1 Poison-record / poison-segment SKIP with bounded-and-reported loss (owner #8)

- **Closest partial analog.** RocksDB `kPointInTimeRecovery` replays the
  longest valid prefix and STOPS at the first bad record. ZFS scrub detects and
  reports checksum errors across a pool. Kafka log truncation drops a torn or
  corrupt tail to reach a clean prefix.
- **What the analogs do NOT cover.** `kPointInTimeRecovery` stops at the first
  bad record rather than SKIPPING a bad span and RESUMING past it into the still
  valid records beyond, and it produces no operator-facing loss report. ZFS scrub
  reports at the block / pool level, not as a per-event typed account of which
  message offsets a queue dropped and why. Kafka truncation discards the tail
  silently and offers no structured record of the discarded span.
- **The IronBus delta IronBus must invent.** Recovery does not stop at the first
  bad frame; it SKIPS the poison record or poison segment and resumes at the next
  valid frame, and it accounts every skipped span as a typed
  [`ironbus.loss-report.v1`](schemas/loss-report.v1.md) `LossEvent` (segment id,
  byte-offset range, bytes skipped, records-lost estimate, and a typed
  `ReasonCode` such as `TornTail` or `CorruptRecordBody`). The accounting is
  BOUNDED with HARD CAPS that FAIL CLOSED: a single event cannot exceed
  `PER_EVENT_BYTE_CAP` (`64 MiB`, effectively one segment) and total loss cannot
  exceed `1%` of durable bytes (`GLOBAL_LOSS_CAP_NUMERATOR` over
  `GLOBAL_LOSS_CAP_DENOMINATOR`); exceeding either cap turns bounded reported
  loss into unbounded silent loss, so recovery FREEZES read-only and exits
  non-zero rather than accept it (see the loss-report schema, "Bounded-loss
  caps", and invariant I3). This is the genuinely NOVEL part: per-event typed
  loss accounting with hard caps that fail closed, where the surveyed systems
  either stop early, report at the wrong granularity, or truncate silently. The
  recovery-time mechanics (stop-at-first-bad-frame detection, the skip-and-resume
  walk, the quarantine of skipped bytes) are owned by
  [#8](https://github.com/ELares/IronBus/issues/8); the on-startup recovery flow
  that drives it is [#7](https://github.com/ELares/IronBus/issues/7).

### 2.2 The bounded-and-reported recovery loss accounting (owner #7)

- **Closest partial analog.** Kafka's recovery logs note that a segment was
  truncated; a general filesystem `fsck` prints what it repaired.
- **What the analogs do NOT cover.** Those outputs are UNSTRUCTURED human log
  lines. No surveyed system emits a machine-readable, externally-frozen record of
  exactly which offsets were dropped and why, that a metrics endpoint, an offline
  inspector, and test fixtures can all read and assert against the SAME shape.
- **The IronBus delta IronBus must invent.** Recovery emits the structured,
  versioned [`ironbus.loss-report.v1`](schemas/loss-report.v1.md): a list of
  `LossEvent`s in the order recovery encountered them, each with the exact
  byte-offset span, the bytes skipped, the records-lost estimate, and the typed
  `ReasonCode`, with the field set and the reason-code integers FROZEN by golden
  tests so a rename or renumber is a CI failure. The delta versus the analogs is
  that loss becomes a first-class, machine-readable CONTRACT rather than a side
  effect noted in a log: this is the product's bounded-and-REPORTED tenet, and
  the observability rule that every truncation, skip, and recovery-loss event
  increments a stable-named counter so no resilience event is ever silent (see
  [METRICS.md](METRICS.md) and invariant I3). The recovery flow that produces and
  surfaces the report on startup is owned by
  [#7](https://github.com/ELares/IronBus/issues/7); the schema freeze itself is
  [#120](https://github.com/ELares/IronBus/issues/120).

### 2.3 Producer SPILL / SHED backpressure without head-of-line stalls (owner #10)

- **Closest partial analog.** Kafka's producer-side buffer BLOCKS or FAILS the
  producer when it fills. SQS routes poison messages to a dead-letter queue and
  caps in-flight messages on the CONSUMER side. Redis handles overflow by
  rejecting writes or evicting under its maxmemory policy.
- **What the analogs do NOT cover.** Kafka's full-buffer behavior is the
  OPPOSITE of spill-to-disk-and-shed: it stalls the producer rather than
  absorbing the burst durably and shedding deterministically. SQS's in-flight cap
  sheds on the consumer side only, not at the producer's ingest under overload.
  None of them combine a durable spill, a deterministic shed policy, and a
  rate-INDEPENDENT shed signal that needs no per-device tuning.
- **The IronBus delta IronBus must invent.** Because the active segment is
  already the durable log, the "spill" tier is the on-disk log itself: there is
  no separate in-memory ring to spill INTO, so the README's "spill to disk then
  shed" collapses to a hard byte cap on the durable log with an explicit overflow
  DISPOSITION (`drop-new` by default, or `drop-oldest`), and every shed
  increments a counter rather than blocking the producer (see
  [BACKPRESSURE.md](BACKPRESSURE.md), the durable-log overflow policy, and
  [WAL.md](WAL.md), "never spill-into-a-second-log"). Layered on top, the
  SPECIFIED CoDel time-in-queue shedding sheds by how long a message has WAITED
  (sojourn), not by queue depth, so the control is rate-independent and needs no
  per-device tuning, with a depth-and-byte BACKSTOP that bounds memory when a
  fully stalled drain produces no sojourn samples at all. The genuinely novel
  combination is structural producer non-blocking: a durable spill plus a
  deterministic, reported shed plus a rate-independent sojourn signal, instead of
  the analog's producer-side block. The overflow policy is shipped today; CoDel,
  the retry budget, and the wire shed signal are SPECIFIED but not yet
  implemented (BACKPRESSURE.md is explicit about which is which). The parent that
  owns this invention is [#10](https://github.com/ELares/IronBus/issues/10).

### 2.4 Honest novelty boundary

Two of the three above are genuinely novel in their COMBINATION, not in any
single primitive. Skip-and-resume recovery, typed loss events, byte caps,
disk-backed queues, and CoDel each exist somewhere. What no surveyed system
ships is (a) per-event typed loss accounting with hard caps that fail closed
during RECOVERY, and (b) a producer path that is non-blocking by spilling to the
durable log and shedding under a rate-independent signal. The bounded-and-
reported loss CONTRACT (a frozen, machine-readable report of exactly what was
dropped and why) is the clearest place IronBus has no clean prior art at all.
The honest statement is therefore: borrow the primitives, invent the
combination and the contract, and own each invention under #7, #8, and #10.

---

## Source-URL durability policy (#30)

The #2 acceptance criterion that "all cited URLs are verifiable" is enforced
mechanically, and every external source this survey leans on is pinned so its
cited content cannot silently change or vanish under it. Two rules apply to any
prior-art source URL added to the docs:

- **Pin a GitHub source citation to an immutable commit, never a branch.** When
  a prior-art claim cites a specific file or specific lines in a GitHub repo
  (a `filestore.go`, a `bookkeeper.conf`), link the `blob/<commit-sha>`
  permalink, NOT a `blob/main` (or `master`/`HEAD`) link whose lines move. The
  link-check's relative half cannot police an external host, so the immutability
  of the cited lines is bought by the SHA in the URL itself. (No prior-art GitHub
  SOURCE-line citation is present in this document on `main` yet; the comparative
  survey that adds them is #2/#26, and this rule is the standing requirement for
  when it lands. GitHub ACTIONS are already SHA-pinned under #142; this rule is
  about prior-art SOURCE URLs.)
- **Record an archive.org snapshot plus a dated note for a mutable vendor doc.**
  A vendor doc tree or blog post can move or 404. Where the docs cite one, the
  citation carries an inline dated `archived YYYY-MM-DD` link to a
  `web.archive.org` snapshot, so the content as cited is recoverable even if the
  live page changes. The
  mutable vendor docs cited across the docs tree today, with their snapshots:

  | Cited vendor doc | Live URL | archive.org snapshot |
  | --- | --- | --- |
  | NDJSON spec (`CLI_CONTRACT.md`) | `https://ndjson.org/` | [2026-05-08](https://web.archive.org/web/20260508182020/https://ndjson.org/) |
  | `cargo deb` (`DISTRIBUTION.md`) | `https://github.com/kornelski/cargo-deb` | [2026-06-05](https://web.archive.org/web/20260605144432/https://github.com/kornelski/cargo-deb) |
  | nfpm (`DISTRIBUTION.md`) | `https://nfpm.goreleaser.com/` | [2026-04-13](https://web.archive.org/web/20260413200705/https://nfpm.goreleaser.com/) |

The integrity of these URLs is checked by two CI layers (#30): a per-PR
relative-link check (`scripts/ci/relative-link-check.sh`, no network, never
flaky) that proves every in-repo doc link and section anchor resolves, and a
weekly external-URL check (`scripts/ci/external-link-check.sh`, run by the
`docs-link-check` workflow) that confirms every cited external URL is reachable
and opens a tracking issue on a dead one. The split is deliberate: the per-PR
gate never reaches the open internet, so a transient third-party outage can
never redden `main`; link ROT is still caught within a week by the cron.

---

## Cross-references

- [ADR-0001](adr/0001-log-is-wal.md): the active segment is the write-ahead log
  (the basis for "one forced `fdatasync` is the durability boundary").
- [DURABILITY.md](DURABILITY.md): invariant I2 (ack-implies-durable), the
  group-commit append actor, the fsyncgate writer-freeze, and the relaxed-level
  opt-in contract.
- [SLO.md](SLO.md): the durability-mode rows that label the async page-cache row
  `not power-loss safe`.
- [EDGE_CONSTRAINTS.md](EDGE_CONSTRAINTS.md): the power-loss / brownout
  constraint-to-knob row and the no-silent-relaxed-mode point.
- [BACKPRESSURE.md](BACKPRESSURE.md): the durable-log overflow policy
  (drop-new / drop-oldest) and the SPECIFIED CoDel sojourn shedding.
- [BASELINE_RIG.md](BASELINE_RIG.md): why cluster-class Kafka / Redpanda are
  appendix-only and excluded from the edge SLO gates.
- [RAM_BUDGET.md](RAM_BUDGET.md): the page cache is reclaimable kernel memory,
  not the broker's private RSS.
- [The `ironbus.loss-report.v1` schema](schemas/loss-report.v1.md): the frozen
  loss report, the per-event and global bounded-loss caps, and the fail-closed
  rule.
- [INVARIANTS.md](INVARIANTS.md): I2 (ack-implies-durable) and I3 (bounded and
  reported loss).
- Issues: [#28](https://github.com/ELares/IronBus/issues/28) (this IO-stance
  reconciliation), [#29](https://github.com/ELares/IronBus/issues/29) (the open
  prior-art gaps), [#2](https://github.com/ELares/IronBus/issues/2) (the parent
  survey), [#4](https://github.com/ELares/IronBus/issues/4) (storage engine),
  [#6](https://github.com/ELares/IronBus/issues/6) (durability),
  [#7](https://github.com/ELares/IronBus/issues/7) (crash recovery),
  [#8](https://github.com/ELares/IronBus/issues/8) (corruption / poison skip),
  [#10](https://github.com/ELares/IronBus/issues/10) (backpressure),
  [#19](https://github.com/ELares/IronBus/issues/19) (SLO).
