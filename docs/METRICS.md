# Metrics and the resilience-observability contract

This is the normative catalog of the metrics IronBus renders on `GET /metrics`
(Prometheus text exposition format), and the **resilience-observability
contract** (#96): every event the resilience machinery sheds, drops, skips,
dead-letters, truncates, force-reaps, or loses on recovery increments a
**stable-named, documented counter**, so no resilience event is ever silent and
the taxonomy can never silently drift.

The contract has three parts:

1. A **frozen taxonomy**: the complete set of resilience counter names is pinned
   by a test (`the_resilience_counter_taxonomy_is_frozen` in
   `crates/ironbus-server/src/health.rs`), modeled on the frozen wire-tag tests.
   Adding, removing, or renaming a resilience counter is therefore a deliberate,
   test-gated edit, not an accident.
2. Each counter is incremented **at the exact event site**, and a test drives the
   event and asserts the increment.
3. Each counter is **documented here** with its name, the event that increments
   it, and its resilience meaning (shed vs drop vs skip vs dead-letter vs
   truncation).

The endpoint shares `/metrics`'s loopback / trusted-network trust model (the
#105 / #107 threat model, see [THREAT_MODEL.md](THREAT_MODEL.md)); it carries no
secret material and no mutating action.

## Resilience counters (the frozen taxonomy)

Every name below is an `ironbus_*_total` counter. The set is frozen: the test
asserts `/metrics` renders **exactly** this set (plus the gauges and the fsync
histogram below). A second, broader golden test
(`the_metric_name_and_type_contract_is_frozen`, #99) pins the **complete**
`(metric name, Prometheus type)` set across counters, gauges, and histograms, so
any rename, type change, or unit change (a unit lives in the name suffix, so a
unit change is a name change) fails CI until this contract and this doc are
bumped deliberately (#22). The metric and label names are a stability contract: a
dashboard or the `ironbus admin` CLI must never be broken by an unannounced
rename. Counters are monotonic statistics (they only increase). They
are **durable across a restart** (#98): the broker snapshots them to a CRC'd
`counters.ckpt` on the cursor-checkpoint cadence and on the graceful-shutdown
flush, and seeds them from that snapshot at startup, so a restart no longer
zeroes the operational history. Because the snapshot is on a cadence (not an
fsync per increment), a crash loses at most the increments since the last
snapshot: the resumed value is a monotonic **lower bound**. The counters are
strictly an observability aid, so a torn or missing `counters.ckpt` recovers as
all-zeros and never blocks startup or touches the durable log, cursors, or DLQ
(recovery-loss gauges are independently repopulated from the last recovery's
loss report).

For the **recovery-loss family** the snapshot lower bound is strengthened to a
strict cross-restart **monotonic non-decreasing** guarantee by
**checkpoint-plus-replay reconciliation** (#307). These are the values that are
genuinely **replay-reconstructable** from a durable artifact (the `LossReport`
the last recovery rebuilds): the reconciled gauges `ironbus_records_skipped`
and `ironbus_bytes_skipped` (the loss report's total records and bytes skipped),
and the recovery-head component of `ironbus_last_skip_offset`. On open the broker
takes, for each, `max(snapshot, replay)` where the *replay* value is what the
durable log / loss report implies. Because it is a pure `max`, reconciliation can
only **raise** a value, never lower it (so #306's lower bound is preserved). It is
best-effort on the read side and **never blocks recovery**: an absent or malformed
loss report degrades to an empty report (replay all-zeros) and the snapshot value
stands, exactly like #306's corrupt-never-blocks-recovery on the write side.

The reconciled values are **checkpoint-plus-replay reconciled** (true cross-restart
monotonic, even across a `kill -9`): `ironbus_records_skipped`,
`ironbus_bytes_skipped`, and the recovery-head contribution to
`ironbus_last_skip_offset`. Everything else retains the **snapshot-only lower
bound** from #306: the operational counters (produced, delivered, acks,
dead-lettered, reaped, …) cannot be replay-derived from the log, and so cannot the
**consumer-truncation** counters `ironbus_truncations_total` /
`ironbus_truncated_records_total` (a force-reap-driven, transient, consumer-cursor
quantity that is not in the durable loss report) nor the consumer-truncation
contribution to `ironbus_last_skip_offset`. For all of those a `kill -9` can still
lose the increments since the last cadence snapshot; that is the only viable design
for a non-replay-derivable quantity. (`ironbus_truncated_records_total` is
deliberately **not** reconciled against the recovery loss report: they are
different quantities, and maxing them would conflate consumer truncation with
recovery loss.)

Each reconciliation that actually raises a recovery-loss value above its snapshot
increments `ironbus_counter_checkpoint_repair_total` once, so an operator can see
the lower-bound recovery firing after a hard crash (a clean shutdown whose
snapshot already dominates the replay increments nothing).

| Counter | Event that increments it | Resilience meaning |
|---------|--------------------------|--------------------|
| `ironbus_produced_total` | A message is appended by `produce`. | Throughput baseline (the denominator for shed/drop rates). |
| `ironbus_produced_bytes_total` | Logical message bytes (key + headers + payload) appended by `produce`. | Throughput / flash-wear baseline. |
| `ironbus_produce_rejected_total` | A `produce` is rejected because the durable log is at or over its byte cap (`max_total_bytes`), under the **drop-new** disk-full policy. Nothing is written and no offset advances. | **Shed** (drop-new backpressure): the broker refuses the *new* write to protect the disk. The producer is told; nothing already durable is lost. |
| `ironbus_delivered_total` | A delivery is handed out by `poll` (a redelivery counts again). | Delivery baseline. |
| `ironbus_redelivered_total` | A delivery whose lease had expired and the message was redelivered. | **Redelivery**: at-least-once retry, not loss. The signal that consumers are not acking in time. |
| `ironbus_dead_lettered_total` | A message exceeds `MaxDeliver` and is parked (committed past, moved to the DLQ sink). | **Dead-letter**: a poison message is removed from the main flow into the DLQ rather than looping forever. |
| `ironbus_dlq_records_total` | A record is durably written to the dead-letter sink. | DLQ depth (survives restart): the durable complement of `dead_lettered`. |
| `ironbus_acks_total` | A commit via `ack` (a `term` commits through the same path). | Commit baseline. |
| `ironbus_segments_reaped_total` | A whole old **sealed** segment is reclaimed by **consumer-safe** retention (the size, age, or count bound). | **Reclaim, loss-free**: only fully-consumed segments are freed. Space reclamation, never consumer-visible loss. |
| `ironbus_segments_force_reaped_total` | A whole old sealed segment is **force-reaped** by the disk-full **drop-oldest** policy to make room for an over-cap `produce`, ignoring consumer safety. | **Drop-oldest**: the data-loss-bearing reclamation. May delete records a slow consumer has not consumed; that consumer then sees a one-time truncation. |
| `ironbus_truncations_total` | A consumer's cursor had fallen **below the oldest retained record** (its data was force-reaped out from under it) and `poll` surfaces a one-time `Poll::Truncated`, resetting the cursor up to `earliest_retained`. One event per surfaced truncation (the same gap never re-counts). | **Skip**: a live consumer loses the span `[old_cursor, earliest_retained)`. Counted the moment it is surfaced so the skip is never silent. The consumer-side complement of `segments_force_reaped`. |
| `ironbus_truncated_records_total` | The sum of the skipped record span over every `Poll::Truncated`. | The **record count** lost to truncations (the span of `ironbus_truncations_total`). A **consumer-truncation** quantity, not in the durable loss report, so it keeps #306's snapshot-only lower bound and is **not** replay-reconciled (#307). |
| `ironbus_counter_checkpoint_repair_total` | A reconciliation on open raised a **recovery-loss** value (`ironbus_records_skipped`, `ironbus_bytes_skipped`, or the recovery-head component of `ironbus_last_skip_offset`) above its durable snapshot, because the **checkpoint-plus-replay** lower bound (`max(snapshot, durable log / loss report)`) implied a higher value than the cadence snapshot alone (#307). Zero when the snapshot already dominated the replay (the clean-shutdown case). | **Lower-bound recovery**: the signal that a hard crash (`kill -9`) lost post-snapshot recovery-loss increments and reconciliation restored them from the durable log, so the counter never silently resumes lower than before the crash. |
| `ironbus_consumer_labels_dropped_total` | A new consumer is refused a distinct `ironbus_consumer_lag_records{consumer}` series because the **1024-series cardinality cap** was reached; its lag is folded into `{consumer="__overflow__"}` instead (#97). | **Cardinality shed**: the registry refuses an unbounded number of distinct consumer labels (which would OOM the very node metrics protect), but the dropped label and its lag are never silent. An operator's cardinality-pressure signal. |
| `ironbus_dedup_hits_total` | An opt-in dedup `produce` carried a `msg_id` already seen within the producer's bounded window, so the broker returned the **original** offset (`PubAckDuplicate`, `duplicate = true`, `rc = 0`) and appended **no** second copy (#33). | **Dedup hit (benign)**: the effectively-once window absorbed a producer's retry rather than double-storing it. A non-zero rate means idempotent retries are being deduplicated, never an error. |
| `ironbus_dedup_out_of_window_total` | A `msg_id` aged out of a producer's window by the **time** bound (its dedup protection lapsed), so a later republish of that id would create a new offset rather than dedup (#33). | **Out-of-window**: the "is the dedup window too small for the retry interval" signal an operator watches to size `--dedup-max-ids` / `--dedup-window-ms`. |
| `ironbus_codel_shed_total` | A NEW `produce` is shed by the **CoDel** time-in-queue (sojourn) control: the standing produce-admission latency stayed above `--codel-target-ms` for a full `--codel-interval-ms` window (#68). | **Load shed** (latency backpressure): the broker refuses the *new* write to protect tail latency. Decided BEFORE the append, so it NEVER drops an already-accepted record (I2 holds). The producer is told via a typed "shed under load" reply. Zero unless CoDel is enabled. |
| `ironbus_codel_backstop_shed_total` | A NEW `produce` is shed by the **sojourn-independent depth/byte backstop** (#68): the admission ring depth bound, OR the durable-log byte cap (`max_total_bytes`), which sheds at enqueue even when a fully stalled drain produces no sojourn samples CoDel could see. | **Backstop shed**: bounds memory under a total drain stall that CoDel cannot detect. The byte-cap shed (`ironbus_produce_rejected_total`) also counts here as the BYTE dimension of the backstop, so this is the unified sojourn-independent shed signal. |
| `ironbus_codel_interval_resets_total` | CoDel detected a **suspend gap** (the monotonic clock jumped past a multiple of `--codel-interval-ms` with no intervening activity) and RESET its window, discarding the across-gap sojourns (#68). | **Suspend-safe**: a sleeping edge device that resumed did NOT misfire a burst of false sheds. A non-zero rate is benign (it means the suspend reset worked), not a loss. |
| `ironbus_retry_shed_total{side="broker"}` | A REDELIVERY is THROTTLED broker-side by the per-client **retry budget** (the Google SRE accept-based adaptive throttle): the client's recent accept rate fell, so the redelivery is DEFERRED (its lease deadline pushed out by the attempt's backoff), spacing the storm out (#69, #402). The `side` label is `broker` (the broker-side re-check; a future client library mirrors it as `client`). | **Anti-amplification, NO data loss**: a redelivery storm is rate-limited, but the throttle DEFERS (never drops): every at-least-once message still eventually redelivers until `MaxDeliver` routes it to the DLQ. Zero unless the retry budget is enabled. |
| `ironbus_fire_and_forget_shed_total` | A fire-and-forget (QoS-0) message is DROPPED by the per-connection **token bucket** because either bucket (message or byte) was empty (#69, #11). The producer set the `PUB_FLAG_FIRE_AND_FORGET` PUB flag and did not wait for a `PubAck`. | **Uncontrolled-tier cap**: the QoS-0 path is bounded to its configured rate so it cannot bypass the consumer-credit brake or starve credited traffic; the QoS-0 producer accepts the drop by contract. It sheds fire-and-forget messages and NOTHING ELSE (the at-least-once path is untouched). Zero unless the bucket is enabled. |
| `ironbus_egress_shed_total` | The **AIMD** egress limiter throttled a Flow batch below what the consumer wanted because it was falling behind (a would-block at the egress grant with a near-full in-flight set, or a nack), so the effective per-consumer egress credit was multiplicatively decreased (#69, #402). | **Egress backpressure**: a consumer falling behind has its effective egress credit halved (within the negotiated #292 cap) rather than the broker piling on, then it recovers additively as the consumer acks promptly. Zero unless the AIMD is enabled (`--egress-limit` non-zero). |
| `ironbus_wal_fsync_headroom_shed_total` | A NEW `produce` is shed by the **fsync-headroom** admission credit (#378): the un-fsynced (buffered-but-not-durable) backlog was at the configured `--wal-fsync-headroom-bytes` and a group-commit drain could not free it (only reachable under a relaxed durability level that defers the fsync). | **Un-fsynced backlog bound** (a memory / loss-window guard): the broker refuses the *new* write to keep the un-fsynced frontier within the headroom. Decided BEFORE the append, so it NEVER drops an already-accepted record (I2 holds). Under the default `sync` level the headroom THROTTLES (drain-then-admit) instead of shedding, so this stays `0` there; a rising value is a relaxed-level broker capping its loss window. |

### Recovery-loss series (startup, per reason)

Distinct from the runtime resilience counters above, these gauges report the
**last recovery's** loss (set at startup from the crash-recovery loss report),
broken down by `ReasonCode`. They are gauges, not `_total` counters, so they are
excluded from the frozen counter set by construction, but they are part of the
same "no silent loss" contract: a torn or corrupt tail dropped at recovery is
always reported, never silently accepted.

```
ironbus_recovery_truncated_bytes              total bytes dropped at the last recovery (the grand total, includes torn tails)
ironbus_recovery_data_loss_bytes              bytes of REAL data loss at the last recovery (the total with torn_tail excluded)
ironbus_recovery_loss_bytes{reason=...}       bytes dropped at the last recovery, by reason
ironbus_recovery_loss_records{reason=...}     records dropped at the last recovery, by reason
ironbus_quarantine_bytes                      persisted on-disk bytes of the forensic quarantine store (surviving restart)
```

`ironbus_recovery_data_loss_bytes` (#59) is the headline **bytes lost** figure: the loss report's
total with `TornTail` **excluded**, because a torn or unsynced tail is bytes that were never fully
written, not previously-durable data that was lost. Counting torn tails as data loss would inflate
fleet loss metrics on every clean power-loss restart, so they show up as a reported skip
(`ironbus_recovery_truncated_bytes` and the `torn_tail` per-reason series carry them) but NOT here.
Every other reason, including the appended `scrubber_suspect` (#92) and `unresolved_dict_id`
(#357, an intact but undecodable record whose compression dictionary is absent), DOES count. It is
a gauge (no `_total`), so it is outside the frozen counter set by construction.

`ironbus_quarantine_bytes` (#134, #315) is the **persisted on-disk footprint** of
the forensic **quarantine store**: the total bytes of the corrupt-byte copies
(copy-not-move, capped) that corruption skips have left in the `quarantine/`
subdirectory for offline analysis. A clean torn tail is not quarantined (there is
no forensic value), so this counts only genuine corruption. It is a gauge seeded
at startup from a one-time read-only scan of the durable blobs, so unlike a
this-recovery-only count it **survives a restart**: a clean reopen with no new
corruption skip still surfaces the real disk pressure prior recoveries' forensic
copies create, rather than reading 0. It is best-effort and never affects what
recovery recovered: the scan is read-only and a missing or unreadable quarantine
dir degrades to 0 without failing `Log::open`. Like the other recovery-loss gauges
it is excluded from the frozen `_total` counter set by construction.

The `reason` label is confined to the fixed `ReasonCode` enum (`torn_tail`,
`corrupt_record_header`, `corrupt_record_body`, `corrupt_segment_header`,
`sequence_gap`, `scrubber_suspect`, `unresolved_dict_id`); no offset, message-id, or subject is
ever a label. The
bounded-loss fail-closed recovery (refuse to exceed the loss cap) is the
companion control in the threat model.

## Operational gauges

These describe steady state, not events. They are not part of the frozen
resilience-counter set.

```
ironbus_committed_offset             the committed consumer cursor (default group)
ironbus_flushed_offset               the durable log head
ironbus_consumer_lag                 flushed minus committed (the headline lag signal)
ironbus_in_flight                    leased but not yet acked
ironbus_writer_healthy               1 live, 0 frozen (the integrity-freeze gauge)
ironbus_last_dead_lettered_offset    offset of the most recent dead-letter (-1 if none)
ironbus_records_skipped              records lost to recovery loss (the durable loss report total), reconciled to max(snapshot, durable loss report) so it never resumes lower than before a crash (#307)
ironbus_bytes_skipped                bytes lost to recovery loss, reconciled to max(snapshot, durable loss report) so it never resumes lower than before a crash (#307)
ironbus_last_skip_offset             highest log offset any skip/loss event reached, reconciled to max(checkpoint, replay) (#307)
ironbus_group_committed_offset{group=...}   per-work-group committed offset
ironbus_group_consumer_lag{group=...}       per-work-group lag
ironbus_group_in_flight{group=...}          per-work-group in-flight depth
```

`ironbus_records_skipped` and `ironbus_bytes_skipped` are the **recovery-loss**
record-count and byte-span gauges (the durable loss report totals). They are
gauges (not `_total`), so they are outside the frozen counter set, but they are
fully **checkpoint-plus-replay reconciled**: on open each is raised to
`max(snapshot, replay-from-the-durable-loss-report)`, so neither resumes lower
than before a crash, and a raise increments
`ironbus_counter_checkpoint_repair_total`.

`ironbus_last_skip_offset` is the highest log offset any skip/loss event reached
(a high-water mark). Its **replay** value is the recovered head a torn-tail
recovery landed on, i.e. an **upper bound** on the highest skipped offset, not the
exact last skip offset (recovery truncates to the last intact record, and any loss
reached up to that head). On open it is raised to `max(checkpoint, replay)`, so its
recovery-derived contribution is reconciled across a restart; its runtime
consumer-truncation contribution (raised to `earliest_retained` on a below-earliest
truncation) is not replay-derivable and keeps only the #306 snapshot lower bound.

The fsync latency histogram is `ironbus_fsync_seconds` (cumulative `le` buckets,
plus `_sum` and `_count`): the produce-time durability-barrier latency. A latency
distribution, not a resilience event, so it is also outside the frozen counter
set.

## Durability-level series (#341, #379)

These surface the active durability level and its power-loss exposure. They are
GAUGES (no `_total` suffix), so they extend the frozen `(name, type)` contract
(`FROZEN_METRIC_TYPES`) but are EXCLUDED from the resilience-counter taxonomy
(`FROZEN_RESILIENCE_COUNTERS`) by construction: a relaxed durability level is an
opt-in trade, not a resilience shed/loss event.

```
ironbus_durability_level_info{level=...}   the ACTIVE level (sync|interval|async|none), value always 1
ironbus_durability_power_loss_unsafe       1 if the active level WAIVES I2 (any relaxed level can lose acked data on a power cut), 0 under the power-loss-safe default sync
ironbus_durability_unsynced_bytes          acknowledged-but-not-yet-fdatasync'd record bytes currently at risk on a power cut; always 0 under sync, the live loss exposure under a relaxed level
```

Under the DEFAULT `sync` level, `ironbus_durability_level_info{level="sync"} 1`,
`ironbus_durability_power_loss_unsafe 0`, and `ironbus_durability_unsynced_bytes 0`:
a zero-config broker advertises itself as the safe durable level with no exposure.
An operator alerts on `ironbus_durability_power_loss_unsafe` crossing to `1` (the
broker can lose acknowledged data) and watches `ironbus_durability_unsynced_bytes`
as the live bytes-at-risk. The level + loss exposure are also in the startup
`materialized-config` line (`durability_level=`, `power_loss_safe=`). See
[DURABILITY.md](DURABILITY.md) for the per-level ack/loss contract.

## Cluster ack-level series (#605, #610)

The CLUSTER twin of the durability-level series: they surface the cluster's
durability posture — the cross-product of *where a record is durable* × *how many
replicas confirm it*. The cluster ack-level spectrum extends the single-node
`0/1/2` ack spectrum:

- `c0` — fire-and-forget (no ack).
- `c1` — leader local-fsync (today's single-node I2 ack, leader-only durability).
- `c2-pagecache` — a quorum has it in PAGE CACHE (NATS-R3-parity, **weaker**),
  offered only as an explicit, **loud opt-in** (it waives the quorum-fsync
  guarantee, surfaces `acked data may be lost if a quorum power-fails before
  fsync`, and falls back to `c2-fsync` if the opt-in is absent).
- `c2-fsync` — a quorum has `fdatasync`'d it. The **`R>=3` default** and the
  strongest level: an R-ack means fsync'd-on-a-quorum **by construction** (the
  honest beat over NATS R3, which acks on a quorum page-cache).

```
ironbus_cluster_ack_total{level=...}          records acked at each cluster ack level; level is c0|c1|c2_pagecache|c2_fsync (LABELED _total counter)
ironbus_cluster_ack_power_loss_unsafe         1 if the active SELECTED cluster ack level waives the quorum-fsync guarantee (c0|c1|c2-pagecache), 0 under the c2-fsync default or no cluster
```

`ironbus_cluster_ack_total` is a **labeled** `_total` counter, so — exactly like
`ironbus_retry_shed_total{side}` — its sample line is EXCLUDED from the
unlabeled-`_total` resilience-taxonomy test by construction and is pinned only in
`FROZEN_METRIC_TYPES`. A produce ack is an observability event, not a resilience
shed/loss, so it is outside `FROZEN_RESILIENCE_COUNTERS`.
`ironbus_cluster_ack_power_loss_unsafe` is a GAUGE (no `_total`), so it extends
`FROZEN_METRIC_TYPES` only, like its single-node sibling.

On a single-node / no-cluster broker every counter is `0` and the gauge is `0`:
the series exist (the frozen taxonomy requires them) and report the honest zero,
because no cluster ack level is selected (the default single-node ack is the
power-loss-safe local fsync). An operator alerts on
`ironbus_cluster_ack_power_loss_unsafe` crossing to `1` (a weaker-than-fsync
cluster durability mode is in use). The quorum-fsync MECHANISM behind `c2-fsync`
is the C2-I2 ISR / quorum-ack gate (#691); see the `cluster::ack_level` module doc
and `ironbus-clustering-design.md` §3.

## Backpressure series (#68, #69)

The backpressure shed COUNTERS are in the resilience-counter table above (every
shed is a `_total` the taxonomy guarantees is never silent). These GAUGES surface
the controllers' live state; they carry no `_total` suffix, so they extend the
frozen `(name, type)` contract (`FROZEN_METRIC_TYPES`) but are EXCLUDED from the
resilience-counter taxonomy (`FROZEN_RESILIENCE_COUNTERS`) by construction.

```
ironbus_codel_sojourn_estimate_ms          the current minimum-sojourn estimate (ms) the CoDel control law is acting on
ironbus_retry_ratio                        the observed retry (shed) rate as a fraction of the request rate, in parts-per-million (divide by 1e6); the 10%-budget signal
ironbus_egress_limit                       the current AIMD egress concurrency limit (between 4 and 128); halves on a degrading sink, climbs back as it heals
ironbus_wal_fsync_headroom_bytes           the configured fsync-headroom admission window in bytes (#378); 0 = disabled / unbounded
```

`ironbus_retry_ratio` makes the anti-amplification claim observable: an operator
watches it stay near or below the configured budget under overload.
`ironbus_egress_limit` makes the AIMD backoff visible. With every backpressure knob
at its disabling default the shed counters are `0` and the gauges report the inert
values (a `0` sojourn, a `0` ratio, the default `16` egress limit), so a zero-config
broker still emits the full series (the taxonomy is complete) with no shed activity.
See [BACKPRESSURE.md](BACKPRESSURE.md) for the control laws and the wire-signal
residual (the structured `retry_after_ms` / `shed` hint waits on #11).

## Edge-resource series (#118)

These surface the edge-specific resource pressures #118 names: flash write
amplification, RAM headroom against a configured ceiling, a portable
throughput-collapse signal, and an opt-in daily physical write budget (the
flash-wear governor). They are additive to the frozen taxonomy: the two
write-amplification byte counters and the over-budget shed counter are TYPE
`counter`; everything else is a gauge. The new GAUGES carry no `_total` suffix, so
the resilience-counter taxonomy test excludes them by construction; the one new
`_total` (`ironbus_daily_write_budget_sheds_total`) IS in the frozen taxonomy (a
shed is a resilience event that is never silent). Every name below is pinned by the
`(name, type)` golden test `the_metric_name_and_type_contract_is_frozen` (#22), so a
rename or type change fails CI until this doc and the contract are bumped together.

```
ironbus_logical_bytes_written          counter, bytes   STORED payload bytes appended this run (key + headers + payload as stored, post-compression under a non-`none` codec; no framing); the write-amplification denominator
ironbus_physical_bytes_written         counter, bytes   bytes actually written to segments this run (record frames + segment headers/footers); the real flash-wear write volume and the write-amplification numerator
ironbus_write_amp_ratio                gauge, ratio     physical / logical, rendered with 3 decimals (0.000 until the first byte is produced)
ironbus_ram_headroom_bytes             gauge, bytes     ram_ceiling_bytes minus the process RSS, or -1 when no ceiling is set or RSS is unavailable on this platform
ironbus_produce_saturated              gauge, 0|1       1 once the broker has shed at least one produce (admission exhaustion); a portable throughput-collapse signal, NOT a thermal sensor
ironbus_daily_physical_write_budget_bytes  gauge, bytes the opt-in daily physical write budget (0 = the flash-wear governor is off)
ironbus_physical_bytes_written_today   gauge, bytes     physical bytes written so far on the current UTC day (the daily-budget meter, reset at the UTC day boundary)
ironbus_daily_write_budget_over        gauge, 0|1       1 when the daily budget is set and today's physical writes have reached it (the broker is shedding produces to protect flash)
ironbus_daily_write_budget_sheds_total counter          produces shed because the daily physical write budget was reached (the governor firing); in the frozen resilience taxonomy
```

**Write amplification.** `ironbus_physical_bytes_written / ironbus_logical_bytes_written`
is the per-run flash write amplification: how many bytes of flash an SSD/eMMC wear
model is charged for each byte of stored payload, counting record framing (header +
trailer + length fields) plus segment headers and footers. Since the #430 write-path
compression wiring the denominator meters STORED (post-compression) payload bytes,
not the producer-facing logical bytes (`ironbus_produced_bytes_total` keeps that
producer-logical meaning): under the default `lz4` codec a compressible payload
shrinks the denominator, so the RATIO can inflate for small compressible payloads
even as the real flash wear per user byte falls. Both counters are
process-lifetime monotonic (a retention reap frees disk but does not un-write the
bytes a wear counter already charged), and reset to zero on each broker open (a run
starts a fresh amplification window). The derived `ironbus_write_amp_ratio` gauge is
rendered exactly, without floating point (integer milli-units), and is greater than
1 in practice (the framing always adds bytes).

**RAM headroom.** `ironbus_ram_headroom_bytes = ram_ceiling_bytes - RSS`, the bytes
of resident headroom before the kernel OOM-kills the process. The RAM ceiling is an
opt-in config knob (`ram_ceiling_bytes`, `0` = unset, the default); set it to the
cgroup/container memory limit or the device RAM budget (e.g. the 64 MiB `tiny`
profile). RSS is read best-effort, with NO `unsafe`: `VmRSS` from
`/proc/self/status` on Linux (the edge target), `ps -o rss=` on macOS (developers),
and unavailable elsewhere. When no ceiling is set OR RSS cannot be read, the gauge
reports the **`-1` unavailable sentinel** rather than a misleading maximal headroom
(the same `-1`-means-none convention `ironbus_last_dead_lettered_offset` uses). This
is pure observability: the engine never enforces the ceiling; the RAM bounds that
actually hold are `consumer_credit_bytes`, `max_in_flight`, `max_groups`, and the
bounded registry. See `crates/ironbus-server/src/rss.rs`.

**The tiny-profile edge-budget CI gate (#118).** These edge series are gated under
the `edge-tiny` profile by `crates/ironbus-cli/tests/edge_tiny_budget.rs`, which boots
the real `ironbus serve --profile edge-tiny`, runs a bounded workload, and scrapes
`/metrics`, asserting: the edge-tiny knobs are in effect (the #87 materialized-config
line), `ironbus_write_amp_ratio` is finite, non-zero, and strictly under the
documented `>= 4x fails` flash-endurance gate (see `docs/EDGE_CONSTRAINTS.md`), the
byte counters advanced with `physical >= logical`, `ironbus_ram_headroom_bytes`
reports the honest `-1` sentinel (the serve path wires no runtime RAM ceiling yet),
and `ironbus_produce_saturated` / `ironbus_daily_write_budget_over` read `0`. It
deliberately does NOT assert a tight RSS number: a precise RSS-under-the-64-MiB-ceiling
measurement is device-only (the `--ram-ceiling-bytes` follow-up), so a shared CI
runner's RSS can never flake the gate.

**Throughput-collapse signal.** `ironbus_produce_saturated` is the portable
saturation/throughput-collapse signal #118 asks for: `1` once the broker has shed at
least one produce (admission exhaustion via the daily-write-budget governor). It is
derived purely from in-process counters, so it is portable across every target. Per
#118 it is **throughput-derived, not a thermal sensor**: a chip-temperature gauge is
left as an optional, device-only add-on where a platform sysfs source exists (binding
the trigger to a Linux-only sensor would break the cross-platform binary), and is not
shipped here.

**Daily physical write budget (opt-in flash-wear governor).** Off by default
(`daily_physical_write_budget_bytes = 0`). When set, once today's physical write
volume (`ironbus_physical_bytes_written_today`, reset at the UTC day boundary on the
clock seam) reaches the budget, the next produce is **shed as a clean pre-write
drop-new reject**: the append returns the non-fatal, distinct
`StorageError::DailyWriteBudgetExceeded`, the engine counts it in
`ironbus_produce_rejected_total`, `ironbus_daily_write_budget_sheds_total` ticks,
`ironbus_daily_write_budget_over` reads `1`, and `ironbus_produce_saturated` flips to
`1`. The budget shed is a **separate error from the disk-full byte-cap shed**
(`StorageError::AtCapacity`) on purpose: no reap ever lowers today's physical-write
meter, so the budget shed is **FINAL under every `disk_full_policy`** and **never
triggers the `DropOldest` force-reap loop** (only the genuine byte-cap shed may
force-reap). It **never weakens durability** (the record is dropped, not written
unsynced), and the writer is not frozen (a budget shed is non-fatal). The first write
of each day is always admitted, so the broker always makes daily progress. The
dead-letter sink carries no budget (a poison record is durable evidence and must
never be shed).

## The bounded metric registry (#97)

The registry (`crates/ironbus-server/src/registry.rs`) makes leaving metrics on
permanently affordable on a few-hundred-MB ARM box: the per-message **append hot
path** never allocates and the registry **read side** a scrape walks (the
`for_each_series` visit, the cumulative-bucket reads, the overflow and uptime
reads) never allocates either, the registry has a **hard memory ceiling**
independent of the record count and disk size, and per-consumer lag is O(1) to
update and O(number of series) to scrape (it is **never** computed by scanning
the log).

Scoping note: the Prometheus **text exposition** the `/metrics` endpoint returns
is serialized into a `String` by `crates/ironbus-server/src/health.rs`, so
rendering that text body **does** allocate (an inherent, already-bounded cost of
the text format). The allocation-free guarantee is the per-message append path
and the registry read side that feeds the body, not the text serialization
itself. Tests pin exactly this: `the_append_and_commit_hot_path_does_not_allocate`
covers the append/commit path and `the_scrape_walk_does_not_allocate` covers the
registry read walk; neither claims the rendered text body is alloc-free.

### Fixed histogram buckets (compile-time, not runtime-configurable)

Two registry histograms share ONE fixed, compile-time bucket set in seconds, and
that set is **not** runtime-configurable (a runtime-tunable bucket set would
unbound the per-series memory):

```
{0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5}  (plus +Inf)
```

- `ironbus_fsync_duration_seconds`: the produce-time fsync (durability-barrier)
  latency, over the fixed buckets above.
- `ironbus_append_duration_seconds`: the whole durable-append (append + fsync)
  latency, over the **same** fixed buckets.

Each is a Prometheus histogram (cumulative `le` buckets, `+Inf`, `_sum`,
`_count`). The legacy `ironbus_fsync_seconds` histogram (its own bounds) is kept
unchanged for backward compatibility; the new `_duration_` series is the #97
fixed-bucket one.

### Per-consumer lag, with a hard cardinality cap

```
ironbus_consumer_lag_records{consumer=...}     per-consumer durable records produced but not yet committed
ironbus_consumer_lag_records{consumer="__overflow__"}   the folded lag of all over-cap consumers (only present once a label is dropped)
ironbus_consumer_overflow_saturated            gauge, 1 once the __overflow__ fold became a monotonic lower bound (see below)
```

`ironbus_consumer_lag_records` is maintained **incrementally**: the durable head
advances on append (O(1), one shared counter, regardless of the number of
series) and a consumer's commit floor advances on commit (O(1)); lag is
`head - committed`, the difference of two incrementally-maintained counts, so a
scrape is O(number of series) and never walks the log or the disk.

There is a **hard cap of 1024 distinct consumer series**. Past the cap a new
consumer is refused its own series, its lag folds into
`{consumer="__overflow__"}` (so the **total lag stays visible**), and
`ironbus_consumer_labels_dropped_total` (in the frozen taxonomy above)
increments. An unbounded consumer cardinality would OOM the very node the
metrics protect, so the cap and the overflow fold are mandatory.

The overflow fold is **idempotent**. The broker commits each consumer on every
ack (and on dead-letter commit, truncation reset, and once per group at open), so
an over-cap consumer arrives at the fold many times over its life. To avoid
double-counting, each distinct over-cap consumer's last committed floor is
tracked in a **bounded fold-ledger** (a second capped array, of the same fixed
1024-entry / 80-byte-per-entry cost as the series array, so it is part of the
hard ceiling, not an unbounded map): a re-commit **updates** that consumer's
contribution in place rather than accumulating. The consequences operators rely
on:

- `ironbus_consumer_labels_dropped_total` counts **distinct** consumer labels
  refused, **once each** on first fold, never per ack: it does not grow when an
  already-folded consumer commits again.
- `ironbus_consumer_lag_records{consumer="__overflow__"}` is the exact sum of the
  tracked over-cap consumers' true lags, so it **does not rise** as a folded
  consumer makes progress (a folded consumer committing a higher offset lowers
  its own term, exactly as a distinct series would).

If the bounded fold-ledger itself saturates (more **distinct** over-cap consumers
over the broker's whole life than the ledger capacity, which equals the
1024-series cap), a brand-new distinct over-cap consumer that cannot be tracked
individually falls back to a documented **coarse** behavior: it still increments
`ironbus_consumer_labels_dropped_total` (it is a distinct refused label), but its
lag is **not** folded into the `__overflow__` total, so that total becomes a
**monotonic lower bound** on the true folded lag rather than exact. This bound is
never wrong-high and never grows as folded consumers make progress. Saturation is
the rare past-1024-distinct-over-cap-consumer case; in the common case the
overflow total is exact.

`ironbus_consumer_overflow_saturated` (#321) surfaces exactly that saturation as a
scrape-visible **gauge** (`0` or `1`), so a Prometheus scraper can alert on it
directly rather than only via a Rust accessor. It is **1** once more than the
overflow-ledger capacity of **distinct** over-cap consumers have been seen over
the broker's lifetime, i.e. once `ironbus_consumer_lag_records{consumer="__overflow__"}`
has become a monotonic **lower bound** rather than the exact folded lag; **0** in
the common case (over-cap cardinality within the ledger capacity). It is a gauge
with **no `_total` suffix**, so it is excluded from the frozen resilience-counter
taxonomy by construction.

### Self-monitoring series

```
ironbus_build_info{version=...}      the build version as a label; the value is always 1
ironbus_start_time_seconds           the broker start time in Unix seconds (captured once at open)
ironbus_uptime_seconds               seconds since the broker started (monotonic-derived, never regresses on a wall-clock step)
```

Both `ironbus_start_time_seconds` and `ironbus_uptime_seconds` derive from the
injected clock seam (never a raw `SystemTime::now`/`Instant::now`), so the
deterministic simulation stays reproducible and uptime never goes backwards on
an NTP step.

### The memory ceiling (signed off against the #19 / #115 edge RAM budget)

The registry's resident cost is a **fixed** sub-100-series core plus the capped
consumer-series array and the equally-capped bounded overflow fold-ledger,
asserted by a test (`the_registry_memory_ceiling_is_fixed_and_bounded`):

```
ceiling = MAX_CONSUMER_SERIES (1024) x per-series cost (80 bytes, fixed-width inline label)
        + the bounded overflow fold-ledger (1024) x the same per-entry cost (80 bytes)
        + the fixed core state (two histograms + scalars, < 1 KiB)
       ~= 80 KiB + 80 KiB + < 1 KiB  <  256 KiB
```

The per-series (and per-ledger-entry) cost is fixed (an inline 64-byte label
buffer plus fixed-width bookkeeping, identical on 32-bit and 64-bit targets), so
the ceiling is INDEPENDENT of the record count, the disk size, and the number of
live consumers (both arrays are preallocated at the cap). At ~161 KiB it is a
small fixed slice of the 64 MiB `tiny`-profile RAM ceiling in
[RAM_BUDGET.md](RAM_BUDGET.md) (well under 0.3% of it), so leaving the full
metric surface on permanently is affordable on a 64 MiB edge node. This is the
#19 sign-off the issue requires.

## Dispositions that are deliberately NOT counted (and why)

The taxonomy is the set of **loss / shed / skip / freeze** events. Some
consumer-lifecycle dispositions are intentionally outside it because they are not
resilience-loss events:

- **Nack-requeue, fenced ack/nack, progress / progress-cap.** A nack requeues the
  message for redelivery (no loss); a fenced ack/nack is a stale-token no-op (the
  message is unaffected); a lease extension reports progress. Redelivery itself is
  counted by `ironbus_redelivered_total` when the requeued message is next
  delivered, so the at-least-once retry path is observable.
- **`term` (intentional drop).** Mechanically a commit through the `ack` path; an
  application's deliberate "discard this message" decision, not a resilience
  drop. It commits through `ironbus_acks_total` today. A future metrics split can
  give it its own counter (a deliberate, test-gated addition here); tracked under
  #96 if it is wanted.
- **Idle named-group eviction (#277).** Loss-free by construction: a group is
  evicted only when fully caught up at the head and lease-free, and only after its
  cursor is durably checkpointed at the head (a write failure keeps the group). A
  re-subscribe resumes from that checkpoint and redelivers nothing. It is a memory
  reclaim, not a skip or drop, so it has no resilience counter.

If any of these later needs a counter, it is added to the frozen taxonomy here
and in `FROZEN_RESILIENCE_COUNTERS`, never as a silent change.

## Health probes: `/healthz` liveness and `/readyz` readiness (#95)

The health server exposes two probes alongside `/metrics`:

- `GET /healthz` is **liveness** with a monotonic-clock HYSTERESIS WATCHDOG. The
  broker's accept loop ticks a monotonic "last progress" beacon on every iteration
  (a connection accepted, refused at the cap, OR the idle would-block poll), so the
  beacon advances even on a totally idle broker: a running loop is liveness whether
  or not it has work. `/healthz` compares `now_monotonic - last_progress` against the
  configurable window (`--health-liveness-window-ms`, default 10 s, `0` = disabled)
  and answers 503 ONLY after a whole window with no tick, which only a stuck (or
  crashed) accept loop produces. A slow-but-progressing fsync keeps it 200, a healthy
  idle node stays 200, and a writer frozen by a fatal fsync still returns `/healthz`
  200 (liveness is not readiness). All timing is on the monotonic clock seam
  (`Clock::now_monotonic_nanos`), never the wall clock, so an NTP step never drives
  liveness. The watchdog is read DIRECTLY off the clock, not through the append actor,
  so liveness measures the accept loop and never blocks on (nor is faulted by) a
  wedged writer.
- `GET /readyz` is **readiness** (the writer-frozen / shutdown gate): 503 while the
  durable-log writer is frozen by a fatal fsync or the broker is shutting down, 200
  once it accepts writes. Replay-in-progress readiness gating is a follow-up
  (recovery completes before the listener opens today, so a started broker has
  already replayed).

### Secure-bind default for the health surface

The whole health surface (`/metrics`, `/healthz`, `/readyz`, opt-in `/admin`) is
UNAUTHENTICATED and UNENCRYPTED today (TLS #107 and an auth identity #106 are
specified but not yet wired). Per the #107 bind invariant, `serve` therefore
REFUSES to start when `--health-addr` resolves to a non-loopback address, failing
closed before any listener opens, with an error that names the address and the
missing protections. The classification is on the RESOLVED address, so a hostname or
the wildcards `0.0.0.0` / `::` that map to a routable IP are caught; loopback binds
freely. `--health-allow-public` is the explicit operator acknowledgement that binds
a non-loopback surface anyway, with a loud startup warning on every start. There is
no such override for the wire `--addr` bind.

## The `/admin` read-only introspection endpoint (#99)

`GET /admin` is an opt-in (`serve --enable-admin`), read-only JSON view of
operational state on the same health server as `/metrics`, with the same trust
model: loopback by default, and any non-loopback bind carries the
widen-requires-auth precondition `/metrics` does (#107). It is strictly
read-only: no route mutates state, and every value is a projection of an existing
read-only engine accessor (mutating admin actions are deferred to #18/#14). The
schema version is pinned in the `Accept` header: a consumer that needs the exact
shape sends `Accept: application/vnd.ironbus.admin.v1+json`; an explicit non-v1
IronBus-admin media type gets `406 Not Acceptable`, while an absent or wildcard
Accept takes the current `v1`.

The v1 body is `{schema_version, broker, segments, consumers[], groups[],
resilience, dlq, config}` with four named sub-resources:

- `segments`: the durable-log span (`count`, `earliest_retained_offset`,
  `head_offset`, `durable_record_count`, `durable_record_bytes`).
- `consumers`: one row per work-group (`name`, `committed_offset`, the
  incremental `consumer_lag` = head minus committed, `in_flight`). `groups` is a
  byte-identical back-compat alias.
- `config`: an echo of the effective bounds (no secret material).
- `resilience`: `frozen` (the integrity-freeze flag, the inverse of healthy),
  `last_skip_offset`, `records_skipped`, `bytes_skipped`,
  `recovery_truncated_bytes`, `counter_checkpoint_repairs`.

The `ironbus admin --health-addr <host:port>` CLI renders segments, consumers,
lag, and the last-skip-offset from this body alone, never parsing a metric name,
so the diagnostics survive a metric rename and a dashboard break.

## Tracing and the OTLP export feature gate (#99, #352)

The broker instruments with the `tracing` crate and installs a JSON log layer by
default at `serve` startup. ERROR and WARN events (the corruption-skip, freeze,
and drop signals this contract forbids being silent) are always recorded
regardless of the head-based sampling ratio, which defaults to `0.0` so the
leanest edge build exports no sampled spans.

OTLP span export is behind the **non-default** `otlp` Cargo feature on
`ironbus-server` and is off at runtime by default; the default-shipped binary and
the size-optimized `edge-min` build link **zero** opentelemetry crates (verify
with `cargo tree --edges normal | grep opentelemetry`, which returns nothing on
the default build and the tree only with `--features otlp`). Export goes through
a bounded, lossy queue that **drops and counts** spans rather than blocking the
thread-per-core core, so a slow or unreachable collector can never stall a
produce.

### The concrete exporter (#352)

The concrete opentelemetry-otlp span exporter is wired and tested behind the
`otlp` feature. The queue, the drop counter, the sampling decision, and the
feature-gated compile-out are real on every build; the exporter itself is
compiled in **only** with `otlp`.

- **Transport: plaintext gRPC (tonic, no TLS).** This is the deliberate
  C-FFI-minimizing choice. OTLP to a co-located collector is plaintext
  `http://127.0.0.1:4317`, so no TLS stack is linked: the otlp build pulls
  **no** `rustls` / `ring` / `aws-lc` / `native-tls` / `openssl`, keeping even
  the feature build pure Rust (so the deny.toml `[bans]` C-FFI denylist, which
  `cargo deny check` evaluates over all features, stays green). The default graph
  is untouched either way.
- **Wiring.** When the broker is **built with** `otlp` and started with
  `serve --enable-otlp-export`, a dedicated drain thread (owning a small
  current-thread Tokio runtime, **off** the thread-per-core path) ticks the
  bounded span queue, maps each drained span onto an OTLP span honoring the
  head-based sampling decision, and ships the batch to the configured collector.
  A slow or down collector never blocks a produce: the queue keeps
  dropping-and-counting, and a failed ship is logged and discarded.
- **The flag.** `serve --enable-otlp-export` turns export on (off by default);
  `serve --otlp-endpoint <url>` (or `IRONBUS_OTLP_ENDPOINT`) sets the collector
  endpoint, defaulting to `http://127.0.0.1:4317`. On the **default build** (no
  `otlp` feature), `--enable-otlp-export` logs a clear
  `WARN: ... built WITHOUT the otlp feature` line and export stays off, so the
  flag is harmless on the shipped binary. The in-process recorder behavior is
  unchanged whenever export is off.
- **Building it in.** `cargo build --features otlp` (server) or
  `cargo build -p ironbus-cli --features otlp` (the broker binary). The MSRV
  (1.78) holds: the plaintext tonic path avoids the high-MSRV url/idna/icu crate
  family.

### Collector setup

Run any OTLP/gRPC collector on the endpoint, e.g.:

```shell
docker run -p 4317:4317 otel/opentelemetry-collector:latest
ironbus serve --data-dir /var/lib/ironbus \
  --enable-otlp-export --otlp-endpoint http://127.0.0.1:4317
```

(the broker must be built `--features otlp`). Plaintext gRPC; terminate TLS at a
sidecar/proxy if the collector is remote, since the exporter ships no TLS by
design.

## See also

- [USAGE.md](USAGE.md): the operator guide; the "Health and metrics" section
  links here for the full catalog.
- [THREAT_MODEL.md](THREAT_MODEL.md): the trust model the metrics endpoint
  shares, and the bounded-loss fail-closed recovery control.
- [INVARIANTS.md](INVARIANTS.md): the resilience invariants (I1 to I8) the
  counters make observable.
