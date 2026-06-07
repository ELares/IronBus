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
histogram below). Counters are monotonic statistics (they only increase). They
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
| `ironbus_truncated_records_total` | The sum of the skipped record span over every `Poll::Truncated`. | The **record count** lost to truncations (the span of `ironbus_truncations_total`). |
| `ironbus_consumer_labels_dropped_total` | A new consumer is refused a distinct `ironbus_consumer_lag_records{consumer}` series because the **1024-series cardinality cap** was reached; its lag is folded into `{consumer="__overflow__"}` instead (#97). | **Cardinality shed**: the registry refuses an unbounded number of distinct consumer labels (which would OOM the very node metrics protect), but the dropped label and its lag are never silent. An operator's cardinality-pressure signal. |

### Recovery-loss series (startup, per reason)

Distinct from the runtime resilience counters above, these gauges report the
**last recovery's** loss (set at startup from the crash-recovery loss report),
broken down by `ReasonCode`. They are gauges, not `_total` counters, so they are
excluded from the frozen counter set by construction, but they are part of the
same "no silent loss" contract: a torn or corrupt tail dropped at recovery is
always reported, never silently accepted.

```
ironbus_recovery_truncated_bytes              total bytes dropped at the last recovery (the grand total)
ironbus_recovery_loss_bytes{reason=...}       bytes dropped at the last recovery, by reason
ironbus_recovery_loss_records{reason=...}     records dropped at the last recovery, by reason
ironbus_quarantine_bytes                      corrupt bytes copied into the forensic quarantine store at the last recovery
```

`ironbus_quarantine_bytes` (#134) is the byte total the forensic **quarantine
store** copied (copy-not-move, capped) from a corruption skip into the
`quarantine/` subdirectory for offline analysis. A clean torn tail is not
quarantined (there is no forensic value), so this counts only genuine corruption.
It is a gauge (set at startup), best-effort, and never affects what recovery
recovered: a quarantine write failure leaves it below the dropped bytes without
failing `Log::open`. Like the other recovery-loss gauges it is excluded from the
frozen `_total` counter set by construction.

The `reason` label is confined to the fixed `ReasonCode` enum (`torn_tail`,
`corrupt_record_header`, `corrupt_record_body`, `sequence_gap`,
`segment_chain_gap`); no offset, message-id, or subject is ever a label. The
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
ironbus_group_committed_offset{group=...}   per-work-group committed offset
ironbus_group_consumer_lag{group=...}       per-work-group lag
ironbus_group_in_flight{group=...}          per-work-group in-flight depth
```

The fsync latency histogram is `ironbus_fsync_seconds` (cumulative `le` buckets,
plus `_sum` and `_count`): the produce-time durability-barrier latency. A latency
distribution, not a resilience event, so it is also outside the frozen counter
set.

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

## See also

- [USAGE.md](USAGE.md): the operator guide; the "Health and metrics" section
  links here for the full catalog.
- [THREAT_MODEL.md](THREAT_MODEL.md): the trust model the metrics endpoint
  shares, and the bounded-loss fail-closed recovery control.
- [INVARIANTS.md](INVARIANTS.md): the resilience invariants (I1 to I8) the
  counters make observable.
