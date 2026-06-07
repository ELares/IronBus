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
```

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
