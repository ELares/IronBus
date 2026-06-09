# The WAL under load and the on-disk file lifecycle

This document describes how IronBus absorbs a sustained high write rate and how the
on-disk files are created, sealed, and retired. It is derived from and cross-checked
against the source (the README and the code are both canonical; where they differ the
code wins, and those divergences are flagged below).

It is a behavior document, not a byte-layout reference. For the exact on-disk record,
segment, checkpoint, and DLQ byte layouts see [CONTRACTS.md](CONTRACTS.md); for the
shared invariants (I1 to I8) and the canonical glossary see
[INVARIANTS.md](INVARIANTS.md). The two frozen storage decisions this builds on are
[ADR 0001 (the active segment is the WAL)](adr/0001-log-is-wal.md) and
[ADR 0002 (v1 never recycles a segment id)](adr/0002-segments-never-recycled-in-v1.md).

Two things up front, because the design issue (#135) describes more than ships today:

- A large part of #135 is a *plan*, not the current code. This document marks every
  claim as IMPLEMENTED or SPECIFIED-BUT-PENDING, and there is a dedicated
  [Specified but not yet implemented](#specified-but-not-yet-implemented) section and a
  [Discrepancies with the #135 design intent](#discrepancies-with-the-135-design-intent)
  section. Each pending item was verified absent in the source, not merely omitted.
- Source of record: the storage layer is in
  `crates/ironbus-storage/src/{log,segment,checkpoint,dlq,loss,naming}.rs`, the record
  framing in `crates/ironbus-core/src/{format,codec}.rs`, and the produce/cursor/reap
  wiring in `crates/ironbus-server/src/engine.rs`.

---

## The model: the active segment is the WAL

IronBus has no separate write-ahead log. The active log segment *is* the WAL
(ADR 0001). The log is a chain of segment files in one data directory; exactly one of
them, the highest-numbered, is the *active* segment that receives appends. Its
predecessors are *sealed*: each carries a footer and is never written again.

A publish is one append to the active segment:
`Log::append` (`log.rs`) frames the record through the codec, writes it at the active
segment's write position, and assigns the next monotonic offset and sequence number.
The record becomes durable only when `Log::sync` calls `fdatasync` on the active
segment file (`SegmentWriter::sync` -> `RandomAccessFile::sync_data`). The engine's
`Engine::produce` (`engine.rs`) does exactly this: append, then `log.sync()`, and only
then return the offset, so a producer's ack is post-fsync (invariant I2,
ack-implies-durable, in INVARIANTS.md). There is one append path and one durability
barrier, not two structures to reconcile on recovery. The full durability CONTRACT this
grounds (the v1 single-`sync`-level guarantee, the crash and ack-ordering tests that
prove it, and the relaxed `interval` / `async` levels that are SPECIFIED but not shipped)
is in [DURABILITY.md](DURABILITY.md).

Why one path: the only durable artifact is the log, so recovery is replay of the log
itself, not a WAL-versus-store reconciliation. The cost (and benefit) is that the
framing, checksum, and recovery path have to be exactly right, which is the work the
record format and crash-recovery pin down.

### Single-writer, via the append actor

The storage `Log` is single-writer by contract: one owner appends (invariant I8). In
the server that single logical writer is a dedicated APPEND ACTOR thread that owns the
`Engine` (`actor.rs`, #177). Connection handlers fan in over a bounded `sync_channel`
and send commands; they never lock the engine and never hold a lock across an
`fdatasync`. The actor GROUP-COMMITS a drained batch of produces with one `fdatasync`
covering the batch, then acks the whole batch (so a `PubAck` still follows the covering
sync, invariant I2). A produce parked in the actor's fsync no longer head-of-line-blocks
every connection: pings (and anything needing no engine state) are answered by the
handler without touching the actor. The earlier `Mutex<Engine>` design held the lock
across the fsync, which froze every connection on a stalled disk; that is removed.

---

## File classes and their lifecycle

There are four kinds of on-disk file in a data directory. Recovery discovers segments
by listing the directory and parsing names; there is no manifest (`naming.rs`: "the
directory of self-describing files is the authority, no manifest required").

### 1. The active `.log` segment

- Name: `seg-<16-hex-id>.log` (`naming::segment_file_name`), e.g.
  `seg-0000000000000000.log`. The id is fixed-width lowercase hex so lexicographic
  order equals numeric order.
- Layout: a 64-byte header, then a contiguous run of record frames. No footer yet.
- Created: on a fresh log (`Log::open` creates segment id 0), or on every roll
  (`Log::start_segment` creates the next id). Creation writes and `fdatasync`s the
  header, then `fdatasync`s the parent directory, so a freshly created segment survives
  a power loss right after creation.
- Lifecycle: it is the WAL. It is **never deleted**. The reaper loops only while a
  second slot exists, which structurally keeps the active (last) slot off the table
  (`Log::reap`, `Log::reap_oldest_forced`). This is the "active segment is provably
  never deletable" property from #135, and it holds in code.

### 2. Sealed `.log` segments (header + records + footer)

- Same name pattern; the difference is on-disk content: a sealed segment ends in a
  32-byte footer (`SegmentFooter`: segment id, last sequence, record count).
- Created: a segment is sealed during a roll (`Log::roll` -> `SegmentWriter::seal`):
  the footer is written and the file gets a full `fsync` (`sync_all`). The seal of the
  old segment completes *before* the new active segment becomes discoverable, so a
  crash in between is recovered by rolling forward.
- Read trust: a footer is trusted as a seal only when it is consistent with the body
  (the record region decodes cleanly up to exactly the footer, and the footer's
  `record_count` and `last_seq` match the recovered records). A footer that disagrees,
  or 32 trailing bytes that merely look like a footer, is not trusted and the segment
  is recovered as unsealed. A body-consistent footer naming a *different* segment id is
  a hard error (`SegmentReader::scan` / `scan_recovery`).
- Reaped: only sealed segments are ever deleted, and only as whole files (see
  [Retention](#retention-deleting-whole-sealed-segments)).

### 3. The cursor checkpoints (`cursor.ckpt`, `cursor-<hex>.ckpt`)

- `cursor.ckpt` holds the durable default work-group's committed cursor.
  `cursor-<hex>.ckpt` holds a named work-group's cursor, where `<hex>` is the
  lowercase-hex-encoded group name (`engine.rs`: `group_checkpoint_name`). The default
  uses `cursor.` (a dot), the named form uses `cursor-` (a dash), so the two never
  collide.
- Format: a fixed two-slot, CRC32C-protected, alternating-write file
  (`checkpoint.rs`). Each write goes to the slot the sequence number selects and is
  `fsync`'d; on recovery the higher-sequence slot whose CRC validates wins, so a torn
  mid-write slot is ignored and the previous value survives. The checkpoint may regress
  to an earlier value after a crash (which only redelivers already-processed messages,
  at-least-once safe) but never advances to a torn or invented one.
- Created: `cursor.ckpt` is created (and the directory fsynced) on `Engine::open` if
  absent. A named group's file is created lazily on its first checkpoint write.
- Reaped: never deleted by IronBus. They are tiny fixed-size files, overwritten in
  place, not retired.

### 4. The resilience-counters checkpoint (`counters.ckpt`)

- `counters.ckpt` holds a durable snapshot of the resilience [counters](METRICS.md)
  (#98), so a restart resumes the operational history (produced, dead-lettered,
  reaped, truncated, etc.) instead of zeroing it.
- Format: the SAME fixed two-slot, CRC32C-protected, alternating-write file as the
  cursor checkpoints (`checkpoint.rs`), only with a slightly larger per-slot payload to
  hold the fixed set of `u64`s plus a version byte. The payload is `Counters::encode_snapshot`:
  a 1-byte version then the counters little-endian, decoded tolerantly so a short or
  trailing-padded payload never panics.
- Written: NOT on every counter increment (an fsync per produce/ack would kill
  throughput). It is snapshotted on the cursor-checkpoint cadence (`maybe_checkpoint`)
  and on the graceful-shutdown flush (`checkpoint_all_groups`). So the resumed counters
  are a monotonic **lower bound**: a crash loses at most the increments since the last
  snapshot, which observability tolerates.
- Recovery / safety: strictly an observability aid, NEVER correctness state. A torn or
  missing `counters.ckpt` recovers as all-zeros and never blocks `Engine::open` or
  affects the durable log, cursors, or DLQ. A counters write failure on the cadence is
  swallowed (lost history, never lost correctness); the explicit shutdown flush surfaces
  it but runs after the cursor flushes.
- Created: on `Engine::open` if absent (and the directory fsynced), exactly like the
  cursor checkpoint.
- Reaped: never deleted; a tiny fixed-size file overwritten in place.

### 5. The `dlq/` subdirectory (a second segmented log)

- The dead-letter sink (`dlq.rs`) is a *second* `Log` rooted at the `dlq/`
  subdirectory, so a poison record uses the exact same framed, CRC32C'd, recoverable
  segment format and is read by the same `SegmentReader` / `OfflineReader`. Inside
  `dlq/` you find the same `seg-<hex>.log` files (active and sealed).
- Created: lazily, on the first dead-letter (a message that exceeded `MaxDeliver`), or
  eagerly by `Engine::open` if the subdirectory already exists (so the per-group
  dead-lettered high-water mark, the idempotency key, is rebuilt before the first
  poison can redeliver). A broker that never dead-letters never creates `dlq/`.
- Reaped: the DLQ log is opened with **no total-byte cap** (poison records are durable
  evidence and must not be shed). It is not on the produce-path retention loop, so in
  the shipped code the DLQ is not auto-reaped.

There is no other on-disk state. In particular there is no index sidecar, no time
index, no `current` pointer file, and no manifest (all verified absent; see
[below](#specified-but-not-yet-implemented)).

---

## Behavior under a high write rate

Under load three things keep the append path cheap and the file set bounded.

### Segment roll cadence

The active segment has a soft size cap, `LogConfig::max_segment_bytes` (default
64 MiB). `Log::append` rolls *before* appending when the active segment's write
position has reached the cap and it holds at least one record. The check is
at-or-over and before the write, so a segment may overshoot the cap by at most the last
record, and an empty segment is never rolled (an oversized record larger than the cap
still gets written, to its own segment). Rolling seals the old segment and starts a
fresh, higher-id one. Under sustained writes this produces a steady stream of fixed-size
sealed segments, each bounded by the cap.

`LogConfig::new` rejects a `max_segment_bytes` below a floor
(`MIN_MAX_SEGMENT_BYTES`, large enough to hold the header, the footer, and at least
two minimum records), so a too-small cap cannot silently fragment the log into
one-record segments.

### O(1) append accounting (the running totals)

The log keeps running totals so the per-append work does not grow with the number of
segments:

- `sealed_record_bytes`: the total durable record bytes across every *sealed*
  predecessor, advanced by the sealed segment's record region on each roll.
- `total_record_count`: the total durable record count across every segment, advanced
  on each append and decremented by a reaped segment's count on a reap.
- Each in-memory `SegmentSlot` carries the sealed segment's `record_count` and
  `max_timestamp_ms`, frozen from the writer's running totals at seal time (and
  recomputed identically at recovery).

So `durable_record_bytes()` (sealed total plus the active segment's live bytes) and
`durable_record_count()` are O(1) reads, and the byte-cap check, the count-retention
check, and the age-retention check never rescan the segment set. `max_timestamp_ms`
tracks the *maximum* (not the last) record timestamp, because producer timestamps are
not monotonic and the age reaper must know when *every* record in a segment has aged
out.

### Overflow: shed (drop-new) or drop-oldest, never spill-into-a-second-log

There is an optional hard cap on total durable record bytes,
`LogConfig::max_total_bytes` (default 0 = unlimited). When it is set and the log is at
or over it, `Log::append` rejects the produce with the non-fatal
`StorageError::AtCapacity` and writes nothing: no offset or sequence advances, and the
writer stays live (a later produce succeeds once retention frees space). A record on an
empty log is always written, so an oversized first record is not wedged out.

What happens on an over-cap produce is the engine's disk-full policy
(`EngineConfig::disk_full_policy`, `engine.rs`):

- `DropNew` (the default): the rejection is final. The producer is told promptly via
  `AtCapacity`, the `produce_rejected` counter increments, and nothing is written. This
  is the "shed" half of the spill-then-shed policy. Durable topics use it (newest data
  is shed, older accepted data preserved).
- `DropOldest` (opt-in): on `AtCapacity` the engine reclaims space and retries. It
  first runs the consumer-safe reaper (in case retention is also configured and can
  free a fully-consumed segment with no data loss), then, if still over cap,
  `Log::reap_oldest_forced` deletes the *oldest sealed* segment ignoring
  consumer-safety, then retries the append. The loop is bounded: if only the active
  segment remains there is nothing left to force out, so it falls back to the drop-new
  rejection (a single oversized in-flight set cannot wedge the log empty). A consumer
  whose records were force-reaped out from under it gets a one-time truncation signal
  on its next poll (see [recovery and truncation](#crash-mid-write-and-truncation)).
  Telemetry topics use it (freshest data matters most).

### Back-pressure in v1

There is no producer stall in v1. `block` (stall the producer until space frees) is out
of scope; the `DiskFullPolicy` enum is `#[non_exhaustive]` so a later `block` variant
is not a breaking change, but it does not exist today. Back-pressure surfaces as the
explicit `AtCapacity` rejection (drop-new) or as forced reclamation plus a truncation
signal (drop-oldest), never as an unbounded queue or a hidden latency spike. The
consumer side has its own credit window (`max_in_flight` per group, `consumer_credit`
per connection), which bounds in-flight delivery but is not the write-path back-pressure
this document covers.

---

## Retention: deleting whole sealed segments

Retention is the cleanup pipeline: it frees disk by deleting whole old sealed segments,
never the active one and never part of a segment.

`Log::reap` (driven by `Engine::reap_for_retention` after each successful, durable
produce) deletes the oldest sealed segments under three composable bounds
(`RetentionBounds`), each independently disabled with 0 and all 0 by default
(retention off):

- `max_bytes`: delete while the log's total durable record bytes exceed this.
- `max_age_ms`: delete a sealed segment whose *maximum* record timestamp is older than
  `now - max_age_ms`, i.e. every record in it has aged out. `now` comes from the engine
  clock seam, so the deterministic simulation drives it, never the host wall clock.
- `max_messages`: delete while the total durable record count exceeds this.

A sealed segment is eligible when *any enabled* bound says it should go, but eligibility
never overrides consumer safety. The reaper deletes a segment only if every record in it
is below the protect floor, which the engine passes as the **minimum committed offset
across every work-group** (`min_committed_offset`), so the slowest group's unconsumed
records are never reaped. The default group always exists, so the floor is well-defined;
a fresh group at offset 0 keeps the floor at 0 (reaping nothing) until it consumes
something.

Crash-safety and accounting (the same for `reap`, `reap_to_size`, and
`reap_oldest_forced`): the segment file is unlinked and the directory fsynced (so the
removal is durable) *before* the slot leaves memory and the running
byte/count totals are decremented by exactly that segment's record region and count. A
crash before the in-memory update leaves the slot and totals untouched (memory never
claims a segment is gone while it survives on disk); a crash after leaves a shorter
contiguous chain with a non-zero start, which recovery already accepts and recomputes
the totals from. So after any reap the running totals still equal a fresh reopen's
recomputed values. Because ADR 0002 forbids recycling, a reaped segment leaves a hole at
the bottom of the id space; the id is gone for good.

### The disk-full drop-oldest primitive

`Log::reap_oldest_forced` is the `DropOldest` reclamation primitive: it force-reaps the
single oldest sealed segment *ignoring* consumer-safety, returning `None` when only the
active segment remains. It can delete records below a slow group's cursor; the engine is
responsible for surfacing the resulting truncation to that group.

### Optional key-based compaction (#337): the opposite of the reaper

Compaction is the IMPLEMENTED, OPT-IN, OFF-BY-DEFAULT counterpart to the reaper. The reaper
deletes WHOLE sealed segments by age/size/count, cheaply, never looking inside. The COMPACTOR
(`Log::maybe_compact` over `crate::compaction`) looks INSIDE a run of adjacent dirty sealed
segments, keeps the latest record per key (plus a tombstone within its 24h TTL, plus every
keyless record), and rewrites only those SURVIVORS into a fresh `version=2` compacted segment,
KEEPING each survivor's ORIGINAL offset and sequence. The result is a SPARSE offset range:
offsets are never renumbered or reused, so I5 holds (it removes offsets, never invents one). It
is for changelog/state-snapshot topics, costs CPU and flash, and so is OFF by default.

The clean is write-new-then-retire-originals whose SINGLE commit point is the durable appearance
of the new compacted segment (the directory fsync), after which the originals are
unlink-then-dir-fsynced (the same drain-safe discipline the reaper uses). A crash at any step
recovers deterministically: the originals win before the commit, the compacted segment after,
never a torn mix. Recovery resolves an overlapping range from the v2 covered-range footer
metadata, with no manifest. It runs OFF the hot path (only sealed segments, only a new file,
never the active segment), so it never races or blocks an append. The order with retention is
fixed (`compact_and_delete`): the cheap whole-segment reaper runs FIRST, then the compactor. The
full design, the survivor rules, and the crash-recovery argument are in
[COMPACTION.md](COMPACTION.md); the v2 byte layout is in [CONTRACTS.md](CONTRACTS.md).

---

## Crash mid-write and truncation

### Torn-tail truncation on recovery

`Log::open` recovers the highest segment. If it is unsealed, recovery scans it
(`scan_recovery`, one record at a time so peak memory is one record), takes the longest
valid prefix, and truncates any torn or unsynced tail back to the last intact record
(`set_len` to `valid_end`, then `sync_all`). The dropped span is recorded as
`recovered_truncated_bytes` and as a structured `LossReport` event carrying the byte
span and a reason. If the highest segment is sealed (a crash after sealing but before the
next segment was created), recovery rolls forward and creates the next segment.

This is invariant I1 (durable prefix) and I4 (recovery is a pure function of the durable
bytes), pinned in INVARIANTS.md. Only synced records survive a power loss; an unsynced
tail is dropped.

### Bounded loss caps

Recovery fails closed rather than accept unbounded silent loss (#120, I3). `Log::recover`
computes a per-event cap (the runtime segment size or 64 MiB, whichever is smaller) and a
global cap (1% of durable bytes, floored at the per-event cap so a normal small-log torn
tail is always within bounds) and runs `LossReport::check_caps`; exceeding either is
`StorageError::ExcessiveRecoveryLoss`, a recovery failure.

### The truncation signal to a lagging consumer

When `DropOldest` force-reaps a prefix out from under a group, the group's committed
cursor can fall below the oldest retained offset. On the next poll the engine detects
`committed < earliest`, resets the cursor up to `earliest_retained` (dropping the now
meaningless acked-ahead set and in-flight leases), and returns `Poll::Truncated` once,
so the caller emits an in-band truncation advisory and the consumer learns it lost the
span `[old_cursor, earliest_retained)` rather than silently skipping it. The same gap
never re-truncates.

---

## The checkpoint cadence

The committed cursor is checkpointed on an interval, not per ack, to bound crash
redelivery while keeping the checkpoint write rate far below one per ack (edge flash
endurance). `Engine::maybe_checkpoint` writes the cursor when it has advanced at least
`checkpoint_interval` offsets since the last checkpoint (a value of 0 is treated as 1,
checkpoint on every advance). A clean disconnect also flushes the cursor
(`checkpoint_cursor`), which additionally captures any acked-ahead set even when the
watermark did not advance. The checkpoint is an optimization: it may lag the true
committed cursor (a crash then redelivers a few already-processed messages) but never
records an offset that was not committed.

Note: in the shipped code the checkpoint records the *consumer* cursor. The #135
"recovery checkpoint (durable point)" that gates segment deletion is a different,
not-yet-implemented watermark (see below). Today the segment-deletion gate is retention
plus the slowest-consumer cursor (the protect floor), with no separate durable-point
watermark on top.

---

## The knobs

All of these are `ironbus serve` flags (`crates/ironbus-cli/src/main.rs`), mapped onto
`EngineConfig` / `LogConfig`.

| Flag | Field | Default | What it does |
| --- | --- | --- | --- |
| `--max-segment-bytes` | `LogConfig::max_segment_bytes` | 64 MiB | Soft roll cap on the active segment. Rejected below `MIN_MAX_SEGMENT_BYTES`. |
| `--max-total-bytes` | `LogConfig::max_total_bytes` | 0 (unlimited) | Hard cap on total durable record bytes. At/over it, a produce is shed with `AtCapacity`. |
| `--max-retained-bytes` | `EngineConfig::max_retained_bytes` | 0 (off) | Size retention bound: reap fully-consumed sealed segments while over this. |
| `--max-age-ms` | `EngineConfig::max_age_ms` | 0 (off) | Age retention bound (ms): reap a sealed segment once all its records are older than this. |
| `--max-messages` | `EngineConfig::max_messages` | 0 (off) | Count retention bound: reap while total record count exceeds this. |
| `--checkpoint-interval` | `EngineConfig::checkpoint_interval` | 1024 | Checkpoint the cursor after it advances this many offsets. |
| `--disk-full-policy` | `EngineConfig::disk_full_policy` | `drop-new` | `drop-new` (shed) or `drop-oldest` (force-reap the oldest sealed segment then accept). |

The 8 MiB edge segment size exists as a constant (`EDGE_SEGMENT_BYTES` in
`core/src/format.rs`) but is **not** wired to a profile switch; to use it today you pass
`--max-segment-bytes 8388608` explicitly (see the discrepancies section).

---

## Specified but not yet implemented

Each item below is described in #135 (or the README) but was verified ABSENT in the
source as of this document. They belong to the seal-then-retire *plan*, not the shipped
code.

- **Index sidecars (`.index`, `.tindex`).** #135's seal path "finalizes and fsyncs the
  derived `.index` and `.tindex` sidecars." No such files are created or read anywhere.
  Reads scan segment files directly (`SegmentReader::scan`); the offset index is derived
  in memory (the sorted `SegmentSlot` list plus a binary search), not persisted. The
  README's "derived offset / time index" is in-memory and rebuilt on startup.
- **A `current` pointer file.** #135's seal "advances the `current` pointer atomically
  (write-temp, rename, fsync parent dir)." There is no pointer file; the active segment
  is simply the highest-id `seg-*.log` in the directory.
- **A manifest / manifest edit log.** #135 has the reaper and append actor mutate a
  manifest. There is none, by design: `naming.rs` states the directory of
  self-describing files is the authority.
- **Preallocation (`fallocate`) and generation-stamped recycling.** #135 preallocates
  segments to full roll size and recycles up to 2 sealed-then-deleted files. Neither
  exists: segments grow as records are appended, and ADR 0002 forbids recycling a
  segment id in v1 (nonce-reuse safety for encryption at rest), pinned by the test
  `segment_ids_increase_monotonically_and_are_never_recycled`. There are no generation
  tags in the segment header. The cross-platform preallocation design (the four-primitive
  shim, default-ON preallocation to roll size, per-OS implementations, and the
  ENOSPC-at-roll fail-fast path) is now SPECIFIED in
  [PREALLOCATION.md](PREALLOCATION.md), which also resolves the recycling question
  honestly: v1 never recycles, and no generation stamp is added to the #5 header because,
  with ids never reused, it is unnecessary (recycling becomes a v2 nonce-safety decision,
  #40).
- **A dedicated append actor + commit thread, group-commit batching, admission
  credits.** The single append actor and group-commit batching are now SHIPPED (#177):
  `actor.rs` owns the `Engine`, drains a batch of queued produces, and issues one
  `fdatasync` per drained batch (the storage "one write plus one sync per group"). What
  is still NOT present from the #135 sketch is the explicit 1 MiB group-commit byte cap
  (the actor drains whatever is available each pass rather than to a byte target) and the
  fsync-headroom admission credits; the bounded `sync_channel` provides backpressure in
  their place. A separate commit thread distinct from the append thread is not split out.
- **A separate recovery-checkpoint (durable-point) deletion watermark.** #135 gates
  deletion on the minimum of three watermarks, one of which is a `(durable_seq,
  durable_offset)` durable point published by a checkpointer on every roll / 1000 ms
  debounce / >= 4 MiB advance. The shipped checkpoint records the consumer cursor only;
  deletion is gated by retention bounds and the slowest-consumer protect floor, with no
  separate durable-point watermark and no debounce/byte-advance trigger.
- **A 90% disk high-water-mark forced reaper run and a periodic janitor timer.** #135's
  reaper is event-driven on every seal plus a 60 s age timer plus a forced run at 90%
  disk. The shipped reap runs only on the produce path (after each successful produce) or
  via the `DropOldest` reclaim loop; there is no disk-usage high-water trigger and no
  standalone timer.
- **`retention.consumer_safe` toggle and a per-consumer max-lag escape hatch.** #135
  exposes a `consumer_safe` flag (and an open question about a lag escape hatch).
  Consumer-safe retention (`Log::reap`) is always consumer-safe; the *only* way to delete
  below a lagging cursor today is the explicit `DropOldest` disk-full policy, which then
  emits the truncation signal. There is no `consumer_safe` config field.
- **An archival offload sink.** #135 mentions an archival sink (`WAL_ttl_seconds` analogue,
  a `state=1 offloaded` enum). It does not exist; there is no offload. (The optional, opt-in,
  key-based COMPACTOR that #135 mentioned alongside it is now IMPLEMENTED, #337; see the
  retention-and-compaction note below.) The archival offload sink remains unspecified.
- **A `quarantined` segment side-state.** The README and the resilience story mention
  quarantining an unreadable segment. The lifecycle states in code are active / sealed
  (plus reaped); a corrupt segment surfaces a typed `StorageError` at scan time rather
  than entering a persisted `quarantined` state.

---

## Discrepancies with the #135 design intent

These are places where the implementation and the #135 text diverge in a way worth
flagging (beyond the simply-not-yet-built items above). The code wins.

- **"Edge profile" is not a profile.** #135 and the README say segments default to
  64 MiB "or 8 MiB on the edge profile." There is no profile selection in the code; the
  default is always 64 MiB, and `EDGE_SEGMENT_BYTES` (8 MiB) is an unused constant unless
  an operator passes `--max-segment-bytes 8388608`.
- **Segment roll is by size only; the 24 h / age roll is not on the active segment.**
  #135 and the README say a segment rolls at "64 MiB or 24 h, whichever comes first"
  (and `DEFAULT_SEGMENT_ROLL_HOURS = 1` exists as a constant). `Log::append` rolls on the
  size cap only; there is no time-based active-segment roll. Time appears only in *age
  retention* of already-sealed segments (`max_age_ms`), which is a different mechanism.
- **The seal-state machine is two states, not six.** #135 specifies
  `active -> sealing -> sealed -> eligible -> deleting -> deleted` plus `recycled` and
  `quarantined`. The code has active and sealed segments and an unlink; the intermediate
  states, the recycle state, and the quarantine state are not modeled.
- **Deletion is gated by two watermarks, not three.** #135's "minimum of checkpoint,
  retention, and slowest-cursor" reduces, in code, to retention bounds AND the
  slowest-consumer protect floor. There is no separate durable-point checkpoint watermark
  in the deletion gate.
- **The `LossReport` reason for a sequence gap differs between the schema and the
  recovery path.** `loss.rs` defines `ReasonCode::SequenceGap` (code 5) for a
  checksum-valid record with an out-of-order sequence, and its doc says the segment is
  "abandoned at that record." But the recovery scan (`scan_body_streaming` in
  `segment.rs`) treats an out-of-order-but-valid frame as a hard
  `StorageError::RecoveredSequenceMismatch` (recovery fails) rather than emitting a
  `SequenceGap` loss event and continuing. So `SequenceGap` is defined in the schema but
  not produced by the current recovery path; the reasons recovery actually emits are
  `TornTail`, `CorruptRecordHeader`, and `CorruptRecordBody`. (`ReasonCode::CorruptSegmentHeader`,
  code 4, is likewise defined but never constructed in production: a bad segment header fails
  the open with a typed `StorageError` rather than being recorded as a loss event.)
- **The README's "spill to disk then shed" is, for a single durable log, just "shed."**
  There is no second spill buffer to spill *into*; the active segment is already on disk,
  so "spill then shed" collapses to: keep appending until the byte cap, then drop-new
  (or drop-oldest). This is consistent with ADR 0001 (one log, no second structure), but
  the "spill" wording can mislead.
- **The DLQ is not retained/reaped.** #135 treats every sealed segment as reapable under
  the three watermarks. The DLQ sink's log is opened with no byte cap and is not on the
  produce-path retention loop, so its segments are not auto-retired (intentional: poison
  records are durable evidence).

---

## Where the verification lives

- Roll, seal, recovery, torn-tail, retention, force-reap, and accounting:
  `crates/ironbus-storage/src/log.rs` and `segment.rs` unit tests, and
  `crates/ironbus-storage/tests/crash_recovery.rs`.
- Checkpoint crash-safety (two-slot, torn-slot fallback, single-byte-corruption
  property): `crates/ironbus-storage/src/checkpoint.rs`.
- DLQ exactly-once move and idempotency: `crates/ironbus-storage/src/dlq.rs`.
- Produce/reap/truncation wiring: `crates/ironbus-server/src/engine.rs`.
- The bounded-loss schema and caps: `crates/ironbus-storage/src/loss.rs`.
