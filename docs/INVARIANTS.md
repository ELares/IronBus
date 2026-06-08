# IronBus invariants and glossary

The shared invariants every IronBus subsystem must hold, plus a glossary of the
load-bearing terms. This is the canonical, cross-subsystem reference that issue
[#131](https://github.com/ELares/IronBus/issues/131) freezes: one numbered
invariants list and one glossary that every other issue cites, so a term like
"offset", "durable", "committed cursor", or "torn tail" means the same thing in
every subsystem.

This document is derived from and cross-checked against the actual code and the
top-level `README.md`, both of which are canonical. Where the issue text and the
implementation diverge, the CODE wins and the divergence is flagged inline. For
the exact on-disk and on-wire byte layouts (field offsets, frame sizes,
checksums), see the byte-layout contracts doc, which is the companion to this
one; this doc states the invariants and defines the vocabulary, and does not
duplicate the field tables.

A note on numbering. This document uses two distinct, separately-numbered
invariant lists, and they are NOT the same set:

- The **shared invariants I1 to I8** below are the cross-subsystem statements
  from issue #131. They are the contract every subsystem is written against.
- The **resilience invariant checkers I1 to I4** are a SEPARATE, smaller,
  independently-numbered set implemented as pure functions in
  `crates/ironbus-storage/src/invariants.rs`. They check recovery output (the
  recovered records, the durable ack history, and the loss report). Their I1 to
  I4 do not line up one-to-one with the I1 to I8 here; the mapping is given in
  the "Resilience invariant checkers" section. This mismatch is a real divergence
  from the issue, which assumed #21's checkers would reference the exact I1 to I8
  statements; today they do not.

---

## Shared invariants (I1 to I8)

Each invariant has a precise statement, why it holds (the mechanism), and where
it is enforced or tested. An invariant that is specified but not yet enforced in
code is in the "Specified, enforcement pending" section, not here.

### I1: durable prefix

**Statement.** At every write boundary, recovery yields a contiguous prefix of
the accepted-offset sequence: offsets `0, 1, ... n-1` with matching per-segment
sequences, no reordering, and no hole below the durable head. Recovery never
reads past a torn or partially written tail.

**Why it holds.** Each segment is scanned one record at a time, validating each
frame (magic, version, header CRC32C, body CRC32C) and the sequence run. The
scan stops at the first torn or corrupt frame, so the valid prefix ends exactly
at the last intact record. A frame whose declared length runs past the region, or
whose header or body fails its checksum, ends the prefix rather than being
half-read. Across the chain, each segment's `base_offset` and `base_seq` must
continue from its predecessor, and every non-final segment must be sealed, so the
recovered run is a single contiguous sequence.

**Where.** Per-segment scan: `SegmentReader::scan_recovery` and
`scan_body_streaming` in `crates/ironbus-storage/src/segment.rs` (the torn-tail
and corrupt-frame stops set `tail_reason` to `TornTail`,
`CorruptRecordHeader`, or `CorruptRecordBody`). Chain validation and the
roll-forward of a crash that left the highest segment sealed:
`Log::scan_recover_chain` and `Log::recover` in
`crates/ironbus-storage/src/log.rs` (`SegmentChainBroken`,
`UnsealedPredecessor`). The prefix property is asserted by
`check_longest_valid_prefix` (the checker labeled I2) in
`crates/ironbus-storage/src/invariants.rs`, with negative fixtures
`i2_negative_fixture_a_gap_in_offsets` and
`i2_negative_fixture_a_broken_sequence`, and by the crash-recovery and
determinism sweeps in `crates/ironbus-storage/tests/`.

### I2: ack implies durable (conditioned on `durability_level=sync`)

**Statement.** Under the DEFAULT durability level `sync`, no ack is observable for
a record that is not covered by a returned `fdatasync` on the active segment. The
active segment IS the write-ahead log; there is no separate WAL file.

This invariant is CONDITIONED on `durability_level=sync` (the default, #341,
#379). The relaxed levels (`interval`, `async`, `none`) are a STRICTLY OPT-IN
exception: they ack BEFORE the covering `fdatasync` and so WAIVE I2 by design, each
carrying its own weaker, documented guarantee instead (see below and
[DURABILITY.md](DURABILITY.md) section 3). An operator who changes nothing runs
`sync`, so I2 holds for every default broker and zero acknowledged data is lost on
a power cut.

**Why it holds (under `sync`).** The append path reserves the next offset and
sequence, writes the framed record, then returns the offset; the record becomes
durable only after `Log::sync`, which calls the file's `sync_data` (`fdatasync`).
Under `sync` the engine's `commit_batch` issues that covering `fdatasync` BEFORE
the append actor releases the ack, so the producer-visible ack follows the
covering fsync. A failed fsync is treated as fatal: it freezes the writer
read-only (the active segment is dropped) and surfaces `WriterFrozen` rather than
acking, so a record is never acked on a failed durability barrier (under every
level: even a relaxed level surfaces the fatal `WriterFrozen` rather than acking a
record the writer can no longer own).

**The relaxed levels' weaker guarantee (I2 waived, by opt-in).** Under
`interval` the ack follows the page-cache `write()` and a background window forces
the `fdatasync` every `flush_interval_ms` / `flush_max_bytes`, so the worst-case
acknowledged loss on a power cut is BOUNDED by the smaller of those two triggers
(at most one flush window). Under `async` the fsync is opportunistic (a roll's
seal or a clean shutdown), so the loss is unbounded until the next such barrier;
`none` removes the periodic window entirely (the largest window). The active level
and its loss exposure are observable (`ironbus_durability_power_loss_unsafe`,
`ironbus_durability_unsynced_bytes`, `ironbus_durability_level_info`, and the
materialized-config line), and the unbounded-loss levels refuse to boot without an
explicit data-loss acknowledgement. The engine `commit_batch` advances the visible
head via `Log::flush_no_sync` (page-cache, no fsync) for a relaxed deferred batch,
and `Engine::force_sync` (on a clean shutdown) plus a segment roll's seal are the
real barriers.

**Where.** `Log::append` and `Log::sync` in
`crates/ironbus-storage/src/log.rs` (the freeze-on-failed-fsync is in `sync`).
The append-then-sync-then-ack ordering is in `Engine::produce` in
`crates/ironbus-server/src/engine.rs`. The durability model itself is in the
`RandomAccessFile` seam (`sync_data` versus `sync_all`) in
`crates/ironbus-storage/src/io.rs`; the `InMemoryFile` model reverts a
data-only-synced truncation on a simulated power loss
(`fix/inmem-fdatasync-metadata`), and the crash classes are exercised by the
seeded fault-recovery sweeps in `crates/ironbus-storage/tests/` (including the
seeded fault scheduler and the same-seed determinism gate in
`tests/seeded_faults.rs`, where one `u64` seed drives the whole crash workload and a
failing case replays from the printed seed, #384). The README
states it directly: "durable on one node by calling `fdatasync` before it
acknowledges a write". The opt-in ack-on-buffer modes named in the issue (the
`interval` / `async` / `none` durability levels) ARE now implemented (#341, #379)
as a strictly opt-in exception to I2: they are off by default, the unbounded-loss
ones are gated behind an explicit data-loss acknowledgement, and they carry their
own documented bound instead of I2. See [DURABILITY.md](DURABILITY.md) section 3.

### I3: bounded, reported loss

**Statement.** A corruption skip loses at most one bounded region per event, the
loss is always reported (never silent, never partial within a record), and it is
capped: at most one segment or 64 MiB per event, and at most 1% of durable bytes
per recovery. Exceeding either cap freezes the log read-only.

**Why it holds.** Every dropped byte span is recorded as a structured
`LossEvent` (segment id, start and end byte offsets, bytes skipped, a
lower-bound record-loss estimate, and a `ReasonCode`) in a versioned
`LossReport`. Recovery computes the per-event cap as the smaller of the runtime
segment size and 64 MiB, and the global cap as 1% of durable bytes floored to the
per-event cap (so a normal torn tail on a tiny log is always in bounds), then
calls `LossReport::check_caps`. A violation returns
`StorageError::ExcessiveRecoveryLoss`, which fails the open rather than accepting
unbounded silent loss. The loss is never partial within a record because the
record CRC32C gates resync: a frame either passes its checksums whole or ends the
valid prefix.

**Where.** The schema, the caps, and `check_caps`:
`crates/ironbus-storage/src/loss.rs` (`LossEvent`, `LossReport`, `ReasonCode`,
`CapViolation`, `PER_EVENT_BYTE_CAP`, `GLOBAL_LOSS_CAP_NUMERATOR` over
`GLOBAL_LOSS_CAP_DENOMINATOR`). The enforcement at recovery (push the event,
compute the caps, fail closed): the I3 block of `Log::recover` in
`crates/ironbus-storage/src/log.rs`. The reusable assertion:
`check_bounded_loss` (the checker labeled I3) in
`crates/ironbus-storage/src/invariants.rs`. Tests:
`check_caps_rejects_a_single_oversized_event`,
`check_caps_rejects_a_cascade_over_the_global_cap`, and
`global_loss_cap_is_one_percent_rounding_down` in `loss.rs`. The README records
the same cap: "at most one segment or 64 MiB per event, at most 1 percent of
durable bytes per recovery".

### I4: recovery is a pure function of the durable bytes

**Statement.** Recovering twice from the same durable image produces identical
records. Recovery consults no wall clock, no ambient state, and no order other
than the on-disk byte order.

**Why it holds.** The scan is a deterministic walk over the segment files in
ascending id order, validating frames and the sequence run; it reconstructs the
running maximum timestamp from the records themselves (not the host clock) for
the age-retention reaper. There is no randomness and no host-time read in the
recovery path.

**Where.** `Log::recover` and `scan_body_streaming` in
`crates/ironbus-storage/src/{log,segment}.rs`. The purity assertion:
`check_pure_recovery` (the checker labeled I4) in
`crates/ironbus-storage/src/invariants.rs`, with negative fixtures
`i4_negative_fixture_diverging_payloads` and
`i4_negative_fixture_different_lengths`. The streaming scan is pinned to agree
with the buffered scan (`scan_recovery` versus `scan`) and the determinism
sweeps in `crates/ironbus-storage/tests/determinism.rs` re-run recovery from an
identical image.

> Note. The issue's I4 is "checkpoint-lower-bound" (a checkpoint names only a
> `(durable_seq, durable_offset)` already fsync'd, and recovery treats it as a
> floor and re-validates forward). That property is real and implemented (see
> I5b below and the checkpoint clamp in the engine), but the code's checker
> numbered I4 is "pure recovery", a different statement. This is one of the
> numbering divergences flagged at the top.

### I5: offset is monotonic across recovery

**Statement.** The offset counter never regresses and never reuses a value across
a crash, a recycle, or a restart. The same holds for the per-segment sequence.

**Why it holds.** Offsets and sequences are minted by reserving the NEXT value
before the write returns, so a record is never durably written under an id the
log cannot advance past. On recovery, the next offset and next sequence are
recomputed as the sum of every segment's `base + record_count`, so they continue
from the recovered head, never below it. The id newtypes are exhaustion-loud:
`Offset::checked_next` and `Seq::checked_next` return `None` (a hard failure)
rather than wrapping, and the offset space treats `u64::MAX` as exhausted rather
than reusing 0.

**Where.** `Offset` and `Seq` in `crates/ironbus-core/src/types.rs`
(`checked_next`, and the doc contract that `None` is a loud failure).
`Log::append` reserves before writing; `Log::recover` and
`scan_recover_chain` recompute `next_offset` and `next_seq` from the chain, in
`crates/ironbus-storage/src/log.rs`. `AckCursor::ack` refuses to overflow the
range end at `u64::MAX` (`acking_the_max_offset_never_overflows_or_collapses_committed`
in `crates/ironbus-core/src/cursor.rs`).

#### I5b: checkpoint lower bound (committed cursor)

**Statement.** A committed-cursor checkpoint names only an offset that was
already acked, never one that was not committed; it may lag the true cursor (a
crash then redelivers a few already-processed messages, which at-least-once
permits) but never leads it. On recovery the checkpoint is treated as a floor and
clamped to the durable head.

**Why it holds.** The cursor's `committed` watermark only advances over a
contiguous acked prefix (see "committed cursor" in the glossary), so a
checkpoint of it can never name an unacked offset. On open, the recovered
committed offset is clamped to `min(recovered, flushed)` (the durable log head),
and a debug assertion guards a checkpoint that exceeds the head; the acked-ahead
ranges are filtered to those strictly above the clamped watermark and at or below
the head. The persisted acked-ahead snapshot is CRC32C-validated, and a corrupt
or torn snapshot falls back to the committed-only resume rather than restoring a
broken cursor.

**Where.** `AckCursor` (the `committed` watermark, `ahead` ranges,
`resume_with_ahead`, `encode_snapshot` / `decode_snapshot` with the trailing
CRC32C) in `crates/ironbus-core/src/cursor.rs`. The clamp on recovery:
`resume_cursor_from_snapshot` in `crates/ironbus-server/src/engine.rs`
(`recovered_committed <= flushed` assertion, the `min(committed, flushed)`
clamp, the `start > committed && end <= flushed` filter). The checkpoint
durability (two-slot, CRC'd): `crates/ironbus-storage/src/checkpoint.rs`.
Tests: the snapshot round-trip and single-bit-flip proptests in `cursor.rs`,
the checkpoint corruption proptests in `crates/ironbus-storage/tests/`.

### I6: ordering never consults the wall clock

**Statement.** Offset and per-segment sequence alone order and (when dedup is
enabled) deduplicate records. No wall-clock read affects ordering. Wall-clock
timestamps are data, used only for retention age, lag age, and the time index,
never for ordering.

**Why it holds.** The append actor assigns a strictly monotonic offset per
accepted record; the record's `timestamp_ms` is a stored field, not an ordering
key. Recovery reconstructs order from on-disk offset and sequence, never from the
timestamp (it takes the MAX timestamp across the prefix precisely because
producer timestamps are not monotonic). The clock seam separates the two time
sources: a monotonic clock for durations (lease deadlines, sojourn) and a wall
clock for record timestamps, and only the former drives any decision, never
ordering.

**Where.** The monotonic-versus-wall split: `Clock` in
`crates/ironbus-core/src/clock.rs` (the doc states the wall clock "can jump or
move backwards", the monotonic clock "never moves backwards within a run"). The
order-from-offset assignment: `Log::append` in
`crates/ironbus-storage/src/log.rs` and the `Offset` doc in
`crates/ironbus-core/src/types.rs`. Recovery's MAX-timestamp reconstruction (not
last, not an ordering use): `scan_body_streaming` in
`crates/ironbus-storage/src/segment.rs`. The opt-in per-producer dedup window
(#33) is keyed by `msg_id` only, never the body, and its TIME bound reads the
MONOTONIC clock (not the wall clock), so an NTP step can never mis-expire the
window: `DedupRegistry` in `crates/ironbus-core/src/dedup.rs` (pure, IO-free, the
caller supplies monotonic `now`), wired on the produce path via
`Engine::append_no_sync_dedup` in `crates/ironbus-server/src/engine.rs`. The
optional PERSISTENT `producer_id` high-water that survives a restart is the one
residual (see pending); the in-memory window is session-scoped and lost on
restart by default.

### I8: single writer

**Statement.** Exactly one logical writer mints offsets and owns the active
segment file descriptor at a time.

**Why it holds.** The engine is synchronous and owns the one `Log`; the network
server wraps it behind a `Mutex` (`SharedEngine = Arc<Mutex<Engine>>`), so all
access is serialized and one append actor owns the engine. The `SegmentWriter`
is the single owner of the active segment's file handle; readers open their own
handles and never write.

**Where.** `SharedEngine` (the `Mutex`-serialized engine) in
`crates/ironbus-server/src/server.rs`; the single-writer comment in
`crates/ironbus-server/src/engine.rs`; the single-owner `SegmentWriter` and the
single-writer note in `crates/ironbus-storage/src/{segment,log}.rs`; the
`Offset` doc ("assigned by the single append actor") in
`crates/ironbus-core/src/types.rs`.

> Note (I7, integrity before transform). The issue's I7 is "CRC32C over the
> outermost on-disk bytes is verified before decrypt and before decompress". The
> CRC-first half is real and enforced: `codec::decode` verifies the header CRC32C
> then the body CRC32C (and only then the optional xxh3-64) before returning a
> record, and CRC32C gates resync. The decrypt and decompress halves are NOT
> enforced today because encryption-at-rest and compression are not implemented:
> only the `COMPRESSED` and (future) encryption flag bits are reserved. I7 is
> therefore listed under "Specified, enforcement pending".

---

## Other always-on invariants

These are not in the issue's numbered list but are load-bearing and enforced in
code, so a subsystem author must hold them too.

- **Bounded resources, no unbounded queues.** In-flight work is a sliding window
  of at most `max_in_flight` offsets above the committed cursor (the
  max-ack-pending bound), and per connection at most `consumer_credit` un-acked
  messages; the effective bound is the min of the two. The lease table size is
  bounded by max-in-flight; the acked-ahead set is bounded by the same window.
  The number of live work-groups is capped by `max_groups`. The durable log can
  be capped by `max_total_bytes` (the drop-new shed) and reclaimed by retention.
  Where: `EngineConfig` and `Engine::poll_in` / `produce` /
  `append_with_policy` in `crates/ironbus-server/src/engine.rs`; the credit
  accounting via `LeaseTable::holds_active` in `crates/ironbus-core/src/lease.rs`;
  the byte cap in `Log::append` / `LogConfig` in
  `crates/ironbus-storage/src/log.rs`.

- **Recovery truncates a torn tail and never replays stale recycled bytes.** A
  CRC-valid frame carrying an out-of-order sequence is a recycled or mixed-up
  file and is a HARD error (`RecoveredSequenceMismatch` / the `SequenceGap`
  reason), not a torn tail: recovery does not accept it as data. Where:
  `scan_body_streaming` and the sequence-continuity check in
  `crates/ironbus-storage/src/segment.rs`;
  `scan_recovery_reports_a_recycled_frame_with_a_bad_seq`.

- **At-least-once leases with a hard cap, fenced against double-ack.** A
  delivered message is in-flight for a visibility timeout (default 30s); only an
  explicit ack removes it; an unacked lease redelivers; `progress` extends the
  deadline by one window but never past a hard cap (default 5 minutes) measured
  from the attempt start, so a stuck consumer cannot hold a message forever. Each
  grant stamps a strictly increasing generation token; a late ack from a holder
  whose lease was already redelivered is fenced (a no-op), so a redelivery never
  double-acks. Where: `LeaseTable` in `crates/ironbus-core/src/lease.rs`
  (`claim`, `ack`, `extend`, `nack`, the generation fencing, the hard-cap clamp);
  proptest `only_the_latest_token_ever_acks`, and
  `extend_defers_redelivery_but_never_past_the_hard_cap`.

- **Exactly-once DLQ move keyed by (group, source offset, attempt).** A poison
  message (over `max_deliver`) ends up in EXACTLY ONE durable place: appended and
  fsync'd to the DLQ sink, THEN the source cursor is committed past it. A crash in
  the window leaves the source uncommitted (it redelivers and re-poisons) while
  the DLQ record is already durable; on reopen the per-group dead-lettered
  high-water mark, rebuilt from the DLQ sink itself (no sidecar), suppresses the
  duplicate append. Where: `Engine::dead_letter_in` (the append-fsync-then-commit
  ordering, the `already_dead_lettered` idempotency check) in
  `crates/ironbus-server/src/engine.rs`; the sink and its high-water-mark recovery
  in `crates/ironbus-storage/src/dlq.rs`; the IO-free disposition decision in
  `crates/ironbus-core/src/delivery.rs`. Tested by a fault-injected crash mid-move
  yielding exactly one DLQ entry with no duplicate on a second crash.

  > Divergence to flag. The issue and the DLQ module doc both name the
  > reconciliation key `(group, source_offset, attempt)`, but the runtime
  > idempotency check (`DlqSink::already_dead_lettered`) keys on
  > `(group, source_offset)` against the per-group high-water mark; the `attempt`
  > is stored in the DLQ record and is part of the logical key, but it does not
  > participate in the dedup test (a given source offset dead-letters once per
  > group regardless of attempt). This is correct for the move (a source offset
  > is poisoned once), but the (group, offset) wording is the precise enforced
  > key.

---

## Resilience invariant checkers (the code's I1 to I4)

`crates/ironbus-storage/src/invariants.rs` implements four pure checkers over
recovery output. They are a SEPARATE, independently-numbered set from the shared
I1 to I8 above. Each is a pure function returning the first
`InvariantViolation` or `Ok(())`, and each has a known-bad negative fixture in
its tests so a checker that always passes is itself caught.

| Code checker | Statement | Maps to shared invariant |
| --- | --- | --- |
| I1 `check_no_acked_loss` | every acked-durable offset is present in the recovered log | I2 (ack implies durable) |
| I2 `check_longest_valid_prefix` | recovered records are a contiguous prefix `0..n` with matching sequences | I1 (durable prefix) |
| I3 `check_bounded_loss` | the loss report is within the per-event and global caps | I3 (bounded, reported loss) |
| I4 `check_pure_recovery` | two recoveries from the same durable image are identical | I4 (pure recovery) |

The cross-cutting takeaway: the checker numbers and the issue's I1 to I8 numbers
are not the same scheme. The issue assumed #21's checkers would reference the
exact I1 to I8 statements; they do not yet. Aligning them (or renaming one set)
is open work tracked under the invariant-checker harness, #120.

---

## Specified, enforcement pending

These are named in the issue or the README but are not enforced in code today.
Listed so a contributor does not mistake a spec for a guarantee.

- **I7 integrity before transform (decrypt and decompress halves).** CRC-first
  is enforced (`codec::decode` in `crates/ironbus-core/src/codec.rs` verifies the
  header then body CRC32C before the xxh3-64, and CRC32C gates resync). The
  "before decrypt" and "before decompress" halves are not enforced because
  encryption-at-rest and compression are not implemented yet: of the relevant
  record flag bits in `crates/ironbus-core/src/types.rs` only `COMPRESSED` is
  defined (no encryption bit is allocated yet; the flags byte simply has
  reserved space). Tracking: compression #12 / #139, encryption-at-rest #18.

- **Opt-in ack-on-buffer durability levels (I2 exception): IMPLEMENTED.** The
  README lists `fdatasync` (default), `interval`, and `none` durability modes. All
  are now implemented (#341, #379): `sync` (the fsync-before-ack default that holds
  I2), plus the strictly opt-in `interval` (bounded loss), `async`, and `none`
  (unbounded loss, gated behind `--async-loss-ack`) levels. They are the
  explicitly-labeled, off-by-default exception to I2; I2 above is conditioned on
  `durability_level=sync`. Tracking: durability #6, #341, #379. No longer pending.

- **Persistent producer-id high-water (part of I6, #33).** The opt-in per-producer
  dedup window IS implemented (`ironbus_core::dedup::DedupRegistry`, wired on the
  produce path, keyed by `msg_id`, dual count + time bound on the monotonic clock,
  epoch fencing, the `PubAckDuplicate` tag-20 dedup-hit response, and the
  `ironbus_dedup_hits_total` / `ironbus_dedup_out_of_window_total` counters). It is
  SESSION-scoped: the in-memory window is lost on broker restart by default. The one
  residual is the OPTIONAL durable `producer_id` + epoch high-water in the WAL that
  would let dedup survive a restart; the in-memory window and its epoch fencing are
  shipped, the WAL persistence is the deferred follow-up. Tracking: queue semantics #3.

- **The full invariant-checker harness and corpus wiring.** The pure checkers
  exist (`invariants.rs`), but the harness that runs I1 to I8 against the corpus
  fixtures and the deterministic simulation as one suite, and that aligns the
  checker numbering with the shared I1 to I8, is not complete. Tracking:
  invariants and checkers #120, verification #21.

- **Loom / concurrency model checking.** No `loom` model exists in the tree
  today; the single-writer property (I8) is held structurally by the `Mutex`,
  not yet proven under a concurrency model checker. Tracking: #122.

- **Versioned loss-report wire schema `ironbus.loss-report.v1`.** The structured
  `LossReport` exists with `SCHEMA_VERSION = 1` and stable `ReasonCode` numeric
  codes (`crates/ironbus-storage/src/loss.rs`), and it derives `serde`. The
  issue asks for it to be frozen under the name `ironbus.loss-report.v1` with one
  versioned definition all consumers cite; the in-code schema is the source of
  truth, but the named, externally-versioned artifact is not separately frozen
  yet. Tracking: corruption skip #8, observability #16, verification #21.

---

## Glossary

Crisp, consistent definitions of the terms a contributor must share. Each is
defined as the code uses it.

- **offset.** A monotonically increasing `u64` position in the durable log,
  assigned by the single append actor, `+1` per accepted record, never reset and
  never reused within a queue's lifetime; offset 0 is the first record.
  Authoritative for ordering. `crates/ironbus-core/src/types.rs` (`Offset`).

- **sequence (seq).** A per-record `u64` that is unique and monotonic WITHIN a
  single segment. A record's sequence must fall in
  `[base_seq, base_seq + record_count)` for its segment; a value outside that
  range marks the record stale or torn during recovery.
  `crates/ironbus-core/src/types.rs` (`Seq`).

- **segment.** One file in the log: a 64-byte header, a contiguous run of record
  frames, and (once sealed) a 32-byte footer. Default roll size 64 MiB (8 MiB on
  the edge profile). A record never spans two segments.
  `crates/ironbus-storage/src/segment.rs`, sizes in
  `crates/ironbus-core/src/format.rs`.

- **active vs sealed segment.** The ACTIVE segment is the single one currently
  appended to; it IS the write-ahead log. A SEALED segment is finalized with a
  durable footer and never appended to again; sealing fsyncs every record in it.
  Exactly one segment is active at a time. `crates/ironbus-storage/src/log.rs`
  (`roll`, `start_segment`).

- **the WAL (log-is-WAL).** There is no separate write-ahead log file. The active
  log segment IS the WAL: a publish is one framed, checksummed, record-aligned
  append to the active segment, and that append is the durable record. The offset
  index is derived and rebuilt on startup. README "How it works"; ADR
  `docs/adr/0001-log-is-wal.md`.

- **cursor / committed offset.** A work-group's committed offset (watermark): the
  next offset to deliver, below which EVERY offset is acked. It advances only over
  a contiguous acked prefix. Out-of-order acks at or above it are held in a sparse
  acked-ahead set until the gap below them fills, then the watermark jumps over
  the now-contiguous run. `AckCursor` in `crates/ironbus-core/src/cursor.rs`.

- **lease / visibility timeout / fence token.** A delivered message is leased
  (in-flight) for a visibility timeout (default 30s); only an explicit ack
  removes it, and an unacked lease redelivers after the timeout. Each grant
  carries a fence (generation) token; ack and extend carry the token they were
  issued under, and an operation whose generation no longer matches the current
  lease is fenced (a no-op), which makes cross-member reclaim race-free and
  prevents a double-ack. A hard cap (default 5 minutes from the attempt start)
  bounds how long `progress` can extend a single attempt.
  `LeaseTable` / `LeaseToken` in `crates/ironbus-core/src/lease.rs`.

- **work-group (competing) vs broadcast.** A work-group is a set of consumers
  that SHARE one committed cursor and one in-flight lease set over the log, so
  they compete to drain the work (each message goes to one live member). A
  broadcast subscriber is its own group, so it sees every message. Groups are
  independent: each named group has its own cursor and lease generation space.
  `Engine::poll_in` and `WorkGroup` in `crates/ironbus-server/src/engine.rs`.

- **default group.** The unnamed group `""`, which always exists. Its durable
  cursor is `cursor.ckpt`; it is the floor for retention (its committed offset
  participates in the min-committed protect floor). `DEFAULT_GROUP` in
  `crates/ironbus-server/src/engine.rs`.

- **credit (per-consumer in-flight) and the in-flight window.** Two bounds on
  un-acked work. The in-flight WINDOW is per-GROUP: at most `max_in_flight`
  offsets above the committed cursor (the max-ack-pending bound). CREDIT is
  per-CONSUMER (per-connection): at most `consumer_credit` un-acked messages a
  single connection may hold (default 64). A Flow delivers
  `min(requested, ceiling - already_held, group window)`, so the effective bound
  is the min of the two. `EngineConfig` (`max_in_flight`, `consumer_credit`) in
  `crates/ironbus-server/src/engine.rs`.

- **DLQ / poison / max-deliver.** A message delivered more than `max_deliver`
  times (default 5) is POISON: it is routed to the dead-letter queue (DLQ), a
  second segmented log under `dlq/`, and committed past in its source group rather
  than redelivered forever. The disposition decision is
  `Disposition::DeadLetter`. `crates/ironbus-core/src/delivery.rs`,
  `crates/ironbus-storage/src/dlq.rs`, `Engine::dead_letter_in`.

- **truncation signal.** A one-time `Poll::Truncated` a group receives when its
  committed cursor has fallen below the oldest retained record (its data was
  force-reaped by the drop-oldest policy). The cursor resets UP to
  earliest-retained and the truncation surfaces exactly once; a later poll no
  longer re-truncates the same gap. `Engine::poll_in` (the `committed < earliest`
  branch) in `crates/ironbus-server/src/engine.rs`.

- **earliest_retained / earliest offset.** The lowest offset still on disk. It
  rises above 0 only once retention or the drop-oldest policy has reaped a prefix.
  A consumer below it is reset with one truncation event.
  `Log::earliest_offset` / `Engine::earliest_retained_offset`.

- **the IO / clock seams.** Two trait boundaries that make the engine
  deterministic and testable. The IO seam is `RandomAccessFile` /
  `Filesystem` (positional reads and writes, `sync_data` versus `sync_all`,
  `set_len`), so storage runs over a real file or an in-memory fault-injecting
  model. The clock seam is `Clock` (a wall clock for record timestamps, a
  monotonic clock for durations); engine logic never reads `SystemTime::now` or
  `Instant::now` directly. `crates/ironbus-storage/src/io.rs`,
  `crates/ironbus-storage/src/fs.rs`, `crates/ironbus-core/src/clock.rs`.

- **MSRV.** Minimum Supported Rust Version: 1.78 (pinned at the workspace root
  and gated by a CI job). It may rise only in a minor release, with the new floor
  always at least 6 months old. `Cargo.toml` (`rust-version = "1.78"`),
  `.github/workflows/ci.yml` (the `msrv` job), README "Key decisions".

- **frozen-tag discipline.** Two related freezes. The on-disk and on-wire formats
  are FROZEN at v1: the format version, the record and segment magics, the field
  offsets, the frame sizes, and the wire frame tags do not change, and dedicated
  tests pin them (`frozen_sizes`, `frozen_values`, the frozen-tag wire test).
  Separately, a RELEASE is cut by pushing a signed version tag, and re-running a
  release for an already-published tag fails closed.
  `crates/ironbus-core/src/format.rs`, `crates/ironbus-proto/`, `RELEASING.md`.

- **durable.** Bytes covering the record have returned from `fdatasync`
  (`sync_data`) on the active segment. There is no separate WAL; the append plus
  its covering fsync is the durable record. See I2.

- **ack.** A producer-visible signal returned only after the record is durable
  (the default level); it carries the assigned offset. See I2.

- **torn tail.** The bytes after the last durable record at the end of the active
  segment, left by a crash or an interrupted write. Recovery truncates them to
  reach the last intact record and reports the dropped span as a `TornTail`
  `LossEvent`. See I1 and I3.

- **loss report / loss event / reason code.** The versioned, structured record of
  everything recovery dropped: a `LossReport` (schema version 1) of `LossEvent`s,
  each a byte span with a `ReasonCode` (`TornTail`, `CorruptRecordHeader`,
  `CorruptRecordBody`, `CorruptSegmentHeader`, `SequenceGap`, each with a frozen
  numeric code). The metrics endpoint and the offline inspector read the same
  shape. `crates/ironbus-storage/src/loss.rs`. See I3.

---

## Where this is enforced, at a glance

| Concern | Crate / file |
| --- | --- |
| Offset, seq, flags, exhaustion-loud ids | `ironbus-core/src/types.rs` |
| Frozen on-disk format constants and offsets | `ironbus-core/src/format.rs` |
| Record frame codec, CRC-before-xxh3, resync | `ironbus-core/src/codec.rs` |
| Committed cursor, acked-ahead, snapshot codec | `ironbus-core/src/cursor.rs` |
| Leases, visibility timeout, fence tokens, hard cap | `ironbus-core/src/lease.rs` |
| Max-deliver / poison disposition, ack vocabulary | `ironbus-core/src/delivery.rs` |
| Clock seam (wall vs monotonic) | `ironbus-core/src/clock.rs` |
| Single durable log, append, sync, recovery, caps | `ironbus-storage/src/log.rs` |
| Per-segment scan, torn-tail and sequence-gap stops | `ironbus-storage/src/segment.rs` |
| Loss report schema, caps, `check_caps` | `ironbus-storage/src/loss.rs` |
| Resilience checkers I1 to I4 (pure) | `ironbus-storage/src/invariants.rs` |
| Durable checkpoint (two-slot, CRC'd) | `ironbus-storage/src/checkpoint.rs` |
| DLQ sink and exactly-once move | `ironbus-storage/src/dlq.rs` |
| IO seam, fdatasync vs fsync model | `ironbus-storage/src/{io,fs,fault}.rs` |
| Engine: cursor commit, DLQ move, credit, group cap | `ironbus-server/src/engine.rs` |
| Single-writer Mutex over the engine | `ironbus-server/src/server.rs` |
