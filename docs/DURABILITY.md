# The durability contract and the levels model

This document is the authority for IronBus's DURABILITY CONTRACT: the precise
guarantee a producer's ack carries, the mechanism that enforces it, the existing
crash-injection and ack-ordering tests that make it falsifiable, and the
relaxed-durability levels that are SPECIFIED but deliberately not shipped. It is
the design deliverable of [#50](https://github.com/ELares/IronBus/issues/50) (the
crash-injection and ack-ordering harness under the durability parent
[#6](https://github.com/ELares/IronBus/issues/6)).

It is derived from and cross-checked against the source. Where the issue text and
the code diverge, the CODE wins and the divergence is flagged inline. For the
shared invariants (I1 to I8) and the canonical glossary see
[INVARIANTS.md](INVARIANTS.md); for the WAL-is-the-log model and the on-disk file
lifecycle see [WAL.md](WAL.md); for the byte-level layouts see
[CONTRACTS.md](CONTRACTS.md); for the loss-report schema see
[the `ironbus.loss-report.v1` schema](schemas/loss-report.v1.md).

## The one honest headline

The #50 task body, and the README's "Modes: `fdatasync` (default), `interval`,
and `none`" line, assume a MENU of durability levels (sync / batch / interval /
async), each with its own per-level loss guarantee. The SAFE level is the only
DEFAULT:

> **An ack means durable, by default.** Under the default `sync` level a `Pub` /
> `PubAck` is emitted only after the `fdatasync` that covers that record has
> returned `Ok`. A power loss can never lose an acknowledged record. This is
> invariant I2 (ack-implies-durable), it is the default, and an operator who
> changes nothing keeps ZERO acknowledged loss on a power cut.

The relaxed levels (`interval`, `async`, `none`) ARE now implemented (#341, #379),
but they are STRICTLY OPT-IN: an operator must explicitly select a relaxed level
with `--durability-level`, and the two unbounded-loss levels (`async`, `none`)
additionally refuse to boot without an explicit data-loss acknowledgement
(`--async-loss-ack`). The default stays `sync`, so the binary you run with no
durability flags is byte-for-byte the historical power-loss-safe broker.

The two things the #50 four-level framing calls "sync" and "batch" are not two
levels in IronBus. They are the SAME safe level, observed once without the
group-commit batcher and once with it. The [#177](https://github.com/ELares/IronBus/issues/177)
append actor AMORTIZES the `fdatasync` (one sync per drained batch instead of one
per record) but it still acks each record only AFTER that covering sync returns,
so batching changes the cost of durability, never the guarantee. "Batch" is an
optimization of the durable level, not a relaxation of it.

The relaxed levels (`interval`, `async` / the README's `none`) trade durability
for throughput. They are CONTRARY to IronBus's Edge-First safe default, they are
IMPLEMENTED but STRICTLY OPT-IN (#341, #379), and they require an operator to
EXPLICITLY opt in and accept a stated bounded-or-unbounded loss before any of them
can weaken I2.

---

## 1. The v1 durability contract (ack-implies-durable, I2)

### The statement

No ack is observable for a record that is not already covered by a returned
`fdatasync` on the active segment. The active segment IS the write-ahead log
(ADR 0001); there is no separate WAL file, so "covered by a returned `fdatasync`"
is the whole durability condition. On a power loss, recovery yields the longest
valid prefix of acked records and truncates any unsynced, never-acked tail; an
acknowledged record is never in that truncated tail, so ACKNOWLEDGED loss on
power loss is ZERO.

This is invariant I2 in [INVARIANTS.md](INVARIANTS.md); this document does not
restate the invariant, it specifies the contract it grounds and maps the
falsification.

### The mechanism (where the guarantee comes from)

Three pieces compose into the contract:

- **Append, then sync, then ack.** `Engine::produce`
  (`crates/ironbus-server/src/engine.rs`) appends the framed, CRC32C'd record to
  the active segment, calls `Log::sync` (which calls `RandomAccessFile::sync_data`,
  i.e. `fdatasync`), and only THEN returns the offset that becomes the producer's
  ack. The append path reserves the next offset and sequence before the write
  returns, so a record is never durably written under an id the log cannot
  advance past (I5).

- **The append actor group-commits, but still acks after the sync.** In the
  server the single logical writer is a dedicated APPEND ACTOR thread
  (`crates/ironbus-server/src/actor.rs`, #177) that owns the `Engine`. It drains a
  batch of queued produces, issues ONE `fdatasync` covering the whole batch
  (`append_no_sync` then `commit_batch`), and only then acks every record in the
  batch. A `PubAck` therefore still follows its covering sync; the batch boundary
  is where the cost is amortized, not where the guarantee is dropped.

- **A failed fsync is fatal, never a silent success.** If the covering
  `fdatasync` returns an error, `Log::sync` (`crates/ironbus-storage/src/log.rs`)
  freezes the writer read-only (the active segment is dropped) and surfaces
  `WriterFrozen` instead of acking. This is the fsyncgate lesson: a storage stack
  that loses an fsync error and then reports success on a retry would ack a record
  that is not durable. IronBus refuses the false success and stops writing.

### The proof (the tests that falsify it)

| Property | Test | Where |
| --- | --- | --- |
| The ack never precedes the covering fsync (the I2 ordering property). With the sync gate held closed the actor parks in `commit_batch`, the produce reply is provably NOT ready (`try_recv` errors), and the reply arrives only after the gate opens and the sync returns. | `an_ack_is_sent_only_after_the_covering_fsync_completes_i2` | `crates/ironbus-server/src/actor.rs` |
| Group commit is real: a drained burst of N concurrent produces is made durable by exactly ONE `fdatasync`, not N, while still landing the contiguous offsets `1..=n` in a single total order. | `a_batch_of_concurrent_produces_issues_one_fdatasync_not_n` | `crates/ironbus-server/src/actor.rs` |
| No acknowledged record is lost across a power loss: every synced (acked) prefix recovers exactly, monotone and intact; the unsynced tail does not survive and was never acked. Swept at EVERY op boundary, with and without segment rolling, and over a holed (reordered / partial) unsynced tail. | `power_loss_at_every_boundary_no_roll`, `power_loss_at_every_boundary_with_rolling`, `power_cut_with_a_holed_unsynced_tail_loses_no_acked_record`, `power_loss_recovers_the_durable_prefix` | `crates/ironbus-storage/tests/crash_recovery.rs` |

The "ack never precedes the condition" property the #50 acceptance asks for is
exactly the `..._i2` actor test above. The condition is the covering
`fdatasync`; the test holds the fsync open and proves the ack cannot arrive while
it is held.

---

## 2. The fsyncgate and crash-after-create gates

These are the two crash classes #50 names specifically, both already covered.

### fsyncgate: no false success, and the writer freezes

The fsyncgate failure mode is a storage layer that observes an `fdatasync` EIO,
drops it, and then reports success when the caller retries, acking a record that
never reached stable storage. IronBus injects exactly that fault and asserts the
opposite outcome:

- `fatal_fsync_freeze_loses_no_acked_record`
  (`crates/ironbus-storage/tests/crash_recovery.rs`): with the previously-acked
  prefix already synced, an unsynced tail is appended and the next `fdatasync` is
  made to fail. `Log::sync` returns `WriterFrozen`, the writer is no longer
  writable, and the durable mark never advanced past the acked prefix. The
  accompanying power loss then recovers EXACTLY the acked prefix: no false
  success, no lost acked record, no resumed writing on a failed barrier.
- `fatal_fsync_freeze_during_a_roll_loses_no_acked_record` (same file): the same
  freeze, but the faulting sync is the seal's `sync_all` inside a segment ROLL,
  not an explicit `Log::sync`. The acked prefix written before the roll still
  survives.
- The fsync-EIO crash class is swept across many workloads and freeze points by
  the property test `a_sync_fault_at_any_point_loses_no_acked_record` (same
  file), which also asserts the armed fsync genuinely froze the writer so the
  property is never vacuous, and by the seeded multi-fault sweep
  `recovery_under_an_arbitrary_seeded_fault_holds_the_invariants`.

### crash-after-create: a freshly created segment survives via the parent-dir fsync

A new segment's directory entry is only durable once the PARENT DIRECTORY is
fsynced; a crash after the inode is created but before the dir entry is durable
could otherwise lose the whole segment. IronBus fsyncs the directory at creation:
`Log::start_segment` (`crates/ironbus-storage/src/log.rs`) writes and syncs the
header, then calls `Filesystem::sync_dir`, so "a freshly created segment survives
a power loss right after creation" (WAL.md). The roll-forward case (a crash that
sealed the highest segment but never created its successor) is exercised by
`recovery_fails_closed_when_a_fault_strikes_the_roll_forward`
(`crates/ironbus-storage/tests/crash_recovery.rs`): the clean path genuinely
rolls forward and creates the next segment (anti-vacuity), and each write-side
fault on that create-write-sync path fails recovery CLOSED with a typed error
rather than vanishing a segment or recovering a silent partial.

### group commit: syncs-per-record < 1 under concurrent load

`a_batch_of_concurrent_produces_issues_one_fdatasync_not_n` already proves the
syncs-per-record ratio drops below 1 under a concurrent burst: N produces, one
sync. The engine-level observation that the fsync-duration histogram records one
observation per `commit_batch` (so the N-produces-one-sync amortization above
contributes a single fsync sample, not one sample per message) is in
`produce_records_one_fsync_observation_each` and the `commit_batch` accounting in
`crates/ironbus-server/src/engine.rs`.

---

## 3. The relaxed durability levels (IMPLEMENTED, strictly opt-in)

This section specifies the levels #50 assumes, now IMPLEMENTED (#341, #379). Each
is an OPT-IN that an operator must explicitly select and whose stated loss they
must accept; the default is and remains the durable `sync` level in section 1.
The level is wired through `EngineConfig::durability_level`; `commit_batch` issues
the covering `fdatasync` under `sync`, forces one on the `interval` window, and
defers it under `async`/`none` (advancing the visible head via
`Log::flush_no_sync`). A segment roll's seal and a clean-shutdown flush
(`Engine::force_sync`, called by `checkpoint_all_groups`) are the relaxed levels'
opportunistic / final barriers.

### The level model

| Level | What it does | When the ack fires | Worst-case ACKNOWLEDGED loss on power loss | Power-loss safe? | Status |
| --- | --- | --- | --- | --- | --- |
| `sync` (the default) | ack only after the covering `fdatasync` returns; the group-commit batcher amortizes the sync but never acks before it | AFTER the covering `fdatasync` returns `Ok` | ZERO (a torn unsynced tail is truncated and was never acked) | yes | IMPLEMENTED |
| `interval` | ack once the record is in the OS page cache; a background window issues an `fdatasync` every `flush_interval_ms` of monotonic time, or after `flush_max_bytes` of unsynced record bytes, whichever first | AFTER the `write()` to the page cache, BEFORE the windowed `fdatasync` | BOUNDED: at most the records acked since the last completed `fdatasync`, bounded by the SMALLER of the time window and the byte budget | NO (acked-but-unsynced records in the open window are lost on a power cut) | IMPLEMENTED |
| `async` (the README's `none`) | ack once the record is in the page cache; an `fdatasync` happens only OPPORTUNISTICALLY (on a segment roll's seal, on a clean shutdown) | AFTER the `write()` to the page cache; the `fdatasync` is asynchronous to the ack | UNBOUNDED until the next `fdatasync`: every record acked since the last sync, with no IronBus time or byte ceiling (bounded only by the OS dirty-writeback window) | NO | IMPLEMENTED, gated behind an explicit data-loss acknowledgement |
| `none` | like `async` but NO periodic fsync at all; the only barriers are a segment roll's seal and a clean shutdown | AFTER the `write()` to the page cache | every record acked since the last segment roll or clean shutdown: the LARGEST loss window | NO | IMPLEMENTED, gated behind an explicit data-loss acknowledgement |

The precise ack timing and bound, per level:

- **`sync`**: the ack is released only AFTER `Log::sync` (the covering
  `fdatasync`) returns `Ok`, so the record is durable when the producer sees the
  `PubAck`. Worst-case loss is ZERO: on a power cut recovery yields the longest
  valid prefix and truncates the unsynced tail, which was never acked.
- **`interval`**: the ack is released after the record's bytes are in the OS page
  cache (the visible head advances via `Log::flush_no_sync`), which happens
  BEFORE the windowed `fdatasync`. A background window forces a covering
  `fdatasync` every `flush_interval_ms` of MONOTONIC time (via the clock seam, so
  an NTP step never mis-fires it, I6) OR once `flush_max_bytes` of unsynced record
  bytes accumulate, whichever comes first. The EXACT worst-case loss bound is the
  records acked since the last completed `fdatasync`, which is bounded by the
  SMALLER of those two triggers: a crash loses AT MOST one flush window's worth of
  acked records, never more.
- **`async`**: the ack is released after the page-cache `write()`; no periodic
  `fdatasync` is forced. The fsync is asynchronous to the ack and happens only
  when a segment rolls (the seal fsyncs the sealed segment) or at clean shutdown.
  Worst-case loss is UNBOUNDED until the next of those events: every record acked
  since the last sync, with no IronBus-imposed time or byte ceiling (only the OS
  dirty-writeback window eventually flushes the page cache).
- **`none`**: identical to `async` except there is no opportunistic mid-run sync
  to rely on at all beyond a segment roll; the loss window is "since the last
  segment roll or clean shutdown", the largest of the four.

Two honesty notes on the naming. First, the #50 "batch" level is NOT a fifth row:
it is the `sync` level WITH group commit on, which is what IronBus already does,
so it collapses into the safe `sync` row. Second, the README spells the
fully-relaxed level `none`; this document keeps `async` and `none` distinct only
in that `none` has NO periodic fsync window where `async` still seals on a roll;
both ack asynchronously to the fsync.

### The opt-in contract

Because `interval`, `async`, and `none` weaken I2, they are gated, not free flags:

- **Off by default, always.** The default is `sync`. An operator gets a relaxed
  level only by setting `--durability-level` (or `IRONBUS_DURABILITY_LEVEL`)
  explicitly; there is no implicit downgrade. A broker run with no durability flag
  is the historical power-loss-safe broker.
- **An explicit loss acknowledgement for `async`/`none`.** The unbounded-loss
  levels refuse to BOOT unless `--async-loss-ack` (the explicit
  `i-accept-acknowledged-data-loss`-style acknowledgement) is set: a fail-closed
  usage error (exit 1) before any listener opens. `interval`'s loss is bounded by
  the operator-chosen window, so it is opt-in but NOT gated behind this flag;
  however, an `interval` with BOTH triggers at `0` is refused (it would silently
  degrade to the unbounded `async` behavior without the acknowledgement).
- **The broker LOUDLY announces a waived I2.** When any relaxed level is active
  the broker logs a startup WARN that I2 is WAIVED, that the broker is NOT
  power-loss safe, and the worst-case acknowledged loss for the active level, on
  every boot. The default `sync` logs no such warning.
- **The loss is part of the contract, and reported.** A relaxed level's bound is a
  number the operator is choosing. An ack under a relaxed level is a weaker
  promise and is documented as such, never presented as the durable ack.

### The #14 configuration keys (implemented)

These follow the existing `serve` flag and `DEFAULT_*` constant conventions (see
[CLI.md](CLI.md)) and are wired under [#14](https://github.com/ELares/IronBus/issues/14).

| key | flag | scope | default | bounds | meaning |
| --- | --- | --- | --- | --- | --- |
| `durability_level` | `--durability-level` | global | `sync` | `sync` \| `interval` \| `async` \| `none` | the level; `sync` is the power-loss-safe default |
| `flush_interval_ms` | `--flush-interval-ms` | global | `1000` | `>= 0` | `interval`: max MONOTONIC ms an acked record may be unsynced (`0` disables the time trigger) |
| `flush_max_bytes` | `--flush-max-bytes` | global | `1048576` | `>= 0` | `interval`: max unsynced record bytes before a forced `fdatasync` (`0` disables the byte trigger) |
| `async_loss_ack` | `--async-loss-ack` | global | `false` | bool | must be `true` to select `async` / `none` (the explicit data-loss acknowledgement) |
| `wal_fsync_headroom_bytes` | `--wal-fsync-headroom-bytes` | global | `0` = OFF | bytes (`0` = unbounded) | the fsync-headroom admission credit (#378): caps the un-fsynced backlog. Under `sync` it throttles the group-commit backlog (a RAM guard); under a relaxed level it CAPS THE LOSS WINDOW in bytes by shedding new produces once the backlog fills |

The fsync-headroom credit (`wal_fsync_headroom_bytes`, #378) is the admission-time
companion to the `interval` byte trigger: where `flush_max_bytes` periodically FLUSHES
the unsynced tail, the headroom THROTTLES OR SHEDS NEW produces once the unsynced
backlog reaches the bound, so under a relaxed level the worst-case acknowledged loss is
held within the configured headroom even without a periodic flush. It reuses the same
`unsynced_bytes()` frontier this section tracks and is decided before the append, so it
never drops an accepted record. Off by default (the un-fsynced frontier is then bounded
only by the level's own barriers). See
[BACKPRESSURE.md, Part C](BACKPRESSURE.md#part-c-fsync-headroom-admission-credits-378).

The crash harness drives each level through crash-at-every-step and asserts the
row's stated loss bound: zero for `sync`, bounded-by-the-window for `interval`,
and the declared window for `async`/`none` (the engine durability tests in
`crates/ironbus-server/src/engine.rs`, e.g.
`async_loses_the_unsynced_tail_on_a_power_cut_but_sync_loses_nothing_same_harness`
and `interval_acks_within_the_window_and_a_crash_loses_at_most_the_window`).

---

## 4. Mapping the #50 acceptance criteria to the existing falsification

The #50 acceptance list, marked against what is PROVEN today versus what waits on
the relaxed levels or on-device hardware.

| #50 acceptance criterion | Status | Where it is proven (or what it waits on) |
| --- | --- | --- |
| Property test proves the ack never precedes the level condition | PROVEN for `sync`; per-level bounds proven for the relaxed levels | `an_ack_is_sent_only_after_the_covering_fsync_completes_i2` (`actor.rs`) for `sync`. The per-level form (a relaxed level's own bound under a power cut) is the engine durability suite in `engine.rs` (section 3). |
| Crash injection drops unsynced bytes at arbitrary points; the loss guarantee holds under it | PROVEN | `power_loss_at_every_boundary_no_roll` / `_with_rolling`, `power_cut_with_a_holed_unsynced_tail_loses_no_acked_record`, the `power_loss_recovers_the_durable_prefix` proptest (`crash_recovery.rs`). The `sync` guarantee (zero acked loss) holds under all of them. The `interval` / `async` / `none` bounds are now proven by the engine durability suite (section 3). |
| fsyncgate fault injection: no false-success on a retried failed sync, and a writer freeze | PROVEN | `fatal_fsync_freeze_loses_no_acked_record`, `fatal_fsync_freeze_during_a_roll_loses_no_acked_record`, `a_sync_fault_at_any_point_loses_no_acked_record` (`crash_recovery.rs`); the freeze itself is `Log::sync` returning `WriterFrozen` (`log.rs`). |
| Crash-after-create: segments never vanish | PROVEN | the parent-directory fsync in `Log::start_segment` (`log.rs`) plus `recovery_fails_closed_when_a_fault_strikes_the_roll_forward` (`crash_recovery.rs`). |
| Group commit shows syncs-per-record < 1 under concurrent load | PROVEN | `a_batch_of_concurrent_produces_issues_one_fdatasync_not_n` (`actor.rs`): N produces, one `fdatasync`. |
| Torn mid-batch write exercises the #5 checksum and #7 stop-at-first-bad-frame path (not just clean truncation) | PROVEN | `last_record_corruption_drops_only_that_record`, `mid_log_header_corruption_stops_at_the_first_bad_record`, `mid_log_body_corruption_stops_at_the_first_bad_record`, `arbitrary_byte_corruption_yields_a_valid_prefix_or_clean_error` (`crash_recovery.rs`); the #45 conformance corpus driven through real recovery in `crates/ironbus-storage/tests/conformance_recovery.rs` and the per-frame corruption cases (including the over-threshold xxh3-field flip) in `crates/ironbus-storage/tests/corruption_corpus.rs`. Recovery stops at the FIRST bad frame and reports a typed `ReasonCode` (I1, I3). |
| Per-level loss guarantee asserted under crash-at-every-step (zero for `sync`, bounded-and-reported for `interval`, declared window for `async`) | PROVEN | the `sync` row (zero acked loss) is proven by the crash-recovery sweeps; the `interval` (loses at most the flush window), `async`, and `none` rows are proven by the engine durability suite (`engine.rs`): `the_default_level_is_sync_and_acks_only_post_fsync_zero_acked_loss`, `async_loses_the_unsynced_tail_on_a_power_cut_but_sync_loses_nothing_same_harness`, `interval_acks_within_the_window_and_a_crash_loses_at_most_the_window`, and the roll/shutdown barrier tests. |
| Throughput / latency / bytes-at-risk curve across all levels on real ARM SD/eMMC, feeding #19 | RESIDUAL (device) | not host-side reproducible; see section 5. |

The in-flight crash-class work (the EIO and consumed-error block-layer fault
seam, the torn-mid-batch corpus expansion) is tracked under
[#55](https://github.com/ELares/IronBus/issues/55), which is editing
`crash_recovery.rs` and the fault layer in parallel; this document does not touch
those files. The bounded-loss caps and the structured loss report this column
relies on are pinned by `crates/ironbus-storage/src/loss.rs` and the
[`ironbus.loss-report.v1` schema](schemas/loss-report.v1.md).

---

## 5. The device residual: the throughput / latency / bytes-at-risk curve

The last #50 acceptance criterion, the throughput vs latency vs bytes-at-risk
curve ACROSS the durability levels on real ARM SD/eMMC, is a DEVICE measurement,
not a host-side or CI artifact. It is a residual for two compounding reasons:

- **It needs the relaxed levels.** A curve "across the levels" cannot be plotted
  while only one level (`sync`) exists. The `interval` and `async` points on the
  curve do not exist until section 3 ships.
- **It needs the reference hardware, and must not be faked.** Emulated power loss
  on an in-memory disk cannot reproduce real flash behavior (FTL write
  reordering, erase-block latency, the actual bytes-at-risk a controller holds in
  its cache), so the numbers must come from a run on the reference aarch64 device,
  not from the in-memory model. This is the same honesty rule the rest of the
  project holds: the macro-bench harness (`crates/ironbus-bench/`, #111) is the
  instrument, every SLO row is a STATED TARGET not a measured result until a run
  on the reference device is recorded and archived, and the live
  coordinated-omission self-test is `#[ignore]`d on shared CI (#284). See
  [SLO.md](SLO.md), whose durability-mode rows already table `group-commit
  fdatasync` (power-loss safe), `async` (page-cache, **not power-loss safe**), and
  `sync-per-message` (power-loss safe) side by side with their targets marked
  not-yet-ratified.

So this curve is documented here as the on-device measurement that feeds
[#19](https://github.com/ELares/IronBus/issues/19) (the SLO and methodology
parent) and is reflected in #20 (the edge resource constraints), produced by the
#111 harness on the reference device under the SLO ratification process, and
explicitly NOT a number this document or any host-side test invents.

---

## Summary: what is true today

- IronBus DEFAULTS to ONE durability level, `sync`: ack-implies-durable (I2). The
  group-commit batcher amortizes the `fdatasync` but never acks before it, so the
  #50 "batch" level is the same safe level, not a relaxation. An operator who
  changes nothing keeps zero acknowledged loss on a power cut.
- Zero acknowledged loss on power loss is PROVEN for the default: the ack-ordering
  property (`..._i2`), the power-loss boundary sweeps, the fsyncgate
  no-false-success and writer-freeze tests, the crash-after-create roll-forward,
  the group-commit one-sync-per-batch test, and the stop-at-first-bad-frame
  corruption path are all in the tree and run per PR.
- The relaxed `interval`, `async`, and `none` levels are IMPLEMENTED (#341, #379)
  with their loss bounds (bounded by the flush window; unbounded until the next
  sync; the largest window) and an explicit, off-by-default opt-in contract: the
  unbounded-loss levels refuse to boot without `--async-loss-ack`, the broker
  loudly logs a waived I2, and the active level + its loss exposure are observable
  (`ironbus_durability_*` gauges and the materialized-config line). The default is
  and remains the durable level.
- The across-levels throughput / latency / bytes-at-risk curve on ARM SD/eMMC is
  a DEVICE residual: it now has the relaxed levels but still needs the reference
  hardware, it is not faked host-side, and it feeds #19.

## Cross-references

- [INVARIANTS.md](INVARIANTS.md): invariant I2 (ack-implies-durable) and the
  canonical glossary terms `durable`, `ack`, `torn tail`, plus the "Specified,
  enforcement pending" entry for the ack-on-buffer durability mode (#6).
- [WAL.md](WAL.md): the active-segment-is-the-WAL model, the append-actor /
  group-commit (#177), the parent-directory fsync on segment creation, and the
  torn-tail truncation on recovery.
- [SLO.md](SLO.md): the durability-mode rows (`group-commit fdatasync`, `async`
  page-cache `not power-loss safe`, `sync-per-message`) and the ratification
  process for the device curve.
- [EDGE_TUNING.md](EDGE_TUNING.md): why the relaxed modes are not exposed as
  `serve` flags (you cannot weaken durability from the command line today).
- [The `ironbus.loss-report.v1` schema](schemas/loss-report.v1.md): the
  structured, versioned report every truncated or skipped span is recorded in.
- Issues: [#50](https://github.com/ELares/IronBus/issues/50) (this harness),
  [#6](https://github.com/ELares/IronBus/issues/6) (durability parent),
  [#177](https://github.com/ELares/IronBus/issues/177) (append actor + group
  commit), [#55](https://github.com/ELares/IronBus/issues/55) (the in-flight
  block-layer fault seam), [#14](https://github.com/ELares/IronBus/issues/14)
  (config keys), [#19](https://github.com/ELares/IronBus/issues/19) (SLO and the
  device curve).
