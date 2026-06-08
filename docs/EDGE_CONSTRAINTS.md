# Edge resource constraints: the constraint-to-knob map, the `tiny` profile, and the RTC-less clock model

This document is the design synthesis for
[#20](https://github.com/ELares/IronBus/issues/20) (edge resource constraints):
it turns each physical limit of a battery-less ARM edge box (flash endurance,
RAM ceiling, weak CPU, unclean power loss, missing real-time clock, thermal
throttling) into a SPECIFIC IronBus knob, fully specifies the `tiny` default
profile, and specifies how record ordering and retention survive a backward
clock jump on a device with no RTC.

Most of #20 is already specified by merged docs. This document writes the three
genuinely-missing design deliverables and CROSS-LINKS the rest so a reader sees
the whole #20 picture in one place:

1. [the hardware-constraint-to-knob mapping table](#1-the-hardware-constraint-to-knob-mapping-table)
   (#20 criterion 1, [#117](https://github.com/ELares/IronBus/issues/117));
2. [the `tiny` profile, fully specified](#2-the-tiny-profile-fully-specified)
   (#20 criteria 2 and 8, [#115](https://github.com/ELares/IronBus/issues/115));
3. [the clock-skew / missing-RTC model](#3-the-clock-skew--missing-rtc-model)
   (#20 criterion 6, [#117](https://github.com/ELares/IronBus/issues/117)).

It is design (docs) only. It introduces no flag and changes no source. Every
knob named below is cross-checked against the merged config (the `serve` flags
in [CLI.md](CLI.md), the `EngineConfigSnapshot` in
`crates/ironbus-server/src/engine.rs`, and the worked budget in
[RAM_BUDGET.md](RAM_BUDGET.md)); where a knob is only CONCEPTUAL (not a real
field yet) it is labelled SPECIFIED-NOT-YET-A-FIELD and points at the owning
issue. It complements, and does not duplicate, the operator-facing manual-flag
table in [EDGE_TUNING.md](EDGE_TUNING.md): that doc is the operator runbook for
the SHIPPED flags; this doc is the design-level map that also covers the
conceptual knobs and the profile/clock design that #20 owns.

## Honest summary up front

Read this before the tables, because it frames how to read them.

- **This is a DESIGN deliverable, not a runtime feature.** It SPECIFIES the
  `tiny` profile and its defaults; it does NOT claim a `--profile tiny` switch
  exists. There is no profile-selection flag in the shipped binary
  ([EDGE_TUNING.md](EDGE_TUNING.md) confirms this), the 64 MiB RAM ceiling is
  NOT enforced by a boot guard ([RAM_BUDGET.md](RAM_BUDGET.md) is explicit about
  that), and the shipped DEFAULT knob values are server-sized, not edge-safe.
  The runtime ENFORCEMENT and the selection flag are the implementation
  residuals named per row.
- **The safe path is already the default where it is wired.** Durability
  (ack-after-`fdatasync`, fatal-fsync, torn-tail truncation) is the only level
  the binary exposes and cannot be weakened from the command line today
  ([DURABILITY.md](DURABILITY.md)). The edge gap is in PROFILE DEFAULTS and
  PROFILE SELECTION, not in the durability mechanism.
- **Numbers here are concrete and testable.** The `tiny` values are real,
  currently-accepted flag values; the RAM arithmetic reuses
  [RAM_BUDGET.md](RAM_BUDGET.md)'s worked budget; the clock model maps onto the
  real record-header `seq` and `timestamp` fields
  (`crates/ironbus-core/src/format.rs`) and the `Clock` seam
  (`crates/ironbus-core/src/clock.rs`).

Throughout, MiB = 1024 * 1024 bytes and KiB = 1024 bytes.

---

## 1. The hardware-constraint-to-knob mapping table

One row per hardware limit. Each row gives the limit, the failure if it is left
unhandled, the governing IronBus knob, the knob's `tiny`-profile default, and
the doc / issue that OWNS the knob. A knob that is a real shipped field is named
in `code` font with its flag; a knob that is only conceptual is labelled
**SPECIFIED-NOT-YET-A-FIELD** and points at the owning issue so the table never
implies a field exists when it does not.

| Hardware limit | Failure if unhandled | Governing knob | `tiny` default | Owned by |
| --- | --- | --- | --- | --- |
| **Flash endurance** (finite SD/eMMC erase cycles) | Tiny random fsyncs and leveled-rewrite write amplification burn out the card in weeks | `max_segment_bytes` (`--max-segment-bytes`): large sequential append-only segments, never recycled in v1 (ADR 0002), so no in-place rewrite | `8388608` (8 MiB, the `EDGE_SEGMENT_BYTES` value) | [WAL.md](WAL.md), [#135](https://github.com/ELares/IronBus/issues/135) / [#13](https://github.com/ELares/IronBus/issues/13) |
| | | Group-commit batching: the append actor amortizes one `fdatasync` over a drained batch instead of one per record (always on, no knob) | always on (#177) | [DURABILITY.md](DURABILITY.md), [#6](https://github.com/ELares/IronBus/issues/6) |
| | | `checkpoint_interval` (`--checkpoint-interval`): the cursor checkpoint write rate stays far below one write per ack | `1024` (default; do NOT lower toward 1 on flash) | [WAL.md](WAL.md), [#7](https://github.com/ELares/IronBus/issues/7) |
| | | Retention bounds `max_retained_bytes` / `max_age_ms` / `max_messages` (`--max-retained-bytes` / `--max-age-ms` / `--max-messages`): reap WHOLE sealed segments, bounding the erase/rewrite volume over time | enable at least one, device-sized (default `0` = off) | [WAL.md](WAL.md), [#13](https://github.com/ELares/IronBus/issues/13) |
| | | The `>= 4x` data-dir write-amplification GATE: a design that writes four or more device bytes per user byte FAILS on the edge | `>= 4x` fails the run | [EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md), [#19](https://github.com/ELares/IronBus/issues/19) |
| **RAM ceiling** (hundreds of MiB, not tens of GiB) | An unbounded buffer OOM-kills the single binary on a burst | `consumer_credit_bytes` (`--consumer-credit-bytes`): per-connection un-acked PAYLOAD-byte budget (the firm RAM-side bound) | `262144` (256 KiB) | [RAM_BUDGET.md](RAM_BUDGET.md), [#275](https://github.com/ELares/IronBus/issues/275) / [#10](https://github.com/ELares/IronBus/issues/10) |
| | | `consumer_credit` (`--consumer-credit`): per-connection un-acked MESSAGE count | `8` | [RAM_BUDGET.md](RAM_BUDGET.md), [#65](https://github.com/ELares/IronBus/issues/65) |
| | | `max_connections` (`--max-connections`): bounds the in-flight set, the read buffers, and the per-connection thread stacks all at once | `32` | [RAM_BUDGET.md](RAM_BUDGET.md), [#105](https://github.com/ELares/IronBus/issues/105) |
| | | `max_groups` (`--max-groups`) and `max_in_flight` (`--max-in-flight`): bound the per-group cursor + lease state | `64` and `256` | [RAM_BUDGET.md](RAM_BUDGET.md), [#240](https://github.com/ELares/IronBus/issues/240) / [#10](https://github.com/ELares/IronBus/issues/10) |
| | | 64 MiB RSS ceiling itemized into a per-buffer budget with a refuse-to-boot guard | **SPECIFIED-NOT-YET-A-FIELD** (no boot guard, no RSS check) | [RAM_BUDGET.md](RAM_BUDGET.md), [#115](https://github.com/ELares/IronBus/issues/115) |
| | | `mmap_max_bytes` (cap mapped pages) | **SPECIFIED-NOT-YET-A-FIELD**; N/A today (storage uses positional file IO, not mmap, so there are no uncounted mapped pages) | [RAM_BUDGET.md](RAM_BUDGET.md), [#115](https://github.com/ELares/IronBus/issues/115) |
| **CPU** (slow ARM core shared with the radio) | Per-record fsync and an expensive codec starve the core and the radio | Codec choice: lz4_flex (cheap, pure Rust) is the default codec; zstd (and its higher levels) is opt-in only, never on the default path | lz4_flex (on-disk compression NOT yet landed; codec reads `none` today) | [ADR-0003](adr/0003-default-compression-lz4-zstd-opt-in.md), [#12](https://github.com/ELares/IronBus/issues/12) |
| | | CRC32C checksum (hardware-accelerated on aarch64), always on, every record | always on | [DURABILITY.md](DURABILITY.md), [#5](https://github.com/ELares/IronBus/issues/5) |
| | | Group-commit batching: one `fdatasync` per drained batch, not per record (single-writer append actor, no thread-count knob) | always on (#177) | [DURABILITY.md](DURABILITY.md), [#6](https://github.com/ELares/IronBus/issues/6) |
| **Power loss / brownout** (no UPS, mid-write cut) | Page-cache writeback loses acknowledged data; a torn tail or a falsely-retried fsync looks durable but is not | `fdatasync`-before-ack: a `PubAck` is emitted only after the covering `fdatasync` returns (invariant I2). The only level exposed; cannot be weakened from the command line | always on, `sync` level | [DURABILITY.md](DURABILITY.md), [#6](https://github.com/ELares/IronBus/issues/6) / [#116](https://github.com/ELares/IronBus/issues/116) |
| | | Torn-tail truncation + CRC32C stop-at-first-bad-frame: recovery yields the longest valid prefix; an unsynced, never-acked tail is dropped | always on | [DURABILITY.md](DURABILITY.md), [#7](https://github.com/ELares/IronBus/issues/7) / [#8](https://github.com/ELares/IronBus/issues/8) |
| | | Fatal-fsync: a failed `fdatasync` freezes the writer read-only (`WriterFrozen`) and is NEVER retried as a transient success (fsyncgate) | always on | [DURABILITY.md](DURABILITY.md), [#6](https://github.com/ELares/IronBus/issues/6) |
| | | `disk_full_policy` (`--disk-full-policy`): drop-new on a brown-out-prone device avoids the extra force-reap writes of drop-oldest | `drop-new` (default) | [EDGE_TUNING.md](EDGE_TUNING.md), [#82](https://github.com/ELares/IronBus/issues/82) |
| **Clock / missing RTC** (wall clock jumps backward when NTP finally syncs) | Trusting wall-clock for ordering inverts record IDs; trusting it for retention mis-expires data | Monotonic `seq` (the record-header sequence / log offset) is the SOLE ordering authority; it is broker-assigned, monotonic, and never reused | always on (offsets monotonic, never reused; `crates/ironbus-storage/src/segment.rs`) | [Section 3](#3-the-clock-skew--missing-rtc-model), [#117](https://github.com/ELares/IronBus/issues/117) |
| | | Wall-clock `timestamp` is producer-supplied advisory metadata, never the ordering key; age-retention uses the segment's MAX timestamp vs the clock-seam `now` and is documented best-effort | always on (advisory); the never-emit-a-smaller-broker-timestamp guard is conceptual | [Section 3](#3-the-clock-skew--missing-rtc-model), [#117](https://github.com/ELares/IronBus/issues/117) |
| | | The monotonic-vs-wall split is the `Clock` trait seam (`now_monotonic_nanos` never decreases within a run; `now_unix_millis` may move backward) | always on (`crates/ironbus-core/src/clock.rs`) | [Section 3](#3-the-clock-skew--missing-rtc-model), [#117](https://github.com/ELares/IronBus/issues/117) |
| **Thermal throttling** (fanless box heats under sustained codec/checksum load) | A silent clock throttle halves throughput and gets misattributed to IronBus | The EDGE_RUN_DISCIPLINE throttle-quarantine GATE: a throttle event in the steady-state window FAILS the run (it does not get averaged in); a throughput-derived collapse signal is the portable trigger, chip temperature a best-effort gauge | a steady-state throttle fails the run; backpressure shed is the active response (specified) | [EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md) ([#113](https://github.com/ELares/IronBus/issues/113)), thermal/loss metrics [#118](https://github.com/ELares/IronBus/issues/118), shed via [#10](https://github.com/ELares/IronBus/issues/10) |

Notes that keep the table honest:

- The rows whose `tiny` default reads "always on" are MECHANISMS with no knob:
  group commit, fatal-fsync, torn-tail truncation, and CRC32C are not tunable,
  they are the safe path itself. They are in the table because #20 criterion 1
  asks for the knob that honors EACH limit, and for these limits the honoring
  thing is a fixed mechanism, not a configurable value.
- Every `tiny` default in this table is a real, currently-accepted flag value
  EXCEPT the two SPECIFIED-NOT-YET-A-FIELD rows (the RSS boot guard and
  `mmap_max_bytes`). Those are the #115 enforcement residual, called out so the
  table never invents a field.
- The thermal active response (shed before the device melts down) is SPECIFIED
  in [BACKPRESSURE.md](BACKPRESSURE.md) (CoDel sojourn shedding) and gated as a
  fail condition in [EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md); the
  throughput-collapse signal that drives it is the #118 metrics deliverable.

---

## 2. The `tiny` profile, fully specified

The `tiny` profile is THE documented default for an unattended, battery-less ARM
box. This section SPECIFIES its values and shows them summing under the 64 MiB
RAM ceiling. It does NOT claim a runtime `--profile tiny` switch: today these are
the individual flag values an operator passes (or sets via `IRONBUS_*` env
vars), and the auto-selection flag is the #115 / #17 / #87 residual noted at the
end.

### The specified `tiny` defaults

These are the values a future `--profile tiny` would set. They are the worked
edge configuration from [RAM_BUDGET.md](RAM_BUDGET.md), kept byte-identical so
the two docs never drift, plus the edge-relevant durability, retention, and
codec defaults the rest of #20 fixes.

| Knob | Flag | `tiny` value | What it bounds / why |
| --- | --- | --- | --- |
| Segment size | `--max-segment-bytes` | `8388608` (8 MiB) | erase-block-friendly sequential append; bounds the largest single working region; the `EDGE_SEGMENT_BYTES` value |
| Consumer credit | `--consumer-credit` | `8` | un-acked messages per connection |
| Consumer byte budget | `--consumer-credit-bytes` | `262144` (256 KiB) | un-acked PAYLOAD bytes per connection (the firm RAM bound); never `0` on the edge |
| Max connections | `--max-connections` | `32` | bounds the in-flight set, the read buffers, and the thread stacks |
| Max groups | `--max-groups` | `64` | live work-groups (never `0` on the edge) |
| Max in-flight | `--max-in-flight` | `256` | per-group delivery window |
| Disk-full policy | `--disk-full-policy` | `drop-new` | brownout-friendly shed; avoids drop-oldest force-reap writes |
| Checkpoint interval | `--checkpoint-interval` | `1024` | cursor checkpoint cadence far below one write per ack; bounds post-crash redelivery |
| Durability level | (always on, not a flag) | `sync` (ack-after-`fdatasync`) | power-loss-safe default; cannot be weakened from the CLI |
| Codec | (design default, no flag) | lz4_flex (zstd opt-in) | cheap on ARM, pure Rust; on-disk compression not yet landed |
| Retention | `--max-retained-bytes` / `--max-age-ms` / `--max-messages` | enable at least one, device-sized | bounds on-disk footprint and the erase/rewrite volume the flash sees |

### Why it sums under the 64 MiB ceiling

The full per-term arithmetic, cited to the source, is in
[RAM_BUDGET.md](RAM_BUDGET.md); it is not re-derived here, only summarized so the
profile is self-contained. With the values above and a representative ~16 KiB
edge record, the STEADY-STATE total is:

```
term1 (per-connection in-flight)   ~4 MiB   (min(8 * 16 KiB, 256 KiB) per conn * 32 conns)
term3 (per-group cursor + leases)  ~1 MiB   (64 groups * 256 in-flight * ~64 bytes)
term4 (active segment in RSS)      ~0       (written straight to file, one-record scratch)
term5 (fixed overhead)            ~4 MiB   (binary resident + runtime + 32 thread stacks; estimate)
-----------------------------------------
total                             ~9 MiB   <<  64 MiB ceiling
```

That lands roughly an order of magnitude under the ceiling, with headroom. The
ONE term not bounded by the credit knobs is the per-connection read buffer
(`term2`), capped only by `max_connections`; at `max_connections = 32` with
edge-sized records its realized residency is ~1 MiB, and its adversarial
worst case (all 32 connections mid-assembly of a near-16-MiB frame) is the
~514 MiB figure RAM_BUDGET.md reports and is part of the auto RAM-guard
follow-up. Every in-memory buffer in the design is bounded, and there is no
unbounded queue anywhere (this is #20 criterion 3, satisfied by the
RAM_BUDGET.md accounting these knobs realize).

### Selectable in the single static binary, no external dependency

The `tiny` defaults are reachable in the single static musl binary with ZERO
external dependency: they are plain `serve` flags (or `IRONBUS_*` env vars), and
the durable, lz4_flex, CRC32C path pulls no vendored-C and no daemon (ADR-0003;
the edge-min static build is [#99](https://github.com/ELares/IronBus/issues/99)
under the single-binary parent [#17](https://github.com/ELares/IronBus/issues/17)).
So #20 criterion 8 (selectable in the single static binary, no external
dependency) holds for the profile VALUES today via flags.

### What is design vs the implementation residual

To be precise about what this section delivers versus what it does not:

- **SPECIFIED here (design done):** the `tiny` profile name, its concrete
  default VALUES, the proof they sum under 64 MiB, and that they ship in the one
  static binary with no external dependency.
- **The #115 implementation residual (NOT claimed as done):** the
  auto-selection mechanism (a `--profile tiny` switch, [#17](https://github.com/ELares/IronBus/issues/17) /
  [#87](https://github.com/ELares/IronBus/issues/87)) that sets these values for
  the operator, the itemized per-buffer budget turned into a refuse-to-boot
  RSS guard, the per-topic RAM floor, and the `mmap_max_bytes=0` assertion (a
  no-op today since storage uses positional IO, not mmap). The 64 MiB ceiling
  is a documented target met BY CONFIGURATION today, not an invariant the binary
  enforces; this is stated plainly in [RAM_BUDGET.md](RAM_BUDGET.md) and is not
  re-claimed as enforced here.

---

## 3. The clock-skew / missing-RTC model

A battery-less edge box often has NO real-time clock: at boot the wall clock
reads an arbitrary value (the build epoch, or whatever the last write left), and
when NTP finally reaches the network the wall clock can STEP BACKWARD by minutes,
hours, or years. This section specifies how record ordering and retention survive
that backward jump. It maps directly onto the two clocks the `Clock` trait
already exposes (`crates/ironbus-core/src/clock.rs`).

### The two clocks, and which one is authoritative

The `Clock` seam exposes exactly two independent sources, and the design assigns
each a single job:

- `now_monotonic_nanos()` NEVER moves backward within a run. It is the source
  for durations (lease deadlines, queue sojourn, uptime). It is NOT durable
  across a reboot (its origin is arbitrary), so it orders WITHIN a run only.
- `now_unix_millis()` is the wall clock. It MAY jump or move backward across a
  reboot or an NTP step. It is ADVISORY metadata, never an ordering key.

### Ordering authority: the monotonic `seq`, never the wall clock

Record ordering is the broker-assigned monotonic SEQUENCE (`seq` in the 36-byte
record header, `crates/ironbus-core/src/format.rs`), which is the log offset's
companion: offsets are "monotonic and never reused"
(`crates/ironbus-storage/src/segment.rs`). The `seq` is assigned by the LOG at
append time as its own monotonic counter (a companion to, but distinct from, the
offset counter; both are broker-assigned and never reused), not derived from any
clock, so:

- **Record IDs never consult the wall clock.** A backward wall-clock jump cannot
  reorder, duplicate, or invert a `seq`, because `seq` does not read the wall
  clock at all. This is stronger than the Redis-Streams reuse-the-last-timestamp
  trick (which it still adopts for the advisory timestamp below): IronBus's
  ORDERING key is structurally clock-independent.
- **`seq` is durable and survives a reboot without an RTC.** The `seq` is in
  every record's on-disk header and the segment header carries `base_seq`, so
  recovery reconstructs the exact monotonic order from disk alone, with no clock
  involved. An RTC-less reboot recovers the same total order it had before the
  power cut.

### Wall-clock timestamps: advisory, and never-decreasing if the broker stamps

The record header also carries an 8-byte `timestamp` (milliseconds since the
Unix epoch). Today it is PRODUCER-SUPPLIED (`PubBody.timestamp_ms` in
`crates/ironbus-proto/src/message.rs` is the producer's timestamp), so it is advisory end-to-end metadata for display and
best-effort time queries, never the ordering key. The code already encodes this
honesty: the segment tracks the MAX record timestamp, not the last, with the
comment "producer timestamps are not monotonic"
(`crates/ironbus-storage/src/segment.rs`).

For any timestamp the BROKER stamps (the segment `created_unix_ms`, and any
future broker-stamped record time), the design adopts the Redis-Streams rule so a
backward wall-clock jump never emits an inverted value:

- **Never emit a smaller broker timestamp than the last one emitted.** The
  broker keeps the last wall-clock value it emitted; on a read of
  `now_unix_millis()` that is SMALLER (a backward jump), it reuses the last value
  (`max(last_emitted, now)`) so a broker-stamped timestamp series is
  non-decreasing even across an NTP step. This is **SPECIFIED-NOT-YET-A-FIELD**:
  the rule is specified here and owned by
  [#117](https://github.com/ELares/IronBus/issues/117); there is no
  monotone-wall-clock wrapper in the tree today (the `Clock` seam deliberately
  lets `now_unix_millis` move backward, and `ManualClock::set_unix_millis`
  documents "the wall clock may move backwards", which is the seam this wrapper
  sits ON, not a contradiction).
- A `clock_step` event is emitted and the wall-clock anchor re-checkpointed when
  a backward jump is detected, so the step is observable rather than silent
  (the metric is the [#118](https://github.com/ELares/IronBus/issues/118)
  deliverable; the anchor is the persisted last-`now_unix_millis` plus the
  matching monotonic reading, a #117 design item).

### Retention under an unreliable wall clock

Age-based retention (`max_age_ms`) is the one place the wall clock touches a
DURABLE decision, so its behavior under a jumping clock is specified explicitly:

- Age retention deletes a sealed segment only when EVERY record in it has aged
  out: the reaper compares the segment's MAX record `timestamp_ms` against
  `now - max_age_ms`, where `now` is the clock-seam wall clock
  (`RetentionBounds.max_age_ms`, `crates/ironbus-storage/src/log.rs`). Using the
  MAX (not the min) means a segment is never deleted while it still holds a
  record that has not aged out.
- **Age retention is best-effort and tolerant of a jumping clock, by design.**
  Because `now` is the wall clock, a backward jump makes `now - max_age_ms`
  smaller, which makes the reaper MORE conservative (it deletes LESS, never
  more), so a clock that jumps backward can DELAY a reap but can never
  prematurely delete unaged data. When the clock later steps forward (NTP
  syncs), the next reap pass catches up. This fail-safe direction (a bad clock
  delays deletion rather than causing premature loss) is the deliberate design
  choice for RTC-less retention.
- The size and count retention bounds (`max_retained_bytes`, `max_messages`) do
  NOT consult any clock, so they are unaffected by clock skew entirely. An
  operator who wants a hard, clock-independent footprint bound on an RTC-less box
  should prefer the byte/count bounds and treat age retention as the best-effort
  add-on.

### What is durable and what survives an RTC-less reboot

Pulling the durability of each piece together, because #20 criterion 6 asks
precisely this:

| State | Durable? | Survives an RTC-less reboot? | Role |
| --- | --- | --- | --- |
| `seq` / log offset (ordering) | yes (record + segment header) | YES, exactly, from disk alone | the sole ordering authority |
| Record `timestamp_ms` (advisory) | yes (record header) | YES (the bytes survive); its WALL meaning is best-effort | display + best-effort time queries, never ordering |
| Segment `created_unix_ms` | yes (segment header) | YES (the bytes survive) | provenance; subject to the never-decrease rule above for new segments |
| Monotonic clock origin | no | NO (resets each run) | within-run durations only (leases, sojourn, uptime) |
| Persisted wall-clock anchor | yes (SPECIFIED-NOT-YET-A-FIELD, #117) | YES once it exists | re-anchor human-readable time after a jump |

So ordering and retention both survive a backward clock jump: ordering because
it is the clock-independent monotonic `seq` recovered from disk, and retention
because the wall clock only ever makes age retention MORE conservative, never
prematurely destructive, and the clock-free byte/count bounds are available as
the hard footprint cap.

### Tie to the `Clock` trait seam

Everything above rides the existing seam. The engine never reads
`SystemTime::now` or `Instant::now` directly; it reads `Clock::now_unix_millis`
(wall, advisory) and `Clock::now_monotonic_nanos` (monotonic, authoritative for
durations), and the deterministic simulation drives a `ManualClock` that can step
the wall clock backward independently of the monotonic clock
(`ManualClock::set_unix_millis` + `advance_monotonic_nanos`). That independent
control is exactly what a clock-skew test needs, so the never-emit-a-smaller
broker-timestamp rule and the age-retention fail-safe direction are both
testable against the seam WITHOUT real hardware. The implementation residual is
the monotone-wall-clock wrapper, the persisted anchor, and the `clock_step`
event (#117 / #118); the ordering authority (monotonic `seq`) is already wired
and durable.

---

## 4. Reconciling the already-satisfied #20 criteria

The remaining #20 acceptance criteria are already satisfied by merged docs. They
are cross-linked here so a reader sees the whole picture in one place; this
document does not restate or re-derive them.

- **Bounded buffers, no unbounded queue (criterion 3).** Every in-memory buffer
  is bounded and the worked `tiny` set sums under 64 MiB. Owned by
  [RAM_BUDGET.md](RAM_BUDGET.md) (the per-term accounting cited to the source)
  and realized by the knobs in
  [section 2](#2-the-tiny-profile-fully-specified).
- **Power-loss-safe default, no silent relaxed mode (criterion 5).**
  Ack-implies-durable (I2): a `PubAck` is emitted only after the covering
  `fdatasync` returns; the relaxed `interval` / `async` levels are SPECIFIED but
  NOT wired and cannot be reached from the command line, so nothing silently
  weakens the safe default. Owned by [DURABILITY.md](DURABILITY.md)
  ([#50](https://github.com/ELares/IronBus/issues/50) /
  [#6](https://github.com/ELares/IronBus/issues/6)) and the edge durability
  defaults in [#116](https://github.com/ELares/IronBus/issues/116).
- **Large, sector-aligned, sequential, batched write path; write amplification
  measurable (criterion 4).** The active segment is the WAL: append-only,
  large, never recycled in v1; the append actor group-commits one `fdatasync`
  per batch; the data-dir write amplification is a measured metric with a
  `>= 4x` edge gate. Owned by [DURABILITY.md](DURABILITY.md) and
  [EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md) (the gate), with the metric
  contract in [#118](https://github.com/ELares/IronBus/issues/118).
- **Codec justified against ARM cost; cold-only higher zstd (criterion 7).**
  lz4_flex (cheap, pure Rust) is the default codec and zstd is opt-in only,
  behind a feature, never on the default path; higher zstd levels are reserved
  for cold/archived data. Owned by
  [ADR-0003](adr/0003-default-compression-lz4-zstd-opt-in.md)
  ([#12](https://github.com/ELares/IronBus/issues/12), decided in #139).

### Contradictions found with merged docs

None. The values, knob names, and mechanisms above were cross-checked against
[RAM_BUDGET.md](RAM_BUDGET.md), [DURABILITY.md](DURABILITY.md),
[EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md), [EDGE_TUNING.md](EDGE_TUNING.md),
[SLO.md](SLO.md), [ADR-0003](adr/0003-default-compression-lz4-zstd-opt-in.md),
and the source (`format.rs`, `clock.rs`, `segment.rs`, `log.rs`, `engine.rs`),
and are consistent with all of them. One naming note that is NOT a contradiction:
the original #20 draft sketched an illustrative profile with a `compression =
"lz4"` line and a `clock_source = "monotonic_plus_logical"` line; the resolved
positions are lz4_flex specifically (ADR-0003) and the monotonic-`seq` ordering
authority (section 3), which this document uses, so the draft's illustrative TOML
is superseded by the merged decisions, not contradicted.

---

## What #20 needs to close for M2, and the residuals

This document writes the three missing #20 design deliverables (the
constraint-to-knob table, the fully-specified `tiny` profile, the RTC-less clock
model) and cross-links the four already-satisfied criteria. The #20 DESIGN is
now complete for the M2 (Prototype-Ready Design) milestone: every acceptance
criterion is either SPECIFIED here, ALREADY-MERGED in a cited doc, or has its
design pinned with a clearly-named IMPLEMENTATION residual.

The implementation residuals (design done, code follow-up) are:

- the auto `--profile tiny` selection and the refuse-to-boot RSS guard /
  per-topic floor ([#115](https://github.com/ELares/IronBus/issues/115),
  [#17](https://github.com/ELares/IronBus/issues/17) /
  [#87](https://github.com/ELares/IronBus/issues/87));
- the monotone-wall-clock wrapper, the persisted wall-clock anchor, and the
  `clock_step` event ([#117](https://github.com/ELares/IronBus/issues/117) /
  [#118](https://github.com/ELares/IronBus/issues/118));
- the edge metrics (write amplification, RAM headroom, throughput-collapse
  thermal signal, loss counters) and the power-loss fault-injection test
  contract ([#118](https://github.com/ELares/IronBus/issues/118));
- the on-device edge runs under the run discipline, a device residual that feeds
  [#19](https://github.com/ELares/IronBus/issues/19) and must not be faked
  ([EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md)).

## Cross-references

- [RAM_BUDGET.md](RAM_BUDGET.md): the source-derived per-buffer RAM accounting
  and the worked `tiny` budget under the 64 MiB ceiling (#115).
- [DURABILITY.md](DURABILITY.md): the ack-implies-durable contract, fatal-fsync,
  torn-tail truncation, and the specified-not-implemented relaxed levels (#50,
  #6).
- [EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md): thermal control, the
  write-amplification `>= 4x` gate, and the run-discipline protocol (#113, #19).
- [EDGE_TUNING.md](EDGE_TUNING.md): the operator-facing manual-flag table for the
  shipped knobs (#117, #19).
- [SLO.md](SLO.md): the edge resource rows (RAM ceiling, write amplification)
  and the ratification process (#110, #19).
- [ADR-0003](adr/0003-default-compression-lz4-zstd-opt-in.md): lz4_flex default
  codec, zstd opt-in only (#12, #139).
- [WAL.md](WAL.md): the active-segment-is-the-WAL model, segment roll, the
  unwired `EDGE_SEGMENT_BYTES`, and retention mechanics (#135, #13).
- [CLI.md](CLI.md): the canonical flag-and-default reference, each cited to its
  `main.rs` constant.
- The `Clock` trait seam (`crates/ironbus-core/src/clock.rs`) and the record
  header `seq` / `timestamp` fields (`crates/ironbus-core/src/format.rs`).
- Issues: [#20](https://github.com/ELares/IronBus/issues/20) (this parent),
  [#115](https://github.com/ELares/IronBus/issues/115) (RAM budget + profile
  enforcement), [#116](https://github.com/ELares/IronBus/issues/116) (edge
  durability defaults), [#117](https://github.com/ELares/IronBus/issues/117)
  (constraint table + clock model), [#118](https://github.com/ELares/IronBus/issues/118)
  (edge metrics + fault-injection contract),
  [#17](https://github.com/ELares/IronBus/issues/17) (single binary + profile
  selection), [#99](https://github.com/ELares/IronBus/issues/99) (edge-min
  build).
