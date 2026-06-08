# Edge run discipline: the protocol that makes edge numbers trustworthy

This document specifies the RUN DISCIPLINE for IronBus edge benchmarks: the
thermal, storage, harness-isolation, steady-state, and multi-hour-run protocol
that a number must be produced under before it can be quoted, ratified, or
gated against. It is issue
[#113](https://github.com/ELares/IronBus/issues/113) under the performance and
benchmarking parent [#19](https://github.com/ELares/IronBus/issues/19), and it
respects the edge resource constraints catalogued in
[#20](https://github.com/ELares/IronBus/issues/20).

Without this discipline, multi-hour tail drift gets misattributed to IronBus
when it is really CPU throttling or device flash garbage collection, and the
fsync-bound durable rate swings 5 to 10x run to run. The protocol below removes
those confounders so a recorded number describes IronBus and not the bench rig.

> **This is a SPECIFIED protocol, not implemented instrumentation. Read this
> first.**
>
> The PROTOCOL below is the deliverable of #113: it states precisely, with
> formulas, what a canonical edge run must do. The HARNESS INSTRUMENTATION that
> would enforce it automatically (the per-window throughput series, the
> coefficient-of-variation and p99-drift steady-state detector, the
> junction-temperature and CPU-frequency logger, the cgroup / `taskset` CPU
> pinning, the throttle-quarantine gate, and the multi-hour run mode) is NOT yet
> in [`crates/ironbus-bench/`](../crates/ironbus-bench). Today that harness
> emits a single-window summary (`results.msgs_per_sec`, the latency
> percentiles, the median `results.steady_rss_bytes`, and
> `results.write_amplification`) with no windowed series and no thermal hooks
> (see `crates/ironbus-bench/src/harness.rs`). Implementing the instrumentation
> is a follow-up that overlaps the live macro-bench work
> ([#111](https://github.com/ELares/IronBus/issues/111),
> [#114](https://github.com/ELares/IronBus/issues/114),
> [#284](https://github.com/ELares/IronBus/issues/284)), so this doc does not
> touch that crate. The actual multi-hour on-device runs require the reference
> Pi 4 / RK3399 hardware and CANNOT be produced host-side or in CI; they are a
> device residual that feeds #19 and MUST NOT be faked. See
> [Residuals](#residuals-what-is-specified-vs-what-must-still-be-built) at the
> end.

---

## Scope and the reference devices

The discipline applies to every canonical edge run: the runs whose numbers feed
the [SLO ratification process](SLO.md#ratification-process) and the device-only
throughput step of the [golden-path acceptance runbook](ACCEPTANCE.md). The
reference devices are the three tiers #19 commits to:

| Tier | Device | Cores | Storage | Role here |
| --- | --- | --- | --- | --- |
| edge-min | Raspberry Pi 4 (4 GB) | 4x Cortex-A72 | SD / USB-SSD | the hard floor and flash-wear realism device; the marquee SLO device |
| edge-mid | RubikPi / RK3399 (4 GB) | 2x A72 + 4x A53 | eMMC | the production hive class |
| x86-ref | small x86 box (e.g. N100) | 4 core | NVMe | the headroom / ceiling check |

The CPU-pinning and second-box-offload rules below are written for the 4-core
edge devices (edge-min and edge-mid), where the harness and the broker contend
for the same handful of cores. The same protocol runs on x86-ref, where core
contention is not the binding constraint.

The default durability for every canonical run is group-commit `fdatasync`
before ack, the safe `sync` level IronBus ships (see [DURABILITY.md](DURABILITY.md));
a run states its durability mode explicitly, because a throughput number without
its durability mode is meaningless (the rule SLO.md enforces).

---

## 1. Thermal control

Edge ARM SoCs throttle their clock when junction temperature crosses the
firmware limit, and a throttle event mid-run silently lowers the throughput
ceiling, so an unmonitored run cannot tell IronBus drift from thermal drift.
The protocol controls and records temperature so a throttled window is
quarantined rather than averaged in.

**Reference cooling.** A canonical run uses NAMED, active cooling, recorded with
the run so it is reproducible:

- edge-min (Raspberry Pi 4): the official Raspberry Pi 4 case fan (or an
  equivalent named active cooler), running at full duty for the whole run, in an
  ambient stated and logged (target ambient 20 to 25 C).
- edge-mid (RK3399 / RubikPi): the board's named active heatsink-fan, full duty,
  same ambient discipline.

Passive cooling (a bare heatsink, no fan) is NOT a canonical configuration,
because it cannot hold steady state for the mandated multi-hour run on a 4-core
ARM box under sustained load. The exact cooler model and the ambient temperature
are recorded in the run provenance.

**Per-window logging.** For every 30 s window of the run, the protocol logs:

- junction temperature `T_j` (the SoC thermal-zone reading, in C); and
- the per-core CPU frequency (the scaling current frequency, in MHz).

On Linux these are the `/sys/class/thermal/thermal_zone*/temp` and
`/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq` sysfs nodes; the logger
samples them once per window and records the window-max `T_j` and the
window-minimum observed frequency (the worst case in the window, not the
average, so a brief throttle is not smoothed away).

**The throttle-quarantine rule.** A THROTTLE EVENT is any of:

- a sysfs / firmware throttle flag asserted during the window (on the Pi 4, the
  `vcgencmd get_throttled` under-voltage / throttle / capping bits, or the
  kernel thermal-pressure / `cpufreq` throttle signal); or
- the observed per-core frequency dropping below the device's rated sustained
  frequency for that window (a frequency cap is a throttle even if the firmware
  flag is not surfaced).

The rule:

- A throttle event during the STEADY-STATE window (section 4) FAILS the run.
  The run is discarded, not clipped, not averaged: a steady-state window that
  throttled does not describe IronBus under its SLO, it describes a thermally
  starved device, so it is not a valid measurement.
- A throttle event during WARM-UP (before steady state is declared) does not by
  itself fail the run, but it resets the steady-state detector: the warm-up has
  not actually settled, so the 5-window steady-state count (section 4) starts
  over from the first non-throttled window.

The run records, per window, `T_j`, the per-core frequency, and a boolean
`throttled`, so the quarantine decision is auditable from the provenance and a
reviewer can see exactly which window failed.

---

## 2. Storage and SD / eMMC state

Aged-versus-fresh flash variance and the device's own background garbage
collection are the storage confounders: the same code on the same card reads 5
to 10x apart depending on the card's erase-block state and fill level. The
protocol fixes the storage state so the variance is contained.

**Fix the device model.** A canonical run names the EXACT card or eMMC model and
the filesystem (model, capacity, and the `ext4`/`F2FS` choice with its mount
options) in the run provenance. A number from one card model is not portable to
another; the model travels with the number.

**Known state before each canonical run.** Before each canonical run, the
storage is returned to a KNOWN state:

- a removable SD / USB-SSD is secure-erased (an ATA secure-erase or `blkdiscard`
  of the whole device) and the filesystem freshly created; or
- a soldered eMMC is `blkdiscard`-trimmed across the data partition and the
  filesystem freshly created.

This removes the prior run's erase-block fragmentation so each run starts from
the same controller state, not from whatever the last run left behind.

**Fixed fill level (50%).** The benchmark filesystem is pre-filled to a FIXED
50% fill level with incompressible filler before the run, so the device's
flash-translation-layer free-block pressure is representative of a real
half-full deployment rather than a best-case empty card. The filler is
incompressible (random bytes) so a controller that compresses cannot cheat the
fill. The fill level (50%) and the filler size are recorded with the run.

**Report write amplification and device temperature.** Every canonical run
reports:

- WRITE AMPLIFICATION, the on-disk data-directory bytes written per byte of user
  payload, exactly the `results.write_amplification` the macro-bench already
  computes (`data_dir_bytes / payload_bytes_produced`,
  `crates/ironbus-bench/src/harness.rs`; `null` when nothing is produced). This
  is the flash-wear realism metric #19 mandates. NOTE: the shipped harness
  measures the data-directory growth, which is a FLOOR on the true device-level
  write amplification; the device controller's own internal amplification (the
  FTL erase-block rewrites underneath the filesystem) is on top of it, so a
  device-level write-amplification reading from the controller's SMART /
  health counters, where the device exposes them, is reported alongside the
  data-dir figure and labelled as the separate, larger device-level number.
- DEVICE TEMPERATURE, the storage device's own temperature where the device
  exposes it (the SD / eMMC / SSD reports it via its health interface), logged
  per window like the SoC junction temperature, because a hot card throttles its
  own controller and changes the durable-write rate.

**The write-amplification gate.** Write amplification is REPORTED on every run,
and on the edge devices a run whose data-directory write amplification is
`>= 4x` FAILS, per the parent #19 flash-wear gate. The threshold is the parent
gate's value; a design that writes four or more device bytes per user byte burns
edge flash too fast to ship. The gate applies to the data-directory figure the
harness computes (the figure IronBus controls); the larger device-level FTL
figure is reported for realism but is a property of the card, not of IronBus, so
it is not itself the IronBus gate.

---

## 3. Harness isolation

On a 4-core edge device the load generator and the broker compete for the same
cores, so an un-isolated harness steals headroom from the very thing it is
measuring and the recorded throughput is the contended number, not IronBus's
number. The protocol pins them apart and budgets the harness's own cost
separately.

**Disjoint CPU sets.** The broker and the harness (the load generator plus the
receiver / recorder) are pinned to DISJOINT CPU sets via cgroups (`cpuset`) or
`taskset` so they never share a core:

- edge-min / edge-mid (4 cores): the broker is pinned to a dedicated subset (for
  example cores 0 to 2) and the harness to the remaining core(s) (for example
  core 3), with the two `cpuset`s disjoint. The exact split is recorded with the
  run.
- the pinning is applied to the SHIPPING `ironbus` binary's process (the broker)
  and to the harness driver process; the open-loop generator's intended-send
  schedule (the wrk2-style coordinated-omission-free timing the macro-bench uses)
  must not itself be perturbed by sharing a core with the broker.

**Budget and report harness CPU and RSS separately.** The harness's OWN CPU
time and resident memory are budgeted and REPORTED as separate quantities, not
folded into the broker's:

- the broker's steady-state RSS is the existing `results.steady_rss_bytes`
  (median broker RSS mid-run), which is the figure the [RAM budget](RAM_BUDGET.md)
  ceiling applies to;
- the HARNESS's own CPU utilization and RSS are recorded as distinct fields, so a
  reviewer can confirm the harness was not starving the broker and the broker's
  numbers are not contaminated by harness overhead.

**Second-box offload on edge-min.** When core contention on edge-min exceeds the
threshold (the harness cannot get its work done on its pinned core without
stealing from the broker's set, i.e. the harness's pinned cores are saturated at
or above the contention threshold of 90% busy across the steady-state window),
the GENERATOR is offloaded to a SECOND BOX, driving the device-under-test over
the network so the device spends its cores on the broker alone. The
intended-send schedule and the recorded latency are still anchored to the
generator's clock (the open-loop, coordinated-omission-free model is preserved
across the network), and the offload is recorded with the run so the topology is
reproducible. On edge-mid and x86-ref the offload is optional; on edge-min under
contention it is required.

---

## 4. The steady-state criterion

A throughput number measured before the device has settled (page cache cold,
segments not yet rolling, allocator cold) is a warm-up artifact, not a sustained
rate, so the protocol declares steady state precisely and discards the warm-up.

**Warm-up bound.** The warm-up window the run discards is

```
warmup = max(60 s, time-to-fill-the-page-cache + 2 segment rolls)
```

That is: at least 60 seconds, AND at least as long as it takes to (a) fill the
page cache for the working set and (b) roll the active segment twice (two
`--max-segment-bytes` rolls at the run's produce rate, so the segment-roll stall
and the new-segment `fdatasync` cost are inside the warm-up, not inside the
measured window). The longer of the two bounds wins. Warm-up windows are
recorded but never counted toward the result.

**Window length.** Steady state is evaluated over fixed 30 s windows (the same
30 s window the thermal logger uses), so the thermal and throughput windows
align and a throttled window (section 1) maps to exactly one throughput window.

**The steady-state declaration.** Steady state is declared when 5 CONSECUTIVE
30 s windows ALL satisfy BOTH stability bounds:

- THROUGHPUT coefficient of variation over the 5 windows

  ```
  CoV = stddev(throughput_window) / mean(throughput_window) <= 0.03   (3%)
  ```

  where `throughput_window` is the per-window `msgs/s` for each of the 5 windows,
  `mean` is their arithmetic mean, and `stddev` is the population standard
  deviation over those 5 samples; AND

- p99 DRIFT across the 5 windows

  ```
  p99_drift = (max(p99_window) - min(p99_window)) / min(p99_window) <= 0.10   (10%)
  ```

  where `p99_window` is the per-window p99 latency (recomputed from each window's
  slice of the HdrHistogram, which the run archives whole so any window's
  percentile recomputes), `max` / `min` are taken over the 5 windows.

When both hold for 5 consecutive windows, steady state is declared and the
measured result is taken from the steady-state windows onward. If a window
breaks either bound (or throttles, per section 1), the 5-window consecutive
count RESETS and the detector starts over from the next clean window. The run's
reported throughput, p50/p99/p99.9, RAM, and write amplification are the
steady-state figures, never the warm-up figures.

---

## 5. The mandated multi-hour sustained run

A 30-second-window steady state can still hide hours-long tail drift (the
Redpanda lesson #19 cites: p99 climbing into seconds after roughly twelve hours).
So every RELEASE additionally requires one long run that proves the tail does not
walk.

**The rule.** Per release, on the reference edge device, run at least one

```
sustained run >= 4 hours
```

under the full discipline above (reference cooling, fixed storage state, disjoint
CPU pinning, steady state declared before the clock starts). The run is divided
into hour buckets, and it PASSES only if the p99 latency does not drift across
the run:

```
p99_drift(hour1 -> hour4) = (p99_hour4 - p99_hour1) / p99_hour1 < 0.25   (25%)
```

where `p99_hourN` is the p99 latency computed over hour N's slice of the archived
histogram. A drift of 25% or more from hour 1 to hour 4 FAILS the sustained run:
the tail is walking (thermal soak, flash GC catching up, a segment-roll or
retention interference, or a real IronBus leak), and the number is not a
sustained number. A throttle event (section 1) anywhere in the sustained run
fails it on the section-1 rule independently.

This is the run that catches what a short burst cannot, and it is the run that
genuinely requires the device for hours: it cannot be produced in CI or on the
x86 dev box and stand in for the edge tail.

---

## 6. Write amplification as a gate (restated)

Pulling the storage gate together with the parent gate, so the >= 4x rule is in
one place:

- Write amplification is REPORTED on every canonical run (section 2), the
  `results.write_amplification` figure (data-directory bytes per user-payload
  byte) the macro-bench already emits.
- On the EDGE devices (edge-min, edge-mid), a run whose data-directory write
  amplification is `>= 4x` FAILS, per the parent #19 flash-wear gate. Four or
  more device bytes per user byte exhausts edge flash endurance too fast to be a
  shippable design.
- The larger device-level FTL write amplification (from the card's own health
  counters, where exposed) is reported alongside for realism but is a property
  of the card, so the IronBus gate is on the figure IronBus controls.

---

## How a run is recorded (provenance)

Everything the protocol measures rides in the run's provenance JSON (the
versioned record the macro-bench already emits per run: `schema_version`,
`git_sha`, `git_dirty`, `build`, `host`, `clock_source`, `config`, `results`,
the raw `HdrHistogram`, and a copy-pasteable `reproduce` command; see SLO.md and
`crates/ironbus-bench/src/provenance.rs`). The run-discipline protocol ADDS, for
a canonical edge run, the fields the instrumentation follow-up must populate:

- the named cooler and ambient temperature;
- per 30 s window: `T_j` (junction temperature), the per-core frequency, the
  `throttled` boolean, and (where exposed) the storage device temperature;
- the exact card / eMMC model, filesystem, the secure-erase / format action, and
  the 50% fill level;
- the CPU-set split (broker `cpuset` vs harness `cpuset`) and whether the
  generator was offloaded to a second box;
- the harness's OWN CPU and RSS, recorded separately from the broker's;
- the per-window throughput and p99 series the steady-state detector ran on, the
  declared steady-state start, the warm-up bound, and the per-hour p99 series for
  the sustained run.

A number is only as trustworthy as its provenance, and these fields are exactly
what a reviewer needs to confirm the discipline was held and to reproduce the
run.

---

## Residuals: what is specified vs what must still be built

This document is the PROTOCOL (specified). Two classes of work remain, stated
honestly so they are not mistaken for done:

1. **Harness instrumentation (a code follow-up).** The automatic enforcement of
   this protocol is NOT yet in [`crates/ironbus-bench/`](../crates/ironbus-bench).
   To be built: the per-window throughput and p99 series, the CoV /
   p99-drift steady-state detector (section 4), the warm-up bound calculator
   (page-cache fill + 2 segment rolls), the junction-temperature / CPU-frequency
   / storage-temperature logger and the throttle-quarantine gate (section 1), the
   cgroup / `taskset` disjoint-CPU-set setup and the separate harness CPU/RSS
   accounting (section 3), the second-box generator offload (section 3), the
   multi-hour run mode and the hour-1-to-hour-4 p99-drift gate (section 5), and
   the additional provenance fields above. This work OVERLAPS the live
   macro-bench tasks (#111 the open-loop generator and histogram, #114 the
   baseline-comparison and regression gate, #284 the coordinated-omission
   self-test as a reliable gate), so this doc deliberately does not touch that
   crate; the instrumentation lands there.

2. **The on-device runs (a device residual).** The actual canonical edge runs,
   and in particular the mandated `>= 4h` sustained run, require the reference
   Pi 4 / RK3399 hardware with the named cooling and the prepared storage. They
   CANNOT be produced host-side or on a shared CI runner and MUST NOT be faked: a
   shared-runner number says nothing about the edge tail, exactly as the
   acceptance runbook and the SLO not-yet-measured disclaimer already state. These
   runs feed the [SLO ratification process](SLO.md#ratification-process) and the
   [#19](https://github.com/ELares/IronBus/issues/19) gate; until a real device
   run is recorded and archived under this discipline, no edge number is ratified.

Because both the instrumentation and the device runs are residuals that cannot
be completed host-side or in CI, this document closes the #113 design (the
methodology) and leaves the harness-implementation and the device-run as
follow-ups for the orchestrator to file under #19 / #111 / #114 / #284.

---

## Cross-references

- [SLO.md](SLO.md): the SLO target table and the ratification process this
  discipline gates; every canonical run feeds it.
- [ACCEPTANCE.md](ACCEPTANCE.md): the release-gate runbook whose device-only
  throughput step runs the #111 macro-bench under this discipline.
- [EDGE_TUNING.md](EDGE_TUNING.md): the edge-knob recommendations (segment size,
  retention, checkpoint interval) that hold write amplification down, the metric
  this discipline gates.
- [RAM_BUDGET.md](RAM_BUDGET.md): the 64 MiB ceiling the broker RSS figure is
  sized against, separate from the harness RSS this discipline reports apart.
- [DURABILITY.md](DURABILITY.md): the safe `sync` (group-commit `fdatasync`)
  level every canonical run states as its durability mode.
- [`crates/ironbus-bench/`](../crates/ironbus-bench): the macro-bench harness
  (#111), the measurement instrument this protocol disciplines; its `harness.rs`
  and `provenance.rs` define the metrics and provenance the instrumentation
  follow-up extends.
- [#19](https://github.com/ELares/IronBus/issues/19): the performance, SLO, and
  benchmarking parent (reference devices, warm-up / steady-state rules, the
  multi-hour-run mandate, the write-amplification flash-wear gate).
- [#20](https://github.com/ELares/IronBus/issues/20): the edge resource
  constraints (thermal throttling, flash wear, RAM ceilings) this discipline
  controls for.
- [#111](https://github.com/ELares/IronBus/issues/111) /
  [#114](https://github.com/ELares/IronBus/issues/114) /
  [#284](https://github.com/ELares/IronBus/issues/284): the live macro-bench
  tasks the instrumentation follow-up overlaps.
