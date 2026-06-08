# IronBus service-level objectives (SLO target table)

This document is the target table for the IronBus performance SLOs and the
process by which a target becomes a ratified, versioned SLO. It is derived from
the README's [Performance targets](../README.md#performance-targets) section and
from the performance design issues
([#19](https://github.com/ELares/IronBus/issues/19), the SLO and methodology
parent) and [#110](https://github.com/ELares/IronBus/issues/110), the task to
ratify and version this table). The code, the README, and the issues are
canonical; where they state a number this document quotes it, and where they do
not it marks the metric as a target to be set during ratification.

> **NOT YET MEASURED. Read this first.**
>
> IronBus does not yet have ratified, measured baselines. Every number in the
> tables below is a STATED TARGET or requirement (from the README and #19 /
> #110), NOT a measured result. No row here has been ratified against a measured
> baseline, and nothing in this document should be read as an SLO that is "met".
>
> The measurement instrument is the macro-bench harness
> ([`crates/ironbus-bench/`](../crates/ironbus-bench), task #111). Its live
> coordinated-omission self-test
> (`an_injected_sigstop_shows_up_in_the_recorded_tail`) is `#[ignore]`d on shared
> CI because the SIGSTOP freeze does not reliably manifest in the tail on
> GitHub's shared runners; it is reliable only on a stable host.
> [#284](https://github.com/ELares/IronBus/issues/284) tracks making it a
> reliable gate. Until a run on the reference edge device is recorded and
> archived, there are no committed measured numbers to ratify the targets
> against. See [Ratification process](#ratification-process) below.

---

## How a target is measured: the instrument

Each target below is tied to a metric the macro-bench harness actually emits, so
the SLO is grounded in a measurable quantity rather than a slogan. The harness
is an OPEN-LOOP load generator (constant target arrival rate, Poisson
inter-arrival jitter, schedule fixed before the run) that drives the SHIPPING
`ironbus` binary over real loopback sockets through the real
[#11](https://github.com/ELares/IronBus/issues/11) client. It records each
message's end-to-end latency from its INTENDED send time (wrk2 style), so a
stalled broker cannot hide its tail (no coordinated omission).

The headline results the harness emits, with their source in
`crates/ironbus-bench/src/harness.rs` and `provenance.rs`:

| Metric | Harness field | How it is computed |
| --- | --- | --- |
| Throughput, msg/s | `results.msgs_per_sec` | messages the receiver recorded / wall-clock run seconds |
| Throughput, MB/s | `results.mb_per_sec` | payload bytes delivered / run seconds, divided by 1024x1024 |
| p50 latency | `results.p50_us` | `histogram.value_at_quantile(0.50)`, microseconds |
| p99 latency | `results.p99_us` | `histogram.value_at_quantile(0.99)`, microseconds |
| p99.9 latency | `results.p999_us` | `histogram.value_at_quantile(0.999)`, microseconds |
| max latency | `results.max_us` | the single worst bucket, microseconds |
| Steady-state RAM | `results.steady_rss_bytes` | the median of broker RSS samples taken mid-run (`null` if the platform cannot read another process's RSS) |
| Write amplification | `results.write_amplification` | on-disk data-dir bytes at run end / user payload bytes produced (`null` if nothing was produced) |
| Tail trustworthy? | `results.tail_resolution_ok` | `true` only at >= 1000 recorded samples, below which p99.9 is not a real measured quantile |

Latencies land in an `HdrHistogram` configured for 1 us to 60 s at 3 significant
figures (~0.1% bucket error); the RAW histogram is archived per run
(`histogram_v2_deflate_base64`) so any percentile recomputes and runs merge
across windows. Every run also emits a versioned provenance JSON
(`schema_version`, `git_sha`, `git_dirty`, `build`, `host`, `clock_source`,
`config`, `results`, the raw histogram, and a copy-pasteable `reproduce`
command), which is exactly the provenance a ratified row must archive.

---

## The SLO target table

Every row is a STATED TARGET, not a measured result, and its STATUS column says
so explicitly. The TARGET column quotes the README or the issue where a number
is stated, and reads "target TBD" where no number is stated yet and the value is
to be set during ratification from the first measured run on the device.

### Marquee figure

The README defines one marquee figure; the rest of the table is calibrated
around it.

> "The provisional marquee target is 256-byte messages, a single consumer,
> durable group-commit `fdatasync`, sustaining at least 60,000 messages per
> second with p99 latency under 6 ms on a Raspberry Pi 4."
> (README, Performance targets)

| Field | Value |
| --- | --- |
| Profile / conditions | 256 B payload, fan-out 1, durability = group-commit `fdatasync`, edge-min (Raspberry Pi 4) |
| Target: throughput | sustained `>= 60,000 msg/s` (quoted above; #110 phrases it `>= 60k msg/s sustained ... until measured`) |
| Target: p99 latency | `< 6 ms` (quoted above) |
| Measured by | `results.msgs_per_sec`, `results.p99_us` |
| Status | **Target, not yet ratified against a measured baseline.** "Provisional" in the README; "provisionally ... until measured" in #110. |

### Throughput and latency, per profile

| Metric | Definition (harness field) | Target (source) | Conditions / profile | Status |
| --- | --- | --- | --- | --- |
| Sustained throughput, msg/s | `results.msgs_per_sec` | `>= 60,000 msg/s` for the marquee (256 B, fan-out 1, group-commit fsync, Pi 4). The README's tenet wording is "sustaining tens of thousands of small messages per second per core." Other devices/sizes/durability modes: target TBD pending ratification (the #19 sketch numbers, e.g. ~80k on Pi4 / ~120k on RK3399, are explicitly "illustrative, to be ratified", not targets). | per {device, message size, fan-out, durability mode} | Target, not yet ratified against a measured baseline. |
| Sustained throughput, MB/s | `results.mb_per_sec` | target TBD pending ratification (the #19 sketch MB/s figures are illustrative only). | per {device, message size, fan-out, durability mode} | Target, not yet ratified against a measured baseline. |
| p50 latency | `results.p50_us` | target TBD pending ratification (the README and #19 state the SLO gate at p99, not p50; p50 is reported and tracked). | per {device, message size, fan-out, durability mode} | Target, not yet ratified against a measured baseline. |
| p99 latency | `results.p99_us` | `< 6 ms` for the marquee (256 B, fan-out 1, group-commit fsync, Pi 4). #19 proposes "p99 gates"; other rows TBD pending ratification. | per {device, message size, fan-out, durability mode} | Target, not yet ratified against a measured baseline. |
| p99.9 latency | `results.p999_us` | target TBD; #19 proposes "p99.9 reported and tracked for regression," not a hard gate. Only trustworthy when `tail_resolution_ok` is `true` (>= 1000 samples). | per {device, message size, fan-out, durability mode} | Target, not yet ratified against a measured baseline. |

### Durability-mode rows (must travel together)

A throughput number is meaningless without its durability mode, so the table
publishes the three modes side by side and labels the page-cache row as not
power-loss safe (#110: page-cache rows carry a literal `not power-loss safe`
label). The default durability is group-commit `fdatasync` before ack (README
key decisions; edge default in #116).

| Durability mode | Definition | Target | Safety label | Status |
| --- | --- | --- | --- | --- |
| group-commit `fdatasync` (default, marquee) | ack only after the covering group-commit `fdatasync`; an ack means durable past a brownout (#116) | the marquee `>= 60,000 msg/s`, `p99 < 6 ms` (Pi 4, 256 B, fan-out 1) | power-loss safe | Target, not yet ratified against a measured baseline. |
| async (page-cache) | ack before fsync; survives a process crash but not power loss | target TBD pending ratification | **not power-loss safe** | Target, not yet ratified against a measured baseline. |
| sync-per-message | one `fdatasync` per message (no group commit) | target TBD pending ratification (the #19 fsync-bound row, e.g. ~150 to 600 durable commits/s on SD/eMMC, is illustrative only) | power-loss safe | Target, not yet ratified against a measured baseline. |

### Edge resource rows

These are STATED constraints from the edge-profile design issues, treated as
hard SLOs per the README's Edge First tenet ("RAM ceilings, flash-wear budgets
... are first-class configuration, not afterthoughts").

| Metric | Definition (harness field) | Target (source) | Conditions / profile | Status |
| --- | --- | --- | --- | --- |
| Steady-state RAM ceiling | `results.steady_rss_bytes` (median broker RSS mid-run) | `64 MiB` ceiling on the `tiny` edge profile, itemized into a per-buffer budget that provably sums under the ceiling, with a refuse-to-boot guard ([#115](https://github.com/ELares/IronBus/issues/115)). Other profiles: target TBD. | edge / `tiny` profile | Target, not yet ratified against a measured baseline. |
| Write amplification | `results.write_amplification` (data-dir bytes / payload bytes) | target TBD pending ratification. #19 mandates it as a REPORTED metric (flash-wear realism); whether it is an SLO gate or informational is an open decision in #19. | edge profile (SD / eMMC), per durability mode | Target, not yet ratified against a measured baseline. |
| Recovery time bound | not measured by the #111 harness today | target TBD. The README bounds the LOSS from a corruption skip (at most one segment or 64 MiB per event, at most 1% of durable bytes per recovery, then freeze read-only), but states no recovery-TIME number; a recovery-time SLO is to be set during ratification. | edge profile | Target, not yet ratified against a measured baseline. |

> The per-device throughput, MB/s, p99, and durable-rate numbers that appear in
> the #19 issue body (the "Illustrative SLO sketch") are labeled in that issue as
> "Illustrative ... NOT final" and "to be ratified." They are reproduced here
> only as the starting proposal for ratification, never as targets, and never as
> measured results.

---

## Ratification process

A target becomes a ratified, versioned SLO only by the following path. Until a
row completes it, the row stays "Target, not yet ratified against a measured
baseline" and, per #110, an unmeasured cell is informational and cannot gate CI.

1. **Run the instrument on the reference device.** Run the #111 macro-bench
   harness (`crates/ironbus-bench/`) on the reference edge device for the row's
   exact conditions (device, message size, fan-out, durability mode), under the
   [edge run discipline](EDGE_RUN_DISCIPLINE.md) #19 mandates: the named
   reference active cooling with per-window junction-temperature and CPU-frequency
   logging (a throttle in the steady-state window fails the run), a fixed
   card/eMMC model secure-erased to a known state at a fixed 50% fill, the broker
   and harness pinned to disjoint CPU sets with harness CPU/RSS reported
   separately, the warm-up = `max(60 s, page-cache-fill + 2 segment rolls)`
   discarded, steady state declared only when 5 consecutive 30 s windows show
   throughput `CoV <= 3%` and `p99 drift <= 10%`, and at least one `>= 4h`
   sustained run per release that passes only if hour-1-to-hour-4 `p99 drift
   < 25%`.
2. **Archive the provenance.** Keep the run's versioned provenance JSON,
   including the RAW `HdrHistogram` (`histogram_v2_deflate_base64`), the `git_sha`
   / `git_dirty`, the `host` (device), the `config`, and the `reproduce`
   command, so any percentile recomputes and the run is re-runnable. A row is
   only as trustworthy as `results.tail_resolution_ok` allows: p99.9 needs
   >= 1000 recorded samples to be a real quantile.
3. **The coordinated-omission self-test must pass on a stable host.** The
   instrument is only honest if it does not commit coordinated omission. The
   injected-stall self-test (`an_injected_sigstop_shows_up_in_the_recorded_tail`)
   must pass on a stable host (`cargo test -p ironbus-bench -- --ignored`), where
   it is reliable. It is `#[ignore]`d on shared CI and is NOT a per-PR gate;
   [#284](https://github.com/ELares/IronBus/issues/284) tracks wiring it into a
   reliable gate (a stable / self-hosted runner or an in-broker fault-injection
   seam). Do not ratify a row from a run whose harness could not be shown honest.
4. **Set the committed gate as a measured floor.** Per the README ("every
   published SLO is a measured floor (the on-device p99 minus a 20 percent
   margin)") and #110 (commit each cell as the measured p50/p99 minus a 20%
   margin, never an aspirational figure), the ratified target is the MEASURED
   value with the margin applied, not the aspirational sketch number.
5. **Version the table.** Record the ratified row with its provenance: the
   `git_sha` of the build, the device, the durability mode, message size, and
   fan-out, and bump this table's version. #110 wants this as versioned data so
   CI and the macro-bench can read targets and compare against them; this
   document is the human-readable companion to that versioned record.

### Not yet measured (disclaimer)

No row in this document has completed the process above. There are no committed
measured baselines for IronBus, because the live coordinated-omission self-test
is `#[ignore]`d on shared CI (reliable only on a stable host, tracked #284) and
no run on the reference edge device has been recorded and archived. Therefore:

- Every TARGET here is a STATED requirement from the README or #19 / #110.
- No target is presented as a measured result, and no SLO is claimed to be "met".
- The remaining work to ratify these targets is to run the #111 harness on the
  reference device, archive the provenance, and version the table; that
  measurement is tracked under #110 (and gated honest by #284).

---

## References

- [README, Performance targets](../README.md#performance-targets): the marquee
  figure and the measured-floor-minus-20%-margin rule.
- [`crates/ironbus-bench/`](../crates/ironbus-bench): the macro-bench harness
  (#111), the measurement instrument; its `harness.rs` and `provenance.rs`
  define every metric and provenance field cited above.
- [#19](https://github.com/ELares/IronBus/issues/19): the SLO, methodology, and
  benchmarking parent (reference devices, illustrative sketch, p99-gates
  proposal, warm-up / steady-state rules).
- [#110](https://github.com/ELares/IronBus/issues/110): ratify and version this
  table from measured floors.
- [#284](https://github.com/ELares/IronBus/issues/284): make the injected-stall
  coordinated-omission self-test a reliable CI gate (currently `#[ignore]`d).
- [EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md) (#113): the run-discipline
  protocol every canonical run must follow (thermal control, storage state,
  harness isolation, the CoV / p99-drift steady-state criterion, the `>= 4h`
  sustained run, and the `>= 4x` write-amplification gate) before its number can
  ratify a row.
- [#115](https://github.com/ELares/IronBus/issues/115): the `tiny` profile RAM
  budget (the 64 MiB ceiling).
- [#116](https://github.com/ELares/IronBus/issues/116): edge durability defaults
  (ack-after-group-commit, fatal-fsync).
- [#117](https://github.com/ELares/IronBus/issues/117): the
  hardware-constraint-to-knob mapping table.
- [#20](https://github.com/ELares/IronBus/issues/20): the edge resource
  constraints these rows respect.
