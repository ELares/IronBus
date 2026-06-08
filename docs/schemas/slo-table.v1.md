# `ironbus.slo-table.v1`

The normative, versioned, machine-readable form of the IronBus SLO target table: the data
artifact CI and the #111 macro-bench read targets from, not only the Markdown in
[SLO.md](../SLO.md). It is the residual of [#110](https://github.com/ELares/IronBus/issues/110)
that is buildable offline today (the measured floors are the device residual, tracked under
[#359](https://github.com/ELares/IronBus/issues/359)).

- **Schema name:** `ironbus.slo-table.v1`
- **`schema_version`:** `1`
- **Data file:** [`slo.v1.json`](slo.v1.json)
- **Source of truth:** [SLO.md](../SLO.md). The human-readable table is canonical for the NUMBERS;
  this JSON quotes them and must AGREE with it. The README, the code, and the issues are canonical
  upstream of SLO.md, exactly as SLO.md states.
- **Frozen by:** the drift gate [`scripts/ci/slo-table-check.sh`](../../scripts/ci/slo-table-check.sh).
  It asserts the JSON parses, carries `schema_version` `1`, has every required field on every row,
  and that the stated targets match the numbers in SLO.md (so SLO.md and the JSON cannot diverge).

> **NOT YET MEASURED.** Like SLO.md, every number here is a STATED TARGET or requirement, NOT a
> measured result. No row is ratified: every `measured` cell is `null` and every `ratified` flag is
> `false`. An unratified row is informational and cannot gate CI (per #110). Ratifying a cell needs
> a recorded run on the reference edge device (the device residual). See
> [Ratification](#ratification-how-a-measured-floor-fills-a-cell) below and the
> [SLO.md ratification process](../SLO.md#ratification-process).

## Why a machine-readable form

SLO.md is the operator-facing table. CI and the macro-bench need to read the SAME targets as DATA:
a versioned JSON with a `schema_version`, so a consumer (the #114 regression gate, a future
ratification tool, the macro-bench reading a row's gate) reads a target and compares against a
measured value without parsing Markdown. The JSON is the machine-readable record #110 asks for;
SLO.md is its human-readable companion. The drift gate keeps the two from diverging.

## `SloTable` (the top-level document)

| field            | type             | notes |
|------------------|------------------|-------|
| `schema_name`    | `string`         | `"ironbus.slo-table.v1"`, the frozen schema name |
| `schema_version` | `integer`        | the schema version; `1`. Bumped only on an INCOMPATIBLE field change (see [Versioning](#versioning-policy)) |
| `source_of_truth`| `string`         | `"docs/SLO.md"`; the human-readable table the numbers are quoted from |
| `note`           | `string`         | the not-yet-measured disclaimer carried in-band so a consumer of the JSON alone reads it |
| `margin_fraction`| `number`         | `0.2`; the documented ratification margin (a ratified gate is the measured value minus 20 percent), per the README measured-floor rule |
| `marquee_row_id` | `string`         | `"marquee"`; the id of the marquee row the rest of the table is calibrated around |
| `rows`           | `list[SloRow]`   | one row per SLO cell, keyed by `{device, message_size_bytes, fan_out, durability_mode}` plus its metric |

## `SloRow` (one SLO cell)

Each row is one cell of the table: a metric, the harness field that measures it, the gate
direction, the stated target (or `null` where SLO.md says "target TBD"), the conditions that key
the row, and the `measured` / `ratified` pair that stays empty until a device run ratifies it.

| field                | type                | notes |
|----------------------|---------------------|-------|
| `id`                 | `string`            | a stable, unique row id (e.g. `"marquee"`, `"steady-rss-tiny"`) |
| `device`             | `string \| null`    | the reference device (e.g. `"raspberry-pi-4"`); `null` where the row is per-profile and the device is not pinned |
| `message_size_bytes` | `integer \| null`   | the message size key; `null` where per-profile |
| `fan_out`            | `integer \| null`   | the fan-out (consumer count) key; `null` where per-profile |
| `durability_mode`    | `string \| null`    | one of `group-commit-fdatasync`, `async-page-cache`, `sync-per-message`; `null` where per-profile |
| `metric`             | `string`            | the metric this row gates (e.g. `throughput_msgs_per_sec`, `p99_latency`, `steady_rss_bytes`, `write_amplification`) |
| `harness_field`      | `string \| null`    | the exact #111 harness field that measures it (e.g. `results.p99_us`); `null` where the #111 harness does not measure it today (the recovery-time row) |
| `gate`               | `string`            | the gate direction: `">="` (a floor, higher passes) or `"<"` (a ceiling, lower passes) |
| `target`             | `number \| null`    | the stated target in `target_unit`; `null` where SLO.md says "target TBD" |
| `target_unit`        | `string`            | the unit of `target` and `measured`: `msgs_per_sec`, `microseconds`, `bytes`, `ratio`, `mb_per_sec` |
| `power_loss_safe`    | `bool \| null`      | the durability safety label (the async page-cache row is `false`, "not power-loss safe"); `null` where the row is not durability-mode specific |
| `source`             | `string`            | where the number comes from (the README quote, the SLO.md row, or the "target TBD" note) |
| `measured`           | `number \| null`    | the measured value (in `target_unit`) recorded on the reference device; `null` until ratified |
| `ratified`           | `bool`              | `true` only once the cell has completed the [ratification process](../SLO.md#ratification-process); `false` for every row today |

### Harness fields and units

The `harness_field` names match the #111 macro-bench provenance JSON exactly
(`crates/ironbus-bench/src/provenance.rs`, `ResultsInfo`): `results.msgs_per_sec`,
`results.mb_per_sec`, `results.p50_us`, `results.p99_us`, `results.p999_us`,
`results.steady_rss_bytes`, `results.write_amplification`. Latency targets are in MICROSECONDS to
match the harness `*_us` fields, so `< 6 ms` is stored as `6000`. The RAM ceiling is in bytes
(`64 MiB` = `67108864`) to match `results.steady_rss_bytes`. Write amplification is a unitless
ratio (the `>= 4x` flash-wear gate is stored as a ceiling `target` of `4` with `gate` `<`, so a
measured value at or above it fails). Throughput is `msgs_per_sec`.

## Ratification: how a measured floor fills a cell

A cell stays `measured: null, ratified: false` (informational, never gating CI) until it completes
the [SLO.md ratification process](../SLO.md#ratification-process). Concretely, for one row:

1. Run the #111 macro-bench (`crates/ironbus-bench/`) on the reference edge device for the row's
   exact `{device, message_size_bytes, fan_out, durability_mode}`, under
   [EDGE_RUN_DISCIPLINE.md](../EDGE_RUN_DISCIPLINE.md) (thermal control, storage state, harness
   isolation, the CoV / p99-drift steady-state criterion, the `>= 4h` sustained run).
2. The coordinated-omission self-test
   (`an_injected_stall_shows_up_in_the_recorded_tail`, #284) must pass, so the harness is shown
   honest before its number ratifies anything.
3. Archive the run's versioned provenance JSON (the raw `HdrHistogram`, `git_sha`, `host`,
   `config`, `reproduce`), so any percentile recomputes and the run re-runs.
4. Set `measured` to the value the harness recorded in `harness_field` (in `target_unit`). Set the
   GATE to the measured floor: the on-device value adjusted by `margin_fraction` (`0.2`). For a
   floor metric (`gate` `>=`, throughput) the ratified gate is `measured * (1 - margin_fraction)`;
   for a ceiling metric (`gate` `<`, a latency or write-amplification) it is
   `measured * (1 + margin_fraction)`. Flip `ratified` to `true` and bump `schema_version` only if
   the field set changed (ratifying a cell does not change the field set, so it does NOT bump the
   version; it is a data edit the drift gate re-checks against SLO.md).

The actual measured numbers are the device residual: they require the reference device and a
tagged baseline (v0.1.0), which is the maintainer action #359 names. Until then every cell is
honestly `null` / `false`, and SLO.md and this JSON say so.

## Versioning policy

`schema_version` is bumped only on an INCOMPATIBLE change to the field SET or a field's meaning (a
rename, removal, reorder, or type change of a row or top-level field). Adding a NEW row, or
editing a row's data (filling `measured`, flipping `ratified`, setting a ratified `target` from a
measured floor) does NOT bump it: those are data edits the drift gate re-validates against SLO.md.
When a bump is genuinely required, the change is: bump `schema_version` in `slo.v1.json`, freeze a
new `slo-table.vN.md`, update this document and the drift gate, and update
[SLO.md](../SLO.md).

## See also

- [SLO.md](../SLO.md): the human-readable SLO target table and the full ratification process.
- [EDGE_RUN_DISCIPLINE.md](../EDGE_RUN_DISCIPLINE.md): the run discipline a canonical measurement
  must follow before it can ratify a cell.
- [`crates/ironbus-bench/`](../../crates/ironbus-bench): the #111 macro-bench, the instrument whose
  provenance fields the `harness_field` names match.
- [loss-report.v1.md](loss-report.v1.md): the other versioned schema doc, the convention this one
  follows.
