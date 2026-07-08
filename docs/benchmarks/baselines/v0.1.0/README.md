# v0.1.0 archived baselines

The performance and coverage baselines snapshotted at the `v0.1.0` release, so the
two dormant CI regression gates have something to compare against and begin
enforcing (issue #1068). Each subsequent release archives its own
`docs/benchmarks/baselines/<tag>/` directory; the CI gates point at the newest.

## `perf-baseline.json` — the #114 rolling-median perf gate baseline

Format: the `ironbus_bench::regression::Baseline` struct
(`crates/ironbus-bench/src/regression.rs`) — `{ "tag", "runs": [RunPoint...] }`,
one `RunPoint` per archived reference-device run
(`device`, `unix_secs`, `throughput_msgs_per_sec`, `p99_us`, `p999_us`,
`warmup_cov_ok`). The `regression-gate` job in `.github/workflows/ci.yml` passes
this file via `--baseline`, so the gate runs its ENFORCING path (per-device
7-day rolling median vs this baseline, thresholds: throughput -10%, p99 +15%,
p99.9 +25%) instead of the pre-release no-op.

**Provenance / honesty note.** These numbers are seeded from the committed
reference run history (`crates/ironbus-bench/tests/fixtures/regression-history.json`,
which encodes the documented ~60k msg/s reference-Pi4 target). Per
[`docs/BASELINE_RIG.md`](../../../BASELINE_RIG.md), the LIVE per-device macro-bench
runs (the #111 reference-device numbers) are a documented host/device residual
that CI cannot produce, so this is the best faithful baseline available at the
first tag. **Owner action to re-anchor:** replace these runs with the medians
from a real `ironbus bench` macro-bench run on the reference edge device (#111)
when one is next taken, keeping the same schema and `"tag": "v0.1.0"`.

## `coverage-baseline.json` — the #385 coverage-regression gate baseline

Format: `{ "tag", "line_coverage_pct", "tolerance_pct", "note" }`. The nightly
`coverage-regression-gate` step (`.github/workflows/nightly.yml`) reads it and
enforces `current >= line_coverage_pct - tolerance_pct`.

`line_coverage_pct` is `null` at cut time on purpose: the authoritative number is
what the nightly `coverage` lane computes with `cargo llvm-cov --workspace
--all-features` on the CI runner (which carries the cmake/cc toolchain the
all-features instrumented build needs — aws-lc-sys/zstd-sys). It is not faithfully
reproducible off that runner, so it is deliberately left for the maintainer to
fill from the first post-tag nightly run (which prints the percentage and retains
`lcov.info`). While `null`, the gate step logs a documented PENDING no-op and does
not fail. Setting the number arms it. See the file's own `note`.
