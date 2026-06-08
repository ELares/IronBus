# The baseline comparison rig and the CI regression gate

This document specifies the apples-to-apples baseline comparison rig and the CI
performance regression gate for IronBus
([#114](https://github.com/ELares/IronBus/issues/114), under the SLO and
benchmarking parent [#19](https://github.com/ELares/IronBus/issues/19)). It
covers the peer-run methodology, the matched-durability-label requirement, the
Little's-Law reporting, and the regression-gate thresholds. The rig and the gate
are implemented as pure, testable code in the `publish = false`
[`crates/ironbus-bench/`](../crates/ironbus-bench) crate, off the shipped
`ironbus` binary's dependency graph.

> **What is implemented vs what is a host residual.** The RIG (the comparison
> schema, the lints, and the Little's-Law math) and the GATE (the rolling-median
> regression logic and the CI wiring) are implemented and tested. The actual LIVE
> RUNS of NATS / Redis / Mosquitto under identical workloads are a documented
> host residual: they require the peer brokers installed on the host or device,
> which CI cannot do. The rig is READY to ingest those runs (it validates and
> serializes whatever rows it is fed); the live multi-broker numbers are a
> follow-up. See [The peer-run host residual](#the-peer-run-host-residual).

---

## Why a rig, not just a benchmark

A baseline comparison is honest only if both sides run the SAME workload under
the SAME durability semantics on the SAME device. The trap the parent issue names
is mislabeled durability turning a comparison into marketing: quoting IronBus's
durable group-commit-`fdatasync` number against a peer's page-cache (no-fsync)
number. The rig makes that error a BUILD FAILURE, not a footnote.

The rig is the schema plus three lints plus one computation:

1. a versioned comparison-report schema (each row is `{system, durability,
   message_size, device, throughput, p50/p99/p999, ...}`);
2. the durability-label-match lint (the central anti-marketing guard);
3. the appendix-labeling rule (cluster-class brokers are appendix-only);
4. the Little's-Law queue-occupancy reporting (`L = lambda * W`).

Source: [`crates/ironbus-bench/src/comparison.rs`](../crates/ironbus-bench/src/comparison.rs).

---

## The peer-run methodology (matched workloads, matched durability)

Every baseline runs on the SAME device, the SAME message size, and the SAME
durability label as the IronBus row it is compared against. The peer
configurations, each chosen so its durability label is explicit and reportable:

| Peer | Configuration | Durability label(s) reported |
| --- | --- | --- |
| NATS JetStream | File-backed stream, default `FileStore` block sizes, `MaxAckPending = 1000` (the JetStream backpressure lever, matched in the run) | `nats-jetstream-file` |
| Redis Streams | `appendfsync everysec` AND `appendfsync always`, BOTH reported (never just the faster one) | `redis-aof-everysec`, `redis-aof-always` |
| Mosquitto (MQTT) | QoS 1 primary; QoS 0 and QoS 2 also reported | `mqtt-qos1` (primary), `mqtt-qos0`, `mqtt-qos2` |

The durability label travels with every number. A page-cache or `everysec` row is
labeled NOT power-loss safe (an acknowledged write can be lost on a brownout), so
a reader is never misled; the rig encodes this in
`DurabilityLabel::is_power_loss_safe`.

### The matched-durability-label requirement (the central lint)

Building a comparison report in which a compared pair carries MISMATCHED
durability labels FAILS the report build. This is the anti-marketing guard: you
cannot assemble a report that compares IronBus's durable group-commit-`fdatasync`
number against a peer's page-cache (no-fsync) number. The lint also requires a
compared pair to share a message size and a device (it is not the same workload
otherwise).

The lint has teeth: a mismatched pair fails (`ReportError::DurabilityMismatch`),
a matched pair passes. Both are unit-tested
(`a_mismatched_durability_pair_fails_the_build`,
`a_matched_durability_pair_builds`).

### Appendix labeling: cluster-class brokers are appendix-only

Kafka and Redpanda are JVM / Seastar multi-node systems, not single-edge-node
brokers, so including them as edge SLO gates would be dishonest. They are
EXCLUDED from the edge gates and may appear ONLY in an x86-ref informational
appendix, clearly labeled `not an edge-class comparison`. The schema encodes
this: an edge-gate row that names Kafka or Redpanda fails the build
(`ReportError::ClusterClassInEdgeGate`); they are legal only in
`Placement::Appendix`, which carries the fixed `not an edge-class comparison`
label. Tested by `kafka_as_an_edge_gate_row_fails_the_build` and
`redpanda_is_allowed_in_the_appendix`.

---

## Little's-Law queue occupancy (`L = lambda * W`)

At a fixed throughput, in-flight count and latency are coupled, so a bounded p99
at a target rate implies a bounded queue occupancy. The rig reports
`L = lambda * W` per row (throughput times p99 latency in seconds), so a reader
can confirm p99 stays within the SLO at the chosen concurrency bound rather than
taking the number on faith. For example, 60,000 msg/s at a 5 ms p99 implies
`L = 60000 * 0.005 = 300` messages in flight. Implemented as
`comparison::littles_law_occupancy` and `ComparisonRow::littles_law_occupancy_p99`,
unit-tested on the known case and rejecting any non-finite or negative input.

---

## The CI regression gate

The gate compares the per-device 7-day ROLLING MEDIAN of the current run history
against the last released tag's per-device median, and fails CI only on real
drift. Source:
[`crates/ironbus-bench/src/regression.rs`](../crates/ironbus-bench/src/regression.rs);
CI binary
[`crates/ironbus-bench/src/bin/regression_gate.rs`](../crates/ironbus-bench/src/bin/regression_gate.rs).

### A rolling median, not a single-run percent gate

Single-run percent gates flap on the noise of edge hardware (thermal throttling,
SD garbage collection) and train people to ignore them. The gate medians the last
7 days of runs PER DEVICE, so one bad run cannot fire it and one lucky run cannot
hide a real regression. A median is robust to a single outlier
(`the_median_is_robust_to_one_outlier`).

### The thresholds

Versus the last released tag's per-device median, on ANY device the gate FAILS
when:

| Metric | Direction | Limit | Rationale |
| --- | --- | --- | --- |
| throughput median | drop | `> 10%` | a real throughput regression |
| p99 median | rise | `> 15%` | the SLO is felt at the tail |
| p99.9 median | rise | `> 25%` | the wider tolerance the deep tail's noise needs |

The numbers are pinned by a test (`the_thresholds_are_exactly_the_issue_values`)
so a silent loosening of the gate is a CI failure.

### Advisory-only noisy runs

A run whose warm-up coefficient-of-variation (CoV) check FAILED is marked
advisory-only and is EXCLUDED from the medians on both sides, so it can neither
fire the gate nor mask a regression (`an_advisory_run_does_not_fire_the_gate`,
`an_advisory_run_does_not_mask_a_real_regression`). If every run in a window is
advisory, the gate cannot conclude and passes with a logged reason rather than
firing on noise. The warm-up CoV criterion itself is specified in
[EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md).

### The human-ratify escape hatch

An edge regression requires a human to ratify before it blocks a release. The
gate distinguishes a fired-but-ratified outcome (a documented PASS, with the audit
reason recorded, never silent) from a hard fail. The CI binary takes
`--ratify "<reason>"`, which converts a fired gate into a logged pass
(`a_human_ratified_regression_passes_with_an_audit_reason`, and the binary test
`a_real_regression_fires_and_exits_nonzero`).

### Graceful no-op when there is no baseline yet

There is NO released tag / baseline history yet (`v0.1.0` is the maintainer's
action). With no prior history, the gate GRACEFULLY NO-OPS: it PASSES (exit 0)
with a logged "no baseline history yet", rather than failing or erroring. This is
the explicit, tested first-run behavior
(`an_empty_baseline_passes_with_a_no_baseline_log`, and the binary tests
`no_baseline_file_is_a_graceful_no_op_exit_zero` /
`a_missing_baseline_path_is_also_a_graceful_no_op`). The
`perf regression gate (#114)` CI job runs the gate binary against the checked-in
history fixture and asserts it took exactly this no-op path. Once a release
archives a baseline JSON, the job passes it via `--baseline` and the gate begins
enforcing.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | pass / graceful no-op (no baseline) / insufficient (all-advisory) data / ratified override |
| `1` | an un-ratified rolling-median regression fired |
| `2` | a usage or input error (missing or invalid `--history`) |

### The input JSON

The gate reads a history JSON (the current per-device runs plus an optional
`now_unix_secs` window anchor) and an optional baseline JSON (the last released
tag's runs). Each run point maps directly onto the provenance JSON a real
`ironbus-bench` run emits (`device`, `unix_secs`, `throughput_msgs_per_sec`,
`p99_us`, `p999_us`, `warmup_cov_ok`). A worked fixture lives at
[`crates/ironbus-bench/tests/fixtures/regression-history.json`](../crates/ironbus-bench/tests/fixtures/regression-history.json).

---

## The peer-run host residual

The rig and the gate are CI-runnable WITHOUT installing any peer broker. What is
NOT done here, and is not faked:

- The ACTUAL runs of NATS JetStream, Redis Streams, and Mosquitto under the
  identical workloads above. These need the peer brokers installed on the host or
  the reference edge device, which CI cannot provide. The rig is ready to ingest
  the resulting rows (the schema + lints validate them), but the live numbers are
  a follow-up.
- The LIVE per-device IronBus baseline history the gate enforces against. That
  comes from the #111 macro-bench run on the reference edge device under the
  [edge run discipline](EDGE_RUN_DISCIPLINE.md), archived per
  [the SLO ratification process](SLO.md#ratification-process). Until a release
  archives that baseline, the gate no-ops by design.

---

## References

- [#114](https://github.com/ELares/IronBus/issues/114): this task (the baseline
  comparison rig and the CI regression gate).
- [#19](https://github.com/ELares/IronBus/issues/19): the SLO, methodology, and
  benchmarking parent (the durability-labeling rule, the cluster-class exclusion,
  the Little's-Law reporting, and the regression-budget decision).
- [SLO.md](SLO.md): the SLO target table and the ratification process a baseline
  row follows before it can gate.
- [EDGE_RUN_DISCIPLINE.md](EDGE_RUN_DISCIPLINE.md): the run-discipline protocol
  (thermal, storage, isolation, the warm-up CoV criterion that decides advisory
  vs eligible) every canonical run must follow.
- [`crates/ironbus-bench/`](../crates/ironbus-bench): the harness, the comparison
  rig (`comparison.rs`), and the regression gate (`regression.rs`,
  `bin/regression_gate.rs`).
