# Golden-path acceptance scenario (the release gate)

This is the runbook for the single scripted end-to-end acceptance scenario that
ties the IronBus subsystems together, from install through power-loss recovery
to in-place upgrade. It is the project's release gate (issue
[#133](https://github.com/ELares/IronBus/issues/133)): a tagged release per #22
must pass this run, alongside the #21 crash-class gates.

The scenario exists as ONE orchestrated integration test that drives the REAL
`ironbus` binary over real loopback sockets and a real on-disk data directory,
end to end, and emits ONE machine-readable PASS/FAIL summary plus the captured
loss report, the measured install-to-first-message, and a throughput number for
the [SLO table](SLO.md) (#19) and the #1 success criteria to consume.

- The harness:
  [`crates/ironbus-cli/tests/acceptance.rs`](../crates/ironbus-cli/tests/acceptance.rs),
  the test `golden_path_acceptance_install_to_recovery_to_upgrade`.
- The CI gate: the `golden-path acceptance gate (#133)` job in
  [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), which runs the
  CI-runnable steps on x86_64 Linux and uploads the summary artifact.
- The focused per-step tests (each a gate on its own invariant) live in
  [`crates/ironbus-cli/tests/golden_path.rs`](../crates/ironbus-cli/tests/golden_path.rs);
  `acceptance.rs` is the orchestrated whole-story run.

## What is REAL and what is HONEST

The run is REAL: nothing is mocked. Every step spawns `ironbus serve`, connects
a real client over TCP, and produces and consumes over the wire against the
actual on-disk segments. The installer step runs the actual
[`scripts/install.sh`](../scripts/install.sh) fail-closed `verify_checksum`
function over the just-built binary, then installs it through the installer's own
`install_binary` (the same atomic write-then-rename, and the same
`ironbus.prev` rollback retention exercised in step 10), and runs the INSTALLED
copy for the rest of the run.

The run is HONEST about what cannot run in CI. The parts that genuinely require
the physical aarch64 reference device or a real `dm-flakey` block layer are NOT
faked:

- The `< 60 s` install-to-first-message bound is a property of the REFERENCE
  DEVICE (#1). The CI run MEASURES install-to-first-message on its own host and
  records the number, but it does NOT assert the `< 60 s` bound (a shared CI
  runner's number does not mean anything about the device). The device runbook
  below asserts the bound on the device.
- The real power cut is a `dm-flakey` run on the device. The CI run uses the
  SIMULATED power cut: the on-disk unsynced-tail model (a torn tail appended
  past the last durable record) that the `crash_recovery` and `golden_path`
  sweeps already use. That model is faithful to the "unsynced page-cache drop"
  failure but is not a real block-layer fault.
- The broker throughput SLO (the marquee `>= 60,000 msg/s` on a Raspberry Pi 4)
  is DEVICE-ONLY and is measured by the macro-bench harness
  ([`crates/ironbus-bench/`](../crates/ironbus-bench), #111), not by this run.
  The acceptance summary's `cli_pub_throughput_msgs_per_sec_floor` is a
  process-spawn-bound FLOOR (one `pub` process+connection per sample), recorded
  so the summary always carries a measured number; it is explicitly NOT the
  broker throughput and not the device SLO.

## The ten steps and the invariant each proves

Each step cites the invariant it proves (from
[INVARIANTS.md](INVARIANTS.md): I1 durable prefix, I2 ack-implies-durable, I3
bounded reported loss) and the owning issue, so a single failing assertion
points at one invariant and one issue.

| # | Step | Proves | Issues | CI scope |
| --- | --- | --- | --- | --- |
| 1 | Install via the fail-closed installer; a tampered artifact is rejected; capture install-to-first-message | installer fail-closed (never places an unverified binary) | #17, #103, #1 | CI runs the install + tamper-reject + measures the time; the `< 60 s` BOUND is device-only |
| 2 | Boot zero-config; `/healthz` and `/readyz` come up bound to loopback only | loopback-only bind, a real router (404 for unknown paths) | #16, #18 | CI |
| 3 | Produce N mixed-size records; every ack carries a durable offset (ack implies durable) | I2 | #3, #6 | CI |
| 4 | Fan out to a broadcast consumer and a competing group with a keyed subset | single total durable order, per-group at-least-once, single-consumer keyed delivery order (the cross-consumer per-key `key_shared` routing is covered by the focused `ironbus-server` engine tests) | #3, #9, #288 | CI |
| 5 | Overload producers past the ring: spill-to-disk then drop-new with a REPORTED counter | spill-then-shed, reported-not-silent, no indefinite hang | #10, #13 | CI |
| 6 | Power-cut mid-batch | a simulated power cut is applied | #21 | CI runs the SIMULATED unsynced-tail cut; the real `dm-flakey` cut is device-only |
| 7 | Recover: consistent durable prefix, torn-tail truncation, structured loss report; the Prometheus counter and the on-disk report agree | I1, I3, counter-equals-report | #7, #8, #16 | CI |
| 8 | Resume via stored cursor; a consumer below earliest_retained gets exactly one truncation and resets | durable-cursor resume, one-time truncation | #11, #13 | CI |
| 9 | Inspect offline with the broker stopped: peek/dump reads only to the durable HWM and reports the same loss as recovery; fixed exit codes | offline inspection agrees with recovery, the fixed exit-code scheme | #15 | CI |
| 10 | Upgrade in place via the REAL `scripts/install.sh` (atomic swap, the prior binary retained as `ironbus.prev` by the installer itself); the data dir opens cleanly with no migration within the major version | atomic swap, real `ironbus.prev` rollback retention, clean reopen with no migration | #17 | CI |

## Running it in CI (x86_64)

The CI gate runs exactly this:

```sh
cargo test -p ironbus-cli --locked --test acceptance -- --nocapture --exact \
  golden_path_acceptance_install_to_recovery_to_upgrade
```

`--nocapture` surfaces the machine-readable summary in the job log. Setting
`IRONBUS_ACCEPTANCE_SUMMARY=<path>` makes the harness also write the summary
JSON to that path (the CI job uploads it as the `golden-path-acceptance-summary`
artifact). The summary shape is:

```json
{
  "acceptance": "golden-path",
  "issue": 133,
  "result": "PASS",
  "host_arch": "x86_64",
  "host_os": "linux",
  "install_to_first_message_ms": 90,
  "cli_pub_throughput_msgs_per_sec_floor": 18,
  "cli_pub_throughput_records": 200,
  "throughput_note": "... a floor only; the broker throughput SLO is device-only via the #111 macro-bench",
  "loss_report": {"loss": {"bytes": 20, "events": [{"segment": 0, "start": 4525, "end": 4545, "reason": "torn_tail"}]}},
  "steps": [ { "n": 1, "name": "...", "invariants": "...", "issues": "...", "scope": "ci", "result": "PASS" }, ... ]
}
```

The `loss_report` is the offline reader's own structured loss object verbatim
(the three units: bytes lost, the `[start, end)` byte-offset range, and the named
reason). `scope` is `ci` for a CI-runnable step and `ci-simulated-device-real`
for step 6 (the CI run does the simulated cut; the real cut is device-only).

## Running it on the aarch64 reference device (the device runbook)

The SAME harness runs on the reference device. The device run additionally
exercises the device-only steps that CI cannot:

1. Build (or cross-build) the static aarch64-musl binary and install it on the
   device with the real installer:

   ```sh
   # On the device (or via the published release):
   curl -fsSL https://raw.githubusercontent.com/ELares/IronBus/main/scripts/install.sh | sh
   ironbus --version
   ```

2. Run the acceptance test on the device, writing the summary out:

   ```sh
   IRONBUS_ACCEPTANCE_SUMMARY="$HOME/acceptance-summary.json" \
     cargo test -p ironbus-cli --release --test acceptance -- --nocapture --exact \
     golden_path_acceptance_install_to_recovery_to_upgrade
   ```

3. Assert the device-only bounds the CI run cannot (these are NOT in the
   automated harness, because the harness must not fail on a CI runner that
   cannot meet a device bound):

   - **Install-to-first-message `< 60 s` (#1).** Read
     `install_to_first_message_ms` from the device summary and confirm it is
     under 60000.
   - **Real power cut (`dm-flakey`).** Replace the simulated unsynced-tail step
     with a real `dm-flakey` run: produce a batch, drop writes mid-batch via a
     `dm-flakey` table, then recover and confirm the same I1 durable prefix,
     torn-tail truncation, and the counter-equals-report agreement step 7
     asserts. The `dm-flakey` setup is the same one the #21 crash-class device
     gate uses.
   - **Throughput SLO.** Run the #111 macro-bench
     ([`crates/ironbus-bench/`](../crates/ironbus-bench)) for the marquee
     conditions (256 B, fan-out 1, group-commit `fdatasync`) under the
     [edge run discipline](EDGE_RUN_DISCIPLINE.md) (#113): the named reference
     cooling with per-window thermal/frequency logging and the
     throttle-quarantine rule, the fixed secure-erased card at 50% fill, the
     broker and harness pinned to disjoint CPU sets, the CoV / p99-drift
     steady-state criterion, and the mandated `>= 4h` sustained run with the
     hour-1-to-hour-4 p99-drift gate. Confirm the measured `msgs_per_sec` and
     `p99_us` against the [SLO table](SLO.md). This is the device throughput
     number, NOT the acceptance summary's process-spawn-bound floor.

4. Archive the device summary and the macro-bench provenance JSON with the
   release, per the [SLO ratification process](SLO.md#ratification-process).

## Why this is a faithful gate, not coverage theater

- It drives the real binary and the real data dir, not a mock or an in-process
  engine handle, so a regression that breaks the wire path, the storage path, or
  the recovery path fails the gate.
- The non-vacuity anchors are explicit: the overload step asserts the server's
  reject counter EQUALS the client's observed shed count (never a silent drop);
  the recovery step asserts the offline loss report and the online Prometheus
  counter AGREE byte for byte; the health step asserts an unknown path is a real
  404 so the healthy markers are not vacuous.
- It is honest about scope: the device-only bounds are documented here as a
  manual runbook and are NOT faked in CI, and the summary labels its throughput
  number as a floor, never the device SLO.
