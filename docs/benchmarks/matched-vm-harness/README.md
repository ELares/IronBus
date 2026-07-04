# Matched-VM cross-broker harness (IronBus vs Redpanda)

The guest-resident harness for [../REDPANDA_MATCHED_2026_07.md](../REDPANDA_MATCHED_2026_07.md):
both brokers and both load clients run **inside one lima `vz` Linux VM** so the VM is the
identical substrate for both (removing the macOS study's Redpanda-in-VM confound).

## Layout
- `lib2.sh` — per-broker lifecycle (IronBus driver-spawned; Redpanda production-mode systemd),
  fairness pins (TMPDIR→ext4, `write_caching=false`, `--smp=6`, tier validation at each start).
- `cell2.sh` — one normalized cell → `results.jsonl` (schema identical to the macOS study).
- `row2.sh` / `all2.sh` — one row / the full P1·P2·P3·C1·L1 × 128·1024 matrix, serial, 3-run medians.
- `p2multi.sh` — IronBus P2 under `bench --producers N` (1/2/4/8).
- `rp_multi.sh` — Redpanda P2 under N parallel `kafka-producer-perf-test` clients (1/4/8).
- `medians2.py` — dedupe (latest per cell) + medians + comparison table.

## Paths
All paths are **guest-relative** (`$HOME/xb2`, `$HOME/IronBus`); the scripts assume the guest
layout described in the study doc. Run inside the VM after building `ironbus` in-guest and
copying the Kafka perf tools + provisioning Redpanda. No host paths, no account details.

## Raw data
`results.jsonl` (matrix), `p2multi.jsonl` (IronBus sweep), `rp_multi.jsonl` (Redpanda sweep) —
the exact rows behind every number in the study doc.
