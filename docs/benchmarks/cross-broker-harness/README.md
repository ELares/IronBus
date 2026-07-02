# Cross-broker benchmark harness

The exact scripts behind [CROSS_BROKER_2026_07.md](../CROSS_BROKER_2026_07.md) — the
IronBus vs Kafka vs Redpanda vs NATS single-node matrix ([#1023](https://github.com/ELares/IronBus/issues/1023)).
Four files:

| Script | Role |
| --- | --- |
| `lib.sh` | Per-broker lifecycle helpers (`fresh_datadir_B` / `start_B TIER` / `wait_ready_B` / `stop_B`), tier-config **validation** (it dies if a broker is not really running the pinned durability knobs), and the serial-discipline port checks. All locations are environment-parameterized (see below). |
| `run_cell.sh` | Runs ONE (row × size × broker) invocation with the row's pinned driver flags, parses the tool output, and appends one normalized JSON line to `results/results.jsonl`. |
| `run_row.sh` | Runs one matrix row across sizes × applicable brokers, serially: fresh data dir → start broker at the row's tier → pilot run → freeze the count (pilot rate × 20 s, clamped) → (Kafka: one unrecorded JVM warm-up) → 3 timed runs → teardown → cooldown. |
| `run_all.sh` | All seven rows (P1 P2 P3 P4 C1 L1 L2) in protocol order, plus a leftover-listener check. |

The matrix, the tiers, the fairness rules, and the results are documented in
[CROSS_BROKER_2026_07.md](../CROSS_BROKER_2026_07.md); this README covers only how to run it.

## Prerequisites

Everything is **user-local** — no system installs, no root on the host. The layout `lib.sh`
expects under one work root (call it `$XBENCH_SCRATCH`):

- `IronBus/target/release/ironbus` (+ `ironbus-bench`) — a **release** build of this repo
  (`cargo build --release`). The IronBus cells spawn their own isolated broker; no manual
  lifecycle.
- `brokers/nats/` — the `nats-server` and `nats` (CLI) binaries, plus
  `nats-sync-always.conf`: a JetStream config whose store dir is `brokers/nats/data`, port
  4222, and — the pinned knob the harness greps for — `sync_interval: always`.
- `brokers/kafka/kafka_2.13-4.3.1/` — the Kafka 4.3.1 tarball unpacked, and
  `brokers/kafka/server-single.properties`: a single-node KRaft config
  (`process.roles=broker,controller`, log dirs under `brokers/kafka/data/kraft-logs`,
  listener on 9092, **no** `log.flush.interval.messages` line — the harness generates the
  fsync/group tier variants from it). A JDK 21 under `brokers/jdk/...` or an exported
  `JAVA_HOME`.
- `brokers/lima/bin/limactl` + a lima VM named `redpanda` (vz backend) with Redpanda
  v26.1.12 installed as a systemd service inside, its Kafka API forwarded to host 9092, and
  `brokers/redpanda/rpk` on the host. Redpanda is Linux-only — the VM is mandatory on macOS,
  and it is exactly why the study treats Redpanda's numbers as an appendix datapoint (a guest
  fsync through a virtual disk is not power-loss-comparable; see the study doc §1).
- `python3` on PATH (the output parser), and the usual BSD userland (`lsof`, `awk`).

Kafka and Redpanda share host port 9092 — that is safe **because the harness is strictly
serial** (it asserts no broker port is in use before starting each cell, and tears each
broker down afterwards). Do not run any of these brokers on the side while a matrix is going.

## Configuration (environment variables)

The committed scripts contain **no machine-specific paths**; the one required variable:

```sh
export XBENCH_SCRATCH=$HOME/xbench-work   # the work root described above
```

Every location can also be overridden individually (`IRONBUS_BIN`, `IRONBUS_RELEASE_DIR`,
`NATS_DIR`, `NATS_SERVER`, `NATS_CLI`, `KAFKA_DIR`, `KAFKA_HOME`, `JAVA_HOME`,
`LIMA_BIN_DIR`, `LIMA_HOME`, `RPK`, `RP_VM`, `KAFKA_CLUSTER_UUID`, `XBENCH_DIR`) — see the
top of `lib.sh`. Logs land in `$XBENCH_DIR/logs/`, results in
`$XBENCH_DIR/results/results.jsonl`.

Run-shaping variables (read by `run_row.sh`):

- `XBENCH_SMOKE=1` — tiny-count validation pass (1 KiB only, 1 timed run, short cooldowns):
  run this first to prove the whole rig end to end in minutes.
- `XBENCH_ONLY_BROKER=<name>` — restrict a row to one broker (targeted rerun).

## Running

```sh
export XBENCH_SCRATCH=$HOME/xbench-work

# prove the rig first (minutes):
XBENCH_SMOKE=1 ./run_all.sh

# the real matrix (hours — the fsync-wall rows are slow by nature):
./run_all.sh          # or one row at a time: ./run_row.sh P1

# reduce medians per cell from results.jsonl (row/size/broker -> median of the timed runs)
python3 - <<'EOF'
import json, collections, statistics
runs = collections.defaultdict(list)
for line in open(f"{__import__('os').environ['XBENCH_SCRATCH']}/xbench/results/results.jsonl"):
    r = json.loads(line)
    if r["mode"] != "timed":
        continue
    runs[(r["row"], r["size"], r["broker"])].append(r)
out = {}
for (row, size, broker), rs in sorted(runs.items()):
    rs.sort(key=lambda r: r["msgs_per_sec"])
    med = rs[len(rs) // 2]
    out[f"{row}/{size}/{broker}"] = {k: med[k] for k in ("msgs_per_sec", "p50_us", "p99_us")}
print(json.dumps(out, indent=1))
EOF
```

Run on a **quiet machine** (no browsers, no indexing, mains power): the L2 row measures
tens-of-microseconds wake-up latencies, and background load measurably distorts it — the
study's run 1 vs run 2 delta on that row is documented in
[#1032](https://github.com/ELares/IronBus/issues/1032).
