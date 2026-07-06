# Monitoring IronBus (Grafana + Prometheus)

This is the operator guide for watching a running broker. The normative metric
catalog lives in [METRICS.md](METRICS.md) (every name is frozen by a CI test); this
doc is the dashboard, the alerts, and the "what do I actually look at" map built on
top of it.

The artifacts live in [`packaging/grafana/`](../packaging/grafana/):

| File | What it is |
| --- | --- |
| `ironbus-dashboard.json` | The importable Grafana dashboard (8 rows, ~32 panels). |
| `dashboard_gen.py` | Generates the JSON from a curated panel spec (regenerate, do not hand-edit). |
| `check_grounded.py` | Local check: every metric the dashboard references is one the broker emits. |
| `ironbus-alerts.yml` | Prometheus alerting rules (critical / warning / info). |
| `prometheus-scrape-example.yml` | Example scrape + `rule_files` config. |

## What IronBus exposes

The broker serves four loopback HTTP endpoints on `--health-addr` (off by default;
set it, e.g. `serve --health-addr 127.0.0.1:9090`). The surface is unauthenticated,
so `serve` refuses a non-loopback `--health-addr` without `--health-allow-public`
(see [THREAT_MODEL.md](THREAT_MODEL.md)).

- **`GET /metrics`** -- Prometheus text exposition (the dashboard + alerts source).
- **`GET /healthz`** -- liveness (accept-loop watchdog). 200 while the loop ticks,
  503 only after a full `--health-liveness-window-ms` with no progress.
- **`GET /readyz`** -- readiness. 503 while the writer is frozen or shutting down,
  200 once it accepts writes.
- **`GET /admin`** -- opt-in (`serve --enable-admin`) read-only JSON snapshot, the
  same data `ironbus admin` renders. Survives a metric rename (it parses no metric
  names), so it is the fallback when a dashboard breaks.

Distributed traces are a separate, opt-in path (OTLP/gRPC behind the non-default
`otlp` Cargo feature + `--enable-otlp-export`); see the Tracing section of
[METRICS.md](METRICS.md). Metrics below need none of it.

## Quick start

1. **Run the broker with the health endpoint:**
   ```sh
   ironbus serve --data-dir /var/lib/ironbus --addr 127.0.0.1:7777 --health-addr 127.0.0.1:9090
   ```
2. **Point Prometheus at it** (job name kept prefixed `ironbus` so the down-alert
   matches) -- see `prometheus-scrape-example.yml`, which also wires `rule_files:
   [ironbus-alerts.yml]`.
3. **Import the dashboard:** Grafana -> Dashboards -> Import -> upload
   `ironbus-dashboard.json`, then pick your Prometheus data source. The `Job` and
   `Instance` variables default to "All", so it works for one broker or a fleet.

## The dashboard, row by row

Each row answers one operator question:

1. **Golden signals** -- _is it alive and safe right now?_ `writer_healthy`,
   `power-loss safety`, `produce saturated`, version, headline `consumer_lag`,
   produce/ack rate, uptime. Glance here first; the three health tiles go red on an
   incident.
2. **Throughput** -- produce / deliver / ack / redeliver rates and bytes/s. Redeliver
   rising while ack is flat = consumers not acking in time.
3. **Durability-barrier latency** -- `fsync` and `append` p50/p99/p99.9 + a heatmap,
   with the **6 ms p99 SLO** line ([SLO.md](SLO.md)). This is the headline perf signal;
   the fsync is the real cost of a durable ack.
4. **Consumer lag & delivery** -- default + per-group lag, in-flight, top-10
   per-consumer lag, redelivery & dead-letter rates, DLQ depth.
5. **Backpressure & shedding** -- every `*_shed_total` rate by reason plus the live
   CoDel / retry / egress controller gauges. All zero unless a knob is enabled; a
   rising series names exactly which control is shedding and why.
6. **Data loss & integrity** -- _these should stay flat ZERO._ Force-reap and
   consumer-truncation rates, last-recovery loss bytes (by reason), skips, and the
   hard-crash checkpoint-repair counter. Any movement here is an incident, not noise.
7. **Durability posture & edge resources** -- active durability level, unsynced
   bytes at risk, flash write-amplification (with the **4x gate**), physical vs
   logical bytes/s, the daily write-budget meter, and RAM headroom.
8. **Retention & offsets** -- segment reclaim (loss-free vs lossy force-reap) and the
   durable-head vs committed-cursor offsets.

## Alerts

`ironbus-alerts.yml` groups by severity. The ones that mean **act now**:

| Alert | Fires when | Why it matters |
| --- | --- | --- |
| `IronbusDown` | scrape fails 1m | broker or health endpoint unreachable |
| `IronbusWriterFrozen` | `ironbus_writer_healthy == 0` | a fatal fsync froze the writer; produces refused |
| `IronbusForceReapDataLoss` | `segments_force_reaped_total` rises | drop-oldest deleted maybe-unconsumed data (disk at cap) |
| `IronbusConsumerTruncation` | `truncations_total` rises | a live consumer lost a span of records |
| `IronbusRecoveryDataLoss` | `recovery_data_loss_bytes > 0` | the last restart lost previously-durable data |

Each **act-now** alert has a response runbook. `IronbusWriterFrozen` → the frozen-writer
runbook, [RECOVERY.md section 8.6](RECOVERY.md#86-the-runbook-the-writer-froze) (a fatal fsync
fail-stopped the writer to hold "acked ⇒ durable"; recovery is fix-storage-then-restart, since
a freeze is terminal and cannot self-thaw). `IronbusForceReapDataLoss` /
`IronbusConsumerTruncation` / `IronbusRecoveryDataLoss` → the data-loss and segment runbooks,
[RECOVERY.md sections 8.1 and 8.4](RECOVERY.md).

Warnings cover degrading-but-not-down posture: `IronbusPowerLossUnsafe` (relaxed
durability is active), `IronbusFsyncP99High` (> 6 ms SLO), `IronbusConsumerLagHigh`,
`IronbusRedeliveryStorm`, `IronbusDeadLettering`, `IronbusBackpressureShedding`,
`IronbusProduceSaturated`, `IronbusWriteAmplificationHigh` (>= 4x), `IronbusRamHeadroomLow`,
`IronbusDailyWriteBudgetOver`. Info covers notable events that are not outages:
`IronbusRestarted`, `IronbusHardCrashRecovered`, `IronbusConsumerOverflowSaturated`,
`IronbusConsumerLabelsDropped`.

Thresholds marked `TUNE` in the rules file (consumer lag, RAM floor, unsynced bytes)
are deployment-specific starting points -- set them to your backlog and RAM budget.
The fsync **6 ms** threshold is the SLO ([SLO.md](SLO.md)). The write-amplification
alert fires at **~20x**, the live lz4 bound -- NOT 4x: 4x is the `--compression none`
raw-bytes CI gate, and the live ratio is over STORED (post-lz4) bytes, so a healthy
compressible workload runs above 4x ([EDGE_CONSTRAINTS.md](EDGE_CONSTRAINTS.md)).

> **Note:** `IronbusDown` keys off `up{job=~"ironbus.*"}`, so the Prometheus scrape
> job must be named with an `ironbus` prefix (the example scrape config does this). If
> you rename the job, update the rule -- otherwise it silently stops detecting a down
> broker (a false negative).

## The "no silent loss" contract on the dashboard

IronBus's design rule is that every shed / drop / skip / truncation / freeze
increments a stable, documented counter ([METRICS.md](METRICS.md)). Row 6 is that
contract made visual: in steady state every series there is **flat zero**, so the
dashboard's job is to make any non-zero impossible to miss. If you only watch a few
things, watch `ironbus_writer_healthy`, `ironbus_segments_force_reaped_total`,
`ironbus_truncations_total`, and `ironbus_recovery_data_loss_bytes`.

## Regenerating the dashboard

The JSON is generated, not hand-edited. After changing a panel spec (or when the
metric catalog moves):

```sh
python3 packaging/grafana/dashboard_gen.py     # rewrites ironbus-dashboard.json
python3 packaging/grafana/check_grounded.py     # asserts every metric it references is emitted
```

`check_grounded.py` greps the server source for the authoritative `ironbus_*` names
and fails if a panel references one the broker does not emit -- run it before
committing a regenerated dashboard (it is not wired into the Rust CI). Validate the
alert rules with `promtool check rules packaging/grafana/ironbus-alerts.yml` if you
have the Prometheus toolchain.

## See also

- [METRICS.md](METRICS.md) -- the normative, CI-frozen metric catalog and the
  resilience-observability contract.
- [SLO.md](SLO.md) -- the performance targets the latency/throughput alerts key off.
- [USAGE.md](USAGE.md) -- the operator guide; its "Health and metrics" section links
  here.
