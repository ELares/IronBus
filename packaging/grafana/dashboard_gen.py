#!/usr/bin/env python3
"""Generate the IronBus Grafana dashboard JSON from a compact panel spec.

IronBus renders Prometheus text exposition on `GET /metrics` (see docs/METRICS.md,
the CI-frozen catalog). This script turns a curated, data-driven panel spec into an
importable Grafana dashboard, so the dashboard stays grounded in the real emitted
`ironbus_*` metric names and is regenerated (not hand-edited) when the catalog moves.

Every PromQL expression below references ONLY a name in the frozen catalog. The
companion local check `check_grounded.py` re-parses the generated JSON and asserts
each `ironbus_*` token it references is a real emitted metric (it greps the server
source for the authoritative names), so a typo or a metric rename is caught before
commit instead of silently breaking a panel. Run it after regenerating; it is not
wired into the Rust CI, so run it by hand (see docs/MONITORING.md).

Usage:
  python3 dashboard_gen.py            # writes ironbus-dashboard.json next to this file
  python3 dashboard_gen.py --stdout   # prints the JSON instead
"""
import argparse, json, os, sys

# The standard per-broker selector. Panels filter by the templated job+instance so the
# dashboard works for a single broker or a fleet (the variables default to "All").
J = 'job=~"$job",instance=~"$instance"'
RI = "$__rate_interval"  # Grafana's scrape-aware rate window
PROM = {"type": "prometheus", "uid": "${datasource}"}

# Grafana threshold-step colors.
RED, GREEN, ORANGE, BLUE, TEXT = "red", "green", "orange", "blue", "text"


def q(expr):
    """A rate() over a counter, with the scrape-aware interval."""
    return f"rate({expr}{{{J}}}[{RI}])"


def hq(quantile, bucket):
    """A histogram_quantile over a *_bucket series, summed by le (the correct shape)."""
    return f"histogram_quantile({quantile}, sum by (le) (rate({bucket}{{{J}}}[{RI}])))"


# ---- the curated rows. Each panel is a dict; `kind` picks the renderer. ----
# kinds: stat | bool (red/green health stat) | ts (timeseries) | heatmap
ROWS = [
    ("Golden signals -- is the broker alive and safe?", [
        {"kind": "bool", "title": "Writer healthy", "w": 6,
         "expr": f"ironbus_writer_healthy{{{J}}}", "good": 1,
         "map": {"1": ("HEALTHY", GREEN), "0": ("FROZEN", RED)},
         "desc": "ironbus_writer_healthy: 1 live, 0 frozen by a fatal fsync (the integrity-freeze gauge). 0 is a hard incident: the durable-log writer has stopped."},
        {"kind": "bool", "title": "Power-loss safety", "w": 6,
         "expr": f"ironbus_durability_power_loss_unsafe{{{J}}}", "good": 0,
         "map": {"0": ("SAFE", GREEN), "1": ("UNSAFE", RED)},
         "desc": "ironbus_durability_power_loss_unsafe: 1 when the active durability level waives I2 (acked data can be lost on a power cut). 0 under the default `sync`."},
        {"kind": "bool", "title": "Produce saturated", "w": 6,
         "expr": f"ironbus_produce_saturated{{{J}}}", "good": 0,
         "map": {"0": ("OK", GREEN), "1": ("SATURATED", RED)},
         "desc": "ironbus_produce_saturated: 1 once the broker has shed at least one produce (admission exhaustion). The portable throughput-collapse signal."},
        {"kind": "stat", "title": "Version", "w": 6, "unit": "none", "textMode": "name",
         "expr": f"ironbus_build_info{{{J}}}", "legend": "{{version}}",
         "desc": "ironbus_build_info{version=...}: the running build version (value is always 1; the version is the label)."},
        {"kind": "stat", "title": "Consumer lag (default group)", "w": 6, "unit": "short",
         "expr": f"ironbus_consumer_lag{{{J}}}", "legend": "lag",
         "thresholds": [(None, GREEN), (10000, ORANGE), (100000, RED)],
         "desc": "ironbus_consumer_lag = flushed head - committed cursor for the default group. The headline backlog signal."},
        {"kind": "stat", "title": "Produce rate", "w": 6, "unit": "ops",
         "expr": q("ironbus_produced_total"), "legend": "msg/s",
         "desc": "rate(ironbus_produced_total): messages appended per second (the throughput baseline)."},
        {"kind": "stat", "title": "Ack rate", "w": 6, "unit": "ops",
         "expr": q("ironbus_acks_total"), "legend": "ack/s",
         "desc": "rate(ironbus_acks_total): commits per second."},
        {"kind": "stat", "title": "Uptime", "w": 6, "unit": "s",
         "expr": f"ironbus_uptime_seconds{{{J}}}", "legend": "uptime",
         "desc": "ironbus_uptime_seconds: seconds since the broker started (monotonic-derived; a sudden drop means a restart)."},
    ]),
    ("Throughput", [
        {"kind": "ts", "title": "Message rates (produce / deliver / ack / redeliver)", "w": 12, "unit": "ops",
         "targets": [(q("ironbus_produced_total"), "produced"),
                     (q("ironbus_delivered_total"), "delivered"),
                     (q("ironbus_acks_total"), "acked"),
                     (q("ironbus_redelivered_total"), "redelivered")],
         "desc": "The core flow rates. Redelivered rising while acked is flat means consumers are not acking inside the lease (at-least-once retries, not loss)."},
        {"kind": "ts", "title": "Byte throughput (produced)", "w": 12, "unit": "Bps",
         "targets": [(q("ironbus_produced_bytes_total"), "produced bytes/s")],
         "desc": "rate(ironbus_produced_bytes_total): logical (key+headers+payload) bytes appended per second."},
        {"kind": "ts", "title": "Dedup (idempotency window)", "w": 12, "unit": "ops",
         "targets": [(q("ironbus_dedup_hits_total"), "dedup hits/s (benign)"),
                     (q("ironbus_dedup_out_of_window_total"), "out-of-window/s")],
         "desc": "rate(ironbus_dedup_hits_total) is idempotent retries absorbed (benign). rate(ironbus_dedup_out_of_window_total) rising means the dedup window is too small for the retry interval -- size --dedup-max-ids / --dedup-window-ms. Zero unless opt-in dedup is used."},
    ]),
    ("Durability-barrier latency (the headline performance signal)", [
        {"kind": "ts", "title": "fsync latency (produce durability barrier)", "w": 12, "unit": "s",
         "targets": [(hq("0.50", "ironbus_fsync_duration_seconds_bucket"), "p50"),
                     (hq("0.99", "ironbus_fsync_duration_seconds_bucket"), "p99"),
                     (hq("0.999", "ironbus_fsync_duration_seconds_bucket"), "p99.9")],
         "slo_line": 0.006,
         "desc": "histogram_quantile over ironbus_fsync_duration_seconds_bucket: the produce-time fdatasync latency. The dashed line is the 6 ms p99 SLO (docs/SLO.md)."},
        {"kind": "ts", "title": "Append latency (append + fsync)", "w": 12, "unit": "s",
         "targets": [(hq("0.50", "ironbus_append_duration_seconds_bucket"), "p50"),
                     (hq("0.99", "ironbus_append_duration_seconds_bucket"), "p99"),
                     (hq("0.999", "ironbus_append_duration_seconds_bucket"), "p99.9")],
         "slo_line": 0.006,
         "desc": "histogram_quantile over ironbus_append_duration_seconds_bucket: the whole durable-append (append + fsync) latency."},
        {"kind": "heatmap", "title": "fsync latency distribution (heatmap)", "w": 24, "unit": "s",
         "expr": f"sum by (le) (rate(ironbus_fsync_duration_seconds_bucket{{{J}}}[{RI}]))",
         "desc": "The full fdatasync latency distribution over the fixed registry buckets. A widening high band is rising tail-latency / device pressure."},
    ]),
    ("Consumer lag & delivery", [
        {"kind": "ts", "title": "Consumer lag (default + per work-group)", "w": 12, "unit": "short",
         "targets": [(f"ironbus_consumer_lag{{{J}}}", "default"),
                     (f"ironbus_group_consumer_lag{{{J}}}", "{{group}}")],
         "desc": "ironbus_consumer_lag and ironbus_group_consumer_lag{group}: flushed head minus committed cursor. Rising = consumers falling behind."},
        {"kind": "ts", "title": "In-flight (leased, not yet acked)", "w": 12, "unit": "short",
         "targets": [(f"ironbus_in_flight{{{J}}}", "default"),
                     (f"ironbus_group_in_flight{{{J}}}", "{{group}}")],
         "desc": "ironbus_in_flight / ironbus_group_in_flight: messages leased to consumers but not yet acked. Pinned at max_in_flight means the consumer is the bottleneck."},
        {"kind": "ts", "title": "Top 10 per-consumer lag", "w": 12, "unit": "short",
         "targets": [(f'topk(10, ironbus_consumer_lag_records{{{J}}})', "{{consumer}}")],
         "desc": "topk(10, ironbus_consumer_lag_records{consumer}): the laggiest consumers. {consumer=\"__overflow__\"} is the folded lag of all over-cap consumers past the 1024-series cap."},
        {"kind": "ts", "title": "Redelivery & dead-letter rate", "w": 12, "unit": "ops",
         "targets": [(q("ironbus_redelivered_total"), "redelivered/s"),
                     (q("ironbus_dead_lettered_total"), "dead-lettered/s")],
         "desc": "rate(ironbus_redelivered_total) is at-least-once retry pressure; rate(ironbus_dead_lettered_total) is poison messages exceeding MaxDeliver routed to the DLQ."},
        {"kind": "ts", "title": "DLQ records (cumulative, survives restart)", "w": 12, "unit": "short",
         "targets": [(f"ironbus_dlq_records_total{{{J}}}", "dlq records")],
         "desc": "ironbus_dlq_records_total: records durably written to the dead-letter sink. The durable complement of dead_lettered."},
        {"kind": "ts", "title": "Consumer cardinality (1024-series cap)", "w": 12, "unit": "short",
         "targets": [(f"ironbus_consumer_overflow_saturated{{{J}}}", "overflow saturated (0/1)"),
                     (f'increase(ironbus_consumer_labels_dropped_total{{{J}}}[1h])', "labels dropped (1h)")],
         "desc": "ironbus_consumer_labels_dropped_total: distinct consumers past the 1024-series cap, folded into {consumer=\"__overflow__\"}. ironbus_consumer_overflow_saturated == 1 means that fold is now a lower bound (very high consumer cardinality)."},
    ]),
    ("Backpressure & shedding (the resilience taxonomy -- every shed is counted)", [
        {"kind": "ts", "title": "Shed rates (by reason)", "w": 12, "unit": "ops", "stack": True,
         "targets": [(q("ironbus_produce_rejected_total"), "disk-full drop-new"),
                     (q("ironbus_codel_shed_total"), "codel (latency)"),
                     (q("ironbus_codel_backstop_shed_total"), "codel backstop"),
                     (q("ironbus_fire_and_forget_shed_total"), "fire-and-forget (QoS-0)"),
                     (q("ironbus_egress_shed_total"), "egress AIMD"),
                     (q("ironbus_wal_fsync_headroom_shed_total"), "wal fsync headroom"),
                     (q("ironbus_daily_write_budget_sheds_total"), "daily write budget"),
                     (f'rate(ironbus_retry_shed_total{{{J}}}[{RI}])', "retry budget ({{side}})")],
         "desc": "Every backpressure shed counter, as a rate. All zero unless the matching knob is enabled. A rising series names exactly which control is shedding."},
        {"kind": "ts", "title": "Backpressure controllers (live state)", "w": 12, "unit": "short",
         "targets": [(f"ironbus_codel_sojourn_estimate_ms{{{J}}}", "codel sojourn (ms)"),
                     (f"ironbus_egress_limit{{{J}}}", "egress limit (4-128)"),
                     (f"ironbus_retry_ratio{{{J}}} / 1e6", "retry ratio (fraction)")],
         "desc": "ironbus_codel_sojourn_estimate_ms (latency the CoDel law acts on), ironbus_egress_limit (AIMD concurrency, halves on a degrading sink), ironbus_retry_ratio/1e6 (shed fraction vs the budget)."},
    ]),
    ("Data loss & integrity (these should stay FLAT ZERO -- any movement is an incident)", [
        {"kind": "ts", "title": "Force-reap & consumer truncation rate", "w": 12, "unit": "ops",
         "targets": [(q("ironbus_segments_force_reaped_total"), "force-reaped segments/s"),
                     (q("ironbus_truncations_total"), "consumer truncations/s"),
                     (q("ironbus_truncated_records_total"), "truncated records/s")],
         "desc": "ironbus_segments_force_reaped_total (drop-oldest deleting maybe-unconsumed data) and ironbus_truncations_total (a live consumer losing a span). Non-zero = real data loss."},
        {"kind": "ts", "title": "Last-recovery loss (bytes)", "w": 12, "unit": "bytes",
         "targets": [(f"ironbus_recovery_data_loss_bytes{{{J}}}", "data-loss bytes"),
                     (f"ironbus_recovery_truncated_bytes{{{J}}}", "truncated bytes (incl torn tail)"),
                     (f"ironbus_bytes_skipped{{{J}}}", "bytes skipped (recovery-loss total)"),
                     (f"ironbus_quarantine_bytes{{{J}}}", "quarantine bytes")],
         "desc": "ironbus_recovery_data_loss_bytes is the headline bytes-lost at the last recovery (torn tails excluded). ironbus_bytes_skipped is the reconciled recovery-loss byte total; ironbus_quarantine_bytes is the forensic corrupt-copy footprint on disk."},
        {"kind": "ts", "title": "Last-recovery loss by reason", "w": 12, "unit": "short",
         "targets": [(f"ironbus_recovery_loss_records{{{J}}}", "records: {{reason}}"),
                     (f"ironbus_recovery_loss_bytes{{{J}}}", "bytes: {{reason}}")],
         "desc": "ironbus_recovery_loss_records{reason} and ironbus_recovery_loss_bytes{reason}: records and bytes dropped at the last recovery, by ReasonCode (torn_tail, corrupt_record_*, sequence_gap, scrubber_suspect, unresolved_dict_id) -- the cause AND magnitude of an incident."},
        {"kind": "ts", "title": "Skips & checkpoint-repair", "w": 12, "unit": "short",
         "targets": [(f"ironbus_records_skipped{{{J}}}", "records skipped (recovery-loss total)"),
                     (f'increase(ironbus_counter_checkpoint_repair_total{{{J}}}[1h])', "ckpt repairs (1h)")],
         "desc": "ironbus_records_skipped is the reconciled recovery-loss record total. A non-zero ironbus_counter_checkpoint_repair_total means a hard crash (kill -9) occurred and reconciliation restored the lower bound."},
        {"kind": "ts", "title": "Loss-locator offsets (where in the log)", "w": 12, "unit": "short",
         "targets": [(f"ironbus_last_skip_offset{{{J}}}", "last skip offset (high-water)"),
                     (f"ironbus_last_dead_lettered_offset{{{J}}}", "last dead-letter offset (-1=none)")],
         "desc": "ironbus_last_skip_offset (highest log offset any skip/loss reached, cross-restart monotonic) and ironbus_last_dead_lettered_offset (-1 = none): when a loss/dead-letter alert fires, these say WHERE in the log to look."},
    ]),
    ("Durability posture & edge resources (flash / RAM)", [
        {"kind": "stat", "title": "Active durability level", "w": 8, "unit": "none", "textMode": "name",
         "expr": f"ironbus_durability_level_info{{{J}}}", "legend": "{{level}}",
         "desc": "ironbus_durability_level_info{level=sync|interval|async|none}: the active level (value 1). `sync` is the power-loss-safe default."},
        {"kind": "ts", "title": "Un-fsynced bytes at risk", "w": 16, "unit": "bytes",
         "targets": [(f"ironbus_durability_unsynced_bytes{{{J}}}", "unsynced bytes")],
         "desc": "ironbus_durability_unsynced_bytes: acked-but-not-yet-fdatasync'd bytes at risk on a power cut. Always 0 under `sync`; the live loss window under a relaxed level."},
        {"kind": "ts", "title": "Flash write amplification", "w": 12, "unit": "none", "decimals": 3,
         "targets": [(f"ironbus_write_amp_ratio{{{J}}}", "physical/logical")],
         "slo_line": 20,
         "desc": "ironbus_write_amp_ratio = physical / STORED (post-compression) bytes. The dashed line is the ~20x LIVE bound (docs/EDGE_CONSTRAINTS.md L217: derived 20x, observed ~7x healthy) -- NOT the 4x figure, which is the `--compression none` raw-bytes CI gate. Under the default lz4 codec the ratio inflates for small compressible payloads even as real flash wear falls, so 4x is normal here; correlate with rate(ironbus_physical_bytes_written)."},
        {"kind": "ts", "title": "Flash bytes written (physical vs logical)", "w": 12, "unit": "Bps",
         "targets": [(q("ironbus_physical_bytes_written"), "physical B/s (flash wear)"),
                     (q("ironbus_logical_bytes_written"), "logical B/s (stored)")],
         "desc": "rate of ironbus_physical_bytes_written (real flash-wear volume: frames + segment headers/footers) vs ironbus_logical_bytes_written (stored, post-compression)."},
        {"kind": "ts", "title": "Daily physical write budget", "w": 12, "unit": "bytes",
         "targets": [(f"ironbus_physical_bytes_written_today{{{J}}}", "written today"),
                     (f"ironbus_daily_physical_write_budget_bytes{{{J}}}", "budget (0 = off)")],
         "desc": "The opt-in flash-wear governor: ironbus_physical_bytes_written_today vs ironbus_daily_physical_write_budget_bytes (resets at the UTC day boundary). At the budget, produces shed."},
        {"kind": "ts", "title": "RAM headroom (against the ceiling)", "w": 12, "unit": "bytes",
         "targets": [(f"ironbus_ram_headroom_bytes{{{J}}} != -1", "ram headroom")],
         "desc": "ironbus_ram_headroom_bytes = ram_ceiling_bytes - RSS. The -1 unavailable sentinel (no ceiling set, or RSS unreadable) is filtered out; falling toward 0 means the OOM cliff is near."},
    ]),
    ("Retention & offsets", [
        {"kind": "ts", "title": "Segment reclaim rate", "w": 12, "unit": "ops",
         "targets": [(q("ironbus_segments_reaped_total"), "reaped (loss-free)/s"),
                     (q("ironbus_segments_force_reaped_total"), "force-reaped (lossy!)/s")],
         "desc": "ironbus_segments_reaped_total is healthy consumer-safe reclaim; ironbus_segments_force_reaped_total is the drop-oldest lossy reclaim (should be zero)."},
        {"kind": "ts", "title": "Log offsets (head vs committed)", "w": 12, "unit": "short",
         "targets": [(f"ironbus_flushed_offset{{{J}}}", "flushed (durable head)"),
                     (f"ironbus_committed_offset{{{J}}}", "committed (default cursor)")],
         "desc": "ironbus_flushed_offset (durable log head) and ironbus_committed_offset (default-group cursor). The gap is the lag; both should climb together."},
    ]),
]


# ---------------------------------------------------------------------------
def thresholds(steps):
    return {"mode": "absolute", "steps": [{"value": v, "color": c} for v, c in steps]}


def mappings(m):
    return [{"type": "value", "options": {k: {"text": t, "color": c} for k, (t, c) in m.items()}}]


def base_fieldconfig(unit, decimals=None, thr=None, custom=None):
    d = {"unit": unit}
    if decimals is not None:
        d["decimals"] = decimals
    if thr is not None:
        d["thresholds"] = thr
    if custom is not None:
        d["custom"] = custom
    return {"defaults": d, "overrides": []}


def panel_stat(spec, pid, gp):
    is_bool = spec["kind"] == "bool"
    fc = base_fieldconfig(
        spec.get("unit", "none"),
        decimals=spec.get("decimals"),
        thr=thresholds(spec["thresholds"]) if "thresholds" in spec
        else (thresholds([(None, GREEN if spec.get("good") == 1 else GREEN)]) if not is_bool else None),
    )
    if is_bool:
        good = spec["good"]
        steps = [(None, GREEN), (1, RED)] if good == 0 else [(None, RED), (1, GREEN)]
        fc["defaults"]["thresholds"] = thresholds(steps)
        fc["defaults"]["mappings"] = mappings(spec["map"])
    return {
        "id": pid, "type": "stat", "title": spec["title"], "gridPos": gp,
        "datasource": PROM, "description": spec.get("desc", ""),
        "fieldConfig": fc,
        "options": {
            "colorMode": "background" if is_bool else "value",
            "graphMode": "none" if is_bool else "area",
            "justifyMode": "auto", "textMode": spec.get("textMode", "auto"),
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        },
        "targets": [{"refId": "A", "datasource": PROM, "expr": spec["expr"],
                     "legendFormat": spec.get("legend", ""), "instant": True}],
    }


def panel_ts(spec, pid, gp):
    custom = {
        "drawStyle": "line", "lineInterpolation": "linear", "lineWidth": 2,
        "fillOpacity": 12 if not spec.get("stack") else 25, "showPoints": "never",
        "spanNulls": True,
    }
    if spec.get("stack"):
        custom["stacking"] = {"mode": "normal", "group": "A"}
    thr = None
    if "slo_line" in spec:
        thr = thresholds([(None, GREEN), (spec["slo_line"], RED)])
        custom["thresholdsStyle"] = {"mode": "line"}
    fc = base_fieldconfig(spec.get("unit", "short"), decimals=spec.get("decimals"), thr=thr, custom=custom)
    targets = [{"refId": chr(65 + i), "datasource": PROM, "expr": e, "legendFormat": lg}
               for i, (e, lg) in enumerate(spec["targets"])]
    return {
        "id": pid, "type": "timeseries", "title": spec["title"], "gridPos": gp,
        "datasource": PROM, "description": spec.get("desc", ""), "fieldConfig": fc,
        "options": {"legend": {"displayMode": "list", "placement": "bottom", "calcs": ["lastNotNull", "max"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
        "targets": targets,
    }


def panel_heatmap(spec, pid, gp):
    return {
        "id": pid, "type": "heatmap", "title": spec["title"], "gridPos": gp,
        "datasource": PROM, "description": spec.get("desc", ""),
        "options": {"calculate": False, "cellGap": 1, "color": {"scheme": "Spectral", "mode": "scheme"},
                    "yAxis": {"unit": spec.get("unit", "s"), "axisPlacement": "left"},
                    "tooltip": {"show": True, "yHistogram": True}},
        "fieldConfig": {"defaults": {"custom": {"hideFrom": {"tooltip": False, "viz": False, "legend": False}}}, "overrides": []},
        "targets": [{"refId": "A", "datasource": PROM, "expr": spec["expr"],
                     "format": "heatmap", "legendFormat": "{{le}}"}],
    }


def build():
    panels, pid, y = [], 1, 0
    for row_title, specs in ROWS:
        panels.append({"id": pid, "type": "row", "title": row_title, "collapsed": False,
                       "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}})
        pid += 1
        y += 1
        x = 0
        row_h = 0
        for spec in specs:
            w = spec.get("w", 12)
            h = spec.get("h", 5 if spec["kind"] in ("stat", "bool") else 8)
            if x + w > 24:
                x = 0
                y += row_h
                row_h = 0
            gp = {"h": h, "w": w, "x": x, "y": y}
            if spec["kind"] in ("stat", "bool"):
                panels.append(panel_stat(spec, pid, gp))
            elif spec["kind"] == "heatmap":
                panels.append(panel_heatmap(spec, pid, gp))
            else:
                panels.append(panel_ts(spec, pid, gp))
            pid += 1
            x += w
            row_h = max(row_h, h)
        y += row_h
    return {
        "title": "IronBus broker",
        "uid": "ironbus-broker",
        "tags": ["ironbus", "edge", "message-queue"],
        "editable": True,
        "schemaVersion": 39,
        "version": 1,
        "refresh": "30s",
        "time": {"from": "now-6h", "to": "now"},
        "timezone": "",
        "templating": {"list": [
            {"name": "datasource", "type": "datasource", "query": "prometheus",
             "label": "Data source", "hide": 0, "current": {}, "refresh": 1},
            {"name": "job", "type": "query", "datasource": PROM, "label": "Job",
             "query": "label_values(ironbus_uptime_seconds, job)", "refresh": 2,
             "multi": True, "includeAll": True, "allValue": ".*",
             "current": {"text": "All", "value": "$__all"}},
            {"name": "instance", "type": "query", "datasource": PROM, "label": "Instance",
             "query": 'label_values(ironbus_uptime_seconds{job=~"$job"}, instance)', "refresh": 2,
             "multi": True, "includeAll": True, "allValue": ".*",
             "current": {"text": "All", "value": "$__all"}},
        ]},
        "annotations": {"list": [{
            "name": "Restarts", "datasource": PROM, "enable": True, "iconColor": "orange",
            "expr": f"changes(ironbus_start_time_seconds{{{J}}}[2m]) > 0",
            "titleFormat": "broker restart", "step": "60s"}]},
        "panels": panels,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stdout", action="store_true")
    a = ap.parse_args()
    dash = build()
    out = json.dumps(dash, indent=2, sort_keys=False) + "\n"
    if a.stdout:
        sys.stdout.write(out)
        return
    dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ironbus-dashboard.json")
    with open(dest, "w") as f:
        f.write(out)
    sys.stderr.write(f"wrote {dest} ({len(dash['panels'])} panels)\n")


if __name__ == "__main__":
    main()
