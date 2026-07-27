#!/usr/bin/env python3
"""storm_medians.py storm.jsonl — fsync-storm cell medians (#1192 S1).

Dedupe: the LATEST record per (n, broker, run_idx) wins (reruns supersede).
Median over the timed runs per cell. Emits storm-final-medians.json + a comparison table.
Same conventions as medians2.py, keyed by producer count N instead of row/size.
"""
import json
import statistics
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "storm.jsonl"
latest = {}
with open(path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        if d["mode"] != "timed":
            continue
        latest[(d["n"], d["broker"], d["run_idx"])] = d

cells = {}
for (n, broker, _), d in latest.items():
    cells.setdefault((n, broker), []).append(d)

FIELDS = (
    "msgs_per_sec",
    "ack_p50_us",
    "ack_p99_us",
    "ack_p50_us_pooled",
    "ack_p99_us_pooled",
    "ack_p999_us_pooled",
)

out = {}
for (n, broker), runs in sorted(cells.items()):
    cell = {"runs": len(runs), "count": runs[0]["count"]}
    for k in FIELDS:
        vals = [r[k] for r in runs if r.get(k) is not None]
        cell[k] = round(statistics.median(vals), 2) if vals else None
    out[f"S1/{n}/{broker}"] = cell

with open("storm-final-medians.json", "w") as f:
    json.dump(out, f, indent=1)

print(f"{'cell':10} {'ironbus':>12} {'redpanda':>12}  winner (aggregate durable msg/s; per-producer ack p50/p99 us)")
for n in (8, 32, 128):
    ib = out.get(f"S1/{n}/ironbus")
    rp = out.get(f"S1/{n}/redpanda")
    if not ib or not rp:
        continue
    a, b = ib["msgs_per_sec"], rp["msgs_per_sec"]
    win = "ironbus" if a > b else "redpanda"
    ratio = max(a, b) / min(a, b)
    print(
        f"S1/N={n:<5} {a:>12} {b:>12}  {win} ({ratio:.2f}x)  "
        f"p50 {ib['ack_p50_us']} vs {rp['ack_p50_us']}  p99 {ib['ack_p99_us']} vs {rp['ack_p99_us']}"
    )
