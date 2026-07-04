#!/usr/bin/env python3
"""medians2.py results.jsonl — matched-VM matrix medians.

Dedupe: the LATEST record per (row,size,broker,run_idx) wins (reruns supersede).
Median over the timed runs per cell. Emits final-medians2.json + a comparison table.
"""
import json
import statistics
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "results.jsonl"
latest = {}
with open(path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        if d["mode"] != "timed":
            continue
        latest[(d["row"], d["size"], d["broker"], d["run_idx"])] = d

cells = {}
for (row, size, broker, _), d in latest.items():
    cells.setdefault((row, size, broker), []).append(d)

out = {}
for (row, size, broker), runs in sorted(cells.items()):
    med = lambda k: (statistics.median([r[k] for r in runs if r[k] is not None])
                     if any(r[k] is not None for r in runs) else None)
    out[f"{row}/{size}/{broker}"] = {
        "msgs_per_sec": round(med("msgs_per_sec"), 1) if med("msgs_per_sec") else None,
        "p50_us": med("p50_us"),
        "p99_us": med("p99_us"),
        "p999_us": med("p999_us"),
        "runs": len(runs),
        "count": runs[0]["count"],
    }

with open("final-medians2.json", "w") as f:
    json.dump(out, f, indent=1)

rows = ["P1", "P2", "P3", "C1", "L1"]
print(f"{'cell':16} {'ironbus':>14} {'redpanda':>14}  winner (throughput; L1 by p50)")
for row in rows:
    for size in (128, 1024):
        ib = out.get(f"{row}/{size}/ironbus")
        rp = out.get(f"{row}/{size}/redpanda")
        if not ib or not rp:
            continue
        if row == "L1":
            a, b = ib["p50_us"], rp["p50_us"]
            win = "ironbus" if a and b and a < b else "redpanda" if a and b else "?"
            print(f"{row}/{size:<11} {a:>12}us {b:>12}us  {win}  (p99 {ib['p99_us']} vs {rp['p99_us']})")
        else:
            a, b = ib["msgs_per_sec"], rp["msgs_per_sec"]
            win = "ironbus" if a and b and a > b else "redpanda" if a and b else "?"
            ratio = (max(a, b) / min(a, b)) if a and b else 0
            print(f"{row}/{size:<11} {a:>14} {b:>14}  {win} ({ratio:.2f}x)")
