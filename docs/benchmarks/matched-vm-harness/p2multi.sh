#!/bin/bash
# p2multi.sh — IronBus P2 multi-connection sweep (post-#1040), guest-resident.
# Companion to the matched matrix (row2.sh does both brokers single-conn). This
# adds IronBus at 1/2/4/8 producers so the published P2 story shows the pipeline
# engaging. Redpanda's single-client (kafka-perf, 5-in-flight) reference comes
# from the matched matrix. 3-run medians into results/p2multi.jsonl.
set -u
IRONBUS="$HOME/IronBus/target/release/ironbus"
OUT="$HOME/xb2/results/p2multi.jsonl"
mkdir -p "$HOME/xb2/results" "$HOME/xb2/tmp"
: > "$OUT"
[ -x "$IRONBUS" ] || { echo "missing $IRONBUS"; exit 1; }

cell() { # SIZE PRODUCERS COUNT
  local size="$1" prods="$2" count="$3" i raw="$HOME/xb2/tmp/p2m.json"
  for i in 1 2 3; do
    (cd "$(dirname "$IRONBUS")" && TMPDIR="$HOME/xb2/tmp" "$IRONBUS" bench \
      --mode publish --stream --pubwindow 1024 --storage disk \
      --count "$count" --payload-bytes "$size" --payload-shape realistic \
      --producers "$prods" --json) > "$raw" 2>"$raw.err" \
      || { echo "FAILED size=$size prods=$prods"; exit 1; }
    XB_S="$size" XB_P="$prods" XB_I="$i" XB_RAW="$raw" XB_OUT="$OUT" python3 <<'PYEOF'
import json, os
d = json.load(open(os.environ["XB_RAW"]))
r = d["results"]
rec = {"broker":"ironbus","row":"P2","size":int(os.environ["XB_S"]),
       "producers":int(os.environ["XB_P"]),"run":int(os.environ["XB_I"]),
       "msgs_per_sec":r["msgs_per_sec"]}
open(os.environ["XB_OUT"],"a").write(json.dumps(rec)+"\n")
print(f"  P2/{rec['size']}B x{rec['producers']} run{rec['run']}: {rec['msgs_per_sec']:.0f} msg/s")
PYEOF
    sleep 3
  done
}

for SIZE in 128 1024; do
  for P in 1 2 4 8; do
    echo "=== P2/${SIZE}B x${P} producers ==="
    if [ "$SIZE" = 128 ]; then cell "$SIZE" "$P" 6000000; else cell "$SIZE" "$P" 1500000; fi
  done
done
echo "P2MULTI DONE"
