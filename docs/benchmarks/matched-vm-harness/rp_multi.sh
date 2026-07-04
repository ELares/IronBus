#!/bin/bash
# rp_multi.sh — Redpanda P2 durable produce under N PARALLEL kafka-perf clients,
# to find its multi-client ceiling (fair comparison vs IronBus --producers N).
# Guest-resident. write.caching=false (fsync-before-ack). Aggregate = total records
# / wall window (first client start -> last client end). 3-run medians.
set -u
KP="$HOME/xb/kafka/kafka_2.13-4.3.1/bin/kafka-producer-perf-test.sh"
RPK="rpk"
BOOT="127.0.0.1:9092"
OUT="$HOME/xb2/results/rp_multi.jsonl"
mkdir -p "$HOME/xb2/results" "$HOME/xb2/tmp"
: > "$OUT"

# ensure redpanda up, production mode, durable
sudo systemctl start redpanda 2>/dev/null || true
for i in $(seq 1 45); do rpk cluster info -X brokers="$BOOT" >/dev/null 2>&1 && break; sleep 2; done

cell() { # SIZE NCLIENTS COUNT_TOTAL
  local size="$1" n="$2" total="$3" run="$4"
  local per=$(( total / n ))
  rpk topic delete bench -X brokers="$BOOT" >/dev/null 2>&1 || true; sleep 1
  rpk topic create bench -p 1 -r 1 -c write.caching=false -X brokers="$BOOT" >/dev/null 2>&1 \
    || { echo "topic create failed"; return 1; }
  local start_ns end_ns pids=() logs=()
  start_ns=$(date +%s%N)
  local c
  for c in $(seq 1 "$n"); do
    local log="$HOME/xb2/tmp/rpm_${size}_${n}_${c}.log"
    logs+=("$log")
    "$KP" --topic bench --num-records "$per" --record-size "$size" --throughput -1 \
      --producer-props bootstrap.servers="$BOOT" acks=all batch.size=65536 linger.ms=5 \
      compression.type=none max.in.flight.requests.per.connection=5 \
      > "$log" 2>&1 &
    pids+=($!)
  done
  local ok=1
  for p in "${pids[@]}"; do wait "$p" || ok=0; done
  end_ns=$(date +%s%N)
  [ "$ok" = 1 ] || { echo "a client failed (size=$size n=$n)"; return 1; }
  local wall_s
  wall_s=$(python3 -c "print(($end_ns - $start_ns)/1e9)")
  XB_S="$size" XB_N="$n" XB_TOTAL="$total" XB_WALL="$wall_s" XB_RUN="$run" XB_OUT="$OUT" python3 <<'PYEOF'
import os
size=int(os.environ["XB_S"]); n=int(os.environ["XB_N"]); total=int(os.environ["XB_TOTAL"])
wall=float(os.environ["XB_WALL"]); run=int(os.environ["XB_RUN"])
rate = total / wall
import json
rec={"broker":"redpanda","row":"P2","size":size,"clients":n,"run":run,"msgs_per_sec":round(rate,1),"wall_s":round(wall,3)}
open(os.environ["XB_OUT"],"a").write(json.dumps(rec)+"\n")
print(f"  redpanda P2/{size}B x{n} clients run{run}: {rate:,.0f} msg/s (wall {wall:.2f}s)")
PYEOF
}

for SIZE in 128 1024; do
  for N in 1 4 8; do
    echo "=== redpanda P2/${SIZE}B x${N} clients ==="
    for r in 1 2 3; do
      if [ "$SIZE" = 128 ]; then cell "$SIZE" "$N" 6000000 "$r"; else cell "$SIZE" "$N" 1500000 "$r"; fi
      sleep 3
    done
  done
done
sudo systemctl stop redpanda 2>/dev/null || true
echo "RP_MULTI DONE"
