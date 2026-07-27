#!/bin/bash
# storm2.sh N BROKER COUNT MODE [RUNIDX] — the many-streams fsync-storm durable produce cell
# (#1192 S1, epic #1196; the baseline row that GATES #1193). Guest-resident.
#
# N concurrent producers, EACH to its OWN stream: N IronBus NAMED streams (sync durability,
# fsync-before-ack — the serve default) vs N Redpanda topics (1 partition, replication 1,
# write.caching=false — fsync-before-ack), every message an awaited durable ack with a single
# in-flight per producer (the per-message storm shape; the Vanlightly many-producer weakness AND
# the #1193 K-serial-fdatasync ceiling, measured honestly on both sides). COUNT is PER PRODUCER.
#
# Both sides run a METHOD-IDENTICAL closed-loop driver (storm-produce in Rust over the real
# IronBus client; StormProducers.java over the official kafka-clients): whole-phase wall
# aggregate, raw nanosecond ack RTTs, nearest-rank percentiles — a same-instrument pair, unlike
# kafka-producer-perf-test's whole-ms summary (epic methodology guardrail 4).
#
# Appends ONE normalized JSON line to results/storm.jsonl and prints MSGS_PER_SEC=<n>.
# BROKER: ironbus | redpanda. MODE: pilot | timed (storm_medians.py keeps only timed).

set -u
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib2.sh"

[ $# -ge 4 ] || xb_die "usage: storm2.sh N BROKER COUNT MODE [RUNIDX]"
N="$1"; BROKER="$2"; COUNT="$3"; MODE="$4"; RUNIDX="${5:-0}"
SIZE=128   # the storm shape is small messages; fixed at the matrix's small-payload column

TS=$(date +%s)
RAW="$XB2_LOGS/storm_${N}_${BROKER}_${MODE}${RUNIDX}_${TS}.log"
RESULTS="$XB2_RESULTS/storm.jsonl"

STORM_BIN="$IRONBUS_RELEASE_DIR/storm-produce"
ENGINE_SHA="$(cut -c1-12 "$HOME/IronBus/.engine-sha" 2>/dev/null || echo unknown)"

CONFIG_SUMMARY=""
VMNOTE="; MATCHED-VM: broker AND client inside the same lima vz VM (Ubuntu kernel 7.0, ext4 on virtio vda1, guest loopback); fsync = guest fdatasync through virtio — matched across brokers, not a host-power-loss claim"

# ============================ IRONBUS =======================================
# A LIVE `ironbus serve` (the shipping default config: sync durability = fsync-before-ack,
# per-stream storage mode = each named stream its OWN log — exactly the K-dirty-streams shape
# #1193 describes), fresh data dir per run on ext4, reaped after the run.
run_ironbus_storm() {
  [ -x "$STORM_BIN" ] || xb_die "missing $STORM_BIN (cargo build --release -p ironbus-bench --bin storm-produce)"
  stop_ironbus                       # stray-broker defense
  assert_serial_clear
  local data="$XB2_TMP/storm-data"
  rm -rf "$data"; mkdir -p "$XB2_TMP"
  "$IRONBUS_BIN" serve --data-dir "$data" > "$RAW.serve" 2>&1 &
  local serve_pid=$!
  wait_port_open 7777 30 || xb_die "ironbus serve did not open 7777 (see $RAW.serve)"
  "$STORM_BIN" --addr 127.0.0.1:7777 --producers "$N" --count "$COUNT" --payload-bytes "$SIZE" \
      > "$RAW" 2>"$RAW.err" \
    || xb_die "storm-produce failed for N=$N (see $RAW.err)"
  kill -INT "$serve_pid" 2>/dev/null
  wait "$serve_pid" 2>/dev/null
  wait_port_free 7777 30 || xb_die "7777 still busy after ironbus serve stop"
  rm -rf "$data"
  CONFIG_SUMMARY="ironbus serve LIVE broker (engine $ENGINE_SHA, shipping defaults: sync durability = fsync-before-ack, per-stream storage mode = one log per named stream), $N named streams storm.0..storm.$((N-1)), $N producer connections, one awaited publish_to per message (single in-flight per producer), realistic ${SIZE}B payload; storm-produce driver: whole-phase wall aggregate, nearest-rank ack percentiles from raw ns samples$VMNOTE"
}

# ============================ REDPANDA ======================================
# lib2.sh production-mode lifecycle (durable tier: write_caching=false validated at start), N
# topics created 1-partition/1-replica with write.caching=false BEFORE the driver runs, fresh
# data dir per run.
run_redpanda_storm() {
  fresh_datadir_redpanda
  start_redpanda durable
  # Create the N topics in one rpk call per chunk (rpk accepts multiple names).
  local names=() i
  for i in $(seq 0 $((N - 1))); do names+=("storm$i"); done
  local chunk=32 j
  for ((j = 0; j < ${#names[@]}; j += chunk)); do
    rpk topic create "${names[@]:j:chunk}" -p 1 -r 1 -c write.caching=false \
        -X brokers="$RP_BOOTSTRAP" >/dev/null \
      || xb_die "rpk topic create failed (chunk starting storm$j)"
  done
  # Compile the matched driver once (kafka-clients from the provisioned perf-tools distro).
  local jdir="$XB2_TMP/stormjava"
  if [ ! -f "$jdir/StormProducers.class" ] || [ "$SCRIPTS_DIR/StormProducers.java" -nt "$jdir/StormProducers.class" ]; then
    command -v javac >/dev/null 2>&1 || xb_die "javac missing (sudo apt-get install -y openjdk-21-jdk-headless)"
    mkdir -p "$jdir"
    javac -cp "$KAFKA_HOME/libs/*" -d "$jdir" "$SCRIPTS_DIR/StormProducers.java" \
      || xb_die "StormProducers.java compile failed"
  fi
  # One JVM, N producer threads (bounded heap/stacks so N=128 fits beside redpanda's 6G pin).
  java -Xmx1g -Xss512k -cp "$KAFKA_HOME/libs/*:$jdir" StormProducers \
      "$RP_BOOTSTRAP" "$N" "$COUNT" "$SIZE" storm \
      > "$RAW" 2>"$RAW.err" \
    || xb_die "StormProducers failed for N=$N (see $RAW.err)"
  stop_redpanda
  CONFIG_SUMMARY="redpanda v26.1.12 single node production mode (--smp=6 --memory=6G, write_caching_default=false validated), $N topics storm0..storm$((N-1)) (1 partition, r=1, write.caching=false = fsync before ack), $N producers (one JVM, official kafka-clients): acks=all, max.in.flight=1, linger.ms=0, compression none, one sync send().get() per message, realistic ${SIZE}B payload; StormProducers driver: whole-phase wall aggregate, nearest-rank ack percentiles from raw ns samples$VMNOTE"
}

case "$BROKER" in
  ironbus)  run_ironbus_storm ;;
  redpanda) run_redpanda_storm ;;
  *) xb_die "unknown broker $BROKER" ;;
esac

# --------------------------------------------------------------------------
# Normalize the driver's JSON -> ONE storm.jsonl row. Both drivers emit the same
# storm-produce-v1 schema, so one parser serves both brokers. ack_p50_us/ack_p99_us are the
# MEDIAN ACROSS PRODUCERS of each producer's own p50/p99 (the per-producer view the cell is
# about); the pooled percentiles ride along for the tail story.
# --------------------------------------------------------------------------
export XB_N="$N" XB_SIZE="$SIZE" XB_BROKER="$BROKER" XB_MODE="$MODE" \
       XB_RUNIDX="$RUNIDX" XB_RAW="$RAW" XB_CONFIG="$CONFIG_SUMMARY" \
       XB_RESULTS_FILE="$RESULTS" XB_TS="$TS"

python3 <<'PYEOF'
import json, os, sys

# The result is the single storm-produce-v1 line; the Kafka client may interleave its own log
# lines on stdout (no slf4j binding config in the perf-tools distro), so scan for the schema
# marker instead of assuming a clean stream.
d = None
with open(os.environ["XB_RAW"]) as f:
    for line in f:
        line = line.strip()
        if line.startswith('{"schema":"storm-produce-v1"'):
            d = json.loads(line)
if d is None:
    sys.stderr.write("PARSE FAILURE: no storm-produce-v1 line in the raw log\n")
    sys.exit(3)
msgs = d["msgs_per_sec"]
if not msgs or msgs != msgs or msgs <= 0:
    sys.stderr.write("PARSE FAILURE: no sane msgs_per_sec\n")
    sys.exit(3)

rec = {
    "row":                "S1",
    "n":                  int(os.environ["XB_N"]),
    "size":               int(os.environ["XB_SIZE"]),
    "broker":             os.environ["XB_BROKER"],
    "tier_label":         "sync-per-message",
    "mode":               os.environ["XB_MODE"],
    "run_idx":            int(os.environ["XB_RUNIDX"]),
    "count":              d["total_messages"],
    "count_per_producer": d["count_per_producer"],
    "msgs_per_sec":       round(msgs, 1),
    "wall_s":             d["wall_s"],
    "ack_p50_us":         d["per_producer_p50_us_median"],
    "ack_p99_us":         d["per_producer_p99_us_median"],
    "ack_p50_us_pooled":  d["ack_p50_us_pooled"],
    "ack_p99_us_pooled":  d["ack_p99_us_pooled"],
    "ack_p999_us_pooled": d["ack_p999_us_pooled"],
    "raw_log":            os.environ["XB_RAW"],
    "config_summary":     os.environ["XB_CONFIG"],
    "ts":                 int(os.environ["XB_TS"]),
}
with open(os.environ["XB_RESULTS_FILE"], "a") as f:
    f.write(json.dumps(rec) + "\n")
print("MSGS_PER_SEC=%d" % int(msgs))
PYEOF
rc=$?
[ $rc -eq 0 ] || xb_die "parser failed for $RAW (rc=$rc)"
exit 0
