#!/bin/bash
# run_cell.sh ROW SIZE BROKER COUNT MODE [RUNIDX]
#   ROW    : P1|P2|P3|P4|C1|L1|L2
#   SIZE   : payload bytes (128|1024)
#   BROKER : ironbus|nats|kafka|redpanda
#   COUNT  : message count for this invocation
#   MODE   : pilot|timed|warmup   (warmup: run but do NOT record)
#   RUNIDX : timed run index (default 0)
#
# Assumes the broker for this cell is ALREADY started with the row's tier
# (run_row.sh owns lifecycle) — except ironbus, whose bench driver spawns its
# own isolated broker. Appends ONE normalized JSON line to results/results.jsonl
# and prints "MSGS_PER_SEC=<n>" on stdout. Every raw tool output is kept in logs/.

set -u
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib.sh"

[ $# -ge 5 ] || xb_die "usage: run_cell.sh ROW SIZE BROKER COUNT MODE [RUNIDX]"
ROW="$1"; SIZE="$2"; BROKER="$3"; COUNT="$4"; MODE="$5"; RUNIDX="${6:-0}"

TS=$(date +%s)
RAW="$XB_LOGS/${ROW}_${SIZE}_${BROKER}_${MODE}${RUNIDX}_${TS}.log"
RESULTS="$XB_RESULTS/results.jsonl"
mkdir -p "$XB_LOGS" "$XB_RESULTS"

PARSER=""        # ironbus_json | nats | kafka_prod | kafka_cons
TIER_LABEL=""
CONFIG_SUMMARY=""

run_ironbus() {
  local args=""
  case "$ROW" in
    P1) args="--mode publish --pubwindow 1 --storage disk"
        TIER_LABEL="sync-per-message"
        CONFIG_SUMMARY="ironbus bench isolated broker, --durability-level sync default, pubwindow=1 (one awaited fsynced ack per publish), lz4 default codec, payload-shape realistic" ;;
    P2) args="--mode publish --stream --pubwindow 1024 --storage disk"
        TIER_LABEL="group-commit-fsync"
        CONFIG_SUMMARY="ironbus bench isolated broker, sync durability, --stream --pubwindow 1024 (group-commit fdatasync over sliding window), lz4, realistic" ;;
    P3) args="--mode publish --stream --pubwindow 1024 --no-fsync --storage disk"
        TIER_LABEL="page-cache-async"
        CONFIG_SUMMARY="ironbus bench isolated broker, --no-fsync => spawned broker at INTERVAL durability (bounded-loss page-cache acks, #1027; NOT power-loss-safe), --stream --pubwindow 1024, lz4, realistic" ;;
    P4) args="--mode publish --stream --pubwindow 1024 --storage memory"
        TIER_LABEL="memory"
        CONFIG_SUMMARY="ironbus bench isolated broker, --storage memory (ephemeral, no files/fsync), --stream --pubwindow 1024, lz4, realistic" ;;
    C1) args="--mode subscribe --consume-tier streaming --storage disk"
        TIER_LABEL="durable-consume"
        CONFIG_SUMMARY="ironbus bench isolated broker, Tier-S streaming consume (windowed StreamFetch + cumulative StreamCommit), SHIPPED default fetch-batch (2048 = credit ceiling, #1027) matching peers-at-their-defaults; drain-only timing, bench self-prefills COUNT msgs" ;;
    L1) args="--mode publish --pubwindow 1 --storage disk"
        TIER_LABEL="sync-per-message"
        CONFIG_SUMMARY="ironbus bench publish pubwindow=1 CLOSED-LOOP: produce->fsynced-ACK RTT percentiles (ack_*, #1024) — matched shape with nats js pub sync (closed-loop); NOT rate-paced (#1032: open-loop low-rate pacing adds ~4x macOS deep-idle wake penalty, a probe artifact); kafka/redpanda stay throttled per their tool constraint (documented)" ;;
    L2) args="--mode publish --pubwindow 1 --storage memory"
        TIER_LABEL="memory"
        CONFIG_SUMMARY="ironbus bench publish pubwindow=1 CLOSED-LOOP on --storage memory: produce->ACK RTT percentiles (ack_*, #1024), no fsync — matched shape with nats js pub sync memory (closed-loop, #1032)" ;;
    *) xb_die "run_cell ironbus: row $ROW not applicable" ;;
  esac
  PARSER="ironbus_json"
  # driver spawns its own broker; run with cwd=release dir so sibling binary resolution works
  (cd "$IRONBUS_RELEASE_DIR" && "$IRONBUS_BIN" bench --count "$COUNT" --payload-bytes "$SIZE" --payload-shape realistic $args --json) > "$RAW" 2>"$RAW.err" \
    || xb_die "ironbus bench failed for $ROW (see $RAW.err)"
}

run_nats() {
  local NC="$NATS_CLI -s $NATS_URL"
  case "$ROW" in
    P1)
      TIER_LABEL="sync-per-message"
      CONFIG_SUMMARY="nats-server jetstream sync_interval=always (fsync per message), stream file R1; nats bench js pub sync (one in-flight publish awaiting PubAck) size=${SIZE}B"
      PARSER="nats"
      $NC bench js pub sync xb.bench --create --storage file --maxbytes 6GB --purge --msgs "$COUNT" --size "${SIZE}B" --no-progress > "$RAW" 2>&1 \
        || xb_die "nats js pub sync failed (see $RAW)" ;;
    P3)
      TIER_LABEL="page-cache-async"
      CONFIG_SUMMARY="nats-server jetstream default sync_interval (~2m, page-cache, NOT power-loss-safe), stream file R1; nats bench js pub async --batch 100"
      PARSER="nats"
      $NC bench js pub async xb.bench --create --storage file --maxbytes 6GB --purge --batch 100 --msgs "$COUNT" --size "${SIZE}B" --no-progress > "$RAW" 2>&1 \
        || xb_die "nats js pub async failed (see $RAW)" ;;
    P4)
      TIER_LABEL="memory"
      CONFIG_SUMMARY="nats jetstream MEMORY storage stream R1 (the ~3.3x-claim peer); nats bench js pub async --batch 100 (ephemeral, lost on exit)"
      PARSER="nats"
      $NC bench js pub async xb.bench --create --storage memory --maxbytes 4GB --purge --batch 100 --msgs "$COUNT" --size "${SIZE}B" --no-progress > "$RAW" 2>&1 \
        || xb_die "nats js pub async memory failed (see $RAW)" ;;
    C1)
      TIER_LABEL="durable-consume"
      CONFIG_SUMMARY="nats jetstream file stream prefilled with COUNT msgs (async pub, purged first), then drained by durable PULL consumer via nats bench js fetch --batch 256 --acks explicit; latency percentiles are per-fetch-op, not e2e"
      PARSER="nats"
      $NC bench js pub async xb.bench --create --storage file --maxbytes 6GB --purge --batch 500 --msgs "$COUNT" --size "${SIZE}B" --no-progress > "$RAW.prefill" 2>&1 \
        || xb_die "nats C1 prefill failed (see $RAW.prefill)"
      # nats bench js fetch does NOT auto-create non-default consumers: create the
      # durable PULL consumer explicitly, starting from the stream head
      $NC consumer add benchstream "xbc${TS}${RUNIDX}" --pull --ack explicit --deliver all --defaults > "$RAW.consumer" 2>&1 \
        || xb_die "nats consumer add failed (see $RAW.consumer)"
      $NC bench js fetch --consumer "xbc${TS}${RUNIDX}" --batch 256 --msgs "$COUNT" --no-progress > "$RAW" 2>&1 \
        || xb_die "nats js fetch failed (see $RAW)" ;;
    L1)
      TIER_LABEL="sync-per-message"
      CONFIG_SUMMARY="nats jetstream sync_interval=always, file R1; nats bench js pub sync = SINGLE in-flight produce->PubAck round-trip; P50/P99/P99.9 are per-publish ack RTT (not pub->sub e2e)"
      PARSER="nats"
      $NC bench js pub sync xb.bench --create --storage file --maxbytes 6GB --purge --msgs "$COUNT" --size "${SIZE}B" --no-progress > "$RAW" 2>&1 \
        || xb_die "nats L1 js pub sync failed (see $RAW)" ;;
    L2)
      TIER_LABEL="memory"
      CONFIG_SUMMARY="nats jetstream MEMORY storage R1; nats bench js pub sync = SINGLE in-flight produce->PubAck RTT (P50/P99/P99.9 per-publish ack RTT, no fsync) — symmetric with ironbus memory ack RTT"
      PARSER="nats"
      $NC bench js pub sync xb.bench --create --storage memory --maxbytes 4GB --purge --msgs "$COUNT" --size "${SIZE}B" --no-progress > "$RAW" 2>&1 \
        || xb_die "nats L2 js pub sync memory failed (see $RAW)" ;;
    *) xb_die "run_cell nats: row $ROW not applicable" ;;
  esac
}

# natscore: EXTRA L2 datapoint — core NATS request-reply RTT (at-most-once, no persistence,
# includes a responder hop: 2 network round trips). NATS's home-turf latency number; NOT
# label-comparable with the ack-RTT cells (documented in config_summary).
run_natscore() {
  local NC="$NATS_CLI -s $NATS_URL"
  [ "$ROW" = "L2" ] || xb_die "run_cell natscore: only L2"
  TIER_LABEL="at-most-once"
  CONFIG_SUMMARY="NATS CORE request-reply RTT: nats bench service serve (1 responder) + service request (1 client, single in-flight); full core round trip incl. responder hop (2 network RTTs), at-most-once, no persistence — EXTRA datapoint, not label-comparable with ack-RTT cells"
  PARSER="nats"
  $NC bench service serve xb.svc --clients 1 --no-progress > "$RAW.serve" 2>&1 &
  local serve_pid=$!
  sleep 1
  $NC bench service request xb.svc --clients 1 --msgs "$COUNT" --size "${SIZE}B" --no-progress > "$RAW" 2>&1
  local rc=$?
  kill "$serve_pid" 2>/dev/null; wait "$serve_pid" 2>/dev/null
  [ $rc -eq 0 ] || xb_die "nats service request failed (see $RAW)"
}

# --- kafka-protocol drivers (kafka AND redpanda share the kafka perf tools) --
kt() { "$KAFKA_HOME/bin/kafka-topics.sh" --bootstrap-server "$KAFKA_BOOTSTRAP" "$@"; }

prep_topic_kafka() { # TOPIC_CONF ("" | "flush.messages=1" | "flush.messages=1000")
  local conf="$1"
  kt --delete --topic bench >/dev/null 2>&1 || true
  sleep 1
  if [ -n "$conf" ]; then
    kt --create --topic bench --partitions 1 --replication-factor 1 --config "$conf" >/dev/null 2>&1 \
      || xb_die "kafka topic create failed"
  else
    kt --create --topic bench --partitions 1 --replication-factor 1 >/dev/null 2>&1 \
      || xb_die "kafka topic create failed"
  fi
}

prep_topic_redpanda() { # WRITE_CACHING (true|false)
  local wc="$1"
  "$RPK" topic delete bench -X brokers="$RP_BOOTSTRAP" >/dev/null 2>&1 || true
  sleep 1
  "$RPK" topic create bench -p 1 -r 1 -c write.caching="$wc" -X brokers="$RP_BOOTSTRAP" >/dev/null 2>&1 \
    || xb_die "rpk topic create failed"
}

run_kafka_like() { # BROKER is kafka or redpanda; differs only in topic prep + labels
  local b="$BROKER" pprops="" prefill=0 vmnote=""
  [ "$b" = "redpanda" ] && vmnote="; REDPANDA IN LIMA VM: virtualized IO + user-space port-forward, not bare-metal-equivalent, appendix-only per rig lint"
  case "$ROW" in
    P1) TIER_LABEL="sync-per-message"
        pprops="acks=all batch.size=1 linger.ms=0 max.in.flight.requests.per.connection=1 compression.type=none"
        [ "$b" = "kafka" ] && CONFIG_SUMMARY="kafka RF1 KRaft, broker log.flush.interval.messages=1 + topic flush.messages=1 (fsync/record); producer-perf $pprops"
        [ "$b" = "redpanda" ] && CONFIG_SUMMARY="redpanda single node, developer_mode=false, write_caching_default=false + topic write.caching=false (fsync before ack); kafka-producer-perf $pprops$vmnote" ;;
    P2) TIER_LABEL="group-commit-fsync"
        pprops="acks=all batch.size=65536 linger.ms=5 compression.type=none"
        [ "$b" = "kafka" ] && CONFIG_SUMMARY="kafka RF1, broker log.flush.interval.messages=1000 + topic flush.messages=1000 (fsync coalesced per 1000 records); producer-perf $pprops"
        [ "$b" = "redpanda" ] && CONFIG_SUMMARY="redpanda write.caching=false (durable, fsync coalesced across flush batch via raft flush knobs); kafka-producer-perf $pprops$vmnote" ;;
    P3) TIER_LABEL="page-cache-async"
        pprops="acks=all batch.size=65536 linger.ms=5 compression.type=none"
        [ "$b" = "kafka" ] && CONFIG_SUMMARY="kafka RF1 DEFAULT flush (OS page-cache, NOT power-loss-safe); producer-perf $pprops"
        [ "$b" = "redpanda" ] && CONFIG_SUMMARY="redpanda write_caching_default=true + topic write.caching=true (relaxed, acked before fsync, NOT power-loss-safe); kafka-producer-perf $pprops$vmnote" ;;
    C1) TIER_LABEL="durable-consume"
        prefill=1
        [ "$b" = "kafka" ] && CONFIG_SUMMARY="kafka RF1 topic prefilled (acks=1 batched), drained by kafka-consumer-perf-test fresh group (committed offsets); msgs_per_sec = fetch.nMsg.sec (fetch phase, excludes group rebalance); latencies not reported by tool"
        [ "$b" = "redpanda" ] && CONFIG_SUMMARY="redpanda topic (write.caching=false) prefilled, drained by kafka-consumer-perf-test fresh group; msgs_per_sec = fetch.nMsg.sec$vmnote" ;;
    L1) TIER_LABEL="sync-per-message"
        pprops="acks=all batch.size=1 linger.ms=0 max.in.flight.requests.per.connection=1 compression.type=none"
        [ "$b" = "kafka" ] && CONFIG_SUMMARY="kafka broker flush.messages=1; producer-perf $pprops THROTTLED to 100 msg/s (below fsync saturation, so latency = produce-ack RTT not queue wait); p50/p99/p99.9 single in-flight, ms->us, whole-ms tool resolution; not pub->sub e2e"
        [ "$b" = "redpanda" ] && CONFIG_SUMMARY="redpanda write.caching=false; producer-perf $pprops THROTTLED to 100 msg/s (below saturation); p50/p99/p99.9 = produce-ack RTT single in-flight, ms->us, whole-ms resolution$vmnote" ;;
    *) xb_die "run_cell $b: row $ROW not applicable" ;;
  esac

  # topic prep, per invocation (fresh segments/offsets between runs)
  if [ "$b" = "kafka" ]; then
    case "$ROW" in
      P1|L1) prep_topic_kafka "flush.messages=1" ;;
      P2)    prep_topic_kafka "flush.messages=1000" ;;
      *)     prep_topic_kafka "" ;;
    esac
  else
    case "$ROW" in
      P3) prep_topic_redpanda true ;;
      *)  prep_topic_redpanda false ;;
    esac
  fi

  if [ "$prefill" = "1" ]; then
    PARSER="kafka_cons"
    "$KAFKA_HOME/bin/kafka-producer-perf-test.sh" --topic bench --num-records "$COUNT" \
      --record-size "$SIZE" --throughput -1 \
      --producer-props bootstrap.servers="$KAFKA_BOOTSTRAP" acks=1 batch.size=65536 linger.ms=5 compression.type=none \
      > "$RAW.prefill" 2>&1 || xb_die "$b C1 prefill failed (see $RAW.prefill)"
    "$KAFKA_HOME/bin/kafka-consumer-perf-test.sh" --bootstrap-server "$KAFKA_BOOTSTRAP" \
      --topic bench --messages "$COUNT" --group "xbg${TS}${RUNIDX}" --timeout 60000 \
      > "$RAW" 2>&1 || xb_die "$b consumer-perf failed (see $RAW)"
  else
    PARSER="kafka_prod"
    local tput="-1"
    [ "$ROW" = "L1" ] && tput="100"   # latency row: fixed low rate, no queueing
    "$KAFKA_HOME/bin/kafka-producer-perf-test.sh" --topic bench --num-records "$COUNT" \
      --record-size "$SIZE" --throughput "$tput" \
      --producer-props bootstrap.servers="$KAFKA_BOOTSTRAP" $pprops \
      > "$RAW" 2>&1 || xb_die "$b producer-perf failed (see $RAW)"
  fi
}

case "$BROKER" in
  ironbus)        run_ironbus ;;
  nats)           run_nats ;;
  natscore)       run_natscore ;;
  kafka|redpanda) run_kafka_like ;;
  *) xb_die "unknown broker $BROKER" ;;
esac

# ---------------------------------------------------------------------------
# Parse the raw output -> ONE normalized JSON line appended to results.jsonl.
# mb_per_sec is recomputed uniformly as msgs_per_sec * SIZE / 1e6 (decimal MB)
# so no broker benefits from its tool's MiB-vs-MB labeling.
# ---------------------------------------------------------------------------
export XB_ROW="$ROW" XB_SIZE="$SIZE" XB_BROKER="$BROKER" XB_TIER="$TIER_LABEL" \
       XB_MODE="$MODE" XB_RUNIDX="$RUNIDX" XB_COUNT="$COUNT" XB_RAW="$RAW" \
       XB_PARSER="$PARSER" XB_CONFIG="$CONFIG_SUMMARY" XB_RESULTS_FILE="$RESULTS" \
       XB_NO_RECORD="${XBENCH_NO_RECORD:-0}" XB_TS="$TS"

python3 <<'PYEOF'
import json, os, re, sys

raw_path = os.environ["XB_RAW"]
parser   = os.environ["XB_PARSER"]
size     = int(os.environ["XB_SIZE"])
text     = open(raw_path, errors="replace").read()

msgs = mb = p50 = p99 = p999 = None

def to_us(val, unit):
    v = float(val.replace(",", ""))
    return v * {"us": 1.0, "ms": 1000.0, "s": 1e6, "m": 6e7}[unit]

if parser == "ironbus_json":
    d = json.loads(text)
    r = d["results"]
    msgs = r["msgs_per_sec"]
    p50  = r.get("latency_p50_us")
    p99  = r.get("latency_p99_us")
    p999 = r.get("latency_p999_us")
    # #1024: publish-mode window=1 cells report produce->ACK RTT percentiles in ack_*;
    # round-trip cells keep e2e latency in latency_*. Prefer latency_*, fall back to ack_*.
    if p50 is None: p50 = r.get("ack_p50_us")
    if p99 is None: p99 = r.get("ack_p99_us")
    if p999 is None: p999 = r.get("ack_p999_us")

elif parser == "nats":
    m = re.search(r"stats:\s*([\d,\.]+)\s*msgs/sec", text)
    if m: msgs = float(m.group(1).replace(",", ""))
    lm = re.search(r"P50:\s*([\d,\.]+)(us|ms|s)", text)
    if lm: p50 = to_us(lm.group(1), lm.group(2))
    lm = re.search(r"P99:\s*([\d,\.]+)(us|ms|s)", text)
    if lm: p99 = to_us(lm.group(1), lm.group(2))
    lm = re.search(r"P99\.9:\s*([\d,\.]+)(us|ms|s)", text)
    if lm: p999 = to_us(lm.group(1), lm.group(2))

elif parser == "kafka_prod":
    # summary line: "N records sent, X records/sec (Y MB/sec), A ms avg latency,
    #   B ms max latency, C ms 50th, D ms 95th, E ms 99th, F ms 99.9th."
    summary = None
    for line in text.splitlines():
        if "records sent" in line and "50th" in line:
            summary = line
    if summary:
        m = re.search(r"([\d\.]+)\s+records/sec", summary)
        if m: msgs = float(m.group(1))
        m = re.search(r"([\d\.]+)\s+ms\s+50th", summary)
        if m: p50 = float(m.group(1)) * 1000.0
        m = re.search(r"([\d\.]+)\s+ms\s+99th", summary)
        if m: p99 = float(m.group(1)) * 1000.0
        m = re.search(r"([\d\.]+)\s+ms\s+99\.9th", summary)
        if m: p999 = float(m.group(1)) * 1000.0

elif parser == "kafka_cons":
    # header then data line; columns: start.time, end.time, data.consumed.in.MB,
    # MB.sec, data.consumed.in.nMsg, nMsg.sec, rebalance.time.ms, fetch.time.ms,
    # fetch.MB.sec, fetch.nMsg.sec
    lines = [l for l in text.splitlines() if l.strip()]
    hdr_i = None
    for i, l in enumerate(lines):
        if l.startswith("start.time"):
            hdr_i = i
    if hdr_i is not None and hdr_i + 1 < len(lines):
        hdr  = [c.strip() for c in lines[hdr_i].split(",")]
        vals = [c.strip() for c in lines[hdr_i + 1].split(",")]
        d = dict(zip(hdr, vals))
        try:
            msgs = float(d["fetch.nMsg.sec"])
        except (KeyError, ValueError):
            msgs = None

if msgs is None or msgs != msgs or msgs <= 0:
    sys.stderr.write("PARSE FAILURE: no sane msgs_per_sec from %s (%s)\n" % (raw_path, parser))
    sys.exit(3)

mb = msgs * size / 1e6

rec = {
    "row":            os.environ["XB_ROW"],
    "size":           size,
    "broker":         os.environ["XB_BROKER"],
    "tier_label":     os.environ["XB_TIER"],
    "mode":           os.environ["XB_MODE"],
    "run_idx":        int(os.environ["XB_RUNIDX"]),
    "count":          int(os.environ["XB_COUNT"]),
    "msgs_per_sec":   round(msgs, 3),
    "mb_per_sec":     round(mb, 4),
    "p50_us":         round(p50, 2) if p50 is not None else None,
    "p99_us":         round(p99, 2) if p99 is not None else None,
    "p999_us":        round(p999, 2) if p999 is not None else None,
    "raw_log":        raw_path,
    "config_summary": os.environ["XB_CONFIG"],
    "ts":             int(os.environ["XB_TS"]),
}

if os.environ.get("XB_NO_RECORD") != "1":
    with open(os.environ["XB_RESULTS_FILE"], "a") as f:
        f.write(json.dumps(rec) + "\n")

print("MSGS_PER_SEC=%d" % int(msgs))
PYEOF
rc=$?
[ $rc -eq 0 ] || xb_die "parser failed for $RAW (rc=$rc)"
exit 0
