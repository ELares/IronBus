#!/bin/bash
# cell2.sh ROW SIZE BROKER COUNT MODE [RUNIDX] — one benchmark cell, guest-resident.
# Appends ONE normalized JSON line to results/results.jsonl (same schema as the
# 2026-07 host study) and prints MSGS_PER_SEC=<n>.
# BROKER: ironbus | redpanda. Rows: P1 P2 P3 C1 L1.

set -u
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib2.sh"

[ $# -ge 5 ] || xb_die "usage: cell2.sh ROW SIZE BROKER COUNT MODE [RUNIDX]"
ROW="$1"; SIZE="$2"; BROKER="$3"; COUNT="$4"; MODE="$5"; RUNIDX="${6:-0}"

TS=$(date +%s)
RAW="$XB2_LOGS/${ROW}_${SIZE}_${BROKER}_${MODE}${RUNIDX}_${TS}.log"
RESULTS="$XB2_RESULTS/results.jsonl"

PARSER=""
TIER_LABEL=""
CONFIG_SUMMARY=""
VMNOTE="; MATCHED-VM: broker AND client inside the same lima vz VM (Ubuntu kernel 7.0, ext4 on virtio vda1, guest loopback); fsync = guest fdatasync through virtio — matched across brokers, not a host-power-loss claim"

run_ironbus() {
  local args=""
  case "$ROW" in
    P1) args="--mode publish --pubwindow 1 --storage disk"
        TIER_LABEL="sync-per-message"
        CONFIG_SUMMARY="ironbus bench isolated broker, --durability-level sync default, pubwindow=1 (one awaited fsynced ack per publish), lz4 default codec, realistic payload$VMNOTE" ;;
    P2) args="--mode publish --stream --pubwindow 1024 --storage disk"
        TIER_LABEL="group-commit-fsync"
        CONFIG_SUMMARY="ironbus bench isolated broker, sync durability, --stream --pubwindow 1024 (group-commit fdatasync over sliding window), lz4, realistic$VMNOTE" ;;
    P3) args="--mode publish --stream --pubwindow 1024 --no-fsync --storage disk"
        TIER_LABEL="page-cache-async"
        CONFIG_SUMMARY="ironbus bench isolated broker, --no-fsync => INTERVAL durability (bounded-loss page-cache acks, NOT power-loss-safe), --stream --pubwindow 1024, lz4, realistic$VMNOTE" ;;
    C1) args="--mode subscribe --consume-tier streaming --storage disk"
        TIER_LABEL="durable-consume"
        CONFIG_SUMMARY="ironbus bench isolated broker, Tier-S streaming consume (windowed StreamFetch + cumulative StreamCommit), default fetch-batch 2048, drain-only timing, self-prefilled$VMNOTE" ;;
    L1) args="--mode publish --pubwindow 1 --storage disk"
        TIER_LABEL="sync-per-message"
        CONFIG_SUMMARY="ironbus bench publish pubwindow=1 CLOSED-LOOP: produce->fsynced-ACK RTT percentiles (ack_*); redpanda stays throttled per its tool constraint (documented)$VMNOTE" ;;
    *) xb_die "run_ironbus: row $ROW not applicable" ;;
  esac
  PARSER="ironbus_json"
  # TMPDIR pin: guest /tmp is tmpfs; the spawned broker's data dir MUST be ext4.
  (cd "$IRONBUS_RELEASE_DIR" && TMPDIR="$XB2_TMP" "$IRONBUS_BIN" bench \
      --count "$COUNT" --payload-bytes "$SIZE" --payload-shape realistic $args --json) \
      > "$RAW" 2>"$RAW.err" \
    || xb_die "ironbus bench failed for $ROW (see $RAW.err)"
}

prep_topic_redpanda() { # WRITE_CACHING (true|false)
  local wc="$1"
  rpk topic delete bench -X brokers="$RP_BOOTSTRAP" >/dev/null 2>&1 || true
  sleep 1
  rpk topic create bench -p 1 -r 1 -c write.caching="$wc" -X brokers="$RP_BOOTSTRAP" >/dev/null 2>&1 \
    || xb_die "rpk topic create failed"
}

run_redpanda() {
  local pprops="" prefill=0
  case "$ROW" in
    P1) TIER_LABEL="sync-per-message"
        pprops="acks=all batch.size=1 linger.ms=0 max.in.flight.requests.per.connection=1 compression.type=none"
        CONFIG_SUMMARY="redpanda single node production mode, write.caching=false (fsync before ack); kafka-producer-perf $pprops$VMNOTE" ;;
    P2) TIER_LABEL="group-commit-fsync"
        pprops="acks=all batch.size=65536 linger.ms=5 compression.type=none"
        CONFIG_SUMMARY="redpanda write.caching=false (durable, fsync coalesced across raft flush batch); kafka-producer-perf $pprops$VMNOTE" ;;
    P3) TIER_LABEL="page-cache-async"
        pprops="acks=all batch.size=65536 linger.ms=5 compression.type=none"
        CONFIG_SUMMARY="redpanda write_caching_default=true + topic write.caching=true (relaxed, acked before fsync, NOT power-loss-safe); kafka-producer-perf $pprops$VMNOTE" ;;
    C1) TIER_LABEL="durable-consume"
        prefill=1
        CONFIG_SUMMARY="redpanda topic (write.caching=false) prefilled, drained by kafka-consumer-perf-test fresh group; msgs_per_sec = fetch.nMsg.sec$VMNOTE" ;;
    L1) TIER_LABEL="sync-per-message"
        pprops="acks=all batch.size=1 linger.ms=0 max.in.flight.requests.per.connection=1 compression.type=none"
        CONFIG_SUMMARY="redpanda write.caching=false; producer-perf $pprops THROTTLED to 100 msg/s (below saturation); p50/p99/p99.9 = produce-ack RTT single in-flight, ms->us, whole-ms tool resolution$VMNOTE" ;;
    *) xb_die "run_redpanda: row $ROW not applicable" ;;
  esac

  case "$ROW" in
    P3) prep_topic_redpanda true ;;
    *)  prep_topic_redpanda false ;;
  esac

  if [ "$prefill" = "1" ]; then
    PARSER="kafka_cons"
    "$KAFKA_HOME/bin/kafka-producer-perf-test.sh" --topic bench --num-records "$COUNT" \
      --record-size "$SIZE" --throughput -1 \
      --producer-props bootstrap.servers="$RP_BOOTSTRAP" acks=1 batch.size=65536 linger.ms=5 compression.type=none \
      > "$RAW.prefill" 2>&1 || xb_die "redpanda C1 prefill failed (see $RAW.prefill)"
    "$KAFKA_HOME/bin/kafka-consumer-perf-test.sh" --bootstrap-server "$RP_BOOTSTRAP" \
      --topic bench --messages "$COUNT" --group "xbg${TS}${RUNIDX}" --timeout 60000 \
      > "$RAW" 2>&1 || xb_die "redpanda consumer-perf failed (see $RAW)"
  else
    PARSER="kafka_prod"
    local tput="-1"
    [ "$ROW" = "L1" ] && tput="100"
    "$KAFKA_HOME/bin/kafka-producer-perf-test.sh" --topic bench --num-records "$COUNT" \
      --record-size "$SIZE" --throughput "$tput" \
      --producer-props bootstrap.servers="$RP_BOOTSTRAP" $pprops \
      > "$RAW" 2>&1 || xb_die "redpanda producer-perf failed (see $RAW)"
  fi
}

case "$BROKER" in
  ironbus)  run_ironbus ;;
  redpanda) run_redpanda ;;
  *) xb_die "unknown broker $BROKER" ;;
esac

# --------------------------------------------------------------------------
# Parse raw output -> ONE normalized JSON line (schema identical to the host
# study so the same analysis tooling applies). mb_per_sec recomputed uniformly.
# --------------------------------------------------------------------------
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

if parser == "ironbus_json":
    d = json.loads(text)
    r = d["results"]
    msgs = r["msgs_per_sec"]
    p50  = r.get("latency_p50_us")
    p99  = r.get("latency_p99_us")
    p999 = r.get("latency_p999_us")
    if p50 is None: p50 = r.get("ack_p50_us")
    if p99 is None: p99 = r.get("ack_p99_us")
    if p999 is None: p999 = r.get("ack_p999_us")

elif parser == "kafka_prod":
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
