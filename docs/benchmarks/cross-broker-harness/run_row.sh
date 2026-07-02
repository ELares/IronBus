#!/bin/bash
# run_row.sh ROW — run one matrix row across sizes x applicable brokers, serially.
#
# Per (size, broker): fresh data dir -> start broker with the row's tier ->
# PILOT short run -> freeze COUNT = pilot_rate * 20s (clamped 50k..5M) ->
# [kafka rows: one extra unrecorded JVM-warmup run] -> 3 timed runs ->
# teardown -> cooldown sleep 20.
#
# ENV XBENCH_SMOKE=1: size=1024 only, COUNT in 500..2000, 1 timed run, cooldown 2.
# ENV XBENCH_ONLY_BROKER=<name>: restrict the row to one broker (targeted rerun).
#
# Applicability (from the matrix):
#   P1: ironbus nats kafka redpanda        (nats core N/A - not durable)
#   P2: ironbus kafka redpanda             (NATS JS: NO ack-after-fsync group-commit mode -> marker)
#   P3: ironbus nats kafka redpanda
#   P4: ironbus nats                       (kafka/redpanda: no true in-RAM mode -> N/A)
#   C1: ironbus nats kafka redpanda
#   L1: ironbus nats kafka redpanda
#   L2: ironbus nats                       (kafka/redpanda: no in-RAM mode -> N/A)

set -u
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib.sh"

[ $# -ge 1 ] || xb_die "usage: run_row.sh ROW(P1|P2|P3|P4|C1|L1|L2)"
ROW="$1"

SMOKE="${XBENCH_SMOKE:-0}"
if [ "$SMOKE" = "1" ]; then
  SIZES="1024"; NRUNS=1; COOLDOWN=2
else
  SIZES="128 1024"; NRUNS=3; COOLDOWN=20
fi

case "$ROW" in
  P1|P3|C1|L1) BROKERS="ironbus nats kafka redpanda" ;;
  P2)          BROKERS="ironbus kafka redpanda"
               xb_log "P2 nats: SKIPPED — NATS JetStream has no ack-after-fsync group-commit mode (honest JS peer is the P1 sync-always number)" ;;
  P4)          BROKERS="ironbus nats"
               xb_log "P4 kafka/redpanda: SKIPPED — no true in-RAM ephemeral broker mode (would mislabel page-cache as memory)" ;;
  L2)          BROKERS="ironbus nats natscore"
               xb_log "L2 kafka/redpanda: SKIPPED — no in-RAM mode; natscore = EXTRA core request-reply datapoint (not label-comparable)" ;;
  *) xb_die "unknown row $ROW" ;;
esac

# broker-specific tier keyword for start_<broker> per row
tier_for() { # BROKER -> echoes tier
  local b="$1"
  case "$b" in
    ironbus) echo "driver" ;;
    nats|natscore)
      case "$ROW" in
        P1|L1) echo "sync" ;;
        *)     echo "default" ;;
      esac ;;
    kafka)
      case "$ROW" in
        P1|L1) echo "fsync" ;;
        P2)    echo "group" ;;
        *)     echo "default" ;;
      esac ;;
    redpanda)
      case "$ROW" in
        P3) echo "relaxed" ;;
        *)  echo "durable" ;;
      esac ;;
  esac
}

pilot_count_for() { # -> small count sized so the pilot stays short
  if [ "$SMOKE" = "1" ]; then
    case "$ROW" in
      C1)       echo 2000 ;;
      L1|L2)    echo 500 ;;
      P1)       echo 1000 ;;
      *)        echo 1000 ;;
    esac
  else
    case "$ROW" in
      P1|L1|L2) echo 3000 ;;   # per-message-fsync / single-in-flight rows are slow
      *)        echo 50000 ;;
    esac
  fi
}

clamp_count() { # RATE -> frozen count = rate*20s clamped 50k..5M (smoke: 500..2000)
  # L rows (single in-flight latency samples) clamp 2k..200k instead: the fsync-bound
  # single-shot paths run at only ~100-300 samples/s, so the 50k throughput floor
  # would blow the 10-30s per-run protocol budget by >10x.
  local rate="$1" c
  c=$((rate * 20))
  if [ "$SMOKE" = "1" ]; then
    [ "$c" -lt 500 ] && c=500
    [ "$c" -gt 2000 ] && c=2000
  elif [ "$ROW" = "L1" ] || [ "$ROW" = "L2" ] || [ "$ROW" = "P1" ]; then
    # P1 (sync-per-message produce) is the same fsync-wall class (~100-500/s on
    # macOS F_FULLFSYNC): the 50k floor would mean >100s per run. rate*20 keeps
    # the 10-30s protocol budget; the 2k floor still gives >=2000 fsync samples.
    [ "$c" -lt 2000 ] && c=2000
    [ "$c" -gt 200000 ] && c=200000
  else
    [ "$c" -lt 50000 ] && c=50000
    [ "$c" -gt 5000000 ] && c=5000000
  fi
  # BYTE CAP: JetStream streams are created with --maxbytes 6GB (file) / 4GB (memory);
  # a frozen count whose bytes exceed the stream cap wedges `nats bench` in a 503
  # maximum-bytes retry-forever loop (err_code 10077). Keep count*size <= ~3GiB.
  if [ -n "${SIZE:-}" ] && [ "$SIZE" -gt 0 ]; then
    local maxmsgs=$(( 3221225472 / SIZE ))
    [ "$c" -gt "$maxmsgs" ] && c=$maxmsgs
  fi
  echo "$c"
}

# If a cell dies mid-row (xb_die exits), tear down whatever broker was started so the
# NEXT row's serial-discipline port check does not fail on our leaked process.
CURRENT_BROKER=""
row_cleanup() {
  if [ -n "$CURRENT_BROKER" ]; then
    "stop_$CURRENT_BROKER" 2>/dev/null || true
  fi
}
trap row_cleanup EXIT

for SIZE in $SIZES; do
  for B in $BROKERS; do
    if [ -n "${XBENCH_ONLY_BROKER:-}" ] && [ "$B" != "$XBENCH_ONLY_BROKER" ]; then continue; fi
    TIER="$(tier_for "$B")"
    xb_log "=== $ROW size=$SIZE broker=$B tier=$TIER ==="

    "fresh_datadir_$B"
    CURRENT_BROKER="$B"
    "start_$B" "$TIER"
    "wait_ready_$B"

    # --- pilot: observe rate, freeze count -------------------------------
    PCOUNT="$(pilot_count_for)"
    xb_log "$ROW/$SIZE/$B pilot (count=$PCOUNT)"
    PILOT_OUT="$("$SCRIPTS_DIR/run_cell.sh" "$ROW" "$SIZE" "$B" "$PCOUNT" pilot 0)" \
      || xb_die "pilot failed for $ROW/$SIZE/$B"
    RATE="$(echo "$PILOT_OUT" | sed -n 's/^MSGS_PER_SEC=//p' | tail -1)"
    [ -n "$RATE" ] && [ "$RATE" -gt 0 ] 2>/dev/null || xb_die "pilot produced no rate for $ROW/$SIZE/$B"
    COUNT="$(clamp_count "$RATE")"
    xb_log "$ROW/$SIZE/$B pilot rate=$RATE msgs/s -> frozen count=$COUNT"

    # --- kafka rows: one extra unrecorded JVM warm-up run (skip in smoke) --
    if [ "$B" = "kafka" ] && [ "$SMOKE" != "1" ]; then
      xb_log "$ROW/$SIZE/kafka JVM warm-up run (unrecorded)"
      XBENCH_NO_RECORD=1 "$SCRIPTS_DIR/run_cell.sh" "$ROW" "$SIZE" "$B" "$COUNT" warmup 0 >/dev/null \
        || xb_die "kafka warmup failed for $ROW/$SIZE"
    fi

    # --- timed runs -------------------------------------------------------
    i=1
    while [ "$i" -le "$NRUNS" ]; do
      xb_log "$ROW/$SIZE/$B timed run $i/$NRUNS (count=$COUNT)"
      "$SCRIPTS_DIR/run_cell.sh" "$ROW" "$SIZE" "$B" "$COUNT" timed "$i" >/dev/null \
        || xb_die "timed run $i failed for $ROW/$SIZE/$B"
      [ "$i" -lt "$NRUNS" ] && sleep "$COOLDOWN"
      i=$((i+1))
    done

    # --- teardown + cooldown ---------------------------------------------
    "stop_$B"
    CURRENT_BROKER=""
    xb_log "$ROW/$SIZE/$B done; cooldown ${COOLDOWN}s"
    sleep "$COOLDOWN"
  done
done

xb_log "row $ROW complete"
