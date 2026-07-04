#!/bin/bash
# row2.sh ROW — one matrix row across sizes x brokers, serially, guest-resident.
# Protocol (identical to the 2026-07 host study): fresh data dir -> start broker
# with the row's tier -> PILOT -> freeze COUNT = pilot_rate*20s (clamped) ->
# [redpanda: one unrecorded JVM-client warm-up run] -> 3 timed runs -> teardown.
#
# ENV XB2_SMOKE=1        : size=1024 only, tiny counts, 1 timed run, cooldown 2.
# ENV XB2_ONLY_BROKER=b  : restrict to one broker (targeted rerun).
#
# Rows: P1 P2 P3 C1 L1 — the matched IronBus-vs-Redpanda matrix. P4/L2 (memory)
# are N/A: redpanda has no in-RAM ephemeral mode (mislabeling page cache as
# memory would be dishonest).

set -u
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib2.sh"

[ $# -ge 1 ] || xb_die "usage: row2.sh ROW(P1|P2|P3|C1|L1)"
ROW="$1"

SMOKE="${XB2_SMOKE:-0}"
if [ "$SMOKE" = "1" ]; then
  SIZES="1024"; NRUNS=1; COOLDOWN=2
else
  SIZES="128 1024"; NRUNS=3; COOLDOWN=15
fi

case "$ROW" in
  P1|P2|P3|C1|L1) BROKERS="ironbus redpanda" ;;
  *) xb_die "unknown row $ROW (matched matrix: P1 P2 P3 C1 L1)" ;;
esac

tier_for() { # BROKER -> tier keyword for start_<broker>
  local b="$1"
  case "$b" in
    ironbus) echo "driver" ;;
    redpanda)
      case "$ROW" in
        P3) echo "relaxed" ;;
        *)  echo "durable" ;;
      esac ;;
  esac
}

pilot_count_for() {
  if [ "$SMOKE" = "1" ]; then
    case "$ROW" in
      C1) echo 2000 ;;
      L1) echo 500 ;;
      *)  echo 1000 ;;
    esac
  else
    case "$ROW" in
      P1|L1) echo 3000 ;;
      *)     echo 50000 ;;
    esac
  fi
}

clamp_count() { # RATE -> frozen count = rate*20s, clamped
  local rate="$1" c
  c=$((rate * 20))
  if [ "$SMOKE" = "1" ]; then
    [ "$c" -lt 500 ] && c=500
    [ "$c" -gt 2000 ] && c=2000
  elif [ "$ROW" = "L1" ] || [ "$ROW" = "P1" ]; then
    # single-in-flight fsync-bound rows: keep the 10-30s protocol budget.
    [ "$c" -lt 2000 ] && c=2000
    [ "$c" -gt 200000 ] && c=200000
  else
    [ "$c" -lt 50000 ] && c=50000
    [ "$c" -gt 5000000 ] && c=5000000
  fi
  # byte cap: bound run time + guest disk (25G free); keep count*size <= ~3GiB.
  if [ -n "${SIZE:-}" ] && [ "$SIZE" -gt 0 ]; then
    local maxmsgs=$(( 3221225472 / SIZE ))
    [ "$c" -gt "$maxmsgs" ] && c=$maxmsgs
  fi
  echo "$c"
}

CURRENT_BROKER=""
row_cleanup() {
  if [ -n "$CURRENT_BROKER" ]; then
    "stop_$CURRENT_BROKER" 2>/dev/null || true
  fi
}
trap row_cleanup EXIT

for SIZE in $SIZES; do
  for B in $BROKERS; do
    if [ -n "${XB2_ONLY_BROKER:-}" ] && [ "$B" != "$XB2_ONLY_BROKER" ]; then continue; fi
    TIER="$(tier_for "$B")"
    xb_log "=== $ROW size=$SIZE broker=$B tier=$TIER ==="

    "fresh_datadir_$B"
    CURRENT_BROKER="$B"
    "start_$B" "$TIER"
    "wait_ready_$B"

    PCOUNT="$(pilot_count_for)"
    xb_log "$ROW/$SIZE/$B pilot (count=$PCOUNT)"
    PILOT_OUT="$("$SCRIPTS_DIR/cell2.sh" "$ROW" "$SIZE" "$B" "$PCOUNT" pilot 0)" \
      || xb_die "pilot failed for $ROW/$SIZE/$B"
    RATE="$(echo "$PILOT_OUT" | sed -n 's/^MSGS_PER_SEC=//p' | tail -1)"
    [ -n "$RATE" ] && [ "$RATE" -gt 0 ] 2>/dev/null || xb_die "pilot produced no rate for $ROW/$SIZE/$B"
    COUNT="$(clamp_count "$RATE")"
    xb_log "$ROW/$SIZE/$B pilot rate=$RATE msgs/s -> frozen count=$COUNT"

    # JVM CLIENT warm-up for redpanda cells (the kafka perf tools JIT-warm on the
    # first pass; ironbus's Rust client needs none). Unrecorded.
    if [ "$B" = "redpanda" ] && [ "$SMOKE" != "1" ]; then
      xb_log "$ROW/$SIZE/redpanda JVM-client warm-up run (unrecorded)"
      XBENCH_NO_RECORD=1 "$SCRIPTS_DIR/cell2.sh" "$ROW" "$SIZE" "$B" "$COUNT" warmup 0 >/dev/null \
        || xb_die "redpanda warmup failed for $ROW/$SIZE"
    fi

    i=1
    while [ "$i" -le "$NRUNS" ]; do
      xb_log "$ROW/$SIZE/$B timed run $i/$NRUNS (count=$COUNT)"
      "$SCRIPTS_DIR/cell2.sh" "$ROW" "$SIZE" "$B" "$COUNT" timed "$i" >/dev/null \
        || xb_die "timed run $i failed for $ROW/$SIZE/$B"
      [ "$i" -lt "$NRUNS" ] && sleep "$COOLDOWN"
      i=$((i+1))
    done

    "stop_$B"
    CURRENT_BROKER=""
    xb_log "$ROW/$SIZE/$B done; cooldown ${COOLDOWN}s"
    sleep "$COOLDOWN"
  done
done

xb_log "row $ROW complete"
