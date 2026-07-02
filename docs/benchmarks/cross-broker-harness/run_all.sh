#!/bin/bash
# run_all.sh — full serial cross-broker benchmark matrix in protocol order.
# Rows can equally be run one at a time: scripts/run_row.sh P1  (etc.)
# ENV XBENCH_SMOKE=1 runs the tiny-count validation pass instead.
set -u
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib.sh"

for ROW in P1 P2 P3 P4 C1 L1 L2; do
  xb_log "########## ROW $ROW ##########"
  "$SCRIPTS_DIR/run_row.sh" "$ROW" || xb_die "row $ROW failed — matrix aborted"
done

# final leftover check: nothing may be left running
for p in 7777 4222 9092; do
  if /usr/sbin/lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1; then
    xb_die "leftover listener on port $p after full matrix"
  fi
done
PATH="$LIMA_BIN_DIR:$PATH" LIMA_HOME="$LIMA_HOME" "$LIMA_BIN_DIR/limactl" list 2>/dev/null | grep redpanda || true
xb_log "matrix complete; results in $XB_RESULTS/results.jsonl"
