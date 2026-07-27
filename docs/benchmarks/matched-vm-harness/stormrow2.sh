#!/bin/bash
# stormrow2.sh — the FROZEN fsync-storm sweep (#1192 S1): N in {8, 32, 128} x both brokers,
# 3 timed runs per cell, serial, fresh broker + data dir per run (storm2.sh owns the per-run
# lifecycle). Counts are PER PRODUCER, frozen after the 2026-07-27 pilots to land both brokers'
# walls in the ~25-40s band at every N (pilot rates: ironbus ~9-10k msg/s flat across N;
# redpanda 6.5k -> 12.5k rising with N):
#   N=8   -> 30000/producer (240k total)
#   N=32  ->  9000/producer (288k total)
#   N=128 ->  2500/producer (320k total)
# Pilot rows (mode=pilot) stay in storm.jsonl; storm_medians.py keeps only mode=timed.
set -u
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

count_for() { # N -> frozen per-producer count
  case "$1" in
    8)   echo 30000 ;;
    32)  echo 9000 ;;
    128) echo 2500 ;;
    *)   echo "stormrow2: no frozen count for N=$1" >&2; exit 1 ;;
  esac
}

for N in 8 32 128; do
  COUNT="$(count_for "$N")"
  for BROKER in ironbus redpanda; do
    echo "=== S1 N=$N $BROKER (count=$COUNT/producer) ===" >&2
    for RUN in 1 2 3; do
      "$SCRIPTS_DIR/storm2.sh" "$N" "$BROKER" "$COUNT" timed "$RUN" \
        || { echo "STORMROW FAILED: N=$N $BROKER run$RUN" >&2; exit 1; }
      sleep 3
    done
  done
done
echo "STORMROW DONE" >&2
