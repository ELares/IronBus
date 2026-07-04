#!/bin/bash
# all2.sh — run the full matched-VM matrix serially: P1 P2 P3 C1 L1.
# Writes a completion marker so the host orchestrator can poll.
set -u
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib2.sh"

MARKER="$XB2/matrix2.done"
rm -f "$MARKER"

for ROW in P1 P2 P3 C1 L1; do
  echo "ROW $ROW START $(date)" >> "$XB2/progress.txt"
  "$SCRIPTS_DIR/row2.sh" "$ROW" || { echo "ROW $ROW FAILED $(date)" >> "$XB2/progress.txt"; exit 1; }
  echo "ROW $ROW OK $(date)" >> "$XB2/progress.txt"
done

echo "MATRIX2 DONE $(date)" >> "$XB2/progress.txt"
touch "$MARKER"
