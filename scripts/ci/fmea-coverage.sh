#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# IronBus consolidated-FMEA coverage gate (#129).
#
# Fails when a required per-issue failure mode is missing from docs/FMEA.md. The
# consolidated FMEA (#129) aggregates every per-issue failure mode into one
# operator-facing table; this gate is the mechanized acceptance criterion that "a
# new failure mode added to any issue must appear here": it asserts that every
# required failure-mode ID is present as a table row, that each row still carries
# its anchor keyword(s) (so a row cannot be gutted to a placeholder while keeping
# its ID), and that the IDs are contiguous F1..Fn (so a row cannot be silently
# dropped from the middle).
#
# Mechanism (deterministic, host-independent, no network, no git history, no gh):
#   1. A CURATED list below names every required failure-mode ID and, after a `|`,
#      the anchor keyword(s) that MUST appear somewhere in FMEA.md for that mode
#      (case-insensitive, fixed-string). Multiple keywords for one ID are separated
#      by `&&` and ALL must be present.
#   2. For each entry: the ID must appear as a table-row id (a line beginning
#      `| Fn |`), and every anchor keyword must appear somewhere in the document.
#   3. The set of row ids in the table must be exactly F1..Fn contiguous with no
#      gap, so deleting or renumbering a row fails the gate.
#
# Extending it when a new failure mode is added (also documented in FMEA.md):
#   - Add the new contiguous row to the table in docs/FMEA.md.
#   - Add a `Fn|<keyword>` line to the REQUIRED block below.
#   - Run `sh scripts/ci/fmea-coverage.sh` locally to confirm it passes.
#
# Exit codes: 0 all required modes present and contiguous; 1 the gate fires (a
# missing ID, a missing keyword, or a gap); 2 a usage/IO error (missing file).
#
# Run locally exactly as CI does:
#   sh scripts/ci/fmea-coverage.sh

set -eu

FMEA_FILE="docs/FMEA.md"

# --------------------------------------------------------------------------------
# REQUIRED: the curated list of failure-mode IDs that MUST appear in FMEA.md, each
# with an anchor keyword (after `|`) that pins the row's substance. To add a mode,
# append a contiguous `Fn|<keyword>` line (keep them in order). `&&` joins multiple
# required keywords for one ID.
# --------------------------------------------------------------------------------
REQUIRED='
F1|power loss&&fdatasync
F2|fsyncgate&&WriterFrozen
F3|Torn tail
F4|Corruption-skip&&quarantine
F5|bounded-loss cap&&ExcessiveRecoveryLoss
F6|Disk full&&AtCapacity
F7|drop-oldest force-reap&&ironbus_truncations_total
F8|redelivery loop&&dead_lettered
F9|Clock regression&&monotonic
F10|Edge OOM&&ram_headroom
F11|Retry storm&&retry_after_ms
F12|unsafe default&&allow-unlimited-deliver
F13|Dedup memory exhaustion&&dedup-max-producers
F14|named-group memory&&TooManyGroups
F15|per-consumer occupancy&&consumer-credit
F16|Connection flood&&FrameTooLarge
F17|Broadcast cumulative-ack silent drop&&BroadcastGroupBusy
F18|head-of-line block&&append-actor
F19|No auth / no TLS&&loopback
F20|cardinality OOM&&consumer_labels_dropped_total
F21|counters lost on crash&&counter_checkpoint_repair_total
F22|Sequence gap&&sequence_gap
F23|segment chain gap&&corrupt_segment_header
F24|interleaving bug&&loom
F25|Pre-auth credential-guessing&&auth_failure_lockout
'

if [ ! -f "$FMEA_FILE" ]; then
  echo "error: $FMEA_FILE not found (run from the repository root)" >&2
  exit 2
fi

fail=0

# The highest required id number (F24 -> 24), derived independently of the loop so it
# survives the while-read subshell. Strip the `F`, sort numerically, take the last.
max_required="$(printf '%s\n' "$REQUIRED" | sed -n 's/^F\([0-9][0-9]*\)|.*/\1/p' | sort -n | tail -n1)"
if [ -z "$max_required" ]; then
  echo "error: the REQUIRED list in $0 is empty or malformed" >&2
  exit 2
fi

# 1 + 2: every required ID is a table row, and its anchor keyword(s) are present.
# Iterate the REQUIRED block one LINE at a time (keywords contain spaces, so a
# word-splitting `for` loop would mangle them); skip blank lines. The loop runs in a
# subshell (it is the right side of a pipe), so it cannot set `fail` directly; it
# exits non-zero on any failure and the `if` after it records that into `fail`.
if ! printf '%s\n' "$REQUIRED" | (
  rc=0
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    id="${entry%%|*}"
    keys="${entry#*|}"

    # The ID must appear as a table-row id: a line starting `| Fn |`.
    if ! grep -qE "^\| ${id} \|" "$FMEA_FILE"; then
      echo "::error::FMEA coverage: required failure mode ${id} has no table row (expected a line '| ${id} | ...') in $FMEA_FILE" >&2
      rc=1
      continue
    fi

    # Each `&&`-joined keyword must appear somewhere in the document
    # (case-insensitive, fixed-string). A keyword can contain spaces, so split only
    # on the literal `&&`.
    rest="$keys"
    while [ -n "$rest" ]; do
      case "$rest" in
        *"&&"*)
          kw="${rest%%&&*}"
          rest="${rest#*&&}"
          ;;
        *)
          kw="$rest"
          rest=""
          ;;
      esac
      if ! grep -qiF "$kw" "$FMEA_FILE"; then
        echo "::error::FMEA coverage: required failure mode ${id} is missing its anchor keyword '${kw}' in $FMEA_FILE (the row was emptied or renamed)" >&2
        rc=1
      fi
    done
  done
  exit "$rc"
); then
  fail=1
fi

# 3: the row ids in the table must be exactly F1..F{max_required} contiguous. We read
# every `| Fn |` row id actually present and check each required number is there.
present_ids="$(grep -oE '^\| F[0-9]+ \|' "$FMEA_FILE" | tr -d '| ' || true)"

n=1
while [ "$n" -le "$max_required" ]; do
  if ! printf '%s\n' "$present_ids" | grep -qx "F${n}"; then
    echo "::error::FMEA coverage: the table is not contiguous: F${n} is missing (expected F1..F${max_required} with no gap)" >&2
    fail=1
  fi
  n=$((n + 1))
done

if [ "$fail" -ne 0 ]; then
  cat >&2 <<EOF
::error::docs/FMEA.md is missing a required per-issue failure mode (or a row was gutted).
The consolidated FMEA (#129) must aggregate every per-issue failure mode. To resolve:
  1. If a failure mode was removed by mistake, restore its table row in docs/FMEA.md.
  2. If you INTENTIONALLY retired a mode, also remove its 'Fn|<keyword>' line from the
     REQUIRED block in this script and renumber the table rows to stay contiguous.
  3. Run 'sh scripts/ci/fmea-coverage.sh' locally to confirm.
EOF
  exit 1
fi

echo "ok: docs/FMEA.md covers all ${max_required} required failure modes (F1..F${max_required}, contiguous, anchors present)"
