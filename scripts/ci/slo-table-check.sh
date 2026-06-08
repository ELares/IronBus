#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# SLO-table drift gate (#359, the #110 residual).
#
# The IronBus SLO target table has a human-readable form (docs/SLO.md) and a versioned,
# machine-readable form (docs/schemas/slo.v1.json, schema ironbus.slo-table.v1) that CI and the
# #111 macro-bench read targets from. This gate keeps the two from diverging: it asserts the JSON
# parses, carries the schema version, has every required field on every row, encodes the
# not-yet-measured invariant (no row is ratified, every measured cell is null), and that the stated
# target NUMBERS match the numbers in SLO.md. So a number changed in one file but not the other
# fails here, on the PR, deterministically.
#
# Mechanism (deterministic, offline, history-free: reads only the working tree; no network, no gh,
# no git history):
#   1. jq parses slo.v1.json, asserts schema_name / schema_version / margin_fraction, and asserts
#      every row carries the full required field set with sane gate / target_unit values.
#   2. The not-yet-measured invariant: every row has `measured: null` and `ratified: false` (no row
#      is ratified today; ratifying a cell is the device residual).
#   3. The drift assertions: each load-bearing target number in the JSON must also appear as the
#      corresponding number in SLO.md (the single source of truth). The marquee throughput and p99,
#      the 64 MiB RAM ceiling, the 4x write-amplification gate, and the 20 percent ratification
#      margin are checked in BOTH directions (the JSON value drives a fixed-string grep of SLO.md).
#
# Exit codes: 0 the JSON parses, is well-formed, is unratified, and agrees with SLO.md; 1 the gate
# fires (a parse error, a missing/!invalid field, a ratified-too-early row, or a number that does
# not match SLO.md); 2 a usage/IO error (a missing file or a missing jq).
#
# Run locally exactly as CI does:
#   sh scripts/ci/slo-table-check.sh
set -eu

JSON="${1:-docs/schemas/slo.v1.json}"
SLO_MD="${2:-docs/SLO.md}"

fail() {
	echo "::error::SLO-table drift gate: $1" >&2
	exit 1
}

if ! command -v jq >/dev/null 2>&1; then
	echo "::error::SLO-table drift gate: jq not found on PATH" >&2
	exit 2
fi
[ -f "$JSON" ] || {
	echo "::error::SLO-table drift gate: $JSON not found" >&2
	exit 2
}
[ -f "$SLO_MD" ] || {
	echo "::error::SLO-table drift gate: $SLO_MD not found" >&2
	exit 2
}

# 1. The JSON must parse.
jq empty "$JSON" 2>/dev/null || fail "$JSON is not valid JSON"

# 2. Top-level fields.
[ "$(jq -r '.schema_name' "$JSON")" = "ironbus.slo-table.v1" ] ||
	fail "schema_name must be \"ironbus.slo-table.v1\""
[ "$(jq -r '.schema_version' "$JSON")" = "1" ] ||
	fail "schema_version must be 1"
[ "$(jq -r '.source_of_truth' "$JSON")" = "docs/SLO.md" ] ||
	fail "source_of_truth must be \"docs/SLO.md\""
[ "$(jq -r '.margin_fraction' "$JSON")" = "0.2" ] ||
	fail "margin_fraction must be 0.2 (the documented 20 percent ratification margin)"
[ "$(jq -r '.rows | type' "$JSON")" = "array" ] ||
	fail "rows must be an array"
[ "$(jq -r '.rows | length' "$JSON")" -ge 1 ] ||
	fail "rows must not be empty"

# The declared marquee row id must name a real row.
marquee_id="$(jq -r '.marquee_row_id' "$JSON")"
[ "$(jq --arg id "$marquee_id" '[.rows[] | select(.id == $id)] | length' "$JSON")" = "1" ] ||
	fail "marquee_row_id \"$marquee_id\" does not name exactly one row"

# 3. Per-row structure. The required keys must all be present on every row (a missing key, e.g. a
# row added without `harness_field`, fails). jq reports the count of rows missing any required key.
required_keys='["id","device","message_size_bytes","fan_out","durability_mode","metric","harness_field","gate","target","target_unit","power_loss_safe","source","measured","ratified"]'
missing="$(jq -r --argjson req "$required_keys" \
	'[.rows[] | select((($req - (keys)) | length) > 0)] | length' "$JSON")"
[ "$missing" = "0" ] || fail "$missing row(s) are missing a required field (need: $required_keys)"

# Every row id must be a non-empty string and unique.
n_rows="$(jq -r '.rows | length' "$JSON")"
n_ids="$(jq -r '[.rows[].id | select(. != null and . != "")] | unique | length' "$JSON")"
[ "$n_rows" = "$n_ids" ] || fail "row ids must be present, non-empty, and unique"

# gate must be one of >= or <; target_unit must be a known unit.
bad_gate="$(jq -r '[.rows[] | select(.gate != ">=" and .gate != "<")] | length' "$JSON")"
[ "$bad_gate" = "0" ] || fail "$bad_gate row(s) have a gate other than \">=\" or \"<\""
bad_unit="$(jq -r '[.rows[] | select([.target_unit] | inside(["msgs_per_sec","microseconds","bytes","ratio","mb_per_sec"]) | not)] | length' "$JSON")"
[ "$bad_unit" = "0" ] || fail "$bad_unit row(s) have an unknown target_unit"

# A non-null target must be a number; a non-null measured must be a number.
bad_target="$(jq -r '[.rows[] | select(.target != null and (.target | type) != "number")] | length' "$JSON")"
[ "$bad_target" = "0" ] || fail "$bad_target row(s) have a non-numeric target"

# 4. The not-yet-measured invariant: no row is ratified, every measured cell is null. Ratifying a
# cell is the device residual (#359); until then no row gates CI.
not_null_measured="$(jq -r '[.rows[] | select(.measured != null)] | length' "$JSON")"
[ "$not_null_measured" = "0" ] ||
	fail "$not_null_measured row(s) have a non-null measured cell, but no run on the reference device has been ratified yet"
ratified="$(jq -r '[.rows[] | select(.ratified != false)] | length' "$JSON")"
[ "$ratified" = "0" ] ||
	fail "$ratified row(s) are ratified == true, but no measured floor has been recorded yet"

# 5. Drift assertions: the load-bearing target NUMBERS in the JSON must also appear in SLO.md, so
# the two cannot diverge. Each assertion pulls the value from the JSON and fixed-string-greps
# SLO.md for the human-readable form of that same number.

# Helper: assert a fixed string is present in SLO.md.
slo_has() {
	grep -qF -- "$1" "$SLO_MD" || fail "SLO.md does not contain \"$1\" (drift from $JSON: $2)"
}

# Marquee throughput: JSON target msgs_per_sec, SLO.md "60,000 msg/s".
m_tput="$(jq -r --arg id "$marquee_id" '.rows[] | select(.id == $id and .metric == "throughput_msgs_per_sec") | .target' "$JSON")"
[ "$m_tput" = "60000" ] || fail "marquee throughput target is $m_tput, expected 60000"
slo_has "60,000 msg/s" "marquee throughput"

# Marquee p99: JSON target microseconds (6000 us == 6 ms), SLO.md "6 ms".
m_p99="$(jq -r '.rows[] | select(.id == "marquee-p99") | .target' "$JSON")"
[ "$m_p99" = "6000" ] || fail "marquee p99 target is $m_p99 us, expected 6000 (6 ms)"
slo_has "6 ms" "marquee p99 (6000 us == 6 ms)"

# Edge RAM ceiling: JSON target bytes (67108864 == 64 MiB), SLO.md "64 MiB".
rss="$(jq -r '.rows[] | select(.id == "steady-rss-tiny") | .target' "$JSON")"
[ "$rss" = "67108864" ] || fail "tiny RAM ceiling target is $rss bytes, expected 67108864 (64 MiB)"
slo_has "64 MiB" "tiny-profile RAM ceiling (67108864 bytes == 64 MiB)"

# Write amplification: JSON ceiling target 4 (the >= 4x fail gate), SLO.md "4x".
wamp="$(jq -r '.rows[] | select(.id == "write-amplification-edge") | .target' "$JSON")"
[ "$wamp" = "4" ] || fail "write-amplification gate target is $wamp, expected 4 (the 4x flash-wear gate)"
slo_has "4x" "write-amplification gate"

# Ratification margin: JSON margin_fraction 0.2, SLO.md "20% margin" and "20 percent".
slo_has "20% margin" "ratification margin (margin_fraction 0.2)"
slo_has "20 percent margin" "ratification margin (margin_fraction 0.2)"

echo "ok: $JSON parses, is ironbus.slo-table.v1, has $n_rows well-formed unratified row(s), and agrees with $SLO_MD"
