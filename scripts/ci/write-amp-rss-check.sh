#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Write-amplification + RSS-per-message fairness + drift gate (#645, V2-M12).
#
# The write-amp / RSS head-to-head vs NATS has a human-readable form
# (docs/benchmarks/write-amp-rss.md) and a machine-readable form
# (docs/benchmarks/write-amp-rss-rows.jsonl). Same first principle as the #646 scoreboard
# gate: a number may be scored head-to-head only when both sides measured the same metric at
# the same workload, and every unpaired context row must carry its asymmetry explicitly. This
# gate mechanizes that on the PR, deterministically:
#
#   1. The rows parse (JSONL) and every row carries the full required field set with a known
#      system and a numeric value.
#   2. FAIRNESS: every head-to-head pair (rows sharing a non-null `pair` id) has exactly two
#      rows, IDENTICAL metric / payload_bytes / msgs on both sides, and exactly one IronBus
#      side (a 256 B write-amp figure can never be scored against a 4 KiB one, nor a
#      write_bytes figure against a du one).
#   3. ASYMMETRY: every UNPAIRED row (pair == null) carries a substantive `asymmetry` note
#      (>= 20 chars), so a context number can never shed its caveat while the number stays.
#   4. LOAD-BEARING LEGS: the matched 256 B write-amplification pair and the 1M-message
#      RSS-per-message pair exist - the two comparisons #645 names cannot be deleted without
#      failing CI.
#   5. DRIFT: every row's `measured` string and the computed write-amp headline ratio must
#      appear in docs/benchmarks/write-amp-rss.md, and the doc must state the du-vs-write_bytes
#      semantics and the JetStream ack asymmetry - so the prose and the rows cannot diverge
#      (the #359 SLO-drift-gate pattern).
#
# What this gate deliberately does NOT do: run NATS, IronBus, or any live benchmark (the #114
# flaky-percent-gate consideration; a comparative run on a shared CI runner is noise). The
# live re-run is manual: `bash docs/benchmarks/write_amp_rss.sh` on a quiet Linux box; if a
# number moves, update the rows AND the doc together or this gate fails the PR.
#
# Deterministic, offline, history-free: reads only the working tree; needs only jq.
#
# Run locally exactly as CI does:
#   sh scripts/ci/write-amp-rss-check.sh
set -eu

ROWS="${1:-docs/benchmarks/write-amp-rss-rows.jsonl}"
DOC="${2:-docs/benchmarks/write-amp-rss.md}"

fail() {
	echo "::error::write-amp-rss gate: $1" >&2
	exit 1
}

if ! command -v jq >/dev/null 2>&1; then
	echo "::error::write-amp-rss gate: jq not found on PATH" >&2
	exit 2
fi
[ -f "$ROWS" ] || {
	echo "::error::write-amp-rss gate: $ROWS not found" >&2
	exit 2
}
[ -f "$DOC" ] || {
	echo "::error::write-amp-rss gate: $DOC not found" >&2
	exit 2
}

# 1. Every line must parse as a JSON object; slurp the sequence into one array for the checks.
jq -s 'map(type) | all(. == "object")' "$ROWS" >/dev/null 2>&1 ||
	fail "$ROWS is not valid JSONL (a line failed to parse as a JSON object)"
n_rows="$(jq -s 'length' "$ROWS")"
[ "$n_rows" -ge 1 ] || fail "$ROWS has no rows"

# Required field set on every row (`pair` may be null but the key must be present; `asymmetry`
# is conditionally required and checked in step 3).
required_keys='["pair","system","leg","metric","payload_bytes","msgs","value","measured","source"]'
missing="$(jq -s --argjson req "$required_keys" \
	'[.[] | select((($req - keys) | length) > 0)] | length' "$ROWS")"
[ "$missing" = "0" ] || fail "$missing row(s) are missing a required field (need: $required_keys)"

# Known systems only; numeric value; non-empty leg/metric/measured; unique (system, leg,
# metric) triples (one leg legitimately yields several metrics, so the TRIPLE is the row id).
bad_sys="$(jq -s '[.[] | select([.system] | inside(["ironbus","nats"]) | not)] | length' "$ROWS")"
[ "$bad_sys" = "0" ] || fail "$bad_sys row(s) have a system other than ironbus/nats"
bad_val="$(jq -s '[.[] | select((.value | type) != "number")] | length' "$ROWS")"
[ "$bad_val" = "0" ] || fail "$bad_val row(s) have a non-numeric value"
bad_str="$(jq -s '[.[] | select(((.leg // "") | length) == 0 or ((.metric // "") | length) == 0 or ((.measured // "") | length) == 0)] | length' "$ROWS")"
[ "$bad_str" = "0" ] || fail "$bad_str row(s) have an empty leg, metric, or measured"
n_ids="$(jq -s '[.[] | "\(.system)/\(.leg)/\(.metric)"] | unique | length' "$ROWS")"
[ "$n_rows" = "$n_ids" ] || fail "row ids (system/leg/metric) must be unique ($n_rows rows, $n_ids distinct ids)"

# 2. FAIRNESS: each non-null pair id groups exactly two rows measuring the SAME metric at the
# SAME workload (payload_bytes AND msgs), with exactly one IronBus side.
bad_size="$(jq -s '[.[] | select(.pair != null)] | group_by(.pair) | map(select(length != 2)) | length' "$ROWS")"
[ "$bad_size" = "0" ] || fail "$bad_size pair id(s) do not group exactly two rows"
bad_match="$(jq -s '[.[] | select(.pair != null)] | group_by(.pair) | map(select((map({metric, payload_bytes, msgs}) | unique | length) != 1)) | length' "$ROWS")"
[ "$bad_match" = "0" ] ||
	fail "$bad_match pair(s) mix metrics or workloads (a pair must compare the SAME metric at the SAME payload_bytes and msgs)"
bad_side="$(jq -s '[.[] | select(.pair != null)] | group_by(.pair) | map(select(([.[] | select(.system == "ironbus")] | length) != 1)) | length' "$ROWS")"
[ "$bad_side" = "0" ] || fail "$bad_side pair(s) do not have exactly one IronBus side"

# 3. ASYMMETRY: every unpaired row must say WHY it cannot be paired, substantively.
bad_asym="$(jq -s '[.[] | select(.pair == null) | select(((.asymmetry // "") | length) < 20)] | length' "$ROWS")"
[ "$bad_asym" = "0" ] ||
	fail "$bad_asym unpaired row(s) lack a substantive asymmetry note (every context leg must state its caveat)"

# 4. LOAD-BEARING LEGS: the two comparisons #645 names must exist at the matched labels.
lb_wamp="$(jq -s '[.[] | select(.pair == "write-amp-wb-256" and .metric == "write_amp_write_bytes" and .payload_bytes == 256)] | length' "$ROWS")"
[ "$lb_wamp" = "2" ] ||
	fail "the load-bearing matched pair write-amp-wb-256 (write_amp_write_bytes at 256 B, two rows) is missing"
lb_rss="$(jq -s '[.[] | select(.pair == "rss-per-msg-1m-256" and .metric == "rss_bytes_per_msg_0_to_1m")] | length' "$ROWS")"
[ "$lb_rss" = "2" ] ||
	fail "the load-bearing matched pair rss-per-msg-1m-256 (rss_bytes_per_msg_0_to_1m, two rows) is missing"

# 5. DRIFT: every measured string must appear verbatim in the doc, so a number changed in one
# place but not the other fails here, on the PR.
misses=0
while IFS= read -r m; do
	if ! grep -qF -- "$m" "$DOC"; then
		echo "::error::write-amp-rss gate: $DOC does not contain \"$m\" (drift from $ROWS)" >&2
		misses=$((misses + 1))
	fi
done <<EOF
$(jq -sr '.[].measured' "$ROWS")
EOF
[ "$misses" = "0" ] || exit 1

# The write-amp headline ratio is COMPUTED from the rows and must be stated in the doc:
# NATS write_bytes amplification over IronBus's on the load-bearing 256 B pair, one decimal.
ratio="$(jq -sr '(([.[] | select(.pair == "write-amp-wb-256" and .system == "nats")][0].value
	/ [.[] | select(.pair == "write-amp-wb-256" and .system == "ironbus")][0].value)
	* 10 | round / 10)' "$ROWS")"
grep -qF -- "${ratio}x" "$DOC" ||
	fail "$DOC does not state the computed 256 B write-amp headline ratio \"${ratio}x\""

# The two metric semantics and the remaining guarantee asymmetry must be stated in prose, not
# only encoded in the rows.
grep -qF -- "write_bytes captures" "$DOC" ||
	fail "$DOC must state what write_bytes captures (rewrite/churn semantics)"
grep -qF -- "du captures" "$DOC" ||
	fail "$DOC must state what du captures (retained-bytes semantics)"
grep -qF -- "NOT fsync-coupled" "$DOC" ||
	fail "$DOC must state that the JetStream publish ack is NOT fsync-coupled even under sync_interval: always"

n_pairs="$(jq -s '[.[] | select(.pair != null) | .pair] | unique | length' "$ROWS")"
n_ctx="$(jq -s '[.[] | select(.pair == null)] | length' "$ROWS")"
echo "ok: $ROWS has $n_rows rows ($n_pairs matched pair(s), $n_ctx asymmetric context row(s)), fairness-linted, headline ${ratio}x, and agrees with $DOC"
