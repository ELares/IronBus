#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Durable-scoreboard fairness + drift gate (#646, V2-M12).
#
# The durable produce + consume scoreboard vs NATS (JetStream AND Core) has a human-readable form
# (the "#646" section of docs/PERF_LEDGER.md) and a machine-readable form
# (docs/benchmarks/durable-scoreboard-rows.jsonl). The scoreboard's first principle is that
# "beats NATS" is only credible at EQUAL durability: a leg may be scored head-to-head only when
# both sides give the same guarantee, and every guarantee-asymmetric leg must carry its asymmetry
# explicitly. This gate mechanizes that principle on the PR, deterministically:
#
#   1. The rows parse (JSONL, one comparison leg per line) and every row carries the full required
#      field set with a known system and a positive numeric throughput.
#   2. FAIRNESS: every head-to-head pair (rows sharing a non-null `pair` id) has exactly two rows,
#      IDENTICAL durability labels on both sides (an fsync-backed ack can never be paired against
#      a page-cache ack), and exactly one IronBus side. This is the same anti-marketing discipline
#      as the #114/#554 durability-label lints, applied to the committed scoreboard.
#   3. ASYMMETRY: every UNPAIRED row (pair == null) carries a substantive `asymmetry` note (>= 20
#      chars), so the guarantee gap can never be silently dropped while the number stays.
#   4. LOAD-BEARING LEG: the matched durable-consume pair (`durable-consume-256`) exists — the
#      leg the issue names as the credible comparison cannot be deleted without failing CI.
#   5. DRIFT: every row's `measured_range` string and the computed headline ratio must appear in
#      docs/PERF_LEDGER.md, and the ledger must state the publish-ack guarantee asymmetry — so the
#      prose and the rows cannot diverge (the #359 SLO-drift-gate pattern).
#
# What this gate deliberately does NOT do: run NATS, IronBus, or any live benchmark. A comparative
# perf run on a shared CI runner produces exactly the flaky percent gate #114's design notes warn
# about; the live re-run is manual via scripts/bench/nats-scoreboard.sh on a quiet box, and the
# IronBus-side absolute regression protection is the existing #114 rolling-median gate.
#
# Deterministic, offline, history-free: reads only the working tree; needs only jq.
#
# Run locally exactly as CI does:
#   sh scripts/ci/durable-scoreboard-check.sh
set -eu

ROWS="${1:-docs/benchmarks/durable-scoreboard-rows.jsonl}"
LEDGER="${2:-docs/PERF_LEDGER.md}"

fail() {
	echo "::error::durable-scoreboard gate: $1" >&2
	exit 1
}

if ! command -v jq >/dev/null 2>&1; then
	echo "::error::durable-scoreboard gate: jq not found on PATH" >&2
	exit 2
fi
[ -f "$ROWS" ] || {
	echo "::error::durable-scoreboard gate: $ROWS not found" >&2
	exit 2
}
[ -f "$LEDGER" ] || {
	echo "::error::durable-scoreboard gate: $LEDGER not found" >&2
	exit 2
}

# 1. Every line must parse as a JSON object; slurp the sequence into one array for the checks.
jq -s 'map(type) | all(. == "object")' "$ROWS" >/dev/null 2>&1 ||
	fail "$ROWS is not valid JSONL (a line failed to parse as a JSON object)"
n_rows="$(jq -s 'length' "$ROWS")"
[ "$n_rows" -ge 1 ] || fail "$ROWS has no rows"

# Required field set on every row (`pair` may be null but the key must be present; `asymmetry` is
# conditionally required and checked in step 3).
required_keys='["pair","system","leg","durability","payload_bytes","throughput_msgs_per_sec","measured_range","source"]'
missing="$(jq -s --argjson req "$required_keys" \
	'[.[] | select((($req - keys) | length) > 0)] | length' "$ROWS")"
[ "$missing" = "0" ] || fail "$missing row(s) are missing a required field (need: $required_keys)"

# Known systems only; positive numeric throughput; non-empty leg + durability; unique leg ids.
bad_sys="$(jq -s '[.[] | select([.system] | inside(["ironbus","nats","nats-core"]) | not)] | length' "$ROWS")"
[ "$bad_sys" = "0" ] || fail "$bad_sys row(s) have a system other than ironbus/nats/nats-core"
bad_thr="$(jq -s '[.[] | select((.throughput_msgs_per_sec | type) != "number" or .throughput_msgs_per_sec <= 0)] | length' "$ROWS")"
[ "$bad_thr" = "0" ] || fail "$bad_thr row(s) have a non-numeric or non-positive throughput_msgs_per_sec"
bad_str="$(jq -s '[.[] | select(((.leg // "") | length) == 0 or ((.durability // "") | length) == 0 or ((.measured_range // "") | length) == 0)] | length' "$ROWS")"
[ "$bad_str" = "0" ] || fail "$bad_str row(s) have an empty leg, durability, or measured_range"
n_legs="$(jq -s '[.[].leg] | unique | length' "$ROWS")"
[ "$n_rows" = "$n_legs" ] || fail "leg ids must be unique ($n_rows rows, $n_legs distinct legs)"

# 2. FAIRNESS: each non-null pair id groups exactly two rows, with identical durability labels and
# exactly one IronBus side. A mismatched-durability "pair" is the marketing comparison this
# scoreboard exists to forbid.
bad_size="$(jq -s '[.[] | select(.pair != null)] | group_by(.pair) | map(select(length != 2)) | length' "$ROWS")"
[ "$bad_size" = "0" ] || fail "$bad_size pair id(s) do not group exactly two rows"
bad_label="$(jq -s '[.[] | select(.pair != null)] | group_by(.pair) | map(select((map(.durability) | unique | length) != 1)) | length' "$ROWS")"
[ "$bad_label" = "0" ] ||
	fail "$bad_label pair(s) carry MISMATCHED durability labels (an fsync-backed leg can never be paired against a page-cache-acked leg)"
bad_side="$(jq -s '[.[] | select(.pair != null)] | group_by(.pair) | map(select(([.[] | select(.system == "ironbus")] | length) != 1)) | length' "$ROWS")"
[ "$bad_side" = "0" ] || fail "$bad_side pair(s) do not have exactly one IronBus side"

# 3. ASYMMETRY: every unpaired row must say WHY it cannot be paired, substantively (>= 20 chars,
# so a stub like "n/a" cannot stand in for the guarantee gap).
bad_asym="$(jq -s '[.[] | select(.pair == null) | select(((.asymmetry // "") | length) < 20)] | length' "$ROWS")"
[ "$bad_asym" = "0" ] ||
	fail "$bad_asym unpaired row(s) lack a substantive asymmetry note (every unpaired leg must state its guarantee gap)"

# 4. LOAD-BEARING LEG: the matched durable-consume head-to-head must exist at the matched label.
lb="$(jq -s '[.[] | select(.pair == "durable-consume-256" and .durability == "durable-consume" and .payload_bytes == 256)] | length' "$ROWS")"
[ "$lb" = "2" ] ||
	fail "the load-bearing matched pair durable-consume-256 (durability durable-consume, 256 B, two rows) is missing — the scoreboard's credible comparison cannot be dropped"

# 5. DRIFT: every measured_range must appear verbatim in the ledger, so a number changed in one
# place but not the other fails here, on the PR.
misses=0
while IFS= read -r range; do
	if ! grep -qF -- "$range" "$LEDGER"; then
		echo "::error::durable-scoreboard gate: $LEDGER does not contain \"$range\" (drift from $ROWS)" >&2
		misses=$((misses + 1))
	fi
done <<EOF
$(jq -sr '.[].measured_range' "$ROWS")
EOF
[ "$misses" = "0" ] || exit 1

# The headline ratio is COMPUTED from the rows (conservative endpoints) and must be stated in the
# ledger: IronBus durable consume over the NATS side of the load-bearing pair, one decimal.
ratio="$(jq -sr '(([.[] | select(.pair == "durable-consume-256" and .system == "ironbus")][0].throughput_msgs_per_sec
	/ [.[] | select(.pair == "durable-consume-256" and .system != "ironbus")][0].throughput_msgs_per_sec)
	* 10 | round / 10)' "$ROWS")"
grep -qF -- "${ratio}x" "$LEDGER" ||
	fail "$LEDGER does not state the computed durable-consume headline ratio \"${ratio}x\""

# The publish-ack guarantee asymmetry must be stated in prose, not only encoded in the rows.
grep -qF -- "NOT fsynced" "$LEDGER" ||
	fail "$LEDGER must state that the JetStream publish ack is NOT fsynced (the guarantee asymmetry)"
grep -qF -- "fsync-backed" "$LEDGER" ||
	fail "$LEDGER must state that the IronBus publish ack is fsync-backed (the guarantee asymmetry)"

n_pairs="$(jq -s '[.[] | select(.pair != null) | .pair] | unique | length' "$ROWS")"
n_ctx="$(jq -s '[.[] | select(.pair == null)] | length' "$ROWS")"
echo "ok: $ROWS has $n_rows rows ($n_pairs matched pair(s), $n_ctx asymmetric context row(s)), fairness-linted, headline ${ratio}x, and agrees with $LEDGER"
