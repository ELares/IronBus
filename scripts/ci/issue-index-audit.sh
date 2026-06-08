#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Governance audit of the committed issue index (#25, #1).
#
# docs/issue-index.yaml is a committed snapshot of the design issue tree: the
# EPIC (#1), the 21 design PARENTS (#2 to #22), and their direct task children,
# each pinned with a stable slug, a parent back-link, a milestone, and a state.
# This audit keeps that snapshot honest as the tracker evolves OUTSIDE pull
# requests, so it is a GOVERNANCE check (a weekly cron and a manual target), not
# a hard per-PR gate.
#
# What it asserts (deterministic; one `gh` fetch of all issues, then offline):
#   STRUCTURAL (offline, no network): always run, even with no `gh`.
#     - The index parses and carries the expected schema and epic.
#     - Every parent (#2 to #22) is present, exactly once, contiguous.
#     - Every node has a slug, and slugs are UNIQUE (no token collision).
#     - Every non-EPIC node BACK-LINKS to a real in-index parent (no dangling
#       parent reference, no orphan), and the EPIC's parent is null.
#     - The parent of a design parent (#2 to #22) is the EPIC; the EPIC's own
#       governance children (#23 to #25) back-link to the EPIC.
#   LIVE (only when `gh` is reachable): adds the tracker cross-checks.
#     - Every index entry is a REAL issue (not a stale/deleted number).
#     - The index milestone for each node MATCHES the issue's live milestone.
#     - Each child's live `Parent: #N` body line MATCHES the index parent.
#     - WARN (never fail) on a NEW untracked issue whose live parent is in scope
#       but which is absent from the index (the tracker grew; regenerate).
#
# Failure policy (the contract #25 asks for):
#   FAIL (exit 1) on a broken back-link, a dangling/orphan reference, a missing
#   or duplicate parent, a slug collision, a milestone mismatch, or an index
#   entry that no longer resolves to a real issue.
#   WARN (exit 0) on a new untracked issue, so the tracker can grow between
#   regenerations without reddening the build.
#   Exit 2 on a usage/IO error (the index file is missing or unparseable).
#
# When `gh` is unavailable (no token, offline), the LIVE checks are SKIPPED with
# a notice and only the structural checks run, so the audit still adds value in a
# network-restricted context and never fails spuriously on a transient outage.
#
# Usage:
#   scripts/ci/issue-index-audit.sh [path-to-issue-index.yaml]
#
# Environment:
#   GH_REPO   owner/name of the repository (default ELares/IronBus).
# Needs `yq` (mikefarah) always; `gh` + `jq` only for the live cross-checks.
set -eu

INDEX="${1:-docs/issue-index.yaml}"
REPO="${GH_REPO:-ELares/IronBus}"
PARENT_LO=2
PARENT_HI=22
EPIC=1

command -v yq >/dev/null 2>&1 || { echo "::error::issue-index-audit: yq not found" >&2; exit 2; }
[ -f "$INDEX" ] || { echo "::error::issue-index-audit: $INDEX not found" >&2; exit 2; }
yq e '.' "$INDEX" >/dev/null 2>&1 || { echo "::error::issue-index-audit: $INDEX is not valid YAML" >&2; exit 2; }

fail=0
warn=0
note() { echo "note: $*"; }
problem() { echo "::error::$*" >&2; fail=$((fail + 1)); }
warning() { echo "::warning::$*" >&2; warn=$((warn + 1)); }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- structural checks (offline) -------------------------------------------------

schema="$(yq e '.schema' "$INDEX")"
[ "$schema" = "ironbus.issue-index.v1" ] || problem "index schema is '$schema', expected ironbus.issue-index.v1"
epic_field="$(yq e '.epic' "$INDEX")"
[ "$epic_field" = "$EPIC" ] || problem "index epic is '$epic_field', expected $EPIC"

# Dump node tuples: number<TAB>parent<TAB>milestone<TAB>state<TAB>slug
yq e -r '.nodes[] | [.number, .parent, .milestone, .state, .slug] | @tsv' "$INDEX" >"$work/nodes.tsv"
cut -f1 "$work/nodes.tsv" | sort -n >"$work/index_numbers.txt"

# Every index number is unique.
dupnums="$(sort "$work/index_numbers.txt" | uniq -d || true)"
[ -z "$dupnums" ] || problem "duplicate issue number(s) in the index: $(echo "$dupnums" | tr '\n' ' ')"

# Slugs are present and unique (the renumber-proof token must not collide).
awk -F'\t' '($5==""){print $1}' "$work/nodes.tsv" >"$work/missing_slug.txt"
if [ -s "$work/missing_slug.txt" ]; then
	problem "node(s) missing a slug: $(tr '\n' ' ' <"$work/missing_slug.txt")"
fi
dupslugs="$(cut -f5 "$work/nodes.tsv" | sort | uniq -d || true)"
[ -z "$dupslugs" ] || problem "slug collision(s) in the index: $(echo "$dupslugs" | tr '\n' ' ')"

# The EPIC is present with a null parent.
epic_line="$(awk -F'\t' -v e="$EPIC" '$1==e' "$work/nodes.tsv" || true)"
if [ -z "$epic_line" ]; then
	problem "the EPIC #$EPIC is absent from the index"
else
	epic_parent="$(printf '%s' "$epic_line" | cut -f2)"
	[ "$epic_parent" = "null" ] || problem "EPIC #$EPIC parent is '$epic_parent', expected null"
fi

# Every parent #2..#22 is present exactly once, and each back-links to the EPIC.
p="$PARENT_LO"
while [ "$p" -le "$PARENT_HI" ]; do
	pline="$(awk -F'\t' -v n="$p" '$1==n' "$work/nodes.tsv" || true)"
	if [ -z "$pline" ]; then
		problem "design parent #$p is missing from the index (broken spine)"
	else
		pp="$(printf '%s' "$pline" | cut -f2)"
		[ "$pp" = "$EPIC" ] || problem "design parent #$p back-links to '$pp', not the EPIC #$EPIC"
	fi
	p=$((p + 1))
done

# Every non-EPIC node's parent must resolve to a number that is itself in the
# index (no dangling parent reference, no orphan).
while IFS="$(printf '\t')" read -r num parent _ms _state _slug; do
	[ "$num" = "$EPIC" ] && continue
	case "$parent" in
	'' | null)
		problem "node #$num has no parent back-link (orphan)"
		continue
		;;
	esac
	if ! grep -qx "$parent" "$work/index_numbers.txt"; then
		problem "node #$num back-links to #$parent, which is not in the index (dangling reference)"
	fi
done <"$work/nodes.tsv"

# Parent-of-a-parent rule: a design parent (#2..#22) must have the EPIC as parent
# (already checked above); a child outside that range must NOT itself claim to be
# a design parent's milestone spine. (Range sanity: a parent value must be in
# [EPIC, PARENT_HI].)
while IFS="$(printf '\t')" read -r num parent _ms _state _slug; do
	[ "$num" = "$EPIC" ] && continue
	case "$parent" in '' | null) continue ;; esac
	if [ "$parent" -lt "$EPIC" ] || [ "$parent" -gt "$PARENT_HI" ]; then
		problem "node #$num parent #$parent is outside the design spine [#$EPIC, #$PARENT_HI]"
	fi
done <"$work/nodes.tsv"

note "structural checks done ($(wc -l <"$work/nodes.tsv" | tr -d ' ') nodes, $((PARENT_HI - PARENT_LO + 1)) parents)"

# --- live cross-checks (require gh) ----------------------------------------------

if ! command -v gh >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
	note "gh/jq unavailable: skipping the live tracker cross-checks (structural checks still ran)"
	echo "issue-index audit: $fail problem(s), $warn warning(s)"
	[ "$fail" -eq 0 ] || exit 1
	exit 0
fi

if ! gh issue list --repo "$REPO" --state all --limit 1 --json number >/dev/null 2>&1; then
	note "gh cannot reach $REPO (no token or offline): skipping the live cross-checks, not a failure"
	echo "issue-index audit: $fail problem(s), $warn warning(s)"
	[ "$fail" -eq 0 ] || exit 1
	exit 0
fi

gh issue list --repo "$REPO" --state all --limit 500 \
	--json number,title,milestone,state >"$work/all.json"
jq -r '.[].number' "$work/all.json" | sort -n >"$work/live_numbers.txt"

ms_key() {
	case "$1" in
	"M0: Vision and Scope") echo "M0" ;;
	"M1: Architecture Specification") echo "M1" ;;
	"M2: Prototype-Ready Design") echo "M2" ;;
	"" | "null") echo "unassigned" ;;
	*) echo "unknown" ;;
	esac
}

# 1. Every index entry is a REAL, currently-existing issue.
while read -r num; do
	if ! grep -qx "$num" "$work/live_numbers.txt"; then
		problem "index entry #$num does not resolve to a real issue (stale index)"
	fi
done <"$work/index_numbers.txt"

# 2. Index milestone matches the live milestone for each node that still exists.
while IFS="$(printf '\t')" read -r num _parent ms _state _slug; do
	grep -qx "$num" "$work/live_numbers.txt" || continue
	live_ms_title="$(jq -r --argjson n "$num" '.[] | select(.number==$n) | (.milestone.title // "")' "$work/all.json")"
	live_key="$(ms_key "$live_ms_title")"
	if [ "$ms" != "$live_key" ]; then
		problem "node #$num milestone is '$ms' in the index but '$live_key' live (regenerate the index)"
	fi
done <"$work/nodes.tsv"

# 3. Each child's live `Parent: #N` body line matches the index parent. Only
#    checked for the task children (#23+), since the design parents' EPIC link is
#    the EPIC's own map, not a body line.
while IFS="$(printf '\t')" read -r num parent _ms _state _slug; do
	[ "$num" = "$EPIC" ] && continue
	[ "$num" -ge "$PARENT_LO" ] && [ "$num" -le "$PARENT_HI" ] && continue
	grep -qx "$num" "$work/live_numbers.txt" || continue
	live_parent="$(gh issue view "$num" --repo "$REPO" --json body --jq '.body' 2>/dev/null \
		| grep -ioE 'Parent:[[:space:]]*#[0-9]+' | head -1 | grep -oE '[0-9]+' || true)"
	if [ -z "$live_parent" ]; then
		warning "node #$num has no live 'Parent: #N' body line; index claims parent #$parent (verify)"
	elif [ "$live_parent" != "$parent" ]; then
		problem "node #$num live parent is #$live_parent but the index says #$parent (broken back-link)"
	fi
done <"$work/nodes.tsv"

# 4. WARN on a NEW untracked issue: a live issue whose `Parent: #N` points into
#    [EPIC, PARENT_HI] but which is absent from the index. The tracker grew; this
#    is a regenerate-the-index nudge, NOT a failure.
while read -r num; do
	[ "$num" -ge "$PARENT_LO" ] && [ "$num" -le "$PARENT_HI" ] && continue
	[ "$num" = "$EPIC" ] && continue
	grep -qx "$num" "$work/index_numbers.txt" && continue
	live_parent="$(gh issue view "$num" --repo "$REPO" --json body --jq '.body' 2>/dev/null \
		| grep -ioE 'Parent:[[:space:]]*#[0-9]+' | head -1 | grep -oE '[0-9]+' || true)"
	[ -z "$live_parent" ] && continue
	if [ "$live_parent" -ge "$EPIC" ] && [ "$live_parent" -le "$PARENT_HI" ]; then
		warning "untracked issue #$num (live parent #$live_parent) is in scope but absent from the index; regenerate docs/issue-index.yaml"
	fi
done <"$work/live_numbers.txt"

echo "issue-index audit: $fail problem(s), $warn warning(s)"
[ "$fail" -eq 0 ] || exit 1
exit 0
