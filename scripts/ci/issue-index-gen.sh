#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the committed issue-index snapshot from the live tracker (#25, #1).
#
# docs/issue-index.yaml is a checkable, machine-readable map of the design issue
# tree: the EPIC (#1), the 21 design PARENTS (#2 to #22), and their direct task
# children, each pinned with a stable SLUG token plus its parent back-link,
# milestone, and state. The slug (drop the [TYPE] prefix, lowercase, hyphenate,
# cap length) is the renumber-proof handle the planning artifacts can cite
# instead of a raw #N that drifts when issues are inserted or reordered.
#
# This generator derives the snapshot from `gh` and prints YAML on stdout. It is
# the SOURCE of the committed file: regenerate and commit when the tree changes.
# scripts/ci/issue-index-audit.sh is the guard that keeps the committed snapshot
# honest between regenerations (it fails on a broken back-link or a dangling
# reference and only warns on a new untracked issue, so the tracker can evolve).
#
# The in-scope set is the EPIC, the contiguous parent range #2 to #22, and every
# issue whose body carries a `Parent: #<1..22>` line (the EPIC's own governance
# children #23 to #25 and every design-parent task child). The parent of a child
# is taken from that body line; the parent of a design parent is the EPIC; the
# EPIC has no parent.
#
# Usage:
#   scripts/ci/issue-index-gen.sh > docs/issue-index.yaml
#
# Environment:
#   GH_REPO   owner/name of the repository (default ELares/IronBus).
# Needs the `gh` CLI authenticated for read and `jq` on PATH. Deterministic for a
# given tracker state: nodes are emitted in ascending issue-number order.
set -eu

REPO="${GH_REPO:-ELares/IronBus}"
PARENT_LO=2
PARENT_HI=22
EPIC=1

command -v gh >/dev/null 2>&1 || { echo "::error::issue-index-gen: gh CLI not found" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "::error::issue-index-gen: jq not found" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# All issues (number, title, milestone, state) in one fetch.
gh issue list --repo "$REPO" --state all --limit 500 \
	--json number,title,milestone,state >"$work/all.json"

# slugify: drop a leading [TYPE] tag, lowercase, collapse non-alnum to single
# hyphens, trim, and cap at 60 chars. POSIX sed/tr only (mawk not involved).
slugify() {
	printf '%s' "$1" \
		| sed -E 's/^\[[A-Za-z]+\][[:space:]]*//' \
		| tr '[:upper:]' '[:lower:]' \
		| sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' \
		| cut -c1-60 \
		| sed -E 's/-+$//'
}

# milestone title -> short key.
mkey() {
	case "$1" in
	"M0: Vision and Scope") echo "M0" ;;
	"M1: Architecture Specification") echo "M1" ;;
	"M2: Prototype-Ready Design") echo "M2" ;;
	"") echo "unassigned" ;;
	*) echo "unknown" ;;
	esac
}

# Escape a YAML double-quoted scalar (only the backslash and double quote matter).
yesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# Field accessors: query each scalar on its own so an empty milestone or any
# delimiter inside a title cannot corrupt field splitting.
title_of() { jq -r --argjson n "$1" '.[] | select(.number==$n) | .title' "$work/all.json"; }
ms_of() { jq -r --argjson n "$1" '.[] | select(.number==$n) | (.milestone.title // "")' "$work/all.json"; }
state_of() { jq -r --argjson n "$1" '.[] | select(.number==$n) | .state' "$work/all.json"; }

# Resolve a child's parent from its body `Parent: #N` line; empty if none.
parent_of() {
	gh issue view "$1" --repo "$REPO" --json body --jq '.body' 2>/dev/null \
		| grep -ioE 'Parent:[[:space:]]*#[0-9]+' \
		| head -1 \
		| grep -oE '[0-9]+' || true
}

# Build the in-scope number list: EPIC, the parents, and every child whose parent
# is in [PARENT_LO, PARENT_HI].
: >"$work/scope.txt"
printf '%s\n' "$EPIC" >>"$work/scope.txt"
n="$PARENT_LO"
while [ "$n" -le "$PARENT_HI" ]; do
	printf '%s\n' "$n" >>"$work/scope.txt"
	n=$((n + 1))
done

# Children: scan all issue numbers, keep those whose Parent line points at the
# EPIC or any design parent (a parent in [EPIC, PARENT_HI], i.e. #1 to #22).
: >"$work/children.txt"
jq -r '.[].number' "$work/all.json" | sort -n | while read -r num; do
	[ "$num" -ge "$PARENT_LO" ] && [ "$num" -le "$PARENT_HI" ] && continue
	[ "$num" = "$EPIC" ] && continue
	p="$(parent_of "$num")"
	[ -z "$p" ] && continue
	if [ "$p" -ge "$EPIC" ] && [ "$p" -le "$PARENT_HI" ]; then
		printf '%s\t%s\n' "$num" "$p" >>"$work/children.txt"
	fi
done

# Merge child numbers into scope.
cut -f1 "$work/children.txt" >>"$work/scope.txt"
sort -n -u "$work/scope.txt" >"$work/scope.sorted"

gen_date="$(date -u +%Y-%m-%d)"

# --- emit the YAML ---------------------------------------------------------------
cat <<HEADER
# IronBus issue index (machine-readable governance snapshot)
#
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A committed, checkable snapshot of the design issue map (#25). It pins, for the
# EPIC (#1), the 21 design PARENTS (#2 to #22), and their direct task children, a
# stable slug token plus the parent back-link, milestone, and state, so the map
# the planning artifacts trust is a verifiable artifact rather than raw #N
# references that drift on renumber.
#
# The slug is the canonical, renumber-proof token: derived once from the issue
# title (drop the [TYPE] prefix, lowercase, hyphenate, cap length) and stable
# across issue reordering. Cross-references should prefer the slug over the raw
# number where a stable handle is wanted.
#
# This file is a SNAPSHOT regenerated from the live tracker; it is allowed to lag
# the tracker between regenerations. scripts/ci/issue-index-audit.sh is the guard:
# it FAILS on a broken back-link or a dangling reference and WARNS (never fails)
# on a new untracked issue, so the tracker can evolve without reddening a build.
# Regenerate with: scripts/ci/issue-index-gen.sh > docs/issue-index.yaml
#
# Generated: ${gen_date} (UTC) from github.com/${REPO}
schema: ironbus.issue-index.v1
epic: ${EPIC}
generated: "${gen_date}"
milestones:
  M0: "M0: Vision and Scope"
  M1: "M1: Architecture Specification"
  M2: "M2: Prototype-Ready Design"
  unassigned: "(no milestone)"

# The 21 design parents (#2 to #22), as slug tokens. These are the spine the
# children hang off; each is a direct child of the EPIC (#1) via the EPIC's
# milestone map. Referenced by slug so a renumber cannot break the link.
parents:
HEADER

# Parent slug-token list.
m="$PARENT_LO"
while [ "$m" -le "$PARENT_HI" ]; do
	printf '  - { number: %s, slug: %s, milestone: %s }\n' \
		"$m" "$(slugify "$(title_of "$m")")" "$(mkey "$(ms_of "$m")")"
	m=$((m + 1))
done

cat <<'MID'

# Every node in scope (EPIC + 21 parents + their direct children), ordered by
# number. parent is the EPIC for the parents themselves, the design parent for a
# task child, and null for the EPIC. milestone is the issue's own label.
nodes:
MID

while read -r num; do
	title="$(title_of "$num")"
	slug="$(slugify "$title")"
	mk="$(mkey "$(ms_of "$num")")"
	st="$(state_of "$num" | tr '[:upper:]' '[:lower:]')"
	if [ "$num" = "$EPIC" ]; then
		pval="null"
	elif [ "$num" -ge "$PARENT_LO" ] && [ "$num" -le "$PARENT_HI" ]; then
		pval="$EPIC"
	else
		pval="$(awk -F'\t' -v N="$num" '$1==N{print $2; exit}' "$work/children.txt")"
	fi
	printf '  - number: %s\n' "$num"
	printf '    slug: %s\n' "$slug"
	printf '    parent: %s\n' "$pval"
	printf '    milestone: %s\n' "$mk"
	printf '    state: %s\n' "$st"
	printf '    title: "%s"\n' "$(yesc "$title")"
done <"$work/scope.sorted"
