#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Developer Certificate of Origin (DCO) sign-off check (#128, #22).
#
# Every commit on a pull request must carry a `Signed-off-by:` trailer, per the DCO documented in
# CONTRIBUTING.md: by signing off, a contributor certifies they have the right to submit the change
# under the project's MIT OR Apache-2.0 license. This is the merge-blocking enforcement of that
# policy. It mirrors the widely-used DCO app's rule but needs no third-party GitHub App.
#
# Usage:
#   scripts/ci/dco-check.sh <base-sha> <head-sha>
#
# It checks every commit in the range `<base-sha>..<head-sha>` (the PR's own commits, not the base
# branch history). A commit missing a `Signed-off-by:` trailer FAILS the check and is named. A merge
# commit is skipped (it carries no authored change of its own). The trailer is matched
# case-insensitively at the start of a line, tolerant of trailing whitespace.
set -eu

if [ "$#" -ne 2 ]; then
	echo "usage: $0 <base-sha> <head-sha>" >&2
	exit 2
fi
base="$1"
head="$2"

range="${base}..${head}"
commits="$(git rev-list --no-merges "$range")"

if [ -z "$commits" ]; then
	echo "ok: DCO check: no non-merge commits in $range to verify"
	exit 0
fi

missing=0
for sha in $commits; do
	# The full commit message body for this one commit. A DCO sign-off is a trailer line of the
	# form `Signed-off-by: Name <email>`. grep -i for case-insensitive, anchored to line start.
	if git log -1 --format='%B' "$sha" | grep -qiE '^[[:space:]]*Signed-off-by:[[:space:]]+.+<.+>[[:space:]]*$'; then
		continue
	fi
	subject="$(git log -1 --format='%s' "$sha")"
	echo "::error::DCO: commit $sha ('$subject') is missing a 'Signed-off-by:' trailer" >&2
	missing=1
done

if [ "$missing" -ne 0 ]; then
	echo "::error::DCO check failed. Sign off every commit with 'git commit -s' (see CONTRIBUTING.md). To fix existing commits: 'git rebase --signoff $base'." >&2
	exit 1
fi

n="$(printf '%s\n' "$commits" | wc -l | tr -d ' ')"
echo "ok: DCO check: all $n commit(s) in $range carry a Signed-off-by trailer"
