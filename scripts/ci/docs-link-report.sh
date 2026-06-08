#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Weekly docs-link report: run the external-URL and issue-index checks and file a
# deduplicated tracking issue on a dead link or a broken index (#30, #25).
#
# This is the issue-filing wrapper for the weekly governance lane, modeled on the
# advisory-scan flow (#128): it is INFORMATIONAL and never merge-blocking (it runs
# on a cron, not on a PR), so it exits 0 even when it files an issue. The
# merge-time, never-flaky guard is the per-PR relative-link check + the offline
# issue-index structural audit in CI; this lane catches the things those cannot:
# external link ROT (a third-party URL that died since the last edit) and tracker
# DRIFT (the live issue map diverging from the committed index), neither of which
# a PR would touch.
#
# It runs two checks and files at most ONE deduplicated issue per check:
#   1. scripts/ci/external-link-check.sh  -> DEAD <url> lines. A dead external URL
#      files/refreshes a `[docs-link]` issue listing the dead URLs.
#   2. scripts/ci/issue-index-audit.sh    -> a non-zero exit means a broken
#      back-link / dangling ref / milestone mismatch / stale entry. That files a
#      `[issue-index]` issue with the audit's problem lines.
# Dedupe is by a stable title marker, exactly like advisory-scan: an OPEN issue
# whose title carries the marker suppresses a duplicate; if one is already open it
# is left as-is (a comment is added so the run is visible) rather than re-opened.
#
# Usage:
#   scripts/ci/docs-link-report.sh
#
# Environment:
#   GH_REPO   owner/name of the repository (set by CI; falls back to gh default).
# Needs `gh` (issues: write), `curl`, `yq`. Sibling scripts must be alongside it.
set -eu

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_flag=""
[ -n "${GH_REPO:-}" ] && repo_flag="--repo ${GH_REPO}"

# file_or_refresh_issue <title-marker> <title> <body>: open a deduplicated issue,
# or, if one with the marker is already open, add a short comment so the recurring
# finding is visible without spawning duplicates. Never fails the lane.
file_or_refresh_issue() {
	_title="$2"
	_body="$3"
	# shellcheck disable=SC2086
	_num="$(gh issue list $repo_flag --state open --search "\"$1\" in:title" \
		--json number,title --jq "[.[] | select(.title | contains(\"$1\"))] | (.[0].number // empty)" 2>/dev/null || true)"
	if [ -n "$_num" ]; then
		echo "skip: an open issue (#$_num) already tracks '$1'; adding a recurrence note"
		# shellcheck disable=SC2086
		gh issue comment "$_num" $repo_flag --body "The weekly docs-link governance run still reports this on $(date -u +%Y-%m-%d). $_body" >/dev/null 2>&1 || true
		return 0
	fi
	# shellcheck disable=SC2086
	if gh issue create $repo_flag --title "$_title" --body "$_body" --label "area:governance" >/dev/null 2>&1; then
		echo "opened a tracking issue: $_title"
	elif gh issue create $repo_flag --title "$_title" --body "$_body" >/dev/null 2>&1; then
		echo "opened a tracking issue (no label): $_title"
	else
		echo "::warning::docs-link-report: failed to open a tracking issue: $_title" >&2
	fi
}

# --- 1. external URL reachability -------------------------------------------------
ext_out="$(mktemp)"
trap 'rm -f "$ext_out"' EXIT
# Default (non-strict) mode: the script reports and exits 0; we read its DEAD lines.
sh "$here/external-link-check.sh" >"$ext_out" 2>&1 || true
dead_urls="$(awk -F'\t' '$1=="DEAD"{print "- `" $2 "` (" $3 ")"}' "$ext_out" || true)"

if [ -n "$dead_urls" ]; then
	marker="[docs-link] dead external source URL"
	body="$(printf '%s\n' \
		"The weekly external-URL reachability check (\`scripts/ci/external-link-check.sh\`, #30) found one or more dead links cited in the docs:" \
		"" \
		"$dead_urls" \
		"" \
		"A cited source that 404s or fails to resolve makes the evidence base unauditable. Fix by updating the URL, pinning a GitHub citation to a \`blob/<commit-sha>\` permalink, or recording an archive.org snapshot (see docs/PRIOR_ART_AND_IO_STANCE.md, the source-URL durability policy). If a host merely rate-limits the checker, add it to the documented skip-list in the script." \
		"" \
		"Filed automatically by \`scripts/ci/docs-link-report.sh\`; deduplicated by the \`${marker}\` title marker.")"
	file_or_refresh_issue "$marker" "$marker" "$body"
else
	echo "ok: no dead external links in the docs"
fi

# --- 2. issue-index integrity (live) ---------------------------------------------
idx_out="$(mktemp)"
# shellcheck disable=SC2064
trap "rm -f '$ext_out' '$idx_out'" EXIT
idx_status=0
sh "$here/issue-index-audit.sh" >"$idx_out" 2>&1 || idx_status=$?

if [ "$idx_status" -ne 0 ]; then
	problems="$(grep -E '^::error::' "$idx_out" | sed -E 's/^::error:://; s/^/- /' || true)"
	[ -z "$problems" ] && problems="- (see the workflow log for details)"
	marker="[issue-index] committed index is stale or broken"
	body="$(printf '%s\n' \
		"The weekly issue-index governance audit (\`scripts/ci/issue-index-audit.sh\`, #25) reported a hard problem in the committed \`docs/issue-index.yaml\`:" \
		"" \
		"$problems" \
		"" \
		"This is a broken back-link, a dangling/orphan reference, a milestone mismatch, a slug collision, or an entry that no longer resolves to a real issue. Regenerate the index with \`scripts/ci/issue-index-gen.sh > docs/issue-index.yaml\` and reconcile, or fix the underlying tracker link. (A NEW untracked issue is only a warning and does not file here.)" \
		"" \
		"Filed automatically by \`scripts/ci/docs-link-report.sh\`; deduplicated by the \`${marker}\` title marker.")"
	file_or_refresh_issue "$marker" "$marker" "$body"
else
	echo "ok: issue-index audit clean"
	# Surface any warnings (e.g. a new untracked issue) in the log without filing.
	grep -E '^::warning::' "$idx_out" || true
fi

echo "docs-link-report: done (external + issue-index governance checks complete)"
exit 0
