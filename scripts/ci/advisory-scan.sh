#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Weekly security advisory scan that files a deduplicated issue on a NEW advisory (#128, #22).
#
# `cargo deny check advisories` is already a merge-blocking gate, so the dependency tree at HEAD is
# advisory-clean at merge time. But a RUSTSEC advisory can be published against a dependency that is
# already merged, days after the fact. This scheduled scan re-checks the committed `Cargo.lock`
# against the freshly-fetched advisory DB and, for each advisory it finds, opens ONE tracking issue,
# guarded so a re-run on the same standing advisory never opens a duplicate.
#
# It is INFORMATIONAL: it must never block a merge (it runs on a cron, not on a PR), so a found
# advisory exits 0 here; the merge-time `cargo-deny` gate is what fails a PR. The dedupe key is the
# advisory id (e.g. RUSTSEC-2024-0001) embedded in a stable issue-title marker; an open issue whose
# title carries that marker suppresses a second one.
#
# Usage:
#   scripts/ci/advisory-scan.sh
#
# Environment:
#   GH_REPO   owner/name of the repository (set by CI; falls back to `gh` default).
# Needs `cargo-deny` and the `gh` CLI authenticated with `issues: write`.
set -eu

marker_prefix="[advisory]"

# Run the advisory check and capture its output without aborting the script on a non-zero exit (a
# found advisory makes cargo-deny exit non-zero, which is the signal we want to act on, not fail on).
report="$(mktemp)"
trap 'rm -f "$report"' EXIT
deny_status=0
cargo deny --format json check advisories >"$report" 2>&1 || deny_status=$?

# Extract the advisory ids cargo-deny reported. The JSON-lines output carries one object per
# diagnostic; an advisory diagnostic has `.fields.advisory.id`. Fall back to a plain RUSTSEC-id grep
# if the JSON shape is unexpected, so a cargo-deny output-format change degrades to "still finds
# ids" rather than silently finding none.
ids=""
if command -v jq >/dev/null 2>&1; then
	ids="$(jq -r 'select(.fields.advisory.id != null) | .fields.advisory.id' "$report" 2>/dev/null | sort -u || true)"
fi
if [ -z "$ids" ]; then
	ids="$(grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' "$report" | sort -u || true)"
fi

if [ -z "$ids" ]; then
	if [ "$deny_status" -ne 0 ]; then
		# cargo-deny failed for a reason that is not a parseable advisory (e.g. a network error);
		# surface it loudly but do not crash the scheduled lane.
		echo "::warning::advisory scan: cargo-deny exited $deny_status but no advisory id was parsed; see the log" >&2
		cat "$report" >&2
	fi
	echo "ok: advisory scan found no advisories against the committed Cargo.lock"
	exit 0
fi

repo_flag=""
if [ -n "${GH_REPO:-}" ]; then
	repo_flag="--repo ${GH_REPO}"
fi

opened=0
skipped=0
for id in $ids; do
	title="${marker_prefix} ${id}"
	# Dedupe: an OPEN issue whose title already carries this advisory's marker means it is already
	# tracked. `gh issue list --search` with the exact marker, then confirm an exact title match.
	# shellcheck disable=SC2086
	existing="$(gh issue list $repo_flag --state open --search "\"${title}\" in:title" \
		--json title --jq "[.[] | select(.title == \"${title}\")] | length" 2>/dev/null || echo "0")"
	if [ "${existing:-0}" != "0" ]; then
		echo "skip: an open issue already tracks ${id}"
		skipped=$((skipped + 1))
		continue
	fi

	body="$(printf '%s\n' \
		"A new security advisory was reported against the committed \`Cargo.lock\` by the weekly \`cargo deny check advisories\` scan." \
		"" \
		"Advisory: \`${id}\` (see https://rustsec.org/advisories/${id}.html )." \
		"" \
		"The merge-time \`cargo-deny\` CI gate will now fail on PRs until this is resolved (bump or remove the affected dependency, or record a reviewed exception in \`deny.toml\`)." \
		"" \
		"This issue was filed automatically by \`scripts/ci/advisory-scan.sh\` (#128); it is deduplicated by the \`${marker_prefix} ${id}\` title marker.")"

	# shellcheck disable=SC2086
	if gh issue create $repo_flag --title "$title" --body "$body" --label "security" >/dev/null 2>&1; then
		echo "opened a tracking issue for ${id}"
		opened=$((opened + 1))
	elif gh issue create $repo_flag --title "$title" --body "$body" >/dev/null 2>&1; then
		# The `security` label may not exist in a fresh repo; retry without a label rather than fail.
		echo "opened a tracking issue for ${id} (no label)"
		opened=$((opened + 1))
	else
		echo "::error::advisory scan: failed to open a tracking issue for ${id}" >&2
		exit 1
	fi
done

echo "ok: advisory scan done: ${opened} issue(s) opened, ${skipped} already tracked"
