#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Weekly external-URL reachability check for the docs and the prior-art sources (#30).
#
# This is the ROBUST half of the #30 link integrity story. It extracts every
# external `http(s)://` URL cited in the docs (the prior-art source URLs above
# all) and verifies each is reachable, with retries and a documented skip-list
# for hosts that block bots or rate-limit. Because external hosts have transient
# outages, this check is designed to be FLAKE-RESISTANT and is run on a WEEKLY
# CRON (and on manual dispatch), NEVER as a per-PR merge gate: a dead link is
# surfaced as a tracked issue (by the workflow that wraps this script), not as a
# red mark on someone's unrelated pull request. The per-PR, never-flaky half is
# scripts/ci/relative-link-check.sh (in-repo relative links and anchors only).
#
# Why the split (the #30 non-flake design): a per-PR check that reaches out to
# the open internet reddens main on any transient blip on a third-party host. So
# the per-PR gate checks ONLY in-repo relative links (zero network), and THIS
# external check runs weekly, retries hard, honors a skip-list, and reports
# instead of blocking. Link ROT is still caught within a week even with no edits.
#
# Anchor awareness: where a cited URL carries a `#fragment`, the fragment cannot
# be verified by a HEAD (servers do not echo client-side fragments), so the URL
# is checked WITHOUT its fragment and the fragment is noted as unverifiable. The
# strong anchor guarantee for prior-art GitHub sources comes instead from pinning
# those URLs to an immutable `blob/<commit-sha>` permalink (so the cited lines
# cannot move) and from recording an archive.org snapshot for mutable vendor docs
# (see docs/PRIOR_ART_AND_IO_STANCE.md and the per-URL archive notes there).
#
# Mechanism (deterministic given the doc set and host reachability):
#   - Extract every `http(s)://...` token from the Markdown under docs/ and the
#     top-level README.md, strip trailing punctuation, de-duplicate.
#   - Drop any URL whose HOST matches the SKIP-LIST below (bot-blockers /
#     rate-limiters / loopback). Each skip is logged with its reason so the list
#     is auditable. A skip is NEVER a failure.
#   - For each remaining URL: try a HEAD, then a GET (some hosts reject HEAD),
#     each up to RETRIES times with a backoff, following redirects, with a
#     per-request timeout. A 2xx or 3xx final status is OK; a 4xx/5xx, or a total
#     connection failure after all retries, is a DEAD link.
#   - Print a summary. Exit non-zero ONLY when invoked with --strict (the manual
#     "fail on dead link" mode); by default exit 0 and let the caller (the weekly
#     workflow) decide to open a tracking issue from the printed report.
#
# Output: a machine-greppable report on stdout. Each dead link is a line
# `DEAD\t<url>\t<status-or-error>`; the final line is `external-link-check: N
# url(s), M dead, K skipped`. The wrapping workflow parses the DEAD lines.
#
# Usage:
#   scripts/ci/external-link-check.sh [--strict] [root-dir]
#     --strict   exit 1 if any link is dead (for a manual/dispatch hard check);
#                default is report-and-exit-0 (the weekly informational lane).
#
# Needs `curl`. POSIX sh; no `gh` (the workflow does the issue-filing).
set -eu

STRICT=0
ROOT="."
for arg in "$@"; do
	case "$arg" in
	--strict) STRICT=1 ;;
	*) ROOT="$arg" ;;
	esac
done
[ -d "$ROOT" ] || { echo "::error::external-link-check: $ROOT is not a directory" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "::error::external-link-check: curl not found" >&2; exit 2; }
cd "$ROOT"

RETRIES=3
TIMEOUT=20
BACKOFF=3
UA="ironbus-link-check/1 (+https://github.com/ELares/IronBus)"

# --------------------------------------------------------------------------------
# SKIP-LIST: hosts that block automated HEAD/GET (anti-bot, login walls, aggressive
# rate-limiting) or that are not externally checkable (loopback). A skipped URL is
# NEVER a failure; it is logged so the list stays honest and small. Add a host here
# ONLY with a one-line reason. Keep this list short; prefer fixing a real dead link
# over silencing it.
#   - 127.0.0.1 / localhost : loopback examples in the docs, not a real endpoint.
# (No third-party host is skipped today; this is the seam to use when one starts
# rejecting the checker.)
# --------------------------------------------------------------------------------
is_skipped_host() {
	case "$1" in
	127.0.0.1 | localhost | 0.0.0.0 | "[::1]") echo "loopback / example endpoint, not externally checkable"; return 0 ;;
	esac
	return 1
}

# URL-level skip patterns: specific URLs that are intentional placeholders or
# fill-in-the-blank template tokens, not real endpoints. Like the host skip-list,
# a skipped URL is NEVER a failure; the match reason is logged.
#   - .../issues/N : the ADR template's literal `#N` placeholder
#     (docs/adr/template.md), meant to be replaced per ADR, not a real issue.
#   - any URL containing a shell variable (e.g. `http://$addr/healthz` in a usage
#     snippet, docs/OPERATIONS.md): a fill-in-the-blank token, not a real endpoint.
is_skipped_url() {
	case "$1" in
	*github.com/*/*/issues/N | *github.com/*/*/issues/N/) echo "ADR template placeholder (#N), filled in per ADR"; return 0 ;;
	*'$'*) echo 'shell-variable placeholder (e.g. $addr) in a usage snippet, not a real endpoint'; return 0 ;;
	esac
	return 1
}

host_of() {
	# Extract the host from an http(s) URL: strip scheme, take up to the first
	# /, ?, or #. Leaves an optional :port attached; we match the bare host below.
	printf '%s' "$1" | sed -E 's#^https?://##; s#[/?#].*$##; s#^[^@]*@##; s#:[0-9]+$##'
}

strip_fragment() { printf '%s' "${1%%#*}"; }
has_fragment() { case "$1" in *'#'*) return 0 ;; *) return 1 ;; esac; }

# Collect the doc set.
files=""
[ -f README.md ] && files="README.md"
docs_md="$(find docs -type f -name '*.md' 2>/dev/null | sort || true)"
files="$files $docs_md"
[ -n "$(printf '%s' "$files" | tr -d ' ')" ] || { echo "::error::external-link-check: no Markdown files found" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Extract and normalize the external URLs. Strip a single set of trailing
# punctuation that Markdown prose commonly leaves attached: `).,;:` and a closing
# angle bracket or backtick. De-duplicate.
# shellcheck disable=SC2086
grep -rhoE 'https?://[^][)<>"`[:space:]]+' $files 2>/dev/null \
	| sed -E 's/[).,;:]+$//' \
	| sort -u >"$work/urls.txt"

total=0
dead=0
skipped=0

while IFS= read -r url; do
	[ -z "$url" ] && continue
	total=$((total + 1))
	host="$(host_of "$url")"
	if reason="$(is_skipped_host "$host")"; then
		echo "SKIP	$url	$reason"
		skipped=$((skipped + 1))
		continue
	fi
	if reason="$(is_skipped_url "$url")"; then
		echo "SKIP	$url	$reason"
		skipped=$((skipped + 1))
		continue
	fi

	check_url="$(strip_fragment "$url")"
	frag_note=""
	if has_fragment "$url"; then
		frag_note=" (fragment not server-verifiable; pin via permalink/archive)"
	fi

	# Try HEAD then GET, each with retries and a backoff. curl's own --retry
	# handles transient 5xx/connection resets; we add an outer loop so a HEAD
	# rejection (405/501) falls through to a GET before declaring a link dead.
	status=""
	method_ok=0
	for method in HEAD GET; do
		attempt=1
		while [ "$attempt" -le "$RETRIES" ]; do
			# curl's `-w %{http_code}` prints the final status (000 on a connection
			# failure, which is exactly the "dead" signal), so the request stays a
			# single clean token with no `|| echo` fallback to double up the value.
			# `|| true` keeps a curl failure (DNS, refused, timeout) from tripping
			# `set -e`: a non-zero exit is the dead-link signal we WANT to record,
			# not an error that should abort the whole scan. `%{http_code}` is then
			# `000`, which the case below maps to connection-failed.
			if [ "$method" = HEAD ]; then
				code="$(curl -s -o /dev/null -I -L \
					--connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
					-A "$UA" -w '%{http_code}' "$check_url" 2>/dev/null || true)"
			else
				code="$(curl -s -o /dev/null -L \
					--connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
					-A "$UA" -w '%{http_code}' "$check_url" 2>/dev/null || true)"
			fi
			[ -n "$code" ] || code="000"
			case "$code" in
			2?? | 3??)
				status="$code"; method_ok=1; break ;;
			405 | 501)
				# Method not allowed / not implemented: stop retrying HEAD, try GET.
				status="$code"; break ;;
			000)
				status="connection-failed" ;;
			*)
				status="http-$code" ;;
			esac
			attempt=$((attempt + 1))
			[ "$attempt" -le "$RETRIES" ] && sleep "$BACKOFF"
		done
		[ "$method_ok" = 1 ] && break
		# Only fall through to GET if HEAD was rejected as a method; otherwise the
		# GET retry below still runs (HEAD connection failures are worth a GET too).
	done

	if [ "$method_ok" = 1 ]; then
		echo "OK	$url	$status$frag_note"
	else
		echo "DEAD	$url	$status"
		dead=$((dead + 1))
	fi
done <"$work/urls.txt"

echo "external-link-check: $total url(s), $dead dead, $skipped skipped"

if [ "$dead" -gt 0 ] && [ "$STRICT" = 1 ]; then
	echo "::error::external-link-check: $dead dead link(s) found (--strict)" >&2
	exit 1
fi
exit 0
