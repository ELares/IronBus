#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Per-PR relative-link integrity check for the docs (#30).
#
# This is the NEVER-FLAKY half of the #30 link integrity story: it makes ZERO
# network calls. It walks every Markdown file under docs/ (and the top-level
# README.md) and verifies that every IN-REPO relative link resolves to a file
# that exists in the tree, and that every same-file `#anchor` and relative
# `path#anchor` points at a heading that actually exists in the target document.
# A moved or renamed doc, a typo'd path, or a stale section anchor fails here, on
# the PR, deterministically. External `http(s)://` and `mailto:` links are NOT
# touched here (they are the weekly external-URL job's concern), so this check
# can never redden a build on a transient network blip.
#
# What it checks for each `[text](target)` link (and `[text]: target` reference
# definitions) in scope:
#   - A relative `path` (no scheme, not starting with `#`, `http`, or `mailto:`):
#     the file `path` must exist, resolved relative to the linking file's dir.
#   - A `#anchor` (same-file): a heading whose GitHub-style slug equals `anchor`
#     must exist in the SAME file.
#   - A `path#anchor`: `path` must exist AND contain a heading slugged `anchor`.
#   - A bare in-repo path with a trailing slash or pointing at a directory is OK
#     if the directory exists.
# Image links `![alt](path)` are checked the same way (the leading `!` is stripped
# by the extractor). Pure anchors into generated/binary targets (`.pdf`, `.dot`)
# skip the anchor check (no headings to slug) but still require the file to exist.
#
# Heading-slug rule (GitHub-compatible, the subset docs use): lowercase, drop
# everything except word chars, spaces, and hyphens, then spaces to hyphens. A
# duplicate heading would get a `-1` suffix on GitHub; the docs here have no
# duplicate headings in a single file, so the base slug is sufficient and a
# collision is reported rather than silently mis-resolved.
#
# Deterministic, offline, history-free: it reads only the working tree. POSIX
# sh + awk/grep/sed only; mawk-safe (no POSIX character classes inside awk).
#
# Usage:
#   scripts/ci/relative-link-check.sh [root-dir]
# root-dir defaults to the repo root (the current directory in CI).
#
# Exit codes: 0 every relative link and anchor resolves; 1 a broken link or a
# missing anchor; 2 a usage/IO error.
set -eu

ROOT="${1:-.}"
[ -d "$ROOT" ] || { echo "::error::relative-link-check: $ROOT is not a directory" >&2; exit 2; }
cd "$ROOT"

# The files in scope: every Markdown doc plus the top-level README.
set --
[ -f README.md ] && set -- README.md
for f in $(find docs -type f -name '*.md' 2>/dev/null | sort); do
	set -- "$@" "$f"
done
[ "$#" -gt 0 ] || { echo "::error::relative-link-check: no Markdown files found under $ROOT" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# slugify_heading <heading-text> -> GitHub-style anchor slug, one per line.
# Matches GitHub's rule for the heading shapes the docs use: lowercase; delete
# every character that is not a letter, digit, space, underscore, or hyphen
# (deletion in place, so `stance (#28)` -> `stance 28`); then spaces to hyphens.
# Repeated hyphens are NOT collapsed (GitHub keeps `a / b` -> `a--b`), and the
# leading/trailing hyphens GitHub would emit are preserved, so the slug is
# byte-faithful to the anchor an author copied from the rendered page.
slugify_heading() {
	printf '%s\n' "$1" \
		| tr '[:upper:]' '[:lower:]' \
		| sed -E 's/[^a-z0-9 _-]+//g' \
		| tr ' ' '-'
}

# Emit the set of anchor slugs for a Markdown file (one per ATX heading line).
# Skips fenced code blocks so a `# comment` inside a code fence is not a heading.
emit_anchors() {
	awk '
		/^```/ { infence = !infence; next }
		!infence && /^#{1,6}[ \t]/ {
			line = $0
			sub(/^#{1,6}[ \t]+/, "", line)
			sub(/[ \t]+#*[ \t]*$/, "", line)   # strip a trailing closing-hash run
			print line
		}
	' "$1" | while IFS= read -r h; do
		slugify_heading "$h"
	done
}

# Extract link targets from a Markdown file: inline `](target)` and reference
# `[id]: target` forms. Print one raw target per line. The `!` of an image link
# is irrelevant to the target, so `![alt](t)` and `[txt](t)` both yield `t`.
emit_targets() {
	# Inline links: ](target) with target up to the first ) or whitespace.
	grep -oE '\]\([^)[:space:]]+\)' "$1" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//' || true
	# Reference definitions at line start: [id]: target
	grep -oE '^\[[^]]+\]:[[:space:]]+[^[:space:]]+' "$1" 2>/dev/null | sed -E 's/^\[[^]]+\]:[[:space:]]+//' || true
}

fail=0
checked=0
problem() { echo "::error::$*" >&2; fail=$((fail + 1)); }

# Pre-compute the anchor set for a file on demand, cached under $work.
anchors_file() {
	# $1 = source markdown path; cache key is the path with slashes replaced.
	key="$(printf '%s' "$1" | tr '/' '_')"
	cache="$work/anchors_$key"
	if [ ! -f "$cache" ]; then
		emit_anchors "$1" >"$cache" 2>/dev/null || : >"$cache"
	fi
	printf '%s' "$cache"
}

for src in "$@"; do
	srcdir="$(dirname "$src")"
	emit_targets "$src" | while IFS= read -r target; do
		[ -z "$target" ] && continue
		# Skip external and non-file schemes outright (handled by the weekly job).
		case "$target" in
		http://* | https://* | mailto:* | tel:* | ftp://*) continue ;;
		'<'*) continue ;; # an autolink fragment that slipped through; ignore
		esac

		# Split off an optional #anchor.
		path="${target%%#*}"
		case "$target" in
		*'#'*) anchor="${target#*#}" ;;
		*) anchor="" ;;
		esac

		# Resolve the file the link points at.
		if [ -z "$path" ]; then
			# Pure same-file anchor (#section).
			resolved="$src"
		else
			# Strip a query string if any (docs do not use them, but be safe).
			path="${path%%\?*}"
			case "$path" in
			/*) resolved=".${path}" ;; # repo-absolute (rare); resolve from root
			*) resolved="$srcdir/$path" ;;
			esac
		fi

		# Normalize a trailing slash to a directory existence test.
		case "$resolved" in
		*/)
			if [ ! -d "$resolved" ]; then
				echo "MISS	$src	$target	missing directory $resolved" >>"$work/fails"
			fi
			continue
			;;
		esac

		if [ ! -e "$resolved" ]; then
			echo "MISS	$src	$target	missing file $resolved" >>"$work/fails"
			continue
		fi

		# If there is an anchor and the target is a Markdown file, the heading
		# must exist. Skip the anchor check for non-Markdown (no headings).
		if [ -n "$anchor" ]; then
			case "$resolved" in
			*.md)
				ac="$(anchors_file "$resolved")"
				if ! grep -qxF "$anchor" "$ac"; then
					echo "ANCH	$src	$target	no heading slugged '$anchor' in $resolved" >>"$work/fails"
				fi
				;;
			*) : ;; # anchor into a non-Markdown target: file existence is enough
			esac
		fi
	done
done

# The loops above run in subshells (pipes), so tally from the spill file.
if [ -f "$work/fails" ]; then
	while IFS="$(printf '\t')" read -r _kind src target msg; do
		problem "$src -> $target : $msg"
	done <"$work/fails"
fi

# Count how many links were inspected, for a useful log line.
checked=0
for src in "$@"; do
	c="$(emit_targets "$src" | grep -cvE '^(https?://|mailto:|tel:|ftp://)' || true)"
	checked=$((checked + c))
done

echo "relative-link-check: inspected ~$checked in-repo links across $# file(s), $fail problem(s)"
[ "$fail" -eq 0 ] || exit 1
exit 0
