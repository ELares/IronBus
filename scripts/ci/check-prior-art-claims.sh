#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# IronBus prior-art claims gate (#26, #2, #27).
#
# Enforces the agree-with-the-yaml contract between the prior-art survey
# (docs/PRIOR_ART.md) and the version-pinned source of record
# (docs/prior-art/claims.yaml): every "[claim-id]" the survey cites MUST exist as
# an id in the claims file, and every id in the claims file MUST be unique.
#
# It is offline and deterministic (no network, no yaml library, no gh): a number
# drifting upstream is surfaced by the accessed_date going stale and by a
# reviewer re-checking a low-confidence entry, NOT by this script.
#
# Mechanism:
#   1. Extract every "id:" value from claims.yaml (the entries under "claims:").
#   2. Assert the ids are unique (a duplicate id silently overwrites a claim).
#   3. Extract every cited id from PRIOR_ART.md. A citation is a token in square
#      brackets that matches an id grammar (lowercase letters, digits, dashes).
#      Markdown links "[text](url)" are excluded (the "](" disqualifies them).
#   4. Assert every cited id is present in the claims file (no dangling citation).
#
# Exit codes: 0 all citations resolve and ids are unique; 1 a gate fired
# (dangling citation or duplicate id); 2 a usage/IO error (a missing input file).

set -eu

# Resolve repo paths relative to this script so it runs from any working dir.
# Unset CDPATH so a `cd` cannot print or jump to an unexpected directory.
unset CDPATH
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "${script_dir}/../.." && pwd)
doc="${repo_root}/docs/PRIOR_ART.md"
claims="${repo_root}/docs/prior-art/claims.yaml"

fail=0

for f in "${doc}" "${claims}"; do
	if [ ! -f "${f}" ]; then
		echo "check-prior-art-claims: missing required file: ${f}" >&2
		exit 2
	fi
done

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT INT TERM

# 1. The ids defined in the claims file: lines like "  - id: kebab-case-id".
grep -E '^[[:space:]]*-[[:space:]]+id:[[:space:]]*' "${claims}" \
	| sed -E 's/^[[:space:]]*-[[:space:]]+id:[[:space:]]*//' \
	| sed -E 's/[[:space:]]+$//' \
	| sort >"${work}/defined.txt"

if [ ! -s "${work}/defined.txt" ]; then
	echo "check-prior-art-claims: no 'id:' entries found in ${claims}" >&2
	exit 2
fi

# 2. Uniqueness of defined ids.
dupes=$(uniq -d "${work}/defined.txt" || true)
if [ -n "${dupes}" ]; then
	echo "check-prior-art-claims: duplicate id(s) in claims.yaml:" >&2
	echo "${dupes}" | sed 's/^/  /' >&2
	fail=1
fi
sort -u "${work}/defined.txt" >"${work}/defined-unique.txt"

# 3. The ids cited in the survey: bracketed tokens [kebab-case-id] that are NOT
#    markdown links. Strip every "[text](url)" link first so a link target can
#    never be mistaken for a citation, then pull out the remaining [token]s that
#    match the id grammar (lowercase, digits, dashes, at least one dash).
sed -E 's/\[[^][]*\]\([^()]*\)//g' "${doc}" \
	| grep -oE '\[[a-z0-9]+(-[a-z0-9]+)+\]' \
	| sed -E 's/^\[//; s/\]$//' \
	| sort -u >"${work}/cited.txt"

if [ ! -s "${work}/cited.txt" ]; then
	echo "check-prior-art-claims: no [claim-id] citations found in ${doc}" >&2
	exit 2
fi

# 4. Every cited id must be defined. comm -23 = cited minus defined = dangling.
dangling=$(comm -23 "${work}/cited.txt" "${work}/defined-unique.txt" || true)
if [ -n "${dangling}" ]; then
	echo "check-prior-art-claims: citation(s) in PRIOR_ART.md with no claims.yaml entry:" >&2
	echo "${dangling}" | sed 's/^/  [/; s/$/]/' >&2
	fail=1
fi

if [ "${fail}" -ne 0 ]; then
	echo "check-prior-art-claims: FAILED" >&2
	exit 1
fi

cited_count=$(wc -l <"${work}/cited.txt" | tr -d '[:space:]')
defined_count=$(wc -l <"${work}/defined-unique.txt" | tr -d '[:space:]')
echo "check-prior-art-claims: OK (${cited_count} distinct citation(s) resolve against ${defined_count} unique claim id(s))"
exit 0
