#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Build the GitHub Release body for a tagged release FROM the CHANGELOG, so the release notes are the
# curated `## [vX.Y.Z]` changelog section (the audit trail #128 already gates as non-empty) plus a
# short, fixed artifact/verification footer — never a hand-maintained string that drifts from the log.
#
# GitHub caps a release body at 125000 characters. This script counts bytes and, if the assembled
# notes would exceed a safe budget, truncates the CHANGELOG portion at a line boundary and appends a
# link to the full CHANGELOG.md at the tag, so a very large release still posts a short summary + link
# instead of failing the `gh release create` call.
#
# Usage:
#   scripts/ci/release-notes.sh <tag> [changelog] [repo] [out-file]
#
#   <tag>        vX.Y.Z (or X.Y.Z); selects the `## [vX.Y.Z]` section (leading `v` optional).
#   [changelog]  path to CHANGELOG.md (default: CHANGELOG.md).
#   [repo]        owner/name for the "full changelog" link + verify hint (default: ELares/IronBus).
#   [out-file]    write the notes here (default: stdout).
#
# Deterministic and history-free: reads only the changelog. Needs only POSIX `awk`/`wc`. The section
# extraction matches the `## [vX.Y.Z]` heading as a LITERAL string, the same rule as the #128 gate
# (scripts/ci/changelog-unreleased.sh), so both agree on which section a tag maps to.
set -eu

tag="${1:?usage: release-notes.sh <tag> [changelog] [repo] [out-file]}"
changelog="${2:-CHANGELOG.md}"
repo="${3:-ELares/IronBus}"
out="${4:-}"

if [ ! -f "$changelog" ]; then
	echo "::error::release-notes: $changelog not found" >&2
	exit 2
fi

# GitHub's hard limit is 125000 chars; leave headroom for multi-byte counting and safety.
LIMIT=125000
BUDGET=123000

bare_version="${tag#v}"

# Extract the body between the exact `## [<heading>]` line and the next `## ` heading. The heading is
# matched as a LITERAL string (awk `==`), so the dots/brackets in a version need no escaping.
extract_section() {
	awk -v target="$1" '
    $0 == target { if (in_section) exit; in_section = 1; next }
    /^## /       { if (in_section) exit }
    in_section   { print }
  ' "$changelog"
}

heading_present() {
	awk -v target="$1" '$0 == target { found = 1 } END { exit(found ? 0 : 1) }' "$changelog"
}

# Prefer `## [vX.Y.Z]`, then `## [X.Y.Z]` (accept either, mirroring the #128 gate's tolerance).
heading=""
for hdr in "## [v${bare_version}]" "## [${bare_version}]"; do
	if heading_present "$hdr"; then
		heading="$hdr"
		break
	fi
done

if [ -z "$heading" ]; then
	echo "::error::release-notes: no '## [v${bare_version}]' or '## [${bare_version}]' section in $changelog" >&2
	exit 1
fi

body="$(extract_section "$heading")"

# The fixed footer: what every IronBus release ships and how to verify it. Kept short and stable so
# the variable-length CHANGELOG body is the only thing that can push the notes over budget.
footer="$(
	cat <<EOF

---

### Artifacts

Static \`musl\` binaries for the three edge triples (x86_64, aarch64, armv7) and a \`.deb\` package per
triple, each with a SHA256; a consolidated \`SHA256SUMS\` (over the binaries, the \`.deb\` packages, and
the CycloneDX SBOM); a \`cargo-auditable\` SBOM (\`ironbus.sbom.json\`); a syft CycloneDX SBOM
(\`ironbus.cyclonedx.json\`, scannable with syft/grype); and a keyless Sigstore build-provenance
attestation over every artifact.

### Verify

\`\`\`sh
sha256sum -c SHA256SUMS
gh attestation verify <artifact> --repo ${repo}
\`\`\`

The fail-closed installer (\`scripts/install.sh\`) verifies the checksum before installing. See
[docs/DISTRIBUTION.md](https://github.com/${repo}/blob/${tag}/docs/DISTRIBUTION.md) for all four
distribution channels and [CHANGELOG.md](https://github.com/${repo}/blob/${tag}/CHANGELOG.md) for the
full history.
EOF
)"

changelog_link="https://github.com/${repo}/blob/${tag}/CHANGELOG.md"

# byte_len <string> prints the byte length (chars for ASCII), the metric GitHub's limit is expressed
# in. Uses `wc -c`; printf %s avoids a trailing newline being counted.
byte_len() { printf '%s' "$1" | wc -c | tr -d ' '; }

assemble() {
	# $1 is the (possibly truncated) changelog body.
	printf '%s\n%s\n' "$1" "$footer"
}

full="$(assemble "$body")"

if [ "$(byte_len "$full")" -le "$LIMIT" ]; then
	notes="$full"
else
	# Too long: keep as many leading CHANGELOG lines as fit under BUDGET (minus the footer and the
	# truncation notice), then append the notice + a link to the full CHANGELOG at the tag. This posts
	# a short summary plus a link rather than failing the release.
	# shellcheck disable=SC2016  # the backticks are literal Markdown in the printf format, not a subshell
	notice="$(
		printf '\n> The full changelog for this release is large and was truncated here. Read the complete `## [%s]` entry: %s\n' "$tag" "$changelog_link"
	)"
	overhead="$(byte_len "$(printf '%s\n%s\n%s\n' '' "$notice" "$footer")")"
	room=$((BUDGET - overhead))
	if [ "$room" -lt 0 ]; then room=0; fi

	truncated=""
	acc=0
	# Accumulate whole lines until the next line would blow the budget.
	while IFS= read -r line; do
		# +1 for the newline that rejoins the line.
		add=$(($(byte_len "$line") + 1))
		if [ $((acc + add)) -gt "$room" ]; then
			break
		fi
		if [ -z "$truncated" ]; then
			truncated="$line"
		else
			truncated="$(printf '%s\n%s' "$truncated" "$line")"
		fi
		acc=$((acc + add))
	done <<EOF
$body
EOF

	notes="$(printf '%s\n%s\n%s\n' "$truncated" "$notice" "$footer")"
fi

if [ -n "$out" ]; then
	printf '%s\n' "$notes" >"$out"
	echo "ok: wrote release notes for '${heading}' to ${out} ($(byte_len "$notes") bytes)" >&2
else
	printf '%s\n' "$notes"
fi
