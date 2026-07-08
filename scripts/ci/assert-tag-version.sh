#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Release precondition: the pushed tag's version MUST equal the workspace version (#128 sibling gate).
#
# A `v*` tag whose version does not match `[workspace.package] version` in the top-level Cargo.toml
# means the release PR forgot to bump the manifest (or the wrong tag was pushed): the shipped binary
# would report one version while the tag/release claims another. The release workflow runs this
# BEFORE it builds anything, and the build jobs `needs:` it, so a mismatch FAILS the whole release
# loudly instead of publishing a mislabeled artifact. `scripts/prepare-release.sh` is the tool that
# keeps the two in lockstep in the first place; this gate is the belt-and-suspenders check at tag time.
#
# Usage:
#   scripts/ci/assert-tag-version.sh <tag-or-version> [path-to-Cargo.toml]
#
# `<tag-or-version>` may be `vX.Y.Z` or `X.Y.Z` (a single leading `v` is stripped). Deterministic and
# history-free: it reads only the manifest. Needs only POSIX `awk`.
set -eu

tag="${1:?usage: assert-tag-version.sh <tag-or-version> [Cargo.toml]}"
manifest="${2:-Cargo.toml}"

if [ ! -f "$manifest" ]; then
	echo "::error::version check: $manifest not found" >&2
	exit 2
fi

# Normalize the tag to a bare version: strip a single leading `v` so `v1.2.3` and `1.2.3` both match.
tag_version="${tag#v}"

# Read the FIRST `version = "..."` inside the `[workspace.package]` table, and stop at the next table
# header so a later `version =` (a dependency's) can never be picked up by mistake.
ws_version="$(
	awk '
    /^\[workspace\.package\]/ { in_sec = 1; next }
    /^\[/                     { in_sec = 0 }
    in_sec && /^[[:space:]]*version[[:space:]]*=/ {
      line = $0
      sub(/^[^"]*"/, "", line)   # drop everything up to the opening quote
      sub(/".*$/, "", line)       # drop the closing quote and the rest
      print line
      exit
    }
  ' "$manifest"
)"

if [ -z "$ws_version" ]; then
	echo "::error::version check: could not read [workspace.package] version from $manifest" >&2
	exit 2
fi

if [ "$tag_version" != "$ws_version" ]; then
	echo "::error::tag/version mismatch: tag is '${tag}' (version '${tag_version}') but ${manifest} [workspace.package] version is '${ws_version}'. Bump the manifest to match the tag (see scripts/prepare-release.sh) or push the correct tag." >&2
	exit 1
fi

echo "ok: tag '${tag}' matches [workspace.package] version '${ws_version}'"
