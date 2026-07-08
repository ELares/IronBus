#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# prepare-release.sh <X.Y.Z> — do the mechanical release-prep edits in one shot, so cutting a release
# is `scripts/prepare-release.sh X.Y.Z` -> review + merge the PR -> `git tag vX.Y.Z && git push`, and
# the Release workflow (.github/workflows/release.yml) builds + publishes automatically. It:
#
#   1. bumps `[workspace.package] version` in the top-level Cargo.toml,
#   2. bumps the internal path-dependency `version = "..."` pins in every crate manifest so cargo's
#      published-version requirement stays in lockstep with the new workspace version,
#   3. reconciles Cargo.lock (via `cargo update --workspace`; a deterministic in-place patch if cargo
#      is unavailable),
#   4. rolls CHANGELOG.md: moves `## [Unreleased]` under a new `## [vX.Y.Z]` heading (with a
#      `_Released <date>._` sub-line, keeping the heading EXACTLY `## [vX.Y.Z]` so the #128 changelog
#      gate matches it) and inserts a fresh empty `## [Unreleased]`,
#   5. scaffolds docs/benchmarks/baselines/vX.Y.Z/ from the previous release's baselines (retagged,
#      coverage number reset to the pending `null`), and
#   6. prints the remaining manual steps (fill in the changelog if empty, re-anchor baselines, open
#      the PR, then tag + push).
#
# It makes NO commit, NO tag, and NO push — it only edits the working tree for review. It is
# idempotent: re-running for the same version is a no-op on the parts already done. See RELEASING.md.
set -euo pipefail

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}
info() { printf '  %s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }

# --- 1. validate the version argument -------------------------------------------------------------
[ "$#" -eq 1 ] || die "usage: scripts/prepare-release.sh <X.Y.Z>"
VERSION="${1#v}" # tolerate a leading `v` (`v0.2.0` -> `0.2.0`)
# Semver: MAJOR.MINOR.PATCH with an optional -prerelease and +build (per semver.org).
if ! printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
	die "not a valid semver version: '$1' (expected X.Y.Z, e.g. 0.2.0)"
fi
TAG="v${VERSION}"

# --- repo root + a portable, in-place file rewriter -----------------------------------------------
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
MANIFEST="Cargo.toml"
[ -f "$MANIFEST" ] || die "no Cargo.toml at repo root ($ROOT)"
grep -q '^\[workspace\.package\]' "$MANIFEST" || die "$MANIFEST has no [workspace.package] table; is this the IronBus repo root?"

# rewrite <file> <awk-program> [awk-args...] — run awk over a file and replace it atomically. Avoids
# `sed -i`, whose flag differs between BSD (macOS) and GNU (Linux) sed.
rewrite() {
	local file="$1"
	shift
	local tmp
	tmp="$(mktemp "${file}.XXXXXX")"
	awk "$@" "$file" >"$tmp"
	mv "$tmp" "$file"
}

# regex-escape a literal string for use in an awk ERE (only `.` matters for a version).
# shellcheck disable=SC2016  # the sed program is a literal char class, it must not shell-expand
esc() { printf '%s' "$1" | sed 's/[.[\*^$()+?{|]/\\&/g'; }

# --- read the current workspace version -----------------------------------------------------------
CUR="$(
	awk '
    /^\[workspace\.package\]/ { in_sec = 1; next }
    /^\[/                     { in_sec = 0 }
    in_sec && /^[[:space:]]*version[[:space:]]*=/ {
      line = $0; sub(/^[^"]*"/, "", line); sub(/".*$/, "", line); print line; exit
    }
  ' "$MANIFEST"
)"
[ -n "$CUR" ] || die "could not read [workspace.package] version from $MANIFEST"

# Guard against an accidental downgrade; allow equal (idempotent re-run).
if [ "$VERSION" != "$CUR" ]; then
	lowest="$(printf '%s\n%s\n' "$VERSION" "$CUR" | sort -V | head -n1)"
	[ "$lowest" = "$CUR" ] || die "refusing to prepare $VERSION: it is older than the current $CUR"
fi

TODAY="$(date -u +%Y-%m-%d)"
echo "Preparing release ${TAG} (current workspace version: ${CUR})" >&2

# --- 2a. bump [workspace.package] version ---------------------------------------------------------
if [ "$VERSION" = "$CUR" ]; then
	info "[workspace.package] version already ${VERSION}, leaving as-is"
else
	rewrite "$MANIFEST" -v new="$VERSION" '
    /^\[workspace\.package\]/ { in_sec = 1; print; next }
    /^\[/                     { in_sec = 0 }
    in_sec && !done && /^[[:space:]]*version[[:space:]]*=/ {
      sub(/"[^"]*"/, "\"" new "\""); done = 1
    }
    { print }
  '
	info "bumped [workspace.package] version ${CUR} -> ${VERSION} in ${MANIFEST}"
fi

# --- 2b. bump the internal path-dep version pins --------------------------------------------------
# Lines like `ironbus-core = { path = "../ironbus-core", version = "0.1.0" }` carry a version
# requirement that must equal the (new) published version, so bump every `version = "<CUR>"` that
# sits on a `path = "../ironbus..."` line. Only crate manifests have these pins.
if [ "$VERSION" = "$CUR" ]; then
	info "internal path-dep version pins already ${VERSION}, leaving as-is"
else
	CUR_RE="$(esc "$CUR")"
	pin_changed=0
	for f in crates/*/Cargo.toml; do
		[ -f "$f" ] || continue
		before="$(grep -c "path = \"\.\./ironbus.*version = \"${CUR}\"" "$f" || true)"
		if [ "$before" -gt 0 ]; then
			rewrite "$f" -v newpin="version = \"${VERSION}\"" -v oldre="version = \"${CUR_RE}\"" '
        /path = "\.\.\/ironbus/ { gsub(oldre, newpin) }
        { print }
      '
			pin_changed=$((pin_changed + before))
		fi
	done
	info "bumped ${pin_changed} internal path-dep version pin(s) ${CUR} -> ${VERSION}"
fi

# --- 3. reconcile Cargo.lock ----------------------------------------------------------------------
# `cargo update --workspace` rewrites ONLY the workspace members' versions in the lock (it leaves
# every third-party dep pinned), which is exactly the reconciliation a version bump needs.
if command -v cargo >/dev/null 2>&1; then
	if cargo update --workspace --offline >/dev/null 2>&1 ||
		cargo update --workspace >/dev/null 2>&1; then
		info "reconciled Cargo.lock with 'cargo update --workspace'"
	else
		warn "'cargo update --workspace' failed; patching Cargo.lock directly"
		patch_lock=1
	fi
else
	warn "cargo not found; patching Cargo.lock directly (run 'cargo build --locked' later to confirm)"
	patch_lock=1
fi

if [ "${patch_lock:-0}" = 1 ]; then
	# Fallback: set the version of each workspace-member package block in Cargo.lock. Workspace members
	# carry no checksum line and are referenced by bare name in `dependencies`, so a version rewrite is
	# self-consistent. Collect the member names from their manifests so io-free-check (which also
	# inherits version.workspace) is covered, not just the ironbus-* crates.
	members=""
	for f in crates/*/Cargo.toml tools/*/Cargo.toml; do
		[ -f "$f" ] || continue
		grep -q '^version.workspace = true' "$f" || continue
		name="$(awk -F'"' '/^name[[:space:]]*=/ { print $2; exit }' "$f")"
		[ -n "$name" ] && members="${members} ${name}"
	done
	# shellcheck disable=SC2016  # $0/$1 are awk fields inside the awk program, not shell expansions
	rewrite Cargo.lock -v members=" ${members} " -v cur="$CUR" -v new="$VERSION" '
    /^name = "/ { name = $0; sub(/^name = "/, "", name); sub(/"$/, "", name) }
    /^version = "/ && index(members, " " name " ") > 0 {
      if ($0 == "version = \"" cur "\"") { print "version = \"" new "\""; next }
    }
    { print }
  '
	info "patched Cargo.lock workspace-member versions ${CUR} -> ${VERSION}"
fi

# --- 4. roll the CHANGELOG ------------------------------------------------------------------------
CHANGELOG="CHANGELOG.md"
if [ ! -f "$CHANGELOG" ]; then
	warn "no $CHANGELOG to roll; skipping"
elif grep -q "^## \[${TAG}\]\$" "$CHANGELOG"; then
	info "CHANGELOG already has a '## [${TAG}]' section, leaving as-is"
elif ! grep -q '^## \[Unreleased\]$' "$CHANGELOG"; then
	warn "CHANGELOG has no '## [Unreleased]' heading; not rolling it (add the section manually)"
else
	# Rename the `## [Unreleased]` heading to `## [vX.Y.Z]` + a `_Released <date>._` sub-line, its body
	# stays in place under the new version, and insert a fresh empty `## [Unreleased]` above it. The new
	# version heading stays EXACTLY `## [vX.Y.Z]` (no in-heading date) so the #128 changelog gate and
	# the release-notes extractor both match it; the date goes on the sub-line, as v0.1.0 did.
	# shellcheck disable=SC2016  # $0 is an awk field inside the awk program, not a shell expansion
	rewrite "$CHANGELOG" -v ver="$VERSION" -v date="$TODAY" '
    $0 == "## [Unreleased]" && !done {
      print "## [Unreleased]"; print ""
      print "## [v" ver "]"; print ""
      print "_Released " date "._"
      done = 1; next
    }
    { print }
  '
	info "rolled CHANGELOG: '## [Unreleased]' -> '## [${TAG}]' (dated ${TODAY}) + fresh '## [Unreleased]'"
fi

# --- 5. scaffold this release's baseline directory ------------------------------------------------
BASE_ROOT="docs/benchmarks/baselines"
NEW_DIR="${BASE_ROOT}/${TAG}"
if [ ! -d "$BASE_ROOT" ]; then
	warn "no ${BASE_ROOT} directory; skipping baseline scaffold"
elif [ -d "$NEW_DIR" ]; then
	info "baseline dir ${NEW_DIR} already exists, leaving as-is"
else
	# Prefer the CURRENT (previous-release) version's baseline dir; else the highest-versioned one.
	PREV_DIR="${BASE_ROOT}/v${CUR}"
	if [ ! -d "$PREV_DIR" ]; then
		PREV_DIR="$(find "$BASE_ROOT" -mindepth 1 -maxdepth 1 -type d -name 'v*' | sort -V | tail -n1)"
	fi
	if [ -z "${PREV_DIR:-}" ] || [ ! -d "$PREV_DIR" ]; then
		warn "no previous baseline dir to scaffold ${NEW_DIR} from; create it by hand (see RELEASING.md)"
	else
		PREV_TAG="$(basename "$PREV_DIR")"
		PREV_RE="$(esc "$PREV_TAG")"
		cp -R "$PREV_DIR" "$NEW_DIR"
		# Retag every "tag" field / heading / prose reference to the new tag, and reset the coverage
		# number to the pending `null` (it is re-recorded from the first post-tag nightly; see the dir's
		# README + RELEASING.md). The perf runs are carried over for the owner to re-anchor.
		for jf in "$NEW_DIR"/*.json "$NEW_DIR"/README.md; do
			[ -f "$jf" ] || continue
			rewrite "$jf" -v oldre="$PREV_RE" -v new="$TAG" '{ gsub(oldre, new); print }'
		done
		if [ -f "$NEW_DIR/coverage-baseline.json" ]; then
			rewrite "$NEW_DIR/coverage-baseline.json" '
        /"line_coverage_pct"[[:space:]]*:/ { sub(/:[[:space:]]*[^,]*/, ": null") }
        { print }
      '
		fi
		info "scaffolded ${NEW_DIR} from ${PREV_DIR} (retagged; coverage reset to pending null)"
	fi
fi

# --- 6. print the remaining steps -----------------------------------------------------------------
cat >&2 <<EOF

Prepared ${TAG}. NOTHING was committed, tagged, or pushed. Next:

  1. Review the working-tree changes:
       git diff --stat
     - Fill in CHANGELOG.md under '## [${TAG}]' if it is empty (the #128 gate FAILS an empty release).
     - Re-anchor the perf/coverage baselines if you have fresh numbers
       (see ${NEW_DIR}/README.md and RELEASING.md).

  2. Commit on a branch and open the release PR (sign off per CONTRIBUTING.md/DCO):
       git switch -c chore/release-${TAG}
       git add -A
       git commit -s -m "chore(release): prepare ${TAG}"
       gh pr create --fill

  3. After the PR is reviewed + merged, tag the merge commit and push it:
       git tag -s ${TAG} -m "${TAG}"   # signed (or -a for annotated)
       git push origin ${TAG}

  The Release workflow (.github/workflows/release.yml) then asserts the tag matches the manifest
  version, checks the changelog is non-empty, builds the static musl binaries + .deb + container,
  and publishes the GitHub Release (notes from the '## [${TAG}]' changelog section) automatically.
EOF
