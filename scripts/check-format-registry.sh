#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# IronBus on-disk-format version-registry gate (#126, #132).
#
# Fails when the on-disk byte layout changes without the version registry being updated.
# The byte layout lives in the `pub const` size, magic, version, and field-offset
# declarations in crates/ironbus-core/src/format.rs (the single source of truth that both
# the codec and its frozen tests read). This script hashes exactly those declarations and
# compares the digest against the hash pinned in docs/compat/versions.md.
#
# Mechanism (deterministic, host-independent, no git history needed):
#   1. Extract every `pub const ...` line from format.rs BEFORE the `#[cfg(test)]` block
#      (so test edits never trip the gate), normalizing only leading/trailing whitespace
#      (so reindentation never trips it). Duplicate field-offset lines across the header
#      and footer offset modules are KEPT (dropping a module must change the digest).
#   2. sha256 the normalized lines.
#   3. Read the pinned digest from the `format-layout-sha256:` sentinel line in
#      docs/compat/versions.md.
#   4. They must match. A layout change shifts the computed digest, so the author MUST
#      update both format.rs and the registry (the pinned digest plus the affected rows)
#      in the same commit, which is the whole point: an encoding change cannot land
#      without touching the registry.
#
# Exit codes: 0 match; 1 mismatch (the gate fires); 2 a usage/IO error (missing file or
# no sha256 tool).
#
# Run locally exactly as CI does:
#   sh scripts/check-format-registry.sh
# Re-pin after an INTENTIONAL layout change (then bump the registry rows by hand):
#   sh scripts/check-format-registry.sh --print   # prints the current digest

set -eu

FORMAT_FILE="crates/ironbus-core/src/format.rs"
FRAME_FILE="crates/ironbus-proto/src/frame.rs"
REGISTRY_FILE="docs/compat/versions.md"
SENTINEL="format-layout-sha256:"
FRAME_SENTINEL="frame-tags-sha256:"

# Pick a sha256 tool: sha256sum on Linux (the CI runner), shasum -a 256 on macOS. Both
# emit the digest as the first whitespace-separated field and agree byte for byte.
sha256_of_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{ print $1 }'
  else
    echo "error: no sha256 tool found (need sha256sum or shasum)" >&2
    exit 2
  fi
}

# The canonical extraction: layout-defining `pub const` lines from the non-test region,
# leading/trailing whitespace stripped. Keep order, keep duplicates.
extract_layout() {
  awk '
    /^#\[cfg\(test\)\]/ { exit }
    /pub const/ { incon = 1 }
    incon {
      line = $0
      sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
      print line
      if ($0 ~ /;/) { incon = 0 }
    }
  ' "$FORMAT_FILE"
}

# The WIRE tag-map extraction (#126, hardening after the registry rotted at 1..=21 while the
# code shipped 1..=49): every `N => FrameType::Variant,` arm of `from_u8`, whitespace-
# normalized. Hashing the decode map (rather than the enum declaration) pins BOTH the tag
# numbers and the variant names in one place, so an append-only tag addition — or any
# renumbering — cannot land without re-pinning the registry sentinel and updating its
# FrameType row plus the CONTRACTS.md table.
extract_frame_tags() {
  awk '
    /fn from_u8/ { inmap = 1 }
    inmap && /=> FrameType::/ {
      line = $0
      sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
      print line
    }
    inmap && /_ => return None/ { exit }
  ' "$FRAME_FILE"
}

if [ ! -f "$FORMAT_FILE" ]; then
  echo "error: $FORMAT_FILE not found (run from the repository root)" >&2
  exit 2
fi
if [ ! -f "$FRAME_FILE" ]; then
  echo "error: $FRAME_FILE not found (run from the repository root)" >&2
  exit 2
fi

computed="$(extract_layout | sha256_of_stdin)"
computed_frame="$(extract_frame_tags | sha256_of_stdin)"

# Guard the extraction itself: an empty tag map means from_u8 moved/renamed and the awk
# anchor silently matched nothing — fail loudly rather than pinning a hash of nothing.
if [ -z "$(extract_frame_tags)" ]; then
  echo "error: extracted zero FrameType tag arms from $FRAME_FILE (did from_u8 move?)" >&2
  exit 2
fi

# `--print` emits the current digests (labeled), for re-pinning after an intentional change.
if [ "${1:-}" = "--print" ]; then
  echo "format-layout-sha256: $computed"
  echo "frame-tags-sha256: $computed_frame"
  exit 0
fi

if [ ! -f "$REGISTRY_FILE" ]; then
  echo "error: $REGISTRY_FILE not found; the version registry must exist" >&2
  exit 2
fi

# The pinned digest is the first token after the sentinel on its line in the registry.
pinned_for() {
  awk -v s="$1" '
    index($0, s) {
      i = index($0, s) + length(s)
      rest = substr($0, i)
      # take the first whitespace-delimited token of the remainder
      n = split(rest, parts, /[ \t]+/)
      for (k = 1; k <= n; k++) { if (parts[k] != "") { print parts[k]; exit } }
    }
  ' "$REGISTRY_FILE"
}
pinned="$(pinned_for "$SENTINEL")"
pinned_frame="$(pinned_for "$FRAME_SENTINEL")"

if [ -z "$pinned" ]; then
  echo "error: no '$SENTINEL <digest>' line found in $REGISTRY_FILE" >&2
  exit 2
fi
if [ -z "$pinned_frame" ]; then
  echo "error: no '$FRAME_SENTINEL <digest>' line found in $REGISTRY_FILE" >&2
  exit 2
fi

if [ "$computed_frame" != "$pinned_frame" ]; then
  cat >&2 <<EOF
::error::the wire FrameType tag map changed but the version registry was not updated.
  computed digest (from $FRAME_FILE): $computed_frame
  pinned digest   (in   $REGISTRY_FILE): $pinned_frame
The from_u8 tag map in $FRAME_FILE changed. Per the compatibility policy (#126) a wire
vocabulary change must also update the registry. To resolve:
  1. If this is an INTENTIONAL append-only tag addition: update the FrameType row in
     $REGISTRY_FILE and the tag table in docs/CONTRACTS.md.
  2. Re-pin:  sh scripts/check-format-registry.sh --print
     then replace the '$FRAME_SENTINEL' value in $REGISTRY_FILE.
  3. Commit frame.rs, the registry, and CONTRACTS.md together.
If you did NOT mean to change the wire vocabulary, revert the edit to $FRAME_FILE.
EOF
  exit 1
fi

if [ "$computed" = "$pinned" ]; then
  echo "ok: on-disk format layout matches the pinned registry digest ($computed)"
  echo "ok: wire FrameType tag map matches the pinned registry digest ($computed_frame)"
  exit 0
fi

cat >&2 <<EOF
::error::on-disk format layout changed but the version registry was not updated.
  computed digest (from $FORMAT_FILE): $computed
  pinned digest   (in   $REGISTRY_FILE): $pinned

The byte-layout consts/offsets in $FORMAT_FILE changed. Per the compatibility policy
(#126, #132) an on-disk encoding change must also update the registry. To resolve:
  1. If this is an INTENTIONAL format change, take a NEW storage FORMAT_VERSION (the
     current one is frozen; see docs/compat/versions.md) and update the affected
     registry rows.
  2. Re-pin the digest:  sh scripts/check-format-registry.sh --print
     then replace the '$SENTINEL' value in $REGISTRY_FILE with the printed digest.
  3. Commit format.rs and the registry together.
If you did NOT mean to change the layout, revert the edit to $FORMAT_FILE.
EOF
exit 1
