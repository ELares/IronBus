#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# SBOM round-trip diff (#102).
#
# Recovers the cargo-auditable SBOM embedded in a shipped `ironbus` binary and asserts it matches
# the dependency graph the build was resolved from, in BOTH directions, so an operator who recovers
# the manifest from a deployed binary can trust it is complete and faithful to `Cargo.lock`:
#
#   1. SBOM crate set  ==  the shipped graph `cargo tree -p ironbus-cli -e normal,build` resolves
#      for the SAME target. A crate in the binary but not the graph, or in the graph but not the
#      binary, is drift and FAILS. (The recovered SBOM lists exactly the crates compiled in, so it
#      is target dependent; the comparison graph is taken for the same `--target`.)
#   2. Every SBOM crate exists in `Cargo.lock` at the SAME version. A crate or version in the binary
#      that `Cargo.lock` does not pin (a stale lock, a rebuilt-from-a-different-lock binary) FAILS.
#      The lock is a superset (it also carries dev-deps and other-target crates), so this direction
#      is a subset check, not equality.
#
# This closes cargo-auditable's stated blind spot only for the Rust graph; vendored C / build-script
# blobs are barred separately by the C-FFI ban (scripts/ci/cffi-ban.sh, also #102).
#
# Usage:
#   scripts/ci/sbom-diff.sh <binary> <target-triple>
#
# Determinism: both inputs are derived with `--locked` from the committed `Cargo.lock`; the script
# sorts and uniques every set before diffing, so the result does not depend on enumeration order.
# It needs `jq`, `cargo`, and `rust-audit-info` on PATH.
set -eu

if [ "$#" -ne 2 ]; then
	echo "usage: $0 <binary> <target-triple>" >&2
	exit 2
fi
bin="$1"
target="$2"

if [ ! -x "$bin" ]; then
	echo "::error::SBOM diff: binary not found or not executable: $bin" >&2
	exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 1. Recover the embedded SBOM and reduce it to a sorted "name vVERSION" set.
rust-audit-info "$bin" >"$work/sbom.json"
test -s "$work/sbom.json"
jq -r '.packages[] | "\(.name) v\(.version)"' "$work/sbom.json" | sort -u >"$work/sbom_set.txt"
if [ ! -s "$work/sbom_set.txt" ]; then
	echo "::error::SBOM diff: recovered SBOM is empty (no cargo-auditable data in $bin?)" >&2
	exit 1
fi

# 2. The graph the shipped binary was resolved from, for the SAME target. `--no-dedupe` keeps a
#    crate that appears under more than one path; `sort -u` collapses it back to a set. The trailing
#    " (proc-macro)" / " (path)" annotations are stripped so the column is just "name vVERSION".
cargo tree -p ironbus-cli -e normal,build --target "$target" \
	--prefix none --no-dedupe --locked 2>/dev/null |
	sed -E 's/ \([^)]*\)//g' |
	awk 'NF >= 2 { print $1, $2 }' |
	sort -u >"$work/tree_set.txt"
if [ ! -s "$work/tree_set.txt" ]; then
	echo "::error::SBOM diff: shipped dependency graph came back empty for $target" >&2
	exit 1
fi

# 3. Direction one: the recovered SBOM must equal the shipped graph exactly.
if ! diff -u "$work/tree_set.txt" "$work/sbom_set.txt" >"$work/graph_diff.txt"; then
	echo "::error::SBOM diff: recovered SBOM does not match the shipped dependency graph" >&2
	echo "  '-' = in the resolved graph but missing from the binary's SBOM" >&2
	echo "  '+' = in the binary's SBOM but not in the resolved graph" >&2
	sed -n '3,$p' "$work/graph_diff.txt" >&2
	exit 1
fi

# 4. Direction two: every SBOM crate must be pinned in Cargo.lock at the same version. `cargo
#    metadata --locked` is the Cargo.lock crate set (verified equal); a subset check, not equality,
#    because the lock also carries dev-deps and other-target crates the binary does not link.
cargo metadata --format-version 1 --locked 2>/dev/null |
	jq -r '.packages[] | "\(.name) v\(.version)"' | sort -u >"$work/lock_set.txt"
missing=0
while IFS= read -r entry; do
	if ! grep -qxF "$entry" "$work/lock_set.txt"; then
		echo "::error::SBOM diff: '$entry' is in the binary's SBOM but not pinned in Cargo.lock" >&2
		missing=1
	fi
done <"$work/sbom_set.txt"
if [ "$missing" -ne 0 ]; then
	exit 1
fi

count="$(wc -l <"$work/sbom_set.txt" | tr -d ' ')"
echo "ok: SBOM round-trip clean: $count crates match the shipped graph and Cargo.lock ($target)"
