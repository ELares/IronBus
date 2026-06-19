#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# SBOM round-trip diff (#102).
#
# Recovers the cargo-auditable SBOM embedded in a shipped `ironbus` binary and asserts it matches
# the dependency graph the build was resolved from, in BOTH directions, so an operator who recovers
# the manifest from a deployed binary can trust it is complete and faithful to `Cargo.lock`:
#
#   1. SBOM crate set  ==  the shipped graph the build was RESOLVED from, for the SAME target. A
#      crate in the binary but not the graph, or in the graph but not the binary, is drift and FAILS.
#      (The recovered SBOM lists exactly the crates compiled in, so it is target dependent; the
#      comparison graph is taken for the same `--target`.)
#   2. Every SBOM crate exists in `Cargo.lock` at the SAME version. A crate or version in the binary
#      that `Cargo.lock` does not pin (a stale lock, a rebuilt-from-a-different-lock binary) FAILS.
#      The lock is a superset (it also carries dev-deps and other-target crates), so this direction
#      is a subset check, not equality.
#
# This closes cargo-auditable's stated blind spot only for the Rust graph; vendored C / build-script
# blobs are barred separately by the C-FFI ban (scripts/ci/cffi-ban.sh, also #102).
#
# PROC-MACRO / WEAK-OPTIONAL / `cfg(any())` EDGE HANDLING (#578). The direction-one comparison set is
# derived from `cargo metadata --filter-platform <target>`'s RESOLVER graph (`.resolve.nodes`), not
# from `cargo tree`'s text output. This is deliberate and load-bearing: cargo-auditable embeds the
# crates from the resolved BUILD-UNIT graph, and `cargo tree -e normal,build --target <t>` does NOT
# print every edge that graph contains. After raft-rs landed (#578) two crates were genuinely linked
# into the binary yet absent from the old `cargo tree` set:
#   * `zerocopy-derive` (proc-macro): `raft 0.7 -> rand 0.8 -> rand_chacha -> ppv-lite86 ->
#     zerocopy (simd) -> zerocopy-derive`. `zerocopy` declares an UNCONDITIONAL `zerocopy-derive`
#     dep gated on `target = "cfg(any())"`; `cargo tree --target <triple>` evaluates `cfg(any())` to
#     false and drops the edge, but the resolver keeps it (cargo tree itself emits the
#     "use --target all" hint). raft uses `rand` for election-timeout jitter, so it is not
#     feature-gateable off; the crate is legitimately shipped.
#   * `anyhow`: raft pulls `slog`, and slog's `std` feature weak-references `anyhow?/std`; the
#     resolver records the `slog -> anyhow` (kind=normal) edge, but `cargo tree`'s text output omits
#     this weak-optional edge. anyhow is therefore genuinely compiled into the binary.
# `--target all` is NOT the fix: it would recover `zerocopy-derive` but still miss the weak-optional
# `anyhow`, AND it would UNION IN other-target crates (wasi, windows-*) the binary never links,
# producing false drift. Filtering the RESOLVER graph to the build target via `--filter-platform`
# and walking only `normal`+`build` dep_kinds from the `ironbus-cli` root reproduces EXACTLY the set
# cargo-auditable embeds (verified 1:1, both directions), while still failing on real drift: a crate
# in the binary but not the resolved graph (a smuggled-in dep) or one resolved-but-stripped from the
# binary both break the diff. Both crates are license-approved in deny.toml; `cargo deny check`
# remains the license/advisory gate.
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

# 2. The graph the shipped binary was resolved from, for the SAME target, taken from the RESOLVER
#    graph rather than `cargo tree`'s text output (see "PROC-MACRO / WEAK-OPTIONAL" note above).
#    `cargo metadata --filter-platform <target>` prunes the resolve graph to crates that can be
#    selected for THIS target (so other-target crates the binary never links stay out), then we walk
#    `.resolve.nodes` from the `ironbus-cli` root following only `normal` (kind=null) and `build`
#    dep_kinds, dropping `dev`. That is the same build-unit graph cargo-auditable embeds, so the
#    weak-optional (`slog -> anyhow`) and `cfg(any())` proc-macro (`zerocopy -> zerocopy-derive`)
#    edges that `cargo tree` omits are present, and dev-deps are excluded. `--filter-platform` only
#    RESOLVES (it does not compile), so it works in CI without the target's linker on PATH.
cargo metadata --format-version 1 --filter-platform "$target" --locked 2>/dev/null >"$work/meta_target.json"
test -s "$work/meta_target.json"
jq -r '
  # An edge counts if ANY of its dep_kinds is normal (kind==null) or build; pure-dev edges are out.
  def keep($e): ($e.dep_kinds // [{kind: null}]) | any(.kind == null or .kind == "build");
  (.resolve.nodes | map({key: .id, value: .}) | from_entries) as $byid
  | (.packages | map({key: .id, value: (.name + " v" + .version)}) | from_entries) as $name
  # Root = the ironbus-cli workspace member. Resolve-node ids are opaque and their shape varies by
  # cargo version (`...#name@ver` for registry crates, `path+file://.../ironbus-cli#0.0.0` for path
  # members), so look the root up by package NAME rather than by string-parsing the id.
  | (.packages[] | select(.name == "ironbus-cli") | .id) as $root
  # Iterative reachability from the root over kept edges (bounded; the lock is far under the cap).
  | reduce range(0; 1000) as $_ (
      {seen: {}, frontier: [$root]};
      if (.frontier | length) == 0 then .
      else . as $s
        | ($s.seen + ($s.frontier | map({key: ., value: true}) | from_entries)) as $seen2
        | [$s.frontier[] as $f | ($byid[$f].deps // [])[] | select(keep(.)) | .pkg] as $cand
        | {seen: $seen2, frontier: ($cand | map(select($seen2[.] | not)) | unique)}
      end
    )
  | .seen | keys[] | $name[.]
' "$work/meta_target.json" | sort -u >"$work/tree_set.txt"
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
