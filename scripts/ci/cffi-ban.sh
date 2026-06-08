#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# C-FFI ban (#102, #139).
#
# IronBus ships as a pure-Rust single binary. This is the forward guard that keeps it that way: it
# fails CI if any crate in the SHIPPED dependency graph (`ironbus-cli` normal + build deps) pulls in
# a C-compiled component or a build script that compiles C / fetches the network. cargo-auditable's
# embedded SBOM cannot see vendored C, build-script blobs, or `dlopen`, so the SBOM round-trip
# (scripts/ci/sbom-diff.sh) is only trustworthy if the graph is provably C-free; this script is the
# other half of that guarantee.
#
# It flags a shipped crate as C-FFI when ANY of these holds, scoped to the shipped graph only so a
# dev-only tool (tools/*, benches, tests) pulling a C-builder never trips it:
#
#   1. it declares a `links` manifest key (it links a native/system library), or
#   2. it has a BUILD dependency on a known C/asm builder (cc, cmake, bindgen, nasm-rs, metadeps,
#      autotools, or pkg-config used to locate a system lib), or
#   3. its name is on an explicit denylist of well-known vendored-C / native crates
#      (*-sys bindings, ring, openssl, zstd, lz4-the-C-binding, etc.).
#
# An ALLOWLIST exempts crates that are pure-Rust bindings to OS SYSCALLS with no compiled C and no
# build script that builds C (libc and nix are raw syscall/ABI bindings; they are already documented
# on the deny.toml allow comment and are off the record path). deny.toml additionally bans the
# best-known C-FFI crates by name as a belt-and-suspenders layer; this script is the structural
# forward guard that also catches an unknown `links`/C-builder crate deny.toml has no rule for.
#
# Usage:
#   scripts/ci/cffi-ban.sh [target-triple]
#
# With no target it inspects the host graph; CI passes the musl release target so the guard runs on
# exactly the graph that ships. Needs `jq` and `cargo` on PATH; reads only the committed Cargo.lock
# (`--locked`), so it is deterministic.
set -eu

target="${1:-}"

# Pure-Rust OS-syscall binding crates that are NOT vendored C and are allowed on the shipped graph.
# Keep this list TIGHT: only crates proven to compile no C and run no C-building build script.
allow_crate() {
	case "$1" in
	libc | nix) return 0 ;;
	*) return 1 ;;
	esac
}

# Well-known vendored-C / native crates. A crate whose name matches here is C-FFI by reputation even
# if its `links`/build-dep signal is not visible in this lock (a forward guard for a future add).
is_denylisted() {
	case "$1" in
	openssl-sys | openssl | libz-sys | libz-ng-sys | zlib-ng | \
		zstd-sys | zstd | lz4-sys | bzip2-sys | brotli-sys | \
		ring | aws-lc-sys | aws-lc-rs | boring-sys | boring | \
		libsqlite3-sys | rusqlite | curl-sys | libgit2-sys | \
		openssl-src | mimalloc | tikv-jemalloc-sys | jemalloc-sys | snappy-sys)
		return 0
		;;
	*) return 1 ;;
	esac
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The shipped graph: ironbus-cli normal + build deps, for the chosen target (host if unset). This is
# the SAME boundary the SBOM diff and the io-free dep-tree check use, so a dev-only tool's deps are
# never in scope. `--no-dedupe` keeps every path; `sort -u` collapses to a crate-name set.
tree_args="-p ironbus-cli -e normal,build --prefix none --no-dedupe --locked"
if [ -n "$target" ]; then
	# shellcheck disable=SC2086
	cargo tree $tree_args --target "$target" 2>/dev/null |
		sed -E 's/ \([^)]*\)//g' | awk 'NF >= 1 { print $1 }' | sort -u >"$work/shipped.txt"
else
	# shellcheck disable=SC2086
	cargo tree $tree_args 2>/dev/null |
		sed -E 's/ \([^)]*\)//g' | awk 'NF >= 1 { print $1 }' | sort -u >"$work/shipped.txt"
fi
if [ ! -s "$work/shipped.txt" ]; then
	echo "::error::C-FFI ban: shipped dependency graph came back empty" >&2
	exit 1
fi

# From cargo metadata, derive for the WHOLE lock: (a) every crate that declares `links`, and (b)
# every crate with a build dep on a known C/asm builder. We intersect each with the shipped set.
meta="$work/metadata.json"
cargo metadata --format-version 1 --locked 2>/dev/null >"$meta"
test -s "$meta"

jq -r '.packages[] | select(.links != null) | .name' "$meta" | sort -u >"$work/links.txt"
jq -r '
  .packages[] as $p
  | $p.dependencies[]
  | select(.kind == "build")
  | select(.name | test("^(cc|cmake|bindgen|nasm-rs|metadeps|autotools|pkg-config)$"))
  | $p.name
' "$meta" | sort -u >"$work/cbuild.txt"

violations=0
report() {
	# $1 crate, $2 reason
	if allow_crate "$1"; then
		echo "note: '$1' is an allowlisted pure-Rust OS-syscall binding ($2), permitted"
		return
	fi
	echo "::error::C-FFI ban: shipped crate '$1' is C-FFI ($2); IronBus ships pure Rust (#139)" >&2
	violations=1
}

while IFS= read -r crate; do
	[ -n "$crate" ] || continue
	if grep -qxF "$crate" "$work/links.txt"; then
		report "$crate" "declares a 'links' native-library key"
	fi
	if grep -qxF "$crate" "$work/cbuild.txt"; then
		report "$crate" "has a build dependency on a C/asm builder"
	fi
	if is_denylisted "$crate"; then
		report "$crate" "is a known vendored-C / native crate"
	fi
done <"$work/shipped.txt"

if [ "$violations" -ne 0 ]; then
	echo "::error::C-FFI ban failed: add the crate to the deny.toml allow comment and this script's allowlist ONLY if it is proven pure Rust, otherwise remove the dependency" >&2
	exit 1
fi

count="$(wc -l <"$work/shipped.txt" | tr -d ' ')"
scope="host"
[ -n "$target" ] && scope="$target"
echo "ok: C-FFI ban clean: $count shipped crates carry no links key, no C-builder build-dep, and none is denylisted ($scope)"
