#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Seed the committed, content-addressed fuzz REGRESSION corpus (#385, residual of #121).
#
# Why a tracked regression corpus exists:
#   fuzz/.gitignore ignores the volatile working `corpus/` and crash `artifacts/` that
#   cargo-fuzz writes, so without this directory a crash found once would never be carried
#   forward. `corpus-regression/<target>/<sha256>` is a SMALL, committed, content-addressed
#   set of permanent seeds: the frozen #45 conformance vectors plus a handful of crafted
#   hostile inputs, one file per target. The per-PR smoke (ci.yml) and the nightly soak both
#   feed it as seeds, and the deterministic replay test
#   (crates/ironbus-server/tests/fuzz_regression_replay.rs) drives every file through the same
#   decoders the fuzz targets call and asserts no panic. A nightly-found crasher is minimized
#   (cargo fuzz tmin) and PROMOTED here by dropping its file under the right target dir; its
#   content-addressed name makes promotion idempotent (re-adding the same bytes is a no-op).
#
# Mechanism (deterministic, host-independent, no network):
#   - Each input is written to `corpus-regression/<target>/<sha256-of-bytes>`. The filename
#     is the SHA-256 of the file's own bytes, the libFuzzer corpus convention, so identical
#     inputs collapse to one file and the set is reproducible byte-for-byte on any host.
#   - `--check` re-derives the set into a temp dir and diffs it against what is committed,
#     exiting non-zero on drift (used by the regression replay test / CI). Default rewrites
#     the committed tree in place.
#
# Usage:
#   sh fuzz/seed-regression-corpus.sh           # (re)write the committed corpus
#   sh fuzz/seed-regression-corpus.sh --check    # assert the committed corpus is up to date
set -eu

# Resolve the repo-relative paths from this script's own location, so it runs from anywhere.
# A clear CDPATH keeps `cd` from echoing or jumping to a CDPATH entry.
unset CDPATH
here=$(cd -- "$(dirname -- "$0")" && pwd)
fuzz_dir=$here
repo_root=$(cd -- "$fuzz_dir/.." && pwd)
conformance=$repo_root/crates/ironbus-core/tests/corpus

mode="write"
if [ "${1:-}" = "--check" ]; then
  mode="check"
elif [ "$#" -gt 0 ]; then
  echo "usage: $0 [--check]" >&2
  exit 2
fi

# Portable SHA-256 of a file -> bare lowercase hex digest (sha256sum on Linux/CI,
# `shasum -a 256` on macOS). One of the two is always present on the supported hosts.
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# A scratch file used to stage each input's bytes before its content hash is known. Binary
# inputs contain NUL bytes, which a shell variable cannot hold, so the bytes NEVER pass
# through a variable: they go stdin -> staging file -> content-addressed destination. In
# check mode a scratch output tree is also created; one trap removes both.
stage=$(mktemp)
if [ "$mode" = check ]; then
  out_root=$(mktemp -d)
  trap 'rm -rf "$stage" "$out_root"' EXIT INT TERM
else
  # The committed tree (write mode).
  out_root=$fuzz_dir/corpus-regression
  trap 'rm -f "$stage"' EXIT INT TERM
fi

# Place one input (read from stdin) into a target's corpus dir under its content hash. The
# bytes are staged to a file first so NUL-containing binary inputs survive intact, then the
# file is renamed to its SHA-256 (the libFuzzer corpus convention; identical inputs collapse).
place() {
  target=$1
  dir=$out_root/$target
  mkdir -p "$dir"
  cat >"$stage"
  digest=$(sha256_file "$stage")
  cp "$stage" "$dir/$digest"
}

# Copy a frozen #45 conformance fixture verbatim into a target's corpus dir under its hash.
seed_from_fixture() {
  target=$1
  fixture=$2
  src=$conformance/$fixture
  if [ ! -f "$src" ]; then
    echo "missing conformance fixture: $src" >&2
    exit 1
  fi
  place "$target" <"$src"
}

# --- record_codec: the frozen v1 record frames are exactly the decoder's valid space; the
#     version-reject fixture is the hostile space the fail-closed decoder must reject.
for fx in \
  record_minimal record_key_only record_key_headers_payload \
  record_compressed record_compressed_over_threshold record_newer_version_reject; do
  seed_from_fixture record_codec "$fx.bin"
done

# --- segment_scan: the full segment fixtures, including every torn/corrupt/zero-window case.
for fx in \
  segment_header segment_sealed_with_footer segment_active_no_footer \
  segment_torn_tail_mid_body segment_torn_tail_mid_trailer \
  segment_mid_log_bit_flip segment_zero_window_tail; do
  seed_from_fixture segment_scan "$fx.bin"
done

# --- Crafted hostile seeds for the decoders that have no conformance fixture. Each MUST be
#     handled by its decoder as a typed error, never a panic or an out-of-bounds read; they
#     are the "teeth" of the per-PR replay. printf octal escapes keep the bytes exact.

# frame_decode: `[ len:u32 LE ][ type:u8 ][ body ]`. A length that claims far more than is
# present must report "incomplete", and an oversize length must be rejected pre-allocation.
printf '\377\377\377\377\004' | place frame_decode                 # len=0xffffffff, lone type byte
printf '\000\000\000\000' | place frame_decode                     # len=0, no type byte
printf '\001\000\000\000\004' | place frame_decode                 # len=1, type only, empty body
printf '\005\000\000\000\004\000\000\000' | place frame_decode     # len=5 but only 3 body bytes
printf '' | place frame_decode                                      # empty input

# pub/ack/deliver/dead_letter bodies: each begins with little-endian length fields. A length
# that overruns the buffer, and an empty body, are the canonical hostile shapes.
printf '\377\377\377\377' | place pub_body                          # claimed key_len = 0xffffffff
printf '' | place pub_body
printf '\010\000\000\000\000\000\000\000' | place ack_body          # one offset claim, no payload
printf '' | place ack_body
printf '\377\377\377\377\000\000\000\000' | place deliver_body      # overlong leading length
printf '' | place deliver_body
printf '\377\377\377\377' | place dead_letter_body                  # overlong leading length
printf '' | place dead_letter_body

# connect/info handshake bodies (#292): `[ version:u8 ][ field_len:u16 LE ][ block ][ trailing ]`.
# An EMPTY body is the historical old-peer no-fields case (valid); an unknown version, and a declared
# field_len that overruns the body, are the canonical hostile shapes a typed error must catch.
printf '' | place connect_body                                      # empty = old-client no request
printf '\011\000\000' | place connect_body                          # version 9 (unknown), zero block
printf '\001\377\377' | place connect_body                          # version 1, field_len=0xffff, no block
printf '' | place info_body                                         # empty = old-server no advert
printf '\011\000\000' | place info_body                             # version 9 (unknown), zero block
printf '\001\377\377' | place info_body                             # version 1, field_len=0xffff, no block

# gap_marker body (#346): a fixed 25-byte layout `[ from:u64 ][ to:u64 ][ bytes_skipped:u64 ][ reason:u8 ]`.
# An empty body and a short/overlong body must each be a typed error, never a panic. A full 25-byte
# marker is the valid shape (`from=0, to=0, bytes_skipped=0, reason=1` = TRIMMED).
printf '' | place gap_marker_body                                   # empty = too short for from
printf '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001' | place gap_marker_body  # 25 bytes, reason=TRIMMED
printf '\377\377\377\377\377\377\377\377' | place gap_marker_body   # 8 bytes: short (truncated)

# cursor_snapshot: a torn/hostile durable checkpoint payload must never crash recovery.
printf '' | place cursor_snapshot                                   # empty snapshot
printf '\001' | place cursor_snapshot                               # one stray byte
printf '\377\377\377\377\377\377\377\377' | place cursor_snapshot   # all-ones header bytes

# Final report / drift check.
if [ "$mode" = check ]; then
  committed=$fuzz_dir/corpus-regression
  if [ ! -d "$committed" ]; then
    echo "committed corpus-regression/ is missing; run: sh fuzz/seed-regression-corpus.sh" >&2
    exit 1
  fi
  if ! diff -r "$committed" "$out_root" >/dev/null 2>&1; then
    echo "::error::the committed fuzz regression corpus is stale" >&2
    echo "re-run: sh fuzz/seed-regression-corpus.sh   (then commit the result)" >&2
    diff -r "$committed" "$out_root" || true
    exit 1
  fi
  echo "ok: committed fuzz regression corpus is up to date"
else
  total=$(find "$out_root" -type f | wc -l | tr -d ' ')
  echo "ok: wrote $total regression-corpus seeds under $out_root"
fi
