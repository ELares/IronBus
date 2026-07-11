#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Verify that a sink-produced Iceberg table is queryable by an INDEPENDENT engine (DuckDB), and that
# its offsets are contiguous with no drops or duplicates. This is the external correctness proof for
# #793 phase 1 — a table nothing can query is worthless.
#
# Usage: duckdb-verify.sh <table-dir> [expected-row-count]
# Requires the `duckdb` CLI on PATH (https://duckdb.org/docs/installation/); it auto-installs the
# `iceberg` extension on first run.
set -euo pipefail

TBL="${1:?usage: duckdb-verify.sh <table-dir> [expected-row-count]}"
EXPECT="${2:-}"

if ! command -v duckdb >/dev/null 2>&1; then
  echo "error: the 'duckdb' CLI is not on PATH" >&2
  exit 2
fi

# `offset` is a SQL reserved word — quote it.
printf "INSTALL iceberg; LOAD iceberg;
SELECT count(*) AS rows,
       min(\"offset\") AS min_off,
       max(\"offset\") AS max_off,
       (max(\"offset\") - min(\"offset\") + 1 = count(*)) AS contiguous,
       (count(*) = count(DISTINCT \"offset\")) AS no_duplicates
FROM iceberg_scan('%s');\n" "$TBL" | duckdb

if [[ -n "$EXPECT" ]]; then
  GOT=$(printf "INSTALL iceberg; LOAD iceberg;
SELECT count(*) FROM iceberg_scan('%s');\n" "$TBL" | duckdb -noheader -list)
  if [[ "$GOT" != "$EXPECT" ]]; then
    echo "FAIL: expected $EXPECT rows, got $GOT" >&2
    exit 1
  fi
  echo "OK: $GOT rows (== expected $EXPECT)"
fi
