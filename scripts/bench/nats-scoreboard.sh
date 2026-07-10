#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Manual re-run rig for the #646 durable produce + consume scoreboard vs NATS (JetStream + Core).
#
# Reproduces every leg of the matched-durability scoreboard in docs/PERF_LEDGER.md (the "#646"
# section; machine-readable rows in docs/benchmarks/durable-scoreboard-rows.jsonl) so anyone can
# regenerate the numbers on their own box. The reference run was AWS t4g.large (2 vCPU Graviton2),
# Ubuntu 24.04 arm64, single-host loopback, 256 B payloads, `ironbus` release 2607.109.15 vs
# `nats-server` 2.14.3 driven by natscli 0.4.0 (all natscli flags below verified against 0.4.0).
#
# This script is DELIBERATELY not run in CI: a comparative benchmark on a shared runner produces a
# flaky percent gate (the #114 design notes name that failure mode). Run it on a quiet, dedicated
# box; if a scoreboard row moves, update durable-scoreboard-rows.jsonl AND the PERF_LEDGER section
# together (scripts/ci/durable-scoreboard-check.sh fails the PR if the two drift apart).
#
# Method notes carried over from the recorded runs (#606, #1100):
#   - fresh broker per scenario; one warmed, NAMED consumer group per broker;
#   - `ironbus bench` spawns its own isolated scratch broker per run, so only the NATS server
#     lifecycle is managed here;
#   - t4g-class instances are burstable: read results as p50/p99-grade, run each leg at least
#     twice, and expect run-to-run spread;
#   - the IronBus publish-window/batch flags mirror the configurations recorded in the ledger
#     (window 1 for the sync leg, full-duplex --stream window 1024 for the windowed leg).
#   - the round-2 filtered-consumer and flat-routing legs are NOT re-run here; their exact
#     commands are in docs/BENCHMARKS.md ("Reproducing").
#
# Usage:
#   scripts/bench/nats-scoreboard.sh [--dry-run] [--leg <name>]
#     --dry-run   print every command without executing anything
#     --leg NAME  run a single leg: durable-consume | sync-publish | windowed-publish |
#                 non-durable-delivery | raw-ingest
# Environment overrides:
#   IRONBUS_BIN (default: ironbus)   NATS_SERVER_BIN (default: nats-server)
#   NATS_BIN (default: nats)         NATS_PORT (default: 4222)
#   PAYLOAD_BYTES (default: 256)     SCOREBOARD_WORKDIR (default: mktemp -d)
set -eu

IRONBUS_BIN="${IRONBUS_BIN:-ironbus}"
NATS_SERVER_BIN="${NATS_SERVER_BIN:-nats-server}"
NATS_BIN="${NATS_BIN:-nats}"
NATS_PORT="${NATS_PORT:-4222}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-256}"

# Message counts sized so each leg finishes in seconds-to-a-minute at the reference rates; scale
# them up for tighter medians on a faster box.
COUNT_SYNC_PUB="${COUNT_SYNC_PUB:-2000}"
COUNT_WINDOWED_PUB="${COUNT_WINDOWED_PUB:-200000}"
COUNT_DURABLE_CONSUME="${COUNT_DURABLE_CONSUME:-100000}"
COUNT_DELIVERY="${COUNT_DELIVERY:-200000}"
COUNT_INGEST="${COUNT_INGEST:-500000}"

DRY_RUN=0
ONLY_LEG=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	--dry-run) DRY_RUN=1 ;;
	--leg)
		[ "$#" -ge 2 ] || {
			echo "error: --leg needs a name" >&2
			exit 2
		}
		ONLY_LEG="$2"
		shift
		;;
	-h | --help)
		sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "error: unknown argument $1 (try --help)" >&2
		exit 2
		;;
	esac
	shift
done

NATS_URL="nats://127.0.0.1:${NATS_PORT}"
NATS_PID=""
WORKDIR=""

say() { printf '\n== %s\n' "$1"; }

# Print the exact command, then run it unless --dry-run.
run() {
	printf '   $ %s\n' "$*"
	if [ "$DRY_RUN" = "0" ]; then
		"$@"
	fi
}

# Same as run() but backgrounds the command and records the pid in BG_PID.
BG_PID=""
run_bg() {
	printf '   $ %s &\n' "$*"
	if [ "$DRY_RUN" = "0" ]; then
		"$@" &
		BG_PID=$!
	fi
}

cleanup() {
	if [ -n "$NATS_PID" ]; then
		kill "$NATS_PID" 2>/dev/null || true
		wait "$NATS_PID" 2>/dev/null || true
		NATS_PID=""
	fi
	if [ -n "$WORKDIR" ]; then
		rm -rf "$WORKDIR"
	fi
}
trap cleanup EXIT INT TERM

# Fresh NATS server per scenario (the recorded methodology). JetStream store under the scratch dir.
start_nats() {
	stop_nats
	scratch="$WORKDIR/nats-$1"
	mkdir -p "$scratch"
	printf '   $ %s -js -sd %s -p %s &\n' "$NATS_SERVER_BIN" "$scratch" "$NATS_PORT"
	if [ "$DRY_RUN" = "1" ]; then
		return 0
	fi
	"$NATS_SERVER_BIN" -js -sd "$scratch" -p "$NATS_PORT" >/dev/null 2>&1 &
	NATS_PID=$!
	# Readiness: poll a client round-trip for up to ~10 s.
	tries=0
	until "$NATS_BIN" --server "$NATS_URL" rtt 1 >/dev/null 2>&1; do
		tries=$((tries + 1))
		if [ "$tries" -ge 50 ]; then
			echo "error: nats-server did not become ready on $NATS_URL" >&2
			exit 1
		fi
		sleep 0.2
	done
}

stop_nats() {
	if [ -n "$NATS_PID" ]; then
		kill "$NATS_PID" 2>/dev/null || true
		wait "$NATS_PID" 2>/dev/null || true
		NATS_PID=""
	fi
}

want() {
	[ -z "$ONLY_LEG" ] || [ "$ONLY_LEG" = "$1" ]
}

if [ "$DRY_RUN" = "0" ]; then
	for bin in "$IRONBUS_BIN" "$NATS_SERVER_BIN" "$NATS_BIN"; do
		command -v "$bin" >/dev/null 2>&1 || {
			echo "error: $bin not found on PATH (set IRONBUS_BIN / NATS_SERVER_BIN / NATS_BIN)" >&2
			exit 2
		}
	done
	WORKDIR="${SCOREBOARD_WORKDIR:-$(mktemp -d)}"
	mkdir -p "$WORKDIR"
	echo "ironbus: $("$IRONBUS_BIN" --version 2>/dev/null || true)"
	echo "nats-server: $("$NATS_SERVER_BIN" --version 2>/dev/null || true)"
	echo "natscli: $("$NATS_BIN" --version 2>/dev/null || true)"
else
	WORKDIR="<workdir>"
fi

# ---------------------------------------------------------------------------------------------
# LEG: durable-consume (THE load-bearing MATCHED pair)
# Both sides drain a durable file/disk-backed stream with a committed cursor / explicit acks.
# t4g.large reference: IronBus 333k msg/s vs JetStream 97-98k msg/s (IronBus 3.4x).
# ---------------------------------------------------------------------------------------------
if want durable-consume; then
	say "durable-consume [MATCHED durable-consume]: IronBus disk streaming consume (ref 333k/s)"
	run "$IRONBUS_BIN" bench --mode subscribe --consume-tier streaming --storage disk \
		--payload-bytes "$PAYLOAD_BYTES" --count "$COUNT_DURABLE_CONSUME"

	say "durable-consume [MATCHED durable-consume]: NATS JetStream file storage, explicit acks (ref 97-98k/s)"
	start_nats durable-consume
	# Fill the file-backed stream, then time the durable-consumer drain (explicit acks).
	run "$NATS_BIN" --server "$NATS_URL" bench js pub async scoreboard.durable \
		--create --storage file --purge \
		--msgs "$COUNT_DURABLE_CONSUME" --size "${PAYLOAD_BYTES}B" --batch 500
	run "$NATS_BIN" --server "$NATS_URL" bench js consume \
		--stream benchstream --acks explicit --batch 500 --msgs "$COUNT_DURABLE_CONSUME"
	stop_nats
fi

# ---------------------------------------------------------------------------------------------
# LEG: sync-publish (guarantee-ASYMMETRIC: never scored head-to-head)
# One awaited ack per publish on both sides — but the IronBus ack is fsync-backed (1.03 ms) and
# the JetStream ack is NOT fsynced (154 us). t4g.large reference: 844/s vs 6.3-6.4k/s.
# ---------------------------------------------------------------------------------------------
if want sync-publish; then
	say "sync-publish [ASYMMETRIC]: IronBus awaited publish, fsync-backed ack (ref 844/s)"
	run "$IRONBUS_BIN" bench --mode publish --storage disk \
		--payload-bytes "$PAYLOAD_BYTES" --count "$COUNT_SYNC_PUB" --pubwindow 1

	say "sync-publish [ASYMMETRIC]: NATS JetStream sync publish, ack NOT fsynced (ref 6.3-6.4k/s)"
	start_nats sync-publish
	run "$NATS_BIN" --server "$NATS_URL" bench js pub sync scoreboard.sync \
		--create --storage file --purge \
		--msgs "$((COUNT_SYNC_PUB * 5))" --size "${PAYLOAD_BYTES}B"
	stop_nats
fi

# ---------------------------------------------------------------------------------------------
# LEG: windowed-publish (guarantee-ASYMMETRIC: never scored head-to-head)
# Windowed/async durable ingest. IronBus's acks stay fsync-backed (group commit); JetStream's
# async acks are not fsynced. t4g.large reference: 54.6k/s vs 90-91k/s (an honest IronBus loss
# on the unmatched comparison).
# ---------------------------------------------------------------------------------------------
if want windowed-publish; then
	say "windowed-publish [ASYMMETRIC]: IronBus full-duplex stream, fsync-backed acks (ref 54.6k/s)"
	run "$IRONBUS_BIN" bench --mode publish --storage disk \
		--payload-bytes "$PAYLOAD_BYTES" --count "$COUNT_WINDOWED_PUB" --stream --pubwindow 1024

	say "windowed-publish [ASYMMETRIC]: NATS JetStream async publish, acks NOT fsynced (ref 90-91k/s)"
	start_nats windowed-publish
	run "$NATS_BIN" --server "$NATS_URL" bench js pub async scoreboard.async \
		--create --storage file --purge \
		--msgs "$COUNT_WINDOWED_PUB" --size "${PAYLOAD_BYTES}B" --batch 500
	stop_nats
fi

# ---------------------------------------------------------------------------------------------
# LEG: non-durable-delivery (MATCHED at NATS Core's own tier)
# Live delivery of every message; NATS Core has no persistence, so this is its matching tier.
# IronBus additionally ACKS every message over a replayable log (the strictly stronger side).
# t4g.large reference: IronBus 716-735k/s (acked) vs Core 667-681k/s (unacked).
# ---------------------------------------------------------------------------------------------
if want non-durable-delivery; then
	say "non-durable-delivery [MATCHED non-durable]: IronBus memory-mode streaming consume, acked (ref 716-735k/s)"
	run "$IRONBUS_BIN" bench --mode subscribe --consume-tier streaming --storage memory \
		--payload-bytes "$PAYLOAD_BYTES" --count "$COUNT_DELIVERY"

	say "non-durable-delivery [MATCHED non-durable]: NATS Core pub -> sub delivery, unacked (ref 667-681k/s)"
	start_nats non-durable-delivery
	# The subscriber must be up first; the pub side then drives it end to end.
	run_bg "$NATS_BIN" --server "$NATS_URL" bench sub scoreboard.core --msgs "$COUNT_DELIVERY"
	if [ "$DRY_RUN" = "0" ]; then sleep 1; fi
	run "$NATS_BIN" --server "$NATS_URL" bench pub scoreboard.core \
		--msgs "$COUNT_DELIVERY" --size "${PAYLOAD_BYTES}B"
	if [ -n "$BG_PID" ]; then
		wait "$BG_PID" || true
		BG_PID=""
	fi
	stop_nats
fi

# ---------------------------------------------------------------------------------------------
# LEG: raw-ingest (guarantee-ASYMMETRIC: never scored head-to-head)
# IronBus acks every message (memory mode); NATS Core's number is a fire-and-forget socket write
# with no subscriber, no ack, no retention. t4g.large reference: 251-254k/s vs 1.64-1.75M/s
# (an honest IronBus loss at a different guarantee entirely).
# ---------------------------------------------------------------------------------------------
if want raw-ingest; then
	say "raw-ingest [ASYMMETRIC]: IronBus memory-mode acked ingest (ref 251-254k/s)"
	run "$IRONBUS_BIN" bench --mode publish --storage memory \
		--payload-bytes "$PAYLOAD_BYTES" --count "$COUNT_INGEST" --stream --pubwindow 1024

	say "raw-ingest [ASYMMETRIC]: NATS Core fire-and-forget publish, no subscriber (ref 1.64-1.75M/s)"
	start_nats raw-ingest
	run "$NATS_BIN" --server "$NATS_URL" bench pub scoreboard.faf \
		--msgs "$((COUNT_INGEST * 2))" --size "${PAYLOAD_BYTES}B"
	stop_nats
fi

say "done. Compare against docs/benchmarks/durable-scoreboard-rows.jsonl; if a row moved, update"
echo "   the rows AND the #646 section of docs/PERF_LEDGER.md together (the CI drift gate insists)."
