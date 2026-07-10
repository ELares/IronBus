#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The NATS side of the #647 effectively-once SURVIVAL head-to-head (V2-M12).
#
# Measures what JetStream's `Nats-Msg-Id` duplicate window actually does when the two things a
# time-bounded window is vulnerable to are injected — a broker RESTART and a producer-offline
# GAP longer than the window — and RECORDS the observed duplicate counts (it asserts nothing;
# the point is measurement):
#
#   S1  retry after a broker restart, window still open (default duplicate_window, clean stop)
#   S1b the same retry after a kill -9 restart (the unclean variant)
#   S2  retry after a producer-offline gap LONGER than the window (no restart)
#   S3  the combined injection: restart PLUS a gap longer than the window
#
# Methodology (mirrors the IronBus leg): the "long gap" scenarios run against a stream with a
# deliberately SHORTENED `duplicates: 5s` window and sleep past it — waiting out the real
# 2-minute default would measure the same lapse, only slower. The restart scenarios keep the
# default window so the restart is isolated from the time bound. The IronBus side of the same
# scenarios is the repeatable `crates/ironbus-cli/tests/effectively_once.rs` integration test;
# the measured results of BOTH sides live in `docs/benchmarks/effectively-once.md`.
#
# Usage (no root needed; downloads the pinned nats-server + natscli for this arch):
#   bash docs/benchmarks/effectively_once_nats.sh
# Environment overrides: NATS_SERVER_VERSION, NATSCLI_VERSION, WORK (scratch dir).
#
# Every observation line is prefixed `OBSERV:` so a transcript can be grepped into the
# results table.

set -u

NATS_SERVER_VERSION=${NATS_SERVER_VERSION:-2.14.3}
NATSCLI_VERSION=${NATSCLI_VERSION:-0.4.0}
WORK=${WORK:-$(mktemp -d /tmp/effectively-once-nats.XXXXXX)}
URL=nats://127.0.0.1:4222
NATS="$WORK/nats -s $URL"
# A private config home: natscli's context machinery errors out ("context not found") when the
# shared config home is unusable; the harness never wants a saved context anyway.
export XDG_CONFIG_HOME="$WORK/xdg"

# The shortened duplicate window for the gap scenarios, and a sleep comfortably past it.
DUPE_WINDOW=5s
GAP_SECONDS=8

case "$(uname -m)" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64) ARCH=amd64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac

mkdir -p "$WORK"
cd "$WORK"

echo "== downloading nats-server v${NATS_SERVER_VERSION} + natscli v${NATSCLI_VERSION} (linux-${ARCH})"
curl -fsSL -o ns.tar.gz "https://github.com/nats-io/nats-server/releases/download/v${NATS_SERVER_VERSION}/nats-server-v${NATS_SERVER_VERSION}-linux-${ARCH}.tar.gz"
tar xzf ns.tar.gz
cp "nats-server-v${NATS_SERVER_VERSION}-linux-${ARCH}/nats-server" .
curl -fsSL -o natscli.zip "https://github.com/nats-io/natscli/releases/download/v${NATSCLI_VERSION}/nats-${NATSCLI_VERSION}-linux-${ARCH}.zip"
unzip -oq natscli.zip
cp "nats-${NATSCLI_VERSION}-linux-${ARCH}/nats" .
./nats-server --version
./nats --version

SRV_PID=""

# Starts nats-server over $1 (store dir), logging to $1.log. JetStream file storage with
# `sync_interval: always` (the durable comparison point, same as the #644 harness).
start_server() {
  local store=$1
  cat > "$store.conf" <<EOF
port: 4222
jetstream {
  store_dir: "$store"
  sync_interval: always
}
EOF
  ./nats-server -c "$store.conf" > "$store.log" 2>&1 &
  SRV_PID=$!
  for _ in $(seq 1 100); do
    $NATS rtt >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "OBSERV: server failed to become ready; log tail:"; tail -5 "$store.log"
  return 1
}

stop_server() { # clean stop (SIGTERM), the normal operational restart
  kill -TERM "$SRV_PID" 2>/dev/null
  wait "$SRV_PID" 2>/dev/null
}

kill_server() { # unclean stop (SIGKILL), the crash variant
  kill -KILL "$SRV_PID" 2>/dev/null
  wait "$SRV_PID" 2>/dev/null
}

messages_in() { # $1 stream: the stream's stored message count (the duplicate ground truth)
  $NATS stream info "$1" --json | grep -o '"messages": *[0-9]*' | head -1 | grep -o '[0-9]*'
}

# Publishes $3 messages onto subject $2 for stream $1, each an ACKNOWLEDGED JetStream publish
# carrying a STABLE `Nats-Msg-Id` (id-1..id-N) — the retryable idempotent-producer shape. A
# second identical call is exactly "the producer retries every publish".
publish_ids() {
  local stream=$1 subject=$2 count=$3
  local i
  for i in $(seq 1 "$count"); do
    $NATS pub "$subject" "payload-$i" -H "Nats-Msg-Id:id-$i" --jetstream >/dev/null 2>&1
  done
}

echo
echo "================ S1: retry after a CLEAN restart (default duplicate_window, still open) ================"
S1=$WORK/store-s1
start_server "$S1"
$NATS stream add S1 --subjects=s1 --storage=file --replicas=1 --defaults >/dev/null
echo "OBSERV: stream S1 duplicate_window: $($NATS stream info S1 --json | grep -o '"duplicate_window": *[0-9]*' | head -1) ns (the 2-minute default)"
publish_ids S1 s1 10
echo "OBSERV: pre-restart: messages=$(messages_in S1) (10 published with Nats-Msg-Id id-1..id-10)"
stop_server
start_server "$S1"
publish_ids S1 s1 10
AFTER=$(messages_in S1)
echo "OBSERV: post-restart retry of the same 10 ids: messages=$AFTER (duplicates appended: $((AFTER - 10)))"
stop_server

echo
echo "================ S1b: the same retry after a KILL -9 restart ================"
S1B=$WORK/store-s1b
start_server "$S1B"
$NATS stream add S1B --subjects=s1b --storage=file --replicas=1 --defaults >/dev/null
publish_ids S1B s1b 10
echo "OBSERV: pre-kill: messages=$(messages_in S1B)"
kill_server
start_server "$S1B"
publish_ids S1B s1b 10
AFTER=$(messages_in S1B)
echo "OBSERV: post-kill-9 retry of the same 10 ids: messages=$AFTER (duplicates appended: $((AFTER - 10)))"
stop_server

echo
echo "================ S2: producer-offline GAP past the window (duplicates: ${DUPE_WINDOW}, no restart) ================"
S2=$WORK/store-s2
start_server "$S2"
$NATS stream add S2 --subjects=s2 --storage=file --replicas=1 --dupe-window="$DUPE_WINDOW" --defaults >/dev/null
publish_ids S2 s2 10
echo "OBSERV: pre-gap: messages=$(messages_in S2) (window shortened to ${DUPE_WINDOW}; the 2-minute default lapses identically, only slower)"
echo "OBSERV: producer offline for ${GAP_SECONDS}s (> ${DUPE_WINDOW} window)..."
sleep "$GAP_SECONDS"
publish_ids S2 s2 10
AFTER=$(messages_in S2)
echo "OBSERV: post-gap retry of the same 10 ids: messages=$AFTER (duplicates appended: $((AFTER - 10)))"
stop_server

echo
echo "================ S3: COMBINED — restart PLUS a gap past the window (duplicates: ${DUPE_WINDOW}) ================"
S3=$WORK/store-s3
start_server "$S3"
$NATS stream add S3 --subjects=s3 --storage=file --replicas=1 --dupe-window="$DUPE_WINDOW" --defaults >/dev/null
publish_ids S3 s3 10
echo "OBSERV: pre-injection: messages=$(messages_in S3)"
stop_server
echo "OBSERV: broker down + producer offline for ${GAP_SECONDS}s (> ${DUPE_WINDOW} window)..."
sleep "$GAP_SECONDS"
start_server "$S3"
publish_ids S3 s3 10
AFTER=$(messages_in S3)
echo "OBSERV: post-restart-plus-gap retry of the same 10 ids: messages=$AFTER (duplicates appended: $((AFTER - 10)))"
stop_server

echo
echo "== done; transcripts in $WORK (grep OBSERV: for the results table inputs)"
